#!/usr/bin/env python3

import argparse
import base64
import os
import re
import signal
import tempfile
import time
from types import SimpleNamespace
import hashlib
import importlib
import importlib.metadata
import json
import math
import platform
import statistics
from collections import Counter
from pathlib import Path


def sha256_file(path, chunk_size=1024 * 1024):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def package_version(package_name):
    try:
        return importlib.metadata.version(package_name)
    except importlib.metadata.PackageNotFoundError:
        return None


def load_json(path):
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def load_jsonl(path):
    records = []
    with path.open("r", encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON in {path} at line {number}.") from exc
    return records


def write_jsonl(path, records):
    """Write fixture/utility records; experiment outputs use exclusive publication."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        for record in records:
            stream.write(json.dumps(record, separators=(",", ":")) + "\n")


def load_trace(path):
    trace = {}
    for record in load_jsonl(path):
        trace_id = record["trace_id"]
        if trace_id in trace:
            raise ValueError(f"Duplicate trace_id {trace_id}.")
        trace[trace_id] = record
    return trace


def build_signing_input(group, trace):
    """Concatenate empirical 112-bit DF17 messages in authentication-group order."""
    parts = []
    for trace_id in group["trace_ids"]:
        if trace_id not in trace:
            raise KeyError(f"Trace ID {trace_id} not found.")
        try:
            message = bytes.fromhex(trace[trace_id]["raw_msg"])
        except ValueError as exc:
            raise ValueError(f"Invalid raw_msg for trace_id {trace_id}.") from exc
        if len(message) != 14:
            raise RuntimeError(f"Trace ID {trace_id} has {len(message)} bytes instead of 14.")
        parts.append(message)
    message = b"".join(parts)
    if len(message) != 14 * group["message_count"]:
        raise RuntimeError("Signing input length mismatch.")
    return message


def load_algorithm_module(config):
    name = config["module"]
    try:
        module = importlib.import_module(name)
    except ImportError as exc:
        raise RuntimeError(f"Could not import algorithm module '{name}'.") from exc
    if not hasattr(module, "Signer"):
        raise RuntimeError(f"Algorithm module '{name}' does not expose Signer.")
    return module


def validate_metadata(algorithm_name, config, signer):
    metadata = signer.metadata()
    expected_pk = config.get("expected_public_key_bytes")
    actual_pk = metadata.get("public_key_bytes")
    if expected_pk is not None and actual_pk != expected_pk:
        raise RuntimeError(f"{algorithm_name}: expected {expected_pk}-byte public key, backend reports {actual_pk}.")
    expected_sig = config.get("expected_signature_bytes")
    actual_sig = metadata.get("maximum_signature_bytes")
    if expected_sig is not None and actual_sig is not None and actual_sig != expected_sig:
        raise RuntimeError(f"{algorithm_name}: expected {expected_sig}-byte signature, backend reports {actual_sig}.")
    return metadata


def create_aircraft_signers(aircraft, algorithm_module):
    signers = {}
    try:
        for icao in sorted(aircraft):
            signers[icao] = algorithm_module.Signer()
        return signers
    except BaseException:
        close_signers(signers)
        raise


def close_signers(signers):
    for signer in signers.values():
        signer.close()


def process_interval(algorithm_name, algorithm_config, k, groups, trace, signers):
    """Compatibility helper for callers processing a small interval in memory."""
    results = [sign_record(algorithm_name, k, group, trace, signers[group["icao"]])
               for group in groups if group["complete"]]
    return results, interval_summary(k, [row["signature_length_bytes"] for row in results])


# Recovery files pin the inputs and private keys before the first signature.
# Result files still contain only hashes; resumed prefixes are protected by a
# durable checksum of records that were verified before they were committed.
RECOVERY_VERSION = 1


def atomic_json(path, value, private=False):
    """Replace a metadata snapshot only after its bytes are durable."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600 if private else 0o644)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def result_path(args, name, k):
    return args.output_dir / f"signatures_{name}_k{k}.jsonl"


def recovery_path(args, name, suffix=""):
    return args.output_dir / ".checkpoints" / f"{name}{suffix}.json"


def interval_summary(k, lengths):
    counts = Counter(lengths)
    return {
        "k": k,
        "complete_groups": len(lengths),
        "signatures_generated": len(lengths),
        "signatures_verified": len(lengths),
        "verification_failures": 0,
        "signature_length": {
            "minimum_bytes": min(lengths) if lengths else None,
            "maximum_bytes": max(lengths) if lengths else None,
            "mean_bytes": statistics.mean(lengths) if lengths else None,
            "median_bytes": statistics.median(lengths) if lengths else None,
            "distribution": {str(n): count for n, count in sorted(counts.items())},
        },
    }


def prepare_experiment(args):
    intervals = sorted(set(args.intervals))
    if not intervals or any(k <= 0 for k in intervals):
        raise ValueError("Authentication intervals must be positive.")
    configs = {
        name: config for name, config in load_json(args.config).items()
        if config.get("enabled", True)
    }
    if not configs:
        raise ValueError("No algorithms are enabled.")
    for name in configs:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            raise ValueError(f"Unsafe algorithm name: {name!r}.")
    trace = load_trace(args.trace)
    if not trace:
        raise ValueError("The signing trace is empty.")
    groups = {}
    group_hashes = {}
    for k in intervals:
        path = args.groups_dir / f"authentication_groups_k{k}.jsonl"
        all_groups = load_jsonl(path)
        groups[k] = [group for group in all_groups if group["complete"]]
        group_hashes[str(k)] = sha256_file(path)
        identifiers = set()
        for group in groups[k]:
            if group["group_id"] in identifiers:
                raise ValueError(f"Duplicate group_id for k={k}: {group['group_id']}.")
            identifiers.add(group["group_id"])
            if group.get("k") != k or group["message_count"] != k or len(group["trace_ids"]) != k:
                raise ValueError(f"Complete group has wrong size for k={k}.")
            if any(trace[tid]["icao"] != group["icao"] for tid in group["trace_ids"]):
                raise ValueError(f"Group aircraft mismatch for k={k}.")
            build_signing_input(group, trace)
    identity = {
        "schema_version": RECOVERY_VERSION,
        "trace_sha256": sha256_file(args.trace),
        "algorithm_config_sha256": sha256_file(args.config),
        "authentication_intervals": intervals,
        "group_sha256": group_hashes,
    }
    return SimpleNamespace(
        configs=configs, trace=trace, groups=groups, identity=identity,
        aircraft=sorted({record["icao"] for record in trace.values()}),
        intervals=intervals,
    )


def validate_record(record, name, config, k, group, trace, key_hashes=None):
    message = build_signing_input(group, trace)
    expected = {
        "algorithm": name, "k": k, "group_id": group["group_id"],
        "icao": group["icao"], "message_count": group["message_count"],
        "message_length_bytes": len(message),
        "message_sha256": sha256_bytes(message),
        "group_formation_time_s": group["group_formation_time_s"],
    }
    for field, value in expected.items():
        if record.get(field) != value:
            raise ValueError(f"{name} k={k} group={group['group_id']}: invalid {field}.")
    if record.get("verification_success") is not True:
        raise ValueError(f"{name} k={k}: verification_success must be true.")
    length = record.get("signature_length_bytes")
    if type(length) is not int or length <= 0:
        raise ValueError(f"{name} k={k}: invalid signature length.")
    expected_length = config.get("expected_signature_bytes")
    if expected_length is not None and length != expected_length:
        raise ValueError(f"{name} k={k}: unexpected signature length {length}.")
    maximum_length = config.get("maximum_signature_bytes")
    if maximum_length is not None and length > maximum_length:
        raise ValueError(f"{name} k={k}: signature exceeds the backend maximum.")
    if not isinstance(record.get("signature_sha256"), str) or not re.fullmatch(
        r"[0-9a-f]{64}", record["signature_sha256"]
    ):
        raise ValueError(f"{name} k={k}: invalid signature digest.")
    if key_hashes is not None and record.get("public_key_sha256") != key_hashes[group["icao"]]:
        raise ValueError(f"{name} k={k}: aircraft key changed.")
    return length


def inspect_records(path, name, config, k, groups, trace, key_hashes=None,
                    committed_bytes=None):
    """Check ordered coverage and record metadata; never claim a re-verification."""
    lengths, digest, offset = [], hashlib.sha256(), 0
    with path.open("rb") as stream:
        for raw in stream:
            if committed_bytes is not None and offset >= committed_bytes:
                break
            offset += len(raw)
            if committed_bytes is not None and offset > committed_bytes:
                raise ValueError(f"Checkpoint offset does not end on a record in {path}.")
            if not raw.endswith(b"\n"):
                raise ValueError(f"Incomplete JSONL record in {path}.")
            if len(lengths) >= len(groups):
                raise ValueError(f"Unexpected extra records in {path}.")
            try:
                record = json.loads(raw)
            except (ValueError, UnicodeDecodeError) as exc:
                raise ValueError(f"Invalid JSONL record in {path}.") from exc
            lengths.append(validate_record(
                record, name, config, k, groups[len(lengths)], trace, key_hashes,
            ))
            digest.update(raw)
    if committed_bytes is not None and offset != committed_bytes:
        raise ValueError(f"Checkpoint prefix is missing bytes in {path}.")
    return lengths, digest, offset


def check_identity(record, identity, path):
    if record.get("identity") != identity:
        raise ValueError(f"Input/config/group metadata changed for {path}; preserve and archive the old run explicitly.")


def read_key_hashes(manifest, aircraft):
    keys = manifest.get("keys", {})
    if set(keys) - set(aircraft):
        raise ValueError("Checkpoint contains unexpected aircraft keys.")
    try:
        return {
            icao: sha256_bytes(base64.b64decode(value["public_key"], validate=True))
            for icao, value in keys.items()
        }
    except (KeyError, ValueError) as exc:
        raise ValueError("Invalid public key checkpoint.") from exc


def inspect_existing(args, experiment, require_complete=False):
    """Preflight every algorithm before generating keys or modifying any result."""
    previous = load_json(args.summary) if args.summary.exists() else {}
    if previous.get("recovery_schema_version") == RECOVERY_VERSION:
        check_identity(previous, experiment.identity, args.summary)
    states = {}
    missing = []
    for name, config in experiment.configs.items():
        manifest_path = recovery_path(args, name)
        legacy_path = recovery_path(args, name, ".legacy")
        if manifest_path.exists() and legacy_path.exists():
            raise ValueError(f"Conflicting key/legacy checkpoints for {name}.")
        manifest = load_json(manifest_path) if manifest_path.exists() else None
        legacy = load_json(legacy_path) if legacy_path.exists() else None
        for path, record in ((manifest_path, manifest), (legacy_path, legacy)):
            if record is not None:
                check_identity(record, experiment.identity, path)
        key_hashes = read_key_hashes(manifest, experiment.aircraft) if manifest else None
        existing = {k for k in experiment.intervals if result_path(args, name, k).exists()}
        if manifest is None and existing and existing != set(experiment.intervals):
            raise ValueError(f"{name}: incomplete legacy result set has no recoverable keys; preserve and archive it explicitly before rerunning.")
        if legacy is not None and existing != set(experiment.intervals):
            raise ValueError(f"{name}: adopted legacy output is missing.")
        if manifest and existing and set(key_hashes) != set(experiment.aircraft):
            raise ValueError(f"{name}: committed outputs have an incomplete aircraft key checkpoint.")
        old = previous.get("algorithms", {}).get(name, {})
        state = {"manifest": manifest, "legacy": legacy, "intervals": {}, "output_files": {}}
        if old.get("legacy_summary_hash_mismatches"):
            state["legacy_summary_hash_mismatches"] = old["legacy_summary_hash_mismatches"]
        for k in experiment.intervals:
            output = result_path(args, name, k)
            checkpoint_path = recovery_path(args, name, f"_k{k}")
            partial = output.with_suffix(output.suffix + ".partial")
            checkpoint = load_json(checkpoint_path) if checkpoint_path.exists() else None
            if checkpoint is not None:
                check_identity(checkpoint, experiment.identity, checkpoint_path)
            if (partial.exists() or checkpoint is not None) and manifest is None:
                raise ValueError(f"{name} k={k}: partial output has no recoverable key checkpoint.")
            if output.exists():
                lengths, digest, offset = inspect_records(
                    output, name, config, k, experiment.groups[k], experiment.trace, key_hashes,
                )
                if len(lengths) != len(experiment.groups[k]):
                    raise ValueError(f"Incomplete final output: {output}.")
                expected_hashes = [(legacy or {}).get("output_hashes", {}).get(str(k))]
                # Old summaries were written only after a whole run and may
                # predate independently regenerated files. Preserve their
                # provenance warning, but do not mistake them for checkpoints.
                old_hash = old.get("output_files", {}).get(str(k), {}).get("sha256")
                if previous.get("recovery_schema_version") == RECOVERY_VERSION:
                    expected_hashes.append(old_hash)
                elif old_hash and old_hash != digest.hexdigest():
                    state.setdefault("legacy_summary_hash_mismatches", []).append(k)
                if manifest:
                    if checkpoint is None or checkpoint.get("records") != len(lengths) or checkpoint.get("bytes") != offset:
                        raise ValueError(f"Missing/inconsistent durable checkpoint for {output}.")
                    expected_hashes.append(checkpoint.get("sha256"))
                if any(value is not None and value != digest.hexdigest() for value in expected_hashes):
                    raise ValueError(f"Recorded output hash mismatch: {output}.")
                state["intervals"][str(k)] = interval_summary(k, lengths)
                state["output_files"][str(k)] = {"file": str(output), "sha256": digest.hexdigest()}
            else:
                missing.append(f"{name}/k={k}")
                if partial.exists() and checkpoint is None:
                    raise ValueError(f"Partial output has no durable checkpoint: {partial}.")
                if checkpoint:
                    if set(key_hashes) != set(experiment.aircraft):
                        raise ValueError(f"{name}: partial output has incomplete aircraft keys.")
                    if partial.exists():
                        lengths, digest, offset = inspect_records(
                            partial, name, config, k, experiment.groups[k], experiment.trace,
                            key_hashes, committed_bytes=checkpoint["bytes"],
                        )
                        if len(lengths) != checkpoint["records"] or digest.hexdigest() != checkpoint["sha256"]:
                            raise ValueError(f"Durable checkpoint digest/count mismatch: {partial}.")
                    elif checkpoint.get("records") != 0 or checkpoint.get("bytes") != 0:
                        raise ValueError(f"Missing partial output: {partial}.")
        state["old_metadata"] = old.get("implementation_metadata")
        metadata = (manifest or {}).get("implementation_metadata") or state["old_metadata"] or {}
        maximum = metadata.get("maximum_signature_bytes")
        if maximum is not None and any(
            interval["signature_length"]["maximum_bytes"] is not None
            and interval["signature_length"]["maximum_bytes"] > maximum
            for interval in state["intervals"].values()
        ):
            raise ValueError(f"{name}: recorded signature length exceeds backend maximum.")
        states[name] = state
    if require_complete and missing:
        raise ValueError("Missing signature outputs: " + ", ".join(missing))
    return states


def validate_existing_outputs(trace_path, groups_dir, config_path, output_dir,
                              summary_path, intervals, require_complete=True):
    """Read-only coverage/integrity validation, also callable by the pipeline."""
    args = SimpleNamespace(trace=Path(trace_path), groups_dir=Path(groups_dir),
                           config=Path(config_path), output_dir=Path(output_dir),
                           summary=Path(summary_path), intervals=intervals)
    experiment = prepare_experiment(args)
    states = inspect_existing(args, experiment, require_complete=require_complete)
    return make_summary(args, experiment, states)


def make_summary(args, experiment, states):
    summary = {
        "recovery_schema_version": RECOVERY_VERSION,
        "identity": experiment.identity,
        "trace_file": str(args.trace), "trace_sha256": experiment.identity["trace_sha256"],
        "algorithm_config_file": str(args.config),
        "algorithm_config_sha256": experiment.identity["algorithm_config_sha256"],
        "trace_records": len(experiment.trace), "unique_aircraft": len(experiment.aircraft),
        "authentication_intervals": experiment.intervals,
        "group_sha256": experiment.identity["group_sha256"],
        "signing_input": {"source": "raw 112-bit DF17 messages",
                          "construction": "byte concatenation in authentication-group order",
                          "bytes_per_message": 14},
        "key_model": {"one_keypair_per_aircraft_per_algorithm": True,
                      "keypair_reused_across_intervals": True,
                      "public_key_distribution_simulated": False},
        "host_timing_used_as_avionics_model": False,
        "software": {"python": platform.python_version(), "platform": platform.platform(),
                     "cryptography": package_version("cryptography"),
                     "liboqs_python": package_version("liboqs-python")},
        "software_metadata_scope": "current validation/signing host; not original generation provenance for adopted legacy outputs",
        "algorithms": {},
    }
    for name, state in states.items():
        config = experiment.configs[name]
        manifest = state["manifest"]
        algorithm = {key: config[key] for key in (
            "family", "paper_name", "parameter_set", "module", "implementation", "implementation_note",
        ) if key in config}
        legacy = manifest is None and bool(state["output_files"])
        algorithm.update({
            "implementation_metadata": (manifest or {}).get("implementation_metadata") or state.get("old_metadata"),
            "aircraft_keypairs": len(experiment.aircraft) if manifest or legacy else 0,
            "intervals": state["intervals"], "output_files": state["output_files"],
            "verification_evidence": (
                "legacy recorded verification; ordered messages, lengths and available file hashes checked; signatures and original keys unavailable for re-verification"
                if legacy else "signatures verified at generation; durable record checksums and aircraft key fingerprints checked on resume"
            ),
            "key_continuity_checkable": manifest is not None,
        })
        if state.get("legacy_summary_hash_mismatches"):
            algorithm["legacy_summary_hash_mismatches"] = state["legacy_summary_hash_mismatches"]
        summary["algorithms"][name] = algorithm
    summary["complete"] = all(len(state["intervals"]) == len(experiment.intervals) for state in states.values())
    return summary


def restore_or_create_signers(args, experiment, name, state):
    module = load_algorithm_module(experiment.configs[name])
    manifest = state["manifest"] or {"identity": experiment.identity, "keys": {}}
    path = recovery_path(args, name)
    signers = {}
    last_progress = time.monotonic()
    atomic_json(args.output_dir / "signature_progress.json", {
        "state": "key_generation", "algorithm": name, "aircraft_keys": 0,
        "total_aircraft": len(experiment.aircraft), "pid": os.getpid(),
        "updated_unix_s": time.time(),
    })
    try:
        for icao in experiment.aircraft:
            saved = manifest["keys"].get(icao)
            if saved:
                signer = module.Signer.from_secret_key(
                    base64.b64decode(saved["secret_key"], validate=True),
                    base64.b64decode(saved["public_key"], validate=True),
                )
            else:
                signer = module.Signer()
            signers[icao] = signer
            metadata = validate_metadata(name, experiment.configs[name], signer)
            if saved and base64.b64encode(signer.public_key_bytes()).decode("ascii") != saved["public_key"]:
                raise ValueError(f"Restored public key mismatch for {name}/{icao}.")
            if "implementation_metadata" in manifest and manifest["implementation_metadata"] != metadata:
                raise ValueError(f"{name}: backend metadata changed since checkpoint creation.")
            manifest["implementation_metadata"] = metadata
            if not saved:
                manifest["keys"][icao] = {
                    "secret_key": base64.b64encode(signer.export_secret_key()).decode("ascii"),
                    "public_key": base64.b64encode(signer.public_key_bytes()).decode("ascii"),
                }
                atomic_json(path, manifest, private=True)
            now = time.monotonic()
            if len(signers) % 50 == 0 or len(signers) == len(experiment.aircraft) or now - last_progress >= args.progress_seconds:
                atomic_json(args.output_dir / "signature_progress.json", {
                    "state": "key_generation", "algorithm": name,
                    "aircraft_keys": len(signers), "total_aircraft": len(experiment.aircraft),
                    "pid": os.getpid(), "updated_unix_s": time.time(),
                })
                print(f"  {name}: {len(signers)}/{len(experiment.aircraft)} persistent aircraft keys ready", flush=True)
                last_progress = now
        state["manifest"] = manifest
        return signers
    except BaseException:
        close_signers(signers)
        raise


def sign_record(name, k, group, trace, signer):
    message = build_signing_input(group, trace)
    signature = signer.sign(message)
    if not signer.verify(message, signature):
        raise RuntimeError(f"Verification failed: algorithm={name}, k={k}, group_id={group['group_id']}.")
    return {
        "algorithm": name, "k": k, "group_id": group["group_id"], "icao": group["icao"],
        "message_count": group["message_count"], "message_length_bytes": len(message),
        "message_sha256": sha256_bytes(message), "signature_length_bytes": len(signature),
        "signature_sha256": sha256_bytes(signature), "verification_success": True,
        "group_formation_time_s": group["group_formation_time_s"],
        "public_key_sha256": sha256_bytes(signer.public_key_bytes()),
    }


def stream_interval(args, experiment, name, k, signers):
    output = result_path(args, name, k)
    partial = output.with_suffix(output.suffix + ".partial")
    checkpoint_path = recovery_path(args, name, f"_k{k}")
    groups = experiment.groups[k]
    key_hashes = {icao: sha256_bytes(signer.public_key_bytes()) for icao, signer in signers.items()}
    if checkpoint_path.exists():
        checkpoint = load_json(checkpoint_path)
        check_identity(checkpoint, experiment.identity, checkpoint_path)
    else:
        checkpoint = {"identity": experiment.identity, "records": 0, "bytes": 0,
                      "sha256": hashlib.sha256().hexdigest()}
        atomic_json(checkpoint_path, checkpoint, private=True)
    if partial.exists():
        lengths, digest, offset = inspect_records(
            partial, name, experiment.configs[name], k, groups, experiment.trace,
            key_hashes, committed_bytes=checkpoint["bytes"],
        )
        if len(lengths) != checkpoint["records"] or digest.hexdigest() != checkpoint["sha256"]:
            raise ValueError(f"Durable checkpoint mismatch: {partial}.")
    else:
        if checkpoint["bytes"] or checkpoint["records"]:
            raise ValueError(f"Missing partial output: {partial}.")
        lengths, digest, offset = [], hashlib.sha256(), 0
    resumed = len(lengths)
    committed_records = resumed
    started = last_progress = time.monotonic()
    status_path = args.output_dir / "signature_progress.json"

    def report(state):
        elapsed = time.monotonic() - started
        fresh = len(lengths) - resumed
        rate = fresh / elapsed if elapsed > 0 and fresh else None
        remaining = len(groups) - len(lengths)
        status = {"state": state, "algorithm": name, "k": k,
                  "verified_records": len(lengths), "total_records": len(groups),
                  "resumed_records": resumed, "events_per_second": rate,
                  "estimated_remaining_seconds": remaining / rate if rate else None,
                  "pid": os.getpid(), "updated_unix_s": time.time()}
        atomic_json(status_path, status)
        speed = f", {rate:.2f} events/s, ETA {remaining / rate / 3600:.2f} h" if rate else ""
        print(f"  {name} k={k}: {len(lengths):,}/{len(groups):,} verified{speed}", flush=True)

    with partial.open("r+b" if partial.exists() else "x+b") as stream:
        # Discard only bytes beyond the last fsynced, atomically recorded prefix.
        stream.truncate(offset)
        stream.seek(offset)

        def commit():
            nonlocal committed_records
            stream.flush()
            os.fsync(stream.fileno())
            atomic_json(checkpoint_path, {
                "identity": experiment.identity, "records": len(lengths),
                "bytes": stream.tell(), "sha256": digest.hexdigest(),
            }, private=True)
            committed_records = len(lengths)

        report("running")
        try:
            for group in groups[resumed:]:
                record = sign_record(name, k, group, experiment.trace, signers[group["icao"]])
                length = validate_record(record, name, experiment.configs[name], k, group, experiment.trace, key_hashes)
                maximum = signers[group["icao"]].metadata().get("maximum_signature_bytes")
                if maximum is not None and length > maximum:
                    raise ValueError(f"{name} k={k}: signature exceeds the backend maximum.")
                encoded = (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")
                stream.write(encoded)
                digest.update(encoded)
                lengths.append(length)
                now = time.monotonic()
                if len(lengths) % args.checkpoint_every == 0 or now - last_progress >= args.progress_seconds:
                    commit()
                    report("running")
                    last_progress = now
            commit()
        except BaseException:
            # An asynchronous signal may land between writing a record and
            # updating its digest/count. Never commit that in-memory state:
            # retain the previous complete durable checkpoint instead.
            del lengths[committed_records:]
            report("interrupted")
            raise
    # An exclusive hard link publishes the verified file without replacing a result.
    os.link(partial, output)
    sync_directory(output.parent)
    partial.unlink()
    report("interval_complete")
    return interval_summary(k, lengths), {"file": str(output), "sha256": digest.hexdigest()}


def run_experiment(args):
    from src.runtime import RunLock

    args.output_dir.mkdir(parents=True, exist_ok=True)
    with RunLock(args.output_dir / ".signatures.lock"):
        try:
            return run_locked_experiment(args)
        except BaseException as exc:
            if not args.validate_only:
                atomic_json(args.output_dir / "signature_progress.json", {
                    "state": "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed",
                    "pid": os.getpid(), "updated_unix_s": time.time(),
                    "error": str(exc) or type(exc).__name__,
                })
            raise


def run_locked_experiment(args):
    experiment = prepare_experiment(args)
    states = inspect_existing(args, experiment, require_complete=args.validate_only)
    if args.validate_only:
        print("All configured signature outputs passed coverage and record-integrity validation.", flush=True)
        return make_summary(args, experiment, states)
    checkpoint_dir = args.output_dir / ".checkpoints"
    checkpoint_dir.mkdir(mode=0o700, exist_ok=True)
    checkpoint_dir.chmod(0o700)
    for name, state in states.items():
        if len(state["intervals"]) == len(experiment.intervals) and state["manifest"] is None and state["legacy"] is None:
            state["legacy"] = {
                "identity": experiment.identity,
                "output_hashes": {k: value["sha256"] for k, value in state["output_files"].items()},
                "evidence": "legacy recorded verification; signatures/private keys unavailable",
            }
            atomic_json(recovery_path(args, name, ".legacy"), state["legacy"], private=True)
    atomic_json(args.summary, make_summary(args, experiment, states))
    for name, state in states.items():
        if len(state["intervals"]) == len(experiment.intervals):
            print(f"{name}: all intervals validated; preserving existing outputs.", flush=True)
            continue
        print(f"{name}: restoring or generating persistent aircraft keypairs.", flush=True)
        signers = restore_or_create_signers(args, experiment, name, state)
        try:
            atomic_json(args.summary, make_summary(args, experiment, states))
            for k in experiment.intervals:
                if str(k) in state["intervals"]:
                    continue
                result, output = stream_interval(args, experiment, name, k, signers)
                state["intervals"][str(k)] = result
                state["output_files"][str(k)] = output
                atomic_json(args.summary, make_summary(args, experiment, states))
        finally:
            close_signers(signers)
    final_states = inspect_existing(args, experiment, require_complete=True)
    summary = make_summary(args, experiment, final_states)
    atomic_json(args.summary, summary)
    atomic_json(args.output_dir / "signature_progress.json", {
        "state": "complete", "pid": os.getpid(), "updated_unix_s": time.time(),
        "summary": str(args.summary),
    })
    print(f"Signature experiment complete: {args.summary}", flush=True)
    return summary



def main():
    parser = argparse.ArgumentParser(description="Generate verified signatures with durable serial recovery.")
    for name in ("trace", "groups-dir", "config", "output-dir", "summary"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--intervals", type=int, nargs="+", default=[1, 5, 10, 20])
    parser.add_argument("--validate-only", action="store_true", help="Check all configured result coverage without signing.")
    parser.add_argument("--checkpoint-every", type=int, default=100)
    parser.add_argument("--progress-seconds", type=float, default=30.0)
    args = parser.parse_args()
    if args.checkpoint_every < 1 or not math.isfinite(args.progress_seconds) or args.progress_seconds <= 0:
        parser.error("Checkpoint frequency and progress interval must be positive.")
    def interrupt(signum, frame):
        raise KeyboardInterrupt(f"Received signal {signum}")

    previous_handler = signal.signal(signal.SIGTERM, interrupt)
    try:
        run_experiment(args)
    finally:
        signal.signal(signal.SIGTERM, previous_handler)


if __name__ == "__main__":
    main()
