"""Generate and validate reusable, real signatures for the radio replay.

The cache contains public keys and complete encoded authentication objects, never
private keys. A completed cache is published atomically and verified on every
load. Interrupted builds are rebuilt; they cannot masquerade as complete input.
No replay loss seed or processor profile influences the signed bytes.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import ctypes.util
import fcntl
import hashlib
import importlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import shutil
import sys
import tempfile

from .generate_signatures import (
    load_algorithm_module, load_trace, package_version, sha256_file,
    sync_directory, validate_metadata,
)
from .replay_simulator import form_groups
from .replay_transport import (
    ALGORITHM_CODES, context_bytes, decode_envelope, describe_group,
    encode_envelope, make_envelope,
)


SCHEMA_VERSION = 1
ALGORITHMS_PATH = Path(__file__).resolve().parents[2] / "config" / "algorithms.json"


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("utf-8")


def _digest(value):
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _algorithm_config(algorithm):
    configs = json.loads(ALGORITHMS_PATH.read_text(encoding="utf-8"))
    if algorithm not in ALGORITHM_CODES or algorithm not in configs:
        raise ValueError(f"Unknown replay signature algorithm: {algorithm}.")
    config = configs[algorithm]
    if not config.get("enabled", True):
        raise ValueError(f"Signature algorithm is disabled: {algorithm}.")
    return config


def _installed_oqs():
    """Do not let liboqs-python's import-time bootstrap download a library."""
    if "oqs" in sys.modules:
        return sys.modules["oqs"]
    if importlib.util.find_spec("oqs") is None:
        raise RuntimeError("Install the crypto dependencies before building a signed workload.")
    root = Path(os.environ.get("OQS_INSTALL_PATH", str(Path.home() / "_oqs")))
    filenames = {"Darwin": ["liboqs.dylib"], "Windows": ["oqs.dll", "liboqs.dll"]}.get(
        platform.system(), ["liboqs.so"])
    candidates = [ctypes.util.find_library(name) for name in ("oqs", "liboqs")]
    candidates += [str(root / folder / filename)
                   for folder in ("lib", "lib64", "bin") for filename in filenames]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            ctypes.CDLL(candidate)
        except OSError:
            continue
        return importlib.import_module("oqs")
    raise RuntimeError("No installed liboqs library is loadable; automatic downloading is disabled. "
                       "Follow docs/native_crypto.md before generating signatures.")


def _backend_identity(algorithm, config):
    if algorithm == "ECDSA-P256":
        try:
            from cryptography.hazmat.backends.openssl.backend import backend
        except ImportError as exc:
            raise RuntimeError("Install cryptography before building a signed workload.") from exc
        return {"backend": "cryptography", "version": package_version("cryptography"),
                "openssl": backend.openssl_version_text(),
                "implementation": config["implementation"]}
    oqs = _installed_oqs()
    implementation = config["implementation"]
    if implementation not in oqs.get_enabled_sig_mechanisms():
        raise RuntimeError(f"liboqs signature mechanism {implementation!r} is not enabled.")
    with oqs.Signature(implementation) as verifier:
        details = dict(verifier.details)
    return {"backend": "liboqs", "version": oqs.oqs_version(),
            "python_version": package_version("liboqs-python"),
            "implementation": implementation, "algorithm_version": details.get("version")}


def backend_identity(algorithm):
    """Identify the selected, installed implementation without generating keys."""
    config = _algorithm_config(algorithm)
    details = _backend_identity(algorithm, config)
    module = load_algorithm_module(config)
    if (getattr(module, "ALGORITHM_ID", None) != algorithm
            or getattr(module, "IMPLEMENTATION", None) != config["implementation"]):
        raise ValueError("Algorithm configuration does not match the actual crypto implementation.")
    return {"algorithm": algorithm, "module": config["module"], **details}


def verifier_for(algorithm, public_key):
    """Return a public-key-only verifier(message, signature), with close()."""
    config = _algorithm_config(algorithm)
    if algorithm == "ECDSA-P256":
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key)

        def verify(message, signature):
            if len(signature) != 64:
                return False
            encoded = encode_dss_signature(int.from_bytes(signature[:32], "big"),
                                           int.from_bytes(signature[32:], "big"))
            try:
                key.verify(encoded, message, ec.ECDSA(hashes.SHA256()))
            except Exception:
                return False
            return True

        verify.close = lambda: None
        return verify
    oqs = _installed_oqs()
    native = oqs.Signature(config["implementation"])
    if len(public_key) != native.details["length_public_key"]:
        native.free()
        raise ValueError("Public key length does not match the signature algorithm.")

    def verify(message, signature):
        try:
            return bool(native.verify(message, signature, public_key))
        except Exception:
            return False

    verify.close = native.free
    return verify


def _prepare(trace, algorithm, interval, max_batch_wait_s):
    config = _algorithm_config(algorithm)
    if type(interval) is not int or interval < 1:
        raise ValueError("interval must be a positive integer.")
    if max_batch_wait_s is not None and (
        isinstance(max_batch_wait_s, bool) or not isinstance(max_batch_wait_s, (int, float))
        or not math.isfinite(max_batch_wait_s) or max_batch_wait_s <= 0
    ):
        raise ValueError("max_batch_wait_s must be null or finite and positive.")
    records = list(trace.values()) if isinstance(trace, dict) else list(trace)
    if not records:
        raise ValueError("A nonempty trace is required.")
    identifiers = set()
    for record in records:
        time = record["relative_time_s"]
        if isinstance(time, bool) or not isinstance(time, (int, float)) or not math.isfinite(time) or time < 0:
            raise ValueError("Trace times must be finite and nonnegative.")
        message = bytes.fromhex(record["raw_msg"])
        if len(message) != 14 or message[0] >> 3 != 17 or message[1:4].hex().upper() != record["icao"]:
            raise ValueError("Trace must contain canonical DF17 observations.")
        if record["trace_id"] in identifiers:
            raise ValueError("Duplicate trace ID.")
        identifiers.add(record["trace_id"])
    records.sort(key=lambda row: (row["relative_time_s"], row["trace_id"]))
    source_groups, _ = form_groups(records, interval, max_batch_wait_s)
    grouped = {row["trace_id"] for _, _, entries, _ in source_groups for row in entries}
    unsigned = [row["trace_id"] for row in records if row["trace_id"] not in grouped]
    backend = backend_identity(algorithm)
    module = load_algorithm_module(config)
    identity = {
        "schema_version": SCHEMA_VERSION, "trace_sha256": _digest(records),
        "trace_messages": len(records), "algorithm": algorithm, "algorithm_config": config,
        "backend": backend, "interval": interval,
        "max_batch_wait_s": max_batch_wait_s,
        "source_sha256": {filename: sha256_file(Path(__file__).with_name(filename))
                          for filename in ("signed_workload.py", "replay_transport.py", "replay_simulator.py")},
        "crypto_source_sha256": {config["module"]: sha256_file(module.__file__),
                                 "src.crypto.common": sha256_file(Path(__file__).parents[1] / "crypto" / "common.py")},
    }
    return config, source_groups, unsigned, identity


def _write_durable(path, data):
    with path.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _build(path, config, source_groups, unsigned, identity):
    module = load_algorithm_module(config)
    signers = {}
    session = bytes.fromhex(_digest(identity))[:8]
    try:
        with (path / "groups.jsonl").open("xb") as stream:
            for icao, seq, entries, formed in source_groups:
                if icao not in signers:
                    signers[icao] = module.Signer()
                    validate_metadata(identity["algorithm"], config, signers[icao])
                signer = signers[icao]
                messages = [(row["relative_time_s"], bytes.fromhex(row["raw_msg"])) for row in entries]
                envelope = make_envelope(icao, seq, session, messages, identity["algorithm"], signer)
                if not signer.verify(context_bytes(envelope.descriptor) + b"".join(raw for _, raw in messages),
                                     envelope.signature):
                    raise ValueError("Generated signature failed cryptographic verification.")
                stream.write(_json_bytes({"members": [row["trace_id"] for row in entries],
                                          "formed_s": formed,
                                          "envelope": base64.b64encode(encode_envelope(envelope)).decode("ascii")}))
            stream.flush()
            os.fsync(stream.fileno())
        keys = {icao: base64.b64encode(signer.public_key_bytes()).decode("ascii")
                for icao, signer in sorted(signers.items())}
        _write_durable(path / "public_keys.json", _json_bytes(keys))
        manifest = {"schema_version": SCHEMA_VERSION, "complete": True, "identity": identity,
                    "groups": len(source_groups), "unsigned_trace_ids": unsigned,
                    "groups_sha256": sha256_file(path / "groups.jsonl"),
                    "public_keys_sha256": sha256_file(path / "public_keys.json")}
        _write_durable(path / "manifest.json", _json_bytes(manifest))
        sync_directory(path)
    finally:
        for signer in signers.values():
            signer.close()


def _load(path, source_groups, unsigned, identity):
    try:
        manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
        if (manifest.get("schema_version") != SCHEMA_VERSION or manifest.get("complete") is not True
                or manifest.get("identity") != identity or manifest.get("groups") != len(source_groups)
                or manifest.get("unsigned_trace_ids") != unsigned):
            raise ValueError("Signed workload manifest does not match the exact trace and grouping policy.")
        for filename, field in (("groups.jsonl", "groups_sha256"), ("public_keys.json", "public_keys_sha256")):
            if sha256_file(path / filename) != manifest.get(field):
                raise ValueError(f"Signed workload file checksum mismatch: {filename}.")
        encoded_keys = json.loads((path / "public_keys.json").read_text(encoding="utf-8"))
        if set(encoded_keys) != {icao for icao, _, _, _ in source_groups}:
            raise ValueError("Signed workload public keys do not match the aircraft.")
        keys = {icao: base64.b64decode(value, validate=True) for icao, value in encoded_keys.items()}
        session = bytes.fromhex(_digest(identity))[:8]
        verifiers, groups = {}, []
        try:
            for icao, public_key in keys.items():
                verifiers[icao] = verifier_for(identity["algorithm"], public_key)
            with (path / "groups.jsonl").open("r", encoding="utf-8") as stream:
                for icao, seq, entries, formed in source_groups:
                    line = stream.readline()
                    if not line:
                        raise ValueError("Signed workload is missing a group.")
                    row = json.loads(line)
                    members = tuple(entry["trace_id"] for entry in entries)
                    if row.get("members") != list(members) or row.get("formed_s") != formed:
                        raise ValueError("Signed workload group membership or formation time mismatch.")
                    envelope = decode_envelope(base64.b64decode(row["envelope"], validate=True))
                    messages = [(entry["relative_time_s"], bytes.fromhex(entry["raw_msg"])) for entry in entries]
                    descriptor = describe_group(icao, seq, session, messages, identity["algorithm"], keys[icao])
                    if envelope.descriptor != descriptor:
                        raise ValueError("Signed workload context does not match the source messages.")
                    signing_input = context_bytes(descriptor) + b"".join(raw for _, raw in messages)
                    if not verifiers[icao](signing_input, envelope.signature):
                        raise ValueError("Cached signature failed cryptographic verification.")
                    groups.append({"descriptor": descriptor, "envelope": envelope, "members": members,
                                   "formed_s": formed, "public_key": keys[icao]})
                if stream.read():
                    raise ValueError("Signed workload contains unexpected trailing groups.")
        finally:
            for verifier in verifiers.values():
                verifier.close()
    except (KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid or incomplete signed workload cache at {path}.") from exc
    return {"groups": groups, "unsigned_trace_ids": unsigned,
            "evidence": {"schema_version": SCHEMA_VERSION, "cache_dir": str(path.resolve()),
                         "cache_identity": _digest(identity), "identity": identity,
                         "manifest_sha256": sha256_file(path / "manifest.json"),
                         "groups_sha256": manifest["groups_sha256"],
                         "public_keys_sha256": manifest["public_keys_sha256"],
                         "signature_count": len(groups), "cryptographically_verified_signatures": len(groups),
                         "private_keys_persisted": False}}


def build_or_load_workload(trace, algorithm, interval, max_batch_wait_s, cache_dir, *, validate_only=False):
    """Build once, or validate and reuse exact signed bytes independently of RF runs.

    One key is generated per aircraft for this workload's provisioned session.
    Only public material is retained. A process lock serializes competing builds
    and is released automatically on interruption; an interrupted workload starts
    afresh with new keys. Completed caches are never silently repaired or replaced.
    """
    config, groups, unsigned, identity = _prepare(trace, algorithm, interval, max_batch_wait_s)
    root = Path(cache_dir)
    cache_id = _digest(identity)
    destination = root / cache_id
    if validate_only:
        if not destination.exists():
            raise ValueError(f"No completed signed workload cache at {destination}.")
        return _load(destination, groups, unsigned, identity)
    root.mkdir(parents=True, exist_ok=True)
    with (root / f".{cache_id}.lock").open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if destination.exists():
            return _load(destination, groups, unsigned, identity)
        temporary = Path(tempfile.mkdtemp(prefix=f".{cache_id}.building-", dir=root))
        try:
            _build(temporary, config, groups, unsigned, identity)
            result = _load(temporary, groups, unsigned, identity)
            os.rename(temporary, destination)
            sync_directory(root)
            result["evidence"]["cache_dir"] = str(destination.resolve())
            return result
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", required=True, type=Path)
    parser.add_argument("--cache-dir", required=True, type=Path)
    parser.add_argument("--algorithms", nargs="+", required=True, choices=sorted(ALGORITHM_CODES))
    parser.add_argument("--intervals", nargs="+", required=True, type=int)
    parser.add_argument("--max-batch-wait-s", type=float)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    trace = load_trace(args.trace)
    for algorithm in args.algorithms:
        for interval in args.intervals:
            result = build_or_load_workload(trace, algorithm, interval, args.max_batch_wait_s, args.cache_dir,
                                           validate_only=args.validate_only)
            print(json.dumps(result["evidence"], sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
