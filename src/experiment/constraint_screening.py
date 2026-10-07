"""Necessary airtime bounds without repeating fixed-length signature generation.

This module never imports an algorithm backend. Fixed signature sizes come from
the experiment configuration; variable sizes come from complete, validated
signature metadata. It estimates offered traffic, not observed RF occupancy.
"""

import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path

from src.experiment.generate_signatures import inspect_records, sha256_file
from src.experiment.operational_feasibility import (
    collect_group_files,
    finite_number,
    load_json,
    load_trace,
    validate_groups,
)


FRAME_AIRTIME_S = 120 / 1_000_000
MODEL_VERSION = 1
SIZE_PROFILE_VERSION = 1
IDENTITY_FIELDS = ("module", "implementation", "parameter_set", "expected_signature_bytes", "maximum_signature_bytes")


def _size_profile_digest(document):
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode("utf-8")).hexdigest()


def _algorithm_identity(config):
    return {field: config.get(field) for field in IDENTITY_FIELDS}


def build_size_profile(algorithms_config, sizes, sizing_provenance, *, trace_evidence, group_evidence):
    """Export observed frequencies and their original, content-addressed inputs."""
    configs = _configs(algorithms_config)
    sources = {(item["algorithm"], item["interval_k"]): item for item in sizing_provenance}
    algorithms = {}
    for algorithm, config in configs.items():
        intervals = {}
        for (name, interval), lengths in sizes.items():
            if name != algorithm:
                continue
            counts = Counter(lengths)
            intervals[str(interval)] = {
                "distribution": [{"signature_bytes": length, "count": count}
                                 for length, count in sorted(counts.items())],
                "sample_count": len(lengths), "sizing_basis": sources[name, interval]["sizing_basis"],
                "source": sources[name, interval],
            }
        algorithms[algorithm] = {"identity": _algorithm_identity(config), "intervals": intervals}
    profile = {
        "schema_version": SIZE_PROFILE_VERSION, "kind": "portable_signature_size_calibration",
        "trace": trace_evidence, "groups": group_evidence, "algorithms": algorithms,
        "interpretation": "Variable-size distributions are observed calibration samples, not universal bounds or newly signed results for future traces. Fixed sizes are configured nominal encodings.",
    }
    profile["profile_sha256"] = _size_profile_digest(profile)
    return profile


def load_size_profile(path, algorithms_config, intervals):
    """Validate a portable calibration and retain all empirical frequency weights.

    The returned lists are samples for seeded resampling on a new trace, never
    evidence of signature coverage or cryptographic verification of that trace.
    """
    path = Path(path)
    intervals = _intervals(intervals)
    profile = load_json(path)
    if not isinstance(profile, dict):
        raise ValueError("Signature size profile must be an object.")
    contents = {key: value for key, value in profile.items() if key != "profile_sha256"}
    if profile.get("profile_sha256") != _size_profile_digest(contents):
        raise ValueError("Signature size profile integrity digest does not match its contents.")
    if (profile.get("schema_version") != SIZE_PROFILE_VERSION
            or profile.get("kind") != "portable_signature_size_calibration"):
        raise ValueError("Unsupported signature size profile schema or kind.")
    if not isinstance(profile.get("algorithms"), dict):
        raise ValueError("Signature size profile algorithms must be an object.")
    if not isinstance(profile.get("groups"), dict) or not profile["groups"]:
        raise ValueError("Signature size profile must retain source group hashes.")
    for label, evidence in [("trace", profile.get("trace")), *[(f"group {k}", item)
                            for k, item in profile.get("groups", {}).items()]]:
        if (not isinstance(evidence, dict) or not isinstance(evidence.get("path"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", str(evidence.get("sha256", "")))):
            raise ValueError(f"Signature size profile must retain a source {label} path and SHA256.")
    sizes, provenance = {}, []
    for algorithm, config in _configs(algorithms_config).items():
        entry = profile["algorithms"].get(algorithm)
        if not isinstance(entry, dict) or entry.get("identity") != _algorithm_identity(config):
            raise ValueError(f"{algorithm}: signature size profile algorithm identity mismatch or missing entry.")
        for interval in intervals:
            record = entry.get("intervals", {}).get(str(interval))
            if not isinstance(record, dict) or not isinstance(record.get("distribution"), list) or not record["distribution"]:
                raise ValueError(f"{algorithm}, k={interval}: missing calibrated size distribution.")
            counts = {}
            for item in record["distribution"]:
                if not isinstance(item, dict):
                    raise ValueError("Size distribution entries must be objects.")
                length = _integer(item.get("signature_bytes"), "calibrated signature_bytes", 1)
                count = _integer(item.get("count"), "calibrated count", 1)
                if length in counts:
                    raise ValueError("Duplicate signature size in calibrated distribution.")
                if config.get("maximum_signature_bytes") is not None and length > config["maximum_signature_bytes"]:
                    raise ValueError(f"{algorithm}: calibrated signature exceeds the configured maximum.")
                counts[length] = count
            count = sum(counts.values())
            if type(record.get("sample_count")) is not int or record["sample_count"] != count:
                raise ValueError("Calibrated sample_count must equal the sum of its frequency weights.")
            if count > 10_000_000:
                raise ValueError("Calibration exceeds the supported ten million empirical samples.")
            fixed = config.get("expected_signature_bytes")
            if fixed is not None:
                _integer(fixed, "expected_signature_bytes", 1)
                if set(counts) != {fixed} or record.get("sizing_basis") != "configured_fixed_size":
                    raise ValueError(f"{algorithm}: calibrated fixed size disagrees with configuration.")
                lengths, basis = [fixed], "configured_fixed_size"
            else:
                source = record.get("source")
                if (record.get("sizing_basis") != "measured_complete_signature_metadata"
                        or not isinstance(source, dict)
                        or source.get("algorithm") != algorithm or source.get("interval_k") != interval
                        or source.get("measured_record_count") != count
                        or not isinstance(source.get("signature_metadata_path"), str)
                        or not re.fullmatch(r"[0-9a-f]{64}", str(source.get("signature_metadata_sha256", "")))
                        or str(interval) not in profile["groups"]):
                    raise ValueError(f"{algorithm}, k={interval}: calibration must retain its original measured-source provenance.")
                lengths = [length for length, weight in sorted(counts.items()) for _ in range(weight)]
                basis = "calibrated_empirical_distribution"
            sizes[algorithm, interval] = lengths
            provenance.append({
                "algorithm": algorithm, "interval_k": interval, "sizing_basis": basis,
                "signature_size_profile_path": str(path), "signature_size_profile_sha256": sha256_file(path),
                "calibration_profile_digest": profile["profile_sha256"],
                "calibration_sample_count": count, "calibration_trace": profile["trace"],
                "calibration_group": profile["groups"].get(str(interval)),
                "original_sizing_source": record.get("source"),
                "measured_current_trace_records": 0,
                "note": "Observed calibration reused by frequency; no signature coverage or cryptographic verification of the current trace is claimed.",
            })
    return sizes, provenance


def _integer(value, name, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}.")
    return value


def _intervals(values):
    values = list(values)
    if not values or len(set(values)) != len(values):
        raise ValueError("Intervals must be nonempty and unique.")
    for value in values:
        _integer(value, "interval", 1)
    return values


def _configs(value):
    value = load_json(Path(value)) if isinstance(value, (str, Path)) else value
    enabled = {name: config for name, config in value.items() if config.get("enabled", True)}
    if not enabled:
        raise ValueError("At least one algorithm must be enabled.")
    for name in enabled:
        if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            raise ValueError(f"Unsafe algorithm name: {name!r}.")
    return enabled


def load_signature_sizes(algorithms_config, signature_dir, intervals, *,
                         trace=None, groups_by_interval=None, size_profile=None):
    """Return ``(sizes[(algorithm, k)], provenance)`` for transport simulations.

    A fixed size is represented by a singleton list, not one entry per group.
    Variable sizes retain their empirical frequency and complete-group order.
    For those sizes, supply a trace indexed by ``trace_id`` and interval-indexed
    groups indexed by ``group_id`` (or group lists). Each record is checked
    against the original signing input. This checks saved verification metadata;
    it does not perform a fresh cryptographic verification.

    ``signature_dir`` may be one directory or an ordered list. Only final
    ``.jsonl`` files are read. The first existing file must validate fully;
    corruption is never hidden by silently selecting another directory.
    """
    intervals = _intervals(intervals)
    if size_profile is not None:
        return load_size_profile(size_profile, algorithms_config, intervals)
    configs = _configs(algorithms_config)
    if signature_dir is None:
        directories = []
    elif isinstance(signature_dir, (str, Path)):
        directories = [Path(signature_dir)]
    else:
        directories = [Path(directory) for directory in signature_dir]
    sizes, provenance = {}, []
    checked_groups = {}
    for algorithm, config in configs.items():
        fixed_size = config.get("expected_signature_bytes")
        if fixed_size is not None:
            _integer(fixed_size, f"{algorithm} expected_signature_bytes", 1)
        for interval in intervals:
            if fixed_size is not None:
                sizes[algorithm, interval] = [fixed_size]
                provenance.append({
                    "algorithm": algorithm,
                    "interval_k": interval,
                    "sizing_basis": "configured_fixed_size",
                    "signature_bytes": fixed_size,
                    "measured_record_count": 0,
                    "note": "Nominal configured encoding size; no signature run is required or claimed.",
                })
                continue
            if trace is None or groups_by_interval is None:
                raise ValueError(f"{algorithm}: variable sizes require the trace and authentication groups.")
            if interval not in checked_groups:
                groups = groups_by_interval[interval]
                if isinstance(groups, list):
                    identifiers = [group["group_id"] for group in groups]
                    if len(set(identifiers)) != len(identifiers):
                        raise ValueError(f"k={interval}: duplicate group IDs.")
                    groups = {group["group_id"]: group for group in groups}
                complete = validate_groups(trace, groups, interval)
                checked_groups[interval] = [info["group"] for info in complete.values()]
            filename = f"signatures_{algorithm}_k{interval}.jsonl"
            path = next((directory / filename for directory in directories
                         if (directory / filename).is_file()), None)
            if path is None:
                raise FileNotFoundError(f"No completed signature metadata for {algorithm}, k={interval}: {filename}")
            groups = checked_groups[interval]
            lengths, digest, byte_count = inspect_records(path, algorithm, config, interval, groups, trace)
            if len(lengths) != len(groups):
                raise ValueError(f"{algorithm}, k={interval}: incomplete signature coverage "
                                 f"({len(lengths)} records for {len(groups)} complete groups).")
            sizes[algorithm, interval] = lengths
            provenance.append({
                "algorithm": algorithm,
                "interval_k": interval,
                "sizing_basis": "measured_complete_signature_metadata",
                "measured_record_count": len(lengths),
                "signature_metadata_path": str(path),
                "signature_metadata_sha256": digest.hexdigest(),
                "signature_metadata_bytes": byte_count,
                "note": "Complete ordered coverage and signing-input digests validated; saved verification_success checked, without fresh cryptographic verification.",
            })
    return sizes, provenance


def _nearest_rank(values, percentile):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def screen(trace_path, groups_dir, algorithms_config_path, signature_results_dir,
           intervals, *, payload_bytes=7, fragment_header_bytes=4,
           object_overhead_bytes=56, per_message_overhead_bytes=8,
           auth_frames_per_second=None, algorithms=None, size_profile=None):
    """Screen raw-signature and explicit-envelope offered airtime bounds.

    The default envelope size includes a 2-byte stream length prefix, a 52-byte
    object header, a 2-byte signature length, and one 8-byte association tag per
    original message. A 4-byte fragment header leaves 3 bytes per 7-byte ME field.
    The raw lower bound always ignores all those headers and uses all 7 bytes.
    ``auth_frames_per_second`` is an optional global scenario budget for added
    authentication frames, not a measured or regulated transmission allowance.
    """
    intervals = _intervals(intervals)
    _integer(payload_bytes, "payload_bytes", 1)
    if payload_bytes > 7:
        raise ValueError("payload_bytes cannot exceed the 7-byte 1090ES ME field.")
    _integer(fragment_header_bytes, "fragment_header_bytes")
    if fragment_header_bytes >= payload_bytes:
        raise ValueError("fragment_header_bytes must leave at least one payload byte.")
    _integer(object_overhead_bytes, "object_overhead_bytes")
    _integer(per_message_overhead_bytes, "per_message_overhead_bytes")
    if auth_frames_per_second is not None:
        finite_number(auth_frames_per_second, "auth_frames_per_second")
        if auth_frames_per_second == 0:
            raise ValueError("auth_frames_per_second must be positive.")
    trace_path, groups_dir = Path(trace_path), Path(groups_dir)
    algorithms_config_path = Path(algorithms_config_path)
    configs = _configs(algorithms_config_path)
    if algorithms is not None:
        algorithms = list(algorithms)
        if not algorithms or len(set(algorithms)) != len(algorithms) or set(algorithms) - set(configs):
            raise ValueError("Selected algorithms must be nonempty, unique and enabled in configuration.")
        configs = {algorithm: configs[algorithm] for algorithm in algorithms}
    trace = load_trace(trace_path)
    if not trace:
        raise ValueError("The trace is empty.")
    times = [finite_number(record["relative_time_s"], "relative_time_s") for record in trace.values()]
    duration = max(times) - min(times)
    if duration <= 0:
        raise ValueError("The trace must span a positive duration.")
    groups_by_interval = collect_group_files(groups_dir, intervals)
    complete_by_interval = {
        interval: validate_groups(trace, groups_by_interval[interval], interval)
        for interval in intervals
    }
    sizes, sizing_provenance = load_signature_sizes(
        configs, signature_results_dir, intervals, trace=trace,
        groups_by_interval=groups_by_interval, size_profile=size_profile,
    )
    basis = {(entry["algorithm"], entry["interval_k"]): entry["sizing_basis"]
             for entry in sizing_provenance}
    baseline_load = len(trace) * FRAME_AIRTIME_S / duration
    effective_payload = payload_bytes - fragment_header_bytes
    rows = []
    for interval in intervals:
        complete = complete_by_interval[interval]
        group_count = len(complete)
        message_count = sum(info["group"]["message_count"] for info in complete.values())
        formation_delays = [info["formation_delay_ms"] for info in complete.values()]
        for algorithm in configs:
            lengths = sizes[algorithm, interval]
            fixed = basis[algorithm, interval] == "configured_fixed_size"
            counts = Counter({lengths[0]: group_count}) if fixed else Counter(lengths)
            calibrated = basis[algorithm, interval] == "calibrated_empirical_distribution"
            scale = group_count / len(lengths) if calibrated else 1
            raw_frames = scale * sum(count * math.ceil(length / 7) for length, count in counts.items())
            overhead = object_overhead_bytes + per_message_overhead_bytes * interval
            modeled_frames = scale * sum(count * math.ceil((length + overhead) / effective_payload)
                                 for length, count in counts.items())
            raw_load = raw_frames * FRAME_AIRTIME_S / duration
            modeled_load = modeled_frames * FRAME_AIRTIME_S / duration
            modeled_rate = modeled_frames / duration
            rows.append({
                "algorithm": algorithm,
                "interval_k": interval,
                "sizing_basis": basis[algorithm, interval],
                "traffic_count_basis": "calibration_distribution_expectation" if calibrated else "complete_group_size_counts",
                "signature_size_distribution_basis": "calibration_sample_counts" if calibrated else "complete_group_counts",
                "calibration_sample_count": len(lengths) if calibrated else None,
                "trace_duration_s": duration,
                "observed_message_count": len(trace),
                "observed_aircraft_count": len({record["icao"] for record in trace.values()}),
                "complete_group_count": group_count,
                "incomplete_group_count": len(groups_by_interval[interval]) - group_count,
                "grouped_message_count": message_count,
                "unsigned_tail_message_count": len(trace) - message_count,
                "signed_trace_fraction": message_count / len(trace),
                "auth_events_per_second": group_count / duration,
                "signature_bytes_min": min(lengths),
                "signature_bytes_mean": sum(length * count for length, count in counts.items()) / sum(counts.values()),
                "signature_bytes_p50": _nearest_rank(lengths, 0.5),
                "signature_bytes_p95": _nearest_rank(lengths, 0.95),
                "signature_bytes_max": max(lengths),
                "signature_size_distribution": {str(length): count for length, count in sorted(counts.items())},
                "group_formation_ms_p50": _nearest_rank(formation_delays, 0.5),
                "group_formation_ms_p95": _nearest_rank(formation_delays, 0.95),
                "baseline_offered_airtime_load": baseline_load,
                "raw_signature_lower_bound_frames": raw_frames,
                "raw_signature_lower_bound_additional_airtime_load": raw_load,
                "raw_signature_lower_bound_total_airtime_load": baseline_load + raw_load,
                "raw_signature_lower_bound_exceeds_serial_capacity": baseline_load + raw_load > 1,
                "modeled_authentication_frames": modeled_frames,
                "modeled_authentication_frames_per_second": modeled_rate,
                "modeled_additional_airtime_load": modeled_load,
                "modeled_total_offered_airtime_load": baseline_load + modeled_load,
                "modeled_exceeds_serial_capacity": baseline_load + modeled_load > 1,
                "global_authentication_frame_budget_per_second": auth_frames_per_second,
                "modeled_exceeds_global_authentication_frame_budget": (
                    modeled_rate > auth_frames_per_second if auth_frames_per_second is not None else None
                ),
            })
    return {
        "model_version": MODEL_VERSION,
        "rows": rows,
        "provenance": {
            "trace": {"path": str(trace_path), "sha256": sha256_file(trace_path)},
            "algorithms_config": {"path": str(algorithms_config_path), "sha256": sha256_file(algorithms_config_path)},
            "authentication_groups": {
                str(interval): {"path": str(groups_dir / f"authentication_groups_k{interval}.jsonl"),
                                "sha256": sha256_file(groups_dir / f"authentication_groups_k{interval}.jsonl")}
                for interval in intervals
            },
            "signature_sizing": sizing_provenance,
        },
        "parameters": {
            "frame_airtime_us": 120,
            "raw_lower_bound_payload_bytes": 7,
            "payload_bytes": payload_bytes,
            "fragment_header_bytes": fragment_header_bytes,
            "object_overhead_bytes": object_overhead_bytes,
            "per_message_overhead_bytes": per_message_overhead_bytes,
            "auth_frames_per_second": auth_frames_per_second,
        },
        "assumptions": [
            "Hypothetical additional 1090ES authentication frames; no allocated or compatible deployed message format is established.",
            "Original observed ADS-B frames transmit without waiting for their detached per-message or batched signature.",
            "Trace observations are used as sender arrivals; capture losses, unobserved aircraft and background Mode S traffic are not inferred.",
            "Offered airtime sums 120-microsecond frame envelopes over the observed span; it is not measured RF occupancy and is not clamped at one.",
            "Fixed sizes are nominal encoding sizes from configuration, independent of whether complete signing runs exist.",
            "Variable sizes use the full empirical frequency distribution of complete validated saved signature metadata.",
            "An explicitly supplied size profile reuses observed calibration frequencies on a new trace; traffic totals are distribution-weighted expectations, and no current-trace signature verification is claimed.",
            "Only complete fixed-count groups are signed; incomplete aircraft tails are counted as unsigned. Timeout batching belongs to replay scenarios.",
            "Headers and association tags are counted in modeled frames; raw-signature lower bounds exclude them. No repetition, FEC, certificate or key-distribution traffic is counted.",
            "Neither computation, contention, receiver losses nor an authentication deadline is tested by these necessary traffic bounds; passing does not establish operational feasibility.",
            "Observed aircraft count is the distinct sample population, not the simultaneous channel population.",
        ],
    }
