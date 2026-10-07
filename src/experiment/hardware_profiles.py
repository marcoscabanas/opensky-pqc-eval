"""Validated, explicitly sourced crypto service times for operational replay.

Published means are represented by one deterministic service time. They are not
empirical samples and must not be used to infer a latency distribution or WCET.
This module neither benchmarks hardware nor samples from a global RNG.
"""

import json
import math
from pathlib import Path


PROFILE_KINDS = {"published_reference", "composite_proxy", "sensitivity_assumption", "measured_local"}
EQUIVALENCES = {"exact_parameter_set", "lineage_proxy", "assumed"}
SAMPLE_KINDS = {"published_mean", "published_estimate", "empirical", "assumed_constant"}
OPERATIONS = {"keygen", "sign", "verify"}


def _positive_number(value, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{label} must be a finite positive number.")
    return float(value)


def _nonempty_text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty string.")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate hardware-profile JSON key: {key}.")
        result[key] = value
    return result


def _validate_timing(timing, label):
    if not isinstance(timing, dict):
        raise ValueError(f"{label} must be an object.")
    samples = timing.get("samples_ms")
    if not isinstance(samples, list) or not samples:
        raise ValueError(f"{label}.samples_ms must be a nonempty list.")
    values = [_positive_number(value, f"{label}.samples_ms") for value in samples]
    kind = timing.get("sample_kind")
    if not isinstance(kind, str) or kind not in SAMPLE_KINDS:
        raise ValueError(f"{label}.sample_kind must identify empirical data or an explicit point estimate.")
    if kind != "empirical" and len(values) != 1:
        raise ValueError(f"{label}: a summary statistic is one service time, not an empirical distribution.")
    if "clock_mhz" in timing:
        _positive_number(timing["clock_mhz"], f"{label}.clock_mhz")
    for key in ("cycles_mean", "cycles_min", "cycles_max", "cycles_approximate"):
        if key in timing:
            _positive_number(timing[key], f"{label}.{key}")
    if "cycles_mean" in timing:
        clock = _positive_number(timing.get("clock_mhz"), f"{label}.clock_mhz")
        if kind != "published_mean" or len(values) != 1:
            raise ValueError(f"{label}: cycles_mean requires a published_mean service time.")
        if not math.isclose(values[0], timing["cycles_mean"] / (clock * 1000), rel_tol=1e-9, abs_tol=1e-9):
            raise ValueError(f"{label}: samples_ms disagrees with cycles_mean / (clock_mhz * 1000).")
        if timing.get("cycles_min", timing["cycles_mean"]) > timing["cycles_mean"] or timing.get("cycles_max", timing["cycles_mean"]) < timing["cycles_mean"]:
            raise ValueError(f"{label}: published cycle statistics are inconsistent.")
    if "execution_count" in timing:
        count = timing["execution_count"]
        if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
            raise ValueError(f"{label}.execution_count must be a positive integer.")


def load_profiles(path):
    """Read a schema-version-1 JSON file and return its validated profile map.

    Missing algorithms and operations remain unavailable; no zero or proxy
    fallback is inserted. The caller explicitly selects sender and receiver
    profiles, then draws from returned timing lists with its own seeded RNG.
    """
    with Path(path).open("r", encoding="utf-8") as handle:
        document = json.load(handle, object_pairs_hook=_unique_object)
    if not isinstance(document, dict) or type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        raise ValueError("Hardware profile schema_version must be 1.")
    profiles = document.get("profiles")
    if not isinstance(profiles, dict) or not profiles:
        raise ValueError("Hardware profiles must be a nonempty object.")
    for identifier, profile in profiles.items():
        _nonempty_text(identifier, "profile identifier")
        if not isinstance(profile, dict) or profile.get("id") != identifier:
            raise ValueError(f"Profile {identifier} must be an object with a matching id.")
        for field in ("label", "platform"):
            _nonempty_text(profile.get(field), f"{identifier}.{field}")
        if not isinstance(profile.get("kind"), str) or profile["kind"] not in PROFILE_KINDS:
            raise ValueError(f"Unknown hardware profile kind for {identifier}.")
        algorithms = profile.get("algorithms")
        if not isinstance(algorithms, dict) or not algorithms:
            raise ValueError(f"{identifier}.algorithms must be a nonempty object.")
        for algorithm, entry in algorithms.items():
            label = f"{identifier}.{algorithm}"
            _nonempty_text(algorithm, "algorithm")
            if not isinstance(entry, dict):
                raise ValueError(f"{label} must be an object.")
            _nonempty_text(entry.get("implementation"), f"{label}.implementation")
            if not isinstance(entry.get("equivalence"), str) or entry["equivalence"] not in EQUIVALENCES:
                raise ValueError(f"{label}.equivalence must distinguish exact parameters, proxy, or assumption.")
            sources = entry.get("source_urls")
            if not isinstance(sources, list) or any(not isinstance(url, str) or not url.startswith("https://") for url in sources):
                raise ValueError(f"{label}.source_urls must be a list of HTTPS source URLs.")
            if entry["equivalence"] != "assumed" and not sources:
                raise ValueError(f"{label}: non-assumed timings require a source.")
            if entry["equivalence"] in {"lineage_proxy", "assumed"}:
                _nonempty_text(entry.get("limitation"), f"{label}.limitation")
            operations = entry.get("operations")
            if not isinstance(operations, dict) or not operations:
                raise ValueError(f"{label}.operations must be a nonempty object.")
            for operation, timing in operations.items():
                if operation not in OPERATIONS:
                    raise ValueError(f"Unknown operation {operation} in {label}.")
                _validate_timing(timing, f"{label}.{operation}")
                if entry["equivalence"] == "assumed" and timing["sample_kind"] != "assumed_constant":
                    raise ValueError(f"{label}: an assumed algorithm must use assumed_constant timings.")
                if entry["equivalence"] != "assumed" and timing["sample_kind"] == "assumed_constant":
                    raise ValueError(f"{label}: assumed_constant timings require assumed equivalence.")
    return profiles


def timing_samples_ms(profile, algorithm, operation):
    """Return a fresh list of service times, rejecting unavailable operations."""
    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise ValueError(f"Unknown hardware operation: {operation}.")
    try:
        timing = profile["algorithms"][algorithm]["operations"][operation]
    except (KeyError, TypeError) as exc:
        identifier = profile.get("id", "unnamed") if isinstance(profile, dict) else "invalid"
        raise ValueError(f"Hardware timing unavailable: {identifier}, {algorithm}, {operation}.") from exc
    _validate_timing(timing, f"{algorithm}.{operation}")
    return [float(value) for value in timing["samples_ms"]]
