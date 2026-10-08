"""Bound replay resources before creating expensive cryptographic workloads.

This diagnostic schedules counts, never fake signatures or scientific results.
For fixed signature sizes it follows the detached radio scheduler without
allocating an array for every authentication frame. Receiver event counts are
bounds because successful reconstruction is not known until the real replay.
Variable-size signatures receive deliberately conservative frame bounds.
"""

from collections import Counter, defaultdict, deque
import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import time

from .hardware_profiles import timing_samples_ms
from .model_support import FRAME_S, validate_scenario
from .replay_transport import OBJECT_FIXED_BYTES, TAG_BYTES, fragment_count


def _positive_integer(value, name, *, zero=False):
    if type(value) is not int or value < (0 if zero else 1):
        raise ValueError(f"{name} must be a {'nonnegative' if zero else 'positive'} integer.")
    return value


def _finite(value, name, *, zero=True):
    if (isinstance(value, bool) or not isinstance(value, (int, float))
            or not math.isfinite(value) or value < 0 or (not zero and value == 0)):
        raise ValueError(f"{name} must be finite and {'nonnegative' if zero else 'positive'}.")
    return float(value)


def count_detached_radio(original_times, sign_ends, frames_per_group, rate, horizon):
    """Count the exact unbounded-queue schedule for one aircraft.

    Inputs are ordered source releases, ordered signing completions, and the
    fixed physical fragment count per group (including any configured copies).
    The arithmetic and release ordering mirror ``_schedule_detached_radio``.
    Memory is proportional to groups, not to the emitted frame count.
    """
    _positive_integer(frames_per_group, "frames_per_group")
    rate = _finite(rate, "rate", zero=False)
    horizon = _finite(horizon, "horizon")
    if rate > 1 / FRAME_S:
        raise ValueError("rate exceeds the radio's frame service capacity.")
    if not original_times:
        if sign_ends:
            raise ValueError("Signing completions require source messages.")
        return {"auth_frames": 0, "completed_objects": 0, "completed_originals": 0}
    for values, label in ((original_times, "original_times"), (sign_ends, "sign_ends")):
        previous = -math.inf
        for value in values:
            _finite(value, label)
            if value < previous:
                raise ValueError(f"{label} must be ordered.")
            previous = value
    available = [time for time in sign_ends if time <= horizon]
    step = 1 / rate
    original_index = group_index = frames = completed_objects = completed_originals = 0
    queue = deque()
    now, gate = original_times[0], 0.0
    while now <= horizon:
        while group_index < len(available) and available[group_index] <= now:
            queue.append(frames_per_group)
            group_index += 1
        if original_index < len(original_times) and original_times[original_index] <= now:
            original_index += 1
            now += FRAME_S
            completed_originals += now <= horizon
            continue
        original_release = original_times[original_index] if original_index < len(original_times) else math.inf
        auth_release = available[group_index] if group_index < len(available) else math.inf
        release = min(original_release, auth_release)
        if not queue:
            if not math.isfinite(release):
                break
            now = max(now, release)
            continue
        first = max(now, gate)
        if release <= first:
            now = max(now, release)
            continue
        if first > horizon:
            break
        count = min(queue[0], int(math.floor((horizon - first) / step)) + 1)
        if math.isfinite(release):
            count = min(count, max(1, int(math.ceil((release - first) / step))))
            while count > 1 and first + (count - 1) * step >= release:
                count -= 1
        # Match the engine's final times[times <= horizon] floating-point guard.
        while count and first + (count - 1) * step > horizon:
            count -= 1
        if not count:
            break
        last = first + (count - 1) * step
        frames += count
        queue[0] -= count
        now, gate = last + FRAME_S, last + step
        if not queue[0]:
            while group_index < len(available) and available[group_index] < now:
                queue.append(frames_per_group)
                group_index += 1
            queue.popleft()
            completed_objects += now <= horizon
    return {"auth_frames": frames, "completed_objects": completed_objects,
            "completed_originals": completed_originals}


def _size_bounds(algorithm, configuration, supplied):
    expected = configuration.get("expected_signature_bytes")
    if expected is not None:
        expected = _positive_integer(expected, f"{algorithm} signature size")
        return expected, expected
    bounds = supplied.get(algorithm)
    if not isinstance(bounds, (tuple, list)) or len(bounds) != 2:
        raise ValueError(f"{algorithm}: supply signature_size_bounds from the installed backend; "
                         "variable signature sizes have no implicit maximum.")
    lower = _positive_integer(bounds[0], "signature size lower bound", zero=True)
    upper = _positive_integer(bounds[1], "signature size upper bound")
    if lower > upper:
        raise ValueError("Signature size lower bound exceeds its upper bound.")
    return lower, upper


def _verdict(lower, upper, budget):
    if lower > budget:
        return "exceeds"
    return "within_bound" if upper <= budget else "undetermined"


def build_resource_preflight(trace, algorithm_configs, profiles, scenarios, intervals, *,
                             horizon_s, observed_frames, signature_size_bounds=None,
                             host_benchmark=None):
    """Return a JSON-serializable resource report without generating signatures.

    ``trace`` is the prepared DF17 iterable (or trace-id dictionary).
    ``observed_frames`` counts additional observed channel events whose starts
    are at or before ``horizon_s``; it must EXCLUDE every target already in trace.
    ``scenarios`` are the entries in signed_replay_scenarios.json. The current
    exact-count detached experiment with unbounded queues and constant sender
    service times is supported. Unsupported settings raise before any work.

    For a variable signature algorithm, explicitly supply ``(0, maximum)`` or
    tighter proven byte bounds from the installed backend. Its emitted frame
    lower bound is zero; its upper bound allows continuous radio pacing after
    the earliest completed group and never assumes a signature was generated.

    Optional ``host_benchmark`` is diagnostic metadata with a ``rows`` list of
    ``algorithm``, ``k``, and ``sign_median_ms`` measurements. It affects only
    host runtime extrapolation, never the simulated service time or event bound.
    The caller supplies recording provenance and any provisional-data warning.
    """
    horizon = _finite(horizon_s, "horizon_s")
    observed_frames = _positive_integer(observed_frames, "observed_frames", zero=True)
    intervals = list(intervals)
    if not intervals or len(set(intervals)) != len(intervals):
        raise ValueError("intervals must be nonempty and unique.")
    for interval in intervals:
        _positive_integer(interval, "interval")
    supplied = signature_size_bounds or {}
    algorithms = {name: configuration for name, configuration in algorithm_configs.items()
                  if configuration.get("enabled", True)}
    if not algorithms:
        raise ValueError("At least one enabled algorithm is required.")
    sizes = {name: _size_bounds(name, configuration, supplied)
             for name, configuration in algorithms.items()}
    aircraft = defaultdict(list)
    identifiers = set()
    values = trace.values() if isinstance(trace, dict) else trace
    for row in values:
        identifier = _positive_integer(row["trace_id"], "trace_id", zero=True)
        if identifier in identifiers:
            raise ValueError("Duplicate trace_id.")
        identifiers.add(identifier)
        time = row["relative_time_s"]
        _finite(time, "relative_time_s")
        if time > horizon:
            raise ValueError("A target lies after the observation horizon.")
        aircraft[row["icao"]].append((time, identifier))
    if not identifiers:
        raise ValueError("A nonempty trace is required.")
    target_count = len(identifiers)
    del identifiers
    for entries in aircraft.values():
        entries.sort()
    normalized = []
    names = set()
    for scenario in scenarios:
        name = scenario["name"]
        if name in names:
            raise ValueError("Scenario names must be unique.")
        names.add(name)
        parameters = dict(scenario["parameters"])
        if parameters.pop("replay_model", None) != "signed_detached":
            raise ValueError("Resource preflight supports only signed_detached scenarios.")
        p = validate_scenario(parameters)
        if p["max_batch_wait_s"] is not None or any(p[key] is not None for key in
                ("sender_queue_limit", "transmission_queue_limit", "receiver_queue_limit")):
            raise ValueError("Resource preflight requires exact-count grouping and unbounded queues.")
        if p["background_frames_per_second"]:
            raise ValueError("Resource preflight requires observed, not synthetic, background.")
        for algorithm in algorithms:
            samples = timing_samples_ms(profiles[scenario["sender_profile"]], algorithm, "sign")
            if len(samples) != 1:
                raise ValueError("Resource preflight requires constant sender service times.")
        normalized.append((scenario, p))
    if not normalized:
        raise ValueError("At least one scenario is required.")
    # JSON framing and decimal trace IDs are counted exactly. Only encoded
    # signature length can vary. Public-key and manifest overhead is separate.
    empty_row_bytes = len(json.dumps({"members": [], "formed_s": 0, "envelope": ""},
                                    sort_keys=True, separators=(",", ":"))) + 1
    workloads, cases, schedules = [], [], {}
    host_rows = {}
    if host_benchmark is not None:
        for row in host_benchmark.get("rows", []):
            key = (row["algorithm"], row["k"])
            if key in host_rows:
                raise ValueError("Duplicate host benchmark algorithm/grouping row.")
            host_rows[key] = _finite(row["sign_median_ms"], "sign_median_ms", zero=False)
    for interval in intervals:
        grouped, group_count, row_overhead = {}, 0, 0
        for icao, entries in aircraft.items():
            originals = [time for time, _ in entries]
            formed = originals[interval - 1::interval]
            group_count += len(formed)
            grouped[icao] = (originals, formed)
            for offset, time in enumerate(formed):
                members = entries[offset * interval:(offset + 1) * interval]
                row_overhead += (empty_row_bytes - 1 + len(json.dumps(time))
                                 + sum(len(str(identifier)) for _, identifier in members)
                                 + interval - 1)
        for algorithm, (size_low, size_high) in sizes.items():
            object_low = OBJECT_FIXED_BYTES + TAG_BYTES * interval + size_low
            object_high = OBJECT_FIXED_BYTES + TAG_BYTES * interval + size_high
            fragment_low, fragment_high = fragment_count(object_low), fragment_count(object_high)
            workload = {
                "algorithm": algorithm, "interval_k": interval, "signature_count": group_count,
                "unsigned_tail_messages": target_count - group_count * interval,
                "signature_bytes_lower": group_count * size_low,
                "signature_bytes_upper": group_count * size_high,
                "groups_jsonl_bytes_lower": row_overhead + group_count * 4 * ((object_low + 2) // 3),
                "groups_jsonl_bytes_upper": row_overhead + group_count * 4 * ((object_high + 2) // 3),
                "required_auth_frames_lower": group_count * fragment_low,
                "required_auth_frames_upper": group_count * fragment_high,
            }
            if (algorithm, interval) in host_rows:
                workload["host_serial_sign_seconds_estimate"] = group_count * host_rows[algorithm, interval] / 1000
            workloads.append(workload)
            for scenario, p in normalized:
                service = timing_samples_ms(profiles[scenario["sender_profile"]], algorithm, "sign")[0] / 1000
                cache_key = (interval, service, size_low, size_high,
                             p["auth_frames_per_second"], p["fragment_copies"])
                if cache_key not in schedules:
                    frames_low = frames_high = completed_groups = completed_originals = 0
                    fixed_size = size_low == size_high
                    for originals, formed in grouped.values():
                        ends, previous = [], 0.0
                        for time in formed:
                            previous = max(previous, time) + service
                            if previous <= horizon:
                                ends.append(previous)
                        if fixed_size:
                            counts = count_detached_radio(originals, ends,
                                fragment_low * p["fragment_copies"], p["auth_frames_per_second"], horizon)
                            frames_low += counts["auth_frames"]
                            frames_high += counts["auth_frames"]
                            completed_groups += counts["completed_objects"]
                            completed_originals += counts["completed_originals"]
                        else:
                            # Omitting every ordinary reservation can only
                            # increase this per-aircraft pacing capacity.
                            # One extra frame makes the upper bound robust to
                            # floating-point rounding at a pacing boundary.
                            capacity = (int(math.floor((horizon - ends[0]) * p["auth_frames_per_second"])) + 2
                                        if ends else 0)
                            frames_high += min(capacity, len(ends) * fragment_high * p["fragment_copies"])
                            completed_groups += len(ends)
                            completed_originals += len(originals)
                    schedules[cache_key] = (frames_low, frames_high, completed_groups, completed_originals)
                frames_low, frames_high, objects, originals = schedules[cache_key]
                fixed = target_count + group_count + observed_frames
                lower = fixed + frames_low
                if (size_low == size_high and p["channel_mode"] == "independent"
                        and p["loss"] == {"kind": "iid", "probability": 0}
                        and not p["receive_jitter_ms"]):
                    # Every completed original and object generates a receive
                    # event, even if subsequent association prevents verifying.
                    lower += originals + objects
                upper = fixed + frames_high + originals + 2 * objects
                cases.append({
                    "scenario": scenario["name"], "algorithm": algorithm, "interval_k": interval,
                    "auth_frame_count_kind": "exact_schedule" if size_low == size_high else "conservative_bounds",
                    "auth_frames_lower": frames_low, "auth_frames_upper": frames_high,
                    "fixed_events": fixed, "processed_events_lower": lower, "processed_events_upper": upper,
                    "max_events": p["max_events"], "event_budget_verdict": _verdict(lower, upper, p["max_events"]),
                })
    return {
        "schema_version": 1, "kind": "resource_preflight", "scientific_result": False,
        "target_messages": target_count, "aircraft": len(aircraft), "horizon_s": horizon,
        "additional_observed_frames": observed_frames, "workloads": workloads, "cases": cases,
        "groups_jsonl_bytes_lower": sum(row["groups_jsonl_bytes_lower"] for row in workloads),
        "groups_jsonl_bytes_upper": sum(row["groups_jsonl_bytes_upper"] for row in workloads),
        "host_benchmark": host_benchmark,
        "limitations": [
            "This resource diagnostic does not generate signatures or estimate reception/authentication success.",
            "An event-budget bound is not a RAM or runtime guarantee; each replay also allocates Python objects and NumPy arrays.",
            "Cache byte bounds cover groups.jsonl only; keys, manifests, prepared data and result files require additional space.",
            "Variable signature lengths have conservative emitted-frame bounds, not invented or sampled signature sizes.",
            "Host runtime extrapolation uses short diagnostic signing measurements, excludes all other work, and never changes the embedded profiles.",
        ],
    }


def installed_signature_size_bounds(algorithm_configs):
    """Read variable-size maxima from installed backend metadata; never keygen."""
    result, sources = {}, {}
    variable = {name: configuration for name, configuration in algorithm_configs.items()
                if configuration.get("enabled", True) and configuration.get("expected_signature_bytes") is None}
    if variable:
        from .signed_workload import _installed_oqs
        oqs = _installed_oqs()
        for algorithm, configuration in variable.items():
            implementation = configuration["implementation"]
            with oqs.Signature(implementation) as native:
                maximum = _positive_integer(native.details["length_signature"], "backend signature maximum")
            result[algorithm] = (0, maximum)
            sources[algorithm] = {"backend": "liboqs", "version": oqs.oqs_version(),
                                  "implementation": implementation, "length_signature": maximum,
                                  "interpretation": "Backend maximum; zero is a deliberately loose lower bound."}
    return result, sources


def run_prepared_preflight(config, window):
    """Validate prepared provenance, count resources, and save a diagnostic.

    Recording quality blockers are retained prominently in the report. They do
    not prevent this inspection and are never cleared by it. No signing or
    scientific replay entry point is called.
    """
    from src.main_experiment import preflight_inputs, selected_algorithm_configs
    from src.processing.prepare_recording import validate_prepared_recording
    from src.runtime import RunLock, atomic_json
    from .hardware_profiles import load_profiles
    from .io_support import load_trace, sha256_file
    from .replay_artifacts import load_scenarios

    metadata = preflight_inputs(config, [window])[window]
    algorithm_configs = selected_algorithm_configs(config)
    output = config["windows"][window]["output"]
    prepared = output / "01_prepared"
    # A missing preparation must not create output folders or a lock file.
    if not (prepared / "manifest.json").is_file():
        raise ValueError("Prepared recording is missing; run scripts/01_prepare.py first.")
    with RunLock(output / ".pipeline.lock"):
        manifest = validate_prepared_recording(config["windows"][window]["raw"], prepared, metadata,
                                              config["target_duration_s"], config["followup_s"])
        trace = load_trace(prepared / "trace.jsonl")
        horizon = config["target_duration_s"] + config["followup_s"]
        observed = 0
        with (prepared / "channel.jsonl").open("r", encoding="utf-8") as stream:
            header = json.loads(next(stream))
            if header.get("coverage_end_s", 0) < horizon:
                raise ValueError("Prepared recording does not cover the configured follow-up.")
            for line in stream:
                row = json.loads(line)
                if "target_trace_id" not in row and row["relative_time_s"] <= horizon:
                    observed += 1
        profiles = load_profiles(config["hardware_profiles"])
        scenarios, _ = load_scenarios(config["scenarios"])
        bounds, sources = installed_signature_size_bounds(algorithm_configs)
        benchmark_path = prepared / "host_benchmark.json"
        benchmark = json.loads(benchmark_path.read_text(encoding="utf-8")) if benchmark_path.exists() else None
        start = time.perf_counter()
        report = build_resource_preflight(trace, algorithm_configs, profiles, scenarios, config["intervals"],
            horizon_s=horizon, observed_frames=observed, signature_size_bounds=bounds, host_benchmark=benchmark)
        report.update({
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "counting_wall_seconds": time.perf_counter() - start,
            "prepared_manifest_sha256": sha256_file(prepared / "manifest.json"),
            "source_sha256": manifest["input_sha256"],
            "signature_size_bound_sources": sources,
            "configuration_sha256": {name: sha256_file(config[name]) for name in
                                     ("config_path", "algorithms_config", "hardware_profiles", "scenarios")},
            "experiment_blockers": metadata.get("experiment_blockers", []),
            "input_warning": "Counts describe the supplied recording and its recorded timestamps only. "
                            "This diagnostic does not authorize scientific signing or replay. "
                            "Corrected acquisition timestamps may change the event counts.",
            "event_budget_verdict_counts": dict(Counter(case["event_budget_verdict"] for case in report["cases"])),
        })
        atomic_json(prepared / "resource_preflight.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--window", required=True, choices=("daytime", "nighttime"))
    parser.add_argument("--config", type=Path, default=Path("config/experiment.json"))
    args = parser.parse_args(argv)
    from src.main_experiment import load_config
    try:
        config = load_config(args.config)
        report = run_prepared_preflight(config, args.window)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(2, f"Resource preflight failed: {error}\n")
    print(config["windows"][args.window]["output"] / "01_prepared" / "resource_preflight.json")
    print(json.dumps({"target_messages": report["target_messages"],
                      "cases": len(report["cases"]),
                      "event_budget_verdicts": report["event_budget_verdict_counts"],
                      "scientific_result": False}, sort_keys=True))


if __name__ == "__main__":
    main()
