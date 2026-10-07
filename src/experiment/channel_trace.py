"""Load observed 1090 MHz interference without filtering by decoded message type.

The channel trace contains target DF17 observations as well as every additional
observed emission. Explicit target references prevent counting target traffic
twice. This validates alignment and the declared recording window; it cannot
establish that a receiver captured every real-world transmission.
"""

import json
import math
from pathlib import Path


FRAME_S = 120e-6


def _number(value, name, *, minimum=None, positive=False):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number, excluding booleans.")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be at least {minimum}.")
    if positive and value <= 0:
        raise ValueError(f"{name} must be positive.")
    return float(value)


def _same_time(left, right):
    return math.isclose(left, right, rel_tol=0,
                        abs_tol=max(1e-12, 4 * math.ulp(left), 4 * math.ulp(right)))


def _origin_matches(origin, timestamp, relative_time):
    # Subtracting a modern Unix epoch timestamp loses precision compared with
    # directly storing relative seconds. Do not use a relative tolerance on the
    # epoch itself: that would permit seconds of clock misalignment.
    derived = timestamp - relative_time
    tolerance = max(1e-12, 4 * math.ulp(origin), 4 * math.ulp(timestamp),
                    4 * math.ulp(relative_time), 4 * math.ulp(derived))
    return math.isclose(origin, derived, rel_tol=0, abs_tol=tolerance)


def _rows(path):
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, ValueError) as error:
                raise ValueError(f"Invalid channel trace JSON at line {line_number}.") from error
            if not isinstance(record, dict):
                raise ValueError(f"Channel trace line {line_number} must be an object.")
            yield line_number, record


def load_channel_trace(path, trace):
    """Return non-target envelopes and metadata for a canonical channel JSONL.

    The first nonempty row declares schema version 1, kind ``channel_trace``,
    ``time_origin_timestamp``, ``coverage_start_s`` (zero), and
    ``coverage_end_s``. Following rows require a unique string/integer
    ``event_id``, nonnegative ``relative_time_s``, and positive ``duration_s``.
    Every replay target must occur exactly once with ``target_trace_id``; other
    rows need neither decoded bytes nor an aircraft address. Event order and
    repeated payloads do not affect inclusion.

    Recording coverage is declared independently of its final event, and is
    checked against the simulation follow-up by :func:`validate_coverage`.
    Offered airtime sums full envelopes whose *start* lies in each window;
    this additive quantity is not measured occupied spectrum.
    """
    records = list(trace.values()) if isinstance(trace, dict) else list(trace)
    if not records:
        raise ValueError("A nonempty target trace is required for channel alignment.")
    targets = {}
    for record in records:
        identifier = record.get("trace_id")
        if type(identifier) is not int:
            raise ValueError("Target trace_id must be an integer, excluding booleans.")
        if identifier in targets:
            raise ValueError(f"Duplicate target trace_id {identifier}.")
        relative = _number(record.get("relative_time_s"), "Target relative_time_s", minimum=0)
        timestamp = _number(record.get("timestamp"), "Target timestamp")
        targets[identifier] = (relative, timestamp)

    rows = iter(_rows(path))
    try:
        _, header = next(rows)
    except StopIteration as error:
        raise ValueError("Channel trace requires a metadata header.") from error
    if type(header.get("schema_version")) is not int or header["schema_version"] != 1:
        raise ValueError("Channel trace schema_version must be 1.")
    if header.get("kind") != "channel_trace":
        raise ValueError("Channel trace header kind must be 'channel_trace'.")
    origin = _number(header.get("time_origin_timestamp"), "time_origin_timestamp")
    coverage_start = _number(header.get("coverage_start_s"), "coverage_start_s", minimum=0)
    if coverage_start != 0:
        raise ValueError("Channel trace coverage_start_s must be zero.")
    coverage_end = _number(header.get("coverage_end_s"), "coverage_end_s", minimum=0)
    target_start = min(relative for relative, _ in targets.values())
    target_end = max(relative for relative, _ in targets.values())
    if target_end > coverage_end and not _same_time(target_end, coverage_end):
        raise ValueError("Channel recording coverage ends before the target trace.")
    for identifier, (relative, timestamp) in targets.items():
        if not _origin_matches(origin, timestamp, relative):
            raise ValueError(f"Channel time origin does not align with target trace_id {identifier}.")

    seen_events, seen_targets = set(), set()
    extra_starts, extra_durations = [], []
    target_airtime, extra_airtime, extra_target_window_airtime = [], [], []
    extra_in_target_window = 0
    for line_number, row in rows:
        identifier = row.get("event_id")
        if type(identifier) not in (str, int) or identifier == "":
            raise ValueError(f"Channel event_id at line {line_number} must be a nonempty string or integer.")
        if identifier in seen_events:
            raise ValueError(f"Duplicate channel event_id {identifier!r}.")
        seen_events.add(identifier)
        start = _number(row.get("relative_time_s"), "Channel relative_time_s", minimum=0)
        duration = _number(row.get("duration_s"), "Channel duration_s", positive=True)
        if not math.isfinite(start + duration):
            raise ValueError("Channel envelope end must be finite.")
        if start > coverage_end and not _same_time(start, coverage_end):
            raise ValueError(f"Channel event {identifier!r} starts outside declared recording coverage.")
        if "target_trace_id" in row:
            target_id = row["target_trace_id"]
            if type(target_id) is not int:
                raise ValueError("target_trace_id must be an integer, excluding booleans.")
            if target_id not in targets:
                raise ValueError(f"Unknown target_trace_id {target_id} in channel trace.")
            if target_id in seen_targets:
                raise ValueError(f"Duplicate target_trace_id {target_id} in channel trace.")
            if not _same_time(start, targets[target_id][0]):
                raise ValueError(f"Channel event time does not match target_trace_id {target_id}.")
            if not _same_time(duration, FRAME_S):
                raise ValueError(f"Target DF17 event {target_id} must have duration_s {FRAME_S}.")
            seen_targets.add(target_id)
            target_airtime.append(duration)
        else:
            extra_starts.append(start)
            extra_durations.append(duration)
            extra_airtime.append(duration)
            if target_start <= start <= target_end:
                extra_in_target_window += 1
                extra_target_window_airtime.append(duration)

    missing = set(targets) - seen_targets
    if missing:
        raise ValueError(f"Channel trace is missing {len(missing)} target trace event(s).")
    target_seconds = math.fsum(target_airtime)
    extra_seconds = math.fsum(extra_airtime)
    extra_window_seconds = math.fsum(extra_target_window_airtime)
    target_duration = target_end - target_start
    summary = {
        "schema_version": 1,
        "time_origin_timestamp": origin,
        "coverage_start_s": coverage_start,
        "coverage_end_s": coverage_end,
        "coverage_duration_s": coverage_end - coverage_start,
        "target_window_start_s": target_start,
        "target_window_end_s": target_end,
        "target_window_duration_s": target_duration,
        "total_frames": len(seen_events),
        "target_frames": len(seen_targets),
        "non_target_frames": len(extra_starts),
        "non_target_frames_within_target_window": extra_in_target_window,
        "airtime_accounting": "Full frame envelopes, selected by start time; additive offered airtime, not RF occupancy.",
        "completeness": "Declared observed channel coverage; completeness of real-world RF traffic is not inferred.",
    }
    for prefix, whole, window in (
        ("target", target_seconds, target_seconds),
        ("non_target", extra_seconds, extra_window_seconds),
        ("total", target_seconds + extra_seconds, target_seconds + extra_window_seconds),
    ):
        summary[f"{prefix}_offered_airtime_s"] = whole
        summary[f"{prefix}_offered_airtime_within_target_window_s"] = window
        summary[f"{prefix}_offered_load"] = whole / coverage_end if coverage_end else None
        summary[f"{prefix}_offered_load_within_target_window"] = window / target_duration if target_duration else None
    for name in ("acquisition", "provenance"):
        if name in header:
            summary[name] = header[name]
    return {
        "extra_starts": extra_starts,
        "extra_durations_s": extra_durations,
        "coverage_end_s": coverage_end,
        "summary": summary,
    }


def validate_coverage(channel_trace, horizon):
    """Reject a replay that extends past the explicitly declared RF recording.

    A last observed event does not prove when recording stopped. Conversely,
    missing recording coverage cannot be treated as a traffic-free drain period.
    """
    horizon = _number(horizon, "Required channel horizon", minimum=0)
    coverage_end = _number(channel_trace.get("coverage_end_s"), "coverage_end_s", minimum=0)
    if horizon > coverage_end and not _same_time(horizon, coverage_end):
        raise ValueError(
            f"Observed channel coverage ends at {coverage_end:g} s, before the required "
            f"{horizon:g} s horizon including authentication follow-up. Supply channel "
            "observations covering the follow-up; missing coverage is not empty traffic."
        )
