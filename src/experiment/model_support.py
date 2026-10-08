"""Shared grouping, scenario validation and timing summaries for signed replay."""

from collections import defaultdict
import math


FRAME_S = 120e-6


def _number(value, name, minimum=0, maximum=None, positive=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{name} must be finite.")
    if value < minimum or (positive and value <= minimum) or (maximum is not None and value > maximum):
        raise ValueError(f"{name} is outside the allowed range.")
    return value


def form_groups(records, interval, max_wait):
    """Yield sender batches before loss; incomplete fixed-k tails remain unsigned."""
    if type(interval) is not int or interval < 1:
        raise ValueError("interval must be a positive integer.")
    aircraft = defaultdict(list)
    for record in records:
        aircraft[record["icao"]].append(record)
    groups, unsigned = [], 0
    for icao, entries in sorted(aircraft.items()):
        pending, seq = [], 0
        for record in entries:
            time = record["relative_time_s"]
            if pending and max_wait is not None and time > pending[0]["relative_time_s"] + max_wait:
                seq += 1
                groups.append((icao, seq, pending, pending[0]["relative_time_s"] + max_wait))
                pending = []
            pending.append(record)
            if len(pending) == interval:
                seq += 1
                groups.append((icao, seq, pending, time))
                pending = []
        if pending:
            if max_wait is None:
                unsigned += len(pending)
            else:
                seq += 1
                groups.append((icao, seq, pending, pending[0]["relative_time_s"] + max_wait))
    groups.sort(key=lambda item: (item[3], item[0], item[1]))
    return groups, unsigned


def _quantiles(values, prefix):
    if not values:
        return {prefix + suffix: None for suffix in ("_mean", "_p50", "_p95", "_p99", "_max")}
    values = sorted(values)
    result = {prefix + "_mean": sum(values) / len(values), prefix + "_max": values[-1]}
    for quantile in (50, 95, 99):
        result[prefix + f"_p{quantile}"] = values[math.ceil(quantile / 100 * len(values)) - 1]
    return result
def validate_loss(loss):
    if not isinstance(loss, dict):
        raise ValueError("loss must be an object.")
    if loss.get("kind") == "iid":
        if set(loss) != {"kind", "probability"}:
            raise ValueError("IID loss requires exactly kind and probability.")
        _number(loss["probability"], "loss probability", maximum=1)
    elif loss.get("kind") == "gilbert_elliott":
        if set(loss) != {"kind", "good_loss", "bad_loss", "mean_good_s", "mean_bad_s"}:
            raise ValueError("Burst loss requires good/bad loss probabilities and mean state durations.")
        for name in ("good_loss", "bad_loss"):
            _number(loss[name], name, maximum=1)
        for name in ("mean_good_s", "mean_bad_s"):
            _number(loss[name], name, positive=True)
    else:
        raise ValueError("Unknown loss model.")


DEFAULTS = {
    "followup_s": 600.0, "coverage_thresholds_s": [1, 5, 10, 30, 60, 300, 600],
    "max_batch_wait_s": None, "auth_frames_per_second": 100.0,
    "sender_queue_limit": None, "transmission_queue_limit": None,
    "receiver_queue_limit": None, "receiver_workers": 1,
    "fragment_copies": 1, "receive_jitter_ms": 0.0,
    "loss": {"kind": "iid", "probability": 0.0},
    "channel_mode": "destructive_overlap", "background_frames_per_second": 0.0,
    "max_events": 100_000_000, "record_events": False,
}


def validate_scenario(scenario):
    if not isinstance(scenario, dict) or set(scenario) - set(DEFAULTS):
        raise ValueError("Unknown delayed-authentication scenario parameter.")
    p = {**DEFAULTS, **scenario}
    _number(p["followup_s"], "followup_s")
    _number(p["auth_frames_per_second"], "auth_frames_per_second", positive=True,
            maximum=1 / FRAME_S)
    _number(p["receive_jitter_ms"], "receive_jitter_ms")
    _number(p["background_frames_per_second"], "background_frames_per_second")
    if p["max_batch_wait_s"] is not None:
        _number(p["max_batch_wait_s"], "max_batch_wait_s", positive=True)
    for name in ("sender_queue_limit", "transmission_queue_limit", "receiver_queue_limit"):
        if p[name] is not None and (type(p[name]) is not int or p[name] < 1):
            raise ValueError(f"{name} must be null or a positive integer.")
    for name in ("receiver_workers", "fragment_copies", "max_events"):
        if type(p[name]) is not int or p[name] < 1:
            raise ValueError(f"{name} must be a positive integer.")
    if type(p["record_events"]) is not bool:
        raise ValueError("record_events must be boolean.")
    if p["channel_mode"] not in {"independent", "destructive_overlap"}:
        raise ValueError("Unknown channel_mode.")
    thresholds = p["coverage_thresholds_s"]
    if not isinstance(thresholds, list) or not thresholds:
        raise ValueError("coverage_thresholds_s must be a nonempty list.")
    for value in thresholds:
        _number(value, "coverage threshold", positive=True)
    if thresholds != sorted(set(thresholds)):
        raise ValueError("Coverage thresholds must be increasing and unique.")
    validate_loss(p["loss"])
    return p


def _queue_full(waiting, now, limit):
    while waiting and waiting[0] <= now:
        waiting.popleft()
    return limit is not None and len(waiting) >= limit
