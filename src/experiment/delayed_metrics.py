"""Separate reception, later authentication, and unfinished observation windows.

Times are seconds. A trace's relative timestamp is an emission proxy, not a
measured aircraft state-generation time. Authentication delays therefore do
not establish the age of the underlying onboard measurement.
"""

from collections import Counter, defaultdict
import math


AUTHENTICATED = {"modeled_authenticated", "authenticated"}
DEFINITIVE_FAILURES = {
    "original_lost", "unsigned_tail", "sender_queue_overflow",
    "transmission_queue_overflow", "receiver_queue_overflow", "fragments_lost",
    "missing_message", "ambiguous_message", "replay", "wrong_session", "unknown_key",
    "invalid_signature", "malformed_object", "verification_unavailable", "association_mismatch",
}
UNRESOLVED = {
    "pending_formation", "pending_sender_queue", "pending_signing",
    "pending_transmission_queue", "pending_transmission", "pending_reception",
    "pending_original_messages", "pending_verification_queue", "pending_verifying",
    "pending", "unresolved", "censored", "censored_horizon",
}


def _number(value, label, *, missing=False):
    if missing and value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{label} must be a finite number.")
    try:
        value = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be a finite number.") from exc
    if missing and math.isnan(value):
        return None
    if not math.isfinite(value):
        raise ValueError(f"{label} must be a finite number.")
    return value


def _stats(values, prefix):
    ordered = sorted(values)
    if not ordered:
        return {f"{prefix}_count": 0, **{f"{prefix}_{key}": None for key in ("mean", "p50", "p95", "p99", "max")}}
    result = {f"{prefix}_count": len(ordered), f"{prefix}_mean": sum(ordered) / len(ordered),
              f"{prefix}_max": ordered[-1]}
    for percentage in (50, 95, 99):
        result[f"{prefix}_p{percentage}"] = ordered[math.ceil(len(ordered) * percentage / 100) - 1]
    return result


def _fraction(numerator, denominator):
    return numerator / denominator if denominator else None


def _array(values, count, label):
    values = list(values)
    if len(values) != count:
        raise ValueError(f"{label} must contain one value per source record.")
    return values


def _mask(values, count, label):
    result = _array(values, count, label)
    if any(value not in (False, True) for value in result):
        raise ValueError(f"{label} must contain boolean reception indicators.")
    return [bool(value) for value in result]


def _information_age(events, start, end, horizon):
    """Integrate age only after first known information; old arrivals never regress it."""
    events = sorted(events)
    updates = []
    newest = None
    for arrival, source in events:
        if newest is None or source > newest:
            newest = source
            if updates and updates[-1][0] == arrival:
                updates[-1] = (arrival, source)
            else:
                updates.append((arrival, source))
    integral, known_seconds, maximum = 0.0, 0.0, None
    first_known = None
    latest_at_end = None
    for index, (arrival, source) in enumerate(updates):
        if arrival > end:
            break
        first_known = max(start, arrival) if first_known is None else first_known
        latest_at_end = source
        left = max(start, arrival)
        right = min(end, updates[index + 1][0] if index + 1 < len(updates) else end)
        if right > left:
            interval = right - left
            integral += interval * ((left - source) + (right - source)) / 2
            known_seconds += interval
            maximum = max(maximum if maximum is not None else 0, right - source)
    duration = end - start
    if latest_at_end is not None and maximum is None:
        maximum = end - latest_at_end
    latest_at_horizon = max((source for arrival, source in events if arrival <= horizon), default=None)
    return {
        "known_seconds": known_seconds,
        "unknown_seconds": max(0.0, duration - known_seconds),
        "known_time_fraction": _fraction(known_seconds, duration),
        "first_known_delay_s": None if first_known is None else first_known - start,
        "age_integral_s2": integral,
        "time_weighted_mean_age_s": _fraction(integral, known_seconds),
        "maximum_age_s": maximum,
        "age_at_capture_end_s": None if latest_at_end is None else end - latest_at_end,
        "age_at_horizon_s": None if latest_at_horizon is None else horizon - latest_at_horizon,
        "fresh_update_count_within_capture": sum(start <= arrival <= end for arrival, _ in updates),
    }


def summarize(records, baseline_received, augmented_received, reception_times,
              authenticated_at, message_outcomes, *, horizon, thresholds_s,
              baseline_reception_times=None, ordinary_tx_delays=None):
    """Summarize paired reception and authentication observed by ``horizon``.

    All arrays follow ``records`` order; missing authentication times are NaN
    or None. Reception timestamps may be missing only when the corresponding
    mask is false. A received message may remain unresolved at the horizon.

    Overall authentication fractions are achieved coverage by the horizon,
    not estimates that unfinished messages will never authenticate. Each
    threshold uses a fixed cohort with its entire source- or reception-based
    follow-up interval observed. A pending eligible message misses that
    threshold while remaining unresolved for eventual authentication.

    Freshness integrates the age of the newest known source observation over
    the capture window [first source timestamp, last source timestamp], per
    aircraft. Unknown initial time is reported separately, never assigned zero
    age. Interarrival gaps compare receptions from the same aircraft only.
    """
    records = list(records)
    if not records:
        raise ValueError("Metrics require at least one source record.")
    count = len(records)
    source_times = [_number(record["relative_time_s"], "source time") for record in records]
    if any(time < 0 for time in source_times):
        raise ValueError("Source times must be nonnegative.")
    if len({record["trace_id"] for record in records}) != count:
        raise ValueError("Source trace IDs must be unique.")
    if any(not isinstance(record.get("icao"), str) or not record["icao"] for record in records):
        raise ValueError("Every source record requires an aircraft identifier.")
    start, end = min(source_times), max(source_times)
    horizon = _number(horizon, "horizon")
    if horizon < end:
        raise ValueError("The observation horizon must cover all source emissions.")
    thresholds = [_number(value, "coverage threshold") for value in thresholds_s]
    if not thresholds or any(value < 0 for value in thresholds) or len(set(thresholds)) != len(thresholds):
        raise ValueError("Coverage thresholds must be nonempty, unique and nonnegative.")
    thresholds.sort()
    baseline = _mask(baseline_received, count, "baseline_received")
    augmented = _mask(augmented_received, count, "augmented_received")
    received_at = [_number(value, "reception time", missing=True)
                   for value in _array(reception_times, count, "reception_times")]
    baseline_at = received_at if baseline_reception_times is None else [
        _number(value, "baseline reception time", missing=True)
        for value in _array(baseline_reception_times, count, "baseline_reception_times")]
    authenticated = [_number(value, "authentication time", missing=True)
                     for value in _array(authenticated_at, count, "authenticated_at")]
    outcomes = _array(message_outcomes, count, "message_outcomes")
    if any(not isinstance(outcome, str) or outcome not in AUTHENTICATED | DEFINITIVE_FAILURES | UNRESOLVED
           for outcome in outcomes):
        raise ValueError("Every message outcome must explicitly identify authentication, definitive failure, or unresolved work.")
    success, failed, unresolved = [], [], []
    for index, source in enumerate(source_times):
        for mask, times, label in ((baseline, baseline_at, "baseline"), (augmented, received_at, "augmented")):
            if mask[index] and (times[index] is None or not source <= times[index] <= horizon):
                raise ValueError(f"{label} reception for record {index} must fall between emission and horizon.")
        time, outcome = authenticated[index], outcomes[index]
        is_success = outcome in AUTHENTICATED
        if is_success != (time is not None):
            raise ValueError("Only authenticated outcomes may have authentication times, and each requires a time.")
        if is_success and (not augmented[index] or not received_at[index] <= time <= horizon):
            raise ValueError("Authentication requires an actually received original and completion between reception and horizon.")
        if outcome == "original_lost" and augmented[index]:
            raise ValueError("A received original cannot have outcome original_lost.")
        success.append(is_success)
        failed.append(outcome in DEFINITIVE_FAILURES)
        unresolved.append(outcome in UNRESOLVED)
    tx_delays = [0.0] * count if ordinary_tx_delays is None else [
        _number(value, "ordinary transmission delay", missing=True)
        for value in _array(ordinary_tx_delays, count, "ordinary_tx_delays")]
    if any(value is not None and value < 0 for value in tx_delays):
        raise ValueError("Ordinary transmission delays must be nonnegative.")
    baseline_count, augmented_count, success_count = sum(baseline), sum(augmented), sum(success)
    if success_count + sum(failed) + sum(unresolved) != count or success_count > augmented_count:
        raise ValueError("Reception/authentication message accounting does not conserve the source records.")
    result = {
        "source_messages": count, "aircraft_count": len({record["icao"] for record in records}),
        "capture_start_s": start, "capture_end_s": end, "capture_duration_s": end - start,
        "observation_horizon_s": horizon, "followup_after_capture_s": horizon - end,
        "baseline_original_received_messages": baseline_count,
        "augmented_original_received_messages": augmented_count,
        "baseline_original_lost_messages": count - baseline_count,
        "augmented_original_lost_messages": count - augmented_count,
        "baseline_original_received_fraction": baseline_count / count,
        "augmented_original_received_fraction": augmented_count / count,
        "additional_original_loss_messages": sum(before and not after for before, after in zip(baseline, augmented)),
        "original_reception_gain_messages": sum(after and not before for before, after in zip(baseline, augmented)),
        "net_additional_original_loss_messages": baseline_count - augmented_count,
        "net_additional_original_loss_fraction": (baseline_count - augmented_count) / count,
        "authenticated_messages": success_count,
        "authenticated_source_fraction": success_count / count,
        "authenticated_received_fraction": _fraction(success_count, augmented_count),
        "definitive_failure_messages": sum(failed), "unresolved_messages": sum(unresolved),
        "received_definitive_failure_messages": sum(ok and fail for ok, fail in zip(augmented, failed)),
        "received_unresolved_messages": sum(ok and pending for ok, pending in zip(augmented, unresolved)),
        "message_outcomes": dict(sorted(Counter(outcomes).items())),
        "ordinary_transmission_delay_basis": "assumed_zero" if ordinary_tx_delays is None else "supplied_model_delays",
        "ordinary_transmission_delay_unknown_messages": sum(value is None for value in tx_delays),
        **_stats([(time - source) * 1000 for time, source, ok in zip(baseline_at, source_times, baseline) if ok], "baseline_original_delivery_ms"),
        **_stats([(time - source) * 1000 for time, source, ok in zip(received_at, source_times, augmented) if ok], "augmented_original_delivery_ms"),
        **_stats([(time - source) * 1000 for time, source in zip(authenticated, source_times) if time is not None], "source_to_auth_ms"),
        **_stats([(time - received) * 1000 for time, received in zip(authenticated, received_at) if time is not None], "receipt_to_auth_ms"),
        **_stats([value * 1000 for value in tx_delays if value is not None], "ordinary_transmission_delay_ms"),
    }
    coverage = []
    for threshold in thresholds:
        source_eligible = [source + threshold <= horizon for source in source_times]
        receipt_eligible = [ok and received + threshold <= horizon for ok, received in zip(augmented, received_at)]
        source_n, receipt_n = sum(source_eligible), sum(receipt_eligible)
        source_received_n = sum(eligible and ok for eligible, ok in zip(source_eligible, augmented))
        source_success = sum(eligible and time is not None and time <= source + threshold
                             for eligible, time, source in zip(source_eligible, authenticated, source_times))
        receipt_success = sum(eligible and time is not None and time <= received + threshold
                              for eligible, time, received in zip(receipt_eligible, authenticated, received_at))
        coverage.append({
            "threshold_s": threshold,
            "source_eligible_messages": source_n,
            "source_ineligible_due_to_followup_messages": count - source_n,
            "source_eligible_received_messages": source_received_n,
            "source_authenticated_within_threshold_messages": source_success,
            "source_authentication_fraction": _fraction(source_success, source_n),
            "source_received_authentication_fraction": _fraction(source_success, source_received_n),
            "source_eligible_unresolved_at_horizon_messages": sum(eligible and pending for eligible, pending in zip(source_eligible, unresolved)),
            "receipt_eligible_messages": receipt_n,
            "receipt_ineligible_due_to_followup_messages": augmented_count - receipt_n,
            "receipt_authenticated_within_threshold_messages": receipt_success,
            "receipt_authentication_fraction": _fraction(receipt_success, receipt_n),
            "receipt_eligible_unresolved_at_horizon_messages": sum(eligible and pending for eligible, pending in zip(receipt_eligible, unresolved)),
        })
    result["threshold_coverage"] = coverage
    aircraft = defaultdict(list)
    for index, record in enumerate(records):
        aircraft[record["icao"]].append(index)
    freshness, gaps = [], defaultdict(list)
    pooled = {kind: [] for kind in ("baseline_received", "augmented_received", "authenticated")}
    for icao, indexes in sorted(aircraft.items()):
        row = {"icao": icao, "source_messages": len(indexes)}
        streams = {
            "baseline_received": [(baseline_at[index], source_times[index]) for index in indexes if baseline[index]],
            "augmented_received": [(received_at[index], source_times[index]) for index in indexes if augmented[index]],
            "authenticated": [(authenticated[index], source_times[index]) for index in indexes if success[index]],
        }
        for kind, events in streams.items():
            info = _information_age(events, start, end, horizon)
            row[kind] = info
            pooled[kind].append(info)
            arrivals = sorted(arrival for arrival, _ in events)
            intervals = [right - left for left, right in zip(arrivals, arrivals[1:])]
            gaps[kind].extend(intervals)
            row.update(_stats(intervals, f"{kind}_interarrival_gap_s"))
        freshness.append(row)
    result["aircraft_freshness"] = freshness
    for kind, infos in pooled.items():
        known = sum(info["known_seconds"] for info in infos)
        integral = sum(info["age_integral_s2"] for info in infos)
        maximum = [info["maximum_age_s"] for info in infos if info["maximum_age_s"] is not None]
        prefix = f"{kind}_information_age"
        result.update({
            f"{prefix}_known_aircraft_seconds": known,
            f"{prefix}_unknown_aircraft_seconds": len(aircraft) * (end - start) - known,
            f"{prefix}_known_time_fraction": _fraction(known, len(aircraft) * (end - start)),
            f"{prefix}_time_weighted_mean_s": _fraction(integral, known),
            f"{prefix}_max_s": max(maximum) if maximum else None,
            f"{prefix}_unknown_aircraft_at_capture_end": sum(info["age_at_capture_end_s"] is None for info in infos),
            f"{prefix}_unknown_aircraft_at_horizon": sum(info["age_at_horizon_s"] is None for info in infos),
            **_stats([info["age_at_capture_end_s"] for info in infos if info["age_at_capture_end_s"] is not None], f"{prefix}_at_capture_end_s"),
            **_stats([info["age_at_horizon_s"] for info in infos if info["age_at_horizon_s"] is not None], f"{prefix}_at_horizon_s"),
            **_stats(gaps[kind], f"{kind}_interarrival_gap_s"),
        })
    result["metric_notes"] = [
        "Source times are trace emission proxies; onboard measurement generation times and physical avionics processing latency are unknown.",
        "Overall authenticated fractions are achieved coverage by the declared horizon; unresolved work is reported separately from definitive failure.",
        "Delay percentiles condition on completed reception or authentication and must be read with loss and unresolved counts.",
        "Each coverage threshold uses only messages with a complete observation interval from its stated source or reception anchor; ineligible horizon-edge messages are excluded.",
        "Interarrival gaps are between consecutive successful arrivals observed by the horizon for the same aircraft; initial and trailing silence is instead exposed by freshness coverage and boundary ages.",
        "Information age uses the newest known source timestamp, never moves backward on late old authentication, and integrates only time after first information becomes known.",
        "Freshness uses a common capture window for every observed aircraft; unknown initial periods are explicit, and aircraft presence outside its observations is not inferred.",
    ]
    return result
