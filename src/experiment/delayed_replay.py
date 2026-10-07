"""Separate surveillance reception from later authentication, with paired RF runs.

The sender schedule is independent of receiver outcomes: there is no feedback.
This lets us construct transmissions, evaluate their shared-channel overlap,
then replay receiver arrivals and verification queues without a per-group age
cutoff. A finite follow-up window censors unfinished work instead of expiring it.
"""

from bisect import bisect_right
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
import hashlib
import heapq
import math
import random

import numpy as np

from .delayed_metrics import summarize
from .hardware_profiles import timing_samples_ms
from .replay_simulator import FRAME_S, form_groups, _number, _quantiles, validate_scenario as validate_legacy
from .replay_transport import ReplayReceiver, describe_group, fragment_count, object_size_bytes
from .shared_channel import evaluate_channel


DEFAULTS = {
    "followup_s": 60.0, "coverage_thresholds_s": [1, 5, 10, 30, 60],
    "max_batch_wait_s": None, "auth_frames_per_second": 100.0,
    "sender_queue_limit": None, "transmission_queue_limit": None,
    "receiver_queue_limit": None, "receiver_workers": 1,
    "fragment_copies": 1, "receive_jitter_ms": 0.0,
    "loss": {"kind": "iid", "probability": 0.01},
    "channel_mode": "destructive_overlap", "background_frames_per_second": 0.0,
    "max_events": 100_000_000, "record_events": False,
}
ASSUMPTIONS = [
    "Observation timestamps proxy emission times. The trace cannot establish onboard measurement-to-transmission latency or total real RF traffic.",
    "Ordinary surveillance is decoded on reception, independently of authentication. Its proxy transmission schedule has priority and zero added transmitter delay by construction.",
    "Paired runs share original emissions, original noise draws, background traffic and reception jitter. Only the augmented run adds authentication frames.",
    "The destructive-overlap scenario is a single collision domain: overlapping frame envelopes destroy all participating receptions. It has no capture, propagation, receiver-power or multi-sensor diversity model and is not calibrated to this capture.",
    "No group is expired by an authentication deadline. The declared follow-up horizon censors unfinished work; pending messages are not counted as verified or as definitive failures.",
    "Sender signing and authentication transmission are serial per aircraft. Receiver verification has a separate configurable processor pool. Null queue limits model unlimited storage, whose required backlog is reported.",
    "Authentication uses the illustrative 7-byte ME format with a 4-byte fragment header, signed association context and 8-byte tags per original; no deployed ADS-B type allocation is asserted.",
    "Logical fragment delivery is modeled rather than exercising a finite binary reassembly buffer. Raw-message reconstruction uses only received observations and delivered descriptors; actual cryptographic transport is tested separately.",
    "Signature lengths and service times are calibration inputs. Modeled authentication completion is not a newly computed signature verification. Published means and lineage proxies do not establish avionics timing.",
    "Keys and sessions are provisioned, clocks are shared with bounded jitter, and no credential traffic, retransmission feedback or forward error correction is modeled.",
    "Loss outcomes distinguish known simulation losses from unfinished work; these diagnostics do not give the sender feedback or imply that a receiver can immediately know which fragments were lost.",
    "Freshness and reception-gap metrics describe raw DF17 observations per aircraft, not fully decoded position-update intervals. Initial unknown information age is reported separately.",
]


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
    validate_legacy({"loss": p["loss"]})
    return p


@dataclass
class Group:
    descriptor: object
    members: tuple
    formed: float
    signature_bytes: int
    fragments: int
    state: str = "pending_formation"
    sign_start: float = math.inf
    sign_end: float = math.inf
    tx_start: float = math.inf
    tx_end: float = math.inf
    offset: int = 0
    sent: int = 0
    received_fragments: int = 0
    object_ready: float = math.inf
    verify_start: float = math.inf
    verify_end: float = math.inf
    decision: float | None = None
    enqueued: bool = False
    known_failure: str | None = None


def _frames(earliest, count, originals, step, horizon):
    """Vectorized stretches of auth frames, shifted around own ordinary frames."""
    if earliest > horizon:
        return np.empty(0, dtype=float)
    cursor, remaining, chunks = earliest, count, []
    position = max(0, bisect_right(originals, cursor) - 1)
    while remaining and cursor <= horizon:
        while position < len(originals) and originals[position] + FRAME_S <= cursor + 1e-12:
            position += 1
        available = min(remaining, max(0, math.floor((horizon - cursor) / step + 1e-10) + 1))
        if not available:
            break
        if position < len(originals):
            before_original = math.floor((originals[position] - FRAME_S - cursor) / step + 1e-10) + 1
            available = min(available, max(0, before_original))
        if available:
            chunks.append(cursor + np.arange(available, dtype=float) * step)
            cursor += available * step
            remaining -= available
        else:
            cursor = max(cursor, originals[position] + FRAME_S)
            position += 1
    return np.concatenate(chunks) if chunks else np.empty(0, dtype=float)


def _queue_full(waiting, now, limit):
    while waiting and waiting[0] <= now:
        waiting.popleft()
    return limit is not None and len(waiting) >= limit


def simulate(trace, algorithm, interval, signature_sizes, sender_profile, receiver_profile, scenario, seed=1,
             *, channel_trace=None):
    p = validate_scenario(scenario)
    if type(seed) is not int or seed < 0:
        raise ValueError("seed must be a nonnegative integer.")
    if not signature_sizes or any(type(size) is not int or size < 1 for size in signature_sizes):
        raise ValueError("Signature sizes must be positive integers.")
    sign_samples = timing_samples_ms(sender_profile, algorithm, "sign")
    verify_samples = timing_samples_ms(receiver_profile, algorithm, "verify")
    records = sorted(list(trace.values()) if isinstance(trace, dict) else list(trace),
                     key=lambda r: (r["relative_time_s"], r["trace_id"]))
    if not records:
        raise ValueError("A nonempty trace is required.")
    by_id, raw, aircraft_times = {}, [], defaultdict(list)
    for index, r in enumerate(records):
        _number(r["relative_time_s"], "trace time")
        message = bytes.fromhex(r["raw_msg"])
        if len(message) != 14 or message[0] >> 3 != 17 or message[1:4].hex().upper() != r["icao"]:
            raise ValueError("Trace must contain canonical DF17 observations.")
        if r["trace_id"] in by_id:
            raise ValueError("Duplicate trace ID.")
        by_id[r["trace_id"]] = index
        raw.append(message)
        aircraft_times[r["icao"]].append(r["relative_time_s"])
    start, end = records[0]["relative_time_s"], records[-1]["relative_time_s"]
    if end <= start:
        raise ValueError("Trace observation duration must be positive.")
    jitter = p["receive_jitter_ms"] / 1000
    horizon = end + p["followup_s"] + FRAME_S + jitter
    original_times = np.array([r["relative_time_s"] for r in records])
    reception_times = original_times + FRAME_S + np.random.default_rng(seed + 7013).uniform(0, jitter, len(records))
    # Different floating-point addition order can otherwise leave the last
    # receipt one ULP short of the requested follow-up. This depends only on
    # the shared original-reception schedule, never on authentication traffic.
    horizon = max(horizon, float(reception_times.max()) + p["followup_s"])
    channel_options = {}
    observed_count = 0
    if channel_trace is not None:
        from .channel_trace import validate_coverage
        validate_coverage(channel_trace, horizon)
        if p["background_frames_per_second"]:
            raise ValueError("Observed channel traffic and synthetic background cannot be combined; use a separate sensitivity run.")
        observed_starts = np.asarray(channel_trace["extra_starts"], dtype=float)
        observed_durations = np.asarray(channel_trace["extra_durations_s"], dtype=float)
        in_horizon = observed_starts <= horizon
        channel_options = {"observed_starts": observed_starts[in_horizon],
                           "observed_durations_s": observed_durations[in_horizon]}
        observed_count = int(np.count_nonzero(in_horizon))
    rng_size, rng_sign, rng_verify = (random.Random(seed + value) for value in (4013, 5021, 6011))
    session = hashlib.sha256(f"delayed-session:{seed}".encode()).digest()[:8]
    keys = {icao: hashlib.sha256(("modeled-key:" + icao).encode()).digest() for icao in aircraft_times}
    source_groups, unsigned = form_groups(records, interval, p["max_batch_wait_s"])
    if len(records) + len(source_groups) + observed_count > p["max_events"]:
        raise RuntimeError("Delayed replay max_events exceeded; no partial result may be published.")
    groups = []
    for icao, seq, entries, formed in source_groups:
        members = tuple(by_id[r["trace_id"]] for r in entries)
        desc = describe_group(icao, seq, session, [(original_times[i], raw[i]) for i in members], algorithm, keys[icao])
        size = rng_size.choice(signature_sizes)
        groups.append(Group(desc, members, formed, size, fragment_count(object_size_bytes(len(members), size))))
    del source_groups

    sign_available, tx_available = defaultdict(float), defaultdict(float)
    sign_waiting, tx_waiting = defaultdict(deque), defaultdict(deque)
    sender_required, radio_required = Counter(), Counter()
    sign_waits, auth_chunks = [], []
    sender_busy = sender_busy_capture = 0.0
    peak_sender = peak_tx = frame_total = 0
    step, copies = 1 / p["auth_frames_per_second"], p["fragment_copies"]
    for group in groups:
        icao = group.descriptor.icao
        if group.formed > horizon:
            continue
        service = rng_sign.choice(sign_samples) / 1000
        if group.formed <= end:
            sender_required[icao] += service
            radio_required[icao] += group.fragments * copies * step
        if _queue_full(sign_waiting[icao], group.formed, p["sender_queue_limit"]):
            group.state = "sender_queue_overflow"
            continue
        group.sign_start = max(group.formed, sign_available[icao])
        group.sign_end = group.sign_start + service
        sign_available[icao] = group.sign_end
        if group.sign_start > group.formed:
            sign_waiting[icao].append(group.sign_start)
        peak_sender = max(peak_sender, len(sign_waiting[icao]))
        sender_busy += max(0, min(group.sign_end, horizon) - group.sign_start)
        sender_busy_capture += max(0, min(group.sign_end, end) - group.sign_start)
        if group.sign_start > horizon:
            group.state = "pending_sender_queue"
            continue
        sign_waits.append(1000 * (group.sign_start - group.formed))
        if group.sign_end > horizon:
            group.state = "pending_signing"
            continue
        if _queue_full(tx_waiting[icao], group.sign_end, p["transmission_queue_limit"]):
            group.state = "transmission_queue_overflow"
            continue
        earliest = max(group.sign_end, tx_available[icao])
        group.state = "pending_transmission_queue"
        if earliest > group.sign_end:
            tx_waiting[icao].append(earliest)
        peak_tx = max(peak_tx, len(tx_waiting[icao]))
        if earliest > horizon:
            group.state = "pending_transmission_queue"
            continue
        count = group.fragments * copies
        # Bound allocations before constructing a potentially large grid.
        possible = min(count, max(0, int((horizon - earliest) / step) + 1))
        if frame_total + possible + len(records) + len(groups) + observed_count > p["max_events"]:
            raise RuntimeError("Delayed replay max_events exceeded; no partial result may be published.")
        times = _frames(earliest, count, aircraft_times[icao], step, horizon)
        group.offset, group.sent = frame_total, len(times)
        frame_total += len(times)
        if len(times):
            auth_chunks.append(times)
            group.tx_start = float(times[0])
            group.state = "pending_transmission"
        if len(times) == count:
            group.tx_end = float(times[-1]) + FRAME_S
            tx_available[icao] = float(times[-1]) + step
            group.state = "pending_reception"
        else:
            tx_available[icao] = math.inf
    auth_times = np.concatenate(auth_chunks) if auth_chunks else np.empty(0, dtype=float)
    del auth_chunks
    channel = evaluate_channel(original_times, [r["icao"] for r in records], auth_times,
                               loss=p["loss"], seed=seed, horizon=horizon,
                               channel_mode=p["channel_mode"],
                               background_frames_per_second=p["background_frames_per_second"],
                               **channel_options)
    baseline = channel["original_success_baseline"]
    received = channel["original_success_with_auth"]
    auth_received = channel["auth_success"]
    auth_arrivals = auth_times + FRAME_S
    if jitter:
        auth_arrivals += np.random.default_rng(seed + 8011).uniform(0, jitter, len(auth_times))
    auth_received = auth_received & (auth_arrivals <= horizon)

    receiver = ReplayReceiver(horizon - start + jitter + 1, FRAME_S + jitter + 1e-6)
    for icao, key in keys.items():
        receiver.register(icao, algorithm, key, session)
    heap, serial = [], 0
    def schedule(time, priority, kind, value):
        nonlocal serial
        serial += 1
        heapq.heappush(heap, (time, priority, serial, kind, value))
    for i in np.flatnonzero(received):
        schedule(float(reception_times[i]), 0, "original", int(i))
    for index, group in enumerate(groups):
        if not group.sent:
            continue
        lo, hi = group.offset, group.offset + group.sent
        full_parts = group.sent // copies
        if full_parts:
            emitted = slice(lo, lo + full_parts * copies)
            finished_parts = (auth_arrivals[emitted] <= horizon).reshape(-1, copies).all(axis=1)
            delivered_parts = auth_received[emitted].reshape(-1, copies).any(axis=1)
            if np.any(finished_parts & ~delivered_parts):
                group.known_failure = "fragments_lost"
        arrivals = np.where(auth_received[lo:hi], auth_arrivals[lo:hi], np.inf)
        if copies > 1:
            if len(arrivals) % copies:
                arrivals = np.pad(arrivals, (0, copies - len(arrivals) % copies), constant_values=np.inf)
            arrivals = arrivals.reshape(-1, copies).min(axis=1)
        group.received_fragments = int(np.isfinite(arrivals).sum())
        if len(arrivals) == group.fragments and np.all(np.isfinite(arrivals)):
            group.object_ready = float(arrivals.max())
            schedule(group.object_ready, 1, "object", index)
        elif group.sent == group.fragments * copies and float(auth_arrivals[lo:hi].max()) <= horizon:
            group.state = "fragments_lost"
        elif group.sent == group.fragments * copies:
            group.state = "pending_reception"

    queue, waiting_originals = deque(), defaultdict(set)
    busy = peak_verify = receiver_events = 0
    receiver_busy = 0.0
    verify_waits = []
    auth_at = np.full(len(records), np.nan)
    def start_workers(now):
        nonlocal busy, receiver_busy
        while queue and busy < p["receiver_workers"]:
            index, ready = queue.popleft()
            group = groups[index]
            group.verify_start = now
            service = rng_verify.choice(verify_samples) / 1000
            group.verify_end = now + service
            group.state = "pending_verifying"
            verify_waits.append((now - ready) * 1000)
            receiver_busy += max(0, min(horizon, group.verify_end) - now)
            busy += 1
            schedule(group.verify_end, 2, "verified", index)

    def reconstruct(index, now):
        nonlocal peak_verify
        group = groups[index]
        if group.enqueued:
            return
        result = receiver.reconstruct(group.descriptor, now)
        if result.status in {"missing_message", "not_yet_current"}:
            group.state = "pending_original_messages"
            waiting_originals[group.descriptor.icao].add(index)
            return
        waiting_originals[group.descriptor.icao].discard(index)
        if result.status != "ready":
            if result.status == "expired":
                raise RuntimeError("Unexpected age expiry in delayed-authentication replay.")
            group.state, group.decision = result.status, now
            return
        if p["receiver_queue_limit"] is not None and len(queue) >= p["receiver_queue_limit"]:
            group.state, group.decision = "receiver_queue_overflow", now
            return
        group.enqueued = True
        group.state = "pending_verification_queue"
        queue.append((index, now))
        peak_verify = max(peak_verify, len(queue))
        start_workers(now)

    while heap:
        now, _, _, kind, index = heapq.heappop(heap)
        if now > horizon:
            break
        receiver_events += 1
        if receiver_events + frame_total + len(groups) + observed_count > p["max_events"]:
            raise RuntimeError("Delayed replay max_events exceeded; no partial result may be published.")
        if kind == "original":
            receiver.observe_message(raw[index], now)
            for group_index in sorted(waiting_originals[records[index]["icao"]]):
                reconstruct(group_index, now)
        elif kind == "object":
            reconstruct(index, now)
        else:
            busy -= 1
            group = groups[index]
            result = receiver.accept_modeled(group.descriptor, now)
            group.state, group.decision = result.status, now
            if result.status == "modeled_authenticated":
                if not np.all(received[list(group.members)]):
                    raise RuntimeError("Ambiguous source/reception association; authenticated source accounting is not identifiable.")
                auth_at[list(group.members)] = now
            start_workers(now)

    outcomes = np.full(len(records), "unsigned_tail", dtype=object)
    diagnosed_groups = []
    for group in groups:
        if group.state == "pending_original_messages":
            group.state = "missing_message"  # all original emissions and bounded receptions have finished
        diagnostic = group.state
        if diagnostic.startswith("pending") or diagnostic == "fragments_lost":
            if not np.all(received[list(group.members)]):
                diagnostic = "missing_message"
            elif group.known_failure:
                diagnostic = group.known_failure
        diagnosed_groups.append(diagnostic)
        outcomes[list(group.members)] = diagnostic
    outcomes[~received] = "original_lost"
    metrics = summarize(records, baseline, received, reception_times, auth_at, outcomes.tolist(),
                        horizon=horizon, thresholds_s=p["coverage_thresholds_s"],
                        ordinary_tx_delays=np.zeros(len(records)))
    if not p["record_events"]:
        metrics.pop("aircraft_freshness", None)
    duration = end - start
    auth_within = int(np.count_nonzero(auth_times <= end))
    backlog = []
    for t in sorted(set([start, *np.linspace(start, end, 11).tolist(), horizon])):
        backlog.append({"time_s": float(t),
                        "sender_unfinished_groups": sum(g.formed <= t < g.sign_end and g.state != "sender_queue_overflow" for g in groups),
                        "transmission_unfinished_groups": sum(g.sign_end <= t < g.tx_end and g.state != "transmission_queue_overflow" for g in groups),
                        "receiver_unfinished_groups": sum(g.object_ready <= t < g.verify_end and g.enqueued for g in groups)})
    summary = {
        **metrics,
        "algorithm": algorithm, "interval_k": interval, "seed": seed,
        "replay_model": "delayed_authentication", "evidence": "modeled_reconstruction_and_verification_service",
        "authentication_mode": "per_message" if interval == 1 else "batched",
        "trace_messages": len(records), "trace_aircraft": len(keys), "trace_duration_s": duration,
        "source_groups": len(groups), "unsigned_tail_messages": unsigned,
        "followup_s": p["followup_s"], "observation_horizon_s": horizon,
        "max_batch_wait_s": p["max_batch_wait_s"], "channel_mode": p["channel_mode"],
        "auth_frames_per_second_per_aircraft": p["auth_frames_per_second"],
        "modeled_authenticated_groups": sum(g.state == "modeled_authenticated" for g in groups),
        "auth_frames_transmitted": frame_total, "auth_frames_received": int(auth_received.sum()),
        "auth_frames_lost": int((~channel["auth_success"]).sum()),
        "auth_frames_in_flight_at_horizon": int((channel["auth_success"] & (auth_arrivals > horizon)).sum()),
        "auth_frames_after_observation": frame_total - auth_within,
        "baseline_offered_airtime_load": len(records) * FRAME_S / duration,
        "additional_offered_airtime_load": auth_within * FRAME_S / duration,
        "sender_busy_seconds_all_aircraft": sender_busy,
        "sender_busy_seconds_during_capture": sender_busy_capture,
        "receiver_busy_seconds_all_workers": receiver_busy,
        "sender_queue_peak_per_aircraft": peak_sender, "transmission_queue_peak_per_aircraft": peak_tx,
        "receiver_queue_peak": peak_verify,
        "sender_offered_utilization_max_per_aircraft": max(sender_required.values(), default=0) / duration,
        "authentication_radio_offered_utilization_max_per_aircraft": max(radio_required.values(), default=0) / duration,
        "backlog_samples": backlog, "channel_summary": channel.get("summary", {}),
        "processed_events": receiver_events + frame_total + len(groups),
        **_quantiles(sign_waits, "signing_queue_ms"), **_quantiles(verify_waits, "verification_queue_ms"),
    }
    group_outcomes = dict(sorted(Counter(diagnosed_groups).items()))
    summary["group_work_states_at_horizon"] = dict(sorted(Counter(g.state for g in groups).items()))
    if channel_trace is not None:
        additional_airtime = float(np.sum(observed_durations[
            (observed_starts >= start) & (observed_starts <= end)]))
        summary["target_offered_airtime_load"] = summary["baseline_offered_airtime_load"]
        summary["non_target_offered_airtime_load"] = additional_airtime / duration
        summary["baseline_offered_airtime_load"] += additional_airtime / duration
        summary["augmented_offered_airtime_load"] = (
            summary["baseline_offered_airtime_load"] + summary["additional_offered_airtime_load"])
        summary["observed_channel_trace"] = channel_trace["summary"]
        summary["processed_events"] += observed_count
    events = []
    if p["record_events"]:
        for g, diagnostic in zip(groups, diagnosed_groups):
            events.append({"icao": g.descriptor.icao, "group_sequence": g.descriptor.seq,
                           "formed_s": g.formed, "message_count": len(g.members), "outcome": diagnostic,
                           "work_state": g.state,
                           "decision_s": g.decision, "fragments_sent": g.sent,
                           "fragments_received": g.received_fragments, "required_fragments": g.fragments})
    assumptions = ASSUMPTIONS
    if channel_trace is not None:
        assumptions = [*ASSUMPTIONS,
                       "The observed channel trace contains every target once plus unmodified non-target transmissions with supplied durations; it covers the full follow-up horizon. Completeness is an acquisition claim, not inferred from decoded messages.",
                       "Non-target transmissions are receiver-side interferers; only target DF17 frames reserve their sender's radio in this scheduling model. Non-target reception and shared-transponder scheduling are not evaluated."]
    return {"summary": summary, "outcomes": group_outcomes, "parameters": p,
            "assumptions": assumptions, "events": events}
