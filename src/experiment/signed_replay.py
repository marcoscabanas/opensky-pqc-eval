"""Real signatures with detached or historical signing-before-send scheduling.

Source timestamps are message-availability proxies. Actual signature bytes are
prepared by ``signed_workload``; published hardware profiles supply the replay
service times. Reception and subsequent cryptographic acceptance are distinct.
"""

from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
import heapq
import math
import random
from pathlib import Path
import tempfile
import time

import numpy as np

from .delayed_metrics import summarize
from .channel_trace import replay_window, validate_coverage
from .model_support import validate_scenario, _queue_full
from .hardware_profiles import timing_samples_ms
from .model_support import FRAME_S, _number, _quantiles, form_groups
from .replay_transport import (
    FragmentReassembler, ReplayReceiver, encode_envelope, fragment_count,
    fragment_envelope, message_tag, _time_us,
)
from .shared_channel import evaluate_shifted_channel
from .signed_workload import verifier_for


ASSUMPTIONS = [
    "Recorded target timestamps proxy onboard message availability; true sensor-generation times are unknown, so added model delay is not measured avionics latency.",
    "Each aircraft has one serial signer and one radio. Ordinary messages wait for their group signature, then have FIFO priority over authentication. An already transmitting fragment is not preempted.",
    "Real signatures cover signed context and ordered raw messages. Delivered seven-byte fragments are reassembled and an actual public-key verification is performed only after modeled receiver service completes.",
    "Hardware-profile service times are separate from host signature-generation time; published means and platform proxies do not establish worst-case execution time or aircraft certification.",
    "The baseline uses recorded target times; the augmented run shifts targets after signing. A second, timing-matched control removes authentication frames while retaining shifted target times to isolate their RF effect.",
    "A fixed capture-plus-follow-up horizon censors unfinished work. Unsent messages are distinguished from transmissions lost on the channel; incomplete fixed-count groups are withheld unsigned.",
    "Receiver reconstruction uses received raw bytes, signed tags and provisioned keys/session, never sender trace IDs. Its association tolerance spans the replay horizon because signing changes transmission times; excess matching observations are rejected as ambiguous.",
    "When byte verification succeeds but the experiment cannot attribute it to all original source occurrences, source authentication is conservatively classified as ambiguous. Repeated identical transmissions cannot be uniquely identified by byte tags alone.",
    "The seven-byte ME allocation is illustrative: four fragment-header bytes leave three data bytes. Keys/session are provisioned out of band; credential traffic, feedback and retransmission requests are not modeled.",
    "Destructive overlap is an uncalibrated single collision domain with no capture, power, geometry or receiver diversity. Independent loss is its collision-free control.",
    "Observed non-target traffic remains at supplied times and durations, including follow-up. Its completeness is an acquisition claim; target messages are counted once. Other transmissions from the same aircraft are interferers, not modeled onboard radio reservations.",
    "Signing and receiver verification are separate processor resources; buffers default to unbounded storage and required backlogs are reported. No measured memory, energy or mixed-criticality isolation claim is made.",
    "A receiver candidate reserves its matching reception occurrences and immutable signed bytes when admitted for verification. Later receptions cannot change that candidate. Invalid verification returns the reserved occurrences to the observation buffer.",
    "Reassembly exercises actual delivered bytes but does not model a finite simultaneous fragment-buffer capacity. A finite transmission_queue_limit, when selected, counts all buffered authentication groups including the active group.",
]


@dataclass(slots=True)
class Group:
    source: dict
    members: tuple
    fragments: int
    state: str = "pending_formation"
    sign_start: float = math.inf
    sign_end: float = math.inf
    service: float = 0.0
    tx_start: float = math.inf
    tx_end: float = math.inf
    original_end: float = math.inf
    chunks: list = field(default_factory=list)
    offset: int = 0
    sent: int = 0
    received_fragments: int = 0
    object_ready: float = math.inf
    delivered: object = None
    verify_start: float = math.inf
    verify_end: float = math.inf
    queued_at: float = math.inf
    signing_input: bytes | None = None
    reserved_observations: list = field(default_factory=list)
    decision: float | None = None
    enqueued: bool = False
    known_failure: str | None = None
    reconstruction_ready: float = math.inf
    verification_valid: bool | None = None

    @property
    def descriptor(self):
        return self.source["descriptor"]

    @property
    def formed(self):
        return self.source["formed_s"]


_ARRAY_CHUNK = 1_000_000
_MEMMAP_THRESHOLD = 8_000_000


class _ReplayReceiver(ReplayReceiver):
    """Avoid scanning retained observations when expiry is provably impossible.

    Reception timestamps are validated as nonnegative. With the study's
    horizon-wide retention, the earliest permissible observation remains at or
    before zero throughout the replay, so filtering cannot remove any item.
    Short-retention uses still take the general receiver's expiry path.
    """

    def observe_message(self, raw, reception_s):
        tag, reception_us = message_tag(raw), _time_us(reception_s)
        if reception_us - self.max_age_us - self.clock_tolerance_us <= 0:
            self.observations[raw[1:4].hex().upper()].append((reception_us, raw, tag))
        else:
            super().observe_message(raw, reception_s)


def _radio_run(first, count, step, horizon):
    """Keep arithmetic runs compact instead of retaining one float per frame."""
    while count and first + (count - 1) * step > horizon:
        count -= 1
    return first, count, step


def _array_buffer(count, scratch, name):
    if count >= _MEMMAP_THRESHOLD:
        return np.memmap(Path(scratch) / name, mode="w+", dtype=np.float64, shape=(count,))
    return np.empty(count, dtype=np.float64)


def _flatten_radio(groups, count, scratch):
    """Expand exact scheduled runs once, with bounded transient allocations."""
    times = _array_buffer(count, scratch, "authentication-times.dat")
    offsets, offset = [], 0
    for group in groups:
        group.offset = offset
        if group.sent:
            offsets.append(offset)
        for first, length, step in group.chunks:
            for begin in range(0, length, _ARRAY_CHUNK):
                size = min(length - begin, _ARRAY_CHUNK)
                # Retain first + index * step evaluation, including rounding.
                times[offset:offset + size] = first + np.arange(begin, begin + size, dtype=float) * step
                offset += size
        group.chunks.clear()
    if offset != count:
        raise RuntimeError("Authentication schedule frame count is inconsistent.")
    return times, np.asarray([*offsets, count], dtype=np.int64)


def _schedule_radio(groups, original_starts, parameters, horizon, budget):
    """Causal, nonpreemptive per-aircraft priority queues, vectorized auth runs."""
    step = 1 / parameters["auth_frames_per_second"]
    copies = parameters["fragment_copies"]
    by_aircraft = defaultdict(list)
    for group in groups:
        if group.sign_end <= horizon and group.state != "sender_queue_overflow":
            by_aircraft[group.descriptor.icao].append(group)
    sent_total = peak_queue = 0
    for available in by_aircraft.values():
        available.sort(key=lambda group: (group.sign_end, group.descriptor.seq))
        next_group = 0
        originals, authentication = deque(), deque()
        now, gate = available[0].sign_end, 0.0
        while now <= horizon:
            while next_group < len(available) and available[next_group].sign_end <= now:
                group = available[next_group]
                next_group += 1
                originals.extend((group, index, position == len(group.members) - 1)
                                 for position, index in enumerate(group.members))
                group.state = "pending_transmission_queue"
            if originals:
                group, index, last = originals.popleft()
                original_starts[index] = now
                now += FRAME_S
                if last:
                    group.original_end = now
                    limit = parameters["transmission_queue_limit"]
                    if limit is not None and len(authentication) >= limit:
                        group.state = "transmission_queue_overflow"
                    else:
                        authentication.append(group)
                        peak_queue = max(peak_queue, len(authentication))
                continue
            release = available[next_group].sign_end if next_group < len(available) else math.inf
            if not authentication:
                if not math.isfinite(release):
                    break
                now = max(now, release)
                continue
            first = max(now, gate)
            if release <= first:
                now = release
                continue
            if first > horizon:
                break
            group = authentication[0]
            remaining = group.fragments * copies - group.sent
            count = min(remaining, int(math.floor((horizon - first) / step)) + 1)
            if math.isfinite(release):
                # Frames starting before release may finish after it: the
                # newly ready ordinary frame waits for that real occupied slot.
                count = min(count, max(1, int(math.ceil((release - first) / step))))
                while count > 1 and first + (count - 1) * step >= release:
                    count -= 1
            if sent_total + count > budget:
                raise RuntimeError("Signed replay max_events exceeded; no partial result may be published.")
            first, count, step = _radio_run(first, count, step, horizon)
            if not count:
                break
            group.chunks.append((first, count, step))
            group.sent += count
            sent_total += count
            group.tx_start = min(group.tx_start, first)
            group.state = "pending_transmission"
            last = first + (count - 1) * step
            now = last + FRAME_S
            gate = last + step
            if group.sent == group.fragments * copies:
                group.tx_end = now
                group.state = "pending_reception"
                authentication.popleft()
    return sent_total, peak_queue


def _schedule_detached_radio(groups, records, original_starts, parameters, horizon, budget):
    """Release every original at its source time, independently of the signer.

    Authentication runs are vectorized only until the next source arrival or
    signing completion. This preserves ordinary priority without looking ahead
    to reserve a radio slot before an ordinary message actually becomes ready.
    """
    step = 1 / parameters["auth_frames_per_second"]
    copies = parameters["fragment_copies"]
    originals_by_aircraft, groups_by_aircraft = defaultdict(list), defaultdict(list)
    for index, record in enumerate(records):
        originals_by_aircraft[record["icao"]].append((record["relative_time_s"], index))
    for group in groups:
        if group.sign_end <= horizon and group.state != "sender_queue_overflow":
            groups_by_aircraft[group.descriptor.icao].append(group)
    sent_total = peak_queue = 0
    for icao, originals in originals_by_aircraft.items():
        available = sorted(groups_by_aircraft[icao],
                           key=lambda group: (group.sign_end, group.descriptor.seq))
        next_original = next_group = 0
        authentication = deque()
        def admit(group):
            nonlocal peak_queue
            limit = parameters["transmission_queue_limit"]
            if limit is not None and len(authentication) >= limit:
                group.state = "transmission_queue_overflow"
            else:
                group.state = "pending_transmission_queue"
                authentication.append(group)
                peak_queue = max(peak_queue, len(authentication))
        now, gate = originals[0][0], 0.0
        while now <= horizon:
            while next_group < len(available) and available[next_group].sign_end <= now:
                group = available[next_group]
                next_group += 1
                admit(group)
            if next_original < len(originals) and originals[next_original][0] <= now:
                original_starts[originals[next_original][1]] = now
                next_original += 1
                now += FRAME_S
                continue
            original_release = originals[next_original][0] if next_original < len(originals) else math.inf
            auth_release = available[next_group].sign_end if next_group < len(available) else math.inf
            release = min(original_release, auth_release)
            if not authentication:
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
            group = authentication[0]
            remaining = group.fragments * copies - group.sent
            count = min(remaining, int(math.floor((horizon - first) / step)) + 1)
            if math.isfinite(release):
                count = min(count, max(1, int(math.ceil((release - first) / step))))
                while count > 1 and first + (count - 1) * step >= release:
                    count -= 1
            if sent_total + count > budget:
                raise RuntimeError("Signed replay max_events exceeded; no partial result may be published.")
            first, count, step = _radio_run(first, count, step, horizon)
            if not count:
                break
            group.chunks.append((first, count, step))
            group.sent += count
            sent_total += count
            group.tx_start = min(group.tx_start, first)
            group.state = "pending_transmission"
            last = first + (count - 1) * step
            now = last + FRAME_S
            gate = last + step
            if group.sent == group.fragments * copies:
                # A signer may finish during this last frame. Until that
                # frame completes the active object still occupies a queue
                # slot, so apply admission before removing it.
                while next_group < len(available) and available[next_group].sign_end < now:
                    admit(available[next_group])
                    next_group += 1
                group.tx_end = now
                group.state = "pending_reception"
                authentication.popleft()
    return sent_total, peak_queue


def _detached_association_tolerance(records, receive_jitter_s):
    """Derive a shared receiver timing allowance from source arrivals alone.

    If an original is ready when its predecessor finishes, ordinary priority
    serves it next. Otherwise it can wait for at most one active auth frame.
    Hence worst-case starts obey b_i = max(a_i + F, b_(i-1) + F).
    Adding the ordinary frame duration bounds reception, independently of
    signing, grouping, rate, channel outcomes, or source membership feedback.
    """
    previous = defaultdict(lambda: -FRAME_S)
    maximum_reception_delay = 0.0
    for record in records:
        arrival, icao = record["relative_time_s"], record["icao"]
        worst_start = max(arrival + FRAME_S, previous[icao] + FRAME_S)
        previous[icao] = worst_start
        maximum_reception_delay = max(maximum_reception_delay, worst_start + FRAME_S - arrival)
    # Signed source and observed reception timestamps round separately to us.
    return maximum_reception_delay + receive_jitter_s + 1e-6


def _ordinary_radio_without_auth(records):
    """Use the same per-aircraft nonpreemptive FIFO radio without auth frames."""
    available = defaultdict(float)
    starts = np.empty(len(records), dtype=float)
    for index, record in enumerate(records):
        icao = record["icao"]
        starts[index] = max(record["relative_time_s"], available[icao])
        available[icao] = starts[index] + FRAME_S
    return starts


def simulate(trace, algorithm, interval, workload, sender_profile, receiver_profile,
             scenario, seed=1, *, channel_trace=None, replay_model="signed_before_send"):
    """Replay exact signatures with per-case temporary disk-backed large arrays."""
    with tempfile.TemporaryDirectory(prefix="adsb-replay-") as scratch:
        return _simulate(trace, algorithm, interval, workload, sender_profile, receiver_profile,
                         scenario, seed, channel_trace=channel_trace,
                         replay_model=replay_model, scratch=scratch)


def _simulate(trace, algorithm, interval, workload, sender_profile, receiver_profile,
              scenario, seed=1, *, channel_trace=None, replay_model="signed_before_send", scratch):
    """Replay cached real signatures without regenerating them for each RF seed."""
    started = time.monotonic()
    def progress(message):
        if len(trace) >= 100_000:
            print(f"  REPLAY +{time.monotonic() - started:.0f}s: {message}", flush=True)
    if replay_model not in {"signed_before_send", "signed_detached"}:
        raise ValueError("Unknown signed replay model.")
    detached = replay_model == "signed_detached"
    p = validate_scenario(scenario)
    if type(seed) is not int or seed < 0:
        raise ValueError("seed must be a nonnegative integer.")
    records = sorted(list(trace.values()) if isinstance(trace, dict) else list(trace),
                     key=lambda record: (record["relative_time_s"], record["trace_id"]))
    if not records:
        raise ValueError("A nonempty trace is required.")
    by_id, raw = {}, []
    for index, record in enumerate(records):
        _number(record["relative_time_s"], "trace time")
        message = bytes.fromhex(record["raw_msg"])
        if len(message) != 14 or message[0] >> 3 != 17 or message[1:4].hex().upper() != record["icao"]:
            raise ValueError("Trace must contain canonical DF17 observations.")
        if record["trace_id"] in by_id:
            raise ValueError("Duplicate trace ID.")
        by_id[record["trace_id"]] = index
        raw.append(message)
    start, end, horizon = replay_window(records, channel_trace, p["followup_s"], p["receive_jitter_ms"])
    declared_window = bool(channel_trace is not None and
                           channel_trace.get("summary", {}).get("target_window_declared", False))
    sign_samples = timing_samples_ms(sender_profile, algorithm, "sign")
    verify_samples = timing_samples_ms(receiver_profile, algorithm, "verify")
    jitter = p["receive_jitter_ms"] / 1000
    association_tolerance = (_detached_association_tolerance(records, jitter)
                             if detached else horizon + jitter + 1)
    source_times = np.array([record["relative_time_s"] for record in records])
    shared_jitter = np.random.default_rng(seed + 7013).uniform(0, jitter, len(records))
    baseline_arrivals = source_times + FRAME_S + shared_jitter
    original_starts = np.full(len(records), np.nan)
    channel_options, observed_count = {}, 0
    observed_starts, observed_durations = np.empty(0), np.empty(0)
    if channel_trace is not None:
        validate_coverage(channel_trace, horizon)
        if p["background_frames_per_second"]:
            raise ValueError("Observed channel traffic and synthetic background cannot be combined.")
        observed_starts = np.asarray(channel_trace["extra_starts"], dtype=float)
        observed_durations = np.asarray(channel_trace["extra_durations_s"], dtype=float)
        mask = observed_starts <= horizon
        observed_starts, observed_durations = observed_starts[mask], observed_durations[mask]
        observed_count = len(observed_starts)
        channel_options.update(observed_starts=observed_starts, observed_durations_s=observed_durations)
    expected, unsigned_count = form_groups(records, interval, p["max_batch_wait_s"])
    supplied = workload["groups"]
    if len(expected) != len(supplied):
        raise ValueError("Signed workload does not match the requested grouping policy.")
    groups, covered = [], set()
    for source, (icao, seq, entries, formed) in zip(supplied, expected):
        members = tuple(entry["trace_id"] for entry in entries)
        descriptor = source["descriptor"]
        if (tuple(source["members"]) != members or source["formed_s"] != formed
                or descriptor.icao != icao or descriptor.seq != seq
                or descriptor.algorithm != algorithm
                or source["envelope"].descriptor != descriptor):
            raise ValueError("Signed workload does not match the requested trace/groups.")
        groups.append(Group(source, tuple(by_id[identifier] for identifier in members),
                            fragment_count(len(encode_envelope(source["envelope"])))))
        covered.update(members)
    unsigned_ids = set(workload["unsigned_trace_ids"])
    if unsigned_ids != set(by_id) - covered or len(unsigned_ids) != unsigned_count:
        raise ValueError("Signed workload has inconsistent unsigned tails.")
    fixed_events = len(records) + len(groups) + observed_count
    if fixed_events > p["max_events"]:
        raise RuntimeError("Signed replay max_events exceeded; no partial result may be published.")
    rng_sign, rng_verify = random.Random(seed + 5021), random.Random(seed + 6011)
    sign_available, waiting = defaultdict(float), defaultdict(deque)
    sender_required, radio_required, radio_airtime_required = Counter(), Counter(), Counter()
    sender_busy = sender_busy_capture = 0.0
    peak_sender = 0
    sign_waits, sign_services, batch_waits = [], [], []
    for group in groups:
        if group.formed > horizon:
            continue
        icao = group.descriptor.icao
        group.service = rng_sign.choice(sign_samples) / 1000
        if group.formed <= end:
            sender_required[icao] += group.service
            radio_required[icao] += group.fragments * p["fragment_copies"] / p["auth_frames_per_second"]
            radio_airtime_required[icao] += group.fragments * p["fragment_copies"] * FRAME_S
        batch_waits.extend(1000 * (group.formed - source_times[index]) for index in group.members)
        if _queue_full(waiting[icao], group.formed, p["sender_queue_limit"]):
            group.state = "sender_queue_overflow"
            continue
        group.sign_start = max(group.formed, sign_available[icao])
        group.sign_end = group.sign_start + group.service
        sign_available[icao] = group.sign_end
        if group.sign_start > group.formed:
            waiting[icao].append(group.sign_start)
        peak_sender = max(peak_sender, len(waiting[icao]))
        sender_busy += max(0.0, min(group.sign_end, horizon) - group.sign_start)
        sender_busy_capture += max(0.0, min(group.sign_end, end) - group.sign_start)
        group.state = "pending_sender_queue" if group.sign_start > horizon else "pending_signing"
        if group.sign_start <= horizon:
            sign_waits.append(1000 * (group.sign_start - group.formed))
            sign_services.append(group.service * 1000)
    if detached:
        frame_total, peak_tx = _schedule_detached_radio(groups, records, original_starts,
            p, horizon, p["max_events"] - fixed_events)
    else:
        frame_total, peak_tx = _schedule_radio(groups, original_starts, p, horizon,
                                             p["max_events"] - fixed_events)
    progress(f"scheduled {frame_total:,} authentication frames")
    # Group validation intermediates are no longer needed during RF/receiver work.
    del expected, covered, by_id
    auth_times, auth_run_offsets = _flatten_radio(groups, frame_total, scratch)
    progress("authentication timeline ready")
    options = dict(loss=p["loss"], seed=seed, horizon=horizon, channel_mode=p["channel_mode"],
                   background_frames_per_second=p["background_frames_per_second"], **channel_options)
    aircraft = [record["icao"] for record in records]
    channel = evaluate_shifted_channel(source_times, original_starts, aircraft, auth_times,
                                       auth_run_offsets=auth_run_offsets, **options)
    progress("augmented channel evaluated")
    timing_control = evaluate_shifted_channel(source_times, original_starts, aircraft, [], **options)
    reception_times = original_starts + FRAME_S + shared_jitter
    baseline = channel["original_success_baseline"] & (baseline_arrivals <= horizon)
    received = channel["original_success_with_auth"] & (reception_times <= horizon)
    control_received = timing_control["original_success_with_auth"] & (reception_times <= horizon)
    # With zero jitter, retain a scalar arrival offset instead of duplicating a
    # potentially gigabyte timeline. The receiver materializes only one group.
    auth_arrivals, auth_arrival_offset = auth_times, FRAME_S
    if jitter:
        auth_arrivals = _array_buffer(frame_total, scratch, "authentication-arrivals.dat")
        jitter_rng = np.random.default_rng(seed + 8011)
        for first in range(0, frame_total, _ARRAY_CHUNK):
            last = min(first + _ARRAY_CHUNK, frame_total)
            auth_arrivals[first:last] = auth_times[first:last] + FRAME_S
            auth_arrivals[first:last] += jitter_rng.uniform(0, jitter, last - first)
        auth_arrival_offset = 0.0
    auth_received = channel["auth_success"].copy()
    auth_lost_count = auth_in_flight_count = 0
    for first in range(0, frame_total, _ARRAY_CHUNK):
        last = min(first + _ARRAY_CHUNK, frame_total)
        completed_auth = auth_arrivals[first:last] + auth_arrival_offset <= horizon
        successful_auth = channel["auth_success"][first:last]
        auth_received[first:last] &= completed_auth
        auth_lost_count += int(np.count_nonzero(~successful_auth & completed_auth if declared_window
                                                else ~successful_auth))
        auth_in_flight_count += int(np.count_nonzero(~completed_auth if declared_window
                                                     else successful_auth & ~completed_auth))
    progress("channel controls complete; receiving exact signature fragments")
    receiver = _ReplayReceiver(horizon + jitter + 1, association_tolerance)
    verifiers = {}
    try:
        for group in groups:
            key = (group.descriptor.icao, group.source["public_key"])
            if key not in verifiers:
                verify = verifier_for(algorithm, group.source["public_key"])
                verifiers[key] = verify
                receiver.register(group.descriptor.icao, algorithm, group.source["public_key"],
                                  group.descriptor.session, verify)
        result = _receive(records, raw, groups, receiver, received, reception_times,
                          auth_arrivals, auth_received, p, horizon, rng_verify,
                          verify_samples, fixed_events + frame_total,
                          auth_arrival_offset=auth_arrival_offset)
    finally:
        for verify in verifiers.values():
            verify.close()
    progress("receiver cryptographic verification complete")
    auth_at, outcomes, diagnosed, receiver_stats, receiver_events = result
    tx_delays = original_starts - source_times
    metrics = summarize(records, baseline, received, reception_times, auth_at, outcomes,
                        horizon=horizon, thresholds_s=p["coverage_thresholds_s"],
                        baseline_reception_times=baseline_arrivals, ordinary_tx_delays=tx_delays,
                        capture_window=(start, end) if declared_window else None)
    if not p["record_events"]:
        metrics.pop("aircraft_freshness", None)
    # A message not observed can still be awaiting signing, radio, or reception.
    metrics["augmented_original_not_received_messages"] = metrics.pop("augmented_original_lost_messages")
    transmitted = np.isfinite(original_starts)
    completed = transmitted & (reception_times <= horizon)
    rf_lost = transmitted & ~channel["original_success_with_auth"]
    if declared_window:
        rf_lost &= completed
    known_withheld = np.array([outcome in {"unsigned_tail", "sender_queue_overflow"}
                               for outcome in outcomes]) & ~transmitted
    duration = end - start
    capture = lambda times: (times >= start) & ((times < end) if declared_window else (times <= end))
    followup = lambda times: np.isfinite(times) & ((times >= end) if declared_window else (times > end))
    observed_airtime = float(np.sum(observed_durations[capture(observed_starts)]))
    original_capture = int(np.count_nonzero(capture(original_starts)))
    auth_capture = sum(int(np.count_nonzero(capture(auth_times[first:first + _ARRAY_CHUNK])))
                       for first in range(0, frame_total, _ARRAY_CHUNK))
    radio_waits = ([1000 * tx_delays[index] for index in np.flatnonzero(transmitted)] if detached else
                   [1000 * (original_starts[index] - group.sign_end)
                    for group in groups for index in group.members if transmitted[index]])
    backlog = [{"time_s": float(time),
                "sender_unfinished_groups": sum(group.formed <= time < group.sign_end
                                                and group.state != "sender_queue_overflow" for group in groups),
                "ordinary_waiting_messages": (int(np.count_nonzero((source_times <= time) &
                    (~transmitted | (original_starts > time)))) if detached else
                    int(sum(group.sign_end <= time and (not transmitted[index] or original_starts[index] > time)
                            for group in groups for index in group.members))),
                "transmission_unfinished_groups": sum(group.sign_end <= time < group.tx_end
                    and group.state != "transmission_queue_overflow" for group in groups),
                "receiver_unfinished_groups": sum(group.enqueued and group.queued_at <= time < group.verify_end
                                                  for group in groups)}
               for time in sorted(set([start, *np.linspace(start, end, 11).tolist(), horizon]))]
    summary = {
        **metrics, **receiver_stats,
        "algorithm": algorithm, "interval_k": interval, "seed": seed,
        "replay_model": replay_model, "evidence": "real_signature_fragment_reassembly_and_verification",
        "authentication_mode": "per_message" if interval == 1 else "batched",
        "signature_workload_evidence": workload.get("evidence", {}),
        "trace_messages": len(records), "trace_aircraft": len(set(aircraft)), "trace_duration_s": duration,
        "target_window_declared": declared_window,
        "target_window_boundary": "[start,end)" if declared_window else "first through last target, inclusive",
        "horizon_policy": ("declared_window_end_plus_followup; completion must occur by cutoff"
                           if declared_window else "last_target_plus_followup_plus_frame_and_max_jitter"),
        "source_groups": len(groups), "unsigned_tail_messages": len(unsigned_ids),
        "followup_s": p["followup_s"], "max_batch_wait_s": p["max_batch_wait_s"],
        "receiver_retention_s": horizon + jitter + 1,
        "receiver_association_tolerance_s": association_tolerance,
        "receiver_association_tolerance_basis": ("source_only_priority_radio_upper_bound_plus_jitter_and_timestamp_rounding"
                                                  if detached else "historical_horizon_wide_tolerance"),
        "channel_mode": p["channel_mode"],
        "auth_frames_per_second_per_aircraft": p["auth_frames_per_second"],
        "authenticated_groups": sum(group.state == "authenticated" for group in groups),
        "complete_authentication_object_groups": sum(group.delivered is not None for group in groups),
        "reconstructed_signing_input_groups": sum(math.isfinite(group.reconstruction_ready) for group in groups),
        "verification_started_groups": sum(math.isfinite(group.verify_start) for group in groups),
        "verification_completed_groups": sum(group.verification_valid is not None for group in groups),
        "cryptographically_valid_groups": sum(group.verification_valid is True for group in groups),
        "invalid_signature_groups": sum(group.verification_valid is False for group in groups),
        "verification_pending_groups": sum(group.enqueued and group.verify_end > horizon for group in groups),
        "authentication_pending_groups": sum(outcome.startswith("pending") for outcome in diagnosed),
        "authentication_definitive_failure_groups": sum(outcome != "authenticated" and
            not outcome.startswith("pending") for outcome in diagnosed),
        "ordinary_frames_transmitted": int(transmitted.sum()),
        "ordinary_frames_rf_lost": int(rf_lost.sum()),
        "ordinary_frames_in_flight_at_horizon": int((transmitted & ~completed & ~rf_lost).sum()),
        "ordinary_messages_withheld_definitively": int(known_withheld.sum()),
        "ordinary_messages_unsent_pending": int((~transmitted & ~known_withheld).sum()),
        "timing_matched_original_received_messages": int(control_received.sum()),
        "authentication_only_additional_rf_loss_messages": int((control_received & ~received).sum()),
        "authentication_only_additional_rf_loss_fraction": float((control_received & ~received).sum() / len(records)),
        "authentication_only_rf_reception_gain_messages": int((received & ~control_received).sum()),
        "auth_frames_transmitted": frame_total, "auth_frames_received": int(auth_received.sum()),
        "auth_frames_lost": auth_lost_count,
        "auth_frames_in_flight_at_horizon": auth_in_flight_count,
        "auth_frames_after_observation": frame_total - auth_capture,
        "actual_signature_bytes_total": sum(len(group.source["envelope"].signature) for group in groups),
        "signature_only_7byte_lower_bound_frames": sum(math.ceil(len(group.source["envelope"].signature) / 7)
                                                      for group in groups),
        "signature_only_7byte_lower_bound_airtime_s": sum(math.ceil(len(group.source["envelope"].signature) / 7)
                                                          for group in groups) * FRAME_S,
        "prototype_required_authentication_frames": sum(group.fragments for group in groups),
        "prototype_required_authentication_airtime_s": sum(group.fragments for group in groups) * FRAME_S,
        "target_offered_airtime_load": len(records) * FRAME_S / duration,
        "non_target_offered_airtime_load": observed_airtime / duration,
        "baseline_offered_airtime_load": (len(records) * FRAME_S + observed_airtime) / duration,
        "augmented_target_offered_airtime_load": original_capture * FRAME_S / duration,
        "additional_offered_airtime_load": auth_capture * FRAME_S / duration,
        "augmented_offered_airtime_load": ((original_capture + auth_capture) * FRAME_S + observed_airtime) / duration,
        "non_target_airtime_seconds_followup": float(np.sum(observed_durations[followup(observed_starts)])),
        "ordinary_airtime_seconds_followup": int(np.count_nonzero(followup(original_starts))) * FRAME_S,
        "authentication_airtime_seconds_followup": (frame_total - auth_capture) * FRAME_S,
        "sender_busy_seconds_all_aircraft": sender_busy,
        "sender_busy_seconds_during_capture": sender_busy_capture,
        "sender_queue_peak_per_aircraft": peak_sender, "transmission_queue_peak_per_aircraft": peak_tx,
        "sender_offered_utilization_max_per_aircraft": max(sender_required.values(), default=0) / duration,
        "authentication_radio_offered_utilization_max_per_aircraft": max(radio_required.values(), default=0) / duration,
        "authentication_required_airtime_load_max_per_aircraft": max(radio_airtime_required.values(), default=0) / duration,
        "backlog_samples": backlog, "channel_summary": channel.get("summary", {}),
        "processed_events": fixed_events + frame_total + receiver_events,
        "group_work_states_at_horizon": dict(sorted(Counter(group.state for group in groups).items())),
        **_quantiles(batch_waits, "batch_formation_wait_ms"),
        **_quantiles(sign_waits, "signing_queue_ms"),
        **_quantiles(sign_services, "signing_service_ms"),
        **_quantiles(radio_waits, "ordinary_radio_queue_ms"),
    }
    if channel_trace is not None:
        summary["observed_channel_trace"] = channel_trace["summary"]
    if detached:
        ordinary_control = _ordinary_radio_without_auth(records)
        baseline_radio_waits = ordinary_control[transmitted] - source_times[transmitted]
        added_radio_waits = original_starts[transmitted] - ordinary_control[transmitted]
        tolerance = 8 * np.spacing(np.maximum(np.abs(original_starts[transmitted]),
                                              np.abs(ordinary_control[transmitted])))
        if np.any(added_radio_waits < -tolerance):
            raise RuntimeError("Authentication radio schedule precedes its no-authentication FIFO control.")
        # Roundoff-sized negative differences are zero delay. Larger negative
        # differences above fail rather than conceal a scheduling inconsistency.
        added_radio_waits = np.maximum(added_radio_waits, 0)
        summary.update({
            **_quantiles((1000 * baseline_radio_waits).tolist(), "baseline_ordinary_radio_queue_ms"),
            **_quantiles((1000 * added_radio_waits).tolist(), "authentication_added_ordinary_delay_ms"),
            "authentication_added_ordinary_delay_positive_messages": int(np.count_nonzero(added_radio_waits > tolerance)),
            "ordinary_delay_control_cohort_messages": int(np.count_nonzero(transmitted)),
            "ordinary_delay_control_basis": "same_per_aircraft_FIFO_radio_without_authentication_frames",
        })
        summary["metric_notes"].append(
            "Authentication-added ordinary delay compares augmented transmission starts with a no-authentication "
            "per-aircraft FIFO radio control, b_i=max(source_i,b_(i-1)+frame_duration), for the same transmitted "
            "source occurrences. This removes ordinary queueing already caused by source-time ties or dense "
            "arrivals. Both delay distributions condition on actually transmitted messages; unsent counts remain separate."
        )
    summary["metric_notes"] += [
        ("Total baseline-to-augmented reception changes combine transmitter waiting, shifted transmission times, and authentication interference. The timing-matched control isolates authentication RF effects conditional on the same shifted target schedule." if detached else
         "Total baseline-to-augmented reception changes combine source withholding, shifted transmission times, and authentication interference. The timing-matched control isolates authentication RF effects conditional on the same shifted target schedule."),
        "Ordinary delay statistics condition on messages actually transmitted or received; unsent pending and definitively withheld counts must be read alongside them.",
        "Offered airtime counts full frame durations by start time, can exceed one under overlap, and is not measured physical channel occupancy.",
        "The signature-only seven-byte count is an analytical lower bound, not a replayed protocol: it excludes association and fragment headers. Both required-size counts cover every formed group and one copy, whether transmitted by the horizon or not.",
        "Verification-stage counts overlap: completed equals valid plus invalid, and source-authenticated can be smaller than cryptographically valid when source occurrence association is ambiguous. Authenticated, definitive-failure and pending group counts are disjoint.",
        "authentication_radio_offered_utilization_max_per_aircraft measures pacing demand (frames/rate), whereas authentication_required_airtime_load_max_per_aircraft uses physical frame durations.",
    ]
    events = []
    if p["record_events"]:
        for group, diagnostic in zip(groups, diagnosed):
            finite = lambda value: value if math.isfinite(value) else None
            events.append({"icao": group.descriptor.icao, "group_sequence": group.descriptor.seq,
                           "formed_s": group.formed, "message_count": len(group.members),
                           "outcome": diagnostic, "work_state": group.state,
                           "sign_start_s": finite(group.sign_start), "sign_end_s": finite(group.sign_end),
                           "ordinary_transmission_starts_s": [finite(original_starts[index]) for index in group.members],
                           "auth_tx_start_s": finite(group.tx_start), "auth_tx_end_s": finite(group.tx_end),
                           "authentication_object_ready_s": finite(group.object_ready),
                           "signing_input_reconstructed_s": finite(group.reconstruction_ready),
                           "verify_start_s": finite(group.verify_start), "verify_end_s": finite(group.verify_end),
                           "cryptographic_verification_valid": group.verification_valid,
                           "decision_s": group.decision, "fragments_sent": group.sent,
                           "fragments_received": group.received_fragments, "required_fragments": group.fragments})
    assumptions = list(ASSUMPTIONS)
    if detached:
        assumptions[1] = "Each aircraft has one serial signer and one radio. Every ordinary message is released at its source timestamp, including unsigned tails and groups rejected by signing queues. Ready ordinary messages have FIFO priority; an ongoing authentication frame is not preempted."
        assumptions[4] = "The baseline uses recorded target times; the augmented run releases targets independently of collection and signing, with radio contention allowed to shift them. A timing-matched control removes authentication frames while retaining the augmented target schedule to isolate their RF effect."
        assumptions[5] = "A fixed capture-plus-follow-up horizon censors unfinished work. Incomplete fixed-count groups cannot authenticate, but their ordinary messages are still transmitted; radio-pending originals remain separate from RF losses."
        assumptions[6] = "Receiver reconstruction uses received raw bytes, signed tags and provisioned keys/session, never sender trace IDs. A shared timing allowance is supplied from an input-only priority-radio upper bound: per aircraft b_i=max(a_i+F,b_(i-1)+F), tolerance=max_i(b_i+F-a_i)+receive jitter+1 microsecond for timestamp rounding. It is fixed across signing/grouping/rate cases for the same trace and jitter, not inferred from actual delays or operational clocks. Retention still spans the horizon; excess matching observations inside the signed first/last window plus this allowance remain ambiguous."
    if declared_window:
        cutoff_note = (
            "The declared target window is [start,end), including quiet edges. The fixed observation cutoff is exactly "
            "window end plus follow-up, without added frame time or jitter. Only frame receptions and verification "
            "completions at or before this cutoff count as complete; in-flight work remains pending. Offered airtime "
            "counts full envelopes by start time, with starts at window end assigned to follow-up."
        )
        assumptions.append(cutoff_note)
        summary["metric_notes"].append(cutoff_note)
    return {"summary": summary, "outcomes": dict(sorted(Counter(diagnosed).items())),
            "parameters": p, "assumptions": assumptions, "events": events}


def _receive(records, raw, groups, receiver, received, reception_times,
             auth_arrivals, auth_received, p, horizon, rng_verify, verify_samples,
             previous_events, *, auth_arrival_offset=0.0):
    heap, serial = [], 0
    def schedule(time, priority, kind, value):
        nonlocal serial
        serial += 1
        heapq.heappush(heap, (time, priority, serial, kind, value))
    for index in np.flatnonzero(received):
        schedule(float(reception_times[index]), 0, "original", int(index))
    copies = p["fragment_copies"]
    for index, group in enumerate(groups):
        if not group.sent:
            continue
        lo, hi = group.offset, group.offset + group.sent
        physical_arrivals = auth_arrivals[lo:hi] + auth_arrival_offset
        arrivals = np.where(auth_received[lo:hi], physical_arrivals, np.inf)
        if len(arrivals) % copies:
            arrivals = np.pad(arrivals, (0, copies - len(arrivals) % copies), constant_values=np.inf)
        logical_arrivals = arrivals.reshape(-1, copies).min(axis=1)
        group.received_fragments = int(np.isfinite(logical_arrivals).sum())
        finished_count = group.sent // copies
        if finished_count:
            finishes = physical_arrivals[:finished_count * copies].reshape(-1, copies).max(axis=1)
            if np.any((finishes <= horizon) & ~np.isfinite(logical_arrivals[:finished_count])):
                group.known_failure = "fragments_lost"
        if len(logical_arrivals) == group.fragments and np.all(np.isfinite(logical_arrivals)):
            # Exercise actual byte fragments, not an assumed successful decode.
            assembler = FragmentReassembler(horizon + 1, max_pending_groups=1)
            fragments = fragment_envelope(group.source["envelope"])
            envelope = None
            for part in np.argsort(logical_arrivals, kind="stable"):
                status, envelope = assembler.add(group.descriptor.icao, fragments[int(part)],
                                                  float(logical_arrivals[part]))
            if status != "reassembled" or envelope is None:
                group.state = "malformed_object"
                continue
            group.delivered = envelope
            group.object_ready = float(logical_arrivals.max())
            schedule(group.object_ready, 1, "object", index)
        elif group.known_failure:
            group.state = "fragments_lost"
    queue, waiting_originals = deque(), defaultdict(set)
    busy = peak_queue = events = 0
    receiver_busy = 0.0
    waits = []
    auth_at = np.full(len(records), np.nan)
    def start_workers(now):
        nonlocal busy, receiver_busy
        while queue and busy < p["receiver_workers"]:
            index, ready = queue.popleft()
            group = groups[index]
            group.verify_start = now
            group.verify_end = now + rng_verify.choice(verify_samples) / 1000
            group.state = "pending_verifying"
            waits.append((now - ready) * 1000)
            receiver_busy += max(0.0, min(horizon, group.verify_end) - now)
            busy += 1
            schedule(group.verify_end, 2, "verified", index)
    def reconstruct(index, now):
        nonlocal peak_queue
        group = groups[index]
        if group.enqueued:
            return
        result = receiver.reconstruct(group.delivered.descriptor, now)
        if result.status in {"missing_message", "not_yet_current"}:
            group.state = "pending_original_messages"
            waiting_originals[group.descriptor.icao].add(index)
            return
        waiting_originals[group.descriptor.icao].discard(index)
        if result.status != "ready":
            group.state, group.decision = result.status, now
            return
        group.reconstruction_ready = min(group.reconstruction_ready, now)
        if p["receiver_queue_limit"] is not None and len(queue) >= p["receiver_queue_limit"]:
            group.state, group.decision = "receiver_queue_overflow", now
            return
        group.enqueued = True
        group.queued_at = now
        group.signing_input = result.signing_input
        descriptor = group.delivered.descriptor
        first = descriptor.first_us - receiver.clock_tolerance_us
        last = min(descriptor.last_us + receiver.clock_tolerance_us, round(now * 1_000_000))
        tags = set(descriptor.message_tags)
        observations = receiver.observations[descriptor.icao]
        chosen = [position for position, (time_us, _, tag) in enumerate(observations)
                  if first <= time_us <= last and tag in tags]
        group.reserved_observations = [observations[position] for position in chosen]
        chosen_set = set(chosen)
        receiver.observations[descriptor.icao] = [item for position, item in enumerate(observations)
                                                if position not in chosen_set]
        group.state = "pending_verification_queue"
        queue.append((index, now))
        peak_queue = max(peak_queue, len(queue))
        start_workers(now)
    while heap:
        now, _, _, kind, index = heapq.heappop(heap)
        if now > horizon:
            break
        events += 1
        if previous_events + events > p["max_events"]:
            raise RuntimeError("Signed replay max_events exceeded; no partial result may be published.")
        if kind == "original":
            receiver.observe_message(raw[index], now)
            for group_index in sorted(waiting_originals[records[index]["icao"]]):
                reconstruct(group_index, now)
        elif kind == "object":
            reconstruct(index, now)
        else:
            busy -= 1
            group = groups[index]
            descriptor = group.delivered.descriptor
            binding = receiver.bindings[descriptor.icao, descriptor.algorithm]
            try:
                valid = binding.verifier(group.signing_input, group.delivered.signature)
            except Exception:
                valid = False
            group.verification_valid = bool(valid)
            group.state, group.decision = "authenticated" if valid else "invalid_signature", now
            if valid:
                receiver.accepted.add((descriptor.icao, descriptor.session, descriptor.seq))
                # This comparison is only source-accounting evidence. The
                # receiver selected/verified its bytes without trace IDs.
                selected_occurrences = Counter((time_us, message)
                    for time_us, message, _ in group.reserved_observations)
                actual_occurrences = Counter((round(reception_times[member] * 1_000_000), raw[member])
                    for member in group.members if received[member])
                if (np.all(received[list(group.members)])
                        and np.all(reception_times[list(group.members)] <= group.queued_at)
                        and selected_occurrences == actual_occurrences):
                    auth_at[list(group.members)] = now
                else:
                    group.state = "ambiguous_message"
            else:
                receiver.observations[descriptor.icao].extend(group.reserved_observations)
                receiver.observations[descriptor.icao].sort(key=lambda item: item[0])
                for group_index in sorted(waiting_originals[descriptor.icao]):
                    reconstruct(group_index, now)
            group.reserved_observations.clear()
            group.signing_input = None
            start_workers(now)
    outcomes = np.full(len(records), "unsigned_tail", dtype=object)
    diagnosed = []
    for group in groups:
        diagnostic = group.state
        # Diagnostics use experiment truth only after receiver processing;
        # neither signing nor receiver reconstruction gets loss feedback.
        if diagnostic.startswith("pending"):
            if any(math.isfinite(reception_times[index]) and reception_times[index] <= horizon
                   and not received[index] for index in group.members):
                diagnostic = "missing_message"
            elif group.known_failure:
                diagnostic = group.known_failure
        diagnosed.append(diagnostic)
        outcomes[list(group.members)] = diagnostic
    for index in range(len(records)):
        if math.isfinite(reception_times[index]) and reception_times[index] <= horizon and not received[index]:
            outcomes[index] = "original_lost"
    return auth_at, outcomes.tolist(), diagnosed, {
        "receiver_busy_seconds_all_workers": receiver_busy, "receiver_queue_peak": peak_queue,
        **_quantiles(waits, "verification_queue_ms"),
    }, events
