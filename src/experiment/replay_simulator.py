"""Seeded discrete-event replay of detached per-message and batched authentication.

Surveillance emissions retain their observed timestamps. They are a transmitter
proxy, not a reconstruction of unobserved RF traffic. This module models genuine
signature sizes and sourced service times; it does not generate signatures.
Actual cryptographic reconstruction is tested separately in replay_transport.
"""

from bisect import bisect_right
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
import hashlib
import heapq
import math
import random

from .hardware_profiles import timing_samples_ms
from .replay_transport import ReplayReceiver, describe_group, fragment_count, object_size_bytes


FRAME_S = 120e-6
DEFAULTS = {
    "max_auth_age_s": 5.0, "max_batch_wait_s": None,
    "auth_frames_per_second": 100.0, "receiver_workers": 1,
    "sender_queue_limit": 256, "receiver_queue_limit": 4096,
    "fragment_copies": 1, "background_occupancy": 0.0,
    "receive_jitter_ms": 0.0, "loss": {"kind": "iid", "probability": 0.01},
    "max_events": 10_000_000, "record_events": False,
}
ASSUMPTIONS = [
    "Observed surveillance timestamps are replayed unchanged as hypothetical sender emission times; missing real transmissions are unknown.",
    "Authentication always follows surveillance; one signature covers one message or a sender-formed batch.",
    "The explicit illustrative wire format uses a 7-byte ME field, a 4-byte fragment header, and signed association/freshness metadata; no allocated ADS-B message type is asserted.",
    "Each aircraft has one signing processor and one FIFO authentication transmitter with a configured frame-rate limit; normal frames have priority on that aircraft's radio.",
    "There is no global channel scheduler, collision/capture simulation or feedback retransmission. Background load is reported additively; loss is an explicit exogenous scenario, not inferred from offered load.",
    "Receiver observations and fragments experience seeded losses and optional bounded reception jitter. Shared clocks, provisioned identity/key/session bindings and no credential transport are assumed.",
    "Sender group descriptions reach the receiver only after every distinct fragment arrives; receiver decisions use observed raw messages and transmitted association metadata, never source trace IDs.",
    "Signature sizes and CPU service times are modeled. Authentication success here is a modeled decision, not a new cryptographic verification.",
    "Published mean service times are constants, not measured timing distributions or worst-case execution bounds. Key generation is offline.",
    "The authentication deadline is an analyst-selected age of the oldest message, not a regulatory ADS-B authentication requirement.",
]


def _number(value, name, minimum=0, maximum=None, positive=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{name} must be finite.")
    if value < minimum or (positive and value <= minimum) or (maximum is not None and value > maximum):
        raise ValueError(f"{name} is outside the allowed range.")
    return value


def validate_scenario(scenario):
    unknown = set(scenario) - set(DEFAULTS)
    if unknown:
        raise ValueError(f"Unknown replay parameters: {sorted(unknown)}")
    result = {**DEFAULTS, **scenario}
    for name in ("max_auth_age_s", "auth_frames_per_second"):
        _number(result[name], name, positive=True)
    if result["auth_frames_per_second"] > 1 / FRAME_S:
        raise ValueError("Authentication frame rate exceeds physical frame serialization capacity.")
    if result["max_batch_wait_s"] is not None:
        _number(result["max_batch_wait_s"], "max_batch_wait_s", positive=True)
    _number(result["background_occupancy"], "background_occupancy", maximum=1)
    _number(result["receive_jitter_ms"], "receive_jitter_ms")
    for name in ("receiver_workers", "sender_queue_limit", "receiver_queue_limit", "fragment_copies", "max_events"):
        if type(result[name]) is not int or result[name] < 1:
            raise ValueError(f"{name} must be a positive integer.")
    if type(result["record_events"]) is not bool:
        raise ValueError("record_events must be boolean.")
    loss = result["loss"]
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
    return result


class LossProcess:
    """Shared time-based burst states; independent seeded original/auth draws."""

    def __init__(self, config, seed, horizon):
        self.config = config
        self.original = random.Random(seed + 1009)
        self.authentication = random.Random(seed + 2027)
        self.changes, self.bad = [], []
        if config["kind"] == "gilbert_elliott":
            rng = random.Random(seed + 3049)
            stationary_bad = config["mean_bad_s"] / (config["mean_bad_s"] + config["mean_good_s"])
            bad, time = rng.random() < stationary_bad, 0.0
            while time <= horizon:
                if len(self.changes) >= 1_000_000:
                    raise ValueError("Burst scenario produces too many state transitions.")
                self.changes.append(time)
                self.bad.append(bad)
                time += rng.expovariate(1 / config["mean_bad_s" if bad else "mean_good_s"])
                bad = not bad

    def lost(self, time, original=False):
        if self.config["kind"] == "iid":
            probability = self.config["probability"]
        else:
            state = self.bad[bisect_right(self.changes, time) - 1]
            probability = self.config["bad_loss" if state else "good_loss"]
        return (self.original if original else self.authentication).random() < probability


@dataclass
class Group:
    descriptor: object
    times: tuple
    formed: float
    signature_bytes: int
    fragments: int
    deadline: float
    state: str = "waiting_formation"
    outcome: str | None = None
    sent: int = 0
    received: set = field(default_factory=set)
    signing_started: float | None = None
    verification_ready: float | None = None
    verification_enqueued: bool = False
    signing_queue_s: float = 0.0
    verification_queue_s: float = 0.0


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


def simulate(trace, algorithm, interval, signature_sizes, sender_profile, receiver_profile, scenario, seed=1):
    """Run one independent scenario; all success fields explicitly mean modeled."""
    parameters = validate_scenario(scenario)
    if type(seed) is not int:
        raise ValueError("seed must be an integer.")
    if not signature_sizes or any(type(size) is not int or size <= 0 for size in signature_sizes):
        raise ValueError("Signature sizes must be a nonempty list of positive integers.")
    sign_ms = timing_samples_ms(sender_profile, algorithm, "sign")
    verify_ms = timing_samples_ms(receiver_profile, algorithm, "verify")
    records = list(trace.values()) if isinstance(trace, dict) else list(trace)
    records.sort(key=lambda record: (record["relative_time_s"], record["trace_id"]))
    if not records:
        raise ValueError("Replay requires a nonempty trace.")
    ids = set()
    for record in records:
        _number(record["relative_time_s"], "trace time")
        raw = bytes.fromhex(record["raw_msg"])
        if len(raw) != 14 or raw[0] >> 3 != 17 or raw[1:4].hex().upper() != record["icao"]:
            raise ValueError("Replay requires canonical DF17 messages with matching aircraft addresses.")
        if record["trace_id"] in ids:
            raise ValueError("Duplicate source trace ID.")
        ids.add(record["trace_id"])
    start, end = records[0]["relative_time_s"], records[-1]["relative_time_s"]
    if end <= start:
        raise ValueError("Replay requires a positive observation duration.")
    age = parameters["max_auth_age_s"]
    jitter = parameters["receive_jitter_ms"] / 1000
    tolerance = FRAME_S + jitter + 1e-6
    horizon = end + age + tolerance
    loss = LossProcess(parameters["loss"], seed, horizon)
    rng_sizes, rng_sign, rng_verify = (random.Random(seed + offset) for offset in (4013, 5021, 6011))
    rng_base_jitter, rng_auth_jitter = random.Random(seed + 7013), random.Random(seed + 8011)
    session = hashlib.sha256(f"replay-session:{seed}".encode()).digest()[:8]
    public_keys = {record["icao"]: hashlib.sha256(("modeled-key:" + record["icao"]).encode()).digest() for record in records}
    receiver = ReplayReceiver(age, tolerance)
    for icao, public_key in public_keys.items():
        receiver.register(icao, algorithm, public_key, session)
    source_groups, unsigned = form_groups(records, interval, parameters["max_batch_wait_s"])
    groups = []
    for icao, seq, entries, formed in source_groups:
        messages = [(record["relative_time_s"], bytes.fromhex(record["raw_msg"])) for record in entries]
        descriptor = describe_group(icao, seq, session, messages, algorithm, public_keys[icao])
        size = rng_sizes.choice(signature_sizes)
        groups.append(Group(descriptor, tuple(time for time, _ in messages), formed, size,
                            fragment_count(object_size_bytes(len(messages), size)), messages[0][0] + age))
    del source_groups

    heap, serial = [], 0
    def schedule(time, priority, kind, value):
        nonlocal serial
        serial += 1
        heapq.heappush(heap, (time, priority, serial, kind, value))

    counters = Counter()
    for record in records:
        time = record["relative_time_s"]
        if loss.lost(time, original=True):
            counters["original_frames_lost"] += 1
        else:
            schedule(time + FRAME_S + rng_base_jitter.uniform(0, jitter), 0, "baseline",
                     bytes.fromhex(record["raw_msg"]))
    for index, group in enumerate(groups):
        schedule(group.formed, 1, "group", index)
        schedule(group.deadline + 1e-9, 9, "expiry", index)
    baseline_times = defaultdict(list)
    for record in records:
        baseline_times[record["icao"]].append(record["relative_time_s"])
    sender_queues, tx_queues = defaultdict(deque), defaultdict(deque)
    sender_busy, tx_pending, tx_available = set(), set(), defaultdict(float)
    verify_queue, waiting_originals = deque(), defaultdict(set)
    verify_busy = 0
    sender_busy_seconds, verify_busy_seconds = 0.0, 0.0
    peak_sender, peak_verify = 0, 0
    latencies, sign_waits, verify_waits, event_rows = [], [], [], []

    def finish(index, outcome, now):
        group = groups[index]
        if group.outcome is not None:
            return
        group.outcome = outcome
        waiting_originals[group.descriptor.icao].discard(index)
        # Expired queued work must release its bounded queue slot immediately.
        for queue in (sender_queues[group.descriptor.icao], verify_queue):
            try:
                queue.remove(index)
            except ValueError:
                pass
        counters[outcome] += 1
        if outcome == "modeled_authenticated":
            counters["modeled_authenticated_messages"] += len(group.times)
            latencies.extend((now - time) * 1000 for time in group.times)
        if parameters["record_events"]:
            event_rows.append({"icao": group.descriptor.icao, "group_sequence": group.descriptor.seq,
                               "message_count": len(group.times), "formed_s": group.formed,
                               "deadline_s": group.deadline, "decision_s": now, "outcome": outcome,
                               "signature_bytes": group.signature_bytes, "required_fragments": group.fragments,
                               "fragments_sent": group.sent, "distinct_fragments_received": len(group.received)})
        group.received.clear()

    def start_signer(icao, now):
        nonlocal sender_busy_seconds
        if icao in sender_busy:
            return
        queue = sender_queues[icao]
        while queue:
            index = queue.popleft()
            group = groups[index]
            if group.outcome is not None:
                continue
            if now > group.deadline:
                finish(index, "expired_sender_queue", now)
                continue
            group.state = "signing"
            group.signing_started = now
            group.signing_queue_s = now - group.formed
            sign_waits.append(group.signing_queue_s * 1000)
            service = rng_sign.choice(sign_ms) / 1000
            sender_busy_seconds += max(0, min(service, horizon - now))
            sender_busy.add(icao)
            schedule(now + service, 2, "signed", index)
            return

    def radio_slot(icao, now):
        times = baseline_times[icao]
        now = max(now, tx_available[icao])
        position = max(0, bisect_right(times, now) - 1)
        while position < len(times) and times[position] < now + FRAME_S:
            if times[position] + FRAME_S > now:
                now = times[position] + FRAME_S
            position += 1
        return now

    def schedule_tx(icao, now):
        if icao not in tx_pending and tx_queues[icao]:
            tx_pending.add(icao)
            schedule(radio_slot(icao, now), 3, "transmit", icao)

    def start_verifiers(now):
        nonlocal verify_busy, verify_busy_seconds
        while verify_busy < parameters["receiver_workers"] and verify_queue:
            index = verify_queue.popleft()
            group = groups[index]
            if group.outcome is not None:
                continue
            if now > group.deadline:
                finish(index, "expired_receiver_queue", now)
                continue
            group.state = "verifying"
            group.verification_queue_s = now - group.verification_ready
            verify_waits.append(group.verification_queue_s * 1000)
            service = rng_verify.choice(verify_ms) / 1000
            verify_busy_seconds += max(0, min(service, horizon - now))
            verify_busy += 1
            schedule(now + service, 6, "verified", index)

    def try_reconstruction(index, now):
        nonlocal peak_verify
        group = groups[index]
        if group.outcome is not None or group.verification_enqueued:
            return
        result = receiver.reconstruct(group.descriptor, now)
        if result.status in {"missing_message", "not_yet_current"}:
            group.state = "waiting_original_messages"
            waiting_originals[group.descriptor.icao].add(index)
            return
        waiting_originals[group.descriptor.icao].discard(index)
        if result.status != "ready":
            finish(index, result.status, now)
            return
        if len(verify_queue) >= parameters["receiver_queue_limit"]:
            finish(index, "receiver_queue_overflow", now)
            return
        group.state, group.verification_ready = "verification_queue", now
        group.verification_enqueued = True
        verify_queue.append(index)
        peak_verify = max(peak_verify, len(verify_queue))
        start_verifiers(now)

    processed_events = 0
    while heap:
        now, _, _, kind, value = heapq.heappop(heap)
        if now > horizon:
            break
        processed_events += 1
        if processed_events > parameters["max_events"]:
            raise RuntimeError("Replay max_events exceeded; no complete result may be published. Increase the configured limit or narrow the scenario.")
        if kind == "baseline":
            receiver.observe_message(value, now)
            counters["original_frames_received"] += 1
            for index in tuple(waiting_originals[value[1:4].hex().upper()]):
                try_reconstruction(index, now)
        elif kind == "group":
            group = groups[value]
            if group.outcome is not None:
                continue
            if now > group.deadline:
                finish(value, "expired_formation", now)
                continue
            icao = group.descriptor.icao
            if len(sender_queues[icao]) >= parameters["sender_queue_limit"]:
                finish(value, "sender_queue_overflow", now)
                continue
            group.state = "sender_queue"
            sender_queues[icao].append(value)
            peak_sender = max(peak_sender, len(sender_queues[icao]))
            start_signer(icao, now)
        elif kind == "signed":
            group = groups[value]
            icao = group.descriptor.icao
            sender_busy.discard(icao)
            if group.outcome is None:
                group.state = "transmission_queue"
                tx_queues[icao].append(value)
                schedule_tx(icao, now)
            start_signer(icao, now)
        elif kind == "transmit":
            icao = value
            tx_pending.discard(icao)
            queue = tx_queues[icao]
            # No feedback channel: a receiver decision cannot cancel sender copies.
            while queue and (now > groups[queue[0]].deadline or
                             groups[queue[0]].sent >= groups[queue[0]].fragments * parameters["fragment_copies"]):
                queue.popleft()
            if not queue:
                continue
            index = queue[0]
            group = groups[index]
            if not group.verification_enqueued:
                group.state = "transmitting"
            part = group.sent // parameters["fragment_copies"]
            group.sent += 1
            counters["auth_frames_transmitted"] += 1
            counters["auth_frames_within_observation" if now <= end else "auth_frames_after_observation"] += 1
            if loss.lost(now):
                counters["auth_frames_lost"] += 1
            else:
                schedule(now + FRAME_S + rng_auth_jitter.uniform(0, jitter), 4, "fragment", (index, part))
            tx_available[icao] = now + max(FRAME_S, 1 / parameters["auth_frames_per_second"])
            if group.sent == group.fragments * parameters["fragment_copies"]:
                queue.popleft()
                if not group.verification_enqueued:
                    group.state = "waiting_fragments"
            schedule_tx(icao, now)
        elif kind == "fragment":
            index, part = value
            group = groups[index]
            counters["auth_frames_received"] += 1
            if group.outcome is None:
                group.received.add(part)
                if len(group.received) == group.fragments:
                    try_reconstruction(index, now)
        elif kind == "verified":
            verify_busy -= 1
            group = groups[value]
            if group.outcome is None:
                # Recheck observations and freshness at the actual completion time.
                decision = receiver.accept_modeled(group.descriptor, now)
                finish(value, decision.status, now)
            start_verifiers(now)
        elif kind == "expiry":
            group = groups[value]
            if group.outcome is None:
                finish(value, "expired_" + group.state, now)

    if any(group.outcome is None for group in groups):
        raise RuntimeError("Replay ended without a decision for every sender group.")
    authenticated = counters["modeled_authenticated_messages"]
    duration = end - start
    baseline_load = len(records) * FRAME_S / duration
    additional_load = counters["auth_frames_within_observation"] * FRAME_S / duration
    summary = {
        "algorithm": algorithm, "interval_k": interval, "seed": seed,
        "authentication_mode": "per_message" if interval == 1 else "batched",
        "evidence": "modeled_authentication_with_receiver_reconstruction",
        "sender_profile": sender_profile.get("id", "test"), "receiver_profile": receiver_profile.get("id", "test"),
        "trace_messages": len(records), "trace_aircraft": len(public_keys), "trace_duration_s": duration,
        "source_groups": len(groups), "unsigned_tail_messages": unsigned,
        "max_auth_age_s": age, "max_batch_wait_s": parameters["max_batch_wait_s"],
        "auth_frames_per_second_per_aircraft": parameters["auth_frames_per_second"],
        "modeled_authenticated_groups": counters["modeled_authenticated"],
        "modeled_authenticated_messages": authenticated,
        "timely_authenticated_source_fraction": authenticated / len(records),
        "timely_authenticated_received_fraction": authenticated / counters["original_frames_received"] if counters["original_frames_received"] else 0.0,
        "original_frames_received": counters["original_frames_received"], "original_frames_lost": counters["original_frames_lost"],
        "auth_frames_transmitted": counters["auth_frames_transmitted"], "auth_frames_received": counters["auth_frames_received"],
        "auth_frames_lost": counters["auth_frames_lost"], "auth_frames_after_observation": counters["auth_frames_after_observation"],
        "baseline_offered_airtime_load": baseline_load, "additional_offered_airtime_load": additional_load,
        "total_offered_airtime_load": baseline_load + additional_load + parameters["background_occupancy"],
        "sender_busy_seconds_all_aircraft": sender_busy_seconds, "receiver_busy_seconds_all_workers": verify_busy_seconds,
        "sender_queue_peak_per_aircraft": peak_sender, "receiver_queue_peak": peak_verify,
        "processed_events": processed_events,
        **_quantiles(latencies, "timely_authentication_age_ms"),
        **_quantiles(sign_waits, "signing_queue_ms"),
        **_quantiles(verify_waits, "verification_queue_ms"),
    }
    outcomes = Counter(group.outcome for group in groups)
    if (sum(outcomes.values()) != len(groups)
            or sum(len(group.times) for group in groups) + unsigned != len(records)
            or authenticated > counters["original_frames_received"]):
        raise RuntimeError("Replay group/message accounting failed.")
    return {"summary": summary, "outcomes": dict(sorted(outcomes.items())),
            "parameters": parameters, "assumptions": ASSUMPTIONS, "events": event_rows}
