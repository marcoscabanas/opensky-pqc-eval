"""Illustrative authentication extension for the operational replay experiment.

This is not a deployed ADS-B format. Normal surveillance messages are transmitted
unchanged; authentication follows in separate, optimistically assigned 7-byte
ME fields. Four bytes identify a group and fragment, leaving three data bytes.
The external aircraft address is also bound inside the signed context.

The receiver only observes raw messages and reception times. Association assumes
a shared microsecond clock and zero propagation unless a tolerance is supplied.
Repeated identical receptions cannot reliably be distinguished from repeated
transmissions: excess matching observations are rejected as ambiguous. Compact
64-bit message tags are association hints, not cryptographic authentication.
The signature covers the entire context and the ordered original messages.
Keys and the current session are provisioned out of band; distribution, session
negotiation, fragment type allocation, and certificate overhead are outside this
illustrative extension. The legacy raw-message signatures are not reused here.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import hashlib
import math
import struct
from typing import Callable, Iterable


MAGIC = b"OA01"
SESSION_BYTES = 8
TAG_BYTES = 8
KEY_FINGERPRINT_BYTES = 16
ME_BYTES = 7
FRAGMENT_HEADER_BYTES = 4
MAX_SEQUENCE = 65535
MAX_OBJECT_BYTES = 65535
ALGORITHM_CODES = {
    "ECDSA-P256": 1,
    "ML-DSA-44": 2,
    "FN-DSA-512": 3,
    "SLH-DSA-SHA2-128s": 4,
}
_ALGORITHM_NAMES = {value: key for key, value in ALGORITHM_CODES.items()}
_CONTEXT_HEADER = struct.Struct(">4sB3s8sHQQH16s")
_FRAGMENT_HEADER = struct.Struct(">HH")
CONTEXT_FIXED_BYTES = _CONTEXT_HEADER.size
OBJECT_FIXED_BYTES = CONTEXT_FIXED_BYTES + 2


def _icao(value: str) -> str:
    value = value.upper()
    if len(value) != 6:
        raise ValueError("Aircraft address must contain six hexadecimal digits.")
    try:
        bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("Aircraft address must contain six hexadecimal digits.") from exc
    return value


def _time_us(time_s: float) -> int:
    if not math.isfinite(time_s) or time_s < 0:
        raise ValueError("Replay times must be finite and nonnegative.")
    value = round(time_s * 1_000_000)
    if value > (1 << 64) - 1:
        raise ValueError("Replay time exceeds the uint64 microsecond range.")
    return value


def message_tag(raw: bytes) -> bytes:
    if len(raw) != 14:
        raise ValueError("A baseline ADS-B message must contain 14 bytes.")
    return hashlib.sha256(raw).digest()[:TAG_BYTES]


def key_fingerprint(public_key: bytes) -> bytes:
    return hashlib.sha256(public_key).digest()[:KEY_FINGERPRINT_BYTES]


@dataclass(frozen=True)
class GroupDescriptor:
    icao: str
    seq: int
    session: bytes
    first_us: int
    last_us: int
    message_tags: tuple[bytes, ...]
    algorithm: str
    key_fingerprint: bytes

    @property
    def message_count(self) -> int:
        return len(self.message_tags)


@dataclass(frozen=True)
class Envelope:
    descriptor: GroupDescriptor
    signature: bytes


def context_bytes(descriptor: GroupDescriptor) -> bytes:
    """Encode every association and freshness field covered by the signature."""
    if descriptor.algorithm not in ALGORITHM_CODES:
        raise ValueError("Unknown replay signature algorithm.")
    if not 0 <= descriptor.seq <= MAX_SEQUENCE:
        raise ValueError("Group sequence exceeds uint16; use a new provisioned session.")
    if len(descriptor.session) != SESSION_BYTES:
        raise ValueError("Session must contain exactly eight bytes.")
    if len(descriptor.key_fingerprint) != KEY_FINGERPRINT_BYTES:
        raise ValueError("Key fingerprint must contain exactly sixteen bytes.")
    if not 0 <= descriptor.first_us <= descriptor.last_us < 1 << 64:
        raise ValueError("Invalid source time interval.")
    if not 1 <= descriptor.message_count <= 65535:
        raise ValueError("A group must contain between one and 65535 messages.")
    if any(len(tag) != TAG_BYTES for tag in descriptor.message_tags):
        raise ValueError("Each compact message tag must contain eight bytes.")
    return _CONTEXT_HEADER.pack(
        MAGIC, ALGORITHM_CODES[descriptor.algorithm], bytes.fromhex(_icao(descriptor.icao)),
        descriptor.session, descriptor.seq, descriptor.first_us, descriptor.last_us,
        descriptor.message_count, descriptor.key_fingerprint,
    ) + b"".join(descriptor.message_tags)


def describe_group(
    icao: str, seq: int, session: bytes, messages: Iterable[tuple[float, bytes]],
    algorithm: str, public_key: bytes,
) -> GroupDescriptor:
    """Build metadata at the sender before any receiver-side losses are applied."""
    icao = _icao(icao)
    items = [(_time_us(time_s), raw) for time_s, raw in messages]
    if not items:
        raise ValueError("Cannot authenticate an empty group.")
    if any(raw[1:4].hex().upper() != icao for _, raw in items):
        raise ValueError("Every source message must carry the declared aircraft address.")
    if any(items[index][0] > items[index + 1][0] for index in range(len(items) - 1)):
        raise ValueError("Sender messages must be ordered by source time.")
    tags = tuple(message_tag(raw) for _, raw in items)
    distinct_by_tag: dict[bytes, set[bytes]] = defaultdict(set)
    for tag, (_, raw) in zip(tags, items):
        distinct_by_tag[tag].add(raw)
    if any(len(values) != 1 for values in distinct_by_tag.values()):
        raise ValueError("Compact message tag collision in source group.")
    descriptor = GroupDescriptor(
        icao, seq, session, items[0][0], items[-1][0], tags, algorithm,
        key_fingerprint(public_key),
    )
    context_bytes(descriptor)
    return descriptor


def make_envelope(
    icao: str, seq: int, session: bytes, messages: Iterable[tuple[float, bytes]],
    algorithm: str, signer,
) -> Envelope:
    """Create a real signature over context plus ordered raw surveillance messages."""
    items = list(messages)
    descriptor = describe_group(icao, seq, session, items, algorithm, signer.public_key_bytes())
    signature = signer.sign(context_bytes(descriptor) + b"".join(raw for _, raw in items))
    envelope = Envelope(descriptor, signature)
    encode_envelope(envelope)
    return envelope


def object_size_bytes(message_count: int, signature_bytes: int) -> int:
    """Exact serialized object size, including all fields and signature length."""
    if not 1 <= message_count <= 65535 or not 1 <= signature_bytes <= 65535:
        raise ValueError("Message count and signature size must be positive uint16 values.")
    result = OBJECT_FIXED_BYTES + TAG_BYTES * message_count + signature_bytes
    if result > MAX_OBJECT_BYTES:
        raise ValueError("Authentication object exceeds its uint16 length field.")
    return result


def fragment_count(object_bytes: int, me_bytes: int = ME_BYTES) -> int:
    """Count full ME fields including fragment headers, stream length, and padding."""
    if not 1 <= object_bytes <= MAX_OBJECT_BYTES:
        raise ValueError("Object length must be a positive uint16 value.")
    if me_bytes != ME_BYTES:
        raise ValueError("This illustrative extension defines a seven-byte ME field.")
    return math.ceil((object_bytes + 2) / (me_bytes - FRAGMENT_HEADER_BYTES))


def encode_envelope(envelope: Envelope) -> bytes:
    descriptor, signature = envelope.descriptor, envelope.signature
    object_size_bytes(descriptor.message_count, len(signature))
    return context_bytes(descriptor) + struct.pack(">H", len(signature)) + signature


def decode_envelope(encoded: bytes) -> Envelope:
    if len(encoded) < OBJECT_FIXED_BYTES + TAG_BYTES + 1 or len(encoded) > MAX_OBJECT_BYTES:
        raise ValueError("Invalid authentication object length.")
    magic, algorithm, icao, session, seq, first_us, last_us, count, fingerprint = (
        _CONTEXT_HEADER.unpack_from(encoded)
    )
    if magic != MAGIC or algorithm not in _ALGORITHM_NAMES:
        raise ValueError("Unknown authentication object format or algorithm.")
    tag_end = CONTEXT_FIXED_BYTES + count * TAG_BYTES
    if count < 1 or tag_end + 2 > len(encoded):
        raise ValueError("Truncated message tag list.")
    signature_size = struct.unpack_from(">H", encoded, tag_end)[0]
    if not signature_size or tag_end + 2 + signature_size != len(encoded):
        raise ValueError("Signature length does not match the object.")
    descriptor = GroupDescriptor(
        icao.hex().upper(), seq, session, first_us, last_us,
        tuple(encoded[offset:offset + TAG_BYTES]
              for offset in range(CONTEXT_FIXED_BYTES, tag_end, TAG_BYTES)),
        _ALGORITHM_NAMES[algorithm], fingerprint,
    )
    context_bytes(descriptor)
    return Envelope(descriptor, encoded[tag_end + 2:])


def fragment_envelope(envelope: Envelope) -> list[bytes]:
    """Return seven-byte ME fields; ICAO remains in the external ADS-B header."""
    encoded = encode_envelope(envelope)
    stream = struct.pack(">H", len(encoded)) + encoded
    payload_bytes = ME_BYTES - FRAGMENT_HEADER_BYTES
    return [
        _FRAGMENT_HEADER.pack(envelope.descriptor.seq, index)
        + stream[offset:offset + payload_bytes].ljust(payload_bytes, b"\0")
        for index, offset in enumerate(range(0, len(stream), payload_bytes))
    ]


@dataclass
class _Assembly:
    first_reception_us: int
    parts: dict[int, bytes] = field(default_factory=dict)
    object_bytes: int | None = None
    largest_part: int = -1


class FragmentReassembler:
    """Independent bounded reassembly with exact duplicate and conflict checks."""

    def __init__(self, max_age_s: float, max_pending_groups: int = 4096):
        self.max_age_us = _time_us(max_age_s)
        if self.max_age_us <= 0 or max_pending_groups < 1:
            raise ValueError("Reassembly age and capacity must be positive.")
        self.max_pending_groups = max_pending_groups
        self.pending: dict[tuple[str, int], _Assembly] = {}

    def add(self, icao: str, fragment: bytes, now_s: float) -> tuple[str, Envelope | None]:
        now_us, icao = _time_us(now_s), _icao(icao)
        for key in list(self.pending):
            if now_us - self.pending[key].first_reception_us > self.max_age_us:
                del self.pending[key]
        if len(fragment) != ME_BYTES:
            return "malformed_fragment", None
        seq, index = _FRAGMENT_HEADER.unpack_from(fragment)
        if index >= fragment_count(MAX_OBJECT_BYTES):
            return "malformed_fragment", None
        key = (icao, seq)
        if key not in self.pending:
            if len(self.pending) >= self.max_pending_groups:
                return "receiver_capacity", None
            self.pending[key] = _Assembly(now_us)
        state = self.pending[key]
        payload = fragment[FRAGMENT_HEADER_BYTES:]
        previous = state.parts.get(index)
        if previous is not None:
            if previous == payload:
                return "duplicate_fragment", None
            del self.pending[key]
            return "conflicting_fragment", None
        state.parts[index] = payload
        state.largest_part = max(state.largest_part, index)
        if index == 0:
            state.object_bytes = struct.unpack_from(">H", payload)[0]
            if not state.object_bytes:
                del self.pending[key]
                return "malformed_object", None
        if state.object_bytes is None:
            return "pending_fragments", None
        count = fragment_count(state.object_bytes)
        # Checking every previously received index for each new fragment makes
        # long signatures quadratic. The largest index is an exact sufficient
        # statistic, including fragments that arrived before index zero.
        if state.largest_part >= count:
            del self.pending[key]
            return "malformed_fragment", None
        if len(state.parts) != count:
            return "pending_fragments", None
        stream = b"".join(state.parts[part] for part in range(count))
        del self.pending[key]
        end = 2 + state.object_bytes
        if any(stream[end:]):
            return "malformed_padding", None
        try:
            envelope = decode_envelope(stream[2:end])
        except ValueError:
            return "malformed_object", None
        if envelope.descriptor.seq != seq or envelope.descriptor.icao != icao:
            return "association_mismatch", None
        return "reassembled", envelope


@dataclass(frozen=True)
class Reconstruction:
    status: str
    signing_input: bytes | None = None
    messages: tuple[bytes, ...] = ()
    descriptor: GroupDescriptor | None = None


@dataclass(frozen=True)
class _Binding:
    fingerprint: bytes
    session: bytes
    verifier: Callable[[bytes, bytes], bool] | None


class ReplayReceiver:
    """Receive raw observations without sender groups, trace IDs, or private keys.

    ``reconstruct`` only establishes availability of the declared original bytes.
    ``accept_modeled`` is explicitly a size/timing-model result; it never claims
    a cryptographic verification. ``receive_fragment`` requires a real verifier.
    Successful acceptance consumes the matching reception occurrences, so one
    occurrence cannot authenticate multiple groups. Completed envelopes that
    await original messages can be retried with ``retry_pending``. The maximum
    age applies to the oldest message in a batch.
    """

    def __init__(self, max_age_s: float, clock_tolerance_s: float = 0.0):
        self.max_age_us = _time_us(max_age_s)
        self.clock_tolerance_us = _time_us(clock_tolerance_s)
        if self.max_age_us <= 0:
            raise ValueError("Receiver maximum authentication age must be positive.")
        self.bindings: dict[tuple[str, str], _Binding] = {}
        self.observations: dict[str, list[tuple[int, bytes, bytes]]] = defaultdict(list)
        self.accepted: set[tuple[str, bytes, int]] = set()
        self.reassembler = FragmentReassembler(max_age_s)
        self.pending_envelopes: dict[tuple[str, bytes, int], Envelope] = {}

    def register(
        self, icao: str, algorithm: str, public_key: bytes, session: bytes,
        verifier: Callable[[bytes, bytes], bool] | None = None,
    ) -> None:
        icao = _icao(icao)
        if algorithm not in ALGORITHM_CODES or len(session) != SESSION_BYTES:
            raise ValueError("Unknown algorithm or invalid eight-byte session.")
        self.bindings[icao, algorithm] = _Binding(key_fingerprint(public_key), session, verifier)

    def observe_message(self, raw: bytes, reception_s: float) -> None:
        """Observe one reception. Duplicate receptions count as ambiguity, not truth."""
        tag, reception_us = message_tag(raw), _time_us(reception_s)
        icao = raw[1:4].hex().upper()
        earliest = reception_us - self.max_age_us - self.clock_tolerance_us
        self.observations[icao] = [
            item for item in self.observations[icao] if item[0] >= earliest
        ]
        self.observations[icao].append((reception_us, raw, tag))

    def reconstruct(self, descriptor: GroupDescriptor, now_s: float) -> Reconstruction:
        """Rebuild signed bytes using only received observations and wire metadata."""
        context = context_bytes(descriptor)
        now_us = _time_us(now_s)
        binding = self.bindings.get((descriptor.icao, descriptor.algorithm))
        if binding is None or binding.fingerprint != descriptor.key_fingerprint:
            return Reconstruction("unknown_key", descriptor=descriptor)
        if binding.session != descriptor.session:
            return Reconstruction("wrong_session", descriptor=descriptor)
        if (descriptor.icao, descriptor.session, descriptor.seq) in self.accepted:
            return Reconstruction("replay", descriptor=descriptor)
        if now_us + self.clock_tolerance_us < descriptor.last_us:
            return Reconstruction("not_yet_current", descriptor=descriptor)
        if now_us - descriptor.first_us > self.max_age_us + self.clock_tolerance_us:
            return Reconstruction("expired", descriptor=descriptor)
        required = Counter(descriptor.message_tags)
        candidates: dict[bytes, list[bytes]] = defaultdict(list)
        first = descriptor.first_us - self.clock_tolerance_us
        last = descriptor.last_us + self.clock_tolerance_us
        for reception_us, raw, tag in self.observations.get(descriptor.icao, ()):
            if first <= reception_us <= min(last, now_us) and tag in required:
                candidates[tag].append(raw)
        for tag, count in required.items():
            available = candidates[tag]
            if len(set(available)) > 1 or len(available) > count:
                return Reconstruction("ambiguous_message", descriptor=descriptor)
            if len(available) < count:
                return Reconstruction("missing_message", descriptor=descriptor)
        messages = tuple(candidates[tag][0] for tag in descriptor.message_tags)
        return Reconstruction("ready", context + b"".join(messages), messages, descriptor)

    def accept_modeled(self, descriptor: GroupDescriptor, now_s: float) -> Reconstruction:
        """Mark a modeled authentication decision without computing any signature."""
        result = self.reconstruct(descriptor, now_s)
        if result.status != "ready":
            return result
        self._consume_observations(descriptor, now_s)
        self.accepted.add((descriptor.icao, descriptor.session, descriptor.seq))
        return Reconstruction("modeled_authenticated", result.signing_input, result.messages, descriptor)

    def _consume_observations(self, descriptor: GroupDescriptor, now_s: float) -> None:
        """Consume only after a successful reconstruction and acceptance decision."""
        first = descriptor.first_us - self.clock_tolerance_us
        last = min(descriptor.last_us + self.clock_tolerance_us, _time_us(now_s))
        tags = set(descriptor.message_tags)
        self.observations[descriptor.icao] = [
            item for item in self.observations.get(descriptor.icao, ())
            if not (first <= item[0] <= last and item[2] in tags)
        ]

    def receive_fragment(self, icao: str, fragment: bytes, now_s: float) -> Reconstruction:
        icao = _icao(icao)
        if not any(address == icao for address, _ in self.bindings):
            return Reconstruction("unknown_key")
        if len(fragment) == ME_BYTES:
            seq = _FRAGMENT_HEADER.unpack_from(fragment)[0]
            sessions = {binding.session for (address, _), binding in self.bindings.items() if address == icao}
            if any((icao, session, seq) in self.accepted for session in sessions):
                return Reconstruction("replay")
        status, envelope = self.reassembler.add(icao, fragment, now_s)
        if envelope is None:
            return Reconstruction(status)
        descriptor = envelope.descriptor
        key = (icao, descriptor.session, descriptor.seq)
        previous = self.pending_envelopes.pop(key, None)
        if previous is not None and previous != envelope:
            return Reconstruction("conflicting_object", descriptor=descriptor)
        result = self._verify_envelope(envelope, now_s)
        if result.status in {"missing_message", "not_yet_current"}:
            if len(self.pending_envelopes) >= self.reassembler.max_pending_groups:
                return Reconstruction("receiver_capacity", descriptor=descriptor)
            self.pending_envelopes[key] = envelope
        return result

    def retry_pending(self, now_s: float) -> list[Reconstruction]:
        """Retry complete objects after original receptions or time advances.

        A result is returned for every retained object. Missing originals remain
        pending until expiry; all terminal results remove the pending object.
        No reception occurrence is consumed by a failed authentication.
        """
        results = []
        for key, envelope in list(self.pending_envelopes.items()):
            result = self._verify_envelope(envelope, now_s)
            results.append(result)
            if result.status not in {"missing_message", "not_yet_current"}:
                del self.pending_envelopes[key]
        return results

    def _verify_envelope(self, envelope: Envelope, now_s: float) -> Reconstruction:
        result = self.reconstruct(envelope.descriptor, now_s)
        if result.status != "ready":
            return result
        binding = self.bindings[envelope.descriptor.icao, envelope.descriptor.algorithm]
        if binding.verifier is None:
            return Reconstruction("verification_unavailable", descriptor=envelope.descriptor)
        try:
            valid = binding.verifier(result.signing_input, envelope.signature)
        except Exception:
            valid = False
        if not valid:
            return Reconstruction("invalid_signature", descriptor=envelope.descriptor)
        self._consume_observations(envelope.descriptor, now_s)
        self.accepted.add((envelope.descriptor.icao, envelope.descriptor.session, envelope.descriptor.seq))
        return Reconstruction("authenticated", result.signing_input, result.messages, envelope.descriptor)
