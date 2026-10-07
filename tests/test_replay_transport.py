import dataclasses
import unittest
from unittest.mock import patch

from src.crypto.ecdsa_p256 import Signer
from src.experiment import replay_transport as transport


ICAO = "40621D"
SESSION = b"sample01"
RAW_A = bytes.fromhex("8D40621D58C382D690C8AC2863A7")
RAW_B = bytes.fromhex("8D40621D58C382D690C8AC2863A8")


class ReplayTransportTests(unittest.TestCase):
    def setUp(self):
        self.signer = Signer()
        self.messages = [(10.0, RAW_A), (10.2, RAW_B)]
        self.envelope = transport.make_envelope(
            ICAO, 4, SESSION, self.messages, "ECDSA-P256", self.signer,
        )

    def receiver(self, max_age_s=5.0):
        receiver = transport.ReplayReceiver(max_age_s)
        receiver.register(
            ICAO, "ECDSA-P256", self.signer.public_key_bytes(), SESSION,
            self.signer.verify,
        )
        return receiver

    def receive(self, receiver, envelope=None, now_s=10.3):
        for fragment in transport.fragment_envelope(envelope or self.envelope):
            result = receiver.receive_fragment(ICAO, fragment, now_s)
        return result

    def observe(self, receiver):
        for time_s, raw in self.messages:
            receiver.observe_message(raw, time_s)

    def test_wire_size_roundtrip_includes_context_tags_signature_and_headers(self):
        encoded = transport.encode_envelope(self.envelope)
        self.assertEqual(len(encoded), 54 + 8 * 2 + 64)
        self.assertEqual(len(encoded), transport.object_size_bytes(2, 64))
        self.assertEqual(transport.decode_envelope(encoded), self.envelope)
        fragments = transport.fragment_envelope(self.envelope)
        self.assertEqual(len(fragments), transport.fragment_count(len(encoded)))
        self.assertTrue(all(len(fragment) == 7 for fragment in fragments))
        # 136 stream bytes require 46 frames, of which 184 bytes are headers.
        self.assertEqual((len(fragments), len(fragments) * 7), (46, 322))

    def test_actual_ecdsa_reconstructs_only_receiver_observations_and_reordered_fragments(self):
        receiver = self.receiver()
        # Observation order does not supply the signed message ordering.
        for time_s, raw in reversed(self.messages):
            receiver.observe_message(raw, time_s)
        fragments = transport.fragment_envelope(self.envelope)
        reversed_fragments = list(reversed(fragments))
        first = reversed_fragments[0]
        self.assertEqual(receiver.receive_fragment(ICAO, first, 10.3).status, "pending_fragments")
        self.assertEqual(receiver.receive_fragment(ICAO, first, 10.3).status, "duplicate_fragment")
        for fragment in reversed_fragments[1:]:
            result = receiver.receive_fragment(ICAO, fragment, 10.3)
        self.assertEqual(result.status, "authenticated")
        self.assertEqual(result.messages, (RAW_A, RAW_B))
        self.assertEqual(
            result.signing_input,
            transport.context_bytes(self.envelope.descriptor) + RAW_A + RAW_B,
        )
        self.assertFalse(self.signer.verify(RAW_A + RAW_B, self.envelope.signature))
        self.assertEqual(receiver.receive_fragment(ICAO, first, 10.4).status, "replay")

    def test_missing_original_fails_despite_complete_signature_recovery(self):
        receiver = self.receiver()
        receiver.observe_message(RAW_A, 10.0)
        self.assertEqual(self.receive(receiver).status, "missing_message")

    def test_baseline_tamper_cannot_satisfy_declared_message_tag(self):
        receiver = self.receiver()
        receiver.observe_message(RAW_A, 10.0)
        receiver.observe_message(RAW_A, 10.2)
        self.assertIn(self.receive(receiver).status, {"ambiguous_message", "missing_message"})

    def test_signature_tamper_is_rejected(self):
        receiver = self.receiver()
        self.observe(receiver)
        altered = dataclasses.replace(self.envelope, signature=b"\0" * 64)
        self.assertEqual(self.receive(receiver, altered).status, "invalid_signature")
        self.assertEqual(self.receive(receiver).status, "authenticated")

    def test_signed_group_sequence_tamper_is_rejected(self):
        receiver = self.receiver()
        self.observe(receiver)
        altered = dataclasses.replace(
            self.envelope,
            descriptor=dataclasses.replace(self.envelope.descriptor, seq=5),
        )
        self.assertEqual(self.receive(receiver, altered).status, "invalid_signature")

    def test_expiry_is_measured_from_first_source_message(self):
        receiver = self.receiver(max_age_s=0.25)
        self.observe(receiver)
        self.assertEqual(self.receive(receiver, now_s=10.3).status, "expired")

    def test_unknown_key_and_wrong_session_are_rejected(self):
        receiver = self.receiver()
        self.observe(receiver)
        descriptor = self.envelope.descriptor
        changed_key = dataclasses.replace(descriptor, key_fingerprint=b"x" * 16)
        changed_session = dataclasses.replace(descriptor, session=b"previous")
        self.assertEqual(receiver.reconstruct(changed_key, 10.3).status, "unknown_key")
        self.assertEqual(receiver.reconstruct(changed_session, 10.3).status, "wrong_session")

    def test_multiplicity_is_required_and_extra_receptions_fail_closed(self):
        envelope = transport.make_envelope(
            ICAO, 5, SESSION, [(10.0, RAW_A), (10.2, RAW_A)], "ECDSA-P256", self.signer,
        )
        receiver = self.receiver()
        receiver.observe_message(RAW_A, 10.0)
        self.assertEqual(receiver.reconstruct(envelope.descriptor, 10.3).status, "missing_message")
        receiver.observe_message(RAW_A, 10.2)
        self.assertEqual(receiver.reconstruct(envelope.descriptor, 10.3).status, "ready")
        receiver.observe_message(RAW_A, 10.1)
        self.assertEqual(receiver.reconstruct(envelope.descriptor, 10.3).status, "ambiguous_message")

    def test_same_payload_outside_signed_window_does_not_replace_lost_original(self):
        receiver = self.receiver()
        receiver.observe_message(RAW_A, 9.9)
        receiver.observe_message(RAW_B, 10.2)
        self.assertEqual(self.receive(receiver).status, "missing_message")

    def test_tag_collision_is_rejected_at_sender_and_receiver(self):
        with patch.object(transport, "message_tag", return_value=b"c" * 8):
            with self.assertRaisesRegex(ValueError, "collision"):
                transport.describe_group(
                    ICAO, 1, SESSION, self.messages, "ECDSA-P256", self.signer.public_key_bytes(),
                )
            descriptor = transport.describe_group(
                ICAO, 1, SESSION, [(10.0, RAW_A), (10.2, RAW_A)],
                "ECDSA-P256", self.signer.public_key_bytes(),
            )
            receiver = self.receiver()
            self.observe(receiver)
            self.assertEqual(receiver.reconstruct(descriptor, 10.3).status, "ambiguous_message")

    def test_conflicting_fragment_and_inconsistent_external_association_fail(self):
        fragments = transport.fragment_envelope(self.envelope)
        reassembler = transport.FragmentReassembler(5.0)
        self.assertEqual(reassembler.add(ICAO, fragments[0], 10.3)[0], "pending_fragments")
        altered = fragments[0][:-1] + bytes([fragments[0][-1] ^ 1])
        self.assertEqual(reassembler.add(ICAO, altered, 10.3)[0], "conflicting_fragment")
        for fragment in fragments:
            status, _ = reassembler.add("FFFFFF", fragment, 10.3)
        self.assertEqual(status, "association_mismatch")

    def test_modeled_acceptance_never_claims_actual_verification(self):
        receiver = self.receiver()
        self.observe(receiver)
        with patch.object(self.signer, "verify", side_effect=AssertionError("must not verify")):
            result = receiver.accept_modeled(self.envelope.descriptor, 10.3)
        self.assertEqual(result.status, "modeled_authenticated")
        self.assertEqual(receiver.accept_modeled(self.envelope.descriptor, 10.4).status, "replay")

    def test_real_reception_requires_verifier(self):
        receiver = transport.ReplayReceiver(5.0)
        receiver.register(ICAO, "ECDSA-P256", self.signer.public_key_bytes(), SESSION)
        self.observe(receiver)
        self.assertEqual(self.receive(receiver).status, "verification_unavailable")

    def test_sequence_overflow_and_malformed_wire_lengths_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "sequence"):
            transport.describe_group(
                ICAO, 65536, SESSION, self.messages, "ECDSA-P256", self.signer.public_key_bytes(),
            )
        with self.assertRaises(ValueError):
            transport.decode_envelope(transport.encode_envelope(self.envelope) + b"x")
        with self.assertRaises(ValueError):
            transport.object_size_bytes(65535, 64)

    def test_one_received_occurrence_cannot_authenticate_multiple_modeled_groups(self):
        descriptor = transport.describe_group(
            ICAO, 1, SESSION, [(10.0, RAW_A)], "ECDSA-P256", self.signer.public_key_bytes(),
        )
        receiver = self.receiver()
        receiver.observe_message(RAW_A, 10.0)
        receiver.observe_message(RAW_B, 10.2)
        self.assertEqual(receiver.accept_modeled(descriptor, 10.3).status, "modeled_authenticated")
        # Changing sequence does not create another received occurrence, even
        # when multiple transmissions have indistinguishable coarse timestamps.
        next_group = dataclasses.replace(descriptor, seq=2)
        self.assertEqual(receiver.accept_modeled(next_group, 10.3).status, "missing_message")
        self.assertEqual([raw for _, raw, _ in receiver.observations[ICAO]], [RAW_B])
        self.assertEqual(receiver.accept_modeled(descriptor, 10.3).status, "replay")

    def test_verified_acceptance_also_consumes_observation_occurrences(self):
        receiver = self.receiver()
        self.observe(receiver)
        self.assertEqual(self.receive(receiver).status, "authenticated")
        second = transport.make_envelope(
            ICAO, 5, SESSION, self.messages, "ECDSA-P256", self.signer,
        )
        self.assertEqual(self.receive(receiver, second).status, "missing_message")

    def test_complete_envelope_can_retry_when_original_receptions_arrive_later(self):
        receiver = transport.ReplayReceiver(5.0, clock_tolerance_s=0.3)
        receiver.register(
            ICAO, "ECDSA-P256", self.signer.public_key_bytes(), SESSION, self.signer.verify,
        )
        self.assertEqual(self.receive(receiver, now_s=10.21).status, "missing_message")
        self.assertEqual(len(receiver.pending_envelopes), 1)
        receiver.observe_message(RAW_A, 10.22)
        receiver.observe_message(RAW_B, 10.23)
        results = receiver.retry_pending(10.24)
        self.assertEqual([result.status for result in results], ["authenticated"])
        self.assertFalse(receiver.pending_envelopes)
        self.assertFalse(receiver.observations[ICAO])
        self.assertEqual(receiver.retry_pending(10.25), [])

    def test_complete_pending_envelope_expires_without_consuming_other_observations(self):
        receiver = self.receiver()
        receiver.observe_message(RAW_A, 10.0)
        self.assertEqual(self.receive(receiver).status, "missing_message")
        self.assertEqual([result.status for result in receiver.retry_pending(15.1)], ["expired"])
        self.assertFalse(receiver.pending_envelopes)
        self.assertEqual(len(receiver.observations[ICAO]), 1)

    def test_actual_all_four_algorithms_verify_and_reject_tampered_wire_signature(self):
        from src.crypto.fn_dsa_512 import Signer as FalconSigner
        from src.crypto.ml_dsa_44 import Signer as MLDSASigner
        from src.crypto.slh_dsa_sha2_128s import Signer as SLHDSASigner

        algorithms = {
            "ECDSA-P256": Signer,
            "ML-DSA-44": MLDSASigner,
            "FN-DSA-512": FalconSigner,
            "SLH-DSA-SHA2-128s": SLHDSASigner,
        }
        for algorithm, signer_class in algorithms.items():
            with self.subTest(algorithm=algorithm):
                signer = signer_class()
                try:
                    envelope = transport.make_envelope(
                        ICAO, 12, SESSION, self.messages, algorithm, signer,
                    )
                    receiver = transport.ReplayReceiver(5.0)
                    receiver.register(ICAO, algorithm, signer.public_key_bytes(), SESSION, signer.verify)
                    self.observe(receiver)
                    signature = bytearray(envelope.signature)
                    signature[-1] ^= 1
                    altered = dataclasses.replace(envelope, signature=bytes(signature))
                    self.assertEqual(self.receive(receiver, altered).status, "invalid_signature")
                    self.assertEqual(self.receive(receiver, envelope).status, "authenticated")
                    self.assertFalse(receiver.observations[ICAO])
                    self.assertEqual(
                        len(transport.encode_envelope(envelope)),
                        transport.object_size_bytes(2, len(envelope.signature)),
                    )
                finally:
                    signer.close()


if __name__ == "__main__":
    unittest.main()
