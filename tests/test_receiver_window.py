"""Exact sorted-window receiver matching versus the unoptimized receiver."""

from dataclasses import replace
import unittest
from unittest.mock import patch

import numpy as np

from src.experiment import signed_replay
from src.experiment.replay_transport import ReplayReceiver, describe_group, message_tag
from tests.fixtures import profile_fixture, trace_fixture
from tests.test_signed_replay import replay, workload_fixture

ICAO = "ABCDEF"
SESSION = b"testsess"
PUBLIC_KEY = b"test receiver key"


def raw(index, icao=ICAO):
    return b"\x8d" + bytes.fromhex(icao) + int(index).to_bytes(10, "big")


def descriptor(messages, seq=1):
    return describe_group(ICAO, seq, SESSION, messages, "ECDSA-P256", PUBLIC_KEY)


def receivers(observations=(), *, max_age=1000, tolerance=0):
    pair = [ReplayReceiver(max_age, tolerance), signed_replay._ReplayReceiver(max_age, tolerance)]
    for receiver in pair:
        receiver.register(ICAO, "ECDSA-P256", PUBLIC_KEY, SESSION)
        for time, message in observations:
            receiver.observe_message(message, time)
    return pair


def original_reservation(receiver, group, now):
    first = group.first_us - receiver.clock_tolerance_us
    last = min(group.last_us + receiver.clock_tolerance_us, round(now * 1e6))
    tags = set(group.message_tags)
    observations = receiver.observations[group.icao]
    chosen = [position for position, (time, _, tag) in enumerate(observations)
              if first <= time <= last and tag in tags]
    selected = [observations[position] for position in chosen]
    chosen = set(chosen)
    receiver.observations[group.icao] = [item for position, item in enumerate(observations) if position not in chosen]
    return selected


class ReceiverWindowTests(unittest.TestCase):
    def assert_reconstruction_equal(self, pair, group, now):
        before = [dict(receiver.observations) for receiver in pair]
        expected, actual = [receiver.reconstruct(group, now) for receiver in pair]
        self.assertEqual(actual, expected)
        for receiver, prior in zip(pair, before):
            self.assertEqual(dict(receiver.observations), prior)
        return actual

    def test_random_sorted_windows_match_missing_ambiguous_and_ready_oracle(self):
        rng = np.random.default_rng(499)
        statuses = set()
        for trial in range(60):
            messages = [(10 + index * .1, raw(index)) for index in range(12)]
            chosen = list(rng.choice(len(messages), size=5, replace=False))
            group = descriptor([messages[index] for index in sorted(chosen)])
            observations = list(messages)
            if trial % 3 == 0:
                observations.remove(messages[chosen[0]])
            elif trial % 3 == 1:
                observations.append(messages[chosen[0]])
            observations += [(0, raw(300)), (9, raw(300)), (20, raw(300))]
            observations.sort(key=lambda item: item[0])
            pair = receivers(observations, tolerance=.000001)
            for now in (9.5, 11.5, 1012):
                statuses.add(self.assert_reconstruction_equal(pair, group, now).status)
        self.assertTrue({"ready", "missing_message", "ambiguous_message", "not_yet_current", "expired"} <= statuses)

    def test_inclusive_microsecond_boundaries_and_future_receptions(self):
        group = descriptor([(10, raw(1)), (11, raw(2))])
        observations = [(9.999998, raw(1)), (9.999999, raw(1)), (11.000001, raw(2)),
                        (11.000002, raw(2)), (12, raw(3))]
        pair = receivers(observations, tolerance=.000001)
        self.assertEqual(self.assert_reconstruction_equal(pair, group, 11).status, "missing_message")
        self.assertEqual(self.assert_reconstruction_equal(pair, group, 11.000001).status, "ready")
        self.assertEqual(self.assert_reconstruction_equal(pair, group, 12).status, "ready")

    def test_distinct_bytes_with_same_compact_tag_remain_ambiguous(self):
        group = descriptor([(10, raw(1))])
        pair = receivers([(0, raw(300)), (10, raw(1)), (20, raw(301))], tolerance=.1)
        for receiver in pair:
            receiver.observations[ICAO].insert(2, (10_000_001, raw(2), message_tag(raw(1))))
        self.assertEqual(self.assert_reconstruction_equal(pair, group, 11).status, "ambiguous_message")

    def test_duplicate_required_tags_and_unrelated_aircraft_match_oracle(self):
        group = descriptor([(10, raw(1)), (10.1, raw(1))])
        pair = receivers([(0, raw(300)), (10, raw(1)), (10.1, raw(1)),
                          (10.1, raw(1, "123456")), (20, raw(301))])
        self.assertEqual(self.assert_reconstruction_equal(pair, group, 11).status, "ready")

    def test_unsorted_input_falls_back_without_changing_retention_or_decisions(self):
        group = descriptor([(10, raw(1)), (10.1, raw(2))])
        pair = receivers([(20, raw(5)), (10.1, raw(2)), (0, raw(6)), (10, raw(1))])
        self.assertEqual(self.assert_reconstruction_equal(pair, group, 20).status, "ready")
        expected = original_reservation(pair[0], group, 20)
        actual = signed_replay._reserve_observations(pair[1], group, 20)
        self.assertEqual(actual, expected)
        self.assertEqual(pair[0].observations, pair[1].observations)

    def test_binding_replay_and_validation_checks_still_use_general_receiver(self):
        base = descriptor([(10, raw(1))])
        pair = receivers([(0, raw(300)), (10, raw(1)), (20, raw(301))])
        for group, status in ((replace(base, key_fingerprint=b"x" * 16), "unknown_key"),
                              (replace(base, session=b"bad-sess"), "wrong_session")):
            self.assertEqual(self.assert_reconstruction_equal(pair, group, 11).status, status)
        for receiver in pair:
            receiver.accepted.add((ICAO, SESSION, 1))
        self.assertEqual(self.assert_reconstruction_equal(pair, base, 11).status, "replay")
        for receiver in pair:
            original = receiver.observations[ICAO]
            with self.assertRaises(ValueError):
                receiver.reconstruct(replace(base, message_tags=(b"bad",)), 11)
            self.assertIs(receiver.observations[ICAO], original)

    def test_short_retention_uses_identical_expiry(self):
        group = descriptor([(10, raw(1))])
        pair = receivers([(0, raw(300)), (10, raw(1)), (20, raw(301))], max_age=5)
        self.assertEqual(pair[0].observations, pair[1].observations)
        self.assertEqual(self.assert_reconstruction_equal(pair, group, 20).status, "expired")

    def test_reservation_and_invalid_verification_restoration_are_exact(self):
        group = descriptor([(10, raw(1)), (10.1, raw(2))])
        pair = receivers([(0, raw(300)), (10, raw(1)), (10.05, raw(999)),
                          (10.1, raw(2)), (20, raw(301))])
        expected = original_reservation(pair[0], group, 11)
        actual = signed_replay._reserve_observations(pair[1], group, 11)
        self.assertEqual(actual, expected)
        self.assertEqual(pair[0].observations, pair[1].observations)
        for receiver, selected in zip(pair, (expected, actual)):
            receiver.observe_message(raw(302), 21)
            receiver.observations[ICAO].extend(selected)
            receiver.observations[ICAO].sort(key=lambda item: item[0])
        self.assertEqual(self.assert_reconstruction_equal(pair, group, 21).status, "ready")

    def test_full_replay_matches_general_receiver_across_models_queues_jitter_and_loss(self):
        records = trace_fixture(count=12, spacing=.05, aircraft=(ICAO, "123456"))
        for model in ("signed_detached", "signed_before_send"):
            for interval in (1, 5):
                for mode, loss in (("independent", 0), ("independent", .01), ("observed_capture", 0)):
                    options = dict(replay_model=model, interval=interval, channel_mode=mode,
                                   loss={"kind": "iid", "probability": loss}, seed=3,
                                   receive_jitter_ms=20, followup_s=5, auth_frames_per_second=700,
                                   profile=profile_fixture(sign_ms=10, verify_ms=200))
                    expected = None
                    with patch.object(signed_replay, "_ReplayReceiver", ReplayReceiver):
                        expected = replay(records, **options)
                    actual = replay(records, **options)
                    self.assertEqual(actual, expected)

    def test_full_invalid_signature_restoration_matches_general_receiver(self):
        records = trace_fixture(count=2, spacing=.2, aircraft=(ICAO,))
        records[1]["raw_msg"] = records[0]["raw_msg"]
        workload = workload_fixture(records)
        envelope = workload["groups"][0]["envelope"]
        workload["groups"][0]["envelope"] = replace(envelope, signature=b"X" + envelope.signature[1:])
        channel = signed_replay.evaluate_shifted_channel
        def lose_second(*args, **kwargs):
            result = channel(*args, **kwargs)
            result["original_success_with_auth"][1] = False
            return result
        options = dict(workload=workload, profile=profile_fixture(verify_ms=500))
        with patch.object(signed_replay, "evaluate_shifted_channel", side_effect=lose_second):
            with patch.object(signed_replay, "_ReplayReceiver", ReplayReceiver):
                expected = replay(records, **options)
            actual = replay(records, **options)
        self.assertEqual(actual, expected)
        self.assertEqual(actual["events"][0]["work_state"], "invalid_signature")
        self.assertEqual(actual["events"][1]["work_state"], "ambiguous_message")


if __name__ == "__main__":
    unittest.main()
