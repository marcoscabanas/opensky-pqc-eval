import copy
import unittest
from unittest.mock import patch

import numpy as np

from src.experiment import delayed_replay
from src.experiment.replay_transport import ReplayReceiver, fragment_count, object_size_bytes
from tests.test_replay_simulator import ALGORITHM, profile_fixture, trace_fixture


def replay(records=None, interval=1, profile=None, seed=1, channel_trace=None, **options):
    profile = profile or profile_fixture()
    scenario = {
        "followup_s": 2, "coverage_thresholds_s": [1, 5, 10, 30, 60],
        "auth_frames_per_second": 8000, "channel_mode": "independent",
        "loss": {"kind": "iid", "probability": 0}, "record_events": True,
        **options,
    }
    return delayed_replay.simulate(trace_fixture() if records is None else records, ALGORITHM,
                                   interval, [64], profile, profile, scenario, seed,
                                   channel_trace=channel_trace)


class DelayedReplayTest(unittest.TestCase):
    def test_observed_followup_traffic_can_prevent_later_authentication(self):
        records = trace_fixture(count=2, spacing=1, aircraft=("ABCDEF",))
        profile = profile_fixture(sign_ms=2000)
        channel = {"extra_starts": [2.0], "extra_durations_s": [0.000072],
                   "coverage_end_s": 7, "summary": {"non_target_frames": 1}}
        control = replay(records, profile=profile, followup_s=5,
                         channel_mode="destructive_overlap")["summary"]
        augmented = replay(records, profile=profile, followup_s=5,
                           channel_mode="destructive_overlap", channel_trace=channel)["summary"]
        self.assertEqual(control["authenticated_messages"], 2)
        self.assertEqual(augmented["authenticated_messages"], 1)
        self.assertEqual(augmented["baseline_original_received_messages"], 2)
        self.assertEqual(augmented["additional_original_loss_messages"], 0)
        self.assertEqual(augmented["non_target_offered_airtime_load"], 0)
        self.assertEqual(augmented["channel_summary"]["observed_frames"], 1)

    def test_observed_capture_cannot_have_missing_followup_or_duplicate_synthetic_load(self):
        channel = {"extra_starts": [], "extra_durations_s": [], "coverage_end_s": 0.5, "summary": {}}
        with self.assertRaisesRegex(ValueError, "follow-up"):
            replay(channel_trace=channel)
        channel["coverage_end_s"] = 100
        with self.assertRaisesRegex(ValueError, "synthetic background"):
            replay(channel_trace=channel, background_frames_per_second=10)

    def test_event_guard_counts_observed_interferers(self):
        channel = {"extra_starts": [0.01] * 20, "extra_durations_s": [0.000072] * 20,
                   "coverage_end_s": 100, "summary": {}}
        with self.assertRaisesRegex(RuntimeError, "max_events"):
            replay(channel_trace=channel, max_events=20)
        # Also enforce the guard as reconstruction and verification accrue.
        channel["extra_starts"], channel["extra_durations_s"] = [0.01], [0.000072]
        limit = replay()["summary"]["processed_events"]
        with self.assertRaisesRegex(RuntimeError, "max_events"):
            replay(channel_trace=channel, max_events=limit)

    def test_authentication_after_five_seconds_succeeds_without_delaying_surveillance(self):
        records = trace_fixture(count=2, spacing=1, aircraft=("ABCDEF",))
        result = replay(records, profile=profile_fixture(sign_ms=6000), followup_s=15,
                        coverage_thresholds_s=[5, 15])
        summary = result["summary"]
        self.assertEqual(result["outcomes"], {"modeled_authenticated": 2})
        self.assertEqual(summary["authenticated_messages"], 2)
        self.assertGreater(summary["source_to_auth_ms_p50"], 5000)
        self.assertEqual(summary["ordinary_transmission_delay_ms_max"], 0)
        self.assertAlmostEqual(summary["augmented_original_delivery_ms_mean"], 0.12)
        self.assertEqual(summary["additional_original_loss_messages"], 0)
        coverage = {row["threshold_s"]: row for row in summary["threshold_coverage"]}
        self.assertEqual(coverage[5]["source_authentication_fraction"], 0)
        self.assertEqual(coverage[15]["source_authentication_fraction"], 1)

    def test_horizon_censors_queued_work_without_turning_it_into_failure(self):
        records = trace_fixture(count=2, spacing=1, aircraft=("ABCDEF",))
        result = replay(records, profile=profile_fixture(sign_ms=10000), followup_s=1)
        summary = result["summary"]
        self.assertEqual(summary["authenticated_messages"], 0)
        self.assertEqual(summary["unresolved_messages"], 2)
        self.assertEqual(summary["definitive_failure_messages"], 0)
        self.assertEqual(result["outcomes"], {"pending_sender_queue": 1, "pending_signing": 1})
        self.assertFalse(any("expired" in name for name in result["outcomes"]))
        coverage = {row["threshold_s"]: row for row in summary["threshold_coverage"]}
        self.assertEqual(coverage[1]["source_authentication_fraction"], 0)
        self.assertIsNone(coverage[5]["source_authentication_fraction"])
        self.assertEqual(coverage[5]["source_ineligible_due_to_followup_messages"], 2)

    def test_source_and_reception_anchored_authentication_delays_are_distinct(self):
        result = replay(profile=profile_fixture(sign_ms=30), receive_jitter_ms=10)
        summary = result["summary"]
        self.assertEqual(summary["authenticated_messages"], summary["source_messages"])
        self.assertAlmostEqual(summary["source_to_auth_ms_mean"] - summary["receipt_to_auth_ms_mean"],
                               summary["augmented_original_delivery_ms_mean"])
        self.assertGreater(summary["augmented_original_delivery_ms_mean"], 0.12)
        self.assertLessEqual(summary["augmented_original_delivery_ms_max"], 10.12 + 1e-9)
        self.assertEqual(summary["baseline_original_delivery_ms_mean"], summary["augmented_original_delivery_ms_mean"])

    def test_last_receipt_has_full_followup_despite_float_addition_order(self):
        end = 46.48973202705383
        records = trace_fixture(count=2, spacing=end, aircraft=("ABCDEF",))
        nominal = end + 60 + delayed_replay.FRAME_S
        required = end + delayed_replay.FRAME_S + 60
        self.assertGreater(required, nominal)  # The previous horizon missed one ULP.
        horizons = []
        for signing_ms in (0.1, 100000):
            with self.subTest(signing_ms=signing_ms):
                summary = replay(records, profile=profile_fixture(sign_ms=signing_ms),
                                 followup_s=60, coverage_thresholds_s=[60])["summary"]
                horizons.append(summary["observation_horizon_s"])
                coverage = summary["threshold_coverage"][0]
                self.assertEqual(coverage["source_eligible_messages"], 2)
                self.assertEqual(coverage["receipt_eligible_messages"], 2)
                self.assertEqual(coverage["receipt_ineligible_due_to_followup_messages"], 0)
        self.assertEqual(horizons, [required, required])

    def test_independent_channel_has_identical_paired_original_noise_and_schedule(self):
        records = trace_fixture(count=20, spacing=0.02, offset=0.0005)
        original = copy.deepcopy(records)
        results = [replay(records, fragment_copies=copies, receive_jitter_ms=0.5,
                          loss={"kind": "iid", "probability": 0.15}, seed=29)
                   for copies in (1, 3)]
        for result in results:
            summary = result["summary"]
            self.assertEqual(summary["baseline_original_received_messages"], summary["augmented_original_received_messages"])
            self.assertEqual(summary["additional_original_loss_messages"], 0)
            self.assertEqual(summary["ordinary_transmission_delay_ms_max"], 0)
        self.assertEqual(results[0]["summary"]["baseline_original_received_messages"],
                         results[1]["summary"]["baseline_original_received_messages"])
        self.assertEqual(results[0]["summary"]["baseline_original_delivery_ms_mean"],
                         results[1]["summary"]["baseline_original_delivery_ms_mean"])
        self.assertEqual(records, original)

    def test_cross_aircraft_authentication_overlap_can_destroy_an_ordinary_frame(self):
        # A emits at 0 and first auth frame starts at 120 us; B emits at 180 us.
        records = trace_fixture(count=1, offset=0.00018)
        control = replay(records, auth_frames_per_second=1000)
        collision = replay(records, auth_frames_per_second=1000, channel_mode="destructive_overlap")
        self.assertEqual(control["summary"]["augmented_original_received_messages"], 2)
        self.assertEqual(collision["summary"]["baseline_original_received_messages"], 2)
        self.assertEqual(collision["summary"]["augmented_original_received_messages"], 1)
        self.assertEqual(collision["summary"]["additional_original_loss_messages"], 1)
        self.assertEqual(collision["summary"]["ordinary_transmission_delay_ms_max"], 0)

    def test_authentication_radio_preserves_own_original_frame_slots(self):
        records = trace_fixture(count=12, spacing=0.0005, aircraft=("ABCDEF",))
        emitted = {}
        channel = delayed_replay.evaluate_channel

        def capture(originals, aircraft, auth, **options):
            emitted["original"] = np.array(originals, copy=True)
            emitted["auth"] = np.array(auth, copy=True)
            return channel(originals, aircraft, auth, **options)

        with patch.object(delayed_replay, "evaluate_channel", side_effect=capture):
            result = replay(records, channel_mode="destructive_overlap")
        self.assertGreater(len(emitted["auth"]), 0)
        self.assertTrue(np.array_equal(emitted["original"], [row["relative_time_s"] for row in records]))
        for original in emitted["original"]:
            overlaps = ((emitted["auth"] < original + delayed_replay.FRAME_S - 1e-12)
                        & (emitted["auth"] + delayed_replay.FRAME_S > original + 1e-12))
            self.assertFalse(np.any(overlaps))
        self.assertEqual(result["summary"]["additional_original_loss_messages"], 0)
        self.assertEqual(result["summary"]["augmented_original_received_messages"], len(records))

    def test_fixed_groups_leave_tails_while_timeout_groups_cover_them(self):
        records = trace_fixture(count=5)
        fixed = replay(records, interval=2)
        bounded = replay(records, interval=2, max_batch_wait_s=0.1)
        self.assertEqual(fixed["summary"]["source_groups"], 4)
        self.assertEqual(fixed["summary"]["unsigned_tail_messages"], 2)
        self.assertEqual(fixed["summary"]["authenticated_messages"], 8)
        self.assertEqual(bounded["summary"]["source_groups"], 10)
        self.assertEqual(bounded["summary"]["unsigned_tail_messages"], 0)
        self.assertEqual(bounded["summary"]["authenticated_messages"], 10)
        self.assertTrue(all(row["message_count"] == 1 for row in bounded["events"]))

    def test_explicit_finite_queue_limits_report_overflow(self):
        records = trace_fixture(count=6, spacing=0.01, aircraft=("ABCDEF",))
        cases = (
            (profile_fixture(sign_ms=100), {"sender_queue_limit": 1}, "sender_queue_overflow", "sender_queue_peak_per_aircraft"),
            (profile_fixture(), {"transmission_queue_limit": 1, "auth_frames_per_second": 10},
             "transmission_queue_overflow", "transmission_queue_peak_per_aircraft"),
            (profile_fixture(verify_ms=100), {"receiver_queue_limit": 1}, "receiver_queue_overflow", "receiver_queue_peak"),
        )
        for profile, parameters, outcome, metric in cases:
            with self.subTest(outcome=outcome):
                result = replay(records, profile=profile, followup_s=10, **parameters)
                self.assertGreater(result["outcomes"].get(outcome, 0), 0)
                self.assertLessEqual(result["summary"][metric], 1)
                self.assertGreater(result["summary"]["definitive_failure_messages"], 0)

    def test_repeated_fragments_have_no_feedback_or_duplicate_verification(self):
        expected = len(trace_fixture()) * fragment_count(object_size_bytes(1, 64)) * 3
        for verification_ms in (0.1, 50):
            with self.subTest(verification_ms=verification_ms):
                result = replay(profile=profile_fixture(verify_ms=verification_ms), fragment_copies=3,
                                auth_frames_per_second=1000, receiver_workers=2)
                self.assertEqual(result["summary"]["auth_frames_transmitted"], expected)
                self.assertEqual(result["summary"]["modeled_authenticated_groups"], 6)
                self.assertAlmostEqual(result["summary"]["receiver_busy_seconds_all_workers"], 6 * verification_ms / 1000)

    def test_missing_or_altered_observation_cannot_reconstruct_signed_input(self):
        records = trace_fixture(count=2, aircraft=("ABCDEF",))
        channel = delayed_replay.evaluate_channel

        def lose_first(*args, **kwargs):
            result = channel(*args, **kwargs)
            result["original_success_baseline"][0] = False
            result["original_success_with_auth"][0] = False
            return result

        with patch.object(delayed_replay, "evaluate_channel", side_effect=lose_first):
            missing = replay(records, interval=2)
        self.assertEqual(missing["outcomes"], {"missing_message": 1})
        self.assertEqual(missing["summary"]["authenticated_messages"], 0)
        self.assertEqual(missing["summary"]["message_outcomes"], {"missing_message": 1, "original_lost": 1})
        observe = ReplayReceiver.observe_message

        def corrupt_first(receiver, raw, now):
            if raw == bytes.fromhex(records[0]["raw_msg"]):
                raw = raw[:-1] + bytes([raw[-1] ^ 1])
            observe(receiver, raw, now)

        with patch.object(ReplayReceiver, "observe_message", corrupt_first):
            altered = replay(records, interval=2)
        self.assertEqual(altered["outcomes"], {"missing_message": 1})
        self.assertEqual(altered["summary"]["authenticated_messages"], 0)
        self.assertEqual(altered["summary"]["augmented_original_received_messages"], 2)

    def test_known_lost_original_is_definitive_even_if_signing_is_unfinished(self):
        records = trace_fixture(count=2, aircraft=("ABCDEF",))
        channel = delayed_replay.evaluate_channel

        def lose_first(*args, **kwargs):
            result = channel(*args, **kwargs)
            result["original_success_baseline"][0] = False
            result["original_success_with_auth"][0] = False
            return result

        with patch.object(delayed_replay, "evaluate_channel", side_effect=lose_first):
            result = replay(records, interval=2, profile=profile_fixture(sign_ms=100000), followup_s=1)
        self.assertEqual(result["summary"]["unresolved_messages"], 0)
        self.assertEqual(result["summary"]["definitive_failure_messages"], 2)
        self.assertEqual(result["summary"]["message_outcomes"], {"missing_message": 1, "original_lost": 1})
        self.assertGreater(result["summary"]["backlog_samples"][-1]["sender_unfinished_groups"], 0)

    def test_fully_lost_fragment_copies_are_definitive_during_partial_transmission(self):
        records = trace_fixture(count=2, spacing=0.005, aircraft=("ABCDEF",))
        channel = delayed_replay.evaluate_channel

        def lose_first_auth(*args, **kwargs):
            result = channel(*args, **kwargs)
            result["auth_success"][0] = False
            return result

        for copies in (1, 3):
            with self.subTest(copies=copies), patch.object(delayed_replay, "evaluate_channel", side_effect=lose_first_auth):
                result = replay(records, interval=2, followup_s=0.02, auth_frames_per_second=100, fragment_copies=copies)
            self.assertGreater(result["summary"]["auth_frames_transmitted"], 1)
            self.assertLess(result["events"][0]["fragments_sent"], result["events"][0]["required_fragments"])
            if copies == 1:
                self.assertEqual(result["summary"]["definitive_failure_messages"], 2)
                self.assertEqual(result["summary"]["unresolved_messages"], 0)
            else:
                self.assertEqual(result["summary"]["definitive_failure_messages"], 0)
                self.assertEqual(result["summary"]["unresolved_messages"], 2)
            self.assertGreater(result["summary"]["backlog_samples"][-1]["transmission_unfinished_groups"], 0)

    def test_capture_backlogs_expose_overload_even_when_later_authentication_completes(self):
        records = trace_fixture(count=10, spacing=0.1, aircraft=("ABCDEF",))
        result = replay(records, profile=profile_fixture(sign_ms=1000), followup_s=0.5)
        summary = result["summary"]
        at_end = min(summary["backlog_samples"], key=lambda row: abs(row["time_s"] - summary["capture_end_s"]))
        self.assertEqual(at_end["sender_unfinished_groups"], 10)
        self.assertGreater(summary["sender_offered_utilization_max_per_aircraft"], 1)
        self.assertEqual(summary["authenticated_messages"], 1)
        self.assertEqual(summary["unresolved_messages"], 9)
        self.assertEqual(summary["definitive_failure_messages"], 0)

    def test_seed_reproduces_iid_and_burst_results_including_collision_comparison(self):
        for loss in ({"kind": "iid", "probability": 0.1},
                     {"kind": "gilbert_elliott", "good_loss": 0.01, "bad_loss": 0.8,
                      "mean_good_s": 0.2, "mean_bad_s": 0.05}):
            with self.subTest(kind=loss["kind"]):
                options = dict(loss=loss, seed=77, channel_mode="destructive_overlap", receive_jitter_ms=0.2)
                self.assertEqual(replay(**options), replay(**options))

    def test_invalid_scenario_and_event_limit_fail_instead_of_publishing_partial_results(self):
        for invalid in ({"max_auth_age_s": 5}, {"followup_s": -1}, {"sender_queue_limit": 0},
                        {"receiver_workers": True}, {"coverage_thresholds_s": [5, 1]},
                        {"loss": {"kind": "iid", "probability": 2}}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                replay(**invalid)
        with self.assertRaisesRegex(RuntimeError, "max_events"):
            replay(max_events=1)
        # No received frames and no completed signatures must not bypass the guard.
        with self.assertRaisesRegex(RuntimeError, "max_events"):
            replay(profile=profile_fixture(sign_ms=100000), followup_s=0,
                   loss={"kind": "iid", "probability": 1}, max_events=1)


if __name__ == "__main__":
    unittest.main()
