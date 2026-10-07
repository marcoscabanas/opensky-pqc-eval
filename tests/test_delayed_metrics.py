import json
import math
import unittest

from src.experiment.delayed_metrics import summarize


def records(times, aircraft=None):
    aircraft = aircraft or ["ABCDEF"] * len(times)
    return [{"trace_id": index + 1, "icao": icao, "relative_time_s": time}
            for index, (icao, time) in enumerate(zip(aircraft, times))]


class DelayedMetricsTest(unittest.TestCase):
    def test_success_after_five_seconds_is_authenticated_and_has_both_delays(self):
        result = summarize(records([0, 10]), [True, True], [True, True], [.2, 10.2],
                           [6, 18], ["modeled_authenticated"] * 2, horizon=20, thresholds_s=[5, 10])
        self.assertEqual(result["authenticated_messages"], 2)
        self.assertEqual(result["authenticated_source_fraction"], 1)
        self.assertEqual(result["unresolved_messages"], 0)
        self.assertAlmostEqual(result["source_to_auth_ms_mean"], 7000)
        self.assertAlmostEqual(result["receipt_to_auth_ms_mean"], 6800)
        self.assertAlmostEqual(result["augmented_original_delivery_ms_mean"], 200)
        short, long = result["threshold_coverage"]
        self.assertEqual(short["source_authenticated_within_threshold_messages"], 0)
        self.assertEqual(long["source_authenticated_within_threshold_messages"], 2)
        self.assertEqual(result["ordinary_transmission_delay_basis"], "assumed_zero")

    def test_horizon_edge_excludes_incomplete_followup_and_pending_is_not_failure(self):
        result = summarize(records([0, 8, 9]), [True] * 3, [True, True, False], [.1, 8.1, 9.1],
                           [4, math.nan, math.nan], ["modeled_authenticated", "pending_signing", "original_lost"],
                           horizon=10, thresholds_s=[1, 5])
        self.assertEqual(result["authenticated_messages"], 1)
        self.assertEqual(result["definitive_failure_messages"], 1)
        self.assertEqual(result["unresolved_messages"], 1)
        self.assertEqual(result["authenticated_source_fraction"], 1 / 3)
        one, five = result["threshold_coverage"]
        self.assertEqual(five["source_eligible_messages"], 1)
        self.assertEqual(five["source_ineligible_due_to_followup_messages"], 2)
        self.assertEqual(five["source_authentication_fraction"], 1)
        self.assertEqual(five["receipt_authentication_fraction"], 1)
        self.assertEqual(one["source_authentication_fraction"], 0)
        self.assertEqual(one["source_eligible_unresolved_at_horizon_messages"], 1)

    def test_source_and_receipt_thresholds_use_different_anchors(self):
        result = summarize(records([0, 9]), [True, True], [True, True], [4, 9.5], [8.5, math.nan],
                           ["modeled_authenticated", "pending_verifying"], horizon=10, thresholds_s=[5, 20])
        row, unavailable = result["threshold_coverage"]
        self.assertEqual(row["source_eligible_messages"], 1)
        self.assertEqual(row["receipt_eligible_messages"], 1)
        self.assertEqual(row["source_authentication_fraction"], 0)
        self.assertEqual(row["receipt_authentication_fraction"], 1)
        self.assertIsNone(unavailable["source_authentication_fraction"])
        self.assertIsNone(unavailable["receipt_authentication_fraction"])

    def test_paired_reception_losses_and_gains_do_not_cancel_each_others_counts(self):
        result = summarize(records([0, 1, 2]), [True, True, False], [True, False, True], [.1, None, 2.1],
                           [None] * 3, ["pending_signing", "original_lost", "pending_signing"],
                           baseline_reception_times=[.1, 1.1, None], horizon=3, thresholds_s=[1])
        self.assertEqual(result["additional_original_loss_messages"], 1)
        self.assertEqual(result["original_reception_gain_messages"], 1)
        self.assertEqual(result["net_additional_original_loss_messages"], 0)
        self.assertEqual(result["baseline_original_received_messages"], 2)
        self.assertEqual(result["augmented_original_received_messages"], 2)
        self.assertEqual(result["received_unresolved_messages"], 2)

    def test_sparse_aircraft_gaps_are_separate_and_initial_unknown_time_is_reported(self):
        result = summarize(records([0, 1, 10, 11], ["AAAAAA", "BBBBBB", "AAAAAA", "BBBBBB"]),
                           [True] * 4, [True] * 4, [0, 1, 10, 11], [None] * 4,
                           ["pending_signing"] * 4, horizon=12, thresholds_s=[1])
        self.assertEqual(result["baseline_received_interarrival_gap_s_count"], 2)
        self.assertEqual(result["baseline_received_interarrival_gap_s_mean"], 10)
        self.assertAlmostEqual(result["baseline_received_information_age_known_time_fraction"], 21 / 22)
        self.assertAlmostEqual(result["baseline_received_information_age_time_weighted_mean_s"], 100.5 / 21)
        self.assertEqual(result["baseline_received_information_age_max_s"], 10)
        aircraft = {row["icao"]: row for row in result["aircraft_freshness"]}
        self.assertEqual(aircraft["BBBBBB"]["baseline_received"]["unknown_seconds"], 1)
        self.assertEqual(aircraft["AAAAAA"]["baseline_received"]["age_at_capture_end_s"], 1)
        self.assertEqual(result["authenticated_information_age_unknown_aircraft_at_capture_end"], 2)
        self.assertIsNone(result["authenticated_information_age_time_weighted_mean_s"])

    def test_authentication_of_old_message_never_regresses_freshness(self):
        result = summarize(records([0, 5, 10]), [True] * 3, [True] * 3, [0, 5, 10], [9, 6, None],
                           ["modeled_authenticated", "modeled_authenticated", "pending_signing"],
                           horizon=12, thresholds_s=[5, 10])
        info = result["aircraft_freshness"][0]["authenticated"]
        self.assertEqual(info["age_at_capture_end_s"], 5)
        self.assertEqual(info["age_at_horizon_s"], 7)
        self.assertEqual(info["known_seconds"], 4)
        self.assertEqual(info["time_weighted_mean_age_s"], 3)
        self.assertEqual(info["fresh_update_count_within_capture"], 1)

    def test_trailing_silence_is_visible_when_no_consecutive_gap_exists(self):
        result = summarize(records([0, 5, 10]), [True] * 3, [True, False, False], [0, 5, 10], [2, None, None],
                           ["modeled_authenticated", "original_lost", "original_lost"],
                           horizon=20, thresholds_s=[5])
        self.assertEqual(result["augmented_received_interarrival_gap_s_count"], 0)
        self.assertIsNone(result["augmented_received_interarrival_gap_s_max"])
        self.assertEqual(result["augmented_received_information_age_at_capture_end_s_max"], 10)
        self.assertEqual(result["augmented_received_information_age_at_horizon_s_max"], 20)
        self.assertEqual(result["authenticated_information_age_time_weighted_mean_s"], 6)
        json.dumps(result, allow_nan=False)

    def test_loss_and_authentication_accounting_is_enforced(self):
        arguments = dict(records=records([0, 1]), baseline_received=[True, True], augmented_received=[True, True],
                         reception_times=[0, 1], authenticated_at=[2, None],
                         message_outcomes=["modeled_authenticated", "pending_signing"], horizon=3, thresholds_s=[1])
        invalid = [
            {"augmented_received": [False, True]},
            {"authenticated_at": [None, None]},
            {"authenticated_at": [4, None]},
            {"message_outcomes": ["original_lost", "pending_signing"]},
            {"message_outcomes": ["modeled_authenticated", "expired_signing"]},
            {"reception_times": [None, 1]},
            {"baseline_received": [True]},
        ]
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                summarize(**{**arguments, **changes})

    def test_no_receipts_returns_unknown_freshness_and_null_conditional_metrics(self):
        result = summarize(records([0, 1]), [False, False], [False, False], [None, None], [None, None],
                           ["original_lost", "original_lost"], horizon=3, thresholds_s=[1])
        self.assertEqual(result["authenticated_source_fraction"], 0)
        self.assertIsNone(result["authenticated_received_fraction"])
        self.assertIsNone(result["source_to_auth_ms_mean"])
        self.assertEqual(result["augmented_received_information_age_known_time_fraction"], 0)
        self.assertIsNone(result["augmented_received_information_age_time_weighted_mean_s"])
        self.assertEqual(result["threshold_coverage"][0]["source_authentication_fraction"], 0)
        self.assertIsNone(result["threshold_coverage"][0]["receipt_authentication_fraction"])
        json.dumps(result, allow_nan=False)


if __name__ == "__main__":
    unittest.main()
