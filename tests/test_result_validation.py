import json
import copy
from pathlib import Path
import tempfile
import unittest
from src.experiment.result_validation import load_report, metric_matrix, metric_statistics, seed_statistics
from src.experiment.replay_artifacts import _digest, _publish


class SignedPlotValidationTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        scenario = {"name": "example", "parameters": {"replay_model": "signed_detached"}}
        identity = {"schema_version": 1, "mode": "replay", "provenance": {}, "parameters": {
            "replay_model": "signed_detached", "algorithms": ["ECDSA-P256"], "intervals": [1],
            "seeds": [1], "scenarios": [scenario]}}
        row = {"scenario": "example", "algorithm": "ECDSA-P256", "interval_k": 1, "seed": 1,
               "replay_model": "signed_detached", "source_messages": 1, "authenticated_messages": 0,
               "definitive_failure_messages": 0, "unresolved_messages": 1,
               "augmented_original_received_messages": 1, "received_definitive_failure_messages": 0,
               "received_unresolved_messages": 1, "source_groups": 1, "authenticated_groups": 0,
               "cryptographically_valid_groups": 0, "verification_completed_groups": 0,
               "verification_started_groups": 0, "reconstructed_signing_input_groups": 0,
               "complete_authentication_object_groups": 0, "invalid_signature_groups": 0,
               "verification_pending_groups": 0, "authentication_pending_groups": 1,
               "authentication_definitive_failure_groups": 0,
               "authentication_only_additional_rf_loss_fraction": 0,
               "additional_offered_airtime_load": 0, "baseline_original_received_messages": 1,
               "receipt_to_auth_ms_count": 0, "receipt_to_auth_ms_p50": None,
               "receipt_to_auth_ms_max": None, "ordinary_transmission_delay_ms_count": 1,
               "ordinary_frames_transmitted": 1, "ordinary_transmission_delay_ms_p50": 0,
               "ordinary_transmission_delay_ms_max": 0}
        self.report = {**identity, "input_fingerprint": _digest(identity), "rows": [row]}
        self.publish()

    def publish(self):
        _publish(self.root / "replay_summary.json", self.root / "replay_overview.csv", self.report)

    def test_null_completed_delay_remains_distinct_from_zero(self):
        report = load_report(self.root)
        self.assertEqual(metric_matrix(report, lambda r: r["receipt_to_auth_ms_p50"])[2], [[None]])
        self.assertEqual(metric_matrix(report, lambda r: r["ordinary_transmission_delay_ms_p50"])[2], [[0]])

    def test_tampered_csv_is_rejected(self):
        with (self.root / "replay_overview.csv").open("a") as stream:
            stream.write("tampered\n")
        with self.assertRaisesRegex(ValueError, "integrity"):
            load_report(self.root)

    def test_complete_hashes_do_not_hide_incomplete_case_matrix(self):
        self.report["parameters"]["intervals"].append(5)
        self.report["input_fingerprint"] = _digest({k: self.report[k] for k in ("schema_version", "mode", "provenance", "parameters")})
        self.publish()
        with self.assertRaisesRegex(ValueError, "matrix"):
            load_report(self.root)

    def test_fabricated_zero_delay_without_completions_is_rejected(self):
        self.report["rows"][0]["receipt_to_auth_ms_p50"] = 0
        self.publish()
        with self.assertRaisesRegex(ValueError, "null"):
            load_report(self.root)

    def test_nonconserving_outcomes_are_rejected_even_with_updated_hashes(self):
        self.report["rows"][0]["unresolved_messages"] = 0
        self.publish()
        with self.assertRaisesRegex(ValueError, "conserve"):
            load_report(self.root)

    def test_multiple_seeds_report_mean_and_range_without_overwriting(self):
        self.report["parameters"]["seeds"] = [1, 2, 3, 4, 5]
        first = self.report["rows"][0]
        self.report["rows"] = [{**first, "seed": seed, "additional_offered_airtime_load": seed}
                               for seed in self.report["parameters"]["seeds"]]
        self.report["input_fingerprint"] = _digest({key: self.report[key]
            for key in ("schema_version", "mode", "provenance", "parameters")})
        self.publish()
        report = load_report(self.root)
        metric = lambda row: row["additional_offered_airtime_load"]
        self.assertEqual(metric_matrix(report, metric)[2], [[3]])
        self.assertEqual(metric_statistics(report, metric)["ECDSA-P256", 1, "example"],
                         {"seed_count": 5, "defined_seed_count": 5, "mean": 3, "min": 1, "max": 5})

    def test_scenario_seed_overrides_keep_control_single_and_capture_repeated(self):
        params = self.report["parameters"]
        params["seeds"] = [1, 2, 3, 4, 5]
        params["scenarios"][0]["seeds"] = [1]
        scenario = copy.deepcopy(params["scenarios"][0])
        scenario.update(name="repeated")
        scenario.pop("seeds")
        params["scenarios"].append(scenario)
        first = self.report["rows"][0]
        self.report["rows"] += [{**first, "scenario": "repeated", "seed": seed}
                                for seed in params["seeds"]]
        self.report["input_fingerprint"] = _digest({key: self.report[key]
            for key in ("schema_version", "mode", "provenance", "parameters")})
        self.publish()
        stats = metric_statistics(load_report(self.root), lambda row: row["source_messages"])
        self.assertEqual(stats["ECDSA-P256", 1, "example"]["seed_count"], 1)
        self.assertEqual(stats["ECDSA-P256", 1, "repeated"]["seed_count"], 5)
        self.assertEqual(stats["ECDSA-P256", 1, "repeated"]["mean"], 1)

    def test_missing_delay_seeds_remain_missing_and_defined_count_is_explicit(self):
        self.assertEqual(seed_statistics([None, 10, 30, None, 20]),
                         {"seed_count": 5, "defined_seed_count": 3, "mean": 20, "min": 10, "max": 30})
        self.assertEqual(seed_statistics([None] * 5)["mean"], None)

    def test_observed_capture_cannot_claim_predicted_baseline_loss(self):
        self.report["parameters"]["scenarios"][0]["parameters"]["channel_mode"] = "observed_capture"
        self.report["rows"][0].update(channel_mode="observed_capture", baseline_original_received_messages=0,
            timing_matched_original_received_messages=1, ordinary_frames_in_flight_at_horizon=0)
        self.report["input_fingerprint"] = _digest({key: self.report[key]
            for key in ("schema_version", "mode", "provenance", "parameters")})
        self.publish()
        with self.assertRaisesRegex(ValueError, "preserve observed"):
            load_report(self.root)

    def test_report_cannot_relabel_a_different_channel_model(self):
        self.report["parameters"]["scenarios"][0]["parameters"]["channel_mode"] = "observed_capture"
        self.report["rows"][0]["channel_mode"] = "independent"
        self.report["input_fingerprint"] = _digest({key: self.report[key]
            for key in ("schema_version", "mode", "provenance", "parameters")})
        self.publish()
        with self.assertRaisesRegex(ValueError, "channel mode differs"):
            load_report(self.root)
