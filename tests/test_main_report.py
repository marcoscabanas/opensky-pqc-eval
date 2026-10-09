"""Metric and artifact checks using temporary, generated experiment inputs."""

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.experiment.main_report import (
    aggregate_rows, case_metrics, compare_windows, coverage_rows, generate_report, signature_airtime_bounds,
)
from src.experiment import signed_experiment
from src.processing.prepare_recording import prepare_recording


class ReportingMetricTests(unittest.TestCase):
    def test_omitted_slh_bound_is_analytical_and_accounts_for_followup(self):
        report = {"parameters": {"algorithms": ["ECDSA-P256"]}, "rows": [
            {"algorithm": "ECDSA-P256", "interval_k": 20, "source_groups": 37228,
             "signature_only_7byte_lower_bound_frames": 372280,
             "trace_duration_s": 3600, "followup_s": 600}]}
        actual, bound = signature_airtime_bounds(report)
        self.assertEqual(actual["basis"], "actual_signed_bytes")
        self.assertTrue(bound["basis"].startswith("analytical_only"))
        self.assertEqual(bound["signature_only_frames"], 41807044)
        self.assertAlmostEqual(bound["required_airtime_s"], 5016.84528)
        self.assertGreater(bound["target_plus_followup_airtime_pct"], 100)
        self.assertEqual(report["parameters"]["algorithms"], ["ECDSA-P256"])

    def point(self):
        return {"threshold_s": 10, "source_eligible_messages": 10,
                "source_authenticated_within_threshold_messages": 2,
                "source_authentication_fraction": .2,
                "source_ineligible_due_to_followup_messages": 3,
                "receipt_eligible_messages": 4,
                "receipt_authenticated_within_threshold_messages": 2,
                "receipt_authentication_fraction": .5,
                "receipt_ineligible_due_to_followup_messages": 1}

    def report(self, point):
        return {"rows": [{"algorithm": "test", "interval_k": 1, "scenario": "test",
                          "seed": 1, "threshold_coverage": [point]}]}

    def test_replicate_summary_does_not_sum_counts_or_pool_percentages(self):
        rows = [{"algorithm": "A", "seed": seed, "messages": count, "eligible": eligible,
                 "pct": 100 * count / eligible} for seed, count, eligible in ((1, 1, 2), (2, 9, 10))]
        summary, = aggregate_rows(rows, ("algorithm",))
        self.assertEqual(summary["seed_count"], 2)
        self.assertEqual(summary["messages_mean"], 5)
        self.assertEqual(summary["messages_min"], 1)
        self.assertEqual(summary["messages_max"], 9)
        self.assertEqual(summary["pct_mean"], 70)
        self.assertNotEqual(summary["pct_mean"], 100 * 10 / 12)

    def test_duplicate_replicate_cannot_silently_overwrite_a_seed(self):
        with self.assertRaisesRegex(ValueError, "duplicate seed"):
            aggregate_rows([{"case": "A", "seed": 1, "value": 2},
                            {"case": "A", "seed": 1, "value": 3}], ("case",))

    def test_deadlines_keep_distinct_source_and_received_denominators(self):
        rows = coverage_rows(self.report(self.point()))
        self.assertEqual([r["authenticated_pct_eligible"] for r in rows], [20, 50])
        self.assertEqual([r["eligible_messages"] for r in rows], [10, 4])
        self.assertEqual([r["excluded_due_to_followup_messages"] for r in rows], [3, 1])

    def test_zero_eligible_cohort_is_missing_not_zero_percent(self):
        point = self.point()
        point.update(receipt_eligible_messages=0, receipt_authenticated_within_threshold_messages=0,
                     receipt_authentication_fraction=None)
        self.assertIsNone(coverage_rows(self.report(point))[1]["authenticated_pct_eligible"])

    def test_invalid_deadline_fraction_is_rejected(self):
        point = self.point()
        point["source_authentication_fraction"] = .9
        with self.assertRaisesRegex(ValueError, "denominator"):
            coverage_rows(self.report(point))

    def test_deadline_sets_cannot_silently_omit_a_seed(self):
        report = self.report(self.point())
        changed = copy.deepcopy(report["rows"][0])
        changed["seed"] = 2
        changed["threshold_coverage"][0]["threshold_s"] = 20
        report["rows"].append(changed)
        with self.assertRaisesRegex(ValueError, "deadline sets"):
            coverage_rows(report)

    def test_deadline_sets_must_match_normalized_configuration(self):
        report = self.report(self.point())
        report["simulator_parameters"] = {"test": {"coverage_thresholds_s": [10, 20]}}
        with self.assertRaisesRegex(ValueError, "deadline sets"):
            coverage_rows(report)


@unittest.skipUnless(importlib.util.find_spec("cryptography") and importlib.util.find_spec("matplotlib"),
                     "Real ECDSA and plot dependencies are required")
class MainReportIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temporary.name)
        cls.window = cls.root / "daytime"
        prepared = cls.window / "01_prepared"
        records = [{"trace_id": i + 1, "icao": "ABCDEF", "raw_msg": "8DABCDEF" + f"{i+1:020X}",
                    "timestamp": 1000 + i * .1, "relative_time_s": i * .1} for i in range(4)]
        raw = cls.root / "recording.jsonl"
        raw_rows = [*records, {"raw_msg": "5DAAAAAA000000", "timestamp": 1000.004, "icao": "AAAAAA", "df": 11}]
        raw.write_text("".join(json.dumps(r) + "\n" for r in raw_rows), encoding="utf-8")
        prepare_recording(raw, prepared, {"timestamp_mode": "unix_seconds", "recording_start": 1000,
                                         "recording_end": 1004}, target_duration_s=.4, followup_s=2)
        scenarios = {"seeds": [1, 2, 3, 4, 5], "scenarios": [{"name": "fixture", "sender_profile": "fixture", "receiver_profile": "fixture", "seeds": [1],
            "parameters": {"replay_model": "signed_detached", "followup_s": 2, "max_batch_wait_s": None,
                           "channel_mode": "independent", "auth_frames_per_second": 5000,
                           "loss": {"kind": "iid", "probability": 0}, "record_events": False}}]}
        scenarios["scenarios"].append({**scenarios["scenarios"][0], "name": "capture",
            "parameters": {**scenarios["scenarios"][0]["parameters"], "channel_mode": "observed_capture"}})
        scenarios["scenarios"][-1].pop("seeds")
        profiles = {"schema_version": 1, "profiles": {"fixture": {"id": "fixture", "label": "Fixture",
            "platform": "Generated test", "kind": "sensitivity_assumption", "algorithms": {"ECDSA-P256": {
                "implementation": "SECP256R1", "equivalence": "assumed", "limitation": "Test input",
                "source_urls": [], "operations": {op: {"samples_ms": [1], "sample_kind": "assumed_constant"}
                                                   for op in ("sign", "verify")}}}}}}
        for name, content in (("scenarios.json", scenarios), ("profiles.json", profiles)):
            (cls.root / name).write_text(json.dumps(content), encoding="utf-8")
        args = signed_experiment.parse_args([
            "--trace", str(prepared / "trace.jsonl"), "--channel-trace", str(prepared / "channel.jsonl"),
            "--hardware-profiles", str(cls.root / "profiles.json"), "--scenarios", str(cls.root / "scenarios.json"),
            "--output-dir", str(cls.window / "03_replay"), "--workloads-dir", str(cls.window / "02_signed"),
            "--algorithm", "ECDSA-P256", "--intervals", "1", "2", "--replay-model", "signed_detached"])[1]
        args.analysis_context = {"mode": "conditional_recorded_timing",
                                 "recording_limitations": ["Generated acquisition timing limitation."]}
        with contextlib.redirect_stdout(io.StringIO()):
            signed_experiment.run(args)
        cls.report = json.loads((cls.window / "03_replay/replay_summary.json").read_text())
        generate_report(cls.window, "Generated test")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_signature_figures_and_full_case_tables_are_nonempty(self):
        for stem in ("01_traffic_by_df", "02_signature_cost", "02_signature_airtime_lower_bound", "03_channel_load", "04_ordinary_delivery",
                     "05_authentication_deadlines", "05_authentication_deadlines_from_reception", "06_backlog_timeline_01", "06_backlog_timeline_02"):
            self.assertGreater((self.window / "figures" / f"{stem}.pdf").stat().st_size, 1000)
        self.assertFalse((self.window / "report.md").exists())
        self.assertFalse(list((self.window / "figures").glob("*.png")))
        self.assertFalse(list((self.window / "figures").glob("*.svg")))
        self.assertFalse((self.window / "figures/06_backlog.pdf").exists())
        manifest = json.loads((self.window / "figures/figure_manifest.json").read_text())
        self.assertIn("conditional timing", manifest["label"])
        self.assertEqual({Path(name).suffix for name in manifest["artifacts"]}, {".pdf", ".csv"})
        self.assertEqual(self.report["provenance"]["analysis_context"]["recording_limitations"],
                         ["Generated acquisition timing limitation."])
        self.assertEqual(len((self.window / "figures/case_metrics.csv").read_text().splitlines()), 13)
        self.assertEqual(len((self.window / "figures/case_summary.csv").read_text().splitlines()), 5)

    def test_interval_tables_keep_each_seed_and_event_derived_fields(self):
        import csv
        with (self.window / "figures/backlog_intervals.csv").open() as handle:
            rows = list(csv.DictReader(handle))
        self.assertTrue(rows)
        self.assertIn("sender_unfinished_groups_mean", rows[0])
        self.assertIn("verification_completed_groups", rows[0])
        self.assertEqual({int(row["seed"]) for row in rows if row["scenario"] == "capture"}, {1, 2, 3, 4, 5})
        self.assertEqual({int(row["seed"]) for row in rows if row["scenario"] == "fixture"}, {1})

    def test_manifest_validation_is_read_only_and_detects_changed_artifacts(self):
        before = {p: p.stat().st_mtime_ns for p in self.window.rglob("*") if p.is_file()}
        outputs = generate_report(self.window, "Generated test", validate_only=True)
        self.assertEqual(outputs, {"figures_dir": str(self.window / "figures"),
                                   "figure_manifest": str(self.window / "figures/figure_manifest.json")})
        self.assertEqual(before, {p: p.stat().st_mtime_ns for p in self.window.rglob("*") if p.is_file()})
        path = self.window / "figures/case_summary.csv"
        original = path.read_bytes()
        try:
            path.write_bytes(original + b"changed")
            with self.assertRaisesRegex(ValueError, "artifact integrity"):
                generate_report(self.window, "Generated test", validate_only=True)
        finally:
            path.write_bytes(original)

    def test_rf_failure_denominator_and_required_versus_actual_load(self):
        row = copy.deepcopy(self.report["rows"][0])
        row.update(ordinary_frames_transmitted=2, ordinary_frames_rf_lost=1,
                   prototype_required_authentication_airtime_s=3, trace_duration_s=10,
                   additional_offered_airtime_load=.02)
        values = case_metrics(row)
        self.assertEqual(values["augmented_rf_failure_pct_transmitted"], 50)
        self.assertEqual(values["actual_added_airtime_pct"], 2)
        self.assertEqual(values["required_authentication_airtime_pct"], 30)
        row.update(ordinary_frames_transmitted=0, ordinary_frames_rf_lost=0)
        self.assertIsNone(case_metrics(row)["augmented_rf_failure_pct_transmitted"])

    def test_matching_windows_export_zero_differences_and_validation(self):
        output = self.root / "comparison"
        compare_windows(self.window, self.window, output)
        compare_windows(self.window, self.window, output, validate_only=True)
        self.assertFalse((output / "report.md").exists())
        self.assertGreater((output / "figures/07_window_comparison.pdf").stat().st_size, 1000)
        self.assertFalse(list((output / "figures").glob("*.png")))
        self.assertFalse(list((output / "figures").glob("*.svg")))
        import csv
        with (output / "figures/window_comparison.csv").open() as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 4)
        for row in rows:
            for key, value in row.items():
                if key.startswith("difference_") and not key.endswith("defined_seed_count"):
                    self.assertEqual(float(value), 0)
        with (output / "figures/window_comparison_by_seed.csv").open() as handle:
            raw_rows = list(csv.DictReader(handle))
        self.assertEqual(len(raw_rows), 12)

    def test_comparison_rejects_different_scenarios_before_writing(self):
        changed = copy.deepcopy(self.report)
        changed["parameters"]["scenarios"][0]["parameters"]["followup_s"] += 1
        with patch("src.experiment.main_report.load_report", side_effect=[self.report, changed]):
            with self.assertRaisesRegex(ValueError, "identical scenario"):
                compare_windows(self.window, self.window, self.root / "invalid_comparison")
        self.assertFalse((self.root / "invalid_comparison").exists())

    def test_comparison_rejects_changed_hardware_profile_contents(self):
        changed = copy.deepcopy(self.report)
        changed["provenance"]["hardware_profiles"]["sha256"] = "changed"
        with patch("src.experiment.main_report.load_report", side_effect=[self.report, changed]):
            with self.assertRaisesRegex(ValueError, "hardware_profiles differs"):
                compare_windows(self.window, self.window, self.root / "invalid_comparison")

    def test_comparison_rejects_different_target_window_lengths(self):
        changed = copy.deepcopy(self.report)
        changed["rows"][0]["trace_duration_s"] += 1
        with patch("src.experiment.main_report.load_report", side_effect=[self.report, changed]):
            with self.assertRaisesRegex(ValueError, "equal target-window"):
                compare_windows(self.window, self.window, self.root / "invalid_comparison")

    def test_report_rejects_traffic_from_a_different_raw_recording(self):
        path = self.window / "01_prepared/traffic.json"
        original = path.read_bytes()
        try:
            traffic = json.loads(original)
            traffic["input_sha256"] = "a different recording"
            path.write_text(json.dumps(traffic), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Prepared traffic does not match"):
                generate_report(self.window, "Generated test", validate_only=True)
        finally:
            path.write_bytes(original)

    def test_report_rejects_replay_linked_to_a_different_prepared_trace(self):
        changed = copy.deepcopy(self.report)
        changed["provenance"]["trace"]["sha256"] = "another trace"
        with patch("src.experiment.main_report.load_report", return_value=changed):
            with self.assertRaisesRegex(ValueError, "different prepared inputs"):
                generate_report(self.window, "Generated test", validate_only=True)


if __name__ == "__main__":
    unittest.main()
