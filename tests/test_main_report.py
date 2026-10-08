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
    case_metrics, compare_windows, coverage_rows, generate_report,
)
from src.experiment import signed_experiment
from src.processing.prepare_recording import prepare_recording


class ReportingMetricTests(unittest.TestCase):
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
                          "threshold_coverage": [point]}]}

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
        raw.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
        prepare_recording(raw, prepared, {"timestamp_mode": "unix_seconds", "recording_start": 1000,
                                         "recording_end": 1004}, target_duration_s=.4, followup_s=2)
        scenarios = {"seeds": [1], "scenarios": [{"name": "fixture", "sender_profile": "fixture", "receiver_profile": "fixture",
            "parameters": {"replay_model": "signed_detached", "followup_s": 2, "max_batch_wait_s": None,
                           "channel_mode": "independent", "auth_frames_per_second": 5000,
                           "loss": {"kind": "iid", "probability": 0}, "record_events": False}}]}
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
        with contextlib.redirect_stdout(io.StringIO()):
            signed_experiment.run(args)
        cls.report = json.loads((cls.window / "03_replay/replay_summary.json").read_text())
        generate_report(cls.window, "Generated test")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_signature_figures_and_full_case_tables_are_nonempty(self):
        for stem in ("01_traffic_by_df", "02_signature_cost", "03_channel_load", "04_ordinary_delivery",
                     "05_authentication_deadlines", "05_authentication_deadlines_from_reception", "06_backlog", "06_backlog_timeline_01"):
            for extension in ("png", "pdf", "svg"):
                self.assertGreater((self.window / "figures" / f"{stem}.{extension}").stat().st_size, 1000)
        text = (self.window / "report.md").read_text()
        self.assertIn("Neither model establishes an empirical operational failure probability", text)
        self.assertNotIn("authentication_outcomes.png", text)
        self.assertEqual(len((self.window / "figures/case_metrics.csv").read_text().splitlines()), 3)

    def test_manifest_validation_is_read_only_and_detects_changed_artifacts(self):
        before = {p: p.stat().st_mtime_ns for p in self.window.rglob("*") if p.is_file()}
        generate_report(self.window, "Generated test", validate_only=True)
        self.assertEqual(before, {p: p.stat().st_mtime_ns for p in self.window.rglob("*") if p.is_file()})
        path = self.window / "report.md"
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
        import csv
        with (output / "figures/window_comparison.csv").open() as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 2)
        for row in rows:
            for key, value in row.items():
                if key.startswith("difference_"):
                    self.assertEqual(float(value), 0)

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
