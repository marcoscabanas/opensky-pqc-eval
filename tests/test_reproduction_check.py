import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import check_reproduction as check


class ReproductionCheckTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.results, self.reference = self.root / "results/runs/development/replay", self.root / "results/reference/development"
        self.raw = self.write("data/development/raw/adsb_sample.jsonl", b'{"fixture":true}\n')
        self.trace = self.write("results/runs/development/processed/experimental_trace.jsonl", b'{"trace_id":1}\n{"trace_id":2}\n')
        self.groups = self.write("results/runs/development/processed/authentication_groups/authentication_groups_k1.jsonl", b'{"group_id":1}\n{"group_id":2}\n')
        self.source = self.write("src/model.py", b"# fixture source\n")
        self.config = {"fixed": {"module": "src.fixed", "implementation": "fixture", "expected_signature_bytes": 64}}
        self.config_path = self.write_json("config/algorithms.json", self.config)
        evidence = lambda path: {"path": str(path.relative_to(self.root)), "sha256": check.file_sha256(path)}
        self.profile = {
            "schema_version": 1, "kind": "portable_signature_size_calibration",
            "trace": evidence(self.trace), "groups": {"1": evidence(self.groups)},
            "algorithms": {"fixed": {
                "identity": {field: self.config["fixed"].get(field) for field in check.IDENTITY_FIELDS},
                "intervals": {"1": {"distribution": [{"signature_bytes": 64, "count": 1}],
                                     "sample_count": 1, "sizing_basis": "configured_fixed_size"}},
            }},
        }
        self.profile["profile_sha256"] = check.digest(self.profile)
        self.profile_path = self.write_json("data/calibration/signature_sizes.json", self.profile)
        self.manifest = {
            "raw_capture": evidence(self.raw),
            "expected": {"source_messages": 2, "aircraft": 1, "screening_rows": 1, "replay_rows": 2},
            "processed_sha256": check.file_sha256(self.trace),
            "groups_sha256": {"1": check.file_sha256(self.groups)},
        }
        self.write_json("data/development/manifest.json", self.manifest)
        self.provenance = {
            "trace": evidence(self.trace), "groups": {"1": evidence(self.groups)},
            "algorithms_config": evidence(self.config_path), "signature_size_profile": evidence(self.profile_path),
            "source_files_sha256": {"model.py": check.file_sha256(self.source)},
        }
        self.screen = [{"algorithm": "fixed", "interval_k": 1, "observed_message_count": 2,
                        "observed_aircraft_count": 1, "grouped_message_count": 2,
                        "unsigned_tail_message_count": 0, "complete_group_count": 2,
                        "signature_bytes_mean": 64.0}]
        self.rows = [self.replay_row("independent"), self.replay_row("destructive_overlap")]
        for directory in (self.results, self.reference):
            self.publish(directory, "screening", self.screen)
            self.publish(directory, "replay", self.rows)

    def write(self, relative, content):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def write_json(self, relative, content):
        return self.write(relative, json.dumps(content, indent=2).encode())

    @staticmethod
    def replay_row(mode):
        independent = mode == "independent"
        received, authenticated, failures = (2, 1, 0) if independent else (1, 0, 1)
        outcomes = {"pending_signing": 1, "modeled_authenticated" if independent else "original_lost": 1}
        group_outcomes = {"pending_signing": 1, "modeled_authenticated" if independent else "missing_message": 1}
        return {
            "scenario": mode, "algorithm": "fixed", "interval_k": 1, "seed": 1,
            "source_messages": 2, "trace_messages": 2, "aircraft_count": 1, "trace_aircraft": 1,
            "baseline_original_received_messages": 2, "baseline_original_lost_messages": 0,
            "augmented_original_received_messages": received, "augmented_original_lost_messages": 2 - received,
            "authenticated_messages": authenticated, "definitive_failure_messages": failures,
            "unresolved_messages": 1, "received_definitive_failure_messages": 0, "received_unresolved_messages": 1,
            "source_groups": 2, "message_outcomes": outcomes, "group_outcomes": group_outcomes,
            "group_work_states_at_horizon": group_outcomes,
            "auth_frames_received": 9, "auth_frames_lost": 1, "auth_frames_in_flight_at_horizon": 0,
            "auth_frames_transmitted": 10, "source_to_auth_ms_count": authenticated,
            "receipt_to_auth_ms_count": authenticated, "source_to_auth_ms_mean": 1000.0 if independent else None,
            "additional_original_loss_messages": 2 - received, "original_reception_gain_messages": 0,
            "net_additional_original_loss_messages": 2 - received, "channel_mode": mode,
            "baseline_original_received_fraction": 1.0, "augmented_original_received_fraction": received / 2,
            "authenticated_source_fraction": authenticated / 2, "authenticated_received_fraction": authenticated / received,
            "followup_s": 60.0,
            "threshold_coverage": [{
                "threshold_s": 60.0, "source_eligible_messages": 2, "source_ineligible_due_to_followup_messages": 0,
                "source_authenticated_within_threshold_messages": authenticated, "source_authentication_fraction": authenticated / 2,
                "receipt_eligible_messages": received, "receipt_ineligible_due_to_followup_messages": 0,
                "receipt_authenticated_within_threshold_messages": authenticated, "receipt_authentication_fraction": authenticated / received,
            }],
            "channel_summary": {"numpy_version": "fixture-1"},
        }

    def publish(self, directory, mode, rows, *, provenance=None):
        parameters = {"algorithms": ["fixed"], "intervals": [1], "signature_directories": []}
        if mode == "replay":
            parameters.update(scenarios=[{"name": "independent"}, {"name": "destructive_overlap"}], seeds=[1])
        report = {"schema_version": 1, "mode": mode, "parameters": parameters,
                  "provenance": copy.deepcopy(self.provenance if provenance is None else provenance)}
        report["input_fingerprint"] = check.digest(report)
        report["rows"] = copy.deepcopy(rows)
        csv_content = check.csv_bytes(rows)
        report["csv_sha256"] = check.hashlib.sha256(csv_content).hexdigest()
        report["report_sha256"] = check.digest(report)
        json_name, csv_name = check.REPORTS[mode]
        directory.mkdir(parents=True, exist_ok=True)
        (directory / json_name).write_text(json.dumps(report, indent=2))
        (directory / csv_name).write_bytes(csv_content)

    def validate(self, *, allow_model_change=False):
        return check.check_results(self.results, self.reference, self.manifest, root=self.root,
                                   allow_model_change=allow_model_change)

    def republish_after_source_change(self):
        self.source.write_text("# revised fixture source\n")
        current = copy.deepcopy(self.provenance)
        current["source_files_sha256"]["model.py"] = check.file_sha256(self.source)
        self.publish(self.results, "screening", self.screen, provenance=current)
        self.publish(self.results, "replay", self.rows, provenance=current)
        return current

    def test_inputs_and_relocated_reports_validate_without_project_imports(self):
        self.assertEqual(check.check_inputs(self.root), self.manifest)
        relocated = copy.deepcopy(self.provenance)
        for entry in (relocated["trace"], relocated["algorithms_config"], relocated["signature_size_profile"], relocated["groups"]["1"]):
            entry["path"] = "/different/checkout/" + entry["path"]
        self.publish(self.reference, "screening", self.screen, provenance=relocated)
        self.publish(self.reference, "replay", self.rows, provenance=relocated)
        self.assertEqual(self.validate(), [])

    def test_raw_and_calibration_tampering_fail(self):
        self.raw.write_bytes(b"changed capture\n")
        with self.assertRaisesRegex(check.CheckError, "Raw sample SHA256"):
            check.check_inputs(self.root)
        invalid = copy.deepcopy(self.profile)
        invalid["algorithms"]["fixed"]["intervals"]["1"]["distribution"][0]["count"] = 2
        with self.assertRaisesRegex(check.CheckError, "integrity"):
            check.check_calibration(invalid, self.config)
        del invalid["profile_sha256"]
        invalid["profile_sha256"] = check.digest(invalid)
        with self.assertRaisesRegex(check.CheckError, "frequency weights"):
            check.check_calibration(invalid, self.config)

    def test_csv_report_and_reference_tampering_are_detected(self):
        csv_path = self.results / check.REPORTS["replay"][1]
        csv_path.write_bytes(csv_path.read_bytes() + b"corruption\n")
        with self.assertRaisesRegex(check.CheckError, "CSV integrity"):
            self.validate()
        self.publish(self.results, "replay", self.rows)
        path = self.results / check.REPORTS["replay"][0]
        report = json.loads(path.read_text())
        report["rows"][0]["source_to_auth_ms_mean"] = 9000.0
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(check.CheckError, "report integrity"):
            self.validate()
        self.publish(self.results, "replay", self.rows)
        reference_csv = self.reference / check.REPORTS["screening"][1]
        reference_csv.write_bytes(b"tampered reference\n")
        with self.assertRaisesRegex(check.CheckError, "CSV integrity"):
            self.validate()

    def test_missing_duplicate_and_wrong_case_matrix_are_rejected(self):
        for rows in (self.rows[:1], [self.rows[0], self.rows[0]],
                     [self.rows[0], {**self.rows[1], "seed": 99}]):
            with self.subTest(rows=rows):
                self.publish(self.results, "replay", rows)
                with self.assertRaises(check.CheckError):
                    self.validate()

    def test_resigned_scientific_changes_and_integer_changes_still_fail(self):
        changed = copy.deepcopy(self.rows)
        changed[0]["source_to_auth_ms_mean"] += 0.01
        self.publish(self.results, "replay", changed)
        with self.assertRaisesRegex(check.CheckError, "source_to_auth_ms_mean"):
            self.validate()
        with self.assertRaises(check.CheckError):
            check.compare_values(2.0, 2, "integer count")
        check.compare_values(1.0 + 5e-10, 1.0, "floating value")

    def test_conservation_and_independent_or_collision_invariants_are_checked(self):
        mutations = [
            lambda row: row.update(auth_frames_lost=0),
            lambda row: row.update(unresolved_messages=0),
            lambda row: row.update(channel_mode="independent"),
            lambda row: row.update(original_reception_gain_messages=1, additional_original_loss_messages=2),
        ]
        for mutation in mutations:
            row = copy.deepcopy(self.rows[1])
            mutation(row)
            with self.subTest(mutation=mutation), self.assertRaises(check.CheckError):
                check.check_conservation(row, self.manifest["expected"])

    def test_changed_input_provenance_and_local_source_are_rejected(self):
        altered = copy.deepcopy(self.provenance)
        altered["trace"]["sha256"] = "a" * 64
        self.publish(self.results, "replay", self.rows, provenance=altered)
        with self.assertRaisesRegex(check.CheckError, "provenance"):
            self.validate()
        self.publish(self.results, "replay", self.rows)
        self.source.write_text("# changed model\n")
        with self.assertRaisesRegex(check.CheckError, "Source file differs"):
            self.validate()

    def test_numpy_metadata_difference_is_not_a_scientific_mismatch_and_is_reported(self):
        changed = copy.deepcopy(self.rows)
        changed[0]["channel_summary"]["numpy_version"] = "fixture-2"
        self.publish(self.results, "replay", changed)
        notes = self.validate()
        self.assertEqual(len(notes), 1)
        self.assertIn("NumPy metadata differs", notes[0])

    def test_optional_model_change_accepts_fresh_reports_but_default_remains_strict(self):
        self.republish_after_source_change()
        with self.assertRaisesRegex(check.CheckError, "source_files_sha256"):
            self.validate()
        notes = self.validate(allow_model_change=True)
        self.assertEqual(len(notes), 2)
        self.assertTrue(all("Model source hashes differ" in note for note in notes))
        self.assertTrue(all("current live source hashes" in note for note in notes))

    def test_model_change_exception_still_rejects_scientific_and_input_changes(self):
        current = self.republish_after_source_change()
        changed = copy.deepcopy(self.rows)
        changed[0]["source_to_auth_ms_mean"] += 0.01
        self.publish(self.results, "replay", changed, provenance=current)
        with self.assertRaisesRegex(check.CheckError, "source_to_auth_ms_mean"):
            self.validate(allow_model_change=True)
        altered = copy.deepcopy(current)
        altered["algorithms_config"]["sha256"] = "a" * 64
        self.publish(self.results, "replay", self.rows, provenance=altered)
        with self.assertRaisesRegex(check.CheckError, "algorithms_config"):
            self.validate(allow_model_change=True)

    def test_model_change_exception_never_accepts_stale_or_missing_live_sources(self):
        self.source.write_text("# reports still describe old source\n")
        with self.assertRaisesRegex(check.CheckError, "Source file differs"):
            self.validate(allow_model_change=True)
        self.republish_after_source_change()
        self.source.write_text("# source changed after revised reports were saved\n")
        with self.assertRaisesRegex(check.CheckError, "Source file differs"):
            self.validate(allow_model_change=True)
        self.source.unlink()
        with self.assertRaisesRegex(check.CheckError, "Declared source file is missing"):
            self.validate(allow_model_change=True)

    def test_model_change_exception_cannot_omit_current_source_files(self):
        current = self.republish_after_source_change()
        omitted = copy.deepcopy(current)
        omitted["source_files_sha256"] = {}
        self.publish(self.results, "screening", self.screen, provenance=omitted)
        with self.assertRaisesRegex(check.CheckError, "source inventory differs"):
            self.validate(allow_model_change=True)
        self.publish(self.results, "screening", self.screen, provenance=current)
        self.write("src/new_engine.py", b"# newly added scientific engine\n")
        with self.assertRaisesRegex(check.CheckError, "source inventory differs"):
            self.validate(allow_model_change=True)

    def test_cli_model_change_flag_is_forwarded_explicitly(self):
        for arguments, allowed in (([], False), (["--allow-model-change"], True)):
            with self.subTest(arguments=arguments), patch.object(check, "check_inputs", return_value=self.manifest), \
                    patch.object(check, "check_results", return_value=[]) as check_results, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(check.main(arguments), 0)
                self.assertEqual(check_results.call_args.kwargs, {"allow_model_change": allowed})

    def test_cli_validation_failure_returns_nonzero_with_clear_error(self):
        error = io.StringIO()
        with patch.object(check, "check_inputs", side_effect=check.CheckError("fixture input mismatch")), contextlib.redirect_stderr(error):
            self.assertEqual(check.main(["--inputs-only"]), 1)
        self.assertIn("FAIL: fixture input mismatch", error.getvalue())


if __name__ == "__main__":
    unittest.main()
