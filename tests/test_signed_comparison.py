import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import compare_signed_results as check


class SignedComparisonTest(unittest.TestCase):
    """Publication checks use a tiny report fixture, without native crypto."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.results, self.reference = self.root / "local", self.root / "published"
        self.cache = self.root / "public_workload"
        self.cache.mkdir()
        provenance = {}
        for name in check.FILE_INPUTS:
            path = self.root / f"{name}.json"
            path.write_text(json.dumps({"fixture": name}))
            provenance[name] = {"path": str(path), "sha256": check.file_digest(path)}
        source = self.root / "src/model.py"
        source.parent.mkdir()
        source.write_text("# Scientific fixture\n")
        provenance["source_files_sha256"] = {"model.py": check.file_digest(source)}
        identity = {"trace_messages": 2, "algorithm": "fixture", "interval": 1,
                    "max_batch_wait_s": None, "backend": {"version": "fixture-only"}}
        (self.cache / "groups.jsonl").write_text('{"fixture":"two group records represented by test metadata"}\n')
        (self.cache / "public_keys.json").write_text('{"fixture":"public key"}\n')
        manifest = {"complete": True, "identity": identity, "groups": 2,
                    "groups_sha256": check.file_digest(self.cache / "groups.jsonl"),
                    "public_keys_sha256": check.file_digest(self.cache / "public_keys.json")}
        (self.cache / "manifest.json").write_text(json.dumps(manifest))
        evidence = {"cache_dir": str(self.cache), "identity": identity,
                    "cache_identity": check.hashlib.sha256(check.canonical(identity) + b"\n").hexdigest(),
                    "signature_count": 2, "cryptographically_verified_signatures": 2,
                    "manifest_sha256": check.file_digest(self.cache / "manifest.json"),
                    "groups_sha256": manifest["groups_sha256"], "public_keys_sha256": manifest["public_keys_sha256"]}
        provenance["signed_workloads"] = {"fixture:k=1:max_batch_wait_s=None": evidence}
        scenario = {"name": "control", "parameters": {"replay_model": "signed_detached", "max_batch_wait_s": None}}
        parameters = {"replay_model": "signed_detached", "algorithms": ["fixture"], "intervals": [1],
                      "seeds": [1], "scenarios": [scenario]}
        row = {
            "scenario": "control", "algorithm": "fixture", "interval_k": 1, "seed": 1,
            "replay_model": "signed_detached", "signature_workload_evidence": evidence,
            "source_messages": 2, "trace_messages": 2, "source_groups": 2,
            "baseline_original_received_messages": 2, "baseline_original_lost_messages": 0,
            "augmented_original_received_messages": 2, "authenticated_messages": 1,
            "definitive_failure_messages": 0, "unresolved_messages": 1,
            "received_definitive_failure_messages": 0, "received_unresolved_messages": 1,
            "ordinary_frames_transmitted": 2, "ordinary_messages_unsent_pending": 0,
            "ordinary_messages_withheld_definitively": 0, "ordinary_frames_rf_lost": 0,
            "ordinary_frames_in_flight_at_horizon": 0, "auth_frames_received": 10,
            "auth_frames_lost": 0, "auth_frames_in_flight_at_horizon": 0, "auth_frames_transmitted": 10,
            "authenticated_groups": 1, "cryptographically_valid_groups": 1,
            "verification_completed_groups": 1, "verification_started_groups": 1,
            "reconstructed_signing_input_groups": 1, "complete_authentication_object_groups": 1,
            "invalid_signature_groups": 0, "authentication_pending_groups": 1,
            "authentication_definitive_failure_groups": 0,
            "message_outcomes": {"authenticated": 1, "pending": 1},
            "group_outcomes": {"authenticated": 1, "pending": 1},
            "group_work_states_at_horizon": {"authenticated": 1, "pending": 1},
            "baseline_original_received_fraction": 1.0, "augmented_original_received_fraction": 1.0,
            "authenticated_source_fraction": 0.5, "authenticated_received_fraction": 0.5,
            "ordinary_transmission_delay_ms_mean": 0.125,
        }
        self.report = {"schema_version": 1, "mode": "replay", "parameters": parameters,
                       "provenance": provenance, "rows": [row], "assumptions": ["Synthetic unit test only"]}
        self.publish(self.results, self.report)
        self.published = copy.deepcopy(self.report)
        for name in check.FILE_INPUTS:
            self.published["provenance"][name]["path"] = f"/publisher/unavailable/{name}.json"
        for entry in self.published["provenance"]["signed_workloads"].values():
            entry["cache_dir"] = "/publisher/unavailable/cache"
        # The deep copy preserves the alias between report and per-row evidence.
        self.publish(self.reference, self.published)

    @staticmethod
    def publish(directory, payload):
        report = copy.deepcopy(payload)
        identity = {key: report[key] for key in ("schema_version", "mode", "provenance", "parameters")}
        request = {**identity, "provenance": {k: v for k, v in report["provenance"].items() if k != "signed_workloads"}}
        report["input_fingerprint"], report["request_sha256"] = check.digest(identity), check.digest(request)
        content = check.csv_bytes(report["rows"])
        report["csv_sha256"] = check.hashlib.sha256(content).hexdigest()
        report["report_sha256"] = check.digest({k: v for k, v in report.items() if k != "report_sha256"})
        directory.mkdir(exist_ok=True)
        (directory / "replay_summary.json").write_text(json.dumps(report))
        (directory / "replay_overview.csv").write_bytes(content)

    def compare(self):
        return check.compare_results(self.results, self.reference, root=self.root)

    def test_relocated_reference_compares_without_accessing_publisher_files(self):
        self.assertEqual(self.compare(), 1)

    def test_tiny_floating_difference_allowed_but_meaningful_difference_rejected(self):
        self.report["rows"][0]["ordinary_transmission_delay_ms_mean"] += 5e-10
        self.publish(self.results, self.report)
        self.assertEqual(self.compare(), 1)
        self.report["rows"][0]["ordinary_transmission_delay_ms_mean"] += 0.001
        self.publish(self.results, self.report)
        with self.assertRaisesRegex(check.ComparisonError, "numeric value differs"):
            self.compare()

    def test_unrecognized_path_fields_are_compared(self):
        self.report["rows"][0]["scientific_path"] = "one"
        self.published["rows"][0]["scientific_path"] = "two"
        self.publish(self.results, self.report)
        self.publish(self.reference, self.published)
        with self.assertRaisesRegex(check.ComparisonError, "scientific_path"):
            self.compare()

    def test_csv_tampering_is_rejected(self):
        with (self.results / "replay_overview.csv").open("ab") as stream:
            stream.write(b"unexpected\n")
        with self.assertRaisesRegex(check.ComparisonError, "CSV integrity"):
            self.compare()

    def test_report_tampering_is_rejected(self):
        path = self.results / "replay_summary.json"
        report = json.loads(path.read_text())
        report["rows"][0]["authenticated_messages"] = 2
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(check.ComparisonError, "report integrity"):
            self.compare()

    def test_resigned_report_still_requires_consistent_request_fingerprint(self):
        path = self.results / "replay_summary.json"
        report = json.loads(path.read_text())
        report["request_sha256"] = "0" * 64
        report["report_sha256"] = check.digest({k: v for k, v in report.items() if k != "report_sha256"})
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(check.ComparisonError, "request fingerprint"):
            self.compare()

    def test_duplicate_cases_rejected_even_with_recomputed_digests(self):
        self.report["rows"].append(copy.deepcopy(self.report["rows"][0]))
        self.publish(self.results, self.report)
        with self.assertRaisesRegex(check.ComparisonError, "duplicate case matrix"):
            self.compare()

    def test_inconsistent_outcomes_rejected_even_with_recomputed_digests(self):
        self.report["rows"][0]["authenticated_messages"] = 2
        self.publish(self.results, self.report)
        with self.assertRaisesRegex(check.ComparisonError, "conserve messages"):
            self.compare()

    def test_different_preserved_signature_bytes_are_not_treated_as_equivalent(self):
        for evidence in self.published["provenance"]["signed_workloads"].values():
            evidence["groups_sha256"] = "1" * 64
        self.publish(self.reference, self.published)
        with self.assertRaisesRegex(check.ComparisonError, "groups_sha256"):
            self.compare()

    def test_changed_local_input_is_rejected(self):
        (self.root / "trace.json").write_text("changed\n")
        with self.assertRaisesRegex(check.ComparisonError, "Local trace bytes"):
            self.compare()

    def test_changed_or_added_model_source_is_rejected(self):
        (self.root / "src/additional_engine.py").write_text("# New scientific module\n")
        with self.assertRaisesRegex(check.ComparisonError, "source inventory"):
            self.compare()

    def test_changed_local_public_cache_is_rejected(self):
        (self.cache / "groups.jsonl").write_text("changed\n")
        with self.assertRaisesRegex(check.ComparisonError, "local groups.jsonl"):
            self.compare()

    def test_missing_case_is_rejected(self):
        self.report["parameters"]["intervals"].append(5)
        self.publish(self.results, self.report)
        with self.assertRaisesRegex(check.ComparisonError, "incomplete or duplicate"):
            self.compare()

    def test_cli_failure_is_nonzero_and_explained(self):
        stderr = io.StringIO()
        with patch.object(check, "compare_results", side_effect=check.ComparisonError("fixture mismatch")), \
                contextlib.redirect_stderr(stderr):
            self.assertEqual(check.main(["--results-dir", str(self.results), "--reference-dir", str(self.reference)]), 1)
        self.assertIn("FAIL: fixture mismatch", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
