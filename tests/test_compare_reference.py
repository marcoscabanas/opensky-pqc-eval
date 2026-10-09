"""Independent checks of reference-table comparison and archive integrity."""

import contextlib
import csv
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from scripts._support.compare_reference import compare_tables, main, read_table


def table_bytes(rows, columns=None):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=columns or list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode()


def row(seed=1):
    return {"algorithm": "Falcon-512", "interval_k": 5, "scenario": "capture",
            "seed": seed, "authenticated_messages": 1_000_000_000,
            "delay_ms": "0.125", "target_window_declared": "True",
            "target_window_boundary": "[start,end)",
            "threshold_coverage": '{"nested": [{"count": 42, "fraction": 0.125}]}',
            "signature_workload_evidence": '{"groups_sha256":"abc", "signature_count": 50}'}


class ReferenceComparisonTests(unittest.TestCase):
    def compare(self, reference, current):
        return compare_tables("daytime", read_table(table_bytes(reference), "reference"),
                              read_table(table_bytes(current), "local"))

    def test_row_column_json_key_order_and_numeric_spelling_do_not_matter(self):
        reference = [row(1), row(2)]
        changed = [dict(item) for item in reversed(reference)]
        for item in changed:
            item["delay_ms"] = "1.25e-1"
            item["authenticated_messages"] = "1000000000.0"
            item["threshold_coverage"] = '{ "nested": [ { "fraction": 0.12500000000001, "count": 42.0 } ] }'
            item["signature_workload_evidence"] = '{"signature_count": 50, "groups_sha256": "abc"}'
        reference_table = read_table(table_bytes(reference), "reference")
        current_table = read_table(table_bytes(changed, list(reversed(changed[0]))), "local")
        result = compare_tables("daytime", reference_table, current_table)
        self.assertTrue(result.matches)
        self.assertEqual(result.matched_cases, 2)

    def test_counts_are_exact_even_when_relative_float_tolerance_would_allow_change(self):
        changed = row()
        changed["authenticated_messages"] += 1
        result = self.compare([row()], [changed])
        self.assertFalse(result.matches)
        self.assertEqual(result.numeric_differences, 1)

    def test_real_numeric_change_is_detected_in_nested_json(self):
        changed = row()
        changed["threshold_coverage"] = '{"nested": [{"count": 43, "fraction": 0.125}]}'
        result = self.compare([row()], [changed])
        self.assertEqual(result.numeric_differences, 1)
        self.assertIn("threshold_coverage.nested[0].count", result.examples[0])

    def test_fresh_signature_provenance_is_distinct_from_numeric_difference(self):
        changed = row()
        changed["signature_workload_evidence"] = '{"groups_sha256":"fresh", "signature_count": 50}'
        result = self.compare([row()], [changed])
        self.assertFalse(result.matches)
        self.assertEqual(result.numeric_differences, 0)
        self.assertEqual(result.metadata_differences, 1)

    def test_missing_extra_duplicate_and_invalid_case_identities_are_not_silently_ignored(self):
        result = self.compare([row(1), row(2)], [row(1), row(3)])
        self.assertEqual((result.missing_cases, result.extra_cases), (1, 1))
        with self.assertRaisesRegex(ValueError, "duplicate case"):
            read_table(table_bytes([row(), row()]), "local")
        for value in ("true", "-1", "1.2"):
            with self.subTest(seed=value), self.assertRaisesRegex(ValueError, "invalid seed"):
                read_table(table_bytes([{**row(), "seed": value}]), "local")

    def test_schema_and_nonfinite_or_duplicate_json_values_are_rejected(self):
        changed = row()
        changed.pop("delay_ms")
        with self.assertRaisesRegex(ValueError, "schema differs"):
            self.compare([row()], [changed])
        for field, value in (("delay_ms", "NaN"), ("delay_ms", "-Infinity"),
                             ("threshold_coverage", '{"fraction": NaN}'),
                             ("threshold_coverage", '{"count": 1, "count": 2}')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                read_table(table_bytes([{**row(), field: value}]), "local")


class ReferenceArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.artifacts = self.root / "download"
        self.artifacts.mkdir()
        self.results = self.root / "results"
        self.member = "results/daytime/03_replay/replay_overview.csv"
        self.contents = table_bytes([row()])
        self.local = self.root / self.member
        self.local.parent.mkdir(parents=True)
        self.local.write_bytes(self.contents)
        self.archive = self.artifacts / "metadata-and-results.zip"
        with zipfile.ZipFile(self.archive, "w") as bundle:
            bundle.writestr(self.member, self.contents)
        self.manifest_path = self.artifacts / "artifact_manifest.json"
        self.manifest = {"files": [{"filename": self.archive.name,
                                    "bytes": self.archive.stat().st_size,
                                    "sha256": hashlib.sha256(self.archive.read_bytes()).hexdigest(),
                                    "members": [{"path": self.member, "bytes": len(self.contents),
                                                 "sha256": hashlib.sha256(self.contents).hexdigest()}]}]}
        self.save_manifest()

    def save_manifest(self):
        self.manifest_path.write_text(json.dumps(self.manifest))

    def invoke(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = main(["--artifacts-dir", str(self.artifacts), "--results-dir", str(self.results),
                         "--window", "daytime"])
        return code, output.getvalue()

    def test_command_compares_without_rewriting_or_extracting_files(self):
        before = {str(p.relative_to(self.root)): p.read_bytes()
                  for p in self.root.rglob("*") if p.is_file()}
        code, output = self.invoke()
        self.assertEqual(code, 0, output)
        self.assertIn("1/1 reference cases match", output)
        after = {str(p.relative_to(self.root)): p.read_bytes()
                 for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_command_returns_difference_status_for_changed_local_metric(self):
        self.local.write_bytes(table_bytes([{**row(), "delay_ms": 5}]))
        code, output = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn("Numeric differences: 1", output)

    def test_archive_corruption_is_rejected_before_reference_is_used(self):
        with self.archive.open("ab") as stream:
            stream.write(b"corruption")
        code, output = self.invoke()
        self.assertEqual(code, 2)
        self.assertIn("checksum or byte-count mismatch", output)

    def test_member_hash_is_checked_even_when_archive_hash_matches(self):
        self.manifest["files"][0]["members"][0]["sha256"] = "0" * 64
        self.save_manifest()
        code, output = self.invoke()
        self.assertEqual(code, 2)
        self.assertIn(self.member + ": checksum", output)

    def test_malformed_manifest_structures_return_input_error_without_traceback(self):
        archive_record = self.manifest["files"][0]
        malformed = [None, [], {"files": None}, {"files": [None]},
                     {"files": [{**archive_record, "members": [None]}]}]
        for manifest in malformed:
            with self.subTest(manifest=manifest):
                self.manifest_path.write_text(json.dumps(manifest))
                code, output = self.invoke()
                self.assertEqual(code, 2)
                self.assertIn("Comparison could not complete", output)
                self.assertNotIn("Traceback", output)

    def test_duplicate_archive_members_cannot_select_an_ambiguous_reference(self):
        with self.archive.open("rb") as stream:
            old = stream.read()
        with zipfile.ZipFile(self.archive, "w") as bundle:
            bundle.writestr(self.member, self.contents)
            bundle.writestr("duplicate", "first")
            # Suppress zipfile's expected warning, while requiring our own error.
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                bundle.writestr("duplicate", "second")
        self.assertNotEqual(self.archive.read_bytes(), old)
        self.manifest["files"][0].update(bytes=self.archive.stat().st_size,
                                       sha256=hashlib.sha256(self.archive.read_bytes()).hexdigest())
        self.save_manifest()
        code, output = self.invoke()
        self.assertEqual(code, 2)
        self.assertIn("Duplicate archive member", output)


if __name__ == "__main__":
    unittest.main()
