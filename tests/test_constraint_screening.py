import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from src.experiment.constraint_screening import (
    _size_profile_digest, build_size_profile, load_signature_sizes, load_size_profile, screen,
)
from src.processing.build_authentication_groups import build_groups_for_interval


class ConstraintScreeningTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.trace = {
            index + 1: {"trace_id": index + 1, "icao": "ABCDEF", "raw_msg": f"{index + 1:028x}",
                        "timestamp": float(index), "relative_time_s": float(index)}
            for index in range(5)
        }
        self.groups = build_groups_for_interval({"ABCDEF": list(self.trace.values())}, 2)
        self.configs = {
            "fixed": {"enabled": True, "expected_signature_bytes": 14},
            "variable": {"enabled": True, "expected_signature_bytes": None},
        }
        self.entries = []
        for group, length in zip((g for g in self.groups if g["complete"]), [7, 15]):
            message = b"".join(bytes.fromhex(self.trace[tid]["raw_msg"]) for tid in group["trace_ids"])
            self.entries.append({
                "algorithm": "variable", "k": 2, "group_id": group["group_id"],
                "icao": group["icao"], "message_count": 2, "message_length_bytes": len(message),
                "message_sha256": hashlib.sha256(message).hexdigest(),
                "signature_length_bytes": length, "signature_sha256": "a" * 64,
                "verification_success": True, "group_formation_time_s": group["group_formation_time_s"],
            })
        self.write_jsonl("trace.jsonl", self.trace.values())
        self.write_jsonl("authentication_groups_k2.jsonl", self.groups)
        self.write_jsonl("signatures_variable_k2.jsonl", self.entries)
        self.write_config()

    def write_config(self):
        (self.root / "algorithms.json").write_text(json.dumps(self.configs))

    def write_jsonl(self, filename, entries):
        (self.root / filename).write_text("".join(json.dumps(entry) + "\n" for entry in entries))

    def run_screen(self, **options):
        return screen(self.root / "trace.jsonl", self.root, self.root / "algorithms.json",
                      self.root, [2], **options)

    def test_fixed_size_needs_no_signature_records(self):
        sizes, provenance = load_signature_sizes({"SLH": {"expected_signature_bytes": 7856}}, None, [1, 20])
        self.assertEqual(sizes, {("SLH", 1): [7856], ("SLH", 20): [7856]})
        self.assertTrue(all(item["sizing_basis"] == "configured_fixed_size" for item in provenance))

    def test_counts_weight_variable_sizes_and_leave_incomplete_tail_unsigned(self):
        result = self.run_screen(auth_frames_per_second=10)
        rows = {row["algorithm"]: row for row in result["rows"]}
        fixed, variable = rows["fixed"], rows["variable"]
        self.assertEqual(fixed["raw_signature_lower_bound_frames"], 4)
        self.assertEqual(variable["raw_signature_lower_bound_frames"], 4)  # ceil(7/7) + ceil(15/7)
        self.assertEqual(variable["signature_bytes_mean"], 11)
        self.assertEqual(variable["signature_bytes_p50"], 7)
        self.assertEqual(variable["signature_bytes_p95"], 15)
        self.assertEqual(variable["signature_size_distribution"], {"7": 1, "15": 1})
        self.assertEqual(variable["modeled_authentication_frames"], 56)  # ceil(79/3) + ceil(87/3)
        self.assertAlmostEqual(variable["modeled_additional_airtime_load"], 56 * 0.00012 / 4)
        self.assertEqual(variable["unsigned_tail_message_count"], 1)
        self.assertEqual(variable["incomplete_group_count"], 1)
        self.assertEqual(variable["signed_trace_fraction"], 0.8)
        self.assertEqual(variable["auth_events_per_second"], 0.5)
        self.assertTrue(variable["modeled_exceeds_global_authentication_frame_budget"])
        measured = result["provenance"]["signature_sizing"][1]
        self.assertEqual(measured["signature_metadata_sha256"],
                         hashlib.sha256((self.root / "signatures_variable_k2.jsonl").read_bytes()).hexdigest())

    def test_offer_above_capacity_is_not_clamped(self):
        self.configs = {"large": {"expected_signature_bytes": 1000000}}
        self.write_config()
        row = self.run_screen()["rows"][0]
        self.assertGreater(row["raw_signature_lower_bound_total_airtime_load"], 1)
        self.assertTrue(row["raw_signature_lower_bound_exceeds_serial_capacity"])
        self.assertIsNone(row["modeled_exceeds_global_authentication_frame_budget"])

    def test_variable_metadata_must_match_trace_and_complete_ordered_groups(self):
        for mutate in [
            lambda entries: entries.pop(),
            lambda entries: entries.append(copy.deepcopy(entries[0])),
            lambda entries: entries.reverse(),
            lambda entries: entries[0].update(verification_success=False),
            lambda entries: entries[0].update(message_sha256="0" * 64),
            lambda entries: entries[0].update(signature_sha256="bad"),
        ]:
            entries = copy.deepcopy(self.entries)
            mutate(entries)
            self.write_jsonl("signatures_variable_k2.jsonl", entries)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                self.run_screen()

    def test_only_completed_files_are_eligible_and_bad_first_source_is_rejected(self):
        missing_dir = self.root / "missing"
        missing_dir.mkdir()
        (missing_dir / "signatures_variable_k2.jsonl.partial").write_text("{}\n")
        args = dict(trace=self.trace, groups_by_interval={2: self.groups})
        with self.assertRaises(FileNotFoundError):
            load_signature_sizes(self.configs, missing_dir, [2], **args)
        sizes, provenance = load_signature_sizes(self.configs, [missing_dir, self.root], [2], **args)
        self.assertEqual(sizes["variable", 2], [7, 15])
        self.assertEqual(provenance[1]["signature_metadata_path"], str(self.root / "signatures_variable_k2.jsonl"))
        (missing_dir / "signatures_variable_k2.jsonl").write_text("{}\n")
        with self.assertRaises(ValueError):
            load_signature_sizes(self.configs, [missing_dir, self.root], [2], **args)

    def test_trace_coverage_and_positive_duration_are_required(self):
        self.write_jsonl("authentication_groups_k2.jsonl", self.groups[:-1])
        with self.assertRaisesRegex(ValueError, "entire trace"):
            self.run_screen()
        for record in self.trace.values():
            record["relative_time_s"] = 0
        self.write_jsonl("trace.jsonl", self.trace.values())
        with self.assertRaisesRegex(ValueError, "positive duration"):
            self.run_screen()

    def test_trace_with_no_complete_group_has_clear_error(self):
        incomplete = build_groups_for_interval({"ABCDEF": list(self.trace.values())}, 20)
        self.write_jsonl("authentication_groups_k20.jsonl", incomplete)
        with self.assertRaisesRegex(ValueError, "no complete groups"):
            screen(self.root / "trace.jsonl", self.root, self.root / "algorithms.json",
                   None, [20], algorithms=["fixed"])

    def test_invalid_model_settings_are_rejected(self):
        for settings in [dict(payload_bytes=8), dict(fragment_header_bytes=7),
                         dict(object_overhead_bytes=-1), dict(per_message_overhead_bytes=0.5),
                         dict(auth_frames_per_second=0), dict(auth_frames_per_second=float("nan"))]:
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                self.run_screen(**settings)
        with self.assertRaisesRegex(ValueError, "require the trace"):
            load_signature_sizes(self.configs, self.root, [2])

    def export_profile(self):
        sizes, sources = load_signature_sizes(self.configs, self.root, [2],
                                              trace=self.trace, groups_by_interval={2: self.groups})
        evidence = lambda name: {"path": str(self.root / name),
                                 "sha256": hashlib.sha256((self.root / name).read_bytes()).hexdigest()}
        profile = build_size_profile(self.configs, sizes, sources,
                                     trace_evidence=evidence("trace.jsonl"),
                                     group_evidence={"2": evidence("authentication_groups_k2.jsonl")})
        path = self.root / "size_profile.json"
        path.write_text(json.dumps(profile))
        return path, profile

    def test_portable_profile_reuses_weighted_sizes_on_new_trace_without_signatures(self):
        profile_path, profile = self.export_profile()
        original_trace_hash = profile["trace"]["sha256"]
        future_records = [
            {"trace_id": index + 1, "icao": "654321", "raw_msg": f"{100 + index:028x}",
             "timestamp": float(index), "relative_time_s": float(index)} for index in range(7)
        ]
        self.write_jsonl("trace.jsonl", future_records)
        self.write_jsonl("authentication_groups_k2.jsonl", build_groups_for_interval({"654321": future_records}, 2))
        (self.root / "signatures_variable_k2.jsonl").rename(self.root / "unavailable_metadata.jsonl")
        result = self.run_screen(size_profile=profile_path)
        variable = next(row for row in result["rows"] if row["algorithm"] == "variable")
        self.assertEqual(variable["complete_group_count"], 3)
        self.assertEqual(variable["calibration_sample_count"], 2)
        self.assertEqual(variable["signature_bytes_mean"], 11)
        self.assertEqual(variable["raw_signature_lower_bound_frames"], 6)
        self.assertEqual(variable["modeled_authentication_frames"], 84)
        self.assertEqual(variable["sizing_basis"], "calibrated_empirical_distribution")
        self.assertEqual(variable["traffic_count_basis"], "calibration_distribution_expectation")
        source = result["provenance"]["signature_sizing"][1]
        self.assertEqual(source["measured_current_trace_records"], 0)
        self.assertEqual(source["calibration_trace"]["sha256"], original_trace_hash)
        self.assertNotEqual(result["provenance"]["trace"]["sha256"], original_trace_hash)

    def test_calibration_identity_integrity_weights_and_source_are_checked(self):
        path, profile = self.export_profile()
        changed = copy.deepcopy(self.configs)
        changed["variable"]["implementation"] = "different implementation"
        with self.assertRaisesRegex(ValueError, "identity"):
            load_size_profile(path, changed, [2])
        changed["variable"] = self.configs["variable"]
        changed["fixed"]["expected_signature_bytes"] = 99
        with self.assertRaisesRegex(ValueError, "identity"):
            load_size_profile(path, changed, [2])
        with self.assertRaisesRegex(ValueError, "missing calibrated"):
            load_size_profile(path, self.configs, [20])
        invalid = copy.deepcopy(profile)
        invalid["algorithms"]["variable"]["intervals"]["2"]["distribution"][0]["count"] = 3
        path.write_text(json.dumps(invalid))
        with self.assertRaisesRegex(ValueError, "integrity"):
            load_size_profile(path, self.configs, [2])
        for mutate in [
            lambda value: value["algorithms"]["variable"]["intervals"]["2"]["distribution"][0].update(count=0),
            lambda value: value["algorithms"]["variable"]["intervals"]["2"].update(sample_count=99),
            lambda value: value["algorithms"]["variable"]["intervals"]["2"]["source"].update(measured_record_count=99),
            lambda value: value.update(groups={}),
        ]:
            invalid = copy.deepcopy(profile)
            mutate(invalid)
            del invalid["profile_sha256"]
            invalid["profile_sha256"] = _size_profile_digest(invalid)
            path.write_text(json.dumps(invalid))
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                load_size_profile(path, self.configs, [2])


if __name__ == "__main__":
    unittest.main()
