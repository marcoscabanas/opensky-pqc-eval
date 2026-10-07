import copy
import json
import math
import tempfile
import unittest
from pathlib import Path

from src.experiment.hardware_profiles import load_profiles, timing_samples_ms


PROFILE_PATH = Path(__file__).resolve().parents[1] / "config" / "hardware_profiles.json"


class HardwareProfilesTest(unittest.TestCase):
    def setUp(self):
        self.document = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))

    def load_document(self, document):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profiles.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            return load_profiles(path)

    def test_reference_converts_cycles_using_measured_clock(self):
        profile = load_profiles(PROFILE_PATH)["embedded_reference"]
        self.assertAlmostEqual(timing_samples_ms(profile, "ML-DSA-44", "sign")[0], 3943121 / 24000)
        self.assertAlmostEqual(timing_samples_ms(profile, "SLH-DSA-SHA2-128s", "sign")[0], 7657558168 / 24000)
        self.assertEqual(timing_samples_ms(profile, "ECDSA-P256", "verify"), [15.3])
        self.assertNotEqual(timing_samples_ms(profile, "ML-DSA-44", "keygen"), timing_samples_ms(profile, "ML-DSA-44", "sign"))

    def test_reference_proxies_and_measurement_scope_remain_visible(self):
        profiles = load_profiles(PROFILE_PATH)
        profile = profiles["embedded_reference"]
        self.assertEqual(profile["kind"], "composite_proxy")
        for name in ("FN-DSA-512", "SLH-DSA-SHA2-128s"):
            entry = profile["algorithms"][name]
            self.assertEqual(entry["equivalence"], "lineage_proxy")
            self.assertTrue(entry["limitation"])
            self.assertTrue(entry["source_commit"])
            self.assertEqual(entry["message_length_bytes"], 59)
        self.assertEqual(set(profiles["pqm4_mldsa44_reference"]["algorithms"]), {"ML-DSA-44"})

    def test_missing_operations_and_algorithms_never_default_to_zero(self):
        profiles = load_profiles(PROFILE_PATH)
        for profile_id, algorithm, operation in [
            ("assumed_receiver_1ms", "ECDSA-P256", "sign"),
            ("pqm4_mldsa44_reference", "FN-DSA-512", "verify"),
            ("embedded_reference", "ML-DSA-44", "unknown"),
        ]:
            with self.subTest(profile_id=profile_id, algorithm=algorithm, operation=operation), self.assertRaises(ValueError):
                timing_samples_ms(profiles[profile_id], algorithm, operation)

    def test_summary_statistics_are_not_fabricated_samples(self):
        profile = load_profiles(PROFILE_PATH)["embedded_reference"]
        timing = profile["algorithms"]["ML-DSA-44"]["operations"]["sign"]
        self.assertEqual(timing["execution_count"], 1000)
        self.assertEqual(len(timing_samples_ms(profile, "ML-DSA-44", "sign")), 1)
        timing["samples_ms"].append(timing["cycles_max"] / 24000)
        with self.assertRaisesRegex(ValueError, "empirical distribution"):
            timing_samples_ms(profile, "ML-DSA-44", "sign")

    def test_empirical_samples_remain_available_without_global_sampling(self):
        profile = copy.deepcopy(self.document["profiles"]["embedded_reference"])
        profile["algorithms"]["ML-DSA-44"]["operations"]["sign"] = {
            "sample_kind": "empirical", "samples_ms": [2.0, 3.5, 12.0],
        }
        samples = timing_samples_ms(profile, "ML-DSA-44", "sign")
        self.assertEqual(samples, [2.0, 3.5, 12.0])
        samples[0] = 999
        self.assertEqual(timing_samples_ms(profile, "ML-DSA-44", "sign"), [2.0, 3.5, 12.0])

    def test_invalid_service_times_are_rejected(self):
        for value in (0, -1, True, "1", None, math.inf, math.nan):
            document = copy.deepcopy(self.document)
            document["profiles"]["assumed_receiver_1ms"]["algorithms"]["ML-DSA-44"]["operations"]["verify"]["samples_ms"] = [value]
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.load_document(document)

    def test_unit_mismatch_and_inconsistent_statistics_are_rejected(self):
        for mutation in (
            lambda timing: timing.update(samples_ms=[timing["samples_ms"][0] * 1000]),
            lambda timing: timing.update(cycles_min=timing["cycles_mean"] + 1),
            lambda timing: timing.update(clock_mhz=0),
            lambda timing: timing.update(execution_count=True),
        ):
            document = copy.deepcopy(self.document)
            timing = document["profiles"]["embedded_reference"]["algorithms"]["ML-DSA-44"]["operations"]["sign"]
            mutation(timing)
            with self.assertRaises(ValueError):
                self.load_document(document)

    def test_missing_provenance_and_assumption_mislabel_are_rejected(self):
        document = copy.deepcopy(self.document)
        document["profiles"]["embedded_reference"]["algorithms"]["ML-DSA-44"]["source_urls"] = []
        with self.assertRaisesRegex(ValueError, "source"):
            self.load_document(document)
        document = copy.deepcopy(self.document)
        document["profiles"]["assumed_receiver_1ms"]["algorithms"]["ML-DSA-44"]["operations"]["verify"]["sample_kind"] = "published_mean"
        with self.assertRaisesRegex(ValueError, "assumed"):
            self.load_document(document)

    def test_duplicate_json_keys_cannot_silently_replace_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "profiles.json"
            path.write_text('{"schema_version": 1, "schema_version": 2}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                load_profiles(path)


if __name__ == "__main__":
    unittest.main()
