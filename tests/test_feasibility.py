import argparse
import copy
import contextlib
import hashlib
import io
import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.experiment.operational_feasibility import (
    analyze_algorithms,
    build_provenance,
    compute_channel_utilization,
    compute_fragmentation,
    main,
    outputs_match,
    sha256_file,
    signature_by_algorithm,
)
from src.processing.build_authentication_groups import build_groups_for_interval


def fixture(interval=2, signature_bytes=14, record_count=5):
    records = [
        {"trace_id": index + 1, "icao": "ABCDEF", "raw_msg": f"{index + 1:028x}",
         "timestamp": float(index), "relative_time_s": float(index)}
        for index in range(record_count)
    ]
    trace = {record["trace_id"]: record for record in records}
    groups = build_groups_for_interval({"ABCDEF": records}, interval)
    entries = []
    for group in groups:
        if not group["complete"]:
            continue
        message = b"".join(bytes.fromhex(trace[tid]["raw_msg"]) for tid in group["trace_ids"])
        entries.append({
            "algorithm": "test", "k": interval, "group_id": group["group_id"],
            "icao": group["icao"], "message_count": interval,
            "message_length_bytes": len(message), "message_sha256": hashlib.sha256(message).hexdigest(),
            "signature_length_bytes": signature_bytes, "verification_success": True,
            "group_formation_time_s": group["group_formation_time_s"],
        })
    return trace, {interval: {g["group_id"]: g for g in groups}}, {interval: {"test": entries}}


def analyze(data, interval=2, **options):
    return analyze_algorithms(*data, ["test"], [interval], **options)[0][0]


class FragmentationTest(unittest.TestCase):
    def test_repetition_adds_whole_frames_and_overhead_reduces_payload(self):
        repeated = compute_fragmentation(64, 7, 2)
        self.assertEqual(repeated["required_fragments"], 10)
        self.assertEqual(repeated["transmitted_fragments"], 20)
        self.assertEqual(repeated["effective_payload_bytes"], 7)
        overhead = compute_fragmentation(64, 7, 1, 2)
        self.assertEqual(overhead["effective_payload_bytes"], 5)
        self.assertEqual(overhead["required_fragments"], 13)

    def test_invalid_physical_parameters_are_rejected(self):
        for arguments in [(64, 14), (0, 7), (64, 0), (64, 7, 1.5), (64, 7, 0), (64, 7, 1, 7)]:
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                compute_fragmentation(*arguments)
        with self.assertRaises(ValueError):
            compute_channel_utilization(10, 0, 0.00012)


class FeasibilityTest(unittest.TestCase):
    def test_known_airtime_loss_formation_latency_and_incomplete_tail(self):
        row = analyze(fixture(), loss_probability=0.1, redundancy_factor=2)
        self.assertAlmostEqual(row["frame_airtime_us"], 120)
        self.assertEqual(row["total_fragment_transmissions"], 8)
        self.assertEqual(row["auth_events_per_second"], 0.5)
        self.assertAlmostEqual(row["baseline_airtime_load"], 5 * 0.00012 / 4)
        self.assertAlmostEqual(row["additional_airtime_load"], 8 * 0.00012 / 4)
        expected_probability = (1 - 0.1 ** 2) ** 2 * 0.9 ** 2
        self.assertAlmostEqual(row["authentication_success_probability_mean"], expected_probability)
        self.assertAlmostEqual(row["expected_authenticated_trace_fraction"], 0.8 * expected_probability)
        self.assertEqual(row["unsigned_message_count"], 1)
        self.assertEqual(row["incomplete_group_count"], 1)
        self.assertAlmostEqual(row["auth_latency_ms_max"], 1000.48)
        self.assertAlmostEqual(row["auth_latency_ms_mean"], 500.48)
        self.assertIsNone(row["detached_auth_feasible"])

    def test_variable_signature_lengths_use_actual_counts(self):
        data = fixture(signature_bytes=7)
        data[2][2]["test"][1]["signature_length_bytes"] = 15
        row = analyze(data, loss_probability=0.1)
        self.assertEqual(row["required_fragments"], 3)
        self.assertEqual(row["total_fragment_transmissions"], 4)
        self.assertAlmostEqual(row["signature_recovery_probability_mean"], (0.9 + 0.9 ** 3) / 2)

    def test_delays_and_budget_decisions_are_explicit(self):
        options = dict(max_channel_occupancy=0.5, max_auth_latency_ms=1100,
                       min_auth_success_probability=0.5, receiver_verification_ms=3,
                       sender_signing_ms=5, inter_frame_gap_us=10)
        row = analyze(fixture(), **options)
        self.assertTrue(row["detached_auth_feasible"])
        self.assertAlmostEqual(row["auth_latency_ms_max"], 1008.25)
        options["max_auth_latency_ms"] = 1000
        self.assertFalse(analyze(fixture(), **options)["detached_auth_feasible"])
        options["max_auth_latency_ms"] = None
        self.assertIsNone(analyze(fixture(), **options)["detached_auth_feasible"])

    def test_loss_endpoints_and_repetition_do_not_rescue_original_messages(self):
        data = fixture()
        self.assertEqual(analyze(data, loss_probability=0)["authentication_success_probability_mean"], 1)
        self.assertEqual(analyze(data, loss_probability=1)["authentication_success_probability_mean"], 0)
        repeated = analyze(data, loss_probability=0.1, redundancy_factor=3)
        self.assertLess(repeated["authentication_success_probability_mean"], 0.9 ** 2)

    def test_offered_load_is_not_clamped_to_one(self):
        row = analyze(fixture(signature_bytes=1000000))
        self.assertGreater(row["total_offered_airtime_load"], 1)
        self.assertTrue(row["exceeds_serial_channel_capacity"])

    def test_missing_duplicate_failed_and_stale_signatures_are_rejected(self):
        for mutation in [
            lambda entries: entries.pop(),
            lambda entries: entries.append(copy.deepcopy(entries[0])),
            lambda entries: entries[0].update(verification_success=False),
            lambda entries: entries[0].update(message_sha256="0" * 64),
            lambda entries: entries[0].update(signature_length_bytes=0),
            lambda entries: entries[0].update(icao="OTHER"),
        ]:
            data = fixture()
            mutation(data[2][2]["test"])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                analyze(data)
        data = fixture()
        del data[2][2]["test"]
        with self.assertRaisesRegex(ValueError, "Missing signatures"):
            analyze(data)

    def test_unknown_and_missing_trace_coverage_are_rejected(self):
        data = fixture()
        del data[1][2][3]  # Incomplete tails must still be reported.
        with self.assertRaisesRegex(ValueError, "entire trace"):
            analyze(data)
        data = fixture()
        data[1][2][1]["trace_ids"][0] = 100
        with self.assertRaisesRegex(ValueError, "unknown or repeated"):
            analyze(data)

    def test_invalid_scenario_values_and_zero_duration_are_rejected(self):
        for options in [dict(loss_probability=-0.1), dict(loss_probability=1.1),
                        dict(bit_rate_bps=0), dict(receiver_verification_ms=math.nan),
                        dict(background_occupancy=1.1), dict(frame_bits=113),
                        dict(bit_rate_bps=2000000), dict(preamble_us=0)]:
            with self.subTest(options=options), self.assertRaises(ValueError):
                analyze(fixture(), **options)
        data = fixture()
        for record in data[0].values():
            record["relative_time_s"] = 0
        with self.assertRaisesRegex(ValueError, "positive duration"):
            analyze(data)


class ProvenanceTest(unittest.TestCase):
    def test_missing_required_algorithm_file_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                signature_by_algorithm(Path(directory), [1], ["absent"])

    def test_fingerprint_tracks_content_and_parameters(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = argparse.Namespace(trace=root / "trace.jsonl", config=root / "config.json",
                                      groups_dir=root, signatures_dir=root, intervals=[2])
            paths = [args.trace, args.config, root / "authentication_groups_k2.jsonl",
                     root / "signatures_test_k2.jsonl"]
            for path in paths:
                path.write_text("{}\n")
            _, original = build_provenance(args, ["test"], {"loss_probability": 0.01})
            _, changed_parameter = build_provenance(args, ["test"], {"loss_probability": 0.02})
            self.assertNotEqual(original, changed_parameter)
            paths[-1].write_text('{"changed":true}\n')
            _, changed_input = build_provenance(args, ["test"], {"loss_probability": 0.01})
            self.assertNotEqual(original, changed_input)

    def test_cached_outputs_require_intact_csv_and_matching_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            summary, csv_path = root / "summary.json", root / "overview.csv"
            csv_path.write_text("algorithm,value\ntest,1\n")
            expected = {"input_fingerprint": "abc", "rows": [{"value": 1}], "summaries": {2: {}, 10: {}}}
            summary.write_text(json.dumps({**expected, "csv_sha256": sha256_file(csv_path)}))
            self.assertTrue(outputs_match(summary, csv_path, expected))
            self.assertFalse(outputs_match(summary, csv_path, {**expected, "input_fingerprint": "def"}))
            csv_path.write_text("changed\n")
            self.assertFalse(outputs_match(summary, csv_path, expected))

    def test_cli_saved_report_validates_across_multiple_interval_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace_path, config_path = root / "trace.jsonl", root / "algorithms.json"
            config_path.write_text(json.dumps({"test": {"enabled": True}}))
            for interval in [2, 10]:
                trace, groups, signatures = fixture(interval=interval, record_count=21)
                trace_path.write_text("".join(json.dumps(record) + "\n" for record in trace.values()))
                (root / f"authentication_groups_k{interval}.jsonl").write_text(
                    "".join(json.dumps(group) + "\n" for group in groups[interval].values()))
                (root / f"signatures_test_k{interval}.jsonl").write_text(
                    "".join(json.dumps(entry) + "\n" for entry in signatures[interval]["test"]))
            arguments = ["operational_feasibility", "--trace", str(trace_path), "--config", str(config_path),
                         "--groups-dir", str(root), "--signatures-dir", str(root), "--output-dir", str(root),
                         "--intervals", "2", "10"]
            with patch("sys.argv", arguments), contextlib.redirect_stdout(io.StringIO()):
                main()
            paths = [root / "operational_feasibility_summary.json", root / "feasibility_overview.csv"]
            before = [(path.read_bytes(), path.stat().st_mtime_ns) for path in paths]
            with patch("sys.argv", arguments + ["--validate-only"]), contextlib.redirect_stdout(io.StringIO()) as output:
                main()
            self.assertIn("VALIDATED: 2 feasibility rows", output.getvalue())
            self.assertEqual(before, [(path.read_bytes(), path.stat().st_mtime_ns) for path in paths])


if __name__ == "__main__":
    unittest.main()
