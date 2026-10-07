import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.experiment import signed_experiment as experiment
from src.experiment.replay_experiment import load_scenarios


class SignedConfigurationTests(unittest.TestCase):
    def test_full_matrix_declares_deterministic_detached_rate_sensitivity(self):
        scenarios, seeds = load_scenarios(Path("config/signed_replay_scenarios.json"))
        self.assertEqual(seeds, [1])
        self.assertEqual(len(scenarios), 6)
        self.assertEqual({(s["parameters"]["channel_mode"], s["parameters"]["auth_frames_per_second"])
                          for s in scenarios},
                         {(mode, rate) for mode in ("independent", "destructive_overlap")
                          for rate in (10, 50, 100)})
        for scenario in scenarios:
            parameters = scenario["parameters"]
            self.assertEqual(parameters["replay_model"], "signed_detached")
            self.assertIsNone(parameters["max_batch_wait_s"])
            self.assertEqual(parameters["followup_s"], 600)
            self.assertEqual(parameters["loss"], {"kind": "iid", "probability": 0})
            self.assertEqual(parameters["receive_jitter_ms"], 0)
            self.assertEqual(parameters["background_frames_per_second"], 0)
            self.assertEqual(parameters["receiver_workers"], 1)
        _, args = experiment.parse_args(["--trace", "trace", "--channel-trace", "channel",
                                         "--output-dir", "output"])
        self.assertEqual(args.scenarios, Path("config/signed_replay_scenarios.json"))
        self.assertEqual(args.intervals, [1, 5, 10, 20])
        self.assertEqual(4 * len(args.intervals) * len(scenarios) * len(seeds), 96)


@unittest.skipUnless(importlib.util.find_spec("cryptography"), "Actual ECDSA requires cryptography")
class SignedExperimentTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.records = [{"trace_id": i + 1, "icao": "ABCDEF", "raw_msg": "8DABCDEF" + f"{i+1:020X}",
                         "timestamp": 1000 + i * 0.1, "relative_time_s": i * 0.1} for i in range(4)]
        self.write_lines("trace.jsonl", self.records)
        self.channel = [{"schema_version": 1, "kind": "channel_trace", "time_origin_timestamp": 1000,
                         "coverage_start_s": 0, "coverage_end_s": 4}]
        self.channel += [{"event_id": r["trace_id"], "relative_time_s": r["relative_time_s"],
                          "duration_s": 0.000120, "target_trace_id": r["trace_id"]} for r in self.records]
        self.channel += [{"event_id": "non-target", "relative_time_s": 0.03, "duration_s": 0.000064}]
        self.write_lines("channel.jsonl", self.channel)
        self.parameters = {"replay_model": "signed_before_send", "followup_s": 2,
                           "max_batch_wait_s": 0.5, "channel_mode": "independent",
                           "auth_frames_per_second": 8000, "loss": {"kind": "iid", "probability": 0},
                           "record_events": True}
        self.scenarios = {"seeds": [1, 2], "scenarios": [
            {"name": "fixture", "sender_profile": "fixture", "receiver_profile": "fixture",
             "parameters": self.parameters}]}
        self.write_json("scenarios.json", self.scenarios)
        self.write_json("profiles.json", {"schema_version": 1, "profiles": {"fixture": {
            "id": "fixture", "label": "Fixture", "platform": "Abstract test", "kind": "sensitivity_assumption",
            "algorithms": {"ECDSA-P256": {"implementation": "SECP256R1", "equivalence": "assumed",
                "limitation": "Test-only service inputs, not an aircraft benchmark", "source_urls": [],
                "operations": {op: {"samples_ms": [1], "sample_kind": "assumed_constant"}
                               for op in ("sign", "verify")}}}}}})
        redirect = contextlib.redirect_stdout(io.StringIO())
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def write_lines(self, name, rows):
        (self.root / name).write_text("".join(json.dumps(row) + "\n" for row in rows))

    def write_json(self, name, document):
        (self.root / name).write_text(json.dumps(document))

    def args(self, *extra):
        return experiment.parse_args([
            "--trace", str(self.root / "trace.jsonl"), "--channel-trace", str(self.root / "channel.jsonl"),
            "--hardware-profiles", str(self.root / "profiles.json"), "--scenarios", str(self.root / "scenarios.json"),
            "--output-dir", str(self.root / "results"), "--workloads-dir", str(self.root / "workloads"),
            "--algorithm", "ECDSA-P256", "--intervals", "1", "2", *extra])[1]

    def test_actual_workloads_replay_then_validate_without_signing_or_replaying(self):
        experiment.run(self.args())
        report_path = self.root / "results/replay_summary.json"
        report = json.loads(report_path.read_text())
        self.assertEqual(len(report["rows"]), 4)
        self.assertEqual(len(report["provenance"]["signed_workloads"]), 2)
        for row in report["rows"]:
            self.assertEqual(row["replay_model"], "signed_before_send")
            self.assertEqual(row["authenticated_messages"], 4)
            self.assertGreater(row["ordinary_transmission_delay_ms_p50"], 0)
            self.assertEqual(row["signature_sizing_basis"], "actual_signed_context_and_raw_messages")
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.rglob("*") if p.is_file()}
        with patch("src.experiment.signed_workload._build", side_effect=AssertionError("must not sign")), \
                patch("src.experiment.signed_replay.simulate", side_effect=AssertionError("must not replay")):
            experiment.run(self.args("--validate-only"))
        self.assertEqual(before, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in self.root.rglob("*") if p.is_file()})

    def test_detached_replay_is_labeled_and_seed_independent_with_cached_signatures(self):
        self.parameters.update(replay_model="signed_detached", max_batch_wait_s=None)
        self.write_json("scenarios.json", self.scenarios)
        experiment.run(self.args("--replay-model", "signed_detached"))
        report = json.loads((self.root / "results/replay_summary.json").read_text())
        self.assertEqual(report["parameters"]["replay_model"], "signed_detached")
        self.assertEqual(report["simulator_parameters"]["fixture"]["replay_model"], "signed_detached")
        self.assertEqual(len(report["provenance"]["signed_workloads"]), 2)
        def without_seed_metadata(value):
            if isinstance(value, dict):
                return {key: without_seed_metadata(item) for key, item in value.items() if key != "seed"}
            if isinstance(value, list):
                return [without_seed_metadata(item) for item in value]
            return value
        for interval in (1, 2):
            pair = [row for row in report["rows"] if row["interval_k"] == interval]
            self.assertEqual([row["seed"] for row in pair], [1, 2])
            self.assertEqual(pair[0]["authenticated_messages"], 4)
            self.assertEqual(pair[0]["replay_model"], "signed_detached")
            self.assertEqual(without_seed_metadata(pair[0]), without_seed_metadata(pair[1]))
        with patch("src.experiment.signed_workload._build", side_effect=AssertionError("must not sign")), \
                patch("src.experiment.signed_replay.simulate", side_effect=AssertionError("must not replay")):
            experiment.run(self.args("--validate-only", "--replay-model", "signed_detached"))

    def test_model_switch_invalidates_saved_replay(self):
        experiment.run(self.args())
        self.parameters["replay_model"] = "signed_detached"
        self.write_json("scenarios.json", self.scenarios)
        with self.assertRaisesRegex(ValueError, "stale"):
            experiment.run(self.args("--validate-only"))

    def test_requested_model_mismatch_fails_before_signing(self):
        with patch("src.experiment.signed_workload.build_or_load_workload") as build:
            with self.assertRaisesRegex(ValueError, "does not match"):
                experiment.run(self.args("--replay-model", "signed_detached"))
        build.assert_not_called()

    def test_mixed_models_require_separate_reports(self):
        self.scenarios["scenarios"].append({**self.scenarios["scenarios"][0], "name": "detached",
                                             "parameters": {**self.parameters, "replay_model": "signed_detached"}})
        self.write_json("scenarios.json", self.scenarios)
        with self.assertRaisesRegex(ValueError, "mix"):
            experiment.run(self.args())

    def test_missing_followup_fails_before_generating_signatures(self):
        self.channel[0]["coverage_end_s"] = 0.4
        self.write_lines("channel.jsonl", self.channel)
        with patch("src.experiment.signed_workload.build_or_load_workload") as build:
            with self.assertRaisesRegex(ValueError, "follow-up"):
                experiment.run(self.args())
        build.assert_not_called()
        self.assertFalse((self.root / "workloads").exists())

    def test_missing_outputs_validation_does_not_create_workloads(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            experiment.run(self.args("--validate-only"))
        self.assertFalse((self.root / "workloads").exists())

    def test_changed_channel_requires_new_run(self):
        experiment.run(self.args())
        self.channel[-1]["duration_s"] = 0.000120
        self.write_lines("channel.jsonl", self.channel)
        with self.assertRaisesRegex(ValueError, "stale"):
            experiment.run(self.args("--validate-only"))

    def test_signature_cache_mutation_invalidates_saved_replay(self):
        experiment.run(self.args())
        group_path = next((self.root / "workloads").rglob("groups.jsonl"))
        group_path.write_bytes(group_path.read_bytes() + b"corruption\n")
        with self.assertRaises(ValueError):
            experiment.run(self.args("--validate-only"))

    def test_resealed_wrong_identity_and_missing_cases_are_rejected(self):
        experiment.run(self.args())
        path = self.root / "results/replay_summary.json"
        csv = self.root / "results/replay_overview.csv"
        original = json.loads(path.read_text())
        for mutation, message in (("identity", "identity"), ("missing_case", "matrix"),
                                  ("wrong_model", "model"), ("wrong_stage_count", "stages")):
            changed = json.loads(json.dumps(original))
            changed.pop("report_sha256")
            changed.pop("csv_sha256")
            if mutation == "identity":
                changed["input_fingerprint"] = "0" * 64
            elif mutation == "missing_case":
                changed["rows"].pop()
            elif mutation == "wrong_model":
                changed["rows"][0]["replay_model"] = "signed_detached"
            else:
                changed["rows"][0]["complete_authentication_object_groups"] = 0
            experiment._publish(path, csv, changed)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, message):
                experiment.run(self.args("--validate-only"))

    def test_legacy_scenario_cannot_be_mislabeled_as_actual_signing(self):
        self.parameters["replay_model"] = "delayed_authentication"
        self.write_json("scenarios.json", self.scenarios)
        with self.assertRaisesRegex(ValueError, "signed_before_send"):
            experiment.run(self.args())


if __name__ == "__main__":
    unittest.main()
