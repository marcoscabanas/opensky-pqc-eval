import contextlib
import copy
import io
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from src.experiment import replay_experiment as experiment
from src.processing.build_authentication_groups import build_groups_for_interval


class ReplayExperimentTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / "outputs"
        self.records = [
            {"trace_id": i + 1, "icao": "ABCDEF", "raw_msg": f"{i + 1:028x}",
             "timestamp": float(i), "relative_time_s": float(i)} for i in range(5)
        ]
        self.write_lines("trace.jsonl", self.records)
        for interval in (1, 2):
            self.write_lines(f"authentication_groups_k{interval}.jsonl",
                             build_groups_for_interval({"ABCDEF": self.records}, interval))
        self.write_json("algorithms.json", {"fixed": {"expected_signature_bytes": 64},
                                            "unavailable_variable": {"expected_signature_bytes": None}})
        entry = {
            "implementation": "test-only assumed service", "equivalence": "assumed", "source_urls": [],
            "limitation": "A fixture assumption, not a hardware measurement.",
            "operations": {operation: {"samples_ms": [1], "sample_kind": "assumed_constant"}
                           for operation in ("sign", "verify")},
        }
        self.write_json("profiles.json", {
            "schema_version": 1,
            "profiles": {"fixture": {"id": "fixture", "label": "Fixture", "platform": "Abstract", 
                                      "kind": "sensitivity_assumption", "algorithms": {"fixed": entry}}},
        })
        self.scenarios = {"seeds": [1, 7], "scenarios": [
            {"name": "iid", "sender_profile": "fixture", "receiver_profile": "fixture",
             "parameters": {"max_auth_age_s": 5, "loss": {"kind": "iid", "probability": 0}}},
        ]}
        self.write_json("scenarios.json", self.scenarios)
        self.stdout = contextlib.redirect_stdout(io.StringIO())
        self.stdout.__enter__()
        self.addCleanup(self.stdout.__exit__, None, None, None)
        source_patch = patch.object(experiment, "_source_evidence", return_value={"model.py": "version1"})
        source_patch.start()
        self.addCleanup(source_patch.stop)

    def write_json(self, filename, value):
        (self.root / filename).write_text(json.dumps(value))

    def write_lines(self, filename, entries):
        (self.root / filename).write_text("".join(json.dumps(entry) + "\n" for entry in entries))

    def args(self, mode="all", *extra):
        return experiment.parse_args([
            "--trace", str(self.root / "trace.jsonl"), "--groups-dir", str(self.root),
            "--algorithms-config", str(self.root / "algorithms.json"),
            "--hardware-profiles", str(self.root / "profiles.json"),
            "--scenarios", str(self.root / "scenarios.json"),
            "--output-dir", str(self.output), "--intervals", "1", "2", "--algorithm", "fixed",
            "--mode", mode, *extra,
        ])[1]

    @staticmethod
    def fake_simulate(trace, algorithm, interval, sizes, sender, receiver, scenario, seed):
        return {"summary": {"observed_message_count": len(trace), "test_seed": seed,
                            "modeled_authentication_success_fraction": 0.5},
                "events": [{"kind": "fixture", "time_s": 1}],
                "outcomes": {"modeled_authenticated": 1, "expired_transmitting": 1},
                "assumptions": ["Fixture simulator assumption."], "parameters": scenario}

    def test_screening_subset_needs_no_signature_or_hardware_files(self):
        args = self.args("screening")
        args.hardware_profiles = self.root / "not_present.json"
        args.scenarios = self.root / "not_present_either.json"
        with patch.object(experiment, "_simulate", side_effect=AssertionError("must not simulate")):
            experiment.run(args)
        report = json.loads((self.output / "constraint_screening_summary.json").read_text())
        self.assertEqual(len(report["rows"]), 2)
        self.assertTrue(all(row["algorithm"] == "fixed" for row in report["rows"]))
        self.assertTrue(all(item["measured_record_count"] == 0 for item in report["provenance"]["signature_sizing"]))
        self.assertFalse((self.output / "replay_summary.json").exists())

    def test_multiple_seed_replay_preserves_profile_labels_and_reuses_intact_cache(self):
        with patch.object(experiment, "_simulate", side_effect=self.fake_simulate) as simulate:
            experiment.run(self.args())
        self.assertEqual(simulate.call_count, 4)
        report = json.loads((self.output / "replay_summary.json").read_text())
        self.assertEqual(len(report["rows"]), 4)
        self.assertEqual([row["seed"] for row in report["rows"]], [1, 7, 1, 7])
        self.assertEqual(report["rows"][0]["sender_timing_equivalence"], "assumed")
        self.assertEqual(report["rows"][0]["receiver_profile_kind"], "sensitivity_assumption")
        self.assertEqual(report["rows"][0]["signature_sizing_basis"], "configured_fixed_size")
        self.assertEqual(report["rows"][0]["group_outcomes"]["expired_transmitting"], 1)
        self.assertEqual(report["assumptions"].count("Fixture simulator assumption."), 1)
        self.assertEqual(report["simulator_parameters"]["iid"]["max_auth_age_s"], 5)
        self.assertEqual(len(report["events"]), 4)
        before = {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in self.output.iterdir()}
        with patch.object(experiment, "_simulate", side_effect=AssertionError("cached replay must not run")):
            experiment.run(self.args("all", "--validate-only"))
        self.assertEqual(before, {path.name: (path.read_bytes(), path.stat().st_mtime_ns) for path in self.output.iterdir()})

    def test_changed_sources_or_seed_require_explicit_replacement(self):
        with patch.object(experiment, "_simulate", side_effect=self.fake_simulate):
            experiment.run(self.args("replay"))
            with self.assertRaisesRegex(ValueError, "stale"):
                experiment.run(self.args("replay", "--seeds", "23"))
            with patch.object(experiment, "_source_evidence", return_value={"model.py": "version2"}):
                with self.assertRaisesRegex(ValueError, "stale"):
                    experiment.run(self.args("replay", "--validate-only"))
                experiment.run(self.args("replay", "--force"))
        report = json.loads((self.output / "replay_summary.json").read_text())
        self.assertEqual(report["provenance"]["source_files_sha256"], {"model.py": "version2"})

    def test_report_and_csv_tampering_are_detected(self):
        experiment.run(self.args("screening"))
        summary, csv_path = [self.output / name for name in experiment.OUTPUT_NAMES["screening"]]
        report = json.loads(summary.read_text())
        fingerprint = report["input_fingerprint"]
        self.assertTrue(experiment.outputs_match(summary, csv_path, fingerprint))
        original_csv = csv_path.read_bytes()
        csv_path.write_bytes(original_csv + b"corruption\n")
        self.assertFalse(experiment.outputs_match(summary, csv_path, fingerprint))
        csv_path.write_bytes(original_csv)
        report["rows"][0]["signature_bytes_mean"] = 1
        summary.write_text(json.dumps(report))
        self.assertFalse(experiment.outputs_match(summary, csv_path, fingerprint))
        # Even a recomputed report digest cannot hide report/CSV disagreement.
        del report["report_sha256"]
        report["report_sha256"] = experiment._digest(report)
        summary.write_text(json.dumps(report))
        self.assertFalse(experiment.outputs_match(summary, csv_path, fingerprint))

    def test_simulator_failure_never_publishes_partial_replay(self):
        with patch.object(experiment, "_simulate", side_effect=[self.fake_simulate(self.records, "fixed", 1, [64], {}, {}, {}, 1),
                                                                 RuntimeError("max_events exceeded")]):
            with self.assertRaisesRegex(RuntimeError, "max_events"):
                experiment.run(self.args("replay"))
        self.assertFalse((self.output / "replay_summary.json").exists())
        self.assertFalse((self.output / "replay_overview.csv").exists())
        with patch.object(experiment, "_simulate", return_value={"summary": {"complete": False}}):
            with self.assertRaisesRegex(ValueError, "incomplete"):
                experiment.run(self.args("replay"))
        self.assertFalse((self.output / "replay_summary.json").exists())

    def test_scenario_selection_seed_validation_and_profile_missing_operations(self):
        for seeds in [[], [1, 1], [True], [-1], [1.5]]:
            with self.subTest(seeds=seeds), self.assertRaises(ValueError):
                experiment.load_scenarios(self.root / "scenarios.json", seeds=seeds)
        with self.assertRaisesRegex(ValueError, "Selected scenarios"):
            experiment.load_scenarios(self.root / "scenarios.json", selected=["absent"])
        invalid = copy.deepcopy(self.scenarios)
        invalid["scenarios"][0]["parameters"]["typo_delay"] = 1
        self.write_json("invalid_scenarios.json", invalid)
        with self.assertRaisesRegex(ValueError, "unknown"):
            experiment.load_scenarios(self.root / "invalid_scenarios.json")
        profiles = json.loads((self.root / "profiles.json").read_text())
        del profiles["profiles"]["fixture"]["algorithms"]["fixed"]["operations"]["sign"]
        self.write_json("profiles.json", profiles)
        with self.assertRaisesRegex(ValueError, "Hardware timing unavailable"):
            experiment.run(self.args("replay"))
        self.assertFalse(self.output.exists())

    def test_validate_only_missing_artifacts_does_not_write(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            experiment.run(self.args("screening", "--validate-only"))
        self.assertFalse(self.output.exists())

    def test_portable_profile_export_import_and_missing_artifact_protection(self):
        experiment.run(self.args("screening"))
        profile_path = self.output / "signature_size_profile.json"
        profile = json.loads(profile_path.read_text())
        report = json.loads((self.output / "constraint_screening_summary.json").read_text())
        self.assertEqual(profile, report["signature_size_profile"])
        self.assertEqual(profile["kind"], "portable_signature_size_calibration")
        future = self.args("replay", "--size-profile", str(profile_path))
        future.output_dir = self.root / "future_results"
        with patch.object(experiment, "_simulate", side_effect=self.fake_simulate):
            experiment.run(future)
        replay = json.loads((future.output_dir / "replay_summary.json").read_text())
        self.assertEqual(replay["signature_size_profile"], profile)
        self.assertIn("signature_size_profile", replay["provenance"])
        profile_path.rename(self.output / "preserved_profile.json")
        with self.assertRaisesRegex(ValueError, "size profile is missing"):
            experiment.run(self.args("screening", "--validate-only"))
        with self.assertRaisesRegex(ValueError, "use --force"):
            experiment.run(self.args("screening"))
        experiment.run(self.args("screening", "--force"))
        self.assertEqual(json.loads(profile_path.read_text()), profile)

    def test_delayed_model_rows_preserve_nested_metrics_and_finite_horizon(self):
        delayed = copy.deepcopy(self.scenarios)
        delayed["scenarios"][0]["parameters"] = {
            "replay_model": "delayed_authentication", "followup_s": 60,
            "coverage_thresholds_s": [1, 5, 10, 30, 60], "max_batch_wait_s": None,
            "auth_frames_per_second": 100, "sender_queue_limit": None,
            "transmission_queue_limit": None, "receiver_queue_limit": None,
            "receiver_workers": 1, "fragment_copies": 1, "receive_jitter_ms": 0,
            "loss": {"kind": "iid", "probability": 0.01}, "max_events": 10000,
            "record_events": False, "channel_mode": "independent", "background_frames_per_second": 0,
        }
        self.write_json("scenarios.json", delayed)

        def delayed_result(*args):
            result = self.fake_simulate(*args)
            result["summary"].update(
                authentication_coverage_by_delay_s={"1": 0.1, "5": 0.25, "60": 0.4},
                pending_at_horizon={"signing_queue": 7, "transmission_queue": 3},
            )
            result["outcomes"] = {"modeled_authenticated": 2, "pending_at_horizon": 10}
            result["assumptions"] = ["Authentication does not expire; pending work is censored at the observation horizon."]
            return result

        with patch.object(experiment, "_simulate", side_effect=delayed_result):
            experiment.run(self.args("replay"))
        report = json.loads((self.output / "replay_summary.json").read_text())
        for row in report["rows"]:
            self.assertEqual(row["replay_model"], "delayed_authentication")
            self.assertEqual(row["authentication_coverage_by_delay_s"], {"1": 0.1, "5": 0.25, "60": 0.4})
            self.assertEqual(row["pending_at_horizon"]["signing_queue"], 7)
            self.assertEqual(row["group_outcomes"]["pending_at_horizon"], 10)
            self.assertNotIn("max_auth_age_s", row)
        self.assertNotIn("max_auth_age_s", report["simulator_parameters"]["iid"])
        self.assertEqual(report["simulator_parameters"]["iid"]["followup_s"], 60)
        self.assertTrue(any("does not expire" in item for item in report["assumptions"]))
        self.assertFalse(any("configured 100" in item for item in report["assumptions"]))
        summary_path, csv_path = [self.output / name for name in experiment.OUTPUT_NAMES["replay"]]
        self.assertTrue(experiment.outputs_match(summary_path, csv_path, report["input_fingerprint"]))

    def test_model_selector_dispatches_without_mutating_configuration(self):
        import sys

        for selected, module_name in ((None, "src.experiment.replay_simulator"),
                                      ("delayed_authentication", "src.experiment.delayed_replay")):
            module = types.ModuleType(module_name)
            module.simulate = Mock(return_value={"summary": {"marker": selected}})
            parameters = {"followup_s": 60} if selected else {"max_auth_age_s": 5}
            if selected:
                parameters["replay_model"] = selected
            before = copy.deepcopy(parameters)
            with patch.dict(sys.modules, {module_name: module}):
                result = experiment._simulate({}, "fixed", 2, [64], {}, {}, parameters, seed=19)
            self.assertEqual(result["summary"]["marker"], selected)
            self.assertEqual(parameters, before)
            self.assertNotIn("replay_model", module.simulate.call_args.args[6])
            self.assertEqual(module.simulate.call_args.args[7], 19)
        with self.assertRaisesRegex(ValueError, "Unknown replay_model"):
            experiment._simulate({}, "fixed", 2, [64], {}, {}, {"replay_model": "typo"})

    def test_observed_channel_end_to_end_and_changed_input_invalidates_cache(self):
        name = "ECDSA-P256"
        for record in self.records:
            record["raw_msg"] = "8DABCDEF" + f"{record['trace_id']:020X}"
        self.write_lines("trace.jsonl", self.records)
        for interval in (1, 2):
            self.write_lines(f"authentication_groups_k{interval}.jsonl",
                             build_groups_for_interval({"ABCDEF": self.records}, interval))
        self.write_json("algorithms.json", {name: {"expected_signature_bytes": 64}})
        profiles = json.loads((self.root / "profiles.json").read_text())
        entries = profiles["profiles"]["fixture"]["algorithms"]
        entries[name] = entries.pop("fixed")
        self.write_json("profiles.json", profiles)
        self.scenarios["scenarios"][0]["parameters"] = {
            "replay_model": "delayed_authentication", "followup_s": 2,
            "channel_mode": "destructive_overlap", "auth_frames_per_second": 8000,
            "loss": {"kind": "iid", "probability": 0},
        }
        self.write_json("scenarios.json", self.scenarios)
        channel = [{"schema_version": 1, "kind": "channel_trace", "time_origin_timestamp": 0,
                    "coverage_start_s": 0, "coverage_end_s": 7}]
        channel += [{"event_id": f"target-{r['trace_id']}", "target_trace_id": r["trace_id"],
                     "relative_time_s": r["relative_time_s"], "duration_s": 0.000120}
                    for r in self.records]
        channel += [{"event_id": "short-reply", "relative_time_s": 0, "duration_s": 0.000072},
                    {"event_id": "followup-traffic", "relative_time_s": 5, "duration_s": 0.000120}]
        self.write_lines("channel.jsonl", channel)
        args = self.args("replay", "--channel-trace", str(self.root / "channel.jsonl"))
        args.algorithm = [name]
        experiment.run(args)
        report = json.loads((self.output / "replay_summary.json").read_text())
        self.assertEqual(report["provenance"]["channel_trace"]["sha256"],
                         experiment._file_evidence(self.root / "channel.jsonl")["sha256"])
        for row in report["rows"]:
            self.assertEqual(row["baseline_original_received_messages"], 4)
            self.assertEqual(row["additional_original_loss_messages"], 0)
            self.assertEqual(row["channel_summary"]["observed_frames"], 2)
            self.assertAlmostEqual(row["baseline_offered_airtime_load"], (5 * 0.000120 + 0.000072) / 4)
            self.assertEqual(row["observed_channel_trace"]["target_frames"], 5)
        args.validate_only = True
        experiment.run(args)
        channel[-1]["duration_s"] *= 2
        self.write_lines("channel.jsonl", channel)
        with self.assertRaisesRegex(ValueError, "stale"):
            experiment.run(args)

    def test_observed_channel_cannot_silently_use_legacy_or_screening(self):
        for mode, error in (("screening", "screening"), ("replay", "delayed_authentication")):
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, error):
                experiment.run(self.args(mode, "--channel-trace", str(self.root / "missing.jsonl")))

    def test_scenario_fields_are_specific_to_selected_model(self):
        for model, forbidden in (("delayed_authentication", "max_auth_age_s"),
                                 ("deadline_authentication", "followup_s")):
            invalid = copy.deepcopy(self.scenarios)
            invalid["scenarios"][0]["parameters"] = {"replay_model": model, forbidden: 5}
            self.write_json("invalid_scenarios.json", invalid)
            with self.subTest(model=model), self.assertRaisesRegex(ValueError, "unknown scenario parameters"):
                experiment.load_scenarios(self.root / "invalid_scenarios.json")

    def test_calibrated_weighted_profile_is_preserved_when_reexported(self):
        config = {"fixed": {"expected_signature_bytes": None}}
        self.write_json("algorithms.json", config)
        lengths = {("fixed", 1): [64, 64, 65], ("fixed", 2): [64, 65]}
        sources = [{"algorithm": algorithm, "interval_k": interval,
                    "sizing_basis": "measured_complete_signature_metadata",
                    "measured_record_count": len(values),
                    "signature_metadata_path": f"historical/signatures_k{interval}.jsonl",
                    "signature_metadata_sha256": "1" * 64}
                   for (algorithm, interval), values in lengths.items()]
        profile = experiment.build_size_profile(
            config, lengths, sources,
            trace_evidence={"path": "historical/trace.jsonl", "sha256": "2" * 64},
            group_evidence={str(k): {"path": f"historical/groups_k{k}.jsonl", "sha256": "3" * 64}
                            for k in (1, 2)},
        )
        self.write_json("original_size_profile.json", profile)
        source_path = self.root / "original_size_profile.json"
        before = source_path.read_bytes(), source_path.stat().st_mtime_ns
        args = self.args("all", "--size-profile", str(source_path))
        with patch.object(experiment, "_simulate", side_effect=self.fake_simulate):
            experiment.run(args)
        self.assertEqual((source_path.read_bytes(), source_path.stat().st_mtime_ns), before)
        self.assertEqual(json.loads((self.output / "signature_size_profile.json").read_text()), profile)
        for name in ("replay_summary.json", "constraint_screening_summary.json"):
            report = json.loads((self.output / name).read_text())
            self.assertEqual(report["signature_size_profile"], profile)
            self.assertEqual(report["signature_size_profile"]["algorithms"]["fixed"]["intervals"]["1"]["distribution"],
                             [{"signature_bytes": 64, "count": 2}, {"signature_bytes": 65, "count": 1}])
            self.assertTrue(all(item["measured_current_trace_records"] == 0
                                for item in report["provenance"]["signature_sizing"]))


class ScientificSourceEvidenceTest(unittest.TestCase):
    def test_real_signature_models_require_signed_entry_point(self):
        for model in ("signed_detached", "signed_before_send"):
            with self.subTest(model=model), self.assertRaisesRegex(ValueError, "signed_experiment"):
                experiment._simulate({}, "ECDSA-P256", 1, [64], {}, {}, {"replay_model": model})

    def test_plot_and_pipeline_changes_do_not_invalidate_scientific_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "src"
            experiment_dir = source / "experiment"
            experiment_dir.mkdir(parents=True)
            harness = experiment_dir / "replay_experiment.py"
            model = experiment_dir / "delayed_replay.py"
            plot = experiment_dir / "plot_delayed_replay.py"
            pipeline = source / "pipeline.py"
            for path in (harness, model, plot, pipeline):
                path.write_text("version1\n")
            with patch.object(experiment, "__file__", str(harness)):
                first = experiment._source_evidence()
                self.assertEqual(set(first), {"experiment/replay_experiment.py", "experiment/delayed_replay.py"})
                plot.write_text("new figure labels\n")
                pipeline.write_text("new progress display\n")
                self.assertEqual(first, experiment._source_evidence())
                model.write_text("new scientific model\n")
                self.assertNotEqual(first, experiment._source_evidence())

    def test_supplied_configs_preserve_old_results_and_select_delayed_model(self):
        root = Path(__file__).resolve().parents[1]
        scenario_path = root / "config" / "delayed_replay_scenarios.json"
        scenarios, seeds = experiment.load_scenarios(scenario_path)
        self.assertEqual(seeds, [1])
        self.assertEqual(len(scenarios), 4)
        self.assertEqual({item["parameters"]["channel_mode"] for item in scenarios},
                         {"independent", "destructive_overlap"})
        self.assertEqual({item["parameters"]["max_batch_wait_s"] for item in scenarios}, {None, 1})
        for scenario in scenarios:
            parameters = scenario["parameters"]
            self.assertEqual(parameters["replay_model"], "delayed_authentication")
            self.assertEqual(parameters["followup_s"], 60)
            self.assertNotIn("max_auth_age_s", parameters)
            self.assertTrue(all(parameters[name] is None
                                for name in ("sender_queue_limit", "transmission_queue_limit", "receiver_queue_limit")))
        for dataset in ("development", "full"):
            config = json.loads((root / "config" / f"{dataset}.json").read_text())
            self.assertEqual(config["signature_size_sources"], [])
            if dataset == "development":
                self.assertEqual(config["replay_results_dir"], "results/runs/development/replay")
                self.assertEqual(config["replay_scenarios"], "config/delayed_replay_scenarios.json")
                self.assertEqual(config["signature_size_profile"], "data/calibration/signature_sizes.json")
            else:
                self.assertEqual(config["replay_results_dir"], "results/runs/full/window_a/replay")
                self.assertEqual(config["replay_scenarios"], "config/signed_replay_scenarios.json")
                self.assertEqual(config["replay_engine"], "signed_detached")
                self.assertNotIn("signature_size_profile", config)


if __name__ == "__main__":
    unittest.main()
