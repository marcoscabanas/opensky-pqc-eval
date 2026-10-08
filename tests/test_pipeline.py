import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src import pipeline
from src.pipeline import stage_outputs
from src.processing.build_authentication_groups import build_groups_for_interval


class StageOutputsTest(unittest.TestCase):
    def test_stage_outputs_cover_all_enabled_algorithms(self):
        config = {
            "analysis_results_dir": "results/development/analysis",
            "signature_results_dir": "results/development/signatures",
            "authentication_intervals": [1, 5],
            "algorithms_config": "config/algorithms.json",
        }

        outputs = stage_outputs("signatures", config)
        names = {p.name for p in outputs}

        self.assertIn("signature_experiment_summary.json", names)
        self.assertIn("signatures_ECDSA-P256_k1.jsonl", names)
        self.assertIn("signatures_ML-DSA-44_k1.jsonl", names)
        self.assertIn("signatures_FN-DSA-512_k1.jsonl", names)
        self.assertIn("signatures_SLH-DSA-SHA2-128s_k1.jsonl", names)

    def test_screening_outputs_include_portable_calibration(self):
        config = {"replay_results_dir": "results/development/replay"}
        self.assertEqual({path.name for path in stage_outputs("screening", config)}, {
            "constraint_screening_summary.json", "constraint_screening_overview.csv",
            "signature_size_profile.json",
        })
        self.assertEqual({path.name for path in stage_outputs("replay", config)}, {
            "replay_summary.json", "replay_overview.csv",
        })


class ExecutionStagesTest(unittest.TestCase):
    def test_modern_runs_are_isolated_from_active_legacy_recovery(self):
        legacy = pipeline.load_config("config/development_recovery.json")
        self.assertEqual(pipeline.pipeline_lock_path(legacy),
                         pipeline.REPO_ROOT / "results/.pipeline.lock")
        locks = []
        for name in ("development", "full_window_a", "full_window_b"):
            config = pipeline.load_config(f"config/{name}.json")
            lock = pipeline.pipeline_lock_path(config)
            self.assertTrue(lock.is_relative_to(pipeline.REPO_ROOT / "results/runs"))
            locks.append(lock)
        self.assertEqual(len(locks), len(set(locks)))
        self.assertEqual(pipeline.pipeline_lock_path(pipeline.load_config("config/full.json")), locks[1])

    def test_run_scope_rejects_outputs_outside_its_lock(self):
        config = pipeline.load_config("config/full_window_a.json")
        config["signed_workloads_dir"] = str(pipeline.REPO_ROOT / "results/development/recovery")
        with self.assertRaisesRegex(ValueError, "signed_workloads_dir"):
            pipeline.pipeline_lock_path(config)
        for path in ("results", "results/runs", "data/development", "results/runs/../development"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "dedicated subdirectory"):
                pipeline.pipeline_lock_path({"run_directory": path})

    def test_absolute_paths_and_symlinks_cannot_escape_run_scope(self):
        root = pipeline.REPO_ROOT / "results/runs/demo"
        with self.assertRaisesRegex(ValueError, "dedicated subdirectory"):
            pipeline.pipeline_lock_path({"run_directory": str(root / "../../development/recovery")})
        with self.assertRaisesRegex(ValueError, "signature_results_dir"):
            pipeline.pipeline_lock_path({"run_directory": str(root),
                                         "signature_results_dir": str(root / "../other/signatures")})
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            runs = repository / "results/runs"
            runs.mkdir(parents=True)
            external = repository / "legacy"
            external.mkdir()
            (runs / "alias").symlink_to(external, target_is_directory=True)
            with patch.object(pipeline, "REPO_ROOT", repository), self.assertRaisesRegex(ValueError, "dedicated subdirectory"):
                pipeline.pipeline_lock_path({"run_directory": str(runs / "alias")})

    def test_legacy_and_recovery_configs_preserve_existing_execution_order(self):
        expected = ["capture", "aircraft", "duplicates", "preprocess", "groups", "signatures", "feasibility"]
        for config in ({}, pipeline.load_config("config/development_recovery.json")):
            self.assertEqual(pipeline.select_stages(config), expected)
            self.assertEqual(pipeline.select_stages(config, from_stage="signatures"), ["signatures", "feasibility"])
            self.assertEqual(pipeline.select_stages(config, validate_only=True), ["signatures", "feasibility"])

    def test_operational_configs_skip_exhaustive_signing_unless_explicit(self):
        expected = ["capture", "aircraft", "duplicates", "preprocess", "groups", "screening", "replay"]
        for filename in ("config/development.json",):
            config = pipeline.load_config(filename)
            self.assertEqual(pipeline.select_stages(config), expected)
            self.assertEqual(pipeline.select_stages(config, from_stage="screening"), ["screening", "replay"])
            self.assertEqual(pipeline.select_stages(config, stage="signatures"), ["signatures"])
            self.assertEqual(pipeline.select_stages(config, validate_only=True), ["screening", "replay"])
            with self.assertRaisesRegex(ValueError, "not in execution_stages"):
                pipeline.select_stages(config, from_stage="signatures")

    def test_full_study_uses_actual_signed_replay(self):
        config = pipeline.load_config("config/full.json")
        self.assertEqual(pipeline.select_stages(config),
                         ["capture", "aircraft", "duplicates", "preprocess", "replay"])
        self.assertEqual(pipeline.select_stages(config, validate_only=True), ["replay"])
        self.assertEqual(config["replay_engine"], "signed_detached")
        self.assertNotIn("signature_size_profile", config)

    def test_full_windows_have_isolated_inputs_and_outputs(self):
        first = pipeline.load_config("config/full_window_a.json")
        second = pipeline.load_config("config/full_window_b.json")
        alias = pipeline.load_config("config/full.json")
        self.assertEqual({key: value for key, value in alias.items() if key != "config_path"},
                         {key: value for key, value in first.items() if key != "config_path"})
        self.assertEqual(first["replay_scenarios"], second["replay_scenarios"])
        for key in ("raw_capture", "channel_trace", "processed_trace", "analysis_results_dir",
                    "signed_workloads_dir", "replay_results_dir"):
            self.assertNotEqual(first[key], second[key])
            self.assertIn("/window_a/", first[key])
            self.assertIn("/window_b/", second[key])

    def test_signed_pipeline_dispatch_asserts_configured_model(self):
        for model in ("signed_detached", "signed_before_send"):
            config = pipeline.load_config("config/full.json")
            config["replay_engine"] = model
            with self.subTest(model=model), patch.object(pipeline, "run_script") as run, \
                    patch.object(pipeline, "validate_preprocessing_provenance") as validate:
                pipeline.run_replay_experiment(config, force=False, mode="replay")
            validate.assert_called_once_with(config)
            args = run.call_args.args
            self.assertEqual(args[0], "src.experiment.signed_experiment")
            self.assertEqual(args[args.index("--replay-model") + 1], model)
            self.assertNotIn("--groups-dir", args)

    def test_invalid_stage_lists_and_conflicting_selections_are_rejected(self):
        for stages in ([], ["replay", "replay"], ["unknown"], "replay", [1]):
            with self.subTest(stages=stages), self.assertRaises(ValueError):
                pipeline.select_stages({"execution_stages": stages})
        with self.assertRaises(ValueError):
            pipeline.select_stages({}, stage="signatures", from_stage="signatures")
        with self.assertRaises(ValueError):
            pipeline.select_stages({}, stage="capture", validate_only=True)

    def test_new_paths_are_resolved_and_size_source_priority_is_preserved(self):
        config = pipeline.load_config("config/development.json")
        for key in ("hardware_profiles", "replay_scenarios", "replay_results_dir"):
            self.assertTrue(Path(config[key]).is_absolute())
        self.assertEqual(config["signature_size_sources"], [])
        self.assertEqual(config["signature_size_profile"],
                         str(pipeline.repo_path("data/calibration/signature_sizes.json")))
        full = pipeline.load_config("config/full.json")
        self.assertEqual(full["signature_size_sources"], [])
        self.assertTrue(Path(full["signed_workloads_dir"]).is_absolute())
        self.assertNotIn("signature_size_profile", full)
        with self.assertRaises(ValueError):
            pipeline.resolve_cfg_paths({"signature_size_sources": "not-a-list"})


class PreprocessingProvenanceTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.raw = self.root / "raw.jsonl"
        self.trace = self.root / "trace.jsonl"
        self.raw.write_text('{"df":17,"fixture":"raw"}\n')
        self.trace.write_text('{"trace_id":1,"fixture":"processed"}\n')
        self.manifest_path = self.root / "preprocessing_manifest.json"
        self.manifest = {
            "input_file": "/previous/checkout/raw.jsonl", "output_file": "/previous/checkout/trace.jsonl",
            "input_sha256": hashlib.sha256(self.raw.read_bytes()).hexdigest(),
            "output_sha256": hashlib.sha256(self.trace.read_bytes()).hexdigest(),
        }
        self.manifest_path.write_text(json.dumps(self.manifest))
        self.config = pipeline.load_config("config/demo.json")
        self.config.update(run_directory=str(self.root), raw_capture=str(self.raw),
                           processed_trace=str(self.trace), analysis_results_dir=str(self.root))

    def test_relocated_identical_artifacts_are_validated_without_rewriting(self):
        paths = (self.raw, self.trace, self.manifest_path)
        before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in paths}
        pipeline.validate_preprocessing_provenance(self.config)
        with patch.object(pipeline, "run_script") as run:
            pipeline.run_preprocess(self.config, False)
        run.assert_not_called()
        self.assertEqual(before, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in paths})

    def test_changed_raw_capture_rejects_preprocessing_reuse(self):
        self.raw.write_text("changed raw capture\n")
        before = self.trace.read_bytes(), self.manifest_path.read_bytes()
        with patch.object(pipeline, "run_script") as run:
            with self.assertRaisesRegex(ValueError, "raw_capture bytes.*manifest"):
                pipeline.run_preprocess(self.config, False)
        run.assert_not_called()
        self.assertEqual(before, (self.trace.read_bytes(), self.manifest_path.read_bytes()))

    def test_changed_processed_trace_is_rejected(self):
        self.trace.write_text("changed processed trace\n")
        with self.assertRaisesRegex(ValueError, "processed_trace bytes.*manifest"):
            pipeline.validate_preprocessing_provenance(self.config)

    def test_missing_or_changed_manifest_fails_without_repair(self):
        for content in (None, "not JSON", "[]", "{}", json.dumps({**self.manifest, "input_sha256": "0" * 64})):
            with self.subTest(content=content):
                if content is None:
                    self.manifest_path.unlink()
                else:
                    self.manifest_path.write_text(content)
                with self.assertRaisesRegex(ValueError, "Raw-to-trace provenance.*fresh run directory"):
                    pipeline.validate_preprocessing_provenance(self.config)

    def test_replay_screening_and_validate_only_require_raw_to_trace_integrity(self):
        for mode in ("replay", "screening"):
            for validate_only in (False, True):
                for force in (False, True):
                    with self.subTest(mode=mode, validate_only=validate_only, force=force):
                        self.config["validate_only"] = validate_only
                        self.raw.write_text("changed capture\n")
                        with patch.object(pipeline, "run_script") as run:
                            with self.assertRaisesRegex(ValueError, "raw_capture bytes"):
                                pipeline.run_replay_experiment(self.config, force, mode)
                        run.assert_not_called()

    def test_valid_provenance_allows_native_validation_dispatch(self):
        self.config["validate_only"] = True
        with patch.object(pipeline, "run_script") as run:
            pipeline.run_replay_experiment(self.config, False, "replay")
        run.assert_called_once()
        self.assertIn("--validate-only", run.call_args.args)
        self.assertEqual(run.call_args.args[0], "src.experiment.signed_experiment")

    def test_legacy_configuration_keeps_original_behavior(self):
        legacy = {key: value for key, value in self.config.items() if key != "run_directory"}
        self.raw.unlink()
        self.manifest_path.write_text("legacy manifest fixture\n")
        pipeline.validate_preprocessing_provenance(legacy)
        with patch.object(pipeline, "run_script") as run:
            pipeline.run_preprocess(legacy, False)
        run.assert_not_called()


class PipelineIntegrationTest(unittest.TestCase):
    def test_screening_and_replay_real_cli_then_read_only_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = [
                {"trace_id": index + 1, "icao": "ABCDEF", "raw_msg": "8DABCDEF" + f"{index + 1:020X}",
                 "timestamp": float(index), "relative_time_s": float(index)}
                for index in range(3)
            ]
            trace = root / "trace.jsonl"
            trace.write_text("".join(json.dumps(record) + "\n" for record in records))
            groups = build_groups_for_interval({"ABCDEF": records}, 1)
            (root / "authentication_groups_k1.jsonl").write_text(
                "".join(json.dumps(group) + "\n" for group in groups))
            algorithms = root / "algorithms.json"
            algorithms.write_text(json.dumps({"ECDSA-P256": {"expected_signature_bytes": 64}}))
            profiles = root / "profiles.json"
            profiles.write_text(json.dumps({
                "schema_version": 1, "profiles": {"fixture": {
                    "id": "fixture", "label": "Fixture", "platform": "Abstract",
                    "kind": "sensitivity_assumption", "algorithms": {"ECDSA-P256": {
                        "implementation": "test-only assumed service", "equivalence": "assumed",
                        "source_urls": [], "limitation": "A test assumption, not a hardware measurement.",
                        "operations": {operation: {"samples_ms": [0.1], "sample_kind": "assumed_constant"}
                                       for operation in ("sign", "verify")},
                    }},
                }},
            }))
            scenarios = root / "scenarios.json"
            scenarios.write_text(json.dumps({"seeds": [1], "scenarios": [{
                "name": "no_loss", "sender_profile": "fixture", "receiver_profile": "fixture",
                "parameters": {"max_auth_age_s": 5, "auth_frames_per_second": 8000,
                               "loss": {"kind": "iid", "probability": 0}},
            }]}))
            config = {
                "processed_trace": str(trace), "authentication_groups_dir": str(root),
                "authentication_intervals": [1], "algorithms_config": str(algorithms),
                "hardware_profiles": str(profiles), "replay_scenarios": str(scenarios),
                "replay_results_dir": str(root / "replay"),
                "signature_results_dir": str(root / "unused_signatures"), "signature_size_sources": [],
            }

            def run_real_cli(module, *args):
                completed = subprocess.run(
                    [sys.executable, "-m", module, *args], cwd=pipeline.REPO_ROOT,
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

            with patch.object(pipeline, "run_script", side_effect=run_real_cli):
                for stage in ("screening", "replay"):
                    pipeline.run_stage(stage, config, force=False)
                outputs = stage_outputs("screening", config) + stage_outputs("replay", config)
                before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in outputs}
                config["validate_only"] = True
                for stage in ("screening", "replay"):
                    pipeline.run_stage(stage, config, force=False)
                self.assertEqual(before, {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in outputs})
            report = json.loads((root / "replay" / "replay_summary.json").read_text())
            self.assertEqual(report["rows"][0]["modeled_authenticated_messages"], 3)
            self.assertFalse((root / "unused_signatures").exists())

    def test_imported_size_profile_dispatch_needs_no_original_signature_directory(self):
        config = pipeline.load_config("config/development.json")
        config["validate_only"] = True
        with patch.object(pipeline, "run_script") as run_script, \
                patch.object(pipeline, "validate_preprocessing_provenance") as validate:
            pipeline.run_replay_experiment(config, False, "screening")
        validate.assert_called_once_with(config)
        args = run_script.call_args.args
        self.assertEqual(args[0], "src.experiment.replay_experiment")
        self.assertNotIn("--signatures-dir", args)
        self.assertIn("--validate-only", args)
        self.assertEqual(args[args.index("--size-profile") + 1], config["signature_size_profile"])
        self.assertEqual(args[args.index("--mode") + 1], "screening")

    def test_full_pipeline_passes_observed_channel_to_replay_only(self):
        config = pipeline.load_config("config/full.json")
        self.assertTrue(config["channel_trace"].endswith("data/full/window_a/raw/channel_trace.jsonl"))
        for mode in ("screening", "replay"):
            with patch.object(pipeline, "run_script") as run_script, \
                    patch.object(pipeline, "validate_preprocessing_provenance") as validate:
                pipeline.run_replay_experiment(config, False, mode)
            validate.assert_called_once_with(config)
            args = run_script.call_args.args
            if mode == "replay":
                self.assertEqual(args[0], "src.experiment.signed_experiment")
                self.assertEqual(args[args.index("--channel-trace") + 1], config["channel_trace"])
                self.assertEqual(args[args.index("--workloads-dir") + 1], config["signed_workloads_dir"])
                self.assertNotIn("--size-profile", args)
            else:
                self.assertNotIn("--channel-trace", args)

    def test_missing_calibration_is_reported_before_launching_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace, algorithms, groups = [root / name for name in ("trace", "algorithms", "authentication_groups_k1.jsonl")]
            for path in (trace, algorithms, groups):
                path.touch()
            missing = root / "missing_size_profile.json"
            config = {"processed_trace": str(trace), "algorithms_config": str(algorithms),
                      "authentication_groups_dir": str(root), "authentication_intervals": [1],
                      "signature_size_profile": str(missing)}
            with patch.object(pipeline, "run_script") as run_script:
                with self.assertRaisesRegex(FileNotFoundError, "missing_size_profile"):
                    pipeline.run_stage("screening", config, False)
            run_script.assert_not_called()

    def test_analysis_stages_accept_pipeline_cli_and_write_summaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "capture.jsonl"
            records = [
                {"df": 17, "icao": "400A0E", "raw_msg": "8D400A0E990DAC85B0044021C766",
                 "timestamp": 10.0, "typecode": 19},
                {"df": 17, "icao": "40621D", "raw_msg": "8D40621D58C382D690C8AC2863A7",
                 "timestamp": 10.5, "typecode": 11},
                {"df": 17, "icao": "400A0E", "raw_msg": "8D400A0E990DAC85B0044021C766",
                 "timestamp": 11.0, "typecode": 19},
                {"df": 17, "icao": "40621D", "raw_msg": "8D40621D58C382D690C8AC2863A7",
                 "timestamp": 12.0, "typecode": 11},
                {"df": 11, "icao": "400A0E", "raw_msg": "5D400A0E000000",
                 "timestamp": 12.5},
            ]
            raw.write_text("".join(json.dumps(record) + "\n" for record in records))
            config = {"raw_capture": str(raw), "analysis_results_dir": str(root / "analysis")}

            def run_real_cli(module, *args):
                # Execute the real parsers; only capture their verbose console output.
                completed = subprocess.run(
                    [sys.executable, "-m", module, *args], cwd=pipeline.REPO_ROOT,
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

            with patch.object(pipeline, "run_script", side_effect=run_real_cli):
                for stage in ("capture", "aircraft", "duplicates"):
                    pipeline.run_stage(stage, config, force=False)

            aircraft = json.loads((root / "analysis" / "aircraft_analysis.json").read_text())
            duplicates = json.loads((root / "analysis" / "duplicate_analysis.json").read_text())
            self.assertEqual(aircraft["total_records"], 5)
            self.assertEqual(aircraft["df17_records"], 4)
            self.assertEqual(aircraft["unique_aircraft"], 2)
            self.assertEqual(aircraft["typecode_distribution"], {"11": 2, "19": 2})
            self.assertEqual(duplicates["usable_df17_records"], 4)
            self.assertEqual(duplicates["unique_icao_raw_message_pairs"], 2)
            self.assertEqual(duplicates["repeated_observations"], 2)
            self.assertEqual(duplicates["multiplicity_distribution"], {"2": 2})
            self.assertEqual(duplicates["repeat_gap_statistics_s"]["mean"], 1.25)

    def test_existing_signatures_still_dispatch_validator_and_propagate_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            algorithms = root / "algorithms.json"
            algorithms.write_text(json.dumps({"ECDSA-P256": {"enabled": True}}))
            config = {
                "analysis_results_dir": str(root / "analysis"),
                "signature_results_dir": str(root / "signatures"),
                "processed_trace": str(root / "trace.jsonl"),
                "authentication_groups_dir": str(root / "groups"),
                "authentication_intervals": [1, 5],
                "algorithms_config": str(algorithms),
            }
            outputs = stage_outputs("signatures", config)
            for path in outputs:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("stale result\n")

            for validate_only in (False, True):
                with self.subTest(validate_only=validate_only):
                    config["validate_only"] = validate_only
                    failure = subprocess.CalledProcessError(1, ["signature validator"])
                    with patch.object(pipeline, "run_script", side_effect=failure) as run_script:
                        with self.assertRaises(subprocess.CalledProcessError):
                            pipeline.run_signatures(config, force=False)
                    run_script.assert_called_once()
                    args = run_script.call_args.args
                    self.assertEqual(args[0], "src.experiment.generate_signatures")
                    self.assertEqual("--validate-only" in args, validate_only)
                    self.assertTrue(all(path.read_text() == "stale result\n" for path in outputs))


if __name__ == "__main__":
    unittest.main()
