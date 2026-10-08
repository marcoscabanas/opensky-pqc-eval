"""The public stages must preserve provenance and never silently perform another stage."""

import contextlib
import copy
import io
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from src import main_experiment as workflow


class MainWorkflowTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.document = {
            "schema_version": 1, "data_manifest": "data/manifest.json",
            "algorithms_config": "config/algorithms.json", "hardware_profiles": "config/profiles.json",
            "scenarios": "config/scenarios.json", "comparison_output": "results/comparison",
            "intervals": [1, 5, 10, 20], "target_duration_s": 3600, "followup_s": 600,
            "windows": {name: {"raw": f"data/{name}.jsonl", "output": f"results/{name}"}
                        for name in workflow.WINDOWS},
        }
        self.write("config/experiment.json", self.document)
        self.write("data/manifest.json", {"schema_version": 1, "windows": {
            name: {"timestamp_mode": "relative_seconds", "recording_start": 0, "recording_end": 4200}
            for name in workflow.WINDOWS}})
        for name in workflow.WINDOWS:
            self.write(f"data/{name}.jsonl", {"record": name})
        self.config = workflow.load_config("config/experiment.json", root=self.root)
        redirect = contextlib.redirect_stdout(io.StringIO())
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def write(self, path, content):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(content) + "\n", encoding="utf-8")
        return destination

    def block_recording(self, name="daytime"):
        path = self.config["data_manifest"]
        metadata = json.loads(path.read_text())
        metadata["windows"][name]["experiment_blockers"] = [
            "Timestamps track network processing batches rather than individual radio receptions."]
        metadata["windows"][name]["status"] = "traffic_only_timing_unverified"
        path.write_text(json.dumps(metadata))

    def test_blocked_recording_can_still_be_prepared_for_traffic_inspection(self):
        self.block_recording()
        with patch.object(workflow, "prepare_window", return_value={"traffic": "preview"}) as prepare, \
                patch.object(workflow, "sign_window") as sign:
            result = workflow.run(self.config, window="daytime", stage="prepare")
        self.assertEqual(result["daytime:prepare"], {"traffic": "preview"})
        self.assertTrue(prepare.call_args.args[2]["experiment_blockers"])
        self.assertFalse(prepare.call_args.kwargs["validate_only"])
        sign.assert_not_called()

    def test_explicit_conditional_analysis_preserves_recording_limitations(self):
        self.block_recording()
        self.config["analysis_mode"] = "conditional_recorded_timing"
        workflow._require_experiment_ready(self.config, ("daytime",))
        with patch.object(workflow, "validate_signature_inventory"), \
                patch("src.experiment.signed_experiment.run") as replay:
            workflow.replay_window(self.config, "daytime")
        context = replay.call_args.args[0].analysis_context
        self.assertEqual(context["mode"], "conditional_recorded_timing")
        self.assertIn("network processing", context["recording_limitations"][0])
        metadata = json.loads(self.config["data_manifest"].read_text())
        self.assertTrue(metadata["windows"]["daytime"]["experiment_blockers"])

    def test_unknown_analysis_mode_is_rejected(self):
        self.write("config/experiment.json", dict(self.document, analysis_mode="ignore_errors"))
        with self.assertRaisesRegex(ValueError, "analysis_mode"):
            workflow.load_config("config/experiment.json", root=self.root)

    def test_blockers_stop_separate_experiment_stages_before_work(self):
        self.block_recording()
        for stage in ("sign", "replay", "report", "compare"):
            with self.subTest(stage=stage), contextlib.ExitStack() as stack:
                operations = [stack.enter_context(patch.object(workflow, name))
                              for name in ("prepare_window", "sign_window", "replay_window",
                                           "report_window", "compare")]
                with self.assertRaisesRegex(ValueError, "daytime: Timestamps track network processing batches"):
                    workflow.run(self.config, window="both" if stage == "compare" else "daytime",
                                 stage=stage)
                for operation in operations:
                    operation.assert_not_called()
        self.assertFalse((self.root / "results").exists())

    def test_direct_stage_calls_cannot_bypass_blockers_including_validation_only(self):
        self.block_recording()
        with patch("src.experiment.signed_workload.backend_identity") as backend, \
                patch("src.experiment.signed_workload.build_or_load_workload") as sign, \
                patch.object(workflow, "validate_signature_inventory") as inventory, \
                patch("src.experiment.signed_experiment.run") as replay, \
                patch("src.experiment.main_report.generate_report") as report, \
                patch("src.experiment.main_report.compare_windows") as compare:
            for operation in (workflow.sign_window, workflow.replay_window, workflow.report_window,
                              workflow.compare):
                for validate_only in (False, True):
                    with self.subTest(stage=operation.__name__, validate_only=validate_only):
                        args = () if operation is workflow.compare else ("daytime",)
                        with self.assertRaisesRegex(ValueError, "Review the recording input audit"):
                            operation(self.config, *args, validate_only=validate_only)
            for operation in (backend, sign, inventory, replay, report, compare):
                operation.assert_not_called()

    def test_blocked_nighttime_prevents_expensive_daytime_stages_in_combined_run(self):
        self.block_recording("nighttime")
        with patch.object(workflow, "prepare_window") as prepare, \
                patch.object(workflow, "sign_window") as sign:
            with self.assertRaisesRegex(ValueError, "nighttime: Timestamps track network processing batches"):
                workflow.run(self.config, window="both", stage="all")
        prepare.assert_called_once()
        self.assertEqual(prepare.call_args.args[1], "daytime")
        sign.assert_not_called()

    def test_malformed_blockers_do_not_silently_allow_experiment(self):
        path = self.config["data_manifest"]
        metadata = json.loads(path.read_text())
        for invalid in (None, "unverified timing", [""]):
            with self.subTest(blockers=invalid):
                metadata["windows"]["daytime"]["experiment_blockers"] = invalid
                path.write_text(json.dumps(metadata))
                with patch.object(workflow, "_signing_inputs") as inputs:
                    with self.assertRaisesRegex(ValueError, "daytime.experiment_blockers must be a list"):
                        workflow.sign_window(self.config, "daytime")
                    inputs.assert_not_called()

    def test_both_preflights_missing_nighttime_before_any_work(self):
        self.config["windows"]["nighttime"]["raw"] = self.root / "not-yet-recorded.jsonl"
        with patch.object(workflow, "prepare_window") as prepare:
            with self.assertRaisesRegex(ValueError, "Missing nighttime recording"):
                workflow.run(self.config, window="both")
            prepare.assert_not_called()
        self.assertFalse((self.root / "results").exists())

    def test_both_rejects_invalid_nighttime_metadata_before_daytime_work(self):
        path = self.config["data_manifest"]
        metadata = json.loads(path.read_text())
        metadata["windows"]["nighttime"]["recording_end"] = None
        path.write_text(json.dumps(metadata))
        with patch.object(workflow, "prepare_window") as prepare, \
                patch.object(workflow, "sign_window") as sign:
            with self.assertRaisesRegex(ValueError, "Invalid nighttime recording metadata.*recording_end"):
                workflow.run(self.config, window="both")
            prepare.assert_not_called()
            sign.assert_not_called()
        self.assertFalse((self.root / "results").exists())

    def test_both_acquires_window_locks_before_work_and_releases_on_conflict(self):
        night_lock = self.config["windows"]["nighttime"]["output"] / ".pipeline.lock"
        day_lock = self.config["windows"]["daytime"]["output"] / ".pipeline.lock"
        with workflow.RunLock(night_lock), patch.object(workflow, "prepare_window") as prepare:
            with self.assertRaisesRegex(RuntimeError, "Another run owns"):
                workflow.run(self.config, window="both", stage="prepare")
            prepare.assert_not_called()
            with workflow.RunLock(day_lock):
                pass

    def test_separate_stages_require_validated_source_before_signing(self):
        with patch.object(workflow, "prepare_window", side_effect=ValueError("raw source changed")), \
                patch.object(workflow, "sign_window") as sign:
            with self.assertRaisesRegex(ValueError, "source changed"):
                workflow.run(self.config, window="daytime", stage="sign")
            sign.assert_not_called()

    def test_all_and_wrappers_share_stages_in_order(self):
        calls = []
        with contextlib.ExitStack() as stack:
            for stage in ("prepare", "sign", "replay", "report"):
                stack.enter_context(patch.object(workflow, stage + "_window",
                    side_effect=lambda config, name, *args, _stage=stage, **kwargs:
                        calls.append((name, _stage, kwargs["validate_only"]))))
            stack.enter_context(patch.object(workflow, "compare", side_effect=lambda *args, **kwargs:
                calls.append(("both", "compare", kwargs["validate_only"]))))
            workflow.run(self.config, window="both")
        self.assertEqual(calls, [(name, stage, False) for name in workflow.WINDOWS
                                 for stage in ("prepare", "sign", "replay", "report")]
                         + [("both", "compare", False)])

    def test_validate_only_does_not_create_run_directories_or_locks(self):
        with patch.object(workflow, "prepare_window") as prepare:
            workflow.run(self.config, window="daytime", stage="prepare", validate_only=True)
        self.assertTrue(prepare.call_args.kwargs["validate_only"])
        self.assertFalse((self.root / "results").exists())

    def test_comparison_needs_both_windows(self):
        with self.assertRaisesRegex(ValueError, "--window both"):
            workflow.run(self.config, window="daytime", stage="compare")

    def test_comparison_validates_both_replays_before_publication(self):
        with patch.object(workflow, "prepare_window") as prepared, \
                patch.object(workflow, "replay_window") as replay, \
                patch.object(workflow, "compare") as compare:
            workflow.run(self.config, window="both", stage="compare", validate_only=True)
        self.assertEqual(prepared.call_count, 2)
        self.assertEqual(replay.call_count, 2)
        self.assertTrue(all(call.kwargs["validate_only"] for call in replay.call_args_list))
        compare.assert_called_once_with(self.config, validate_only=True)

    def test_replay_does_not_generate_missing_signatures(self):
        with patch.object(workflow, "validate_signature_inventory", side_effect=ValueError("Run step 02_sign first")) as sign, \
                patch("src.experiment.signed_experiment.run") as replay:
            with self.assertRaisesRegex(ValueError, "02_sign"):
                workflow.replay_window(self.config, "daytime")
        sign.assert_called_once_with(self.config, "daytime")
        replay.assert_not_called()

    def test_replay_engine_is_forbidden_to_build_unexpected_caches(self):
        self.config["algorithms"] = ["ECDSA-P256", "FN-DSA-512"]
        with patch.object(workflow, "validate_signature_inventory"), \
                patch("src.experiment.signed_experiment.run") as replay:
            workflow.replay_window(self.config, "daytime")
        self.assertTrue(replay.call_args.args[0].require_workloads)
        self.assertEqual(replay.call_args.args[0].algorithm, self.config["algorithms"])

    def test_algorithm_selection_preserves_enabled_backends_and_legacy_defaults(self):
        self.write("config/algorithms.json", {
            "ECDSA-P256": {"enabled": True}, "SLH-DSA-SHA2-128s": {"enabled": True},
            "disabled": {"enabled": False}})
        self.assertEqual(list(workflow.selected_algorithm_configs(self.config)),
                         ["ECDSA-P256", "SLH-DSA-SHA2-128s"])
        self.config["algorithms"] = ["ECDSA-P256"]
        self.assertEqual(list(workflow.selected_algorithm_configs(self.config)), ["ECDSA-P256"])
        self.assertTrue(json.loads(self.config["algorithms_config"].read_text())["SLH-DSA-SHA2-128s"]["enabled"])
        for selection, message in ((["missing"], "Unknown selected algorithm"),
                                   (["disabled"], "Selected algorithm is disabled")):
            with self.subTest(selection=selection):
                self.config["algorithms"] = selection
                with self.assertRaisesRegex(ValueError, message):
                    workflow.selected_algorithm_configs(self.config)

    def test_config_rejects_empty_or_duplicate_algorithm_selection(self):
        for selection in (None, [], "ECDSA-P256", [""], [1], [[]], ["ECDSA-P256", "ECDSA-P256"]):
            with self.subTest(selection=selection):
                self.write("config/experiment.json", dict(self.document, algorithms=selection))
                with self.assertRaisesRegex(ValueError, "algorithms must contain distinct nonempty"):
                    workflow.load_config("config/experiment.json", root=self.root)

    def test_output_directories_cannot_overlap_or_contain_inputs(self):
        for output in ("results/daytime", "results/daytime/child", "data", "."):
            with self.subTest(output=output):
                modified = copy.deepcopy(self.document)
                modified["windows"]["nighttime"]["output"] = output
                self.write("config/experiment.json", modified)
                with self.assertRaises(ValueError):
                    workflow.load_config("config/experiment.json", root=self.root)

    def test_config_rejects_duplicate_grouping_sizes_and_nonpositive_durations(self):
        for field, value in (("intervals", [1, 1]), ("followup_s", 0), ("target_duration_s", True)):
            with self.subTest(field=field):
                modified = dict(self.document, **{field: value})
                self.write("config/experiment.json", modified)
                with self.assertRaises(ValueError):
                    workflow.load_config("config/experiment.json", root=self.root)

    def test_signature_inventory_rejects_changed_inputs_and_altered_caches(self):
        prepared = self.root / "results/daytime/01_prepared"
        prepared.mkdir(parents=True)
        (prepared / "trace.jsonl").write_text("trace\n")
        (prepared / "manifest.json").write_text("{}\n")
        self.write("config/algorithms.json", {"ECDSA-P256": {
            "module": "src.crypto.ecdsa_p256", "implementation": "SECP256R1"}})
        identity = {"module": "src.crypto.ecdsa_p256", "implementation": "SECP256R1"}
        evidence = {"cache_dir": str(self.root / "results/daytime/02_signed/digest"), "signature_count": 1}
        with patch.object(workflow, "_study_cases", return_value=(["ECDSA-P256"], [], [])), \
                patch("src.experiment.signed_workload.backend_identity", return_value=identity), \
                patch("src.experiment.io_support.load_trace", return_value={1: {}}), \
                patch("src.experiment.signed_workload.build_or_load_workload",
                      return_value={"evidence": evidence}) as build:
            created = workflow.sign_window(self.config, "daytime")
            self.assertTrue(created["complete"])
            self.assertEqual(created["workloads"]["ECDSA-P256:k=1"]["cache_dir"], "digest")
            self.assertFalse(any(call.kwargs["validate_only"] for call in build.call_args_list))
            build.reset_mock()
            workflow.sign_window(self.config, "daytime", validate_only=True)
            self.assertTrue(all(call.kwargs["validate_only"] for call in build.call_args_list))
            evidence["signature_count"] = 2
            with self.assertRaisesRegex(ValueError, "differ from the saved"):
                workflow.sign_window(self.config, "daytime", validate_only=True)
            (prepared / "trace.jsonl").write_text("changed trace\n")
            with self.assertRaisesRegex(ValueError, "stale"):
                workflow.sign_window(self.config, "daytime")

    @unittest.skipUnless(importlib.util.find_spec("cryptography") and importlib.util.find_spec("matplotlib"),
                         "Actual workflow needs cryptography and matplotlib")
    def test_actual_prepare_sign_replay_and_stale_source_rejection(self):
        """Use generated observations and real ECDSA; no archived fixture inputs."""
        self.config.update(intervals=[1, 2], target_duration_s=1, followup_s=1, algorithms=["ECDSA-P256"])
        self.write("config/experiment.json", dict(self.document, intervals=[1, 2],
                                                   target_duration_s=1, followup_s=1, algorithms=["ECDSA-P256"]))
        algorithms = json.loads((workflow.ROOT / "config/algorithms.json").read_text())
        self.write("config/algorithms.json", {name: algorithms[name]
                   for name in ("ECDSA-P256", "SLH-DSA-SHA2-128s")})
        self.write("config/profiles.json", {"schema_version": 1, "profiles": {"fixture": {
            "id": "fixture", "label": "Fixture", "platform": "Abstract test", "kind": "sensitivity_assumption",
            "algorithms": {"ECDSA-P256": {"implementation": "SECP256R1", "equivalence": "assumed",
                "limitation": "Test-only timing", "source_urls": [],
                "operations": {op: {"samples_ms": [1], "sample_kind": "assumed_constant"}
                               for op in ("sign", "verify")}}}}}})
        self.write("config/scenarios.json", {"seeds": [1], "scenarios": [{
            "name": "fixture", "sender_profile": "fixture", "receiver_profile": "fixture",
            "parameters": {"replay_model": "signed_detached", "followup_s": 1,
                           "max_batch_wait_s": None, "channel_mode": "independent",
                           "auth_frames_per_second": 8000, "loss": {"kind": "iid", "probability": 0}}}]})
        self.write("data/manifest.json", {"schema_version": 1, "windows": {
            "daytime": {"timestamp_mode": "relative_seconds", "recording_start": 0, "recording_end": 3}}})
        raw = self.config["windows"]["daytime"]["raw"]
        raw.write_text("".join(json.dumps({"timestamp": index / 10,
                                           "raw_msg": "8DABCDEF" + f"{index:020X}"}) + "\n"
                               for index in range(1, 5)))
        for stage in ("prepare", "sign", "replay"):
            workflow.run(self.config, window="daytime", stage=stage)
        output = self.config["windows"]["daytime"]["output"]
        report = json.loads((output / "03_replay/replay_summary.json").read_text())
        self.assertEqual(len(report["rows"]), 2)
        self.assertEqual({row["algorithm"] for row in report["rows"]}, {"ECDSA-P256"})
        self.assertTrue(all(row["authenticated_messages"] == 4 for row in report["rows"]))
        inventory = json.loads((output / "02_signed/signatures_manifest.json").read_text())
        self.assertEqual(set(inventory["workloads"]), {"ECDSA-P256:k=1", "ECDSA-P256:k=2"})
        self.assertTrue((output / "figures/01_traffic_by_df.png").exists())
        with patch("src.experiment.signed_workload._build", side_effect=AssertionError("must not sign")), \
                patch("src.experiment.signed_replay.simulate", side_effect=AssertionError("must not replay")):
            workflow.run(self.config, window="daytime", stage="replay", validate_only=True)
            # Published artifacts must remain verifiable in another checkout path.
            with tempfile.TemporaryDirectory() as copied:
                clone = Path(copied) / "clone"
                shutil.copytree(self.root, clone)
                clone_config = workflow.load_config("config/experiment.json", root=clone)
                workflow.run(clone_config, window="daytime", stage="replay", validate_only=True)
        with raw.open("a") as stream:
            stream.write(json.dumps({"timestamp": 2, "raw_msg": "58ABCDEF000000"}) + "\n")
        with self.assertRaisesRegex(ValueError, "checksum changed"):
            workflow.run(self.config, window="daytime", stage="replay")


if __name__ == "__main__":
    unittest.main()
