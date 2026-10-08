"""Resource bounds are checked against the actual scheduler and replay engine."""

import base64
import contextlib
import copy
import io
import json
from pathlib import Path
import random
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import numpy as np

from src.experiment.model_support import FRAME_S
from src.experiment.replay_transport import encode_envelope
from src.experiment.resource_preflight import build_resource_preflight, count_detached_radio, main
from src.experiment.signed_replay import Group, _schedule_detached_radio
from tests.fixtures import ALGORITHM, profile_fixture, trace_fixture
from tests.test_signed_replay import replay, workload_fixture
from tests.test_prepare_recording import frame


def scenario(name="resource_case", **parameters):
    return {"name": name, "sender_profile": "test", "receiver_profile": "test", "parameters": {
        "replay_model": "signed_detached", "followup_s": 2,
        "auth_frames_per_second": 100, "channel_mode": "independent",
        "loss": {"kind": "iid", "probability": 0}, **parameters}}


def report(records, *, scenarios=None, intervals=(1,), profile=None, observed=0,
           horizon=3, fixed=True, benchmark=None):
    return build_resource_preflight(records,
        {ALGORITHM: {"expected_signature_bytes": 64 if fixed else None}},
        {"test": profile or profile_fixture()}, scenarios or [scenario()], intervals,
        horizon_s=horizon, observed_frames=observed,
        signature_size_bounds={ALGORITHM: (0, 64)} if not fixed else None,
        host_benchmark=benchmark)


class ResourcePreflightTest(unittest.TestCase):
    def test_exact_radio_counts_match_engine_with_contention_and_cutoffs(self):
        rng = random.Random(3017)
        for trial in range(80):
            originals = sorted(rng.choice((0, 0.00012, 0.003, rng.random() * 0.03))
                               for _ in range(rng.randint(1, 30)))
            interval = rng.choice((1, 2, 5))
            service = rng.choice((0.00001, 0.00012, 0.006))
            horizon = rng.choice((0.00012, 0.013, 0.03, 0.06))
            rate = rng.choice((10, 100, 8000, 1 / FRAME_S))
            fragments = rng.choice((1, 2, 42, 829))
            ends, available = [], 0
            for formed in originals[interval - 1::interval]:
                available = max(formed, available) + service
                ends.append(available)
            groups = [Group({"descriptor": SimpleNamespace(icao="ABCDEF", seq=i)}, (),
                            fragments, sign_end=end) for i, end in enumerate(ends)]
            starts = np.full(len(originals), np.nan)
            records = [{"icao": "ABCDEF", "relative_time_s": time} for time in originals]
            actual, _ = _schedule_detached_radio(groups, records, starts,
                {"auth_frames_per_second": rate, "fragment_copies": 1, "transmission_queue_limit": None},
                horizon, 1_000_000)
            counted = count_detached_radio(originals, ends, fragments, rate, horizon)
            with self.subTest(trial=trial):
                self.assertEqual(counted["auth_frames"], actual)
                self.assertEqual(counted["completed_objects"], sum(g.tx_end <= horizon for g in groups))
                self.assertEqual(counted["completed_originals"], int(np.sum(starts + FRAME_S <= horizon)))

    def test_actual_replay_processed_events_stay_inside_bounds(self):
        records = trace_fixture(count=8, spacing=0.03)
        profile = profile_fixture(sign_ms=0.6, verify_ms=50)
        horizon = records[-1]["relative_time_s"] + 2 + FRAME_S
        configurations = [scenario("clear"), scenario("collision", channel_mode="destructive_overlap"),
            scenario("erasure", loss={"kind": "iid", "probability": 0.25}),
            scenario("jitter", receive_jitter_ms=20)]
        for fixed in (True, False):
            for interval in (1, 2, 5):
                for configuration in configurations:
                    parameters = {k: v for k, v in configuration["parameters"].items() if k != "replay_model"}
                    case_horizon = horizon + parameters.get("receive_jitter_ms", 0) / 1000
                    predicted = report(records, scenarios=[configuration], intervals=[interval], profile=profile,
                                       horizon=case_horizon, fixed=fixed)["cases"][0]
                    actual = replay(records, interval=interval, profile=profile,
                                    replay_model="signed_detached", **parameters)["summary"]
                    with self.subTest(fixed=fixed, interval=interval, scenario=configuration["name"]):
                        self.assertLessEqual(predicted["processed_events_lower"], actual["processed_events"])
                        self.assertGreaterEqual(predicted["processed_events_upper"], actual["processed_events"])
                        self.assertLessEqual(predicted["auth_frames_lower"], actual["auth_frames_transmitted"])
                        self.assertGreaterEqual(predicted["auth_frames_upper"], actual["auth_frames_transmitted"])

    def test_background_is_counted_once_and_fixed_size_json_bytes_are_exact(self):
        records = trace_fixture(count=6, spacing=0.2)
        for interval in (1, 2, 5):
            prediction = report(records, intervals=[interval], observed=153)
            workload = workload_fixture(records, interval)
            byte_count = 0
            for group in workload["groups"]:
                row = {"members": list(group["members"]), "formed_s": group["formed_s"],
                       "envelope": base64.b64encode(encode_envelope(group["envelope"])).decode("ascii")}
                byte_count += len((json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode())
            estimate = prediction["workloads"][0]
            self.assertEqual(estimate["groups_jsonl_bytes_lower"], byte_count)
            self.assertEqual(estimate["groups_jsonl_bytes_upper"], byte_count)
            self.assertEqual(prediction["cases"][0]["fixed_events"], len(records) + len(workload["groups"]) + 153)

    def test_budget_verdicts_distinguish_failure_from_uncertainty(self):
        records = trace_fixture(count=2)
        self.assertEqual(report(records, scenarios=[scenario(max_events=3)])["cases"][0]["event_budget_verdict"], "exceeds")
        self.assertEqual(report(records, scenarios=[scenario(max_events=10000)])["cases"][0]["event_budget_verdict"], "within_bound")
        self.assertEqual(report(records, scenarios=[scenario(max_events=50)], fixed=False)["cases"][0]["event_budget_verdict"], "undetermined")

    def test_host_measurement_cannot_change_radio_or_event_bounds(self):
        records = trace_fixture()
        plain = report(records)
        measured = report(records, benchmark={"rows": [{"algorithm": ALGORITHM, "k": 1, "sign_median_ms": 428}]})
        self.assertEqual(measured["cases"], plain["cases"])
        self.assertAlmostEqual(measured["workloads"][0]["host_serial_sign_seconds_estimate"], len(records) * 0.428)
        self.assertFalse(measured["scientific_result"])

    def test_invalid_or_unsupported_settings_fail_before_signing(self):
        records = trace_fixture()
        for options in ({"max_batch_wait_s": 1}, {"sender_queue_limit": 2}, {"transmission_queue_limit": 2},
                        {"receiver_queue_limit": 2}, {"background_frames_per_second": 1}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                report(records, scenarios=[scenario(**options)])
        empirical = copy.deepcopy(profile_fixture())
        empirical["algorithms"][ALGORITHM]["operations"]["sign"] = {
            "samples_ms": [1, 2], "sample_kind": "empirical"}
        with self.assertRaisesRegex(ValueError, "constant"):
            report(records, profile=empirical)
        with self.assertRaisesRegex(ValueError, "Duplicate trace_id"):
            report(records + [records[0]])
        with self.assertRaisesRegex(ValueError, "ordered"):
            count_detached_radio([1, 0], [], 1, 100, 2)
        with self.assertRaisesRegex(ValueError, "variable signature"):
            build_resource_preflight(records, {ALGORITHM: {"expected_signature_bytes": None}},
                                     {"test": profile_fixture()}, [scenario()], [1], horizon_s=3, observed_frames=0)

    def test_cli_reports_missing_configuration_without_creating_outputs(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()) as errors:
            absent = Path(directory) / "absent.json"
            with self.assertRaises(SystemExit) as exited:
                main(["--window", "daytime", "--config", str(absent)])
            self.assertEqual(exited.exception.code, 2)
            self.assertIn("Resource preflight failed", errors.getvalue())
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_cli_allows_inspection_of_blocked_prepared_data_without_signing(self):
        from src.processing.prepare_recording import prepare_recording

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw, output = root / "daytime.jsonl", root / "results"
            raw.write_text("".join(json.dumps({"timestamp": time, "raw_msg": frame(df)}) + "\n"
                                   for time, df in ((0.1, 17), (11, 11), (12, 17))))
            metadata = {"timestamp_mode": "relative_seconds", "recording_start": 0, "recording_end": 15,
                        "experiment_blockers": ["Synthetic test: timing unverified."]}
            prepare_recording(raw, output / "01_prepared", metadata, target_duration_s=10, followup_s=5)
            manifest = root / "data_manifest.json"
            manifest.write_text(json.dumps({"schema_version": 1, "windows": {"daytime": metadata}}))
            algorithms = root / "algorithms.json"
            algorithms.write_text(json.dumps({ALGORITHM: {"expected_signature_bytes": 64},
                                              "SLH-DSA-SHA2-128s": {"expected_signature_bytes": 7856}}))
            scenarios = root / "scenarios.json"
            configuration = scenario(followup_s=5)
            configuration.update(sender_profile="embedded_reference", receiver_profile="embedded_reference")
            scenarios.write_text(json.dumps({"scenarios": [configuration]}))
            config = root / "experiment.json"
            config.write_text(json.dumps({"schema_version": 1, "data_manifest": str(manifest),
                "algorithms_config": str(algorithms), "algorithms": [ALGORITHM],
                "hardware_profiles": str(Path(__file__).resolve().parents[1] / "config/hardware_profiles.json"),
                "scenarios": str(scenarios), "intervals": [1], "target_duration_s": 10, "followup_s": 5,
                "windows": {"daytime": {"raw": str(raw), "output": str(output)},
                            "nighttime": {"raw": str(root / "nighttime.jsonl"), "output": str(root / "night")}},
                "comparison_output": str(root / "comparison")}))
            with contextlib.redirect_stdout(io.StringIO()), \
                    patch("src.experiment.signed_workload.build_or_load_workload") as sign, \
                    patch("src.experiment.signed_replay.simulate") as simulation:
                main(["--window", "daytime", "--config", str(config)])
            sign.assert_not_called()
            simulation.assert_not_called()
            diagnostic = json.loads((output / "01_prepared/resource_preflight.json").read_text())
            self.assertEqual(diagnostic["experiment_blockers"], metadata["experiment_blockers"])
            self.assertEqual(diagnostic["additional_observed_frames"], 2)
            self.assertEqual({case["algorithm"] for case in diagnostic["cases"]}, {ALGORITHM})
            self.assertEqual({workload["algorithm"] for workload in diagnostic["workloads"]}, {ALGORITHM})
            self.assertFalse(diagnostic["scientific_result"])
            self.assertIsNone(diagnostic["host_benchmark"])


if __name__ == "__main__":
    unittest.main()
