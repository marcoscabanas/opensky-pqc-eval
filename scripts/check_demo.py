#!/usr/bin/env python3
"""Verify the synthetic current-method demo without generating or repairing outputs.

Use --inputs-only before installing native crypto dependencies. The full check
re-verifies all cached real signatures and checks the complete replay identity.
It does not require every message to authenticate under modeled congestion.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_inputs(root=ROOT):
    from src.processing.preprocess_capture import build_trace, load_df17_records
    from src.experiment.channel_trace import load_channel_trace, validate_coverage

    root = Path(root)
    manifest = json.loads((root / "data/demo/manifest.json").read_text())
    require(manifest.get("kind") == "synthetic_implementation_fixture", "Demo must be explicitly synthetic.")
    for name, digest in manifest["files"].items():
        path = Path(name)
        require(not path.is_absolute() and ".." not in path.parts, "Fixture path must be repository-relative.")
        require(hashlib.sha256((root / path).read_bytes()).hexdigest() == digest,
                f"Demo fixture checksum mismatch: {name}.")
    records, diagnostics = load_df17_records(root / "data/demo/adsb_capture.jsonl")
    trace = build_trace(records)
    expected = manifest["expected"]
    require(len(trace) == expected["target_messages"] == 21, "Demo target population changed.")
    require(diagnostics["total_records"] == expected["raw_records"] == 23, "Demo raw population changed.")
    require(len({row["icao"] for row in trace}) == expected["aircraft"] == 1, "Demo aircraft count changed.")
    require(trace[-1]["relative_time_s"] == expected["target_duration_s"] == 20, "Demo target duration changed.")
    channel = load_channel_trace(root / "data/demo/channel_trace.jsonl", {row["trace_id"]: row for row in trace})
    validate_coverage(channel, expected["target_duration_s"] + 600 + 0.00012)
    require(len(channel["extra_starts"]) == expected["channel_non_target_frames"] == 3,
            "Demo must retain all three background frames, including follow-up.")
    return manifest, trace


def check_demo(config_path=ROOT / "config/demo.json", root=ROOT):
    from src.pipeline import load_config
    from src.experiment import signed_experiment
    from src.experiment.operational_feasibility import load_trace
    from src.experiment.plot_signed_replay import load_report

    manifest, expected_trace = check_inputs(root)
    expected = manifest["expected"]
    config = load_config(config_path)
    require(Path(config["raw_capture"]).resolve() == (Path(root) / "data/demo/adsb_capture.jsonl").resolve()
            and Path(config["channel_trace"]).resolve() == (Path(root) / "data/demo/channel_trace.jsonl").resolve(),
            "Demo configuration must use the packaged synthetic inputs.")
    require(config.get("replay_engine") == "signed_detached", "Demo must use signed_detached.")
    trace = load_trace(Path(config["processed_trace"]))
    require(list(trace.values()) == expected_trace, "Processed demo trace differs from packaged raw input.")
    arguments = ["--trace", config["processed_trace"], "--channel-trace", config["channel_trace"],
                 "--output-dir", config["replay_results_dir"], "--workloads-dir", config["signed_workloads_dir"],
                 "--algorithms-config", config["algorithms_config"], "--hardware-profiles", config["hardware_profiles"],
                 "--scenarios", config["replay_scenarios"], "--replay-model", "signed_detached", "--validate-only",
                 "--intervals", *map(str, config["authentication_intervals"])]
    signed_experiment.run(signed_experiment.parse_args(arguments)[1])
    report = load_report(Path(config["replay_results_dir"]))
    params = report["parameters"]
    require(set(params["algorithms"]) == set(expected["algorithms"]), "Demo must include all four algorithms.")
    require(params["intervals"] == expected["intervals"] and params["seeds"] == expected["seeds"],
            "Demo grouping or seed inventory changed.")
    require(len(params["scenarios"]) == expected["scenarios"] and len(report["rows"]) == expected["replay_cases"],
            "Expected 96 demo cases across six scenarios.")
    require({(s["parameters"]["channel_mode"], s["parameters"]["auth_frames_per_second"])
             for s in params["scenarios"]} == {(mode, rate) for mode in ("independent", "destructive_overlap")
                                               for rate in (10, 50, 100)}, "Demo scenario matrix changed.")
    workloads = report["provenance"]["signed_workloads"]
    require(len(workloads) == expected["workloads"], "Expected 16 cached workloads.")
    require(sum(w["cryptographically_verified_signatures"] for w in workloads.values()) == expected["signatures"],
            "Expected 112 actual, verified signatures.")
    for row in report["rows"]:
        k = row["interval_k"]
        groups = expected["groups_per_interval"][str(k)]
        require(row["source_groups"] == groups and row["unsigned_tail_messages"] == 21 - groups * k,
                "Demo grouping or unsigned tails differ from the fixture.")
        require(row["ordinary_frames_transmitted"] == 21 and row["ordinary_messages_unsent_pending"] == 0
                and row["ordinary_messages_withheld_definitively"] == 0,
                "Detached demo must transmit all original messages, including unsigned tails.")
        require(row["invalid_signature_groups"] == 0, "An attempted demo signature verification failed.")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=ROOT / "config/demo.json")
    parser.add_argument("--inputs-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.inputs_only:
            check_inputs()
            print("PASS: synthetic demo input hashes, 21 targets, and 621 s channel coverage.")
        else:
            check_demo(args.config)
            print("PASS: synthetic signed_detached demo; all four algorithms, 112 verified signatures, 96 complete cases.")
            print("Modeled pending authentication or RF loss is a reported outcome, not a failed implementation check.")
    except (OSError, ValueError, KeyError, TypeError, ImportError, RuntimeError) as exc:
        parser.exit(1, f"FAIL: {exc}\n")


if __name__ == "__main__":
    main()
