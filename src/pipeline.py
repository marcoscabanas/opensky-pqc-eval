#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
import os
import signal
from datetime import datetime, timezone
from pathlib import Path

from src.runtime import RunLock, atomic_json

REPO_ROOT = Path(__file__).resolve().parents[1]

LEGACY_STAGE_ORDER = [
    "capture",
    "aircraft",
    "duplicates",
    "preprocess",
    "groups",
    "signatures",
    "feasibility",
]
STAGE_ORDER = LEGACY_STAGE_ORDER + ["screening", "replay"]
VALIDATION_STAGES = {"signatures", "feasibility", "screening", "replay"}


def repo_path(path_value: str | Path) -> Path:
    path = Path(path_value)
    if path.is_absolute():
        return path
    return (REPO_ROOT / path).resolve()


def resolve_cfg_paths(config: dict) -> dict:
    resolved = dict(config)
    for key in (
        "raw_capture",
        "processed_trace",
        "authentication_groups_dir",
        "analysis_results_dir",
        "signature_results_dir",
        "algorithms_config",
        "hardware_profiles",
        "replay_scenarios",
        "replay_results_dir",
        "signature_size_profile",
        "channel_trace",
        "signed_workloads_dir",
    ):
        if key in resolved and isinstance(resolved[key], str):
            resolved[key] = str(repo_path(resolved[key]))
    if "signature_size_sources" in resolved:
        sources = resolved["signature_size_sources"]
        if not isinstance(sources, list) or any(not isinstance(path, str) or not path for path in sources):
            raise ValueError("signature_size_sources must be a list of nonempty path strings.")
        resolved["signature_size_sources"] = [str(repo_path(path)) for path in sources]
    return resolved


def select_stages(config: dict, stage="all", from_stage=None, validate_only=False) -> list[str]:
    """Keep old configuration behavior while allowing an explicit operational workflow."""
    configured = config.get("execution_stages", LEGACY_STAGE_ORDER)
    if (not isinstance(configured, list) or not configured
            or any(not isinstance(name, str) or name not in STAGE_ORDER for name in configured)
            or len(set(configured)) != len(configured)):
        raise ValueError("execution_stages must be a nonempty list of unique known stage names.")
    if from_stage and stage != "all":
        raise ValueError("Use either --stage or --from-stage, not both.")
    if from_stage:
        if from_stage not in configured:
            raise ValueError(f"Stage '{from_stage}' is not in execution_stages; use --stage for an explicit single stage.")
        selected = configured[configured.index(from_stage):]
    elif stage == "all":
        selected = list(configured)
    elif stage in STAGE_ORDER:
        selected = [stage]
    else:
        raise ValueError(f"Unknown stage: {stage}")
    if validate_only:
        if from_stage or (stage != "all" and stage not in VALIDATION_STAGES):
            raise ValueError("--validate-only supports all, signatures, feasibility, screening, or replay, without --from-stage.")
        selected = [name for name in selected if name in VALIDATION_STAGES]
        if not selected:
            raise ValueError("No stages in execution_stages support --validate-only.")
    return selected


def replay_output_dir(config: dict) -> Path:
    if config.get("replay_results_dir"):
        return repo_path(config["replay_results_dir"])
    return repo_path(config["signature_results_dir"]).parent / "replay"


def load_config(path: str | Path) -> dict:
    config_path = repo_path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as handle:
        config = json.load(handle)

    resolved = resolve_cfg_paths(config)
    resolved["config_path"] = str(config_path)
    return resolved


def script_path(*parts: str) -> Path:
    return (REPO_ROOT / Path(*parts)).resolve()


def run_script(module: str, *args: str) -> None:
    command = [sys.executable, "-m", module, *args]
    print(f"\n>>> {' '.join(command)}", flush=True)
    child = subprocess.Popen(command, cwd=str(REPO_ROOT))
    try:
        returncode = child.wait()
        if returncode:
            raise subprocess.CalledProcessError(returncode, command)
    except BaseException:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        raise


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def enabled_algorithm_names(config: dict) -> list[str]:
    algorithms_path = repo_path(config.get("algorithms_config", "config/algorithms.json"))
    with algorithms_path.open("r", encoding="utf-8") as handle:
        algorithms_config = json.load(handle)
    return [
        name for name, value in algorithms_config.items()
        if value.get("enabled", True)
    ]


def stage_outputs(stage: str, config: dict) -> list[Path]:
    if stage == "capture":
        return [repo_path(config["analysis_results_dir"]) / "capture_summary.json"]
    if stage == "aircraft":
        return [repo_path(config["analysis_results_dir"]) / "aircraft_analysis.json"]
    if stage == "duplicates":
        return [repo_path(config["analysis_results_dir"]) / "duplicate_analysis.json"]
    if stage == "preprocess":
        return [
            repo_path(config["processed_trace"]),
            repo_path(config["analysis_results_dir"]) / "preprocessing_manifest.json",
        ]
    if stage == "groups":
        base = repo_path(config["authentication_groups_dir"])
        summary = repo_path(config["analysis_results_dir"]) / "authentication_group_summary.json"
        files = [summary]
        for interval in config.get("authentication_intervals", [1, 5, 10, 20]):
            files.append(base / f"authentication_groups_k{interval}.jsonl")
        return files
    if stage == "signatures":
        base = repo_path(config["signature_results_dir"])
        files = [base / "signature_experiment_summary.json"]
        algorithms = enabled_algorithm_names(config)
        for interval in config.get("authentication_intervals", [1, 5, 10, 20]):
            for algorithm in algorithms:
                files.append(base / f"signatures_{algorithm}_k{interval}.jsonl")
        return files
    if stage == "feasibility":
        base = repo_path(config["signature_results_dir"]).parent / "feasibility"
        return [base / "operational_feasibility_summary.json", base / "feasibility_overview.csv"]
    if stage == "screening":
        base = replay_output_dir(config)
        return [base / "constraint_screening_summary.json", base / "constraint_screening_overview.csv",
                base / "signature_size_profile.json"]
    if stage == "replay":
        base = replay_output_dir(config)
        return [base / "replay_summary.json", base / "replay_overview.csv"]
    raise ValueError(f"Unknown stage: {stage}")


def missing_required(stage: str, config: dict) -> list[Path]:
    required = []
    if stage in {"aircraft", "duplicates", "preprocess", "groups", "signatures"}:
        capture_output = repo_path(config["analysis_results_dir"]) / "capture_summary.json"
        if not capture_output.exists():
            required.append(capture_output)
    if stage in {"preprocess", "groups", "signatures"}:
        raw_capture = repo_path(config["raw_capture"])
        if not raw_capture.exists():
            required.append(raw_capture)
    if stage in {"groups", "signatures"}:
        processed_trace = repo_path(config["processed_trace"])
        if not processed_trace.exists():
            required.append(processed_trace)
    if stage in {"signatures", "feasibility"}:
        groups_dir = repo_path(config["authentication_groups_dir"])
        if not groups_dir.exists():
            required.append(groups_dir)
    if stage == "feasibility":
        signature_dir = repo_path(config["signature_results_dir"])
        if not signature_dir.exists():
            required.append(signature_dir)
    if stage in {"screening", "replay"}:
        inputs = [repo_path(config["processed_trace"]),
                  repo_path(config.get("algorithms_config", "config/algorithms.json"))]
        signed_replay = stage == "replay" and config.get("replay_engine") in {"signed_before_send", "signed_detached"}
        if not signed_replay:
            inputs.extend(repo_path(config["authentication_groups_dir"]) / f"authentication_groups_k{interval}.jsonl"
                          for interval in config.get("authentication_intervals", [1, 5, 10, 20]))
            if config.get("signature_size_profile"):
                inputs.append(repo_path(config["signature_size_profile"]))
        if stage == "replay":
            default_scenarios = "config/signed_replay_scenarios.json" if signed_replay else "config/replay_scenarios.json"
            inputs.extend([repo_path(config.get("hardware_profiles", "config/hardware_profiles.json")),
                           repo_path(config.get("replay_scenarios", default_scenarios))])
            if config.get("channel_trace"):
                inputs.append(repo_path(config["channel_trace"]))
        required.extend(path for path in inputs if not path.exists())
    return required


def can_run(stage: str, config: dict, force: bool) -> bool:
    outputs = stage_outputs(stage, config)
    if force:
        return True
    for output in outputs:
        if output.exists():
            print(f"SKIP: {stage} -> {output} already exists (use --force to regenerate).")
            return False
    return True


def run_capture(config: dict, force: bool) -> None:
    stage = "capture"
    output = stage_outputs(stage, config)[0]
    if not force and output.exists():
        print(f"SKIP: {stage} -> {output} already exists (use --force to regenerate).")
        return
    ensure_parent(output)
    run_script(
        "src.analysis.analyze_capture",
        str(repo_path(config["raw_capture"])),
        "--output",
        str(output),
    )


def run_aircraft(config: dict, force: bool) -> None:
    stage = "aircraft"
    output = stage_outputs(stage, config)[0]
    if not force and output.exists():
        print(f"SKIP: {stage} -> {output} already exists (use --force to regenerate).")
        return
    ensure_parent(output)
    run_script(
        "src.analysis.analyze_aircraft",
        str(repo_path(config["raw_capture"])),
        "--summary",
        str(output),
    )


def run_duplicates(config: dict, force: bool) -> None:
    stage = "duplicates"
    output = stage_outputs(stage, config)[0]
    if not force and output.exists():
        print(f"SKIP: {stage} -> {output} already exists (use --force to regenerate).")
        return
    ensure_parent(output)
    run_script(
        "src.analysis.analyze_duplicates",
        str(repo_path(config["raw_capture"])),
        "--summary",
        str(output),
    )


def run_preprocess(config: dict, force: bool) -> None:
    stage = "preprocess"
    output_trace = repo_path(config["processed_trace"])
    output_manifest = stage_outputs(stage, config)[1]
    if not force and output_trace.exists() and output_manifest.exists():
        print(f"SKIP: {stage} -> {output_trace} and {output_manifest} already exist (use --force to regenerate).")
        return
    if not force and (output_trace.exists() or output_manifest.exists()):
        raise RuntimeError("Preprocessing outputs are incomplete; use --force explicitly or a new output directory.")
    ensure_parent(output_trace)
    ensure_parent(output_manifest)
    run_script(
        "src.processing.preprocess_capture",
        str(repo_path(config["raw_capture"])),
        "--output",
        str(output_trace),
        "--manifest",
        str(output_manifest),
    )


def run_groups(config: dict, force: bool) -> None:
    stage = "groups"
    output_dir = repo_path(config["authentication_groups_dir"])
    summary = repo_path(config["analysis_results_dir"]) / "authentication_group_summary.json"
    if not force and all((output_dir / f"authentication_groups_k{interval}.jsonl").exists() for interval in config.get("authentication_intervals", [1, 5, 10, 20])) and summary.exists():
        print(f"SKIP: {stage} -> output group files already exist (use --force to regenerate).")
        return
    if not force and any(path.exists() for path in stage_outputs(stage, config)):
        raise RuntimeError("Group outputs are incomplete; use --force explicitly or a new output directory.")
    output_dir.mkdir(parents=True, exist_ok=True)
    run_script(
        "src.processing.build_authentication_groups",
        str(repo_path(config["processed_trace"])),
        "--output-dir",
        str(output_dir),
        "--summary",
        str(summary),
        "--intervals",
        *[str(interval) for interval in config.get("authentication_intervals", [1, 5, 10, 20])],
    )


def run_signatures(config: dict, force: bool) -> None:
    output_dir = repo_path(config["signature_results_dir"])
    summary = output_dir / "signature_experiment_summary.json"
    if force and any(output_dir.glob("signatures_*.jsonl")):
        raise ValueError("Completed signatures are preserved. Use a new signature_results_dir for a fresh experiment.")
    output_dir.mkdir(parents=True, exist_ok=True)
    extra = ["--validate-only"] if config.get("validate_only") else []
    run_script(
        "src.experiment.generate_signatures",
        "--trace",
        str(repo_path(config["processed_trace"])),
        "--groups-dir",
        str(repo_path(config["authentication_groups_dir"])),
        "--config",
        str(repo_path(config["algorithms_config"])),
        "--output-dir",
        str(output_dir),
        "--summary",
        str(summary),
        "--intervals",
        *[str(interval) for interval in config.get("authentication_intervals", [1, 5, 10, 20])],
        "--checkpoint-every", str(config.get("signing", {}).get("checkpoint_every", 100)),
        "--progress-seconds", str(config.get("signing", {}).get("progress_seconds", 30)),
        *extra,
    )


def run_feasibility(config: dict, force: bool) -> None:
    output_dir = repo_path(config["signature_results_dir"]).parent / "feasibility"
    output_dir.mkdir(parents=True, exist_ok=True)
    options = config.get("operational_feasibility", {})
    allowed = {
        "payload_bytes", "bit_rate_bps", "loss_probability", "redundancy_factor",
        "fragment_overhead_bytes", "preamble_us", "frame_bits", "inter_frame_gap_us",
        "receiver_verification_ms", "sender_signing_ms", "background_occupancy",
        "max_channel_occupancy", "max_auth_latency_ms", "min_auth_success_probability",
    }
    unknown = set(options) - allowed
    if unknown:
        raise ValueError(f"Unknown operational_feasibility options: {sorted(unknown)}")
    extra = []
    for key, value in options.items():
        if value is not None:
            extra.extend(["--" + key.replace("_", "-"), str(value)])
    if force:
        extra.append("--force")
    if config.get("validate_only"):
        extra.append("--validate-only")
    run_script(
        "src.experiment.operational_feasibility",
        "--trace",
        str(repo_path(config["processed_trace"])),
        "--groups-dir",
        str(repo_path(config["authentication_groups_dir"])),
        "--signatures-dir",
        str(repo_path(config["signature_results_dir"])),
        "--config",
        str(repo_path(config["algorithms_config"])),
        "--output-dir",
        str(output_dir),
        "--intervals",
        *[str(interval) for interval in config.get("authentication_intervals", [1, 5, 10, 20])],
        *extra,
    )


def run_replay_experiment(config: dict, force: bool, mode: str) -> None:
    """Dispatch screening/replay with output-integrity validation on every run."""
    extra = []
    if mode == "replay" and config.get("replay_engine") in {"signed_before_send", "signed_detached"}:
        if not config.get("channel_trace"):
            raise ValueError("Signed full-study replay requires channel_trace.")
        if force:
            extra.append("--force")
        if config.get("validate_only"):
            extra.append("--validate-only")
        if config.get("signed_workloads_dir"):
            extra.extend(["--workloads-dir", str(repo_path(config["signed_workloads_dir"]))])
        run_script(
            "src.experiment.signed_experiment",
            "--trace", str(repo_path(config["processed_trace"])),
            "--channel-trace", str(repo_path(config["channel_trace"])),
            "--algorithms-config", str(repo_path(config.get("algorithms_config", "config/algorithms.json"))),
            "--hardware-profiles", str(repo_path(config.get("hardware_profiles", "config/hardware_profiles.json"))),
            "--scenarios", str(repo_path(config.get("replay_scenarios", "config/signed_replay_scenarios.json"))),
            "--replay-model", config["replay_engine"],
            "--output-dir", str(replay_output_dir(config)),
            "--intervals", *[str(k) for k in config.get("authentication_intervals", [1, 5, 10, 20])],
            *extra,
        )
        return
    sources = config.get("signature_size_sources", [config["signature_results_dir"]])
    if sources:
        extra.extend(["--signatures-dir", *[str(repo_path(path)) for path in sources]])
    if config.get("signature_size_profile"):
        extra.extend(["--size-profile", str(repo_path(config["signature_size_profile"]))])
    if mode in {"replay", "all"} and config.get("channel_trace"):
        extra.extend(["--channel-trace", str(repo_path(config["channel_trace"]))])
    if force:
        extra.append("--force")
    if config.get("validate_only"):
        extra.append("--validate-only")
    run_script(
        "src.experiment.replay_experiment",
        "--trace", str(repo_path(config["processed_trace"])),
        "--groups-dir", str(repo_path(config["authentication_groups_dir"])),
        "--algorithms-config", str(repo_path(config.get("algorithms_config", "config/algorithms.json"))),
        "--hardware-profiles", str(repo_path(config.get("hardware_profiles", "config/hardware_profiles.json"))),
        "--scenarios", str(repo_path(config.get("replay_scenarios", "config/replay_scenarios.json"))),
        "--output-dir", str(replay_output_dir(config)),
        "--intervals", *[str(interval) for interval in config.get("authentication_intervals", [1, 5, 10, 20])],
        "--mode", mode,
        *extra,
    )


def run_stage(stage: str, config: dict, force: bool) -> None:
    missing = missing_required(stage, config)
    if missing:
        missing_text = "\n  - ".join(str(path) for path in missing)
        raise FileNotFoundError(
            f"Cannot run '{stage}' because required input(s) are missing:\n  - {missing_text}"
        )

    if stage == "capture":
        run_capture(config, force)
        return
    if stage == "aircraft":
        run_aircraft(config, force)
        return
    if stage == "duplicates":
        run_duplicates(config, force)
        return
    if stage == "preprocess":
        run_preprocess(config, force)
        return
    if stage == "groups":
        run_groups(config, force)
        return
    if stage == "signatures":
        run_signatures(config, force)
        return
    if stage == "feasibility":
        run_feasibility(config, force)
        return
    if stage in {"screening", "replay"}:
        run_replay_experiment(config, force, stage)
        return
    raise ValueError(f"Unsupported stage: {stage}")


def main() -> None:
    def interrupted(signum, frame):
        raise KeyboardInterrupt(f"Received signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description="Config-driven pipeline for the ADS-B post-quantum evaluation.")
    parser.add_argument("--config", required=True, type=str, help="Path to a pipeline configuration JSON file.")
    parser.add_argument("--stage", choices=STAGE_ORDER + ["all"], default="all", help="Single stage to run. Default follows execution_stages, or the legacy pipeline if absent.")
    parser.add_argument("--from-stage", choices=STAGE_ORDER, help="Run from this stage through the configured execution_stages.")
    parser.add_argument("--force", action="store_true", help="Regenerate existing output files even when they already exist.")
    parser.add_argument("--validate-only", action="store_true", help="Audit configured signature, feasibility, screening, or replay outputs without regenerating them.")
    args = parser.parse_args()

    config = load_config(args.config)
    config["validate_only"] = args.validate_only

    if args.validate_only and args.force:
        parser.error("--validate-only cannot be combined with --force")
    try:
        selected = select_stages(config, args.stage, args.from_stage, args.validate_only)
    except ValueError as exc:
        parser.error(str(exc))

    output_dir = repo_path(config["signature_results_dir"])
    status_path = output_dir / "pipeline_status.json"
    with RunLock(REPO_ROOT / "results" / ".pipeline.lock"):
        status = {"pid": os.getpid(), "config": config["config_path"], "stages": selected,
                  "started_at": datetime.now(timezone.utc).isoformat(), "state": "running"}
        try:
            for stage in selected:
                status["stage"] = stage
                if not args.validate_only:
                    atomic_json(status_path, status)
                print(f"\n=== RUNNING STAGE: {stage} ===", flush=True)
                run_stage(stage, config, args.force)
        except BaseException as exc:
            status.update(state="interrupted" if isinstance(exc, KeyboardInterrupt) else "failed",
                          error=str(exc), finished_at=datetime.now(timezone.utc).isoformat())
            if not args.validate_only:
                atomic_json(status_path, status)
            raise
        status.update(state="complete", finished_at=datetime.now(timezone.utc).isoformat())
        if not args.validate_only:
            atomic_json(status_path, status)
        print("\n=== PIPELINE VALIDATION COMPLETE ===" if args.validate_only else "\n=== PIPELINE COMPLETE ===", flush=True)


if __name__ == "__main__":
    main()
