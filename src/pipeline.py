#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

STAGE_ORDER = [
    "capture",
    "aircraft",
    "duplicates",
    "preprocess",
    "groups",
    "signatures",
    "feasibility",
]


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
    ):
        if key in resolved and isinstance(resolved[key], str):
            resolved[key] = str(repo_path(resolved[key]))
    return resolved


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
    print(f"\n>>> {' '.join(command)}")
    subprocess.run(command, cwd=str(REPO_ROOT), check=True)


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
        "--output",
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
        "--output",
        str(output),
    )


def run_preprocess(config: dict, force: bool) -> None:
    stage = "preprocess"
    output_trace = repo_path(config["processed_trace"])
    output_manifest = stage_outputs(stage, config)[1]
    if not force and output_trace.exists() and output_manifest.exists():
        print(f"SKIP: {stage} -> {output_trace} and {output_manifest} already exist (use --force to regenerate).")
        return
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
    stage = "signatures"
    output_dir = repo_path(config["signature_results_dir"])
    summary = output_dir / "signature_experiment_summary.json"
    algorithms = enabled_algorithm_names(config)
    required = [summary]
    for interval in config.get("authentication_intervals", [1, 5, 10, 20]):
        for algorithm in algorithms:
            required.append(output_dir / f"signatures_{algorithm}_k{interval}.jsonl")
    if not force and all(path.exists() for path in required):
        print(f"SKIP: {stage} -> output signature files already exist (use --force to regenerate).")
        return
    output_dir.mkdir(parents=True, exist_ok=True)
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
    )


def run_feasibility(config: dict, force: bool) -> None:
    stage = "feasibility"
    output_dir = repo_path(config["signature_results_dir"]).parent / "feasibility"
    summary = output_dir / "operational_feasibility_summary.json"
    csv_path = output_dir / "feasibility_overview.csv"
    if not force and summary.exists() and csv_path.exists():
        print(f"SKIP: {stage} -> output feasibility files already exist (use --force to regenerate).")
        return
    output_dir.mkdir(parents=True, exist_ok=True)
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
        "--payload-bytes",
        "14",
        "--bit-rate-bps",
        "1000000",
        "--loss-probability",
        "0.01",
        "--redundancy-factor",
        "1.0",
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
    raise ValueError(f"Unsupported stage: {stage}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Config-driven pipeline for the ADS-B post-quantum evaluation.")
    parser.add_argument("--config", required=True, type=str, help="Path to a pipeline configuration JSON file.")
    parser.add_argument("--stage", choices=STAGE_ORDER + ["all"], default="all", help="Single stage to run. Default is the full pipeline.")
    parser.add_argument("--from-stage", choices=STAGE_ORDER, help="Run from the selected stage through the end of the pipeline.")
    parser.add_argument("--force", action="store_true", help="Regenerate existing output files even when they already exist.")
    args = parser.parse_args()

    config = load_config(args.config)

    if args.from_stage and args.stage != "all":
        raise ValueError("Use either --stage or --from-stage, not both.")

    if args.from_stage:
        start_index = STAGE_ORDER.index(args.from_stage)
        selected = STAGE_ORDER[start_index:]
    elif args.stage == "all":
        selected = STAGE_ORDER
    else:
        selected = [args.stage]

    for stage in selected:
        print(f"\n=== RUNNING STAGE: {stage} ===")
        run_stage(stage, config, args.force)

    print("\n=== PIPELINE COMPLETE ===")


if __name__ == "__main__":
    main()
