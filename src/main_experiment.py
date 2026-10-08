"""Numbered, provenance-checked workflow for the daytime and nighttime study.

The public commands share these functions. Preparation never substitutes sample
data; replay never creates a missing signature cache. Completed workloads are
reused, but an interrupted unfinished workload must be signed again.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import math
from pathlib import Path
from types import SimpleNamespace

from src.runtime import RunLock, atomic_json


ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ("daytime", "nighttime")
STAGES = ("prepare", "sign", "replay", "report", "compare", "all")


def _read(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _path(root, value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Configured file and directory paths must be nonempty strings.")
    return (root / value).resolve()


def load_config(path, *, root=ROOT):
    """Resolve all configured paths against the repository, not the shell cwd."""
    root = Path(root).resolve()
    path = _path(root, str(path))
    config = _read(path)
    if not isinstance(config, dict) or config.get("schema_version") != 1:
        raise ValueError("Experiment configuration requires schema_version: 1.")
    result = dict(config, config_path=path)
    for field in ("data_manifest", "algorithms_config", "hardware_profiles", "scenarios", "comparison_output"):
        result[field] = _path(root, config.get(field))
    intervals = config.get("intervals")
    if (not isinstance(intervals, list) or not intervals
            or any(type(k) is not int or k < 1 for k in intervals)
            or len(set(intervals)) != len(intervals)):
        raise ValueError("intervals must contain distinct positive integers.")
    for field, default in (("target_duration_s", 3600), ("followup_s", 600)):
        value = config.get(field, default)
        if (isinstance(value, bool) or not isinstance(value, (int, float))
                or not math.isfinite(value) or value <= 0):
            raise ValueError(f"{field} must be a finite positive number.")
        result[field] = value
    declared = config.get("windows", {})
    if not isinstance(declared, dict) or set(declared) != set(WINDOWS):
        raise ValueError("windows must define daytime and nighttime inputs and outputs.")
    result["windows"] = {}
    for name in WINDOWS:
        entry = declared[name]
        if not isinstance(entry, dict):
            raise ValueError(f"{name} must specify raw and output paths.")
        result["windows"][name] = {field: _path(root, entry.get(field)) for field in ("raw", "output")}
    outputs = [result["windows"][name]["output"] for name in WINDOWS] + [result["comparison_output"]]
    inputs = [path, result["data_manifest"], result["algorithms_config"], result["hardware_profiles"],
              result["scenarios"], *(result["windows"][name]["raw"] for name in WINDOWS)]
    if any(a == b or a in b.parents or b in a.parents
           for index, a in enumerate(outputs) for b in outputs[index + 1:]):
        raise ValueError("Window and comparison output directories must be separate.")
    if any(output == item or output in item.parents for output in outputs for item in inputs):
        raise ValueError("Output directories must not contain experiment inputs or configuration.")
    return result


def preflight_inputs(config, names):
    """Check every requested recording before starting any expensive stage."""
    from src.processing.prepare_recording import validate_recording_metadata

    for name in names:
        path = config["windows"][name]["raw"]
        if not path.is_file():
            raise ValueError(f"Missing {name} recording: {path}. Place the original 70-minute JSONL there "
                             f"and complete its entry in {config['data_manifest']}. No sample data is substituted.")
    manifest = _read(config["data_manifest"])
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ValueError("Data manifest requires schema_version: 1.")
    entries = manifest.get("windows", {})
    if not isinstance(entries, dict):
        raise ValueError("Data manifest windows must contain named recording metadata objects.")
    for name in names:
        if not isinstance(entries.get(name), dict):
            raise ValueError(f"Data manifest must describe the {name} recording under windows.{name}.")
        try:
            validate_recording_metadata(entries[name], config["target_duration_s"], config["followup_s"])
        except ValueError as error:
            raise ValueError(f"Invalid {name} recording metadata in {config['data_manifest']}: {error}") from error
    return {name: entries[name] for name in names}


def prepare_window(config, name, metadata, *, validate_only=False):
    from src.processing.prepare_recording import prepare_recording, validate_prepared_recording

    entry = config["windows"][name]
    operation = validate_prepared_recording if validate_only else prepare_recording
    prepared = operation(entry["raw"], entry["output"] / "01_prepared", metadata,
                         target_duration_s=config["target_duration_s"], followup_s=config["followup_s"])
    if not validate_only:
        from src.experiment.main_report import plot_traffic
        plot_traffic(entry["output"] / "01_prepared", entry["output"] / "figures", name.capitalize())
    return prepared


def _study_cases(config):
    from src.experiment.replay_artifacts import load_scenarios
    from src.experiment.model_support import validate_scenario
    from src.experiment.hardware_profiles import load_profiles, timing_samples_ms

    entries = _read(config["algorithms_config"])
    if not isinstance(entries, dict):
        raise ValueError("Algorithm configuration must be an object.")
    algorithms = [name for name, entry in entries.items() if entry.get("enabled", True)]
    if not algorithms:
        raise ValueError("At least one signature algorithm must be enabled.")
    scenarios, seeds = load_scenarios(config["scenarios"])
    profiles = load_profiles(config["hardware_profiles"])
    for scenario in scenarios:
        parameters = dict(scenario["parameters"])
        if parameters.pop("replay_model", None) != "signed_detached":
            raise ValueError("The main experiment requires signed_detached scenarios.")
        parameters = validate_scenario(parameters)
        if parameters["max_batch_wait_s"] is not None:
            raise ValueError("The main experiment uses exact-count grouping with no batch timeout.")
        if parameters["followup_s"] != config["followup_s"]:
            raise ValueError("Scenario followup_s differs from the experiment's recording follow-up.")
        if parameters["background_frames_per_second"]:
            raise ValueError("The main experiment uses recorded traffic, not synthetic background.")
        for role, operation in (("sender", "sign"), ("receiver", "verify")):
            profile = profiles.get(scenario[f"{role}_profile"])
            if profile is None:
                raise ValueError(f"Unknown {role} profile {scenario[f'{role}_profile']}.")
            for algorithm in algorithms:
                timing_samples_ms(profile, algorithm, operation)
    return algorithms, scenarios, seeds


def _portable_workload(evidence):
    """Cache directory names are content hashes; never bind an inventory to a checkout."""
    return {**evidence, "cache_dir": Path(evidence["cache_dir"]).name}


def _signing_inputs(config, name):
    output = config["windows"][name]["output"]
    algorithms, scenarios, _ = _study_cases(config)
    prepared = output / "01_prepared"
    cache = output / "02_signed"
    identity = {"schema_version": 1, "trace_sha256": _sha256(prepared / "trace.jsonl"),
                "preparation_manifest_sha256": _sha256(prepared / "manifest.json"),
                "algorithms_config_sha256": _sha256(config["algorithms_config"]),
                "algorithms": algorithms, "intervals": config["intervals"], "max_batch_wait_s": None}
    return algorithms, scenarios, prepared, cache, identity


def validate_signature_inventory(config, name):
    """Check stage-2 completion and hashes; the replay engine verifies signatures.

    This avoids verifying every expensive workload twice before each replay.
    ``require_workloads`` then prevents the engine from creating absent caches.
    """
    algorithms, _, _, cache, identity = _signing_inputs(config, name)
    inventory_path = cache / "signatures_manifest.json"
    if not inventory_path.is_file():
        raise ValueError(f"Completed signature inventory is missing: {inventory_path}. Run step 02_sign first.")
    inventory = _read(inventory_path)
    if inventory.get("identity") != identity or inventory.get("complete") is not True:
        raise ValueError("Signature inventory does not match the prepared trace and experiment settings.")
    expected = {f"{algorithm}:k={interval}" for algorithm in algorithms for interval in config["intervals"]}
    if set(inventory.get("workloads", {})) != expected:
        raise ValueError("Signature inventory does not contain every requested algorithm and group size.")
    for evidence in inventory["workloads"].values():
        name = evidence.get("cache_dir")
        if not isinstance(name, str) or name in ("", ".", "..") or Path(name).name != name:
            raise ValueError("Signature cache paths must be directory names inside 02_signed.")
        directory = cache / name
        if not directory.resolve().is_relative_to(cache.resolve()):
            raise ValueError("Signature cache cannot escape 02_signed.")
        for filename, field in (("manifest.json", "manifest_sha256"),
                                ("groups.jsonl", "groups_sha256"), ("public_keys.json", "public_keys_sha256")):
            if not (directory / filename).is_file() or _sha256(directory / filename) != evidence.get(field):
                raise ValueError(f"Signed cache is missing or altered: {directory / filename}. Run step 02_sign to inspect it.")
    return inventory


def sign_window(config, name, *, validate_only=False):
    from src.experiment.io_support import load_trace
    from src.experiment.signed_workload import backend_identity, build_or_load_workload
    from src.experiment.channel_trace import load_channel_trace, replay_window as bounds, validate_coverage
    from src.experiment.model_support import validate_scenario

    algorithms, scenarios, prepared, cache, identity = _signing_inputs(config, name)
    configured = _read(config["algorithms_config"])
    # Check every backend before beginning slow workloads.
    for algorithm in algorithms:
        backend = backend_identity(algorithm)
        if any(configured[algorithm].get(key) != backend[key] for key in ("module", "implementation")):
            raise ValueError(f"{algorithm}: configured implementation differs from the installed signing backend.")
    trace = load_trace(prepared / "trace.jsonl")
    if scenarios:
        channel = load_channel_trace(prepared / "channel.jsonl", trace)
        for scenario in scenarios:
            parameters = dict(scenario["parameters"])
            parameters.pop("replay_model")
            parameters = validate_scenario(parameters)
            _, _, horizon = bounds(trace, channel, parameters["followup_s"], parameters["receive_jitter_ms"])
            validate_coverage(channel, horizon)
            if len(trace) + sum(t <= horizon for t in channel["extra_starts"]) > parameters["max_events"]:
                raise ValueError("Input traffic alone exceeds max_events; choose an explicit larger event budget before signing.")
        del channel
    inventory_path = cache / "signatures_manifest.json"
    previous = _read(inventory_path) if inventory_path.exists() else None
    if validate_only and previous is None:
        raise ValueError(f"Completed signature inventory is missing: {inventory_path}. Run step 02_sign first.")
    if previous is not None and previous.get("identity") != identity:
        raise ValueError("The signature inventory is stale for these inputs/settings. Preserve the previous "
                         "results and select a new output directory before rebuilding.")
    workloads = {}
    for algorithm in algorithms:
        for interval in config["intervals"]:
            print(f"SIGNATURES: {name}, {algorithm}, k={interval}" +
                  (" (validate cached signatures)" if validate_only or previous else " (build or reuse)"), flush=True)
            workload = build_or_load_workload(trace, algorithm, interval, None, cache,
                                             validate_only=validate_only or previous is not None)
            workloads[f"{algorithm}:k={interval}"] = _portable_workload(workload["evidence"])
            del workload
    inventory = {"identity": identity, "workloads": workloads, "complete": True}
    if previous is not None:
        if previous != inventory:
            raise ValueError("Signed caches differ from the saved signature inventory.")
    else:
        atomic_json(inventory_path, inventory)
    return inventory


def replay_window(config, name, *, validate_only=False):
    from src.experiment.signed_experiment import run

    # Stage 3 may only consume caches explicitly completed by stage 2.
    validate_signature_inventory(config, name)
    output = config["windows"][name]["output"]
    return run(SimpleNamespace(
        trace=output / "01_prepared" / "trace.jsonl",
        channel_trace=output / "01_prepared" / "channel.jsonl",
        algorithms_config=config["algorithms_config"], hardware_profiles=config["hardware_profiles"],
        scenarios=config["scenarios"], output_dir=output / "03_replay", workloads_dir=output / "02_signed",
        intervals=config["intervals"], algorithm=None, scenario=None, seeds=None,
        replay_model="signed_detached", force=False, validate_only=validate_only, require_workloads=True,
    ))


def report_window(config, name, *, validate_only=False):
    from src.experiment.main_report import generate_report

    # Validate replay provenance and cryptography before presenting its findings.
    replay_window(config, name, validate_only=True)
    return generate_report(config["windows"][name]["output"], name.capitalize(), validate_only=validate_only)


def compare(config, *, validate_only=False):
    from src.experiment.main_report import compare_windows

    return compare_windows(config["windows"]["daytime"]["output"],
                           config["windows"]["nighttime"]["output"],
                           config["comparison_output"], validate_only=validate_only)


def run(config, *, window="daytime", stage="all", validate_only=False):
    if window not in (*WINDOWS, "both") or stage not in STAGES:
        raise ValueError("Unknown window or stage.")
    if stage == "compare" and window != "both":
        raise ValueError("Comparison requires --window both.")
    names = WINDOWS if window == "both" else (window,)
    metadata = preflight_inputs(config, names)
    result = {}
    with ExitStack() as locks:
        if not validate_only:
            for name in names:
                locks.enter_context(RunLock(config["windows"][name]["output"] / ".pipeline.lock"))
        for name in names:
            output = config["windows"][name]["output"]
            print(f"WINDOW: {name}; stage: {stage}; output: {output}", flush=True)
            steps = ("prepare", "sign", "replay", "report") if stage == "all" else (stage,)
            if stage not in ("all", "prepare"):
                prepare_window(config, name, metadata[name], validate_only=True)
            for selected in steps:
                if selected == "prepare":
                    result[f"{name}:prepare"] = prepare_window(config, name, metadata[name], validate_only=validate_only)
                elif selected == "sign":
                    result[f"{name}:sign"] = sign_window(config, name, validate_only=validate_only)
                elif selected == "replay":
                    result[f"{name}:replay"] = replay_window(config, name, validate_only=validate_only)
                elif selected == "report":
                    result[f"{name}:report"] = report_window(config, name, validate_only=validate_only)
                elif selected == "compare":
                    replay_window(config, name, validate_only=True)
        if window == "both" and stage in ("all", "compare"):
            if not validate_only:
                locks.enter_context(RunLock(config["comparison_output"] / ".pipeline.lock"))
            result["comparison"] = compare(config, validate_only=validate_only)
    return result


def main(argv=None, *, fixed_stage=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--window", choices=(*WINDOWS, "both"), required=True)
    parser.add_argument("--config", type=Path, default=ROOT / "config" / "experiment.json",
                        help="Experiment configuration; contained paths are relative to the repository root.")
    if fixed_stage is None:
        parser.add_argument("--stage", choices=STAGES, default="all")
    parser.add_argument("--validate-only", action="store_true",
                        help="Check existing outputs and cryptographic signatures without creating results.")
    args = parser.parse_args(argv)
    try:
        run(load_config(args.config), window=args.window, stage=fixed_stage or args.stage,
            validate_only=args.validate_only)
    except (OSError, ValueError, RuntimeError, KeyError, ImportError) as exc:
        parser.exit(2, f"ERROR: {exc}\n")
    print("VALIDATED existing experiment outputs." if args.validate_only else "DONE. Requested stages completed.",
          flush=True)


if __name__ == "__main__":
    main()
