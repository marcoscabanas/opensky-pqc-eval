"""Run reproducible traffic screening and operational replay without signing.

Example: python -m src.experiment.replay_experiment --trace TRACE --groups-dir
GROUPS --algorithms-config config/algorithms.json --signatures-dir SIGNATURES
--output-dir RESULTS --mode all
"""

import argparse
import csv
import hashlib
import io
import json
import os
import tempfile
from contextlib import nullcontext
from pathlib import Path

from src.experiment.constraint_screening import build_size_profile, load_signature_sizes, screen
from src.experiment.generate_signatures import sha256_file
from src.experiment.hardware_profiles import load_profiles, timing_samples_ms
from src.experiment.operational_feasibility import collect_group_files, load_json, load_trace, validate_groups
from src.runtime import RunLock


SCHEMA_VERSION = 1
LEGACY_SCENARIO_FIELDS = {
    "max_auth_age_s", "max_batch_wait_s", "auth_frames_per_second", "receiver_workers",
    "sender_queue_limit", "receiver_queue_limit", "fragment_copies", "background_occupancy",
    "receive_jitter_ms", "loss", "max_events", "record_events",
}
DELAYED_SCENARIO_FIELDS = {
    "followup_s", "coverage_thresholds_s", "max_batch_wait_s", "auth_frames_per_second",
    "sender_queue_limit", "transmission_queue_limit", "receiver_queue_limit", "receiver_workers",
    "fragment_copies", "receive_jitter_ms", "loss", "max_events", "record_events", "channel_mode",
    "background_frames_per_second",
}
MODEL_FIELDS = {
    "deadline_authentication": LEGACY_SCENARIO_FIELDS,
    "delayed_authentication": DELAYED_SCENARIO_FIELDS,
    "signed_before_send": DELAYED_SCENARIO_FIELDS,
    "signed_detached": DELAYED_SCENARIO_FIELDS,
}
SIGNED_REPLAY_MODELS = {"signed_before_send", "signed_detached"}
SCENARIO_FIELDS = LEGACY_SCENARIO_FIELDS | DELAYED_SCENARIO_FIELDS | {"replay_model"}
OUTPUT_NAMES = {
    "screening": ("constraint_screening_summary.json", "constraint_screening_overview.csv"),
    "replay": ("replay_summary.json", "replay_overview.csv"),
}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_evidence(path):
    path = Path(path)
    return {"path": str(path), "sha256": sha256_file(path)}


def _source_evidence():
    """Hash model and validation code, excluding presentation/dispatch wrappers.

    Plot additions and pipeline UI edits cannot change computed replay results.
    Scientific source modules remain included, including newly added engines.
    """
    source_root = Path(__file__).resolve().parents[1]
    return {str(path.relative_to(source_root)): sha256_file(path)
            for path in sorted(source_root.rglob("*.py"))
            if path.name != "pipeline.py" and not path.name.startswith("plot")}


def _replay_model(parameters):
    model = parameters.get("replay_model", "deadline_authentication")
    if not isinstance(model, str) or model not in MODEL_FIELDS:
        raise ValueError(f"Unknown replay_model: {model!r}.")
    return model


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"Duplicate JSON key: {name}.")
        result[name] = value
    return result


def load_scenarios(path, selected=None, seeds=None):
    with Path(path).open(encoding="utf-8") as handle:
        document = json.load(handle, object_pairs_hook=_unique_object)
    if not isinstance(document, dict) or not isinstance(document.get("scenarios"), list):
        raise ValueError("Scenario configuration must contain a scenarios list.")
    scenarios = {}
    for scenario in document["scenarios"]:
        if not isinstance(scenario, dict) or set(scenario) - {"name", "sender_profile", "receiver_profile", "parameters", "description"}:
            raise ValueError("Scenario entries must be objects with known fields.")
        name = scenario.get("name")
        if not isinstance(name, str) or not name.strip() or name in scenarios:
            raise ValueError("Scenario names must be nonempty and unique.")
        if any(not isinstance(scenario.get(field), str) or not scenario[field].strip()
               for field in ("sender_profile", "receiver_profile")):
            raise ValueError(f"{name}: sender_profile and receiver_profile must be explicit profile names.")
        parameters = scenario.get("parameters")
        if not isinstance(parameters, dict):
            raise ValueError(f"{name}: unknown or missing scenario parameters.")
        model = _replay_model(parameters)
        if set(parameters) - (MODEL_FIELDS[model] | {"replay_model"}):
            raise ValueError(f"{name}: unknown scenario parameters for {model}.")
        scenarios[name] = scenario
    if not scenarios:
        raise ValueError("At least one scenario is required.")
    if selected is not None:
        if not selected or len(set(selected)) != len(selected) or set(selected) - set(scenarios):
            raise ValueError("Selected scenarios must be nonempty, unique and present in configuration.")
        scenarios = {name: scenarios[name] for name in selected}
    seeds = document.get("seeds", [1]) if seeds is None else seeds
    if (not isinstance(seeds, list) or not seeds or any(type(seed) is not int or seed < 0 for seed in seeds)
            or len(set(seeds)) != len(seeds)):
        raise ValueError("Seeds must be a nonempty list of unique nonnegative integers.")
    return list(scenarios.values()), seeds


def _csv_bytes(rows):
    fields = sorted({key for row in rows for key in row})
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
                         if isinstance(value, (dict, list)) else value for key, value in row.items()})
    return output.getvalue().encode("utf-8")


def outputs_match(summary_path, csv_path, input_fingerprint):
    """Check input/model identity, report integrity, and exact CSV row content."""
    try:
        report = load_json(Path(summary_path))
        content_hash = report.pop("report_sha256")
        if (report.get("input_fingerprint") != input_fingerprint
                or report.get("schema_version") != SCHEMA_VERSION or _digest(report) != content_hash):
            return False
        csv_content = Path(csv_path).read_bytes()
        return (hashlib.sha256(csv_content).hexdigest() == report.get("csv_sha256")
                and csv_content == _csv_bytes(report["rows"]))
    except (OSError, KeyError, ValueError, TypeError, AttributeError):
        return False


def _publish(summary_path, csv_path, report, *, profile_path=None):
    """Stage both files; publish the integrity-bearing JSON last as commit marker."""
    csv_content = _csv_bytes(report["rows"])
    report = {**report, "csv_sha256": hashlib.sha256(csv_content).hexdigest()}
    report["report_sha256"] = _digest(report)
    json_content = json.dumps(report, indent=2, allow_nan=False).encode("utf-8") + b"\n"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = []
    try:
        artifacts = [(csv_path, csv_content)]
        if profile_path is not None:
            artifacts.append((profile_path, json.dumps(report["signature_size_profile"], indent=2, allow_nan=False).encode("utf-8") + b"\n"))
        artifacts.append((summary_path, json_content))
        for destination, content in artifacts:
            with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=f".{destination.name}.", delete=False) as handle:
                temporary.append((Path(handle.name), destination))
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        for staged, destination in temporary:
            os.replace(staged, destination)
    finally:
        for staged, _ in temporary:
            staged.unlink(missing_ok=True)


def _simulate(trace, algorithm, interval, sizes, sender, receiver, scenario, seed=1, *, channel_trace=None):
    """Dispatch without modifying saved scenario parameters or importing eagerly."""
    parameters = dict(scenario)
    model = _replay_model(parameters)
    parameters.pop("replay_model", None)
    if model in SIGNED_REPLAY_MODELS:
        raise ValueError(f"Use src.experiment.signed_experiment for actual {model} replay.")
    if model == "delayed_authentication":
        from src.experiment.delayed_replay import simulate
        if channel_trace is not None:
            return simulate(trace, algorithm, interval, sizes, sender, receiver, parameters, seed,
                            channel_trace=channel_trace)
    else:
        if channel_trace is not None:
            raise ValueError("Observed channel traces require delayed_authentication replay.")
        from src.experiment.replay_simulator import simulate
    return simulate(trace, algorithm, interval, sizes, sender, receiver, parameters, seed)


def _profile_evidence(profile, algorithm, operation):
    entry = profile["algorithms"][algorithm]
    return {
        "id": profile["id"], "label": profile["label"], "kind": profile["kind"],
        "platform": profile["platform"], "limitations": profile.get("limitations", []),
        "implementation": entry["implementation"], "equivalence": entry["equivalence"],
        "limitation": entry.get("limitation"), "source_urls": entry["source_urls"],
        "timing": entry["operations"][operation],
    }


def run(args):
    """Execute selected cases, preserving matching artifacts and rejecting stale ones."""
    if args.force and args.validate_only:
        raise ValueError("--force and --validate-only are mutually exclusive.")
    modes = ["screening", "replay"] if args.mode == "all" else [args.mode]
    configs = {name: config for name, config in load_json(args.algorithms_config).items()
               if config.get("enabled", True)}
    algorithms = list(configs) if args.algorithm is None else args.algorithm
    if not algorithms or len(set(algorithms)) != len(algorithms) or set(algorithms) - set(configs):
        raise ValueError("Selected algorithms must be nonempty, unique and enabled.")
    configs = {name: configs[name] for name in algorithms}
    trace = load_trace(args.trace)
    groups = collect_group_files(args.groups_dir, args.intervals)
    for interval in args.intervals:
        validate_groups(trace, groups[interval], interval)
    sizes, sizing_provenance = load_signature_sizes(
        configs, args.signatures_dir, args.intervals, trace=trace, groups_by_interval=groups,
        size_profile=args.size_profile,
    )
    input_evidence = {
        "trace": _file_evidence(args.trace), "algorithms_config": _file_evidence(args.algorithms_config),
        "groups": {str(k): _file_evidence(args.groups_dir / f"authentication_groups_k{k}.jsonl") for k in args.intervals},
        "signature_sizing": sizing_provenance, "source_files_sha256": _source_evidence(),
    }
    if args.size_profile is not None:
        size_profile = load_json(args.size_profile)
        input_evidence["signature_size_profile"] = _file_evidence(args.size_profile)
    else:
        size_profile = build_size_profile(configs, sizes, sizing_provenance,
                                          trace_evidence=input_evidence["trace"], group_evidence=input_evidence["groups"])
    base_parameters = {"algorithms": algorithms, "intervals": args.intervals,
                       "signature_directories": [str(path) for path in args.signatures_dir]}
    profiles, scenarios, seeds = {}, [], []
    if "replay" in modes:
        profiles = load_profiles(args.hardware_profiles)
        scenarios, seeds = load_scenarios(args.scenarios, args.scenario, args.seeds)
        for scenario in scenarios:
            for role, operation in (("sender", "sign"), ("receiver", "verify")):
                identifier = scenario[f"{role}_profile"]
                if identifier not in profiles:
                    raise ValueError(f"Unknown {role} hardware profile: {identifier}.")
                for algorithm in algorithms:
                    timing_samples_ms(profiles[identifier], algorithm, operation)
    channel_trace = None
    channel_path = getattr(args, "channel_trace", None)
    if channel_path is not None:
        if "replay" not in modes:
            raise ValueError("--channel-trace applies to replay, not analytical screening alone.")
        if any(_replay_model(s["parameters"]) != "delayed_authentication" for s in scenarios):
            raise ValueError("Observed channel traces require delayed_authentication replay.")
        from src.experiment.channel_trace import load_channel_trace
        channel_trace = load_channel_trace(channel_path, trace)
    requests = {}
    for mode in modes:
        evidence, parameters = dict(input_evidence), dict(base_parameters)
        if mode == "replay":
            evidence.update(hardware_profiles=_file_evidence(args.hardware_profiles), scenarios=_file_evidence(args.scenarios))
            if channel_path is not None:
                evidence["channel_trace"] = _file_evidence(channel_path)
            parameters.update(scenarios=scenarios, seeds=seeds)
        identity = {"schema_version": SCHEMA_VERSION, "mode": mode, "provenance": evidence, "parameters": parameters}
        summary_name, csv_name = OUTPUT_NAMES[mode]
        paths = (args.output_dir / summary_name, args.output_dir / csv_name)
        fingerprint = _digest(identity)
        requests[mode] = {**identity, "input_fingerprint": fingerprint, "paths": paths}
    profile_output = args.output_dir / "signature_size_profile.json" if "screening" in modes else None
    profile_matches = False
    if profile_output is not None:
        try:
            profile_matches = load_json(profile_output) == size_profile
        except (OSError, ValueError):
            pass
        if not profile_matches and args.validate_only:
            raise ValueError("Existing signature size profile is missing, altered, or stale.")
        if not profile_matches and not args.force and (profile_output.exists()
                or any(path.exists() for request in requests.values() for path in request["paths"])):
            raise ValueError("Existing signature size profile is missing, altered, or stale; use --force to explicitly replace it.")
    # Check every destination before computing or publishing any replacement.
    for mode, request in requests.items():
        paths = request["paths"]
        request["cached"] = outputs_match(*paths, request["input_fingerprint"])
        if mode == "screening" and not profile_matches:
            request["cached"] = False
        if not request["cached"] and args.validate_only:
            raise ValueError(f"Existing {mode} outputs are missing, altered, or stale.")
        if not request["cached"] and not args.force and any(path.exists() for path in paths):
            raise ValueError(f"Existing {mode} outputs are incomplete, altered, or stale; use --force to explicitly replace them.")
    for mode, request in requests.items():
        if request["cached"]:
            print(f"VALIDATED: {mode} inputs, source model, parameters and output integrity; existing files preserved.", flush=True)
            continue
        common = {key: value for key, value in request.items() if key not in {"paths", "cached"}}
        common["signature_size_profile"] = size_profile
        if mode == "screening":
            result = screen(args.trace, args.groups_dir, args.algorithms_config, args.signatures_dir,
                            args.intervals, algorithms=algorithms, size_profile=args.size_profile)
            report = {**common, "screening_model_version": result["model_version"],
                      "rows": result["rows"], "assumptions": result["assumptions"],
                      "transport_parameters": result["parameters"]}
        else:
            rows, events, hardware_evidence = [], [], {}
            simulator_assumptions, simulator_parameters = [], {}
            total = len(scenarios) * len(seeds) * len(algorithms) * len(args.intervals)
            for scenario in scenarios:
                sender, receiver = profiles[scenario["sender_profile"]], profiles[scenario["receiver_profile"]]
                for algorithm in algorithms:
                    sender_evidence = _profile_evidence(sender, algorithm, "sign")
                    receiver_evidence = _profile_evidence(receiver, algorithm, "verify")
                    hardware_evidence[f"{scenario['name']}:{algorithm}"] = {
                        "sender": sender_evidence, "receiver": receiver_evidence,
                    }
                    for interval in args.intervals:
                        for seed in seeds:
                            print(f"REPLAY {len(rows) + 1}/{total}: {scenario['name']} {algorithm} k={interval} seed={seed}", flush=True)
                            result = _simulate(trace, algorithm, interval, sizes[algorithm, interval],
                                               sender, receiver, scenario["parameters"], seed,
                                               **({"channel_trace": channel_trace} if channel_trace is not None else {}))
                            if not isinstance(result, dict) or not isinstance(result.get("summary"), dict):
                                raise ValueError("Simulator must return a summary object.")
                            if result.get("complete") is False or result["summary"].get("complete") is False:
                                raise ValueError("Simulator stopped with incomplete results; no replay report will be published.")
                            simulator_assumptions.extend(result.get("assumptions", []))
                            if "parameters" in result:
                                simulator_parameters[scenario["name"]] = {
                                    **result["parameters"], "replay_model": _replay_model(scenario["parameters"]),
                                }
                            identity = {"scenario": scenario["name"], "algorithm": algorithm,
                                        "interval_k": interval, "seed": seed}
                            rows.append({**result["summary"], **identity,
                                         "replay_model": _replay_model(scenario["parameters"]),
                                         "group_outcomes": result.get("outcomes", result.get("outcome_counts", {})),
                                         "sender_profile": sender["id"], "receiver_profile": receiver["id"],
                                         "sender_profile_kind": sender["kind"], "receiver_profile_kind": receiver["kind"],
                                         "sender_timing_equivalence": sender_evidence["equivalence"],
                                         "receiver_timing_equivalence": receiver_evidence["equivalence"],
                                         "sender_timing_sample_kind": sender_evidence["timing"]["sample_kind"],
                                         "receiver_timing_sample_kind": receiver_evidence["timing"]["sample_kind"],
                                         "signature_sizing_basis": next(p["sizing_basis"] for p in sizing_provenance
                                                                        if p["algorithm"] == algorithm and p["interval_k"] == interval)})
                            if result.get("events"):
                                events.append({**identity, "events": result["events"]})
            report = {**common, "rows": rows, "events": events, "hardware_profiles_used": hardware_evidence,
                      "simulator_parameters": simulator_parameters,
                      "assumptions": list(dict.fromkeys([
                          "Authentication outcomes are modeled receiver reconstruction and service completion, not new cryptographic signature verification.",
                          "Detached per-message or batched authentication never holds an original surveillance frame for signing.",
                          "Configured authentication frame-rate budgets apply per aircraft and are hypothetical sensitivity assumptions, not regulatory allocations.",
                          "Published service-time means are constants; neither empirical timing tails, aircraft WCET nor certification is established.",
                          "When selected, the embedded composite profile mixes platforms and explicitly labeled lineage proxies; a constrained embedded receiver profile does not characterize a ground server.",
                          "Observed trace arrivals are a sender approximation; actual sender traffic, capture loss and uncaptured competing traffic are unknown.",
                          "Fixed-length signatures use configured sizes; Falcon sizes use validated saved metadata or an explicitly supplied portable calibration distribution. Calibration reuse is not signature coverage or verification of the current trace.",
                          "Simulated authentication objects do not contain newly generated signatures; variable lengths are sampled from the declared observed distribution, which is not a universal bound.",
                      ] + simulator_assumptions))}
        _publish(*request["paths"], report,
                 profile_path=profile_output if mode == "screening" and not profile_matches else None)
        print(f"WROTE: {request['paths'][0]} ({len(report['rows'])} rows)", flush=True)
    return {mode: str(request["paths"][0]) for mode, request in requests.items()}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--channel-trace", type=Path,
                        help="Complete observed 1090 MHz event JSONL, including target links and follow-up coverage.")
    parser.add_argument("--groups-dir", type=Path, required=True)
    parser.add_argument("--algorithms-config", type=Path, required=True)
    parser.add_argument("--signatures-dir", type=Path, nargs="+", default=[])
    parser.add_argument("--size-profile", type=Path,
                        help="Reuse an exported empirical size calibration on a new trace, without its signature files.")
    parser.add_argument("--hardware-profiles", type=Path, default=Path("config/hardware_profiles.json"))
    parser.add_argument("--scenarios", type=Path, default=Path("config/replay_scenarios.json"))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--intervals", type=int, nargs="+", default=[1, 5, 10, 20])
    parser.add_argument("--mode", choices=["screening", "replay", "all"], default="all")
    parser.add_argument("--scenario", nargs="+", help="Names of configured scenarios to run.")
    parser.add_argument("--algorithm", nargs="+", help="Enabled algorithm names to run.")
    parser.add_argument("--seeds", type=int, nargs="+", help="Override configured reproducible random seeds.")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--validate-only", action="store_true")
    return parser, parser.parse_args(argv)


def main(argv=None):
    parser, args = parse_args(argv)
    try:
        context = nullcontext() if args.validate_only else RunLock(args.output_dir / ".replay_experiment.lock")
        with context:
            run(args)
    except (ValueError, OSError, RuntimeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
