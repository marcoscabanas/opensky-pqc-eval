"""Generate real signed workloads, then replay detached or before-send authentication.

This module runs the main study using real signatures and measured input bytes.
Only one algorithm/grouping workload is held in memory at a time; its exact
signature bytes are reused across receiver/channel scenarios. The declared
deterministic experiment needs one replay per case; seeds are retained only for
optional stochastic sensitivity studies.
"""

import argparse
from contextlib import nullcontext
import json
import os
from pathlib import Path
import tempfile

from src.experiment.channel_trace import load_channel_trace, validate_coverage, replay_window
from src.experiment.model_support import validate_scenario
from src.experiment.hardware_profiles import load_profiles, timing_samples_ms
from src.experiment.io_support import load_json, load_trace
from src.experiment.replay_artifacts import (
    SCHEMA_VERSION, SIGNED_REPLAY_MODELS, _digest, _file_evidence, _profile_evidence, _publish,
    _source_evidence, load_scenarios, outputs_match,
)
from src.runtime import RunLock


def _validate_rows(rows, scenarios, algorithms, intervals, seeds, count):
    expected = {(s["name"], a, k, seed) for s in scenarios for a in algorithms for k in intervals for seed in seeds}
    actual = [(r.get("scenario"), r.get("algorithm"), r.get("interval_k"), r.get("seed")) for r in rows]
    if len(actual) != len(expected) or set(actual) != expected:
        raise ValueError("Signed replay case matrix is incomplete or duplicated.")
    models = {s["name"]: s["parameters"]["replay_model"] for s in scenarios}
    for row in rows:
        if row.get("replay_model") != models[row["scenario"]] or row.get("source_messages") != count:
            raise ValueError("Signed replay model or source population mismatch.")
        fields = ("authenticated_messages", "definitive_failure_messages", "unresolved_messages",
                  "augmented_original_received_messages", "received_definitive_failure_messages",
                  "received_unresolved_messages")
        if any(type(row.get(key)) is not int or row[key] < 0 for key in fields):
            raise ValueError("Signed replay outcome counts must be nonnegative integers.")
        success, failed, pending, received, rx_failed, rx_pending = (row[key] for key in fields)
        if (success + failed + pending != count or received > count
                or success + rx_failed + rx_pending != received):
            raise ValueError("Signed replay outcomes do not conserve source messages and receptions.")
        stages = ("authenticated_groups", "cryptographically_valid_groups", "verification_completed_groups",
                  "verification_started_groups", "reconstructed_signing_input_groups",
                  "complete_authentication_object_groups", "source_groups")
        other_counts = ("invalid_signature_groups", "verification_pending_groups",
                        "authentication_pending_groups", "authentication_definitive_failure_groups")
        if any(type(row.get(key)) is not int or row[key] < 0 for key in stages + other_counts):
            raise ValueError("Signed replay authentication stages must be nonnegative integer counts.")
        if any(row[left] > row[right] for left, right in zip(stages, stages[1:])):
            raise ValueError("Signed replay authentication stages are inconsistent.")
        if (row["source_groups"] != row["authenticated_groups"] + row["authentication_pending_groups"]
                + row["authentication_definitive_failure_groups"]
                or row["verification_completed_groups"] != row["cryptographically_valid_groups"]
                + row["invalid_signature_groups"]):
            raise ValueError("Signed replay authentication stages do not conserve groups.")


def _load_case(path, identity):
    """Accept only an intact case tied to current inputs, code and signed bytes."""
    document = load_json(path)
    checksum = document.pop("checkpoint_sha256", None)
    if document.get("identity") != identity or checksum != _digest(document):
        raise ValueError("Signed replay case checkpoint is stale or altered; use --force explicitly.")
    if not isinstance(document.get("row"), dict) or not isinstance(document.get("assumptions"), list):
        raise ValueError("Signed replay case checkpoint is malformed; use --force explicitly.")
    return document


def _save_case(path, document):
    """Publish one complete case atomically so interruption preserves prior work."""
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {**document, "checkpoint_sha256": _digest(document)}
    staged = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".case-", delete=False) as stream:
            staged = Path(stream.name)
            json.dump(document, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(staged, path)
    finally:
        if staged is not None:
            staged.unlink(missing_ok=True)


def run(args):
    if args.force and args.validate_only:
        raise ValueError("--force and --validate-only are mutually exclusive.")
    if (not args.intervals or any(type(k) is not int or k < 1 for k in args.intervals)
            or len(set(args.intervals)) != len(args.intervals)):
        raise ValueError("Intervals must be distinct positive integers.")
    configurations = load_json(args.algorithms_config)
    enabled = {name: entry for name, entry in configurations.items() if entry.get("enabled", True)}
    algorithms = list(enabled) if args.algorithm is None else args.algorithm
    if not algorithms or len(set(algorithms)) != len(algorithms) or set(algorithms) - set(enabled):
        raise ValueError("Algorithms must be distinct enabled configuration entries.")
    scenarios, seeds = load_scenarios(args.scenarios, args.scenario, args.seeds)
    models = {scenario["parameters"].get("replay_model") for scenario in scenarios}
    if not models <= SIGNED_REPLAY_MODELS:
        raise ValueError("This entry point requires signed_detached or signed_before_send scenarios.")
    if len(models) != 1:
        raise ValueError("Do not mix signed_detached and signed_before_send models in one report; use separate runs.")
    model = next(iter(models))
    if getattr(args, "replay_model", None) not in (None, model):
        raise ValueError("The requested replay model does not match the scenario configuration.")
    profiles = load_profiles(args.hardware_profiles)
    trace = load_trace(args.trace)
    channel = load_channel_trace(args.channel_trace, trace)
    normalized, hardware = {}, {}
    for scenario in scenarios:
        parameters = dict(scenario["parameters"])
        parameters.pop("replay_model")
        parameters = validate_scenario(parameters)
        if parameters["background_frames_per_second"]:
            raise ValueError("Observed channel traffic cannot be combined with synthetic background.")
        # Fail missing follow-up before spending time generating signatures.
        _, _, required_horizon = replay_window(trace, channel, parameters["followup_s"], parameters["receive_jitter_ms"])
        validate_coverage(channel, required_horizon)
        if len(trace) + sum(t <= required_horizon for t in channel["extra_starts"]) > parameters["max_events"]:
            raise ValueError("Input traffic alone exceeds max_events; choose an explicit larger event budget before signing.")
        normalized[scenario["name"]] = parameters
        for role, operation in (("sender", "sign"), ("receiver", "verify")):
            profile_id = scenario[f"{role}_profile"]
            if profile_id not in profiles:
                raise ValueError(f"Unknown {role} profile {profile_id}.")
            for algorithm in algorithms:
                timing_samples_ms(profiles[profile_id], algorithm, operation)
        for algorithm in algorithms:
            hardware[f"{scenario['name']}:{algorithm}"] = {
                role: _profile_evidence(profiles[scenario[f"{role}_profile"]], algorithm, operation)
                for role, operation in (("sender", "sign"), ("receiver", "verify"))
            }
    evidence = {name: _file_evidence(getattr(args, name))
                for name in ("trace", "channel_trace", "algorithms_config", "hardware_profiles", "scenarios")}
    evidence["source_files_sha256"] = _source_evidence()
    parameters = {"algorithms": algorithms, "intervals": args.intervals,
                  "scenarios": scenarios, "seeds": seeds, "replay_model": model}
    if getattr(args, "analysis_context", None) is not None:
        evidence["analysis_context"] = args.analysis_context
    request = {"schema_version": SCHEMA_VERSION, "mode": "replay",
               "provenance": evidence, "parameters": parameters}
    request_hash = _digest(request)
    summary_path, csv_path = (args.output_dir / name for name in ("replay_summary.json", "replay_overview.csv"))
    prior = None
    if summary_path.exists() or csv_path.exists():
        try:
            candidate = load_json(summary_path)
            matching = (candidate.get("request_sha256") == request_hash
                        and outputs_match(summary_path, csv_path, candidate.get("input_fingerprint")))
        except (OSError, ValueError, KeyError, TypeError):
            matching = False
        if matching and not args.force:
            prior = candidate
        elif not args.force:
            raise ValueError("Signed replay outputs are incomplete, altered, or stale; use a new directory or --force.")
    elif args.validate_only:
        raise ValueError("Signed replay outputs are missing; validation cannot generate them.")

    from src.experiment.signed_workload import backend_identity, build_or_load_workload
    from src.experiment.signed_replay import simulate
    for algorithm in algorithms:
        identity = backend_identity(algorithm)
        for key in ("module", "implementation"):
            if enabled[algorithm].get(key) != identity[key]:
                raise ValueError(f"{algorithm}: configured {key} does not match the actual signing backend.")
    cache = args.workloads_dir or args.output_dir / "signed_workloads"
    rows, events, assumptions, workloads = [], [], [], {}
    policies = list(dict.fromkeys(normalized[item["name"]]["max_batch_wait_s"] for item in scenarios))
    total = len(scenarios) * len(algorithms) * len(args.intervals) * len(seeds)
    for algorithm in algorithms:
        for interval in args.intervals:
            for wait in policies:
                key = f"{algorithm}:k={interval}:max_batch_wait_s={wait}"
                print(f"SIGNED WORKLOAD: {key}", flush=True)
                workload = build_or_load_workload(trace, algorithm, interval, wait, cache,
                                                 validate_only=args.validate_only or prior is not None or getattr(args, "require_workloads", False))
                # Artifact identity must survive copying a published cache into a new checkout.
                workload["evidence"] = {**workload["evidence"], "cache_dir": Path(workload["evidence"]["cache_dir"]).name}
                workloads[key] = workload["evidence"]
                if prior is not None:
                    if prior["provenance"].get("signed_workloads", {}).get(key) != workload["evidence"]:
                        raise ValueError("Signed workload differs from saved replay provenance; use --force explicitly.")
                    del workload
                    continue
                for scenario in scenarios:
                    configuration = normalized[scenario["name"]]
                    if configuration["max_batch_wait_s"] != wait:
                        continue
                    sender, receiver = (profiles[scenario[f"{role}_profile"]] for role in ("sender", "receiver"))
                    for seed in seeds:
                        case = {"scenario": scenario["name"], "algorithm": algorithm,
                                "interval_k": interval, "seed": seed}
                        checkpoint_identity = {"schema_version": 1, "request_sha256": request_hash,
                                               "case": case, "signed_workload": workload["evidence"]}
                        checkpoint_path = args.output_dir / "cases" / request_hash / f"{_digest(case)}.json"
                        if checkpoint_path.exists() and not args.force:
                            checkpoint = _load_case(checkpoint_path, checkpoint_identity)
                            _validate_rows([checkpoint["row"]], [scenario], [algorithm], [interval],
                                           [seed], len(trace))
                            rows.append(checkpoint["row"])
                            assumptions.extend(checkpoint["assumptions"])
                            if checkpoint.get("events"):
                                events.append({**case, "events": checkpoint["events"]})
                            print(f"RESUMED CASE {len(rows)}/{total}: {scenario['name']} {algorithm} k={interval} seed={seed}", flush=True)
                            continue
                        print(f"SIGNED REPLAY {len(rows) + 1}/{total}: {scenario['name']} {algorithm} k={interval} seed={seed}", flush=True)
                        result = simulate(trace, algorithm, interval, workload, sender, receiver,
                                          configuration, seed, channel_trace=channel, replay_model=model)
                        if (not isinstance(result, dict) or not isinstance(result.get("summary"), dict)
                                or result.get("complete") is False or result["summary"].get("complete") is False):
                            raise ValueError("Incomplete signed replay; no partial report may be published.")
                        if result["summary"].get("replay_model", model) != model:
                            raise ValueError("Signed replay engine returned a different model.")
                        timing = hardware[f"{scenario['name']}:{algorithm}"]
                        row = {**result["summary"], **case, "replay_model": model,
                                     "group_outcomes": result.get("outcomes", {}),
                                     "sender_profile": sender["id"], "receiver_profile": receiver["id"],
                                     "sender_profile_kind": sender["kind"], "receiver_profile_kind": receiver["kind"],
                                     "sender_timing_equivalence": timing["sender"]["equivalence"],
                                     "receiver_timing_equivalence": timing["receiver"]["equivalence"],
                                     "sender_timing_sample_kind": timing["sender"]["timing"]["sample_kind"],
                                     "receiver_timing_sample_kind": timing["receiver"]["timing"]["sample_kind"],
                                     "signature_sizing_basis": "actual_signed_context_and_raw_messages"}
                        _validate_rows([row], [scenario], [algorithm], [interval], [seed], len(trace))
                        _save_case(checkpoint_path, {"identity": checkpoint_identity, "row": row,
                                   "assumptions": result.get("assumptions", []),
                                   "events": result.get("events", [])})
                        rows.append(row)
                        print(f"CHECKPOINTED CASE {len(rows)}/{total}", flush=True)
                        assumptions.extend(result.get("assumptions", []))
                        if result.get("events"):
                            events.append({**case, "events": result["events"]})
                del workload
    if prior is not None:
        if set(prior["provenance"].get("signed_workloads", {})) != set(workloads):
            raise ValueError("Saved signed-workload inventory differs from the requested cases.")
        identity = {**request, "provenance": {**evidence, "signed_workloads": workloads}}
        if (prior.get("input_fingerprint") != _digest(identity)
                or any(prior.get(key) != value for key, value in identity.items())):
            raise ValueError("Signed replay identity does not match current inputs and verified workloads.")
        _validate_rows(prior["rows"], scenarios, algorithms, args.intervals, seeds, len(trace))
        print("VALIDATED: signed replay, exact signatures, inputs, source, and output integrity.", flush=True)
        return {"replay": str(summary_path)}
    identity = {**request, "provenance": {**evidence, "signed_workloads": workloads}}
    _validate_rows(rows, scenarios, algorithms, args.intervals, seeds, len(trace))
    report = {**identity, "request_sha256": request_hash, "input_fingerprint": _digest(identity),
              "rows": rows, "events": events, "hardware_profiles_used": hardware,
              "simulator_parameters": {name: {**values, "replay_model": model}
                                       for name, values in normalized.items()},
              "assumptions": list(dict.fromkeys(assumptions))}
    _publish(summary_path, csv_path, report)
    print(f"WROTE: {summary_path} ({len(rows)} real-signature replay cases)", flush=True)
    return {"replay": str(summary_path)}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--channel-trace", type=Path, required=True)
    parser.add_argument("--algorithms-config", type=Path, default=Path("config/algorithms.json"))
    parser.add_argument("--hardware-profiles", type=Path, default=Path("config/hardware_profiles.json"))
    parser.add_argument("--scenarios", type=Path, default=Path("config/signed_replay_scenarios.json"))
    parser.add_argument("--replay-model", choices=sorted(SIGNED_REPLAY_MODELS),
                        help="Require scenarios to use this model; otherwise infer it from the scenario file.")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--workloads-dir", type=Path)
    parser.add_argument("--intervals", type=int, nargs="+", default=[1, 5, 10, 20])
    parser.add_argument("--algorithm", nargs="+")
    parser.add_argument("--scenario", nargs="+")
    parser.add_argument("--seeds", type=int, nargs="+")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--validate-only", action="store_true")
    return parser, parser.parse_args(argv)


def main(argv=None):
    parser, args = parse_args(argv)
    try:
        context = nullcontext() if args.validate_only else RunLock(args.output_dir / ".replay_experiment.lock")
        with context:
            run(args)
    except (OSError, ValueError, RuntimeError, KeyError, ImportError) as error:
        parser.exit(2, f"ERROR: {error}\n")


if __name__ == "__main__":
    main()
