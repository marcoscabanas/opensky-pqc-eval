#!/usr/bin/env python3
"""Compare a locally reproduced signed replay with a preserved reference.

Requires only Python's standard library. Run the native pipeline's
--validate-only check first to reverify the actual signatures. This command
checks report/CSV integrity, local input/source/public-cache bytes, the complete
case matrix, outcome conservation, and matching scientific values. It does not
perform cryptographic verification or assert that a report was independently
recomputed. Only documented file/cache location fields may differ.
"""

import argparse
import copy
import csv
import hashlib
import io
import itertools
import json
import math
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
FILE_INPUTS = ("trace", "channel_trace", "algorithms_config", "hardware_profiles", "scenarios")
CASE_FIELDS = ("scenario", "algorithm", "interval_k", "seed")
MODELS = {"signed_detached", "signed_before_send"}
ABS_TOLERANCE = 1e-9
REL_TOLERANCE = 1e-12


class ComparisonError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ComparisonError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_digest(path):
    checksum = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def _object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path):
    def nonfinite(value):
        raise ComparisonError(f"Nonfinite JSON value: {value}")
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_object,
                      parse_constant=nonfinite)


def csv_bytes(rows):
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=sorted({key for row in rows for key in row}),
                            lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
                         if isinstance(value, (dict, list)) else value for key, value in row.items()})
    return stream.getvalue().encode("utf-8")


def count(value, label, minimum=0):
    require(type(value) is int and value >= minimum, f"{label}: expected integer >= {minimum}")
    return value


def sha(value, label):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), f"{label}: invalid SHA256")
    return value


def _distinct(values, label):
    require(isinstance(values, list) and values, f"{label}: empty or missing case dimension")
    require(len(set(values)) == len(values), f"{label}: duplicate case dimension")
    return values


def check_outcomes(row, label):
    n = count(row["source_messages"], f"{label}.source_messages", 1)
    get = lambda key: count(row[key], f"{label}.{key}")
    require(get("trace_messages") == n, f"{label}: trace/source counts disagree")
    baseline, received, success = (get(key) for key in (
        "baseline_original_received_messages", "augmented_original_received_messages", "authenticated_messages"))
    require(baseline + get("baseline_original_lost_messages") == n and received <= n,
            f"{label}: ordinary reception counts do not conserve messages")
    require(success + get("definitive_failure_messages") + get("unresolved_messages") == n
            and success + get("received_definitive_failure_messages") + get("received_unresolved_messages") == received,
            f"{label}: authentication outcomes do not conserve messages")
    require(get("ordinary_frames_transmitted") + get("ordinary_messages_unsent_pending")
            + get("ordinary_messages_withheld_definitively") == n,
            f"{label}: ordinary transmission outcomes do not conserve messages")
    require(received + get("ordinary_frames_rf_lost") + get("ordinary_frames_in_flight_at_horizon")
            == get("ordinary_frames_transmitted"), f"{label}: ordinary frame outcomes do not conserve transmissions")
    require(get("auth_frames_received") + get("auth_frames_lost") + get("auth_frames_in_flight_at_horizon")
            == get("auth_frames_transmitted"), f"{label}: fragment outcomes do not conserve transmissions")
    stages = ("authenticated_groups", "cryptographically_valid_groups", "verification_completed_groups",
              "verification_started_groups", "reconstructed_signing_input_groups",
              "complete_authentication_object_groups", "source_groups")
    stage_counts = [get(key) for key in stages]
    require(all(left <= right for left, right in zip(stage_counts, stage_counts[1:])),
            f"{label}: authentication stage counts are inconsistent")
    require(get("verification_completed_groups") == get("cryptographically_valid_groups") + get("invalid_signature_groups")
            and get("source_groups") == get("authenticated_groups") + get("authentication_pending_groups")
            + get("authentication_definitive_failure_groups"), f"{label}: group outcomes do not conserve groups")
    for field, total in (("message_outcomes", n), ("group_outcomes", get("source_groups")),
                         ("group_work_states_at_horizon", get("source_groups"))):
        require(isinstance(row[field], dict) and sum(count(value, f"{label}.{field}")
                for value in row[field].values()) == total, f"{label}: {field} does not conserve outcomes")
    for field, numerator, denominator in (
        ("baseline_original_received_fraction", baseline, n),
        ("augmented_original_received_fraction", received, n),
        ("authenticated_source_fraction", success, n),
        ("authenticated_received_fraction", success, received),
    ):
        expected = numerator / denominator if denominator else None
        value = row[field]
        require((value is None if expected is None else type(value) in (int, float)
                 and math.isfinite(value) and math.isclose(value, expected, abs_tol=ABS_TOLERANCE,
                                                          rel_tol=REL_TOLERANCE)),
                f"{label}: {field} disagrees with its counts")


def load_report(directory):
    directory = Path(directory)
    report = load_json(directory / "replay_summary.json")
    require(type(report.get("schema_version")) is int and report["schema_version"] == 1
            and report.get("mode") == "replay", f"{directory}: unsupported signed report schema")
    require(report.get("report_sha256") == digest({k: v for k, v in report.items() if k != "report_sha256"}),
            f"{directory}: report integrity digest mismatch")
    identity = {key: report[key] for key in ("schema_version", "mode", "provenance", "parameters")}
    require(report.get("input_fingerprint") == digest(identity), f"{directory}: input fingerprint mismatch")
    provenance, parameters = report["provenance"], report["parameters"]
    request = {**identity, "provenance": {k: v for k, v in provenance.items() if k != "signed_workloads"}}
    require(report.get("request_sha256") == digest(request), f"{directory}: request fingerprint mismatch")
    require(parameters.get("replay_model") in MODELS, f"{directory}: expected a signed replay model")
    for key in FILE_INPUTS:
        require(isinstance(provenance[key].get("path"), str) and provenance[key]["path"],
                f"{directory}: missing {key} path")
        sha(provenance[key]["sha256"], key)
    sources = provenance["source_files_sha256"]
    require(isinstance(sources, dict) and sources, f"{directory}: missing model source inventory")
    for key, value in sources.items():
        path = Path(key)
        require(not path.is_absolute() and ".." not in path.parts, f"{directory}: invalid source path")
        sha(value, key)
    algorithms = _distinct(parameters["algorithms"], "algorithms")
    intervals = _distinct(parameters["intervals"], "intervals")
    seeds = _distinct(parameters["seeds"], "seeds")
    for k in intervals:
        count(k, "interval", 1)
    for seed in seeds:
        count(seed, "seed")
    scenarios = parameters["scenarios"]
    names = _distinct([s["name"] for s in scenarios], "scenarios")
    require(all(s["parameters"].get("replay_model") == parameters["replay_model"] for s in scenarios),
            f"{directory}: mixed replay models")
    expected = set(itertools.product(names, algorithms, intervals, seeds))
    rows = report["rows"]
    require(isinstance(rows, list) and rows, f"{directory}: missing scientific rows")
    indexed = {tuple(row[key] for key in CASE_FIELDS): row for row in rows}
    require(len(indexed) == len(rows) and set(indexed) == expected,
            f"{directory}: incomplete or duplicate case matrix")
    actual_csv = (directory / "replay_overview.csv").read_bytes()
    require(hashlib.sha256(actual_csv).hexdigest() == report["csv_sha256"] and actual_csv == csv_bytes(rows),
            f"{directory}: CSV integrity or report/CSV agreement failed")
    workloads = provenance["signed_workloads"]
    require(isinstance(workloads, dict) and workloads, f"{directory}: missing signed-workload evidence")
    used_workloads = set()
    scenario_lookup = {s["name"]: s for s in scenarios}
    for key, row in indexed.items():
        label = f"{directory}: {key}"
        require(row["replay_model"] == parameters["replay_model"], f"{label}: wrong replay model")
        wait = scenario_lookup[row["scenario"]]["parameters"].get("max_batch_wait_s")
        workload_key = f"{row['algorithm']}:k={row['interval_k']}:max_batch_wait_s={wait}"
        require(workload_key in workloads and row["signature_workload_evidence"] == workloads[workload_key],
                f"{label}: row workload evidence differs from report provenance")
        used_workloads.add(workload_key)
        check_outcomes(row, label)
        evidence = workloads[workload_key]
        workload_identity = evidence["identity"]
        # Signed-workload identities hash canonical JSON with a trailing newline;
        # replay report identities use the same canonical encoding without it.
        require(evidence["cache_identity"] == hashlib.sha256(canonical(workload_identity) + b"\n").hexdigest()
                and workload_identity["trace_messages"] == row["source_messages"]
                and workload_identity["algorithm"] == row["algorithm"]
                and workload_identity["interval"] == row["interval_k"]
                and workload_identity["max_batch_wait_s"] == wait,
                f"{label}: signed workload identity mismatch")
        require(evidence["signature_count"] == evidence["cryptographically_verified_signatures"] == row["source_groups"],
                f"{label}: signature inventory differs from source groups")
    require(used_workloads == set(workloads), f"{directory}: unexpected signed-workload inventory")
    return report, indexed


def check_local_files(report, root=ROOT):
    """Check local result evidence, without rewriting or trusting reference paths."""
    root = Path(root)
    def local(path):
        value = Path(path)
        return value if value.is_absolute() else root / value
    provenance = report["provenance"]
    for name in FILE_INPUTS:
        entry = provenance[name]
        require(file_digest(local(entry["path"])) == entry["sha256"], f"Local {name} bytes differ from report")
    source_root = root / "src"
    sources = {str(p.relative_to(source_root)): file_digest(p) for p in source_root.rglob("*.py")
               if p.name != "pipeline.py" and not p.name.startswith("plot")}
    require(sources == provenance["source_files_sha256"], "Local model source inventory/hashes differ from report")
    for name, evidence in provenance["signed_workloads"].items():
        directory = local(evidence["cache_dir"])
        for filename, field in (("manifest.json", "manifest_sha256"), ("groups.jsonl", "groups_sha256"),
                                ("public_keys.json", "public_keys_sha256")):
            require(file_digest(directory / filename) == evidence[field], f"{name}: local {filename} differs from report")
        manifest = load_json(directory / "manifest.json")
        require(manifest.get("complete") is True and manifest.get("identity") == evidence["identity"]
                and manifest.get("groups") == evidence["signature_count"]
                and all(manifest.get(key) == evidence[key] for key in ("groups_sha256", "public_keys_sha256")),
                f"{name}: local cache manifest differs from report evidence")


def comparable(report):
    """Ignore only known location fields and digests incorporating those fields."""
    result = copy.deepcopy(report)
    for key in ("report_sha256", "csv_sha256", "request_sha256", "input_fingerprint"):
        del result[key]
    for name in FILE_INPUTS:
        result["provenance"][name].pop("path")
    for evidence in result["provenance"]["signed_workloads"].values():
        evidence.pop("cache_dir")
    for row in result["rows"]:
        row["signature_workload_evidence"].pop("cache_dir")
    result["rows"].sort(key=lambda row: tuple(row[key] for key in CASE_FIELDS))
    return result


def compare_values(actual, expected, label="report"):
    if isinstance(expected, dict):
        require(isinstance(actual, dict) and set(actual) == set(expected), f"{label}: object fields differ")
        for key in expected:
            compare_values(actual[key], expected[key], f"{label}.{key}")
    elif isinstance(expected, list):
        require(isinstance(actual, list) and len(actual) == len(expected), f"{label}: list lengths differ")
        for index, (left, right) in enumerate(zip(actual, expected)):
            compare_values(left, right, f"{label}[{index}]")
    elif type(expected) is float:
        require(type(actual) in (int, float) and math.isfinite(actual) and math.isfinite(expected)
                and math.isclose(actual, expected, rel_tol=REL_TOLERANCE, abs_tol=ABS_TOLERANCE),
                f"{label}: numeric value differs ({actual!r} versus {expected!r})")
    else:
        require(type(actual) is type(expected) and actual == expected, f"{label}: value differs")


def compare_results(results_dir, reference_dir, *, root=ROOT):
    actual, rows = load_report(results_dir)
    reference, _ = load_report(reference_dir)
    check_local_files(actual, root)
    compare_values(comparable(actual), comparable(reference))
    return len(rows)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, required=True, help="Fresh local replay using preserved public signed workloads.")
    parser.add_argument("--reference-dir", type=Path, required=True, help="Preserved published replay summary and CSV.")
    args = parser.parse_args(argv)
    try:
        total = compare_results(args.results_dir, args.reference_dir)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"PASS: {total} signed replay cases; report/CSV integrity, local inputs/model/public-cache hashes, "
          "case matrix, outcome conservation, and scientific values match.")
    print("Only input/cache location fields were excluded from comparison. "
          "Run the native pipeline --validate-only separately to reverify signatures.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
