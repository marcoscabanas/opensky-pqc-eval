#!/usr/bin/env python3
"""Check packaged inputs and reproduced scientific results using only stdlib.

Run with --inputs-only before installing scientific/native dependencies. The
default full check compares results/runs/development/replay with results/reference/development.
Absolute checkout paths do not participate in the scientific comparison.
"""

import argparse
import csv
import hashlib
import io
import itertools
import json
import math
from pathlib import Path
import re
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ABS_TOLERANCE = 1e-9
REL_TOLERANCE = 1e-12
REPORTS = {
    "screening": ("constraint_screening_summary.json", "constraint_screening_overview.csv"),
    "replay": ("replay_summary.json", "replay_overview.csv"),
}
IDENTITY_FIELDS = ("module", "implementation", "parameter_set", "expected_signature_bytes", "maximum_signature_bytes")


class CheckError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise CheckError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def file_sha256(path):
    checksum = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream, object_pairs_hook=_unique_object,
                         parse_constant=lambda value: (_ for _ in ()).throw(CheckError(f"Nonfinite JSON value: {value}")))


def _hash(value, label):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), f"{label}: invalid SHA256")
    return value


def _count(value, label, minimum=0):
    require(type(value) is int and value >= minimum, f"{label}: expected integer >= {minimum}")
    return value


def csv_bytes(rows):
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=sorted({key for row in rows for key in row}), lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
                         if isinstance(value, (dict, list)) else value for key, value in row.items()})
    return output.getvalue().encode("utf-8")


def check_calibration(profile, configurations=None):
    require(isinstance(profile, dict), "Calibration must be a JSON object")
    payload = {key: value for key, value in profile.items() if key != "profile_sha256"}
    require(profile.get("profile_sha256") == digest(payload), "Calibration profile integrity digest mismatch")
    require(type(profile.get("schema_version")) is int and profile["schema_version"] == 1
            and profile.get("kind") == "portable_signature_size_calibration", "Unsupported calibration schema")
    require(isinstance(profile.get("trace"), dict), "Calibration trace provenance missing")
    _hash(profile["trace"].get("sha256"), "Calibration trace")
    groups = profile.get("groups")
    require(isinstance(groups, dict) and groups, "Calibration group provenance missing")
    for interval, evidence in groups.items():
        require(interval.isdigit() and int(interval) > 0 and isinstance(evidence, dict), "Invalid calibration group entry")
        _hash(evidence.get("sha256"), f"Calibration group k={interval}")
    algorithms = profile.get("algorithms")
    require(isinstance(algorithms, dict) and algorithms, "Calibration algorithms missing")
    if configurations is not None:
        configurations = {key: value for key, value in configurations.items() if value.get("enabled", True)}
        require(set(algorithms) == set(configurations), "Calibration algorithm set differs from configured enabled algorithms")
    for name, algorithm in algorithms.items():
        require(isinstance(algorithm, dict) and isinstance(algorithm.get("identity"), dict), f"{name}: missing calibration identity")
        identity = algorithm["identity"]
        if configurations is not None:
            expected = {key: configurations[name].get(key) for key in IDENTITY_FIELDS}
            require(identity == expected, f"{name}: calibration algorithm identity differs from configuration")
        intervals = algorithm.get("intervals")
        require(isinstance(intervals, dict) and set(intervals) == set(groups), f"{name}: incomplete calibration intervals")
        for interval, record in intervals.items():
            label = f"{name} k={interval} calibration"
            require(isinstance(record, dict) and isinstance(record.get("distribution"), list) and record["distribution"], f"{label}: empty distribution")
            counts = {}
            for item in record["distribution"]:
                require(isinstance(item, dict), f"{label}: invalid distribution entry")
                size = _count(item.get("signature_bytes"), f"{label} signature size", 1)
                count = _count(item.get("count"), f"{label} frequency", 1)
                require(size not in counts, f"{label}: duplicate signature size")
                maximum = identity.get("maximum_signature_bytes")
                require(maximum is None or size <= maximum, f"{label}: size exceeds configured maximum")
                counts[size] = count
            total = sum(counts.values())
            require(_count(record.get("sample_count"), f"{label} sample count", 1) == total, f"{label}: frequency weights do not sum to sample count")
            fixed = identity.get("expected_signature_bytes")
            if fixed is not None:
                require(set(counts) == {fixed} and record.get("sizing_basis") == "configured_fixed_size", f"{label}: fixed size disagrees with identity")
            else:
                source = record.get("source")
                require(record.get("sizing_basis") == "measured_complete_signature_metadata" and isinstance(source, dict), f"{label}: measured provenance missing")
                require(source.get("algorithm") == name and source.get("interval_k") == int(interval)
                        and source.get("measured_record_count") == total, f"{label}: measured provenance disagrees with distribution")
                _hash(source.get("signature_metadata_sha256"), f"{label} metadata")


def check_inputs(root=REPOSITORY_ROOT):
    root = Path(root)
    manifest = load_json(root / "data/development/manifest.json")
    require(isinstance(manifest, dict) and isinstance(manifest.get("raw_capture"), dict), "Input manifest raw_capture missing")
    raw = manifest["raw_capture"]
    raw_path = Path(raw.get("path", ""))
    require(str(raw_path) != "." and not raw_path.is_absolute() and ".." not in raw_path.parts, "Raw capture manifest path must be repository-relative")
    expected_hash = _hash(raw.get("sha256"), "Raw capture manifest")
    require(file_sha256(root / raw_path) == expected_hash, "Raw sample SHA256 does not match data/development/manifest.json")
    expected = manifest.get("expected")
    require(isinstance(expected, dict), "Input manifest expected counts missing")
    for key in ("source_messages", "aircraft", "screening_rows", "replay_rows"):
        _count(expected.get(key), f"Manifest expected.{key}", 1)
    profile = load_json(root / "data/calibration/signature_sizes.json")
    config_path = root / "config/algorithms.json"
    check_calibration(profile, load_json(config_path) if config_path.exists() else None)
    if "processed_sha256" in manifest:
        require(profile["trace"]["sha256"] == _hash(manifest["processed_sha256"], "Manifest processed trace"), "Calibration trace differs from manifest processed SHA256")
    if "groups_sha256" in manifest:
        actual = {interval: evidence["sha256"] for interval, evidence in profile["groups"].items()}
        require(actual == manifest["groups_sha256"], "Calibration group hashes differ from input manifest")
    return manifest


def _without_paths(value):
    if isinstance(value, dict):
        return {key: _without_paths(item) for key, item in value.items()
                if key != "path" and not key.endswith("_path") and key != "signature_directories"}
    if isinstance(value, list):
        return [_without_paths(item) for item in value]
    return value


def compare_values(actual, expected, label="value", notes=None):
    """Compare scientific values; integer fields are exact, floating fields tolerant."""
    if label.endswith(".channel_summary.numpy_version"):
        if actual != expected and notes is not None:
            notes.add(f"NumPy metadata differs ({actual} versus reference {expected}); scientific values were compared independently.")
        return
    if isinstance(expected, dict):
        require(isinstance(actual, dict) and set(actual) == set(expected), f"{label}: object fields differ")
        for key in expected:
            compare_values(actual[key], expected[key], f"{label}.{key}", notes)
    elif isinstance(expected, list):
        require(isinstance(actual, list) and len(actual) == len(expected), f"{label}: list lengths differ")
        for index, (left, right) in enumerate(zip(actual, expected)):
            compare_values(left, right, f"{label}[{index}]", notes)
    elif type(expected) is float:
        require(type(actual) in (float, int) and math.isfinite(actual) and math.isfinite(expected)
                and math.isclose(actual, expected, abs_tol=ABS_TOLERANCE, rel_tol=REL_TOLERANCE),
                f"{label}: {actual!r} differs from reference {expected!r}")
    else:
        require(type(actual) is type(expected) and actual == expected,
                f"{label}: {actual!r} differs from reference {expected!r}")


def check_report(directory, mode, expected_rows):
    json_name, csv_name = REPORTS[mode]
    path = Path(directory) / json_name
    report = load_json(path)
    require(isinstance(report, dict) and report.get("mode") == mode and report.get("schema_version") == 1, f"{path}: invalid report mode/schema")
    payload = {key: value for key, value in report.items() if key != "report_sha256"}
    require(report.get("report_sha256") == digest(payload), f"{path}: report integrity digest mismatch")
    identity = {key: report[key] for key in ("schema_version", "mode", "provenance", "parameters")}
    require(report.get("input_fingerprint") == digest(identity), f"{path}: input/model fingerprint mismatch")
    rows = report.get("rows")
    require(isinstance(rows, list) and len(rows) == expected_rows, f"{path}: expected {expected_rows} {mode} rows")
    actual_csv = (Path(directory) / csv_name).read_bytes()
    require(hashlib.sha256(actual_csv).hexdigest() == report.get("csv_sha256"), f"{csv_name}: CSV integrity digest mismatch")
    require(actual_csv == csv_bytes(rows), f"{csv_name}: CSV contents differ from report rows")
    parameters = report["parameters"]
    algorithms, intervals = parameters["algorithms"], parameters["intervals"]
    if mode == "screening":
        fields = ("algorithm", "interval_k")
        matrix = set(itertools.product(algorithms, intervals))
    else:
        fields = ("scenario", "algorithm", "interval_k", "seed")
        matrix = set(itertools.product([entry["name"] for entry in parameters["scenarios"]], algorithms, intervals, parameters["seeds"]))
    indexed = {}
    for row in rows:
        require(isinstance(row, dict) and all(field in row for field in fields), f"{path}: row identity missing")
        key = tuple(row[field] for field in fields)
        require(key not in indexed, f"{path}: duplicate case {key}")
        indexed[key] = row
    require(set(indexed) == matrix, f"{path}: case matrix is incomplete or contains unexpected cases")
    return report, indexed


def check_conservation(row, expected):
    label = f"{row.get('scenario')} / {row.get('algorithm')} / k={row.get('interval_k')} / seed={row.get('seed')}"
    n = _count(row.get("source_messages"), f"{label} source_messages", 1)
    require(n == expected["source_messages"] and row.get("trace_messages") == n
            and row.get("aircraft_count") == expected["aircraft"] and row.get("trace_aircraft") == expected["aircraft"], f"{label}: trace population differs from manifest")
    def count(name):
        return _count(row.get(name), f"{label} {name}")
    base, augmented = count("baseline_original_received_messages"), count("augmented_original_received_messages")
    authenticated = count("authenticated_messages")
    require(base + count("baseline_original_lost_messages") == n
            and augmented + count("augmented_original_lost_messages") == n, f"{label}: original reception/loss conservation failed")
    require(authenticated + count("definitive_failure_messages") + count("unresolved_messages") == n,
            f"{label}: authentication/failure/censor conservation failed")
    require(authenticated <= augmented and authenticated + count("received_definitive_failure_messages")
            + count("received_unresolved_messages") == augmented, f"{label}: received-message authentication conservation failed")
    for name, total in (("message_outcomes", n), ("group_outcomes", count("source_groups")),
                        ("group_work_states_at_horizon", count("source_groups"))):
        values = row.get(name)
        require(isinstance(values, dict), f"{label}: {name} missing")
        require(sum(_count(value, f"{label} {name}.{key}") for key, value in values.items()) == total,
                f"{label}: {name} conservation failed")
    require(count("auth_frames_received") + count("auth_frames_lost") + count("auth_frames_in_flight_at_horizon")
            == count("auth_frames_transmitted"), f"{label}: authentication frame conservation failed")
    require(count("source_to_auth_ms_count") == authenticated and count("receipt_to_auth_ms_count") == authenticated,
            f"{label}: authentication delay sample counts disagree")
    added, gains = count("additional_original_loss_messages"), count("original_reception_gain_messages")
    require(added - gains == base - augmented == row.get("net_additional_original_loss_messages"), f"{label}: paired loss attribution disagrees")
    if row.get("channel_mode") == "independent":
        require(base == augmented and added == gains == 0, f"{label}: independent control unexpectedly harms/gains original receptions")
    elif row.get("channel_mode") == "destructive_overlap":
        require(gains == 0 and augmented <= base, f"{label}: destructive collisions cannot improve original reception")
    else:
        raise CheckError(f"{label}: unrecognized channel mode")
    for name, numerator, denominator in (
        ("baseline_original_received_fraction", base, n), ("augmented_original_received_fraction", augmented, n),
        ("authenticated_source_fraction", authenticated, n), ("authenticated_received_fraction", authenticated, augmented),
    ):
        compare_values(row.get(name), numerator / denominator if denominator else None, f"{label}.{name}")
    for coverage in row.get("threshold_coverage", []):
        for anchor, population in (("source", n), ("receipt", augmented)):
            eligible = _count(coverage.get(f"{anchor}_eligible_messages"), f"{label} eligible {anchor}")
            ineligible = _count(coverage.get(f"{anchor}_ineligible_due_to_followup_messages"), f"{label} ineligible {anchor}")
            successes = _count(coverage.get(f"{anchor}_authenticated_within_threshold_messages"), f"{label} threshold success {anchor}")
            require(eligible + ineligible == population and successes <= min(eligible, authenticated), f"{label}: threshold cohort conservation failed")
            compare_values(coverage.get(f"{anchor}_authentication_fraction"), successes / eligible if eligible else None,
                           f"{label}.{anchor}_authentication_fraction")
            if coverage["threshold_s"] <= row["followup_s"]:
                require(eligible == population, f"{label}: full-follow-up threshold excluded eligible {anchor} observations")


def _relocated_path(root, value):
    path = Path(value)
    if not path.is_absolute():
        return root / path if ".." not in path.parts else None
    try:
        return root / path.relative_to(root)
    except ValueError:
        for index, part in reversed(list(enumerate(path.parts))):
            if part in {"src", "config", "data", "runs", "results"}:
                return root.joinpath(*path.parts[index:])
    return None


def check_local_provenance(provenance, root):
    """Validate available inputs by relocated path and every declared source file."""
    root = Path(root)
    sources = provenance.get("source_files_sha256", {})
    require(isinstance(sources, dict), "Source-file provenance must be an object")
    for relative, expected_hash in sources.items():
        path = Path(relative)
        require(not path.is_absolute() and ".." not in path.parts, "Source-file provenance must be relative to src")
        candidate = root / "src" / path
        require(candidate.is_file(), f"Declared source file is missing: {candidate}")
        require(file_sha256(candidate) == expected_hash, f"Source file differs from saved model: {candidate}")
    def walk(value):
        if isinstance(value, dict):
            if isinstance(value.get("path"), str) and "sha256" in value:
                candidate = _relocated_path(root, value["path"])
                if candidate is not None and candidate.is_file():
                    require(file_sha256(candidate) == value["sha256"], f"Input content differs from saved provenance: {candidate}")
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(provenance)


def check_results(results_dir, reference_dir, manifest, root=REPOSITORY_ROOT, *, allow_model_change=False):
    expected, notes = manifest["expected"], set()
    for mode in ("screening", "replay"):
        reference, expected_rows = check_report(reference_dir, mode, expected[f"{mode}_rows"])
        result, actual_rows = check_report(results_dir, mode, expected[f"{mode}_rows"])
        require(set(actual_rows) == set(expected_rows), f"{mode}: cases differ from reference identities")
        result_provenance = _without_paths(result["provenance"])
        reference_provenance = _without_paths(reference["provenance"])
        source_key = "source_files_sha256"
        if (allow_model_change and source_key in result_provenance and source_key in reference_provenance
                and result_provenance[source_key] != reference_provenance[source_key]):
            # This exception is only for comparison against the frozen model.
            # Current reports must still match the live source files below.
            del result_provenance[source_key]
            del reference_provenance[source_key]
            notes.add(f"{mode}: Model source hashes differ from the frozen reference; "
                      "current live source hashes and all scientific values were checked.")
        compare_values(result_provenance, reference_provenance, f"{mode}.input_content_provenance")
        compare_values(_without_paths(result["parameters"]), _without_paths(reference["parameters"]), f"{mode}.parameters")
        check_local_provenance(result["provenance"], root)
        if allow_model_change:
            # Match replay_experiment._source_evidence without importing project
            # modules or scientific dependencies. A stale report cannot hide a
            # newly added engine by omitting it from its source inventory.
            source_root = Path(root) / "src"
            live_sources = {str(path.relative_to(source_root)) for path in source_root.rglob("*.py")
                            if path.name != "pipeline.py" and not path.name.startswith("plot")}
            require(set(result["provenance"].get(source_key, {})) == live_sources,
                    f"{mode}: saved source inventory differs from current live scientific source files")
        if "processed_sha256" in manifest:
            require(result["provenance"]["trace"]["sha256"] == manifest["processed_sha256"], f"{mode}: processed trace differs from manifest")
        if "groups_sha256" in manifest:
            require({k: v["sha256"] for k, v in result["provenance"]["groups"].items()} == manifest["groups_sha256"], f"{mode}: group hashes differ from manifest")
        for key in expected_rows:
            row = actual_rows[key]
            if mode == "replay":
                check_conservation(row, expected)
                check_conservation(expected_rows[key], expected)
            else:
                require(row.get("observed_message_count") == expected["source_messages"]
                        and row.get("observed_aircraft_count") == expected["aircraft"], f"screening {key}: trace population differs from manifest")
                require(row["grouped_message_count"] + row["unsigned_tail_message_count"] == expected["source_messages"]
                        and row["complete_group_count"] * row["interval_k"] == row["grouped_message_count"], f"screening {key}: group coverage does not conserve messages")
            compare_values(row, expected_rows[key], f"{mode}.case{key}", notes)
    return sorted(notes)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs-only", action="store_true", help="Check raw capture and portable calibration without generated outputs.")
    parser.add_argument("--results-dir", type=Path, default=REPOSITORY_ROOT / "results/runs/development/replay")
    parser.add_argument("--reference-dir", type=Path, default=REPOSITORY_ROOT / "results/reference/development")
    parser.add_argument("--allow-model-change", action="store_true",
                        help="Allow source hashes to differ from the frozen reference; still require current live source hashes and all scientific values to match.")
    args = parser.parse_args(argv)
    try:
        manifest = check_inputs()
        print("PASS: raw sample SHA256 and portable signature-size calibration integrity")
        if not args.inputs_only:
            notes = check_results(args.results_dir, args.reference_dir, manifest,
                                  allow_model_change=args.allow_model_change)
            print(f"PASS: {manifest['expected']['replay_rows']} replay cases and {manifest['expected']['screening_rows']} screening rows; digests, conservation, paired reception and reference values")
            for note in notes:
                print(f"NOTE: {note}")
    except (CheckError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
