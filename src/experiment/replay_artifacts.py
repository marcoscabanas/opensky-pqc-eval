"""Scenario loading and content-addressed replay report provenance."""

import csv
import hashlib
import io
import json
import os
import tempfile
from pathlib import Path
from .io_support import sha256_file, load_json


SCHEMA_VERSION = 1


DELAYED_SCENARIO_FIELDS = {
    "followup_s", "coverage_thresholds_s", "max_batch_wait_s", "auth_frames_per_second",
    "sender_queue_limit", "transmission_queue_limit", "receiver_queue_limit", "receiver_workers",
    "fragment_copies", "receive_jitter_ms", "loss", "max_events", "record_events", "channel_mode",
    "background_frames_per_second",
}


MODEL_FIELDS = {
    "signed_before_send": DELAYED_SCENARIO_FIELDS,
    "signed_detached": DELAYED_SCENARIO_FIELDS,
}


SIGNED_REPLAY_MODELS = {"signed_before_send", "signed_detached"}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_evidence(path):
    path = Path(path)
    return {"path": path.name, "sha256": sha256_file(path)}


def _source_evidence():
    """Hash model and validation code, excluding presentation/dispatch wrappers.

    Plot additions and pipeline UI edits cannot change computed replay results.
    Scientific source modules remain included, including newly added engines.
    """
    source_root = Path(__file__).resolve().parents[1]
    return {str(path.relative_to(source_root)): sha256_file(path)
            for path in sorted(source_root.rglob("*.py"))
            if path.name not in {"main_experiment.py", "main_report.py", "result_validation.py"}}


def _replay_model(parameters):
    model = parameters.get("replay_model", "signed_detached")
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


def _profile_evidence(profile, algorithm, operation):
    entry = profile["algorithms"][algorithm]
    return {
        "id": profile["id"], "label": profile["label"], "kind": profile["kind"],
        "platform": profile["platform"], "limitations": profile.get("limitations", []),
        "implementation": entry["implementation"], "equivalence": entry["equivalence"],
        "limitation": entry.get("limitation"), "source_urls": entry["source_urls"],
        "timing": entry["operations"][operation],
    }
