"""Validate saved main-experiment reports before presenting scientific metrics."""

import json
import math
from pathlib import Path
from .replay_artifacts import _digest, outputs_match, scenario_seeds
from .signed_experiment import _validate_rows


LABELS = {"ECDSA-P256": "ECDSA P-256", "ML-DSA-44": "ML-DSA-44",
          "FN-DSA-512": "Falcon-512", "SLH-DSA-SHA2-128s": "SLH-DSA-SHA2-128s"}


def _number(value, label, maximum=None):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{label} must be finite and nonnegative.")
    if maximum is not None and value > maximum:
        raise ValueError(f"{label} exceeds {maximum}.")
    return value


def load_report(results_dir):
    """Check paired report/CSV integrity, exact matrix, conservation, and metrics."""
    directory = Path(results_dir)
    path = directory / "replay_summary.json"
    report = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(report, dict) or report.get("mode") != "replay" or not report.get("rows"):
        raise ValueError("Expected a nonempty replay report.")
    if not outputs_match(path, directory / "replay_overview.csv", report.get("input_fingerprint")):
        raise ValueError("Replay JSON/CSV integrity check failed.")
    identity = {key: report[key] for key in ("schema_version", "mode", "provenance", "parameters")}
    if report["input_fingerprint"] != _digest(identity):
        raise ValueError("Replay input identity fingerprint mismatch.")
    params = report["parameters"]
    if params.get("replay_model") != "signed_detached":
        raise ValueError("This plotter requires the current signed_detached model.")
    for key in ("algorithms", "intervals", "seeds"):
        values = params[key]
        if not isinstance(values, list) or not values or len(set(values)) != len(values):
            raise ValueError(f"Expected distinct nonempty {key}.")
    if any(type(seed) is not int or seed < 0 for seed in params["seeds"]):
        raise ValueError("Seeds must be nonnegative integers.")
    if any(type(k) is not int or k < 1 for k in params["intervals"]):
        raise ValueError("Grouping intervals must be positive integers.")
    scenarios = params["scenarios"]
    if (not scenarios or len({s["name"] for s in scenarios}) != len(scenarios)
            or any(s["parameters"].get("replay_model") != "signed_detached" for s in scenarios)):
        raise ValueError("Expected distinct detached scenarios.")
    rows = report["rows"]
    count = rows[0]["source_messages"]
    if type(count) is not int or count <= 0:
        raise ValueError("Expected a positive source population.")
    _validate_rows(rows, scenarios, params["algorithms"], params["intervals"], params["seeds"], count)
    channel_modes = {scenario["name"]: scenario["parameters"].get("channel_mode") for scenario in scenarios}
    for row in rows:
        if channel_modes[row["scenario"]] is not None and row.get("channel_mode") != channel_modes[row["scenario"]]:
            raise ValueError("Replay channel mode differs from its configured reception model.")
        _number(row["authentication_only_additional_rf_loss_fraction"], "RF loss fraction", 1)
        _number(row["additional_offered_airtime_load"], "Added offered airtime")
        received = _number(row["baseline_original_received_messages"], "Baseline receptions", count)
        if type(received) is not int:
            raise ValueError("Reception counts must be integers.")
        if row.get("channel_mode") == "observed_capture":
            completed = row["ordinary_frames_transmitted"] - row["ordinary_frames_in_flight_at_horizon"]
            if received != count or row.get("timing_matched_original_received_messages") != completed:
                raise ValueError("Observed-capture baseline and no-authentication control must preserve observed transmissions.")
        for stem, expected_count in (("receipt_to_auth_ms", row["authenticated_messages"]),
                                     ("ordinary_transmission_delay_ms", row["ordinary_frames_transmitted"])):
            n = row[stem + "_count"]
            if type(n) is not int or n != expected_count or not 0 <= n <= count:
                raise ValueError(f"{stem} population is inconsistent.")
            for suffix in ("p50", "max"):
                value = row[stem + "_" + suffix]
                if n == 0:
                    if value is not None:
                        raise ValueError(f"{stem} without observations must be null, not zero.")
                else:
                    _number(value, stem + "_" + suffix)
    return report


def metric_matrix(report, metric):
    """Mean of declared replicate metrics, preserving absent values as None.

    A mean of per-seed percentiles is not a percentile of pooled messages.
    Callers must use that explicit label, and use metric_statistics for ranges
    and the number of seeds with a defined metric.
    """
    params = report["parameters"]
    cases = [(a, k) for a in params["algorithms"] for k in params["intervals"]]
    scenarios = [s["name"] for s in params["scenarios"]]
    indexed = metric_statistics(report, metric)
    return cases, scenarios, [[indexed[a, k, s]["mean"] for s in scenarios] for a, k in cases]


def grouped_rows(report):
    """Group explicitly declared replicates; reject missing/duplicate seeds."""
    params = report["parameters"]
    expected = {scenario["name"]: scenario_seeds(scenario, params["seeds"])
                for scenario in params["scenarios"]}
    indexed = {}
    for row in report["rows"]:
        key = row["algorithm"], row["interval_k"], row["scenario"]
        indexed.setdefault(key, []).append(row)
    for (algorithm, interval, scenario), rows in indexed.items():
        seeds = [row["seed"] for row in rows]
        if len(seeds) != len(set(seeds)) or set(seeds) != set(expected[scenario]):
            raise ValueError("Metric groups must contain each declared seed exactly once.")
        rows.sort(key=lambda row: expected[scenario].index(row["seed"]))
    if len(indexed) != len(params["algorithms"]) * len(params["intervals"]) * len(expected):
        raise ValueError("Metric case matrix is incomplete.")
    return indexed


def seed_statistics(values):
    """Descriptive mean and observed range; never a confidence interval."""
    values = list(values)
    defined = [value for value in values if value is not None]
    if any(type(value) not in (int, float) or not math.isfinite(value) for value in defined):
        raise ValueError("Replicate metrics must be finite numbers or None.")
    return {"seed_count": len(values), "defined_seed_count": len(defined),
            "mean": None if not defined else math.fsum(defined) / len(defined),
            "min": None if not defined else min(defined),
            "max": None if not defined else max(defined)}


def metric_statistics(report, metric):
    return {key: seed_statistics(metric(row) for row in rows)
            for key, rows in grouped_rows(report).items()}
