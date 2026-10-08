"""Validate saved main-experiment reports before presenting scientific metrics."""

import json
import math
from pathlib import Path
from .replay_artifacts import _digest, outputs_match
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
    if len(params["seeds"]) != 1:
        raise ValueError("Plot one seed per report; do not average completed-delay percentiles across seeds.")
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
    for row in rows:
        _number(row["authentication_only_additional_rf_loss_fraction"], "RF loss fraction", 1)
        _number(row["additional_offered_airtime_load"], "Added offered airtime")
        received = _number(row["baseline_original_received_messages"], "Baseline receptions", count)
        if type(received) is not int:
            raise ValueError("Reception counts must be integers.")
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
    """Preserve absent observations as None; never convert them to zero delay."""
    params = report["parameters"]
    cases = [(a, k) for a in params["algorithms"] for k in params["intervals"]]
    scenarios = [s["name"] for s in params["scenarios"]]
    indexed = {(r["algorithm"], r["interval_k"], r["scenario"]): r for r in report["rows"]}
    return cases, scenarios, [[metric(indexed[a, k, s]) for s in scenarios] for a, k in cases]
