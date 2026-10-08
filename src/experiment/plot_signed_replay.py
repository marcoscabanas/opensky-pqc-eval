"""Plot integrity-checked current signed_detached reports without rerunning crypto.

Each cell is one scenario/algorithm/group size. Only single-seed reports are
accepted: percentiles across runs must not be averaged into a false percentile.
Report integrity is checked here; use signed_experiment --validate-only to also
re-verify cached signatures and current input/source/backend provenance.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile

from src.experiment.replay_experiment import _digest, outputs_match
from src.experiment.signed_experiment import _validate_rows


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


def _draw(report, output_dir, label):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError as exc:
        raise RuntimeError("Install plotting dependencies: python -m pip install -r config/requirements/replay.txt.") from exc
    matplotlib.rcParams.update({"font.size": 9, "svg.fonttype": "none", "pdf.fonttype": 42,
                                "svg.hashsalt": "opensky-signed-detached-v1"})
    figure_specs = [
        ("ordinary_impact", "Ordinary transmission and channel impact", [
            ("Additional RF loss from authentication (%)", lambda r: r["authentication_only_additional_rf_loss_fraction"] * 100, 100),
            ("Maximum ordinary transmission delay (ms)", lambda r: r["ordinary_transmission_delay_ms_max"], None),
            ("Added offered airtime during target window (%)", lambda r: r["additional_offered_airtime_load"] * 100, None)],
         "RF loss compares authentication with a timing-matched control, relative to all source messages. "
         "Delay includes aircraft radio waiting. Offered airtime is additive frame duration, not measured RF occupancy."),
        ("authentication_outcomes", "Authentication outcomes at the observation cutoff", [
            ("Authenticated source messages (%)", lambda r: r["authenticated_messages"] / r["source_messages"] * 100, 100),
            ("Pending source messages (%)", lambda r: r["unresolved_messages"] / r["source_messages"] * 100, 100),
            ("Definitive failure source messages (%)", lambda r: r["definitive_failure_messages"] / r["source_messages"] * 100, 100)],
         "The three outcomes sum to 100% for each case. Pending means unresolved at the cutoff; "
         "failure includes unsigned incomplete final groups. These are source-population fractions."),
        ("completed_authentication_delay", "Time from ordinary reception to completed authentication", [
            ("Median completed authentication delay (s)", lambda r: None if r["receipt_to_auth_ms_p50"] is None
             else r["receipt_to_auth_ms_p50"] / 1000, None)],
         "Only successfully authenticated messages contribute to these medians. Gray cells marked with a dash "
         "have no completed authentications. Read together with authentication_outcomes; zero and missing are different."),
    ]
    paths = []
    for stem, title, specifications, note in figure_specs:
        nrows = len(report["parameters"]["algorithms"]) * len(report["parameters"]["intervals"])
        fig, axes = plt.subplots(1, len(specifications), figsize=(7 * len(specifications) + 1, max(7, nrows * 0.38 + 3)), squeeze=False)
        for axis, (metric_title, metric, fixed_max) in zip(axes.flat, specifications):
            cases, scenarios, values = metric_matrix(report, metric)
            array = np.array([[np.nan if v is None else v for v in row] for row in values], dtype=float)
            finite = array[np.isfinite(array)]
            maximum = fixed_max or (float(finite.max()) if finite.size and finite.max() > 0 else 1)
            colors = plt.get_cmap("viridis").with_extremes(bad="#DADADA")
            plot = axis.imshow(np.ma.masked_invalid(array), aspect="auto", vmin=0, vmax=maximum, cmap=colors)
            axis.set_title(metric_title, pad=10)
            axis.set_yticks(range(len(cases)), [f"{LABELS.get(a, a)} / k={k}" for a, k in cases], fontsize=8)
            axis.set_xticks(range(len(scenarios)), [s.replace("detached_", "").replace("_", " ") for s in scenarios],
                            rotation=35, ha="right", fontsize=8)
            for y, row in enumerate(values):
                for x, value in enumerate(row):
                    text = "—" if value is None else (f"{value:.3g}" if value else "0")
                    axis.text(x, y, text, ha="center", va="center", fontsize=8,
                              color="#252525" if value is None or value > maximum * .6 else "white")
            fig.colorbar(plot, ax=axis, fraction=.04, pad=.03)
        fig.suptitle(f"{label}\n{title}", fontsize=13, y=.98)
        import textwrap
        footer = textwrap.fill(note, 110 if len(specifications) == 1 else 240)
        footer += "\nOne replay per cell; no confidence intervals. Timing follows the report's processor profiles and model assumptions."
        fig.text(.02, .025, footer, va="bottom", fontsize=8)
        fig.tight_layout(rect=(0, .14, 1, .94))
        for suffix in ("pdf", "png", "svg"):
            path = output_dir / f"{stem}.{suffix}"
            metadata = {"Date": None} if suffix == "svg" else ({"CreationDate": None, "ModDate": None} if suffix == "pdf" else None)
            fig.savefig(path, dpi=180, facecolor="white", metadata=metadata)
            paths.append(path)
        plt.close(fig)
    return paths


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def plot_results(results_dir, output_dir, label="Signed detached replay"):
    results_dir, output_dir = Path(results_dir), Path(output_dir)
    report = load_report(results_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    previous = {name: os.environ.get(name) for name in ("MPLCONFIGDIR", "XDG_CACHE_HOME")}
    try:
        with tempfile.TemporaryDirectory(prefix="opensky-signed-figures-") as cache:
            for name, value in previous.items():
                if value is None:
                    os.environ[name] = cache
            paths = _draw(report, output_dir, label)
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
    manifest = {"schema_version": 1, "replay_model": "signed_detached", "label": label,
                "source_reports": {name: _sha256(results_dir / name) for name in ("replay_summary.json", "replay_overview.csv")},
                "plotter_sha256": _sha256(__file__), "figure_files": {p.name: _sha256(p) for p in paths},
                "case_count": len(report["rows"]), "aggregation": "One single-seed case per cell; no across-seed aggregation.",
                "missing_delay": "Gray dash means no completed observations; never converted to zero.",
                "validation": "Saved report/CSV integrity, identity, matrix, outcomes and plotted metrics; use signed_experiment --validate-only for live signature/input/source validation."}
    destination = output_dir / "figure_manifest.json"
    destination.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return paths + [destination]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--label", default="Signed detached replay", help="Use 'Synthetic implementation demo' for the demo fixture.")
    args = parser.parse_args(argv)
    try:
        for path in plot_results(args.results_dir, args.output_dir, args.label):
            print(path)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
