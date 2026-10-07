"""Export reproducible replay figures (SVG, PNG and PDF) from saved reports.

Run with --results-dir results/development/replay --output-dir PATH.
Matplotlib is an optional plotting dependency; no experiment is run here.
"""

import argparse
from collections import defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import tempfile
import textwrap


PALETTE = ("#0072B2", "#D55E00", "#009E73", "#CC79A7", "#E69F00", "#56B4E9")
MARKERS = ("o", "s", "^", "D", "v", "P")
ALGORITHM_LABELS = {
    "ECDSA-P256": "ECDSA P-256",
    "ML-DSA-44": "ML-DSA-44",
    "FN-DSA-512": "Falcon-512 lineage",
    "SLH-DSA-SHA2-128s": "SLH-DSA-SHA2-128s",
}


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _load_report(path, mode):
    report = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(report, dict) or report.get("mode") != mode or not report.get("rows"):
        raise ValueError(f"{path}: expected a nonempty {mode} report.")
    recorded_hash = report.get("report_sha256")
    contents = {key: value for key, value in report.items() if key != "report_sha256"}
    actual_hash = hashlib.sha256(json.dumps(contents, sort_keys=True, separators=(",", ":"),
                                           allow_nan=False).encode()).hexdigest()
    if recorded_hash != actual_hash:
        raise ValueError(f"{path}: report integrity digest mismatch.")
    return report


def _number(value, name, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} must be a finite nonnegative number.")
    if maximum is not None and value > maximum:
        raise ValueError(f"{name} exceeds {maximum}.")
    return value


def _validate_rows(replay, screening):
    if replay["provenance"]["trace"]["sha256"] != screening["provenance"]["trace"]["sha256"]:
        raise ValueError("Replay and screening must refer to the same trace SHA256.")
    screening_keys = set()
    for row in screening["rows"]:
        key = row["algorithm"], row["interval_k"]
        if key in screening_keys:
            raise ValueError(f"Duplicate screening row: {key}.")
        screening_keys.add(key)
        for field in ("raw_signature_lower_bound_additional_airtime_load", "modeled_additional_airtime_load",
                      "baseline_offered_airtime_load"):
            _number(row[field], field)
    replay_keys = set()
    for row in replay["rows"]:
        key = row["scenario"], row["algorithm"], row["interval_k"], row["seed"]
        if key in replay_keys:
            raise ValueError(f"Duplicate replay row: {key}.")
        replay_keys.add(key)
        if (row["algorithm"], row["interval_k"]) not in screening_keys:
            raise ValueError(f"Missing screening comparison for {key}.")
        if type(row["interval_k"]) is not int or row["interval_k"] < 1:
            raise ValueError("Batch intervals must be positive integers.")
        _number(row["timely_authenticated_source_fraction"], "timely authenticated fraction", maximum=1)
        _number(row["additional_offered_airtime_load"], "additional offered airtime")
        _number(row["baseline_offered_airtime_load"], "baseline offered airtime")
        if _number(row["max_auth_age_s"], "authentication deadline") == 0:
            raise ValueError("Authentication deadlines must be positive.")


def _seed_note(rows):
    seeds = sorted({row["seed"] for row in rows})
    if len(seeds) == 1:
        return f"One deterministic seed ({seeds[0]}); no confidence intervals."
    return f"Mean of available seed runs ({len(seeds)} seeds overall); faint points show individual runs, not confidence intervals."


def _profile_note(rows):
    profiles = sorted({row["sender_profile"] for row in rows})
    receivers = sorted({row["receiver_profile"] for row in rows})
    return ("Sender: " + ", ".join(profiles) + "; receiver: " + ", ".join(receivers)
            + ". Embedded composite mixes platforms and includes Falcon/SLH lineage proxies where selected.")


def _mean_curve(axis, rows, metric, *, color, marker, label, scale=1):
    grouped = defaultdict(list)
    for row in rows:
        grouped[row["interval_k"]].append(row[metric] * scale)
    xs = sorted(grouped)
    if any(len(values) > 1 for values in grouped.values()):
        for x, values in grouped.items():
            axis.scatter([x] * len(values), values, s=14, alpha=0.28, color=color, zorder=2)
    axis.plot(xs, [statistics.mean(grouped[x]) for x in xs], color=color, marker=marker,
              label=label, linewidth=1.8, markersize=5, zorder=3)


def _axis_style(axis, intervals):
    axis.set_xticks(intervals)
    axis.set_xlabel("Messages per signature, k (maximum with timeout)")
    axis.grid(axis="y", color="#D7DDE4", linewidth=0.6)
    axis.set_axisbelow(True)
    axis.spines[["top", "right"]].set_visible(False)


def _save_figure(figure, destination, stem):
    paths = []
    for suffix in ("svg", "png", "pdf"):
        path = destination / f"{stem}.{suffix}"
        metadata = {"Date": None} if suffix == "svg" else (
            {"CreationDate": None, "ModDate": None} if suffix == "pdf" else None)
        figure.savefig(path, dpi=220, facecolor="white", metadata=metadata)
        paths.append(path)
    return paths


def _draw(replay, screening, output_dir):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.ticker import PercentFormatter
    except ImportError as exc:
        raise RuntimeError("Plotting requires the optional matplotlib dependency; install this project's plotting extra.") from exc
    matplotlib.rcParams.update({"font.size": 9, "axes.titlesize": 10, "axes.labelsize": 9,
                                "svg.fonttype": "none", "pdf.fonttype": 42, "svg.hashsalt": "opensky-replay-v1"})
    rows = replay["rows"]
    scenarios = list(dict.fromkeys(row["scenario"] for row in rows))
    algorithms = list(dict.fromkeys(row["algorithm"] for row in rows))
    intervals = sorted({row["interval_k"] for row in rows})
    columns = min(3, len(scenarios))
    panel_rows = math.ceil(len(scenarios) / columns)
    figure, axes = plt.subplots(panel_rows, columns, figsize=(5 * columns, 3.7 * panel_rows + 2.3),
                                squeeze=False, sharey=True)
    for axis, scenario in zip(axes.flat, scenarios):
        selected = [row for row in rows if row["scenario"] == scenario]
        deadlines = ", ".join(f"{value:g}" for value in sorted({row["max_auth_age_s"] for row in selected}))
        waits = {row["max_batch_wait_s"] for row in selected}
        wait_note = "fixed k" if waits == {None} else "batch wait: " + ", ".join(
            "unbounded" if value is None else f"{value:g} s" for value in sorted(waits, key=lambda value: -1 if value is None else value))
        axis.set_title(f"{scenario.replace('_', ' ')}\nOldest-message deadline: {deadlines} s; {wait_note}", pad=10)
        for index, algorithm in enumerate(algorithms):
            samples = [row for row in selected if row["algorithm"] == algorithm]
            if samples:
                _mean_curve(axis, samples, "timely_authenticated_source_fraction", color=PALETTE[index % len(PALETTE)],
                            marker=MARKERS[index % len(MARKERS)], label=ALGORITHM_LABELS.get(algorithm, algorithm))
        _axis_style(axis, intervals)
        axis.set_ylim(-0.035, 1.04)
        axis.yaxis.set_major_formatter(PercentFormatter(1))
        axis.set_ylabel("Source messages authenticated before deadline")
    for axis in list(axes.flat)[len(scenarios):]:
        axis.set_visible(False)
    handles, labels = axes.flat[0].get_legend_handles_labels()
    figure.suptitle("Modeled timely authentication of the observed trace", fontsize=16, x=0.05, ha="left", y=0.97)
    figure.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 0.90), ncol=min(4, len(algorithms)), frameon=False)
    footer = (_seed_note(rows) + "\n" + textwrap.fill(_profile_note(rows), 155)
              + "\nObserved arrivals proxy sender traffic. Results include unsigned fixed-k tails; no aircraft certification claim.")
    figure.text(0.05, 0.025, footer, ha="left", va="bottom", fontsize=8, color="#44505D")
    figure.subplots_adjust(left=0.07, right=0.97, top=0.79, bottom=0.24, wspace=0.27, hspace=0.55)
    paths = _save_figure(figure, output_dir, "timely_authentication")
    plt.close(figure)

    columns = min(2, len(algorithms))
    panel_rows = math.ceil(len(algorithms) / columns)
    figure, axes = plt.subplots(panel_rows, columns, figsize=(7 * columns, 3.6 * panel_rows + 2.7), squeeze=False)
    screening_by_key = {(row["algorithm"], row["interval_k"]): row for row in screening["rows"]}
    for axis, algorithm in zip(axes.flat, algorithms):
        baseline_rows = [screening_by_key[algorithm, k] for k in intervals]
        baseline = baseline_rows[0]["baseline_offered_airtime_load"]
        axis.set_title(ALGORITHM_LABELS.get(algorithm, algorithm), pad=9)
        axis.plot(intervals, [row["raw_signature_lower_bound_additional_airtime_load"] * 100 for row in baseline_rows],
                  color="#252525", linestyle="--", linewidth=1.8, label="Fixed-k signature-only lower bound")
        axis.plot(intervals, [row["modeled_additional_airtime_load"] * 100 for row in baseline_rows],
                  color="#777777", linestyle=":", linewidth=2.0, label="Fixed-k full-envelope demand, all complete groups")
        for index, scenario in enumerate(scenarios):
            selected = [row for row in rows if row["scenario"] == scenario and row["algorithm"] == algorithm]
            if selected:
                _mean_curve(axis, selected, "additional_offered_airtime_load", scale=100,
                            color=PALETTE[index % len(PALETTE)], marker=MARKERS[index % len(MARKERS)],
                            label="Replay sent: " + scenario.replace("_", " "))
        if baseline < 1:
            axis.axhline((1 - baseline) * 100, color="#A56A13", linewidth=1, linestyle="-.",
                         label="Serial airtime remaining after observed baseline")
        _axis_style(axis, intervals)
        axis.set_yscale("symlog", linthresh=1)
        axis.set_ylim(bottom=0)
        axis.set_ylabel("Additional offered frame-envelope load (%)\nSymmetric log scale; linear below 1%")
    for axis in list(axes.flat)[len(algorithms):]:
        axis.set_visible(False)
    handles, labels = axes.flat[0].get_legend_handles_labels()
    figure.suptitle("Authentication traffic demand and transmitted replay traffic", fontsize=16, x=0.06, ha="left", y=0.975)
    figure.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 0.94), ncol=2, frameon=False, fontsize=8)
    baseline_values = sorted({round(row["baseline_offered_airtime_load"] * 100, 4) for row in rows})
    baseline_note = ", ".join(f"{value:g}%" for value in baseline_values)
    deadlines = ", ".join(f"{value:g} s" for value in sorted({row["max_auth_age_s"] for row in rows}))
    footer = (f"Observed DF17 baseline: {baseline_note}; not included in plotted additional loads. Replay oldest-message deadline: {deadlines}.\n"
              "Bounds assume complete fixed-k groups and no expiry; replay sends only scheduled frames within the observation window.\n"
              "A lower replay load can result from expiry or CPU/queue limits; it is not improved channel feasibility. Loads are not measured RF occupancy.\n"
              "Capacity reference excludes additional background traffic. " + _seed_note(rows) + "\n"
              + textwrap.fill(_profile_note(rows), 155))
    figure.text(0.06, 0.02, footer, ha="left", va="bottom", fontsize=8, color="#44505D")
    figure.subplots_adjust(left=0.09, right=0.98, top=0.80, bottom=0.22, wspace=0.26, hspace=0.48)
    paths.extend(_save_figure(figure, output_dir, "offered_airtime"))
    plt.close(figure)
    return paths


def plot_results(results_dir, output_dir):
    results_dir, output_dir = Path(results_dir), Path(output_dir)
    replay_path = results_dir / "replay_summary.json"
    screening_path = results_dir / "constraint_screening_summary.json"
    replay, screening = _load_report(replay_path, "replay"), _load_report(screening_path, "screening")
    _validate_rows(replay, screening)
    output_dir.mkdir(parents=True, exist_ok=True)
    previous_cache = os.environ.get("MPLCONFIGDIR")
    previous_xdg_cache = os.environ.get("XDG_CACHE_HOME")
    try:
        with tempfile.TemporaryDirectory(prefix="opensky-matplotlib-") as cache:
            if previous_cache is None:
                os.environ["MPLCONFIGDIR"] = cache
            if previous_xdg_cache is None:
                os.environ["XDG_CACHE_HOME"] = cache
            paths = _draw(replay, screening, output_dir)
    finally:
        if previous_cache is None:
            os.environ.pop("MPLCONFIGDIR", None)
        if previous_xdg_cache is None:
            os.environ.pop("XDG_CACHE_HOME", None)
    manifest = {
        "schema_version": 1,
        "source_reports": {str(path): _sha256(path) for path in (replay_path, screening_path)},
        "figure_files": {path.name: _sha256(path) for path in paths},
        "seed_aggregation": "Arithmetic mean of available runs for each scenario/algorithm/k; no confidence intervals.",
        "interpretation": "Modeled replay; published composite hardware includes lineage proxies. Screening counts all complete fixed-k groups; replay counts scheduled transmissions within the observation window and before expiry.",
    }
    manifest_path = output_dir / "figure_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return paths + [manifest_path]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        for path in plot_results(args.results_dir, args.output_dir):
            print(path)
    except (OSError, ValueError, RuntimeError, KeyError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
