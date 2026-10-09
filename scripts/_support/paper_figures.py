#!/usr/bin/env python3
"""Render compact paper figures from completed result tables; never sign or replay.

Run from the repository root: .venv/bin/python scripts/06_paper_figures.py
The paired figures are sized for a 7-inch text block. Values and input hashes
are retained in the manifest.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile


ROOT = Path(__file__).resolve().parents[2]
WINDOWS = ("daytime", "nighttime")
ALGORITHMS = ("ECDSA-P256", "FN-DSA-512", "ML-DSA-44")
SLH = "SLH-DSA-SHA2-128s"
LABELS = {
    "ECDSA-P256": "ECDSA P-256 (classical)",
    "FN-DSA-512": "Falcon-512",
    "ML-DSA-44": "ML-DSA-44",
    SLH: "SLH-DSA (analytical only)",
}
GROUPS = (1, 5, 10, 20)
DEADLINES = (1, 5, 10, 30, 60, 300, 600)
CONTROL = "detached_independent_r50"
RECEIVERS = (CONTROL, CONTROL + "_workers4", CONTROL + "_verify1ms")


def number(row, key):
    value = float(row[key])
    if not math.isfinite(value):
        raise ValueError(f"Non-finite {key}: {row[key]!r}")
    return value


def unique(rows, **conditions):
    matches = [r for r in rows if all(r.get(k) == str(v) for k, v in conditions.items())]
    if len(matches) != 1:
        raise ValueError(f"Expected one row for {conditions}; found {len(matches)}")
    return matches[0]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_inputs(results):
    data, hashes = {}, {}
    for window in WINDOWS:
        base = results / window
        paths = {
            "bounds": base / "figures/signature_airtime_lower_bounds.csv",
            "deadlines": base / "figures/authentication_deadline_summary.csv",
            "cases": base / "figures/case_summary.csv",
            "traffic": base / "01_prepared/traffic.json",
            "prepared": base / "01_prepared/manifest.json",
        }
        data[window] = {}
        for kind, path in paths.items():
            hashes[str(path.relative_to(results))] = sha256(path)
            with path.open(encoding="utf-8", newline="") as stream:
                data[window][kind] = list(csv.DictReader(stream)) if path.suffix == ".csv" else json.load(stream)
        item = data[window]
        params = item["prepared"]["parameters"]
        target = float(params["target_duration_s"])
        followup = float(params["followup_s"])
        if target != 3600 or followup != 600:
            raise ValueError("These paper figures require a 3600 s target and 600 s follow-up")
        expected = int(item["prepared"]["experimental_trace"]["records"])
        for algorithm in ALGORITHMS:
            for group in GROUPS:
                row = unique(item["cases"], algorithm=algorithm, interval_k=group, scenario=CONTROL)
                if number(row, "source_messages_mean") != expected or int(row["seed_count"]) != 1:
                    raise ValueError("Control source count or deterministic run count is inconsistent")
        item["target_s"] = target
        item["horizon_s"] = target + followup
        item["source_messages"] = expected
    return data, hashes


def save_figure(figure, name, output, manifest, details, plt):
    path = output / f"{name}.pdf"
    figure.savefig(path, dpi=220, metadata={"CreationDate": None, "ModDate": None})
    manifest["figures"][name] = {"files": [path.name], **details}
    plt.close(figure)


def bounds_figure(data, output, manifest, plt, np):
    algorithms = ALGORITHMS + (SLH,)
    colors = ("#0072B2", "#009E73", "#E69F00", "#CC79A7")
    fig, axes = plt.subplots(1, 2, figsize=(7, 3.15), sharey=True)
    values = {}
    for ax, window in zip(axes, WINDOWS):
        values[window] = {}
        for index, (algorithm, color) in enumerate(zip(algorithms, colors)):
            heights = []
            for group in GROUPS:
                row = unique(data[window]["bounds"], algorithm=algorithm, interval_k=group)
                required = number(row, "required_airtime_s")
                percent = number(row, "target_window_airtime_pct")
                if not math.isclose(percent, 100 * required / data[window]["target_s"], rel_tol=1e-10):
                    raise ValueError("Airtime percentage disagrees with saved frame demand")
                if percent <= 0 or number(row, "groups") <= 0:
                    raise ValueError("Logarithmic screening plot requires positive demand and groups")
                if number(row, "payload_bytes_per_frame") != 7:
                    raise ValueError("Screening figure assumes seven signature bytes per frame")
                heights.append(percent)
            values[window][algorithm] = dict(zip(map(str, GROUPS), heights))
            ax.bar(np.arange(4) + (index - 1.5) * 0.19, heights, width=0.18,
                   color=color, label=LABELS[algorithm], hatch="///" if algorithm == SLH else None,
                   edgecolor="black" if algorithm == SLH else "none", linewidth=0.4)
        ax.set(yscale="log", xticks=np.arange(4), xticklabels=[str(k) for k in GROUPS],
               xlabel="Messages per signature, $k$", title=window.title())
        ax.axhline(100, color="0.25", linestyle="--", linewidth=0.8)
        ax.grid(axis="y", which="major", alpha=0.2)
        ax.set_axisbelow(True)
    axes[0].set_ylabel("Signature-only airtime / target hour (%)")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.53, 1.01), ncol=2,
               frameon=False, handlelength=1.5, columnspacing=1.8)
    fig.subplots_adjust(left=0.105, right=0.985, bottom=0.18, top=0.77, wspace=0.12)
    save_figure(fig, "01_signature_airtime_bounds", output, manifest, {
        "values_pct_target_hour": values,
        "classical_reference": "ECDSA-P256",
        "interpretation": "Optimistic signature-only demand; excludes ordinary frames and protocol metadata. ECDSA is the classical reference. SLH analytical only. 100% line is one target hour, not an operational capacity threshold.",
    }, plt)


def traffic_figure(data, output, manifest, plt, np):
    dfs = sorted({int(df) for item in data.values() for df in item["traffic"]["cumulative_by_df"]})
    colors = plt.get_cmap("tab10")
    if len(dfs) > 10:
        raise ValueError("More than ten DF series need a larger distinct color palette")
    fig, axes = plt.subplots(1, 2, figsize=(7, 3.1), sharex=True, sharey=True)
    counts = {}
    for ax, window in zip(axes, WINDOWS):
        item = data[window]
        times = np.asarray(item["traffic"]["time_s"], dtype=float)
        horizon, target = item["horizon_s"], item["target_s"]
        if not np.all(np.isfinite(times)) or times[0] != 0 or np.any(np.diff(times) <= 0):
            raise ValueError("Traffic bin-end times must be finite, start at zero and increase")
        if target not in times or horizon not in times:
            raise ValueError("Saved traffic bins must include the exact target and follow-up boundaries")
        mask = times <= horizon
        target_i = int(np.flatnonzero(times == target)[0])
        horizon_i = int(np.flatnonzero(times == horizon)[0])
        counts[window] = {}
        for index, df in enumerate(dfs):
            series = item["traffic"]["cumulative_by_df"].get(str(df))
            values = np.zeros(len(times), dtype=int) if series is None else np.asarray(series["messages"])
            if len(values) != len(times) or not np.all(np.isfinite(values)) or np.any(values < 0) or np.any(np.diff(values) < 0) or np.any(values != np.floor(values)):
                raise ValueError(f"Invalid cumulative counts for {window}, DF {df}")
            counts[window][str(df)] = {"first_hour": int(values[target_i]), "through_followup": int(values[horizon_i])}
            ax.step(times[mask] / 60, values[mask] / 1e6, where="post", color=colors(index),
                    linewidth=1.35 if df == 17 else 1.05, label=f"DF {df}")
        if counts[window]["17"]["first_hour"] != item["source_messages"]:
            raise ValueError("DF17 first-hour count disagrees with target source messages")
        ax.axvspan(target / 60, horizon / 60, color="0.93", zorder=0)
        ax.axvline(target / 60, color="0.35", linestyle="--", linewidth=0.8)
        ax.set(xlim=(0, horizon / 60), ylim=(0, None), xticks=np.arange(0, 71, 10),
               xlabel="Minutes since recording start", title=window.title())
        ax.grid(alpha=0.17)
        ax.set_axisbelow(True)
    axes[0].set_ylabel("Cumulative decoded frames (millions)")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.53, 1.005), ncol=5,
               frameon=False, handlelength=1.7, columnspacing=1.25)
    fig.subplots_adjust(left=0.105, right=0.985, bottom=0.18, top=0.77, wspace=0.12)
    save_figure(fig, "02_recorded_traffic", output, manifest, {
        "recorded_frame_counts": counts,
        "interpretation": "Cumulative exported decoded Mode S frames at saved bin ends, truncated to exactly the target plus follow-up horizon. Shading denotes follow-up. No inference of unobserved traffic.",
    }, plt)


def deadlines_figure(data, output, manifest, plt, np):
    rows = [(algorithm, group) for algorithm in ALGORITHMS for group in GROUPS]
    fig, axes = plt.subplots(1, 2, figsize=(7, 4.15), sharey=True)
    values = {}
    for ax, window in zip(axes, WINDOWS):
        matrix = []
        for algorithm, group in rows:
            line = []
            for deadline in DEADLINES:
                row = unique(data[window]["deadlines"], algorithm=algorithm, interval_k=group,
                             scenario=CONTROL, anchor="source", deadline_s=f"{deadline:.1f}")
                if int(row["seed_count"]) != 1 or number(row, "excluded_due_to_followup_messages_mean") != 0:
                    raise ValueError("Deadline plot requires a deterministic control with complete follow-up")
                eligible = number(row, "eligible_messages_mean")
                authenticated = number(row, "authenticated_messages_mean")
                percent = number(row, "authenticated_pct_eligible_mean")
                if eligible != data[window]["source_messages"] or not 0 <= authenticated <= eligible:
                    raise ValueError("Deadline numerator or all-target denominator is inconsistent")
                if not math.isclose(percent, 100 * authenticated / eligible, rel_tol=1e-9, abs_tol=1e-12):
                    raise ValueError("Saved authentication percentage disagrees with counts")
                line.append(percent)
            matrix.append(line)
        values[window] = matrix
        im = ax.imshow(np.asarray(matrix), vmin=0, vmax=100, cmap="viridis", aspect="auto")
        for i, line in enumerate(matrix):
            for j, value in enumerate(line):
                label = "0" if value == 0 else ("<0.1" if value < 0.1 else f"{value:.1f}")
                ax.text(j, i, label, ha="center", va="center", fontsize=7.2,
                        color="white" if value < 50 else "#151515")
        ax.set(xticks=range(len(DEADLINES)), xticklabels=[str(x) for x in DEADLINES],
               yticks=range(len(rows)), title=window.title(), xlabel="Deadline from source timestamp (s)")
        for boundary in (3.5, 7.5):
            ax.axhline(boundary, color="white", linewidth=1)
        ax.tick_params(axis="both", length=0)
    short = {"ECDSA-P256": "ECDSA", "FN-DSA-512": "Falcon", "ML-DSA-44": "ML-DSA"}
    axes[0].set_yticklabels([f"{short[a]}  $k={k}$" for a, k in rows])
    fig.suptitle("No-interference control · 50 authentication frames/s per aircraft", fontsize=9, y=0.985)
    fig.subplots_adjust(left=0.135, right=0.87, bottom=0.13, top=0.865, wspace=0.12)
    color_ax = fig.add_axes((0.893, 0.13, 0.017, 0.735))
    fig.colorbar(im, cax=color_ax, ticks=(0, 25, 50, 75, 100), label="Authenticated (% of all targets)")
    save_figure(fig, "03_authentication_deadlines", output, manifest, {
        "scenario": CONTROL, "anchor": "source", "denominator": "all first-hour target messages",
        "classical_reference": "ECDSA-P256",
        "deadlines_s": list(DEADLINES), "row_order": [[a, k] for a, k in rows], "values_pct": values,
        "interpretation": "Single reference verification worker; per-message deadlines, not the common replay cutoff. Exact zeros displayed as 0; positive values below 0.1% displayed as <0.1.",
    }, plt)


def receiver_figure(data, output, manifest, plt, np):
    fig, axes = plt.subplots(1, 2, figsize=(7, 3.25), sharey=True)
    receiver_labels = ("1 reference worker", "4 reference workers", "1 assumed 1 ms worker")
    colors = ("#0072B2", "#009E73", "#E69F00")
    values = {}
    for ax, window in zip(axes, WINDOWS):
        values[window] = {algorithm: {} for algorithm in ALGORITHMS}
        for index, (scenario, label, color) in enumerate(zip(RECEIVERS, receiver_labels, colors)):
            heights = []
            for algorithm in ALGORITHMS:
                row = unique(data[window]["cases"], algorithm=algorithm, interval_k=1, scenario=scenario)
                percent = number(row, "authenticated_pct_source_mean")
                source = number(row, "source_messages_mean")
                count = number(row, "authenticated_messages_mean")
                if int(row["seed_count"]) != 1 or source != data[window]["source_messages"] or not 0 <= count <= source:
                    raise ValueError("Invalid deterministic receiver sensitivity counts")
                if not math.isclose(percent, 100 * count / source, rel_tol=1e-9):
                    raise ValueError("Receiver sensitivity percentage disagrees with saved counts")
                heights.append(percent)
                values[window][algorithm][scenario] = percent
            bars = ax.bar(np.arange(3) + (index - 1) * 0.26, heights, width=0.24,
                          label=label, color=color)
            ax.bar_label(bars, labels=[f"{v:.1f}" for v in heights], padding=2, fontsize=7.2)
        ax.set(ylim=(0, 107), yticks=(0, 25, 50, 75, 100), xticks=range(3),
               xticklabels=["ECDSA P-256\n(classical reference)", "Falcon-512", "ML-DSA-44"],
               title=window.title())
        ax.grid(axis="y", alpha=0.2)
        ax.set_axisbelow(True)
    axes[0].set_ylabel("Authenticated at cutoff (% of all targets)")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.54, 0.94),
               ncol=3, frameon=False, handlelength=1.4, columnspacing=1.6)
    fig.suptitle("Per-message authentication ($k=1$) · no interference · 50 frames/s per aircraft",
                 fontsize=9, y=0.995)
    fig.subplots_adjust(left=0.09, right=0.985, bottom=0.17, top=0.75, wspace=0.12)
    save_figure(fig, "04_verifier_capacity", output, manifest, {
        "algorithms": list(ALGORITHMS), "classical_reference": "ECDSA-P256", "interval_k": 1,
        "receiver_scenarios": list(RECEIVERS), "values_pct_all_targets": values,
        "interpretation": "Per-message authentication by the target-plus-follow-up cutoff, with no interference and fixed 50-frame/s pacing. ECDSA is the classical reference. Reference workers use each algorithm's declared benchmark profile; the 1 ms verification time is assumed, not measured.",
    }, plt)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=ROOT / "results")
    parser.add_argument("--output-dir", type=Path, default=None,
                        help="Default: <results-dir>/paper/figures")
    args = parser.parse_args(argv)
    results = args.results_dir.resolve()
    output = args.output_dir.resolve() if args.output_dir else results / "paper/figures"
    data, hashes = read_inputs(results)
    output.mkdir(parents=True, exist_ok=True)
    manifest = {"schema_version": 1, "generator": "scripts/06_paper_figures.py",
                "generator_sha256": sha256(ROOT / "scripts" / "06_paper_figures.py"),
                "implementation": "scripts/_support/paper_figures.py",
                "implementation_sha256": sha256(Path(__file__)), "source_sha256": hashes,
                "figures": {}}
    with tempfile.TemporaryDirectory(prefix="adsb-paper-matplotlib-") as cache:
        os.environ.setdefault("MPLCONFIGDIR", cache)
        os.environ.setdefault("XDG_CACHE_HOME", cache)
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np
        matplotlib.rcParams.update({"font.size": 8, "axes.titlesize": 9,
                                    "axes.labelsize": 8, "xtick.labelsize": 8,
                                    "ytick.labelsize": 8, "legend.fontsize": 8,
                                    "axes.spines.top": False, "axes.spines.right": False,
                                    "pdf.fonttype": 42, "svg.fonttype": "none",
                                    "svg.hashsalt": "adsb-paper-figures-v1"})
        for make in (bounds_figure, traffic_figure, deadlines_figure, receiver_figure):
            make(data, output, manifest, plt, np)
        manifest["matplotlib_version"] = matplotlib.__version__
        manifest["numpy_version"] = np.__version__
    manifest["artifact_sha256"] = {
        name: sha256(output / name)
        for detail in manifest["figures"].values() for name in detail["files"]
    }
    (output / "figure_manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Generated four PDF paper figures and input manifest in {output}")


if __name__ == "__main__":
    main()
