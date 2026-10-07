"""Export delayed-authentication coverage, reception, and clock/status figures.

Example: python -m src.experiment.plot_delayed_replay --results-dir RESULTS
--output-dir FIGURES --interval 5

Reads an integrity-checked replay_summary.json. No experiment is run and no
saved report is modified. Matplotlib is the optional plotting dependency.
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


PLOT_VERSION = 1
PALETTE = ("#0072B2", "#D55E00", "#009E73", "#CC79A7", "#E69F00", "#56B4E9")
MARKERS = ("o", "s", "^", "D", "v", "P")
ALGORITHM_LABELS = {
    "ECDSA-P256": "ECDSA P-256", "ML-DSA-44": "ML-DSA-44",
    "FN-DSA-512": "Falcon-512 lineage", "SLH-DSA-SHA2-128s": "SLH-DSA-SHA2-128s",
}


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _number(value, label, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{label} must be finite and nonnegative.")
    if maximum is not None and value > maximum:
        raise ValueError(f"{label} exceeds {maximum}.")
    return value


def _count(value, label):
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer.")
    return value


def _load_report(path):
    report = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(report, dict) or report.get("mode") != "replay" or not report.get("rows"):
        raise ValueError("Expected a nonempty replay report.")
    contents = {key: value for key, value in report.items() if key != "report_sha256"}
    digest = hashlib.sha256(json.dumps(contents, sort_keys=True, separators=(",", ":"),
                                       allow_nan=False).encode()).hexdigest()
    if report.get("report_sha256") != digest:
        raise ValueError("Replay report integrity digest mismatch.")
    return report


def _validate_rows(rows, interval):
    if type(interval) is not int or interval < 1:
        raise ValueError("--interval must be a positive integer.")
    seen = set()
    for row in rows:
        if row.get("replay_model") != "delayed_authentication":
            raise ValueError("Every plotted row must use replay_model=delayed_authentication.")
        key = row["scenario"], row["algorithm"], row["interval_k"], row["seed"]
        if key in seen:
            raise ValueError(f"Duplicate scenario/algorithm/interval/seed: {key}.")
        seen.add(key)
        if _count(row["interval_k"], "interval_k") == 0:
            raise ValueError("interval_k must be positive.")
        _count(row["seed"], "seed")
        total = _count(row["source_messages"], "source_messages")
        if not total:
            raise ValueError("Each row must contain source messages.")
        for prefix in ("baseline", "augmented"):
            received = _count(row[f"{prefix}_original_received_messages"], "received messages")
            fraction = _number(row[f"{prefix}_original_received_fraction"], "received fraction", 1)
            if received > total or not math.isclose(fraction, received / total, abs_tol=1e-12):
                raise ValueError("Reception count and fraction disagree.")
        successful = _count(row["authenticated_messages"], "authenticated_messages")
        failed = _count(row["received_definitive_failure_messages"], "received_definitive_failure_messages")
        pending = _count(row["received_unresolved_messages"], "received_unresolved_messages")
        if successful + failed + pending != row["augmented_original_received_messages"]:
            raise ValueError("Received-message authentication outcomes do not conserve receptions.")
        _number(row["followup_s"], "followup_s")
        for prefix in ("augmented_original_delivery_ms", "receipt_to_auth_ms"):
            for quantile in ("p50", "p95"):
                value = row[f"{prefix}_{quantile}"]
                if value is not None:
                    _number(value, f"{prefix}_{quantile}")
            lower, upper = row[f"{prefix}_p50"], row[f"{prefix}_p95"]
            if (lower is None) != (upper is None) or (lower is not None and lower > upper):
                raise ValueError("Delay percentiles must be ordered or both unavailable.")
        if row["channel_mode"] not in {"independent", "destructive_overlap"}:
            raise ValueError("Unknown channel mode.")
        coverage = row["threshold_coverage"]
        if not isinstance(coverage, list) or not coverage:
            raise ValueError("Every row must contain threshold coverage.")
        thresholds = set()
        for item in coverage:
            threshold = _number(item["threshold_s"], "threshold_s")
            if threshold in thresholds:
                raise ValueError("Duplicate threshold within a replay row.")
            thresholds.add(threshold)
            denominator = _count(item["receipt_eligible_messages"], "receipt_eligible_messages")
            numerator = _count(item["receipt_authenticated_within_threshold_messages"], "threshold successes")
            fraction = item["receipt_authentication_fraction"]
            if denominator > row["augmented_original_received_messages"] or numerator > denominator:
                raise ValueError("Threshold cohort counts are inconsistent.")
            if denominator == 0:
                if fraction is not None:
                    raise ValueError("An empty threshold cohort must have an unavailable fraction.")
            elif fraction is None or not math.isclose(_number(fraction, "coverage fraction", 1),
                                                      numerator / denominator, abs_tol=1e-12):
                raise ValueError("Threshold coverage fraction does not match its cohort counts.")
    if not any(row["interval_k"] == interval for row in rows):
        raise ValueError(f"No rows for k={interval}; choose an available --interval.")


def _scenario_title(rows):
    scenario = rows[0]["scenario"].replace("_", " ")
    modes = {row["channel_mode"] for row in rows}
    channel = "independent reception control" if modes == {"independent"} else "destructive overlap sensitivity"
    waits = {row["max_batch_wait_s"] for row in rows}
    batching = "fixed count" if waits == {None} else "batch wait ≤ " + ", ".join(
        "unbounded" if value is None else f"{value:g} s"
        for value in sorted(waits, key=lambda value: -1 if value is None else value))
    return f"{scenario}\n{channel}; {batching}"


def _common_note(rows):
    followups = ", ".join(f"{value:g} s" for value in sorted({row["followup_s"] for row in rows}))
    seeds = sorted({row["seed"] for row in rows})
    seed_note = (f"One deterministic seed ({seeds[0]}); no confidence intervals." if len(seeds) == 1
                 else f"Means of available seed runs ({len(seeds)} seeds overall); no confidence intervals.")
    senders = ", ".join(sorted({row["sender_profile"] for row in rows}))
    receivers = ", ".join(sorted({row["receiver_profile"] for row in rows}))
    profile = f"Hardware profiles: sender {senders}; receiver {receivers}."
    if "embedded_reference" in senders or "embedded_reference" in receivers:
        profile += " Composite embedded references mix platforms and include lineage proxies; no aircraft WCET claim."
    else:
        profile += " Profile assumptions and implementation equivalence are retained in the source report; no aircraft WCET claim."
    return [
        f"Follow-up after capture: {followups}; finite observation horizon, with no authentication-age expiry. {seed_note}",
        "Destructive overlap is an uncalibrated sensitivity model: one collision domain, all overlaps erased, no power/capture effects.",
        profile,
    ]


def _style(axis):
    axis.grid(axis="y", color="#D9DFE6", linewidth=0.6)
    axis.set_axisbelow(True)
    axis.spines[["top", "right"]].set_visible(False)


def _footer(figure, lines, width=160):
    text = "\n".join(textwrap.fill(line, width) for line in lines)
    figure.text(0.055, 0.018, text, ha="left", va="bottom", fontsize=7.7, color="#465260")


def _save(figure, destination, stem):
    paths = []
    for suffix in ("svg", "png", "pdf"):
        path = destination / f"{stem}.{suffix}"
        metadata = {"Date": None} if suffix == "svg" else (
            {"CreationDate": None, "ModDate": None} if suffix == "pdf" else None)
        figure.savefig(path, dpi=220, facecolor="white", metadata=metadata)
        paths.append(path)
    return paths


def _draw(report, output_dir, interval):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        from matplotlib.lines import Line2D
        from matplotlib.patches import Patch
        from matplotlib.ticker import NullFormatter, PercentFormatter
    except ImportError as exc:
        raise RuntimeError("Install the project's optional matplotlib plotting dependency to export figures.") from exc
    matplotlib.rcParams.update({"font.size": 9, "axes.titlesize": 10, "axes.labelsize": 9,
                                "svg.fonttype": "none", "pdf.fonttype": 42,
                                "svg.hashsalt": f"opensky-delayed-replay-v{PLOT_VERSION}"})
    rows = report["rows"]
    scenarios = list(dict.fromkeys(row["scenario"] for row in rows))
    algorithms = list(dict.fromkeys(row["algorithm"] for row in rows))
    colors = {name: PALETTE[index % len(PALETTE)] for index, name in enumerate(algorithms)}
    markers = {name: MARKERS[index % len(MARKERS)] for index, name in enumerate(algorithms)}
    selected_interval = [row for row in rows if row["interval_k"] == interval]
    columns = min(2, len(scenarios))
    panel_rows = math.ceil(len(scenarios) / columns)
    dimensions = (7 * columns, 3.3 * panel_rows + 2.8)
    figure, axes = plt.subplots(panel_rows, columns, figsize=dimensions, squeeze=False, sharey=True)
    for axis, scenario in zip(axes.flat, scenarios):
        selected = [row for row in selected_interval if row["scenario"] == scenario]
        all_case_rows = [row for row in rows if row["scenario"] == scenario]
        axis.set_title(_scenario_title(all_case_rows), pad=10)
        thresholds = set()
        for algorithm in algorithms:
            grouped = defaultdict(list)
            for row in selected:
                if row["algorithm"] == algorithm:
                    for item in row["threshold_coverage"]:
                        thresholds.add(item["threshold_s"])
                        if item["receipt_authentication_fraction"] is not None:
                            grouped[item["threshold_s"]].append(item["receipt_authentication_fraction"])
            xs = sorted(grouped)
            if xs:
                axis.plot(xs, [statistics.mean(grouped[x]) for x in xs], color=colors[algorithm],
                          marker=markers[algorithm], linewidth=1.8, markersize=5,
                          label=ALGORITHM_LABELS.get(algorithm, algorithm))
                for x, values in grouped.items():
                    if len(values) > 1:
                        axis.scatter([x] * len(values), values, color=colors[algorithm], s=14, alpha=0.3)
        if thresholds:
            axis.set_xscale("log" if min(thresholds) > 0 else "symlog", **({} if min(thresholds) > 0 else {"linthresh": 1}))
            axis.set_xticks(sorted(thresholds), [f"{value:g}" for value in sorted(thresholds)])
            axis.xaxis.set_minor_formatter(NullFormatter())
        else:
            axis.text(0.5, 0.5, f"No k={interval} observations", transform=axis.transAxes, ha="center")
        axis.set_xlabel("Time allowed after original reception (s)")
        axis.set_ylabel("Authenticated / eligible received messages")
        axis.set_ylim(-0.025, 1.025)
        axis.yaxis.set_major_formatter(PercentFormatter(1))
        _style(axis)
    for axis in list(axes.flat)[len(scenarios):]:
        axis.set_visible(False)
    legend = [Line2D([], [], color=colors[name], marker=markers[name], label=ALGORITHM_LABELS.get(name, name))
              for name in algorithms]
    figure.suptitle(f"Authentication after ordinary reception — k={interval}", fontsize=16, x=0.055, ha="left", y=0.975)
    figure.legend(handles=legend, loc="upper center", bbox_to_anchor=(0.5, 0.935),
                  ncol=min(4, len(algorithms)), frameon=False)
    _footer(figure, [
        "Each threshold uses its own fully observed reception-anchored cohort; messages without full follow-up are excluded from that denominator.",
        "Pending eligible messages miss that threshold but remain unresolved for eventual authentication. Curves are modeled verification-service completion.",
        *_common_note(rows),
    ])
    figure.subplots_adjust(left=0.075, right=0.975, top=0.845, bottom=0.235, hspace=0.62, wspace=0.24)
    paths = _save(figure, output_dir, "authentication_coverage")
    plt.close(figure)

    figure, axes = plt.subplots(panel_rows, columns, figsize=dimensions, squeeze=False, sharey=True)
    intervals = sorted({row["interval_k"] for row in rows})
    for axis, scenario in zip(axes.flat, scenarios):
        selected = [row for row in rows if row["scenario"] == scenario]
        axis.set_title(_scenario_title(selected), pad=10)
        baseline_by_case = defaultdict(list)
        for row in selected:
            baseline_by_case[row["interval_k"], row["seed"]].append(row["baseline_original_received_fraction"])
        # One shared baseline line is valid only when algorithms retain the
        # same baseline population/noise under each paired scenario and seed.
        if any(max(values) - min(values) > 1e-12 for values in baseline_by_case.values()):
            raise ValueError("Paired baseline reception differs between algorithms in one scenario/seed/k.")
        baseline_by_k = defaultdict(list)
        for (k, _), values in baseline_by_case.items():
            baseline_by_k[k].append(values[0])
        xs = sorted(baseline_by_k)
        axis.plot(xs, [statistics.mean(baseline_by_k[x]) for x in xs], color="#252525",
                  linestyle="--", linewidth=2, marker="x", label="Paired baseline: ordinary traffic only", zorder=5)
        for algorithm in algorithms:
            grouped = defaultdict(list)
            for row in selected:
                if row["algorithm"] == algorithm:
                    grouped[row["interval_k"]].append(row["augmented_original_received_fraction"])
            xs = sorted(grouped)
            if xs:
                axis.plot(xs, [statistics.mean(grouped[x]) for x in xs], color=colors[algorithm],
                          marker=markers[algorithm], linewidth=1.8, markersize=5,
                          label=ALGORITHM_LABELS.get(algorithm, algorithm))
                for x, values in grouped.items():
                    if len(values) > 1:
                        axis.scatter([x] * len(values), values, color=colors[algorithm], s=14, alpha=0.3)
        axis.set_xticks(intervals)
        axis.set_xlabel("Messages per signature, k (maximum with timeout)")
        axis.set_ylabel("Ordinary messages received / source messages")
        axis.set_ylim(-0.025, 1.025)
        axis.yaxis.set_major_formatter(PercentFormatter(1))
        _style(axis)
    for axis in list(axes.flat)[len(scenarios):]:
        axis.set_visible(False)
    baseline_handle = Line2D([], [], color="#252525", linestyle="--", marker="x", label="Ordinary traffic only")
    figure.suptitle("Effect of added authentication traffic on ordinary reception", fontsize=16, x=0.055, ha="left", y=0.975)
    figure.legend(handles=[baseline_handle, *legend], loc="upper center", bbox_to_anchor=(0.5, 0.935),
                  ncol=min(3, len(algorithms) + 1), frameon=False)
    _footer(figure, [
        "Dashed baseline and colored authentication cases share the same original transmissions and exogenous loss draws; denominator is all source messages.",
        "Original emissions are never held for signing. Differences here reflect reception loss from modeled added traffic, not an airborne transmission delay.",
        *_common_note(rows),
    ])
    figure.subplots_adjust(left=0.075, right=0.975, top=0.815, bottom=0.235, hspace=0.62, wspace=0.24)
    paths.extend(_save(figure, output_dir, "surveillance_impact"))
    plt.close(figure)

    figure, axes = plt.subplots(len(scenarios), 2, figsize=(14, 2.35 * len(scenarios) + 3.1), squeeze=False)
    states = [
        ("Authenticated", "#009E73"), ("Received: definitive failure", "#D99A45"),
        ("Received: pending at horizon", "#738EC2"), ("Original not received", "#4F5966"),
    ]
    for row_index, scenario in enumerate(scenarios):
        latency_axis, status_axis = axes[row_index]
        samples = [row for row in selected_interval if row["scenario"] == scenario]
        for index, algorithm in enumerate(algorithms):
            cases = [row for row in samples if row["algorithm"] == algorithm]
            if not cases:
                continue
            for prefix, offset, marker, color in (
                ("augmented_original_delivery_ms", -0.12, "o", "#30363D"),
                ("receipt_to_auth_ms", 0.12, "s", colors[algorithm]),
            ):
                valid = [row for row in cases if row[f"{prefix}_p50"] is not None]
                if valid:
                    median = statistics.mean(row[f"{prefix}_p50"] for row in valid) / 1000
                    upper = statistics.mean(row[f"{prefix}_p95"] for row in valid) / 1000
                    latency_axis.plot([median, upper], [index + offset] * 2, color=color, linewidth=1.7)
                    latency_axis.plot(median, index + offset, marker=marker, color=color, markersize=5)
                    latency_axis.plot(upper, index + offset, marker="|", color=color, markersize=9)
                elif prefix == "receipt_to_auth_ms":
                    latency_axis.text(0.98, index + offset, "no completed authentication", fontsize=7,
                                      transform=latency_axis.get_yaxis_transform(), ha="right", va="center", color="#687482")
            fractions = [
                statistics.mean(row["authenticated_messages"] / row["source_messages"] for row in cases),
                statistics.mean(row["received_definitive_failure_messages"] / row["source_messages"] for row in cases),
                statistics.mean(row["received_unresolved_messages"] / row["source_messages"] for row in cases),
                statistics.mean(1 - row["augmented_original_received_fraction"] for row in cases),
            ]
            left = 0
            for fraction, (_, color) in zip(fractions, states):
                status_axis.barh(index, fraction, left=left, height=0.65, color=color,
                                 edgecolor="white", linewidth=0.35)
                left += fraction
        for axis in (latency_axis, status_axis):
            axis.set_yticks(range(len(algorithms)), [ALGORITHM_LABELS.get(name, name) for name in algorithms])
            axis.set_ylim(len(algorithms) - 0.5, -0.5)
            _style(axis)
            axis.grid(False, axis="y")
            axis.grid(True, axis="x", color="#D9DFE6", linewidth=0.6)
        latency_axis.set_xscale("symlog", linthresh=0.001)
        latency_axis.set_xlim(left=-0.00005)
        latency_axis.set_xlabel("Elapsed time (s): linear below 1 ms, log above")
        latency_axis.set_title(_scenario_title([row for row in rows if row["scenario"] == scenario]), pad=8)
        status_axis.set_xlim(0, 1)
        status_axis.xaxis.set_major_formatter(PercentFormatter(1))
        status_axis.set_xlabel("Fraction of all source messages at observation horizon")
        status_axis.set_title("Completed, failed, and still unresolved", pad=8)
    figure.suptitle(f"Separate reception and authentication clocks — k={interval}", fontsize=16, x=0.055, ha="left", y=0.985)
    clock_legend = [
        Line2D([], [], color="#30363D", marker="o", label="Source proxy → ordinary reception"),
        Line2D([], [], color="#0072B2", marker="s", label="Ordinary reception → authentication"),
        Line2D([], [], color="#555555", marker="|", label="Marker: median; line ends at p95"),
    ]
    figure.legend(handles=clock_legend, loc="upper center", bbox_to_anchor=(0.5, 0.96), ncol=3, frameon=False, fontsize=8)
    figure.legend(handles=[Patch(facecolor=color, label=name) for name, color in states],
                  loc="upper center", bbox_to_anchor=(0.5, 0.932), ncol=4, frameon=False, fontsize=8)
    _footer(figure, [
        "Delay percentiles condition on completed receptions/authentications; compare them with pending and lost fractions at right. Zero completions are not zero latency.",
        "Across multiple seeds, plotted medians and p95 values are means of per-run percentiles, not pooled percentiles. Pending work is censored, not declared permanently failed.",
        "Source timestamps proxy observed emissions; onboard measurement age is unavailable. Authentication does not delay ordinary transmission.",
        *_common_note(rows),
    ])
    figure.subplots_adjust(left=0.155, right=0.985, top=0.86, bottom=0.20, hspace=0.78, wspace=0.48)
    paths.extend(_save(figure, output_dir, "authentication_clocks_and_pending"))
    plt.close(figure)
    return paths


def plot_results(results_dir, output_dir, interval=5):
    results_dir, output_dir = Path(results_dir), Path(output_dir)
    replay_path = results_dir / "replay_summary.json"
    report = _load_report(replay_path)
    _validate_rows(report["rows"], interval)
    output_dir.mkdir(parents=True, exist_ok=True)
    previous_cache = os.environ.get("MPLCONFIGDIR")
    previous_xdg = os.environ.get("XDG_CACHE_HOME")
    try:
        with tempfile.TemporaryDirectory(prefix="opensky-delayed-matplotlib-") as cache:
            if previous_cache is None:
                os.environ["MPLCONFIGDIR"] = cache
            if previous_xdg is None:
                os.environ["XDG_CACHE_HOME"] = cache
            with tempfile.TemporaryDirectory(prefix=".delayed-figures-", dir=output_dir) as staged:
                staged = Path(staged)
                staged_paths = _draw(report, staged, interval)
                manifest = {
                    "schema_version": 1, "plot_version": PLOT_VERSION,
                    "replay_model": "delayed_authentication", "selected_interval_k": interval,
                    "source_reports": {str(replay_path): _sha256(replay_path)},
                    "plot_source_sha256": _sha256(__file__),
                    "figure_files": {path.name: _sha256(path) for path in staged_paths},
                    "seed_aggregation": "Arithmetic means of per-run fractions or percentiles; no confidence intervals and no pooled delay percentiles.",
                    "interpretation": "Reception-anchored threshold cohorts require full follow-up; horizon-pending authentication remains censored. Destructive overlap is uncalibrated; hardware profiles may include lineage proxies.",
                }
                staged_manifest = staged / "delayed_figure_manifest.json"
                staged_manifest.write_text(json.dumps(manifest, indent=2, allow_nan=False) + "\n", encoding="utf-8")
                paths = []
                # The manifest is the last published artifact and checks every
                # image against the exact report and plotting source consumed.
                for path in [*staged_paths, staged_manifest]:
                    destination = output_dir / path.name
                    os.replace(path, destination)
                    paths.append(destination)
                return paths
    finally:
        if previous_cache is None:
            os.environ.pop("MPLCONFIGDIR", None)
        if previous_xdg is None:
            os.environ.pop("XDG_CACHE_HOME", None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--interval", type=int, default=5, help="k shown in coverage and clock/status figures (default: 5). Reception impact shows every available k.")
    args = parser.parse_args(argv)
    try:
        for path in plot_results(args.results_dir, args.output_dir, args.interval):
            print(path)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
