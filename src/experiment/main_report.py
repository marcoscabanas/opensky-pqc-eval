"""Generate the main experiment's figures from integrity-checked replay outputs.

This module never signs messages or reruns the simulator. All cases are retained;
no algorithm, grouping size or channel scenario is selected for favorable results.
"""

from contextlib import contextmanager
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile

from src.experiment.result_validation import LABELS, load_report, metric_matrix


BACKLOG = {
    "sender_unfinished_groups": "Signing unfinished groups",
    "transmission_unfinished_groups": "Transmission unfinished groups",
    "receiver_unfinished_groups": "Verification unfinished groups",
}


def _hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _number(value, label):
    if type(value) not in (float, int) or not math.isfinite(value) or value < 0:
        raise ValueError(f"Invalid nonnegative metric: {label}")
    return value


def _percent(numerator, denominator):
    return None if denominator == 0 else 100 * numerator / denominator


def _scenario_label(scenario):
    parameters = scenario["parameters"]
    channel = ("Collision-free" if parameters["channel_mode"] == "independent"
               else "Destructive overlap")
    return f"{channel}\n{parameters['auth_frames_per_second']:g} auth frames/s/aircraft"


def case_metrics(row):
    """Expose demand, transmitted load and explicitly denominated failure rates."""
    duration = _number(row["trace_duration_s"], "trace_duration_s")
    if duration <= 0:
        raise ValueError("A positive trace duration is required for channel load.")
    source = row["source_messages"]
    transmitted = _number(row["ordinary_frames_transmitted"], "ordinary_frames_transmitted")
    lost = _number(row["ordinary_frames_rf_lost"], "ordinary_frames_rf_lost")
    if lost > transmitted:
        raise ValueError("RF losses cannot exceed transmitted ordinary frames.")
    result = {
        "algorithm": row["algorithm"], "interval_k": row["interval_k"], "scenario": row["scenario"],
        "source_messages": source, "ordinary_frames_transmitted": transmitted,
        "ordinary_frames_rf_lost": lost,
        "ordinary_frames_in_flight_at_horizon": row["ordinary_frames_in_flight_at_horizon"],
        "ordinary_messages_unsent_pending": row["ordinary_messages_unsent_pending"],
        "ordinary_messages_withheld_definitively": row["ordinary_messages_withheld_definitively"],
        "baseline_nonreception_pct_source": _percent(source - row["baseline_original_received_messages"], source),
        "augmented_nonreception_pct_source": _percent(source - row["augmented_original_received_messages"], source),
        "augmented_rf_failure_pct_transmitted": _percent(lost, transmitted),
        "authentication_added_rf_loss_pct_source": row["authentication_only_additional_rf_loss_fraction"] * 100,
        "baseline_offered_airtime_pct": row["baseline_offered_airtime_load"] * 100,
        "augmented_offered_airtime_pct": row["augmented_offered_airtime_load"] * 100,
        "actual_added_airtime_pct": row["additional_offered_airtime_load"] * 100,
        "required_authentication_airtime_pct": row["prototype_required_authentication_airtime_s"] / duration * 100,
        "required_authentication_frames": row["prototype_required_authentication_frames"],
        "authentication_frames_sent": row["auth_frames_transmitted"],
        "authentication_airtime_seconds_followup": row["authentication_airtime_seconds_followup"],
        "ordinary_transmission_delay_ms_p95": row["ordinary_transmission_delay_ms_p95"],
        "authenticated_pct_source": _percent(row["authenticated_messages"], source),
        "authenticated_messages": row["authenticated_messages"],
        "pending_messages": row["unresolved_messages"],
        "definitive_failure_messages": row["definitive_failure_messages"],
        "unsigned_tail_messages": row["unsigned_tail_messages"],
    }
    for name, value in result.items():
        if name not in ("algorithm", "scenario") and value is not None:
            _number(value, name)
    return result


def coverage_rows(report):
    """Preserve each deadline's actual eligible population, including zero cohorts."""
    output = []
    for row in report["rows"]:
        thresholds = set()
        for point in row["threshold_coverage"]:
            threshold = _number(point["threshold_s"], "threshold_s")
            if threshold in thresholds:
                raise ValueError("Duplicate authentication deadline.")
            thresholds.add(threshold)
            for anchor in ("source", "receipt"):
                eligible = _number(point[f"{anchor}_eligible_messages"], "eligible messages")
                authenticated = _number(point[f"{anchor}_authenticated_within_threshold_messages"], "authenticated messages")
                if authenticated > eligible:
                    raise ValueError("Deadline authentication count exceeds its eligible cohort.")
                expected = None if eligible == 0 else authenticated / eligible
                actual = point[f"{anchor}_authentication_fraction"]
                if (actual is None) != (expected is None) or (actual is not None and not math.isclose(actual, expected)):
                    raise ValueError("Deadline authentication fraction disagrees with its denominator.")
                output.append({"algorithm": row["algorithm"], "interval_k": row["interval_k"],
                               "scenario": row["scenario"], "anchor": anchor, "deadline_s": threshold,
                               "eligible_messages": eligible, "authenticated_messages": authenticated,
                               "excluded_due_to_followup_messages": point[f"{anchor}_ineligible_due_to_followup_messages"],
                               "authenticated_pct_eligible": _percent(authenticated, eligible)})
    return output


def _traffic(path):
    traffic = json.loads(path.read_text(encoding="utf-8"))
    if traffic.get("kind") != "recorded_traffic" or traffic.get("schema_version") != 1:
        raise ValueError("Expected prepared recorded_traffic schema 1.")
    times = traffic["time_s"]
    for time in times:
        _number(time, "traffic time")
    if not times or times[0] != 0 or any(a >= b for a, b in zip(times, times[1:])):
        raise ValueError("Traffic times must be strictly increasing.")
    duration = _number(traffic["coverage_duration_s"], "recording coverage")
    target = _number(traffic["target_duration_s"], "target duration")
    if target <= 0 or target > duration or times[-1] != duration:
        raise ValueError("Cumulative traffic must cover the declared target and follow-up intervals.")
    if not traffic["cumulative_by_df"]:
        raise ValueError("No recorded DF traffic is available.")
    for df, counts in traffic["cumulative_by_df"].items():
        for metric in ("messages", "payload_bytes"):
            values = counts[metric]
            if len(values) != len(times) or any(type(v) is not int or v < 0 for v in values) or any(a > b for a, b in zip(values, values[1:])):
                raise ValueError(f"Invalid cumulative {metric} for DF {df}.")
            if values[-1] != traffic["totals_by_df"][df][metric]:
                raise ValueError("Cumulative traffic does not match recorded totals.")
    return traffic


def _write_csv(path, rows):
    if not rows:
        raise ValueError(f"Cannot export an empty table: {path.name}")
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


@contextmanager
def _plotting():
    previous = {key: os.environ.get(key) for key in ("MPLCONFIGDIR", "XDG_CACHE_HOME")}
    try:
        with tempfile.TemporaryDirectory(prefix="opensky-main-figures-") as cache:
            for key, value in previous.items():
                if value is None:
                    os.environ[key] = cache
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            matplotlib.rcParams.update({"font.size": 9, "svg.fonttype": "none", "pdf.fonttype": 42,
                                        "svg.hashsalt": "opensky-main-experiment-v1"})
            yield plt
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)


def _save(plt, fig, directory, stem, title, note):
    import textwrap
    fig.suptitle(title, fontsize=13)
    fig.text(.02, .015, textwrap.fill(note, max(70, int(fig.get_figwidth() * 15))), va="bottom", fontsize=8)
    fig.tight_layout(rect=(0, .10, 1, .95))
    paths = []
    for extension in ("png", "pdf", "svg"):
        path = directory / f"{stem}.{extension}"
        metadata = {"Date": None} if extension == "svg" else ({"CreationDate": None, "ModDate": None} if extension == "pdf" else None)
        fig.savefig(path, dpi=160, facecolor="white", metadata=metadata)
        paths.append(path)
    plt.close(fig)
    return paths


def _heatmap(plt, axis, values, rows, columns, title, maximum=None, signed=False):
    import numpy as np
    array = np.array([[np.nan if value is None else value for value in row] for row in values], dtype=float)
    finite = array[np.isfinite(array)]
    vmax = maximum or (max(abs(finite)) if finite.size and max(abs(finite)) > 0 else 1)
    cmap = plt.get_cmap("RdBu_r" if signed else "viridis").with_extremes(bad="#dddddd")
    plot = axis.imshow(np.ma.masked_invalid(array), aspect="auto", cmap=cmap, vmin=-vmax if signed else 0, vmax=vmax)
    axis.set_yticks(range(len(rows)), rows, fontsize=8)
    axis.set_xticks(range(len(columns)), columns, rotation=35, ha="right", fontsize=8)
    axis.set_title(title, fontsize=10)
    for y, row in enumerate(values):
        for x, value in enumerate(row):
            ink = "#222222" if value is None or (abs(value) < .5 * vmax if signed else value > .55 * vmax) else "white"
            axis.text(x, y, "—" if value is None else f"{value:.3g}", ha="center", va="center", fontsize=7, color=ink)
    plt.colorbar(plot, ax=axis, fraction=.04, pad=.03)


def _case_figure(plt, report, output, stem, title, specs, note, label):
    fig, axes = plt.subplots(1, len(specs), figsize=(6.5 * len(specs), max(6, len(report["parameters"]["algorithms"]) * len(report["parameters"]["intervals"]) * .39 + 3)), squeeze=False)
    names = {s["name"]: _scenario_label(s) for s in report["parameters"]["scenarios"]}
    for axis, (caption, getter, maximum) in zip(axes.flat, specs):
        cases, scenarios, values = metric_matrix(report, getter)
        _heatmap(plt, axis, values, [f"{LABELS.get(a, a)} / k={k}" for a, k in cases],
                 [names[s] for s in scenarios], caption, maximum)
    return _save(plt, fig, output, stem, f"{label}: {title}", note)


def _source_files(directory, report):
    """Bind the traffic figure and replay to the same prepared recording."""
    prepared = directory / "01_prepared"
    manifest = json.loads((prepared / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1 or manifest.get("kind") != "prepared_recording":
        raise ValueError("A main-experiment preparation manifest is required for reporting.")
    traffic = _traffic(prepared / "traffic.json")
    hashes = {}
    for key, filename in (("trace", "trace.jsonl"), ("channel", "channel.jsonl"), ("traffic", "traffic.json")):
        evidence = manifest["files"][key]
        hashes[filename] = _hash(prepared / filename)
        if evidence.get("path") != filename or evidence.get("sha256") != hashes[filename]:
            raise ValueError(f"Prepared {key} does not match its manifest; rerun preparation validation.")
    for field, filename in (("trace", "trace.jsonl"), ("channel_trace", "channel.jsonl")):
        if report["provenance"][field]["sha256"] != hashes[filename]:
            raise ValueError(f"Replay {field} belongs to different prepared inputs.")
    parameters = manifest["parameters"]
    if (traffic.get("input_sha256") != manifest.get("input_sha256")
            or traffic["target_duration_s"] != parameters["target_duration_s"]
            or traffic["coverage_duration_s"] != parameters["coverage_duration_s"]
            or traffic["totals_by_df"] != manifest["source_capture"]["totals_by_df"]):
        raise ValueError("Traffic graph and preparation manifest describe different recordings.")
    for row in report["rows"]:
        if (row["source_messages"] != manifest["experimental_trace"]["records"]
                or row["capture_start_s"] != 0
                or row["capture_end_s"] != traffic["target_duration_s"]
                or row["trace_duration_s"] != traffic["target_duration_s"]
                or row["followup_s"] != parameters["followup_s"]):
            raise ValueError("Replay population or window differs from preparation metadata.")
    return {"replay_summary.json": _hash(directory / "03_replay/replay_summary.json"),
            "replay_overview.csv": _hash(directory / "03_replay/replay_overview.csv"),
            "manifest.json": _hash(prepared / "manifest.json"), **hashes}


def _draw_traffic(plt, traffic, figures, label):
    fig, axes = plt.subplots(2, 1, figsize=(11, 8), sharex=True)
    dfs = sorted(traffic["cumulative_by_df"], key=int)
    times = [time / 60 for time in traffic["time_s"]]
    for axis, metric, divisor, caption in zip(axes, ("messages", "payload_bytes"), (1, 1e6), ("Cumulative recorded frames", "Cumulative encoded bytes (MB)")):
        for index, df in enumerate(dfs):
            axis.step(times, [v / divisor for v in traffic["cumulative_by_df"][df][metric]],
                      where="post", label=f"DF {df}", color=plt.get_cmap("tab20")(index % 20), linewidth=1.6)
        axis.axvspan(traffic["target_duration_s"] / 60, traffic["coverage_duration_s"] / 60, color="black", alpha=.08)
        axis.axvline(traffic["target_duration_s"] / 60, color="black", linestyle="--", linewidth=.8)
        axis.set_ylabel(caption)
        axis.grid(alpha=.2)
    axes[0].legend(loc="upper left", ncol=min(6, len(dfs)))
    axes[1].set_xlabel("Minutes since recording start (shaded region: authentication follow-up)")
    return _save(plt, fig, figures, "01_traffic_by_df", f"{label}: cumulative recorded traffic by DF",
                 "Each curve is that DF's cumulative count, measured at bin ends. Encoded bytes include parity, exclude RF preambles, and are neither JSON file size nor radio airtime. This recording cannot represent transmissions the receiver did not observe.")


def plot_traffic(prepared_dir: Path, output_dir: Path, label: str):
    """Expose the first figure immediately after preparation, before signing."""
    traffic = _traffic(Path(prepared_dir) / "traffic.json")
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    with _plotting() as plt:
        return _draw_traffic(plt, traffic, output, label)


def _manifest(directory, sources, label, paths, validate_only):
    path = directory / "figures/figure_manifest.json"
    identity = {"schema_version": 1, "label": label, "source_files": sources, "reporter_sha256": _hash(__file__)}
    if validate_only:
        saved = json.loads(path.read_text(encoding="utf-8"))
        if any(saved.get(key) != value for key, value in identity.items()):
            raise ValueError("Report is stale: source files, label or reporting code changed.")
        if not saved.get("artifacts"):
            raise ValueError("Report manifest has no artifacts.")
        for name, digest in saved["artifacts"].items():
            candidate = (directory / name).resolve()
            if not candidate.is_relative_to(directory.resolve()) or _hash(candidate) != digest:
                raise ValueError(f"Report artifact integrity check failed: {name}")
    else:
        identity["artifacts"] = {str(p.relative_to(directory)): _hash(p) for p in paths}
        path.write_text(json.dumps(identity, indent=2) + "\n", encoding="utf-8")
    return {"report_path": str(directory / "report.md"), "figure_manifest": str(path)}


def generate_report(results_dir: Path, label: str, *, validate_only=False):
    """Write six figure families, all-case tables and a factual Markdown gallery."""
    directory = Path(results_dir)
    report = load_report(directory / "03_replay")
    traffic = _traffic(directory / "01_prepared/traffic.json")
    sources = _source_files(directory, report)
    metrics = [case_metrics(row) for row in report["rows"]]
    coverage = coverage_rows(report)
    if validate_only:
        return _manifest(directory, sources, label, [], True)
    figures = directory / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    paths, gallery = [], []
    cases = [(a, k) for a in report["parameters"]["algorithms"] for k in report["parameters"]["intervals"]]
    case_labels = [f"{LABELS.get(a, a)} / k={k}" for a, k in cases]
    indexed = {(row["algorithm"], row["interval_k"], row["scenario"]): row for row in metrics}
    def value(key):
        return lambda row: indexed[row["algorithm"], row["interval_k"], row["scenario"]][key]
    with _plotting() as plt:
        paths += _draw_traffic(plt, traffic, figures, label)
        gallery.append(("01_traffic_by_df", "Recorded traffic by DF", "Every retained DF contributes to channel traffic. The dashed line separates target selection from follow-up."))

        costs = []
        for algorithm, k in cases:
            matching = [r for r in report["rows"] if (r["algorithm"], r["interval_k"]) == (algorithm, k)]
            names = ("source_groups", "actual_signature_bytes_total", "prototype_required_authentication_frames")
            if any(any(r[name] != matching[0][name] for name in names) for r in matching):
                raise ValueError("A signed workload's size differs across replay scenarios.")
            first = matching[0]
            groups = first["source_groups"]
            costs.append({"algorithm": algorithm, "interval_k": k, "signed_groups": groups,
                          "mean_signature_bytes_per_group": None if not groups else first["actual_signature_bytes_total"] / groups,
                          "mean_required_frames_per_group": None if not groups else first["prototype_required_authentication_frames"] / groups,
                          "total_required_authentication_frames": first["prototype_required_authentication_frames"]})
        fig, axes = plt.subplots(1, 3, figsize=(15, max(6, len(cases) * .39 + 2)), squeeze=False)
        for axis, key, caption in zip(axes.flat, ("mean_signature_bytes_per_group", "mean_required_frames_per_group", "total_required_authentication_frames"),
                                     ("Mean signature bytes/group", "Mean protocol fragments/group", "Total required fragments")):
            _heatmap(plt, axis, [[r[key]] for r in costs], case_labels, ["All formed groups"], caption)
        paths += _save(plt, fig, figures, "02_signature_cost", f"{label}: actual signature and fragmentation cost",
                       "Real cached signature lengths. Fragment counts include association information and fragment headers. Required fragments cover every formed group, including work unfinished at the cutoff. Incomplete final groups are unsigned.")
        gallery.append(("02_signature_cost", "Signature transmission cost", "These sizes describe the actual signed workloads; the same signatures are reused across replay scenarios."))

        paths += _case_figure(plt, report, figures, "03_channel_load", "channel demand for every case", [
            ("Baseline offered airtime (%)", value("baseline_offered_airtime_pct"), None),
            ("Added authentication actually sent (%)", value("actual_added_airtime_pct"), None),
            ("Total augmented offered airtime (%)", value("augmented_offered_airtime_pct"), None),
            ("Required authentication airtime / window (%)", value("required_authentication_airtime_pct"), None)],
            "First three panels count frames starting in the target interval. Required demand includes all formed groups even if not transmitted. Offered airtime sums frame durations; overlaps can make it exceed 100%, and it is not physical RF occupancy. Follow-up traffic is tabulated separately.", label)
        gallery.append(("03_channel_load", "Channel load and unmet demand", "All algorithms, group sizes, pacing rates and channel models are shown. Low transmitted load can result from a signer that cannot keep up."))

        paths += _case_figure(plt, report, figures, "04_ordinary_delivery", "ordinary-message transmission failures and delay", [
            ("Baseline non-reception (% source)", value("baseline_nonreception_pct_source"), 100),
            ("Augmented RF failure (% transmitted)", value("augmented_rf_failure_pct_transmitted"), 100),
            ("Added RF loss from auth (% source)", value("authentication_added_rf_loss_pct_source"), 100),
            ("Ordinary transmission delay p95 (ms)", value("ordinary_transmission_delay_ms_p95"), None)],
            "These are modeled failures, not measured operational failure probabilities. Destructive-overlap scenarios lose overlapping frames; collision-free scenarios do not. Added RF loss uses a timing-matched control. RF-failure percentages divide by all transmitted ordinary frames; other percentages divide by all targets. Unsent and in-flight messages remain unresolved, not RF losses; their counts are tabulated. Delay conditions on transmitted frames.", label)
        gallery.append(("04_ordinary_delivery", "Ordinary-message delivery", "The model estimates the percentage of transmission failures under its overlap assumptions. It does not establish a real-world receiver failure rate."))

        scenarios = report["parameters"]["scenarios"]
        thresholds = sorted({r["deadline_s"] for r in coverage})
        covered = {(r["algorithm"], r["interval_k"], r["scenario"], r["anchor"], r["deadline_s"]): r["authenticated_pct_eligible"] for r in coverage}
        for anchor in ("source", "receipt"):
            columns = min(3, len(scenarios))
            rows = math.ceil(len(scenarios) / columns)
            fig, axes = plt.subplots(rows, columns, figsize=(7 * columns, max(6, len(cases) * .38 + 3) * rows), squeeze=False)
            for axis, scenario in zip(axes.flat, scenarios):
                values = [[covered[a, k, scenario["name"], anchor, t] for t in thresholds] for a, k in cases]
                _heatmap(plt, axis, values, case_labels, [f"{t:g}s" for t in thresholds], _scenario_label(scenario), 100)
            for axis in list(axes.flat)[len(scenarios):]:
                axis.set_visible(False)
            stem = "05_authentication_deadlines" + ("_from_reception" if anchor == "receipt" else "")
            paths += _save(plt, fig, figures, stem, f"{label}: authenticated within each deadline from {anchor} (%)",
                           "Percent of the eligible population authenticated by each deadline. Source anchor includes received and lost targets; receipt anchor includes received targets only. Each deadline excludes messages lacking its full observation time. Exact eligible/excluded counts are in authentication_deadlines.csv. A dash means zero eligible messages. These are threshold measurements, not an interpolated delay distribution.")
            gallery.append((stem, f"Authentication deadlines from {anchor}", "Use the denominator table when comparing thresholds; incomplete observation can change the eligible cohort."))

        backlog_table = []
        for row in report["rows"]:
            samples = row["backlog_samples"]
            if not samples:
                raise ValueError("Missing saved backlog samples.")
            for sample in samples:
                for key in BACKLOG:
                    _number(sample[key], key)
                backlog_table.append({"algorithm": row["algorithm"], "interval_k": row["interval_k"], "scenario": row["scenario"], **sample})
        paths += _case_figure(plt, report, figures, "06_backlog", "unfinished work at the observation cutoff", [
            (caption, lambda row, key=key: row["backlog_samples"][-1][key], None) for key, caption in BACKLOG.items()],
            "Unfinished counts include queued and in-service groups, not only waiting queues. Cutoff is the end of capture plus follow-up. Detailed sampled timelines appear below; straight segments connect saved samples and do not establish continuous queue evolution.", label)
        gallery.append(("06_backlog", "Unfinished work", "Signing, transmission and verification are separate resources. Counts include work currently in service."))
        for scenario_index, scenario in enumerate(scenarios, 1):
            algorithms = report["parameters"]["algorithms"]
            fig, axes = plt.subplots(len(algorithms), len(BACKLOG), figsize=(15, max(5, len(algorithms) * 2.8)), squeeze=False)
            for ai, algorithm in enumerate(algorithms):
                for axis, (key, caption) in zip(axes[ai], BACKLOG.items()):
                    for k in report["parameters"]["intervals"]:
                        row = next(r for r in report["rows"] if (r["algorithm"], r["interval_k"], r["scenario"]) == (algorithm, k, scenario["name"]))
                        samples = row["backlog_samples"]
                        axis.plot([(s["time_s"] - row["capture_start_s"]) / 60 for s in samples], [s[key] for s in samples], marker=".", label=f"k={k}")
                        axis.axvline((row["capture_end_s"] - row["capture_start_s"]) / 60, color="gray", linestyle=":", linewidth=.7)
                    axis.set_title(f"{LABELS.get(algorithm, algorithm)}: {caption}", fontsize=9)
                    axis.set_xlabel("Minutes since target start")
                    axis.set_ylabel("Unfinished groups")
                    axis.grid(alpha=.2)
                    axis.legend(fontsize=7)
            stem = f"06_backlog_timeline_{scenario_index:02d}"
            paths += _save(plt, fig, figures, stem, f"{label}: backlog — {_scenario_label(scenario).replace(chr(10), ', ')}",
                           "Markers are saved samples; lines only guide the eye. The dotted line ends the target interval. Pending work includes groups in service. Different y-axis scales preserve visibility of each processing stage.")
            gallery.append((stem, f"Backlog timeline: {scenario['name']}", "All group sizes are shown separately for each algorithm."))

    for name, table in (("case_metrics.csv", metrics), ("signature_cost.csv", costs), ("authentication_deadlines.csv", coverage), ("backlog_samples.csv", backlog_table)):
        path = figures / name
        _write_csv(path, table)
        paths.append(path)
    total_frames = sum(r["messages"] for r in traffic["totals_by_df"].values())
    first = report["rows"][0]
    lines = [f"# {label} experiment report", "", "This report is generated from the recorded traffic and integrity-checked replay outputs. It contains measured/model outputs, not an automatic aircraft-feasibility verdict.", "",
             f"- Recorded frames across all DFs: **{total_frames:,}**.", f"- Target messages: **{first['source_messages']:,}**.",
             f"- Replay cases: **{len(report['rows'])}**, with every configured algorithm, grouping size and scenario retained.",
             f"- Recording coverage: **{traffic['coverage_duration_s']:g} seconds**; target-selection interval: **{traffic['target_duration_s']:g} seconds**.", "",
             "Ordinary messages are sent independently of signing and can be read before authentication completes. A fixed follow-up censors unfinished authentication; unsigned tails and pending work remain in the case table. Embedded timing inputs model processing, rather than measuring the host machine's offline runtime.", "",
             "The destructive-overlap model assumes overlapping frames are lost. Collision-free scenarios provide a reference. Neither model establishes an empirical operational failure probability; receiver power capture, geography and reception diversity are not modeled. The input recording omits transmissions its receiver did not observe.", "",
             "## Tables", "", "- [All cases, load, delivery and message accounting](figures/case_metrics.csv)", "- [Signature and fragmentation cost](figures/signature_cost.csv)",
             "- [Authentication deadline numerators and denominators](figures/authentication_deadlines.csv)", "- [Sampled unfinished work](figures/backlog_samples.csv)",
             "- [Complete replay output](03_replay/replay_summary.json)", "- [Artifact hashes](figures/figure_manifest.json)", "", "## Figures", ""]
    for stem, title, note in gallery:
        lines += [f"### {title}", "", note, "", f"![{title}](figures/{stem}.png)", "", f"[PDF](figures/{stem}.pdf) · [SVG](figures/{stem}.svg)", ""]
    lines += ["## Scientific conclusions", "", "Pending review of the real experiment. Interpret processing demand, radio demand, ordinary-message failures and authentication coverage together before drawing a feasibility conclusion.", ""]
    report_path = directory / "report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    paths.append(report_path)
    return _manifest(directory, sources, label, paths, False)


def compare_windows(daytime_dir: Path, nighttime_dir: Path, output_dir: Path, *, validate_only=False):
    """Compare identical configurations; differences are nighttime minus daytime."""
    directories = [Path(daytime_dir), Path(nighttime_dir)]
    reports = [load_report(d / "03_replay") for d in directories]
    if reports[0]["parameters"] != reports[1]["parameters"]:
        raise ValueError("Daytime/nighttime comparison requires identical scenario and algorithm parameters.")
    if reports[0]["rows"][0]["trace_duration_s"] != reports[1]["rows"][0]["trace_duration_s"]:
        raise ValueError("Daytime/nighttime comparison requires equal target-window durations.")
    for key in ("hardware_profiles", "algorithms_config", "source_files_sha256"):
        left, right = [r["provenance"][key] for r in reports]
        if (left.get("sha256") if isinstance(left, dict) and "sha256" in left else left) != (right.get("sha256") if isinstance(right, dict) and "sha256" in right else right):
            raise ValueError(f"Daytime/nighttime {key} differs; use matched model and hardware inputs.")
    directory = Path(output_dir)
    sources = {name: _source_files(d, report) for name, d, report in zip(("daytime", "nighttime"), directories, reports)}
    if validate_only:
        return _manifest(directory, sources, "Daytime/nighttime comparison", [], True)
    indexed = [{(r["algorithm"], r["interval_k"], r["scenario"]): case_metrics(r) for r in report["rows"]} for report in reports]
    keys = ("authenticated_pct_source", "augmented_rf_failure_pct_transmitted", "actual_added_airtime_pct", "ordinary_transmission_delay_ms_p95")
    titles = ("Authenticated at cutoff (percentage points)", "RF failure (percentage points)", "Added airtime (percentage points)", "Ordinary delay p95 (ms)")
    rows = []
    for case in indexed[0]:
        row = {"algorithm": case[0], "interval_k": case[1], "scenario": case[2]}
        for metric in keys:
            day, night = indexed[0][case][metric], indexed[1][case][metric]
            row["daytime_" + metric], row["nighttime_" + metric] = day, night
            row["difference_" + metric] = None if day is None or night is None else night - day
        rows.append(row)
    figures = directory / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    with _plotting() as plt:
        fig, axes = plt.subplots(1, len(keys), figsize=(25, max(6, len(reports[0]["parameters"]["algorithms"]) * len(reports[0]["parameters"]["intervals"]) * .39 + 3)), squeeze=False)
        deltas = {(r["algorithm"], r["interval_k"], r["scenario"]): r for r in rows}
        names = {s["name"]: _scenario_label(s) for s in reports[0]["parameters"]["scenarios"]}
        for axis, key, title in zip(axes.flat, keys, titles):
            cases, scenarios, values = metric_matrix(reports[0], lambda r: deltas[r["algorithm"], r["interval_k"], r["scenario"]]["difference_" + key])
            _heatmap(plt, axis, values, [f"{LABELS.get(a, a)} / k={k}" for a, k in cases], [names[s] for s in scenarios], title, signed=True)
        paths = _save(plt, fig, figures, "07_window_comparison", "Matched window comparison: nighttime minus daytime",
                      "Differences describe these two recordings. They do not establish a causal daytime/nighttime effect or uncertainty across days. Positive values mean a larger nighttime value, not uniformly better performance. All configurations and hardware/source inputs must match.")
    table = figures / "window_comparison.csv"
    _write_csv(table, rows)
    paths.append(table)
    report_path = directory / "report.md"
    report_path.write_text("# Daytime/nighttime comparison\n\nIdentical configurations are matched by algorithm, group size and scenario. Differences are **nighttime minus daytime**. Read absolute values in the table before interpreting differences.\n\n![Matched window comparison](figures/07_window_comparison.png)\n\n[PDF](figures/07_window_comparison.pdf) · [SVG](figures/07_window_comparison.svg) · [All matched values and differences](figures/window_comparison.csv)\n\nThese two observations do not establish a causal day/night effect or uncertainty across days. Scientific conclusions remain pending review alongside the traffic, coverage and backlog figures for each window.\n", encoding="utf-8")
    paths.append(report_path)
    return _manifest(directory, sources, "Daytime/nighttime comparison", paths, False)
