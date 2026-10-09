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

from src.experiment.result_validation import (
    LABELS, grouped_rows, load_report, metric_matrix, metric_statistics, seed_statistics,
)


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
    channel = {"independent": "No-interference control",
               "observed_capture": "Observed baseline + random capture",
               "destructive_overlap": "Destructive overlap (legacy)"}[parameters["channel_mode"]]
    label = f"{channel}\n{parameters['auth_frames_per_second']:g} auth frames/s/aircraft"
    if scenario.get("receiver_profile") == "assumed_receiver_1ms":
        label += "\nAssumed 1 ms verifier"
    elif parameters.get("receiver_workers", 1) != 1:
        label += f"\n{parameters['receiver_workers']} reference workers"
    return label


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
        "seed": row["seed"],
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
        "authentication_added_ordinary_delay_ms_p95": row.get("authentication_added_ordinary_delay_ms_p95"),
        "authentication_added_ordinary_delay_ms_max": row.get("authentication_added_ordinary_delay_ms_max"),
        "baseline_ordinary_radio_queue_ms_p95": row.get("baseline_ordinary_radio_queue_ms_p95"),
        "authentication_delayed_ordinary_pct_source": (
            _percent(row["authentication_added_ordinary_delay_positive_messages"], source)
            if "authentication_added_ordinary_delay_positive_messages" in row else None),
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
    output, case_thresholds = [], {}
    configured = {scenario["name"]: scenario["parameters"].get("coverage_thresholds_s")
                  for scenario in report.get("parameters", {}).get("scenarios", [])}
    for name, parameters in report.get("simulator_parameters", {}).items():
        configured[name] = parameters.get("coverage_thresholds_s", configured.get(name))
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
                               "scenario": row["scenario"], "seed": row["seed"],
                               "anchor": anchor, "deadline_s": threshold,
                               "eligible_messages": eligible, "authenticated_messages": authenticated,
                               "excluded_due_to_followup_messages": point[f"{anchor}_ineligible_due_to_followup_messages"],
                               "authenticated_pct_eligible": _percent(authenticated, eligible)})
        key = row["algorithm"], row["interval_k"], row["scenario"]
        declared = configured.get(row["scenario"])
        if (declared is not None and thresholds != set(declared)) or thresholds != case_thresholds.setdefault(key, thresholds):
            raise ValueError("Authentication deadline sets must match configuration and every declared seed.")
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


def aggregate_rows(rows, keys):
    """Summarize each metric across seeds without pooling or summing counts."""
    groups = {}
    for row in rows:
        groups.setdefault(tuple(row[key] for key in keys), []).append(row)
    output = []
    for key, members in groups.items():
        seeds = [row["seed"] for row in members]
        if len(seeds) != len(set(seeds)):
            raise ValueError("Aggregate rows contain a duplicate seed.")
        result = {**dict(zip(keys, key)), "seed_count": len(seeds),
                  "seeds": ";".join(str(seed) for seed in sorted(seeds))}
        fields = [field for field in members[0] if field not in (*keys, "seed")]
        for field in fields:
            stats = seed_statistics(row[field] for row in members)
            for statistic in ("mean", "min", "max", "defined_seed_count"):
                result[f"{field}_{statistic}"] = stats[statistic]
        output.append(result)
    return output


def _format_stats(stats, digits=2, *, compact=False):
    if not stats or stats["mean"] is None:
        return "—" if compact else "n/a"
    def fmt(value):
        if not compact:
            return f"{value:,.{digits}f}"
        if value and (abs(value) < .01 or abs(value) >= 1000):
            coefficient, exponent = f"{value:.1e}".split("e")
            return f"{coefficient.rstrip('0').rstrip('.')}e{int(exponent)}"
        return f"{value:.3g}"
    result = fmt(stats["mean"])
    if stats["seed_count"] > 1 and (not compact or stats["min"] != stats["max"]):
        separator = "," if compact else ", "
        result += ("\n" if compact else " ") + f"[{fmt(stats['min'])}{separator}{fmt(stats['max'])}]"
    if stats["defined_seed_count"] < stats["seed_count"]:
        result += f" ({stats['defined_seed_count']}/{stats['seed_count']} defined)"
    return result


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
    path = directory / f"{stem}.pdf"
    fig.savefig(path, dpi=160, facecolor="white", metadata={"CreationDate": None, "ModDate": None})
    plt.close(fig)
    return [path]


def _heatmap(plt, axis, values, rows, columns, title, maximum=None, signed=False, annotations=None):
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
            caption = annotations[y][x] if annotations is not None else ("—" if value is None else f"{value:.3g}")
            axis.text(x, y, caption, ha="center", va="center", fontsize=6 if annotations else 7, color=ink)
    plt.colorbar(plot, ax=axis, fraction=.04, pad=.03)


def _case_figure(plt, report, output, stem, title, specs, note, label):
    fig, axes = plt.subplots(1, len(specs), figsize=(6.5 * len(specs), max(6, len(report["parameters"]["algorithms"]) * len(report["parameters"]["intervals"]) * .39 + 3)), squeeze=False)
    names = {s["name"]: _scenario_label(s) for s in report["parameters"]["scenarios"]}
    for axis, (caption, getter, maximum) in zip(axes.flat, specs):
        cases, scenarios, values = metric_matrix(report, getter)
        stats = metric_statistics(report, getter)
        annotations = [[_format_stats(stats[a, k, s], compact=True) for s in scenarios] for a, k in cases]
        _heatmap(plt, axis, values, [f"{LABELS.get(a, a)} / k={k}" for a, k in cases],
                 [names[s] for s in scenarios], caption, maximum, annotations=annotations)
    return _save(plt, fig, output, stem, f"{label}: {title}",
                 "Cells show replicate mean [observed minimum, maximum] when repeated; exactly zero-width ranges are omitted. Ranges are not confidence intervals. " + note)


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
    axes[1].set_xlabel("Minutes since recording start (shaded region: recording after target selection)")
    note = "Each curve is that DF's cumulative count, measured at bin ends. Encoded bytes include parity, exclude RF preambles, and are neither JSON file size nor radio airtime. This recording cannot represent transmissions the receiver did not observe."
    if traffic.get("timing_warning"):
        note = traffic["timing_warning"] + " " + note
    return _save(plt, fig, figures, "01_traffic_by_df", f"{label}: cumulative recorded traffic by DF", note)


def plot_traffic(prepared_dir: Path, output_dir: Path, label: str):
    """Expose the first figure immediately after preparation, before signing."""
    traffic = _traffic(Path(prepared_dir) / "traffic.json")
    manifest_path = Path(prepared_dir) / "manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        metadata = manifest.get("parameters", {}).get("metadata", {})
        if metadata.get("experiment_blockers"):
            label += " — traffic inspection only"
            traffic["timing_warning"] = (
                "RF timing is unverified: the horizontal axis uses recorded decoder timestamps. "
                "The marked target/follow-up division is provisional; this figure establishes counts, not radio collisions."
            )
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    with _plotting() as plt:
        return _draw_traffic(plt, traffic, output, label)


def _manifest(directory, sources, label, paths, validate_only):
    path = directory / "figures/figure_manifest.json"
    identity = {"schema_version": 1, "label": label, "source_files": sources, "reporter_sha256": _hash(__file__),
                "validation_sha256": _hash(Path(__file__).with_name("result_validation.py"))}
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
    return {"figures_dir": str(directory / "figures"), "figure_manifest": str(path)}


def signature_airtime_bounds(report):
    """Optimistic seven-byte signature-only demand; no simulated SLH outcomes."""
    result, seen, groups_by_k = [], set(), {}
    for row in report["rows"]:
        key = row["algorithm"], row["interval_k"]
        if key in seen:
            continue
        seen.add(key)
        k, groups = row["interval_k"], row["source_groups"]
        if k in groups_by_k and groups_by_k[k] != groups:
            raise ValueError("Algorithms must use identical group counts for the size comparison.")
        groups_by_k[k] = groups
        frames = row["signature_only_7byte_lower_bound_frames"]
        result.append({"algorithm": row["algorithm"], "interval_k": k, "groups": groups,
                       "basis": "actual_signed_bytes", "signature_only_frames": frames})
    if "SLH-DSA-SHA2-128s" not in report["parameters"]["algorithms"]:
        # FIPS 205 Table 2: SLH-DSA-SHA2-128s signatures are exactly 7,856 bytes.
        # This is a size-only analytical bound, never a fake signed workload.
        for k, groups in groups_by_k.items():
            result.append({"algorithm": "SLH-DSA-SHA2-128s", "interval_k": k, "groups": groups,
                           "basis": "analytical_only_FIPS205_7856_bytes_no_workload",
                           "signature_only_frames": groups * math.ceil(7856 / 7)})
    first = report["rows"][0]
    for row in result:
        seconds = row["signature_only_frames"] * 120e-6
        row.update(payload_bytes_per_frame=7, frame_duration_s=120e-6,
                   required_airtime_s=seconds,
                   target_window_airtime_pct=100 * seconds / first["trace_duration_s"],
                   target_plus_followup_airtime_pct=100 * seconds / (first["trace_duration_s"] + first["followup_s"]))
    return result


def generate_report(results_dir: Path, label: str, *, validate_only=False):
    """Write PDF figures, all-case CSV tables and their integrity manifest."""
    directory = Path(results_dir)
    report = load_report(directory / "03_replay")
    traffic = _traffic(directory / "01_prepared/traffic.json")
    sources = _source_files(directory, report)
    analysis = (report["provenance"].get("analysis_context")
                or report["parameters"].get("analysis_context") or {})
    conditional = analysis.get("mode") == "conditional_recorded_timing"
    if conditional:
        label += " (conditional timing)"
    metrics = [case_metrics(row) for row in report["rows"]]
    coverage = coverage_rows(report)
    lower_bounds = signature_airtime_bounds(report)
    if validate_only:
        return _manifest(directory, sources, label, [], True)
    figures = directory / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    paths = []
    cases = [(a, k) for a in report["parameters"]["algorithms"] for k in report["parameters"]["intervals"]]
    case_labels = [f"{LABELS.get(a, a)} / k={k}" for a, k in cases]
    indexed = {(row["algorithm"], row["interval_k"], row["scenario"], row["seed"]): row for row in metrics}
    def value(key):
        return lambda row: indexed[row["algorithm"], row["interval_k"], row["scenario"], row["seed"]][key]
    with _plotting() as plt:
        paths += _draw_traffic(plt, traffic, figures, label)

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

        bound_algorithms = list(dict.fromkeys(r["algorithm"] for r in lower_bounds))
        bound_cases = report["parameters"]["intervals"]
        bound_index = {(r["algorithm"], r["interval_k"]): r for r in lower_bounds}
        fig, axis = plt.subplots(figsize=(11, 6))
        width = .8 / len(bound_algorithms)
        for ai, algorithm in enumerate(bound_algorithms):
            analytical = algorithm not in report["parameters"]["algorithms"]
            bars = [bound_index[algorithm, k]["target_window_airtime_pct"] for k in bound_cases]
            axis.bar([i - .4 + width * (ai + .5) for i in range(len(bound_cases))], bars, width,
                     label=LABELS.get(algorithm, algorithm) + (" (analytical only)" if analytical else ""),
                     hatch="///" if analytical else None)
        axis.axhline(100, color="black", linestyle="--", linewidth=1, label="100% of target-window airtime")
        axis.set_xticks(range(len(bound_cases)), [f"k = {k}" for k in bound_cases])
        axis.set_ylabel("Signature-only required airtime / target window (%)")
        axis.set_yscale("log")
        axis.grid(axis="y", alpha=.2)
        axis.legend(fontsize=8)
        paths += _save(plt, fig, figures, "02_signature_airtime_lower_bound", f"{label}: optimistic signature-only demand",
                       "Assumes all seven payload bytes carry signature data, without association or fragment headers. Active algorithms use actual signature lengths. Hatched SLH bars use its fixed 7,856-byte size only; no SLH signing or replay is claimed. These are required-airtime bounds, not measured occupancy or loss probabilities.")

        paths += _case_figure(plt, report, figures, "03_channel_load", "channel demand for every case", [
            ("Baseline offered airtime (%)", value("baseline_offered_airtime_pct"), None),
            ("Added authentication actually sent (%)", value("actual_added_airtime_pct"), None),
            ("Total augmented offered airtime (%)", value("augmented_offered_airtime_pct"), None),
            ("Required authentication airtime / window (%)", value("required_authentication_airtime_pct"), None)],
            "First three panels count frames starting in the target interval. Required demand includes all formed groups even if not transmitted. Offered airtime sums frame durations; overlaps can make it exceed 100%, and it is not physical RF occupancy. Follow-up traffic is tabulated separately.", label)

        paths += _case_figure(plt, report, figures, "04_ordinary_delivery", "ordinary-message reception failures and transmission delay", [
            ("Baseline non-reception (% source)", value("baseline_nonreception_pct_source"), 100),
            ("Augmented RF failure (% transmitted)", value("augmented_rf_failure_pct_transmitted"), 100),
            ("Added RF loss from auth (% source)", value("authentication_added_rf_loss_pct_source"), 100),
            ("Auth-added transmission delay maximum (ms)", value("authentication_added_ordinary_delay_ms_max"), None)],
            "Observed-capture starts from the successfully recorded baseline and adds only losses involving authentication frames under seeded random priorities. Added loss uses the same shifted ordinary schedule without authentication as its control. RF-failure percentages divide by transmitted ordinary frames; added loss divides by all targets. Unsent/in-flight messages remain separate. Added TX delay compares the same messages with a FIFO ordinary-only radio. These are assumed capture outcomes, not measured failure probabilities.", label)

        scenarios = report["parameters"]["scenarios"]
        thresholds = sorted({r["deadline_s"] for r in coverage})
        covered = {}
        for point in coverage:
            key = point["algorithm"], point["interval_k"], point["scenario"], point["anchor"], point["deadline_s"]
            covered.setdefault(key, []).append(point["authenticated_pct_eligible"])
        covered = {key: seed_statistics(values) for key, values in covered.items()}
        for anchor in ("source", "receipt"):
            columns = min(3, len(scenarios))
            rows = math.ceil(len(scenarios) / columns)
            fig, axes = plt.subplots(rows, columns, figsize=(7 * columns, max(6, len(cases) * .38 + 3) * rows), squeeze=False)
            for axis, scenario in zip(axes.flat, scenarios):
                stats = [[covered[a, k, scenario["name"], anchor, t] for t in thresholds] for a, k in cases]
                values = [[point["mean"] for point in points] for points in stats]
                annotations = [[_format_stats(point, compact=True) for point in points] for points in stats]
                _heatmap(plt, axis, values, case_labels, [f"{t:g}s" for t in thresholds], _scenario_label(scenario), 100,
                         annotations=annotations)
            for axis in list(axes.flat)[len(scenarios):]:
                axis.set_visible(False)
            stem = "05_authentication_deadlines" + ("_from_reception" if anchor == "receipt" else "")
            paths += _save(plt, fig, figures, stem, f"{label}: authenticated within each deadline from {anchor} (%)",
                           "Mean percentage [observed seed minimum, maximum]; exactly zero-width ranges are omitted. Ranges are not confidence intervals. Source anchor includes received and lost targets; receipt anchor includes received targets only. Each seed/deadline excludes messages without its full follow-up. Exact per-seed numerators and denominators remain in authentication_deadlines.csv. Missing values remain undefined, not zero. These are discrete deadline measurements.")

        backlog_table = []
        interval_backlog = all("backlog_interval_summaries" in row for row in report["rows"])
        if any("backlog_interval_summaries" in row for row in report["rows"]) and not interval_backlog:
            raise ValueError("Cannot mix interval-based and legacy snapshot backlog data.")
        for row in report["rows"]:
            samples = row["backlog_interval_summaries" if interval_backlog else "backlog_samples"]
            if not samples:
                raise ValueError("Missing saved backlog summaries.")
            previous_end = row["capture_start_s"]
            for sample in samples:
                if interval_backlog:
                    start, end = sample["start_s"], sample["end_s"]
                    if not math.isclose(start, previous_end, abs_tol=1e-8) or end <= start:
                        raise ValueError("Backlog intervals must be consecutive and positive.")
                    previous_end = end
                    for stage in BACKLOG:
                        mean = _number(sample[stage + "_mean"], stage + "_mean")
                        maximum = _number(sample[stage + "_max"], stage + "_max")
                        if mean > maximum and not math.isclose(mean, maximum, rel_tol=1e-10, abs_tol=1e-8):
                            raise ValueError("Mean unfinished work cannot exceed its interval maximum.")
                    for stage in ("signing", "transmission", "verification"):
                        count = _number(sample[stage + "_completed_groups"], "completed groups")
                        if type(count) is not int:
                            raise ValueError("Completion counts must be integers.")
                else:
                    for stage in BACKLOG:
                        _number(sample[stage], stage)
                backlog_table.append({"algorithm": row["algorithm"], "interval_k": row["interval_k"],
                                      "scenario": row["scenario"], "seed": row["seed"], **sample})
            if interval_backlog and not math.isclose(previous_end, row["observation_horizon_s"], abs_tol=1e-8):
                raise ValueError("Backlog intervals must cover the full observation horizon.")
        groups = grouped_rows(report)
        # The user-requested timeline replaces the redundant cutoff overview.
        # Legacy snapshots are dots only, never interpolated into a time series.
        for scenario_index, scenario in enumerate(scenarios, 1):
            algorithms = report["parameters"]["algorithms"]
            fig, axes = plt.subplots(len(algorithms), len(BACKLOG), figsize=(15, max(5, len(algorithms) * 2.8)), squeeze=False)
            for ai, algorithm in enumerate(algorithms):
                for axis, (stage, caption) in zip(axes[ai], BACKLOG.items()):
                    for ki, k in enumerate(report["parameters"]["intervals"]):
                        members = groups[algorithm, k, scenario["name"]]
                        color = plt.get_cmap("tab10")(ki % 10)
                        source_start = members[0]["capture_start_s"]
                        if interval_backlog:
                            bins = [row["backlog_interval_summaries"] for row in members]
                            boundaries = [(point["start_s"], point["end_s"]) for point in bins[0]]
                            if any([(point["start_s"], point["end_s"]) for point in points] != boundaries for points in bins):
                                raise ValueError("Replicate backlog bins must have matching boundaries.")
                            means = [seed_statistics(points[index][stage + "_mean"] for points in bins)
                                     for index in range(len(boundaries))]
                            maxima = [max(points[index][stage + "_max"] for points in bins)
                                      for index in range(len(boundaries))]
                            x = [(left - source_start) / 60 for left, _ in boundaries] + [(boundaries[-1][1] - source_start) / 60]
                            extend = lambda values: [*values, values[-1]]
                            axis.step(x, extend([point["mean"] for point in means]), where="post", color=color, label=f"k={k}")
                            axis.step(x, extend(maxima), where="post", color=color, linestyle=":", linewidth=.7, alpha=.6)
                            if len(members) > 1:
                                axis.fill_between(x, extend([point["min"] for point in means]),
                                                  extend([point["max"] for point in means]), step="post", color=color, alpha=.15)
                        else:
                            times = [point["time_s"] for point in members[0]["backlog_samples"]]
                            means = [seed_statistics(row["backlog_samples"][index][stage] for row in members)["mean"]
                                     for index in range(len(times))]
                            axis.scatter([(time - source_start) / 60 for time in times], means, s=10, color=color, label=f"k={k}")
                        axis.axvline((members[0]["capture_end_s"] - source_start) / 60, color="gray", linestyle="--", linewidth=.6)
                    axis.set_title(f"{LABELS.get(algorithm, algorithm)}: {caption}", fontsize=9)
                    axis.set_xlabel("Minutes since target start")
                    axis.set_ylabel("Unfinished groups")
                    axis.grid(alpha=.2)
                    axis.legend(fontsize=7)
            stem = f"06_backlog_timeline_{scenario_index:02d}"
            note = ("Solid steps: mean across seeds of exact time-weighted unfinished work within each saved interval. Shading: observed seed range, not a confidence interval. Dotted steps: largest event-derived interval maximum across seeds. These interval summaries include every modeled admission/completion and include queued plus in-service work; they are not instantaneous queue samples. Dashed vertical line ends target selection."
                    if interval_backlog else "Legacy instantaneous snapshots are displayed as unconnected points. They do not establish queue behavior between observations; no interpolation is used.")
            paths += _save(plt, fig, figures, stem, f"{label}: unfinished work — {_scenario_label(scenario).replace(chr(10), ', ')}", note)

    outcome_reasons = {}
    for row in report["rows"]:
        key = row["algorithm"], row["interval_k"], row["scenario"]
        outcome_reasons.setdefault(key, set()).update(row["message_outcomes"])
    outcomes = [{"algorithm": row["algorithm"], "interval_k": row["interval_k"],
                 "scenario": row["scenario"], "seed": row["seed"], "outcome": outcome,
                 "messages": row["message_outcomes"].get(outcome, 0),
                 "source_messages": row["source_messages"],
                 "pct_source": _percent(row["message_outcomes"].get(outcome, 0), row["source_messages"])}
                for row in report["rows"]
                for outcome in sorted(outcome_reasons[row["algorithm"], row["interval_k"], row["scenario"]])]
    common = ("algorithm", "interval_k", "scenario")
    backlog_name = "backlog_intervals" if interval_backlog else "backlog_samples"
    backlog_keys = (*common, "start_s", "end_s") if interval_backlog else (*common, "time_s")
    tables = [("case_metrics.csv", metrics), ("case_summary.csv", aggregate_rows(metrics, common)),
              ("signature_cost.csv", costs), ("signature_airtime_lower_bounds.csv", lower_bounds),
              ("authentication_deadlines.csv", coverage),
              ("authentication_deadline_summary.csv", aggregate_rows(coverage, (*common, "anchor", "deadline_s"))),
              ("authentication_outcomes.csv", outcomes),
              ("authentication_outcome_summary.csv", aggregate_rows(outcomes, (*common, "outcome"))),
              (backlog_name + ".csv", backlog_table),
              (backlog_name + "_summary.csv", aggregate_rows(backlog_table, backlog_keys))]
    for name, table in tables:
        path = figures / name
        _write_csv(path, table)
        paths.append(path)
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
    indexed = [{(row["algorithm"], row["interval_k"], row["scenario"], row["seed"]): case_metrics(row)
                for row in report["rows"]} for report in reports]
    if set(indexed[0]) != set(indexed[1]):
        raise ValueError("Daytime/nighttime comparison requires identical declared case seeds.")
    keys = ("authenticated_pct_source", "authentication_added_rf_loss_pct_source", "actual_added_airtime_pct",
            "authentication_added_ordinary_delay_ms_p95")
    titles = ("Authenticated at cutoff (% of targets; pp)", "Auth-added ordinary loss (% of targets; pp)",
              "Added offered airtime (percentage points)", "Auth-added delay: mean seed p95 (ms)")
    raw_rows = []
    for case in indexed[0]:
        row = {"algorithm": case[0], "interval_k": case[1], "scenario": case[2], "seed": case[3]}
        for metric in keys:
            day, night = indexed[0][case][metric], indexed[1][case][metric]
            row["daytime_" + metric], row["nighttime_" + metric] = day, night
            row["difference_" + metric] = None if day is None or night is None else night - day
        raw_rows.append(row)
    rows = aggregate_rows(raw_rows, ("algorithm", "interval_k", "scenario"))
    figures = directory / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    with _plotting() as plt:
        params = reports[0]["parameters"]
        fig, axes = plt.subplots(1, len(keys), figsize=(25, max(6, len(params["algorithms"]) * len(params["intervals"]) * .48 + 3)), squeeze=False)
        deltas = {(row["algorithm"], row["interval_k"], row["scenario"]): row for row in rows}
        names = {scenario["name"]: _scenario_label(scenario) for scenario in params["scenarios"]}
        cases = [(algorithm, k) for algorithm in params["algorithms"] for k in params["intervals"]]
        scenarios = [scenario["name"] for scenario in params["scenarios"]]
        for axis, key, title in zip(axes.flat, keys, titles):
            def stats(case):
                item = deltas[case]
                return {"seed_count": item["seed_count"], **{statistic: item["difference_" + key + "_" + statistic]
                    for statistic in ("mean", "min", "max", "defined_seed_count")}}
            values = [[stats((a, k, scenario))["mean"] for scenario in scenarios] for a, k in cases]
            annotations = [[_format_stats(stats((a, k, scenario)), compact=True) for scenario in scenarios] for a, k in cases]
            _heatmap(plt, axis, values, [f"{LABELS.get(a, a)} / k={k}" for a, k in cases],
                     [names[scenario] for scenario in scenarios], title, signed=True, annotations=annotations)
        paths = _save(plt, fig, figures, "07_window_comparison", "Matched window comparison: nighttime minus daytime",
                      "Mean difference [observed seed minimum, maximum]; exactly zero-width ranges are omitted. Ranges are not confidence intervals. Authentication and added ordinary-loss percentages divide by all target messages. Added loss is measured against the timing-matched no-authentication control. Each difference matches seed labels across different recordings. Positive means larger nighttime values, not uniformly better performance. These windows do not establish a causal day/night effect or variation across days. Counts are not summed across repetitions.")
    for filename, values in (("window_comparison.csv", rows), ("window_comparison_by_seed.csv", raw_rows)):
        table = figures / filename
        _write_csv(table, values)
        paths.append(table)
    return _manifest(directory, sources, "Daytime/nighttime comparison", paths, False)
