#!/usr/bin/env python3
"""Render methodology diagrams and a dataset table from prepared recordings.

Run from the repository root: .venv/bin/python scripts/07_methodology_figures.py
This script does not generate signatures or run the replay simulator. Diagrams
are seven inches wide, exported as vector PDFs.
"""

from __future__ import annotations

import argparse
import csv
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import tempfile
from zoneinfo import ZoneInfo


ROOT = Path(__file__).resolve().parents[2]
WINDOWS = ("daytime", "nighttime")


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def dataset_characteristics(results, output, manifest):
    rows = []
    for window in WINDOWS:
        base = results / window / "01_prepared"
        paths = {kind: base / name for kind, name in (
            ("manifest", "manifest.json"), ("traffic", "traffic.json"),
            ("trace", "trace.jsonl"))}
        hashes = {kind: sha256(path) for kind, path in paths.items()}
        manifest["source_sha256"].update({
            str(paths[kind].relative_to(results)): value
            for kind, value in hashes.items()
        })
        prepared = json.loads(paths["manifest"].read_text(encoding="utf-8"))
        traffic = json.loads(paths["traffic"].read_text(encoding="utf-8"))
        for kind in ("traffic", "trace"):
            if hashes[kind] != prepared["files"][kind]["sha256"]:
                raise ValueError(f"{window}: prepared {kind} hash mismatch")
        target = float(prepared["parameters"]["target_duration_s"])
        followup = float(prepared["parameters"]["followup_s"])
        if target != 3600 or followup != 600:
            raise ValueError("These diagrams describe a 3600 s target and 600 s follow-up")
        times = traffic["time_s"]
        target_i = times.index(target)
        first_hour_all = sum(int(series["messages"][target_i])
                             for series in traffic["cumulative_by_df"].values())
        first_hour_df17 = int(traffic["cumulative_by_df"]["17"]["messages"][target_i])
        icaos, bins, count = set(), [set() for _ in range(60)], 0
        with paths["trace"].open(encoding="utf-8") as stream:
            for line in stream:
                item = json.loads(line)
                when = float(item["relative_time_s"])
                if not math.isfinite(when) or not 0 <= when < target:
                    raise ValueError(f"{window}: target outside first-hour interval")
                icao = item["icao"]
                icaos.add(icao)
                bins[int(when // 60)].add(icao)
                count += 1
        expected = prepared["experimental_trace"]
        if count != first_hour_df17 or count != expected["records"] or len(icaos) != expected["unique_aircraft"]:
            raise ValueError(f"{window}: target counts disagree with saved metadata")
        channel = prepared["channel"]
        start = float(channel["time_origin_timestamp"])
        coverage = float(channel["coverage_duration_s"])
        if coverage < target + followup:
            raise ValueError(f"{window}: recording does not cover the observation horizon")
        tz = ZoneInfo("Europe/Amsterdam")
        local = lambda timestamp: datetime.fromtimestamp(timestamp, tz).isoformat(timespec="seconds")
        rows.append({
            "window": window,
            "timezone": "Europe/Amsterdam",
            "first_exported_timestamp_local": local(start),
            "target_window_end_local": local(start + target),
            "replay_cutoff_local": local(start + target + followup),
            "recording_exclusive_end_local": local(start + coverage),
            "recorded_span_s": coverage,
            "target_duration_s": target,
            "followup_s": followup,
            "recorded_mode_s_frames_full_file": prepared["source_capture"]["total_records"],
            "recorded_mode_s_frames_first_hour": first_hour_all,
            "df17_target_messages": count,
            "distinct_target_icao_addresses": len(icaos),
            "mean_recorded_mode_s_rate_first_hour_per_s": first_hour_all / target,
            "mean_target_df17_rate_first_hour_per_s": count / target,
            "peak_distinct_target_icao_addresses_per_nonoverlapping_60s_bin": max(map(len, bins)),
        })
    path = output / "dataset_characteristics.csv"
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    manifest["dataset_characteristics"] = {
        "file": path.name,
        "rows": rows,
        "interpretation": "Counts and rates use exported decoded Mode S frames. Target statistics use only first-hour DF17 frames. Peak activity is distinct target ICAO addresses in fixed non-overlapping 60 s bins anchored at the earliest supplied timestamp, not instantaneous airborne aircraft. Dates derive from supplied timestamps, not unverified user recollection. Coverage end is the declared exclusive bound, not a verified RF recording stop time.",
    }


def save_figure(fig, name, output, manifest, details, plt):
    path = output / f"{name}.pdf"
    fig.savefig(path, dpi=220, metadata={"CreationDate": None, "ModDate": None})
    manifest["figures"][name] = {"files": [path.name], "size_inches": list(fig.get_size_inches()), **details}
    plt.close(fig)


def workflow_figure(output, manifest, plt):
    from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
    from matplotlib.path import Path as MplPath

    fig = plt.figure(figsize=(7, 7.5))
    ax = fig.add_axes([0, 0, 1, 1], xlim=(0, 7), ylim=(0, 7.5))
    ax.axis("off")
    boxes = []

    def node(x, y, w, h, title, body, fill, *, body_y=.25, fontsize=8):
        patch = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.015,rounding_size=0.05",
                               linewidth=0.8, edgecolor="#53616a", facecolor=fill, zorder=3)
        ax.add_patch(patch)
        title_text = ax.text(x + w / 2, y + h - 0.16, title, ha="center", va="center",
                             fontsize=fontsize, fontweight="bold", zorder=4)
        body_text = ax.text(x + w / 2, y + body_y, body, ha="center", va="center",
                            fontsize=fontsize, linespacing=1.2, zorder=4)
        boxes.append((patch, title_text, body_text))

    def arrow(points, color="#495761", width=0.95):
        codes = [MplPath.MOVETO] + [MplPath.LINETO] * (len(points) - 1)
        ax.add_patch(FancyArrowPatch(path=MplPath(points, codes), arrowstyle="-|>",
                                    mutation_scale=9, linewidth=width, color=color,
                                    zorder=2))

    blue, yellow, green = "#e9f3f9", "#fff3d7", "#e7f3ed"
    rose, grey = "#fae9e7", "#f1f2f3"
    ax.text(.15, 7.29, "A  Sender and alternative channel assumptions",
            fontsize=9, fontweight="bold", va="center")

    node(.15, 6.30, 1.60, .70, "Recorded input", "daytime.jsonl or\nnighttime.jsonl", blue)
    node(2.10, 6.30, 2.70, .70, "First-hour DF17 targets",
         "Eligible for ordinary transmission\nwithout waiting for a signature", blue)
    node(5.15, 6.30, 1.70, .70, "Aircraft radio",
         "Ordinary priority\nPace auth. fragments", blue)
    arrow([(1.765, 6.65), (2.085, 6.65)])
    arrow([(4.815, 6.65), (5.135, 6.65)])

    node(2.10, 5.25, 2.70, .78, "Authentication generation",
         "Collect $k$ messages; sign $C$ + original bytes\n"
         "using the aircraft private key\n"
         "Fragment context $C$ + signature $\\sigma$", yellow, body_y=.29)
    arrow([(3.45, 6.285), (3.45, 6.045)])
    ax.text(3.60, 6.15, "Retained copies", fontsize=8, va="center", color="#71591a")
    arrow([(4.815, 5.64), (5.60, 5.64), (5.60, 6.285)])
    ax.text(5.74, 5.91, "Extra\nframes", fontsize=8, va="center")

    # Both radio traffic and recorded non-target traffic enter the selected
    # channel assumption. These are separate runs, not a two-channel receiver.
    ax.plot([.95, .95, 6.50, 6.50], [6.285, 5.02, 5.02, 6.285],
            color="#495761", linewidth=.95, zorder=2)
    ax.text(1.09, 5.60, "Other recorded\nframes", fontsize=8, va="center")
    ax.text(3.5, 4.88, "Select one channel assumption per run", ha="center",
            va="center", fontsize=8, fontweight="bold", color="#495761")
    node(.15, 3.94, 3.15, .78, "No-interference control",
         "Receive every completed transmitted frame,\n"
         "including overlapping ordinary and auth. frames.", blue, body_y=.28)
    node(3.65, 3.94, 3.20, .78, "Capture model: seeds 1–5",
         "Direct overlaps involving auth. use priorities.\n"
         "Recorded–recorded overlaps remain accepted.", yellow, body_y=.28)
    arrow([(1.725, 5.02), (1.725, 4.735)])
    arrow([(5.25, 5.02), (5.25, 4.735)])

    # Reception and authentication below are the same procedure in each run.
    ax.plot([1.725, 1.725, 5.25, 5.25], [3.925, 3.75, 3.75, 3.925],
            color="#495761", linewidth=.95, zorder=2)
    ax.plot([3.50, 3.50], [3.75, 3.30], color="#495761", linewidth=.95, zorder=2)
    ax.text(.15, 3.57, "B  Receiver and authentication", fontsize=9,
            fontweight="bold", va="center")
    ax.text(3.75, 3.57, "Same receiver steps in each run", fontsize=8,
            va="center", color="#495761")
    node(.15, 2.45, 2.20, .70, "Ordinary frames received",
         "Read immediately; cache originals\nRecord ordinary-reception coverage", green)
    node(2.70, 2.45, 2.45, .70, "Authentication fragments received",
         "Reassemble all fragments\nRecover context $C$ and signature $\\sigma$", green)
    node(5.50, 2.45, 1.35, .70, "Provisioned",
         "Public key $pk$\nand session", grey)
    arrow([(3.50, 3.30), (1.25, 3.30), (1.25, 3.165)])
    arrow([(3.50, 3.30), (3.925, 3.30), (3.925, 3.165)])

    node(.15, 1.45, 3.20, .73, "Associate group and rebuild signed input",
         "Match all $k$ original messages using context/tags\n"
         "$M = C \\parallel m_1 \\parallel \\cdots \\parallel m_k$", green, body_y=.26)
    node(3.70, 1.45, 3.15, .73, "Verification queue → worker → library",
         "Check $\\mathrm{Verify}(pk, M, \\sigma)$ after modeled service\n"
         "Use cryptography (ECDSA) or liboqs (PQ)", green, body_y=.26)
    arrow([(1.25, 2.435), (1.25, 2.195)])
    arrow([(3.925, 2.435), (3.925, 2.31), (2.75, 2.31), (2.75, 2.195)])
    arrow([(6.175, 2.435), (6.175, 2.195)])
    arrow([(3.365, 1.815), (3.685, 1.815)])
    ax.text(3.525, 1.98, "$M,\\sigma$", ha="center", fontsize=8)

    node(.15, .30, 3.20, .72, "Incomplete reconstruction / cutoff",
         "Lost inputs: group cannot be reconstructed.\n"
         "Unfinished work at 4,200 s: pending.", grey, body_y=.25)
    node(3.70, .30, 1.95, .72, "Valid + unambiguous",
         "Authenticate all $k$ messages\nRecord completion time", "#d2e9dc", body_y=.25)
    node(5.95, .30, .90, .72, "Rejected",
         "Invalid or\nambiguous", rose, body_y=.25)
    arrow([(1.25, 1.435), (1.25, 1.035)])
    ax.text(1.39, 1.22, "Cannot complete", fontsize=8, va="center", color="#495761")
    ax.plot([5.275, 5.275], [1.435, 1.21], color="#495761", linewidth=.95, zorder=2)
    arrow([(5.275, 1.21), (4.675, 1.21), (4.675, 1.035)])
    arrow([(5.275, 1.21), (6.40, 1.21), (6.40, 1.035)])
    ax.text(.15, .08, "Receptions and verification must finish by 4,200 s; no retransmission or erasure coding.",
            fontsize=8, va="center", color="#495761")

    # Check labels against their own rectangles at the exported physical size.
    fig.canvas.draw()
    renderer = fig.canvas.get_renderer()
    for patch, *texts in boxes:
        bounds = patch.get_window_extent(renderer)
        for text in texts:
            bb = text.get_window_extent(renderer)
            if not (bounds.x0 <= bb.x0 <= bb.x1 <= bounds.x1 and bounds.y0 <= bb.y0 <= bb.y1 <= bounds.y1):
                raise ValueError(f"Diagram label does not fit its node: {text.get_text()!r}")
    save_figure(fig, "00_methodology_workflow", output, manifest, {
        "interpretation": "Two-panel event-replay pipeline. Panel A splits first-hour DF17 ordinary transmission from signing retained copies, combines target/authentication transmissions with recorded background, and shows no-interference and seeded capture as alternative runs. Panel B applies the same receiver procedure under either assumption: cache ordinary inputs, reassemble context/signature, associate and reconstruct exact signed bytes, queue modeled verification service, and execute real public-key verification. Only valid, unambiguously associated groups receive authentication credit. Missing material is not automatically a cryptographic rejection; known lost inputs prevent reconstruction and work unfinished at the common cutoff remains pending. No retransmission or erasure coding.",
    }, plt)


def timeline_figure(output, manifest, plt):
    from matplotlib.patches import Rectangle

    fig = plt.figure(figsize=(7, 2.65))
    ax = fig.add_axes([0, 0, 1, 1], xlim=(0, 7), ylim=(0, 2.65))
    ax.axis("off")
    start, end = .2, 6.8
    target = start + (end - start) * 60 / 70
    ax.add_patch(Rectangle((target, .53), end - target, 1.79, color="#f0f0f0", zorder=0))
    ax.text((start + target) / 2, 2.43, "First-hour target window", ha="center", va="center",
            fontsize=8.5, fontweight="bold")
    ax.text((target + end) / 2, 2.43, "Follow-up\n600 s", ha="center", va="center", fontsize=8)
    lanes = (
        (1.80, end, "Recorded background traffic continues throughout replay", "#e9f3f9"),
        (1.27, target, "First-hour DF17 targets create signing groups", "#fff3d7"),
        (.74, end, "Signing, fragment transmission and verification may continue", "#e7f3ed"),
    )
    for y, right, label, color in lanes:
        ax.add_patch(Rectangle((start, y), right - start, .35, facecolor=color,
                               edgecolor="#647078", linewidth=.75))
        ax.text((start + right) / 2, y + .175, label, ha="center", va="center", fontsize=8)
    ax.text((target + end) / 2, 1.445, "No new\ngroups", ha="center", va="center", fontsize=7.8)
    ax.plot([target, target], [.56, 2.28], color="#647078", linestyle="--", linewidth=.75)
    ax.plot([end, end], [.56, 2.28], color="#495761", linewidth=1)
    ax.plot([start, end], [.55, .55], color="#647078", linewidth=.8)
    for x, label, ha in ((start, "0", "left"), (target, "60 min\n3,600 s", "center"),
                         (end, "70 min\n4,200 s", "right")):
        ax.plot([x, x], [.50, .59], color="#647078", linewidth=.8)
        ax.text(x, .46, label, ha=ha, va="top", fontsize=7.8, linespacing=1.2)
    ax.text(.2, .055, "Cutoff coverage includes follow-up; unfinished work remains pending at 4,200 s.",
            ha="left", va="bottom", fontsize=8, color="#495761")
    save_figure(fig, "00_observation_window", output, manifest, {
        "target_duration_s": 3600,
        "followup_s": 600,
        "replay_horizon_s": 4200,
        "interpretation": "Follow-up gives every first-hour message a full 600 s source-relative observation interval, while final-cutoff coverage may include authentication later than a message's individual deadline. No new target groups form during follow-up; incomplete tails are not flushed. Recorded background traffic remains present. Horizontal scale is proportional to elapsed time.",
    }, plt)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=ROOT / "results")
    parser.add_argument("--output-dir", type=Path, default=None,
                        help="Default: <results-dir>/paper/figures")
    args = parser.parse_args(argv)
    results = args.results_dir.resolve()
    output = args.output_dir.resolve() if args.output_dir else results / "paper/figures"
    output.mkdir(parents=True, exist_ok=True)
    manifest = {"schema_version": 1, "generator": "scripts/07_methodology_figures.py",
                "generator_sha256": sha256(ROOT / "scripts" / "07_methodology_figures.py"),
                "implementation": "scripts/_support/methodology_figures.py",
                "implementation_sha256": sha256(Path(__file__)), "source_sha256": {}, "figures": {}}
    dataset_characteristics(results, output, manifest)
    with tempfile.TemporaryDirectory(prefix="adsb-methodology-matplotlib-") as cache:
        os.environ.setdefault("MPLCONFIGDIR", cache)
        os.environ.setdefault("XDG_CACHE_HOME", cache)
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        matplotlib.rcParams.update({"font.size": 8, "font.family": "DejaVu Sans",
                                    "pdf.fonttype": 42, "svg.fonttype": "none",
                                    "svg.hashsalt": "adsb-methodology-figures-v1"})
        workflow_figure(output, manifest, plt)
        timeline_figure(output, manifest, plt)
        manifest["matplotlib_version"] = matplotlib.__version__
    artifacts = [name for detail in manifest["figures"].values() for name in detail["files"]]
    artifacts.append(manifest["dataset_characteristics"]["file"])
    manifest["artifact_sha256"] = {name: sha256(output / name) for name in artifacts}
    (output / "methodology_figure_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Generated two PDF methodology figures, dataset table and manifest in {output}")


if __name__ == "__main__":
    main()
