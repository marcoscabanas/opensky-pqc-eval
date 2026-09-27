#!/usr/bin/env python3

import argparse
import csv
import json
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path


def percentile(values, p):
    """Return percentile p using linear interpolation."""
    if not values:
        return None

    values = sorted(values)

    if len(values) == 1:
        return values[0]

    index = (len(values) - 1) * p
    lower = math.floor(index)
    upper = math.ceil(index)

    if lower == upper:
        return values[lower]

    fraction = index - lower

    return (
        values[lower] * (1.0 - fraction)
        + values[upper] * fraction
    )


def safe_stats(values):
    """Return descriptive statistics for a numeric sequence."""
    if not values:
        return {
            "count": 0,
            "mean": None,
            "median": None,
            "p90": None,
            "p95": None,
            "p99": None,
            "min": None,
            "max": None,
        }

    return {
        "count": len(values),
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "p90": percentile(values, 0.90),
        "p95": percentile(values, 0.95),
        "p99": percentile(values, 0.99),
        "min": min(values),
        "max": max(values),
    }


def classify_gap(gap):
    """
    Classify the time separation between consecutive observations
    of the same (ICAO, raw_msg) pair.

    No category is interpreted as a duplicate-reception threshold.
    The bins are descriptive only.
    """
    if gap == 0:
        return "exactly_0"

    if gap <= 0.001:
        return "0_to_1_ms"

    if gap <= 0.010:
        return "1_to_10_ms"

    if gap <= 0.100:
        return "10_to_100_ms"

    if gap <= 1.0:
        return "100_ms_to_1_s"

    if gap <= 10.0:
        return "1_to_10_s"

    return "over_10_s"


def analyze_duplicates(input_path):
    observations = defaultdict(list)

    total_records = 0
    malformed_records = 0
    df17_records = 0
    usable_df17_records = 0
    missing_icao = 0
    missing_raw_msg = 0
    missing_timestamp = 0

    with input_path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                malformed_records += 1
                continue

            total_records += 1

            if record.get("df") != 17:
                continue

            df17_records += 1

            icao = record.get("icao")
            raw_msg = record.get("raw_msg")
            timestamp = record.get("timestamp")

            if not icao:
                missing_icao += 1
                continue

            if not raw_msg:
                missing_raw_msg += 1
                continue

            if timestamp is None:
                missing_timestamp += 1
                continue

            icao = icao.upper()
            raw_msg = raw_msg.upper()
            timestamp = float(timestamp)

            observations[(icao, raw_msg)].append(timestamp)
            usable_df17_records += 1

    repeated_rows = []
    all_repeat_gaps = []
    gap_bins = Counter()
    multiplicity_counts = Counter()

    unique_message_pairs = len(observations)
    repeated_message_pairs = 0
    repeated_observations = 0

    for (icao, raw_msg), timestamps in observations.items():
        timestamps.sort()

        occurrences = len(timestamps)
        multiplicity_counts[occurrences] += 1

        if occurrences < 2:
            continue

        repeated_message_pairs += 1
        repeated_observations += occurrences - 1

        gaps = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, occurrences)
        ]

        for gap in gaps:
            all_repeat_gaps.append(gap)
            gap_bins[classify_gap(gap)] += 1

        repeated_rows.append({
            "icao": icao,
            "raw_msg": raw_msg,
            "occurrences": occurrences,
            "first_timestamp": timestamps[0],
            "last_timestamp": timestamps[-1],
            "span_s": timestamps[-1] - timestamps[0],
            "min_gap_s": min(gaps),
            "mean_gap_s": statistics.mean(gaps),
            "median_gap_s": statistics.median(gaps),
            "max_gap_s": max(gaps),
        })

    repeated_rows.sort(
        key=lambda row: (
            -row["occurrences"],
            row["icao"],
            row["raw_msg"],
        )
    )

    gap_order = [
        "exactly_0",
        "0_to_1_ms",
        "1_to_10_ms",
        "10_to_100_ms",
        "100_ms_to_1_s",
        "1_to_10_s",
        "over_10_s",
    ]

    gap_distribution = {
        category: gap_bins.get(category, 0)
        for category in gap_order
    }

    multiplicity_distribution = {
        str(multiplicity): count
        for multiplicity, count in sorted(
            multiplicity_counts.items()
        )
    }

    summary = {
        "input_file": str(input_path),
        "total_records": total_records,
        "malformed_records": malformed_records,
        "df17_records": df17_records,
        "usable_df17_records": usable_df17_records,
        "df17_records_missing_icao": missing_icao,
        "df17_records_missing_raw_msg": missing_raw_msg,
        "df17_records_missing_timestamp": missing_timestamp,
        "unique_icao_raw_message_pairs": unique_message_pairs,
        "repeated_icao_raw_message_pairs": repeated_message_pairs,
        "repeated_observations": repeated_observations,
        "repeat_gap_statistics_s": safe_stats(
            all_repeat_gaps
        ),
        "repeat_gap_distribution": gap_distribution,
        "multiplicity_distribution": multiplicity_distribution,
    }

    return summary, repeated_rows


def write_csv(output_path, rows):
    """Write repeated-message groups to CSV."""
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    fieldnames = [
        "icao",
        "raw_msg",
        "occurrences",
        "first_timestamp",
        "last_timestamp",
        "span_s",
        "min_gap_s",
        "mean_gap_s",
        "median_gap_s",
        "max_gap_s",
    ]

    with output_path.open(
        "w",
        encoding="utf-8",
        newline=""
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(rows)


def print_optional_stat(label, value, unit="s"):
    """Print a statistic that may be None."""
    if value is None:
        print(f"{label:<30} N/A")
    else:
        print(f"{label:<30} {value:.9f} {unit}")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Characterize repeated DF17 raw-message observations "
            "in a raw pyModeS/OpenSky capture."
        )
    )

    parser.add_argument(
        "input",
        type=Path,
        help="Path to the raw JSONL capture.",
    )

    parser.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="Optional JSON summary output path.",
    )

    parser.add_argument(
        "--repeated",
        type=Path,
        default=None,
        help="Optional repeated-message CSV output path.",
    )

    args = parser.parse_args()

    summary, repeated_rows = analyze_duplicates(
        args.input
    )

    print("\n=== DF17 Repeated-Message Analysis ===")

    print(
        f"DF17 records:                  "
        f"{summary['df17_records']:,}"
    )
    print(
        f"Usable DF17 records:           "
        f"{summary['usable_df17_records']:,}"
    )
    print(
        f"Unique (ICAO, raw_msg) pairs:  "
        f"{summary['unique_icao_raw_message_pairs']:,}"
    )
    print(
        f"Repeated message pairs:        "
        f"{summary['repeated_icao_raw_message_pairs']:,}"
    )
    print(
        f"Repeated observations:         "
        f"{summary['repeated_observations']:,}"
    )

    print("\n=== Repeat Gap Distribution ===")

    gap_labels = {
        "exactly_0": "Exactly 0",
        "0_to_1_ms": "0 < dt <= 1 ms",
        "1_to_10_ms": "1 ms < dt <= 10 ms",
        "10_to_100_ms": "10 ms < dt <= 100 ms",
        "100_ms_to_1_s": "100 ms < dt <= 1 s",
        "1_to_10_s": "1 s < dt <= 10 s",
        "over_10_s": "dt > 10 s",
    }

    total_gaps = sum(
        summary["repeat_gap_distribution"].values()
    )

    for category, count in summary[
        "repeat_gap_distribution"
    ].items():
        percentage = (
            100.0 * count / total_gaps
            if total_gaps
            else 0.0
        )

        print(
            f"{gap_labels[category]:<30} "
            f"{count:>8,} "
            f"({percentage:6.2f}%)"
        )

    stats = summary["repeat_gap_statistics_s"]

    print("\n=== Repeat Gap Statistics ===")

    print_optional_stat("Mean:", stats["mean"])
    print_optional_stat("Median:", stats["median"])
    print_optional_stat("P90:", stats["p90"])
    print_optional_stat("P95:", stats["p95"])
    print_optional_stat("P99:", stats["p99"])
    print_optional_stat("Minimum:", stats["min"])
    print_optional_stat("Maximum:", stats["max"])

    print("\n=== Multiplicity Distribution ===")

    for multiplicity, count in summary[
        "multiplicity_distribution"
    ].items():
        print(
            f"{multiplicity:>4} occurrence(s): "
            f"{count:>8,} unique message pairs"
        )

    print("\n=== Top 10 Most Repeated Messages ===")

    for row in repeated_rows[:10]:
        print(
            f"{row['icao']}  "
            f"{row['occurrences']:>5,} occurrences  "
            f"span={row['span_s']:.6f} s  "
            f"median_gap={row['median_gap_s']:.6f} s  "
            f"{row['raw_msg']}"
        )

    if args.summary:
        args.summary.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with args.summary.open(
            "w",
            encoding="utf-8"
        ) as f:
            json.dump(
                summary,
                f,
                indent=2
            )

        print(
            f"\nJSON summary written to: "
            f"{args.summary}"
        )

    if args.repeated:
        write_csv(
            args.repeated,
            repeated_rows
        )

        print(
            f"Repeated-message CSV written to: "
            f"{args.repeated}"
        )


if __name__ == "__main__":
    main()