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


def classify_typecode(tc):
    """
    Group ADS-B type codes into broad message categories.

    Categories are intentionally descriptive and retain the original
    type code separately in the output.
    """
    if tc is None:
        return "unknown"

    if 1 <= tc <= 4:
        return "aircraft_identification"
    if 5 <= tc <= 8:
        return "surface_position"
    if 9 <= tc <= 18:
        return "airborne_position_baro"
    if tc == 19:
        return "airborne_velocity"
    if 20 <= tc <= 22:
        return "airborne_position_gnss"
    if tc == 28:
        return "aircraft_status"
    if tc == 29:
        return "target_state_status"
    if tc == 31:
        return "aircraft_operational_status"

    return "other"


def analyze_aircraft(input_path):
    aircraft = defaultdict(list)

    total_records = 0
    malformed_records = 0
    df17_records = 0
    missing_icao = 0
    missing_timestamp = 0

    typecode_counts = Counter()
    category_counts = Counter()

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
            timestamp = record.get("timestamp")
            raw_msg = record.get("raw_msg")
            typecode = record.get("typecode")

            if not icao:
                missing_icao += 1
                continue

            if timestamp is None:
                missing_timestamp += 1
                continue

            timestamp = float(timestamp)
            icao = icao.upper()

            typecode_counts[typecode] += 1
            category_counts[classify_typecode(typecode)] += 1

            aircraft[icao].append({
                "timestamp": timestamp,
                "raw_msg": raw_msg,
                "typecode": typecode,
            })

    aircraft_rows = []
    all_interarrivals = []
    all_message_rates = []
    all_message_counts = []
    all_durations = []

    for icao, messages in aircraft.items():
        messages.sort(key=lambda x: x["timestamp"])

        timestamps = [m["timestamp"] for m in messages]

        interarrivals = [
            timestamps[i] - timestamps[i - 1]
            for i in range(1, len(timestamps))
        ]

        first_timestamp = timestamps[0]
        last_timestamp = timestamps[-1]
        duration = last_timestamp - first_timestamp

        message_count = len(messages)

        # Mean observed message rate is only meaningful when the
        # aircraft has more than one observation over a non-zero period.
        mean_rate = (
            (message_count - 1) / duration
            if message_count > 1 and duration > 0
            else None
        )

        raw_counter = Counter(
            m["raw_msg"]
            for m in messages
            if m["raw_msg"] is not None
        )

        unique_raw_messages = len(raw_counter)

        repeated_raw_observations = sum(
            count - 1
            for count in raw_counter.values()
            if count > 1
        )

        aircraft_typecodes = Counter(
            m["typecode"] for m in messages
        )

        ia_stats = safe_stats(interarrivals)

        row = {
            "icao": icao,
            "message_count": message_count,
            "first_timestamp": first_timestamp,
            "last_timestamp": last_timestamp,
            "observation_duration_s": duration,
            "mean_message_rate_hz": mean_rate,
            "mean_interarrival_s": ia_stats["mean"],
            "median_interarrival_s": ia_stats["median"],
            "p90_interarrival_s": ia_stats["p90"],
            "p95_interarrival_s": ia_stats["p95"],
            "p99_interarrival_s": ia_stats["p99"],
            "max_interarrival_s": ia_stats["max"],
            "unique_raw_messages": unique_raw_messages,
            "repeated_raw_observations": repeated_raw_observations,
            "typecodes": dict(sorted(
                aircraft_typecodes.items(),
                key=lambda x: (
                    x[0] is None,
                    x[0] if x[0] is not None else 999
                )
            )),
        }

        aircraft_rows.append(row)

        all_message_counts.append(message_count)
        all_durations.append(duration)

        if mean_rate is not None:
            all_message_rates.append(mean_rate)

        all_interarrivals.extend(interarrivals)

    # Sort aircraft by descending number of observed DF17 messages.
    aircraft_rows.sort(
        key=lambda x: x["message_count"],
        reverse=True
    )

    summary = {
        "input_file": str(input_path),
        "total_records": total_records,
        "malformed_records": malformed_records,
        "df17_records": df17_records,
        "df17_records_missing_icao": missing_icao,
        "df17_records_missing_timestamp": missing_timestamp,
        "unique_aircraft": len(aircraft),
        "typecode_distribution": {
            str(tc): count
            for tc, count in sorted(
                typecode_counts.items(),
                key=lambda x: (
                    x[0] is None,
                    x[0] if x[0] is not None else 999
                )
            )
        },
        "message_category_distribution": dict(
            sorted(category_counts.items())
        ),
        "aircraft_message_count": safe_stats(
            all_message_counts
        ),
        "aircraft_observation_duration_s": safe_stats(
            all_durations
        ),
        "aircraft_mean_message_rate_hz": safe_stats(
            all_message_rates
        ),
        "all_df17_interarrival_s": safe_stats(
            all_interarrivals
        ),
    }

    return summary, aircraft_rows


def write_csv(output_path, rows):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "icao",
        "message_count",
        "first_timestamp",
        "last_timestamp",
        "observation_duration_s",
        "mean_message_rate_hz",
        "mean_interarrival_s",
        "median_interarrival_s",
        "p90_interarrival_s",
        "p95_interarrival_s",
        "p99_interarrival_s",
        "max_interarrival_s",
        "unique_raw_messages",
        "repeated_raw_observations",
        "typecodes",
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

        for row in rows:
            csv_row = dict(row)
            csv_row["typecodes"] = json.dumps(
                row["typecodes"],
                separators=(",", ":")
            )
            writer.writerow(csv_row)


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Characterize per-aircraft DF17 ADS-B "
            "traffic in a raw pyModeS/OpenSky capture."
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
        "--aircraft",
        type=Path,
        default=None,
        help="Optional per-aircraft CSV output path.",
    )

    args = parser.parse_args()

    summary, aircraft_rows = analyze_aircraft(
        args.input
    )

    print("\n=== DF17 Aircraft Analysis ===")
    print(
        f"DF17 records:                 "
        f"{summary['df17_records']:,}"
    )
    print(
        f"Unique aircraft:              "
        f"{summary['unique_aircraft']:,}"
    )
    print(
        f"Missing ICAO:                 "
        f"{summary['df17_records_missing_icao']:,}"
    )
    print(
        f"Missing timestamp:            "
        f"{summary['df17_records_missing_timestamp']:,}"
    )

    print("\n=== ADS-B Type Codes ===")

    for tc, count in summary[
        "typecode_distribution"
    ].items():
        percentage = (
            100.0 * count / summary["df17_records"]
            if summary["df17_records"]
            else 0.0
        )

        print(
            f"TC {tc:>2}: "
            f"{count:>8,} "
            f"({percentage:6.2f}%)"
        )

    print("\n=== Message Categories ===")

    for category, count in summary[
        "message_category_distribution"
    ].items():
        percentage = (
            100.0 * count / summary["df17_records"]
            if summary["df17_records"]
            else 0.0
        )

        print(
            f"{category:<30} "
            f"{count:>8,} "
            f"({percentage:6.2f}%)"
        )

    msg_stats = summary["aircraft_message_count"]

    print("\n=== Messages per Aircraft ===")
    print(f"Mean:                         {msg_stats['mean']:.2f}")
    print(f"Median:                       {msg_stats['median']:.2f}")
    print(f"P90:                          {msg_stats['p90']:.2f}")
    print(f"P95:                          {msg_stats['p95']:.2f}")
    print(f"Maximum:                      {msg_stats['max']:,}")

    rate_stats = summary[
        "aircraft_mean_message_rate_hz"
    ]

    print("\n=== Per-Aircraft Observed DF17 Rate ===")
    print(f"Mean:                         {rate_stats['mean']:.3f} msg/s")
    print(f"Median:                       {rate_stats['median']:.3f} msg/s")
    print(f"P90:                          {rate_stats['p90']:.3f} msg/s")
    print(f"P95:                          {rate_stats['p95']:.3f} msg/s")
    print(f"Maximum:                      {rate_stats['max']:.3f} msg/s")

    ia_stats = summary["all_df17_interarrival_s"]

    print("\n=== DF17 Per-Aircraft Inter-Arrival Times ===")
    print(f"Mean:                         {ia_stats['mean']:.6f} s")
    print(f"Median:                       {ia_stats['median']:.6f} s")
    print(f"P90:                          {ia_stats['p90']:.6f} s")
    print(f"P95:                          {ia_stats['p95']:.6f} s")
    print(f"P99:                          {ia_stats['p99']:.6f} s")
    print(f"Maximum:                      {ia_stats['max']:.6f} s")

    print("\n=== Top 10 Aircraft by DF17 Messages ===")

    for row in aircraft_rows[:10]:
        rate = row["mean_message_rate_hz"]

        rate_text = (
            f"{rate:.3f}"
            if rate is not None
            else "N/A"
        )

        print(
            f"{row['icao']}  "
            f"{row['message_count']:>6,} messages  "
            f"{row['observation_duration_s']:>8.2f} s  "
            f"{rate_text:>7} msg/s"
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

    if args.aircraft:
        write_csv(
            args.aircraft,
            aircraft_rows
        )

        print(
            f"Aircraft CSV written to: "
            f"{args.aircraft}"
        )


if __name__ == "__main__":
    main()