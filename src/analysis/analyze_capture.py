#!/usr/bin/env python3

import argparse
import json
from collections import Counter
from pathlib import Path


def analyze_capture(input_path: Path) -> dict:
    df_counts = Counter()
    df17_icao = set()
    df17_raw = Counter()
    df17_per_second = Counter()

    total_records = 0
    malformed_records = 0
    timestamps = []

    with input_path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                malformed_records += 1
                continue

            total_records += 1

            df = record.get("df")
            timestamp = record.get("timestamp")
            raw_msg = record.get("raw_msg")
            icao = record.get("icao")

            if df is not None:
                df_counts[df] += 1

            if timestamp is not None:
                timestamps.append(float(timestamp))

            if df == 17:
                if icao:
                    df17_icao.add(icao)

                if raw_msg:
                    df17_raw[raw_msg] += 1

                if timestamp is not None:
                    df17_per_second[int(float(timestamp))] += 1

    df17_count = df_counts[17]
    df18_count = df_counts[18]

    if timestamps:
        start_time = min(timestamps)
        end_time = max(timestamps)
        duration = end_time - start_time
    else:
        start_time = None
        end_time = None
        duration = 0.0

    mean_df17_rate = df17_count / duration if duration > 0 else 0.0
    peak_df17_rate = max(df17_per_second.values(), default=0)

    repeated_df17_observations = sum(
        count - 1 for count in df17_raw.values() if count > 1
    )

    summary = {
        "input_file": str(input_path),
        "total_records": total_records,
        "malformed_records": malformed_records,
        "capture": {
            "start_timestamp": start_time,
            "end_timestamp": end_time,
            "duration_seconds": duration,
        },
        "downlink_formats": {
            str(df): count for df, count in sorted(df_counts.items())
        },
        "df17_extended_squitter": {
            "records": df17_count,
            "percentage_of_total": (
                100.0 * df17_count / total_records if total_records else 0.0
            ),
            "unique_icao_addresses": len(df17_icao),
            "unique_raw_messages": len(df17_raw),
            "repeated_raw_message_observations": repeated_df17_observations,
            "mean_messages_per_second": mean_df17_rate,
            "peak_messages_per_second_1s_bin": peak_df17_rate,
        },
        "df18_extended_squitter": {
            "records": df18_count,
            "percentage_of_total": (
                100.0 * df18_count / total_records if total_records else 0.0
            ),
        },
    }

    return summary


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a raw pyModeS/OpenSky Mode S capture."
    )
    parser.add_argument(
        "input",
        type=Path,
        help="Path to the input JSONL capture.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path for the JSON summary.",
    )
    args = parser.parse_args()

    summary = analyze_capture(args.input)

    print("\n=== Capture Summary ===")
    print(f"Total records:          {summary['total_records']:,}")
    print(f"Malformed records:      {summary['malformed_records']:,}")
    print(
        f"Capture duration:       "
        f"{summary['capture']['duration_seconds']:.2f} s"
    )

    print("\n=== Downlink Formats ===")
    for df, count in summary["downlink_formats"].items():
        percentage = 100.0 * count / summary["total_records"]
        print(f"DF{df:>2}: {count:>10,}  ({percentage:6.2f}%)")

    df17 = summary["df17_extended_squitter"]

    print("\n=== DF17 ADS-B Extended Squitter ===")
    print(f"Records:                {df17['records']:,}")
    print(f"Percentage of capture:  {df17['percentage_of_total']:.2f}%")
    print(f"Unique ICAO addresses:  {df17['unique_icao_addresses']:,}")
    print(f"Unique raw messages:    {df17['unique_raw_messages']:,}")
    print(
        f"Repeated observations:  "
        f"{df17['repeated_raw_message_observations']:,}"
    )
    print(
        f"Mean DF17 rate:         "
        f"{df17['mean_messages_per_second']:.2f} msg/s"
    )
    print(
        f"Peak DF17 rate (1 s):   "
        f"{df17['peak_messages_per_second_1s_bin']:,} msg/s"
    )

    df18 = summary["df18_extended_squitter"]

    print("\n=== DF18 Extended Squitter ===")
    print(f"Records:                {df18['records']:,}")
    print(f"Percentage of capture:  {df18['percentage_of_total']:.2f}%")

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        print(f"\nSummary written to: {args.output}")


if __name__ == "__main__":
    main()