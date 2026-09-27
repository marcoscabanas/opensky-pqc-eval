#!/usr/bin/env python3

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


REQUIRED_FIELDS = (
    "icao",
    "raw_msg",
    "timestamp",
)


def sha256_file(path, chunk_size=1024 * 1024):
    """Calculate the SHA-256 digest of a file."""
    digest = hashlib.sha256()

    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def load_df17_records(input_path):
    """
    Load valid DF17 observations from the raw JSONL capture.

    No deduplication, aircraft filtering, or ADS-B type-code filtering
    is performed.
    """
    records = []

    total_records = 0
    malformed_records = 0
    non_df17_records = 0

    missing_fields = Counter()

    with input_path.open("r", encoding="utf-8") as f:
        for source_line, line in enumerate(f, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                malformed_records += 1
                continue

            total_records += 1

            if record.get("df") != 17:
                non_df17_records += 1
                continue

            missing = [
                field
                for field in REQUIRED_FIELDS
                if record.get(field) is None
                or record.get(field) == ""
            ]

            if missing:
                for field in missing:
                    missing_fields[field] += 1

                continue

            try:
                timestamp = float(record["timestamp"])
            except (TypeError, ValueError):
                missing_fields["invalid_timestamp"] += 1
                continue

            icao = str(record["icao"]).upper()
            raw_msg = str(record["raw_msg"]).upper()

            records.append({
                "source_line": source_line,
                "timestamp": timestamp,
                "icao": icao,
                "raw_msg": raw_msg,
                "typecode": record.get("typecode"),
            })

    diagnostics = {
        "total_records": total_records,
        "malformed_records": malformed_records,
        "non_df17_records": non_df17_records,
        "excluded_df17_records": sum(
            missing_fields.values()
        ),
        "missing_or_invalid_fields": dict(
            sorted(missing_fields.items())
        ),
    }

    return records, diagnostics


def build_trace(records):
    """
    Sort observations chronologically and assign deterministic IDs.

    source_line is used as the secondary sort key so that observations
    with identical timestamps retain their original capture order.
    """
    records.sort(
        key=lambda record: (
            record["timestamp"],
            record["source_line"],
        )
    )

    if not records:
        return []

    start_timestamp = records[0]["timestamp"]

    trace = []

    for trace_id, record in enumerate(
        records,
        start=1
    ):
        trace.append({
            "trace_id": trace_id,
            "timestamp": record["timestamp"],
            "relative_time_s": (
                record["timestamp"]
                - start_timestamp
            ),
            "icao": record["icao"],
            "raw_msg": record["raw_msg"],
            "typecode": record["typecode"],
            "source_line": record["source_line"],
        })

    return trace


def validate_trace(trace, input_records):
    """
    Validate that preprocessing preserved every accepted DF17
    observation exactly once.
    """
    if len(trace) != len(input_records):
        raise RuntimeError(
            "Trace validation failed: output record count "
            "does not match accepted input record count."
        )

    if not trace:
        return

    expected_ids = list(
        range(1, len(trace) + 1)
    )

    actual_ids = [
        record["trace_id"]
        for record in trace
    ]

    if actual_ids != expected_ids:
        raise RuntimeError(
            "Trace validation failed: trace_id sequence "
            "is not contiguous."
        )

    timestamps = [
        record["timestamp"]
        for record in trace
    ]

    if timestamps != sorted(timestamps):
        raise RuntimeError(
            "Trace validation failed: timestamps are "
            "not monotonically ordered."
        )

    if trace[0]["relative_time_s"] != 0.0:
        raise RuntimeError(
            "Trace validation failed: first relative "
            "timestamp is not zero."
        )


def write_jsonl(output_path, trace):
    """Write the canonical experimental trace."""
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output_path.open(
        "w",
        encoding="utf-8"
    ) as f:
        for record in trace:
            f.write(
                json.dumps(
                    record,
                    separators=(",", ":")
                )
            )
            f.write("\n")


def build_manifest(
    input_path,
    output_path,
    trace,
    diagnostics,
    input_sha256,
    output_sha256,
):
    """Construct a reproducibility manifest."""
    if trace:
        start_timestamp = trace[0]["timestamp"]
        end_timestamp = trace[-1]["timestamp"]
        duration = (
            end_timestamp
            - start_timestamp
        )
    else:
        start_timestamp = None
        end_timestamp = None
        duration = 0.0

    unique_aircraft = len({
        record["icao"]
        for record in trace
    })

    typecode_counts = Counter(
        record["typecode"]
        for record in trace
    )

    repeated_counter = Counter(
        (
            record["icao"],
            record["raw_msg"]
        )
        for record in trace
    )

    unique_message_pairs = len(
        repeated_counter
    )

    repeated_observations = sum(
        count - 1
        for count in repeated_counter.values()
        if count > 1
    )

    return {
        "input_file": str(input_path),
        "output_file": str(output_path),
        "input_sha256": input_sha256,
        "output_sha256": output_sha256,
        "preprocessing_rules": {
            "downlink_format": 17,
            "required_fields": list(
                REQUIRED_FIELDS
            ),
            "deduplication": False,
            "aircraft_filtering": False,
            "typecode_filtering": False,
            "global_timestamp_sorting": True,
            "timestamp_tie_breaker": (
                "original source line"
            ),
            "relative_time_origin": (
                "first retained DF17 observation"
            ),
        },
        "source_capture": diagnostics,
        "experimental_trace": {
            "records": len(trace),
            "unique_aircraft": unique_aircraft,
            "start_timestamp": start_timestamp,
            "end_timestamp": end_timestamp,
            "duration_seconds": duration,
            "unique_icao_raw_message_pairs": (
                unique_message_pairs
            ),
            "repeated_raw_message_observations": (
                repeated_observations
            ),
            "typecode_distribution": {
                str(typecode): count
                for typecode, count in sorted(
                    typecode_counts.items(),
                    key=lambda item: (
                        item[0] is None,
                        (
                            item[0]
                            if item[0] is not None
                            else 999
                        ),
                    ),
                )
            },
        },
        "validation": {
            "record_count_preserved": True,
            "trace_ids_contiguous": True,
            "timestamps_monotonic": True,
            "first_relative_time_zero": True,
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Construct the canonical DF17 experimental "
            "trace from a raw pyModeS/OpenSky capture."
        )
    )

    parser.add_argument(
        "input",
        type=Path,
        help="Path to the raw JSONL capture.",
    )

    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help=(
            "Path for the canonical experimental "
            "trace JSONL."
        ),
    )

    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help=(
            "Path for the preprocessing manifest JSON."
        ),
    )

    args = parser.parse_args()

    print("\n=== Experimental Trace Preprocessing ===")

    print(
        f"Input:                         "
        f"{args.input}"
    )

    input_sha256 = sha256_file(
        args.input
    )

    records, diagnostics = load_df17_records(
        args.input
    )

    trace = build_trace(
        records
    )

    validate_trace(
        trace,
        records
    )

    write_jsonl(
        args.output,
        trace
    )

    output_sha256 = sha256_file(
        args.output
    )

    manifest = build_manifest(
        args.input,
        args.output,
        trace,
        diagnostics,
        input_sha256,
        output_sha256,
    )

    args.manifest.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with args.manifest.open(
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            manifest,
            f,
            indent=2
        )

    trace_summary = manifest[
        "experimental_trace"
    ]

    print(
        f"Raw records:                   "
        f"{diagnostics['total_records']:,}"
    )
    print(
        f"Non-DF17 records excluded:     "
        f"{diagnostics['non_df17_records']:,}"
    )
    print(
        f"Malformed records:             "
        f"{diagnostics['malformed_records']:,}"
    )
    print(
        f"Invalid DF17 records excluded: "
        f"{diagnostics['excluded_df17_records']:,}"
    )

    print("\n=== Canonical DF17 Trace ===")

    print(
        f"Records retained:              "
        f"{trace_summary['records']:,}"
    )
    print(
        f"Unique aircraft:               "
        f"{trace_summary['unique_aircraft']:,}"
    )
    print(
        f"Duration:                      "
        f"{trace_summary['duration_seconds']:.6f} s"
    )
    print(
        f"Unique (ICAO, raw_msg) pairs:  "
        f"{trace_summary['unique_icao_raw_message_pairs']:,}"
    )
    print(
        f"Repeated raw observations:     "
        f"{trace_summary['repeated_raw_message_observations']:,}"
    )

    print("\n=== Reproducibility ===")

    print(
        f"Input SHA-256:                 "
        f"{input_sha256}"
    )
    print(
        f"Output SHA-256:                "
        f"{output_sha256}"
    )

    print("\n=== Validation ===")
    print("Record count preserved:        PASS")
    print("Trace IDs contiguous:          PASS")
    print("Timestamps monotonic:          PASS")
    print("Relative time origin:          PASS")

    print(
        f"\nExperimental trace written to: "
        f"{args.output}"
    )
    print(
        f"Manifest written to:           "
        f"{args.manifest}"
    )


if __name__ == "__main__":
    main()