#!/usr/bin/env python3

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


DEFAULT_INTERVALS = [1, 5, 10, 20]

REQUIRED_FIELDS = (
    "trace_id",
    "timestamp",
    "relative_time_s",
    "icao",
    "raw_msg",
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


def load_trace(input_path):
    """Load and validate the canonical experimental trace."""
    records = []
    malformed_records = 0

    with input_path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                malformed_records += 1
                raise ValueError(
                    f"Malformed JSON on line {line_number}."
                ) from exc

            missing = [
                field
                for field in REQUIRED_FIELDS
                if field not in record
                or record[field] is None
            ]

            if missing:
                raise ValueError(
                    f"Line {line_number} is missing required "
                    f"field(s): {', '.join(missing)}"
                )

            records.append(record)

    if malformed_records:
        raise RuntimeError(
            f"{malformed_records} malformed record(s) encountered."
        )

    if not records:
        raise ValueError(
            "Experimental trace contains no records."
        )

    return records


def validate_trace(records):
    """Verify assumptions required by the grouping stage."""
    expected_ids = list(
        range(1, len(records) + 1)
    )

    actual_ids = [
        record["trace_id"]
        for record in records
    ]

    if actual_ids != expected_ids:
        raise ValueError(
            "Trace IDs are not contiguous and ordered."
        )

    timestamps = [
        float(record["timestamp"])
        for record in records
    ]

    if timestamps != sorted(timestamps):
        raise ValueError(
            "Experimental trace is not globally "
            "chronologically ordered."
        )


def group_records_by_aircraft(records):
    """
    Construct chronologically ordered message streams
    independently for each aircraft.
    """
    aircraft = defaultdict(list)

    for record in records:
        aircraft[record["icao"]].append(record)

    for icao in aircraft:
        aircraft[icao].sort(
            key=lambda record: (
                float(record["timestamp"]),
                int(record["trace_id"]),
            )
        )

    return aircraft


def build_groups_for_interval(aircraft, k):
    """
    Construct authentication groups for one interval k.

    Complete groups contain exactly k observations.

    A final incomplete group is retained when the aircraft's
    observed message count is not divisible by k.
    """
    groups = []

    for icao in sorted(aircraft):
        messages = aircraft[icao]

        aircraft_group_index = 1

        for start in range(0, len(messages), k):
            group_messages = messages[
                start:start + k
            ]

            message_count = len(group_messages)
            complete = message_count == k

            first_message = group_messages[0]
            last_message = group_messages[-1]

            group = {
                "icao": icao,
                "k": k,
                "aircraft_group_index": (
                    aircraft_group_index
                ),
                "message_count": message_count,
                "complete": complete,
                "trace_ids": [
                    message["trace_id"]
                    for message in group_messages
                ],
                "first_trace_id": (
                    first_message["trace_id"]
                ),
                "last_trace_id": (
                    last_message["trace_id"]
                ),
                "first_message_time_s": float(
                    first_message["relative_time_s"]
                ),
                "last_message_time_s": float(
                    last_message["relative_time_s"]
                ),
                "group_formation_time_s": (
                    float(
                        last_message["relative_time_s"]
                    )
                    if complete
                    else None
                ),
            }

            groups.append(group)
            aircraft_group_index += 1

    # Assign a deterministic global group identifier
    # in chronological order of the first message.
    groups.sort(
        key=lambda group: (
            group["first_message_time_s"],
            group["first_trace_id"],
            group["icao"],
            group["aircraft_group_index"],
        )
    )

    for group_id, group in enumerate(
        groups,
        start=1
    ):
        group["group_id"] = group_id

    return groups


def validate_groups(groups, records, k):
    """
    Verify that every baseline trace observation appears
    exactly once for this value of k.
    """
    trace_ids = []

    for group in groups:
        trace_ids.extend(group["trace_ids"])

        if group["complete"]:
            if group["message_count"] != k:
                raise RuntimeError(
                    f"k={k}: complete group does not "
                    f"contain exactly {k} messages."
                )

            if group["group_formation_time_s"] is None:
                raise RuntimeError(
                    f"k={k}: complete group has no "
                    "formation timestamp."
                )

        else:
            if group["message_count"] >= k:
                raise RuntimeError(
                    f"k={k}: incomplete group contains "
                    f"{group['message_count']} messages."
                )

            if group["group_formation_time_s"] is not None:
                raise RuntimeError(
                    f"k={k}: incomplete group incorrectly "
                    "has a formation timestamp."
                )

    expected_ids = {
        record["trace_id"]
        for record in records
    }

    observed_ids = set(trace_ids)

    if observed_ids != expected_ids:
        missing = expected_ids - observed_ids
        extra = observed_ids - expected_ids

        raise RuntimeError(
            f"k={k}: trace coverage validation failed. "
            f"Missing={len(missing)}, extra={len(extra)}."
        )

    if len(trace_ids) != len(expected_ids):
        duplicate_count = (
            len(trace_ids)
            - len(set(trace_ids))
        )

        raise RuntimeError(
            f"k={k}: one or more trace observations "
            f"appear in multiple groups "
            f"({duplicate_count} duplicate references)."
        )


def summarize_groups(groups, k):
    """Generate summary statistics for one interval."""
    complete_groups = [
        group
        for group in groups
        if group["complete"]
    ]

    incomplete_groups = [
        group
        for group in groups
        if not group["complete"]
    ]

    complete_messages = sum(
        group["message_count"]
        for group in complete_groups
    )

    pending_messages = sum(
        group["message_count"]
        for group in incomplete_groups
    )

    aircraft_with_complete_group = {
        group["icao"]
        for group in complete_groups
    }

    aircraft_with_incomplete_group = {
        group["icao"]
        for group in incomplete_groups
    }

    incomplete_size_distribution = Counter(
        group["message_count"]
        for group in incomplete_groups
    )

    return {
        "k": k,
        "total_groups": len(groups),
        "complete_groups": len(
            complete_groups
        ),
        "incomplete_groups": len(
            incomplete_groups
        ),
        "messages_in_complete_groups": (
            complete_messages
        ),
        "messages_pending_at_trace_end": (
            pending_messages
        ),
        "aircraft_with_complete_group": len(
            aircraft_with_complete_group
        ),
        "aircraft_with_incomplete_terminal_group": len(
            aircraft_with_incomplete_group
        ),
        "incomplete_group_size_distribution": {
            str(size): count
            for size, count in sorted(
                incomplete_size_distribution.items()
            )
        },
    }


def write_groups(output_path, groups):
    """Write authentication groups as JSONL."""
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with output_path.open(
        "w",
        encoding="utf-8"
    ) as f:
        for group in groups:
            f.write(
                json.dumps(
                    group,
                    separators=(",", ":")
                )
            )
            f.write("\n")


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Construct per-aircraft authentication groups "
            "from the canonical DF17 experimental trace."
        )
    )

    parser.add_argument(
        "input",
        type=Path,
        help=(
            "Path to the canonical experimental "
            "trace JSONL."
        ),
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help=(
            "Directory in which authentication-group "
            "JSONL files will be written."
        ),
    )

    parser.add_argument(
        "--summary",
        type=Path,
        required=True,
        help=(
            "Path for the authentication-group "
            "summary JSON."
        ),
    )

    parser.add_argument(
        "--intervals",
        type=int,
        nargs="+",
        default=DEFAULT_INTERVALS,
        help=(
            "Authentication intervals to evaluate. "
            "Default: 1 5 10 20."
        ),
    )

    args = parser.parse_args()

    intervals = sorted(set(args.intervals))

    if any(k < 1 for k in intervals):
        raise ValueError(
            "All authentication intervals must be "
            "positive integers."
        )

    print("\n=== Authentication Group Construction ===")
    print(f"Input: {args.input}")

    input_sha256 = sha256_file(
        args.input
    )

    records = load_trace(
        args.input
    )

    validate_trace(
        records
    )

    aircraft = group_records_by_aircraft(
        records
    )

    args.output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    interval_summaries = {}
    output_files = {}

    for k in intervals:
        print(
            f"\n--- Building groups for k={k} ---"
        )

        groups = build_groups_for_interval(
            aircraft,
            k
        )

        validate_groups(
            groups,
            records,
            k
        )

        interval_summary = summarize_groups(
            groups,
            k
        )

        output_path = (
            args.output_dir
            / f"authentication_groups_k{k}.jsonl"
        )

        write_groups(
            output_path,
            groups
        )

        output_sha256 = sha256_file(
            output_path
        )

        output_files[str(k)] = {
            "file": str(output_path),
            "sha256": output_sha256,
        }

        interval_summaries[str(k)] = (
            interval_summary
        )

        print(
            f"Total groups:                  "
            f"{interval_summary['total_groups']:,}"
        )
        print(
            f"Complete groups:               "
            f"{interval_summary['complete_groups']:,}"
        )
        print(
            f"Incomplete terminal groups:    "
            f"{interval_summary['incomplete_groups']:,}"
        )
        print(
            f"Messages in complete groups:   "
            f"{interval_summary['messages_in_complete_groups']:,}"
        )
        print(
            f"Messages pending at trace end: "
            f"{interval_summary['messages_pending_at_trace_end']:,}"
        )
        print(
            f"Aircraft with complete group:  "
            f"{interval_summary['aircraft_with_complete_group']:,}"
        )

        print("Trace coverage validation:     PASS")

    summary = {
        "input_file": str(args.input),
        "input_sha256": input_sha256,
        "trace_records": len(records),
        "unique_aircraft": len(aircraft),
        "authentication_intervals": (
            intervals
        ),
        "grouping_rules": {
            "grouping_scope": (
                "independent per ICAO address"
            ),
            "message_order": (
                "chronological within aircraft"
            ),
            "grouping_basis": (
                "consecutive receiver-observed DF17 messages"
            ),
            "complete_group_size": "k",
            "terminal_incomplete_groups_retained": True,
            "incomplete_groups_generate_signature": False,
            "aircraft_removed_for_insufficient_messages": False,
            "baseline_trace_modified": False,
            "group_formation_time": (
                "relative timestamp of final message "
                "in a complete group"
            ),
        },
        "intervals": interval_summaries,
        "output_files": output_files,
        "validation": {
            "all_trace_records_referenced_once_per_interval": True,
            "complete_groups_have_exactly_k_messages": True,
            "incomplete_groups_have_fewer_than_k_messages": True,
        },
    }

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

    print("\n=== Group Construction Complete ===")
    print(
        f"Baseline trace records:        "
        f"{len(records):,}"
    )
    print(
        f"Unique aircraft:               "
        f"{len(aircraft):,}"
    )
    print(
        f"Input SHA-256:                 "
        f"{input_sha256}"
    )
    print(
        f"Summary written to:            "
        f"{args.summary}"
    )


if __name__ == "__main__":
    main()