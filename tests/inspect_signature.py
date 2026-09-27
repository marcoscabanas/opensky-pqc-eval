#!/usr/bin/env python3

import argparse
import hashlib
import json
from pathlib import Path


def load_jsonl_record(path: Path, key: str, value):
    """Return the first JSONL record for which record[key] == value."""
    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            if not line.strip():
                continue

            record = json.loads(line)

            if record.get(key) == value:
                return record

    raise RuntimeError(
        f"No record with {key}={value!r} found in {path}"
    )


def load_trace_records(path: Path, trace_ids):
    """Load the requested trace records, preserving trace_ids order."""
    wanted = set(trace_ids)
    records = {}

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            record = json.loads(line)
            trace_id = record.get("trace_id")

            if trace_id in wanted:
                records[trace_id] = record

            if len(records) == len(wanted):
                break

    missing = [trace_id for trace_id in trace_ids if trace_id not in records]

    if missing:
        raise RuntimeError(
            f"Missing trace IDs in {path}: {missing}"
        )

    return [records[trace_id] for trace_id in trace_ids]


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Audit one authentication event by independently rebuilding "
            "its signing input from the canonical ADS-B trace."
        )
    )

    parser.add_argument(
        "--trace",
        required=True,
        type=Path,
        help="Canonical experimental_trace.jsonl file.",
    )

    parser.add_argument(
        "--groups",
        required=True,
        type=Path,
        help="Authentication-group JSONL file for the selected k.",
    )

    parser.add_argument(
        "--signatures",
        required=True,
        type=Path,
        help="Signature-result JSONL file.",
    )

    parser.add_argument(
        "--group-id",
        required=True,
        type=int,
        help="Authentication group ID to inspect.",
    )

    args = parser.parse_args()

    # ---------------------------------------------------------
    # Load authentication group
    # ---------------------------------------------------------

    group = load_jsonl_record(
        args.groups,
        "group_id",
        args.group_id,
    )

    if not group.get("complete", False):
        raise RuntimeError(
            f"Group {args.group_id} is incomplete and should not have "
            "been signed."
        )

    trace_ids = group["trace_ids"]

    # ---------------------------------------------------------
    # Recover original ADS-B observations from canonical trace
    # ---------------------------------------------------------

    trace_records = load_trace_records(
        args.trace,
        trace_ids,
    )

    raw_messages = []

    for record in trace_records:
        raw_msg = record["raw_msg"]

        message_bytes = bytes.fromhex(raw_msg)

        if len(message_bytes) != 14:
            raise RuntimeError(
                f"Trace ID {record['trace_id']} produced "
                f"{len(message_bytes)} bytes instead of 14."
            )

        raw_messages.append(message_bytes)

    # ---------------------------------------------------------
    # Independently reconstruct signing input
    # ---------------------------------------------------------

    signing_input = b"".join(raw_messages)

    calculated_hash = hashlib.sha256(signing_input).hexdigest()

    # ---------------------------------------------------------
    # Load recorded signature result
    # ---------------------------------------------------------

    signature_record = load_jsonl_record(
        args.signatures,
        "group_id",
        args.group_id,
    )

    recorded_hash = signature_record.get("message_sha256")

    hash_match = calculated_hash == recorded_hash

    expected_input_length = 14 * len(trace_ids)
    length_match = len(signing_input) == expected_input_length

    aircraft_match = (
        signature_record.get("icao") == group.get("icao")
    )

    k_match = (
        signature_record.get("k") == group.get("k")
    )

    # ---------------------------------------------------------
    # Human-readable audit
    # ---------------------------------------------------------

    print()
    print("=== Authentication Event Audit ===")
    print()

    print(f"Algorithm: {signature_record.get('algorithm')}")
    print(f"k: {group.get('k')}")
    print(f"Group ID: {args.group_id}")
    print(f"Aircraft ICAO: {group.get('icao')}")
    print()

    print("Trace IDs:")
    for trace_id in trace_ids:
        print(f"  {trace_id}")
    print()

    print("Raw ADS-B messages:")
    for record in trace_records:
        print(
            f"  trace_id={record['trace_id']}: "
            f"{record['raw_msg']}"
        )
    print()

    print("Signing input (hex):")
    print(f"  {signing_input.hex().upper()}")
    print()

    print("Signing input length:")
    print(
        f"  {len(signing_input)} bytes "
        f"(expected {expected_input_length})"
    )
    print()

    print("Calculated SHA-256:")
    print(f"  {calculated_hash}")
    print()

    print("Recorded SHA-256:")
    print(f"  {recorded_hash}")
    print()

    print(f"Hash match: {hash_match}")
    print(f"Input length match: {length_match}")
    print(f"Aircraft match: {aircraft_match}")
    print(f"k match: {k_match}")
    print()

    print(
        f"Signature length: "
        f"{signature_record.get('signature_length_bytes')} bytes"
    )

    print(
        f"Recorded verification: "
        f"{signature_record.get('verification_success')}"
    )

    print()

    passed = all(
        [
            hash_match,
            length_match,
            aircraft_match,
            k_match,
            signature_record.get("verification_success") is True,
        ]
    )

    if passed:
        print("RESULT: PASS")
    else:
        print("RESULT: FAIL")
        raise SystemExit(1)


if __name__ == "__main__":
    main()