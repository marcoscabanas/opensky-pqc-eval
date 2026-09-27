#!/usr/bin/env python3

import argparse
import csv
import json
import math
from collections import defaultdict
from pathlib import Path


def load_json(path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_jsonl(path):
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            records.append(json.loads(line))
    return records


def load_trace(path):
    records = load_jsonl(path)
    trace = {record["trace_id"]: record for record in records}
    return trace


def collect_group_files(groups_dir, intervals):
    result = {}
    for interval in intervals:
        path = groups_dir / f"authentication_groups_k{interval}.jsonl"
        groups = load_jsonl(path)
        result[interval] = {g["group_id"]: g for g in groups}
    return result


def collect_signature_files(signatures_dir, intervals):
    result = {}
    for interval in intervals:
        path = signatures_dir / f"signatures_ECDSA-P256_k{interval}.jsonl"
        if not path.exists():
            # allow all algorithms by scanning the dir for matching pattern
            candidates = list(signatures_dir.glob(f"*k{interval}.jsonl"))
            if not candidates:
                continue
            result[interval] = {}
            for candidate in candidates:
                alg = candidate.name.split(f"_k{interval}.jsonl")[0].replace("signatures_", "")
                result[interval][alg] = load_jsonl(candidate)
            continue
        result[interval] = {"ECDSA-P256": load_jsonl(path)}
    return result


def signature_by_algorithm(signatures_dir, intervals, algorithms):
    result = {}
    for interval in intervals:
        result[interval] = {}
        for algorithm in algorithms:
            path = signatures_dir / f"signatures_{algorithm}_k{interval}.jsonl"
            if path.exists():
                result[interval][algorithm] = load_jsonl(path)
    return result


def compute_single_message_feasibility(signature_bytes, payload_bytes):
    fits_single_message = signature_bytes <= payload_bytes
    return {
        "signature_bytes": signature_bytes,
        "payload_bytes": payload_bytes,
        "fits_single_message": fits_single_message,
        "required_fragments": max(1, math.ceil(signature_bytes / payload_bytes)) if not fits_single_message else 1,
    }


def compute_fragmentation(signature_bytes, payload_bytes, redundancy_factor=1.0):
    effective_payload = max(1, int(payload_bytes * redundancy_factor))
    required_fragments = int(math.ceil(signature_bytes / effective_payload)) if signature_bytes > 0 else 0
    if signature_bytes <= effective_payload:
        required_fragments = 1
    return {
        "signature_bytes": signature_bytes,
        "payload_bytes": payload_bytes,
        "redundancy_factor": redundancy_factor,
        "effective_payload_bytes": effective_payload,
        "required_fragments": required_fragments,
        "bytes_per_fragment": effective_payload,
    }


def compute_channel_utilization(trace_record_count, extra_bytes_per_event, interval):
    """Very lightweight proxy for occupancy cost in the observed trace."""
    if trace_record_count <= 0:
        return 0.0
    # This is intentionally a coarse operational proxy rather than a full PHY model.
    return extra_bytes_per_event / max(1, trace_record_count)


def analyze_algorithms(trace, groups_by_interval, signatures_by_interval, algorithms, intervals, payload_bytes, bit_rate_bps, loss_probability, redundancy_factor):
    rows = []
    summaries = {}

    for interval in intervals:
        groups = groups_by_interval.get(interval, {})
        signatures = signatures_by_interval.get(interval, {})
        for algorithm_name, entries in signatures.items():
            if not entries:
                continue
            sig_lengths = [entry.get("signature_length_bytes", 0) for entry in entries]
            if not sig_lengths:
                continue
            signature_bytes = max(sig_lengths)
            single = compute_single_message_feasibility(signature_bytes, payload_bytes)
            frag = compute_fragmentation(signature_bytes, payload_bytes, redundancy_factor)
            event_count = len(entries)
            total_signature_bytes = sum(sig_lengths)
            expected_fragments = frag["required_fragments"]
            added_bytes_per_event = max(signature_bytes, 0)
            occupancy = compute_channel_utilization(len(trace), added_bytes_per_event, interval)
            recovery_probability = (1.0 - loss_probability) ** expected_fragments
            latency_ms = (expected_fragments * (8 * max(signature_bytes, 1) / max(bit_rate_bps, 1))) * 1000.0

            row = {
                "algorithm": algorithm_name,
                "interval_k": interval,
                "signature_bytes": signature_bytes,
                "fits_single_message": single["fits_single_message"],
                "required_fragments": frag["required_fragments"],
                "effective_payload_bytes": frag["effective_payload_bytes"],
                "total_signature_bytes_across_events": total_signature_bytes,
                "event_count": event_count,
                "channel_occupancy_proxy": occupancy,
                "recovery_probability": recovery_probability,
                "latency_ms": latency_ms,
                "immediate_auth_feasible": single["fits_single_message"],
                "detached_auth_feasible": True,
                "loss_tolerant": recovery_probability > 0.5,
            }
            rows.append(row)

        summary = {
            "interval_k": interval,
            "algorithms": {
                algorithm_name: {
                    "signature_bytes": max([entry.get("signature_length_bytes", 0) for entry in entries]),
                    "fits_single_message": max([entry.get("signature_length_bytes", 0) for entry in entries]) <= payload_bytes,
                    "required_fragments": max(1, math.ceil(max([entry.get("signature_length_bytes", 0) for entry in entries]) / payload_bytes)) if max([entry.get("signature_length_bytes", 0) for entry in entries]) > payload_bytes else 1,
                }
                for algorithm_name, entries in signatures.items()
                if entries
            },
        }
        summaries[interval] = summary

    return rows, summaries


def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "algorithm",
        "interval_k",
        "signature_bytes",
        "fits_single_message",
        "required_fragments",
        "effective_payload_bytes",
        "total_signature_bytes_across_events",
        "event_count",
        "channel_occupancy_proxy",
        "recovery_probability",
        "latency_ms",
        "immediate_auth_feasible",
        "detached_auth_feasible",
        "loss_tolerant",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def main():
    parser = argparse.ArgumentParser(description="Operational feasibility analysis for ADS-B authentication signatures.")
    parser.add_argument("--trace", type=Path, required=True)
    parser.add_argument("--groups-dir", type=Path, required=True)
    parser.add_argument("--signatures-dir", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--intervals", type=int, nargs="+", default=[1, 5, 10, 20])
    parser.add_argument("--payload-bytes", type=int, default=14)
    parser.add_argument("--bit-rate-bps", type=float, default=1000000.0)
    parser.add_argument("--loss-probability", type=float, default=0.01)
    parser.add_argument("--redundancy-factor", type=float, default=1.0)
    args = parser.parse_args()

    config = load_json(args.config)
    algorithms = [name for name, value in config.items() if value.get("enabled", True)]
    trace = load_trace(args.trace)
    groups_by_interval = collect_group_files(args.groups_dir, args.intervals)
    signatures_by_interval = signature_by_algorithm(args.signatures_dir, args.intervals, algorithms)
    rows, summaries = analyze_algorithms(
        trace,
        groups_by_interval,
        signatures_by_interval,
        algorithms,
        args.intervals,
        args.payload_bytes,
        args.bit_rate_bps,
        args.loss_probability,
        args.redundancy_factor,
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = args.output_dir / "operational_feasibility_summary.json"
    csv_path = args.output_dir / "feasibility_overview.csv"
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump({
            "input_trace": str(args.trace),
            "intervals": args.intervals,
            "payload_bytes": args.payload_bytes,
            "bit_rate_bps": args.bit_rate_bps,
            "loss_probability": args.loss_probability,
            "redundancy_factor": args.redundancy_factor,
            "algorithms": algorithms,
            "summaries": summaries,
            "rows": rows,
        }, f, indent=2)
    write_csv(csv_path, rows)
    print(f"Operational feasibility summary written to: {summary_path}")
    print(f"CSV summary written to: {csv_path}")


if __name__ == "__main__":
    main()
