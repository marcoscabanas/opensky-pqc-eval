#!/usr/bin/env python3
"""Explicit lower-bound transport scenarios for a hypothetical 1090ES extension.

The 56-bit ME field is an optimistic ceiling, not spare capacity in today's
ADS-B messages. These estimates do not establish protocol compatibility.
"""

import argparse
import csv
import hashlib
import json
import math
import os
import tempfile
from pathlib import Path


MODEL_VERSION = 2
SOURCES = [
    {
        "url": "https://www.icao.int/SAM/Documents/SAMIG11/SAMIG11_NE06Rev2.pdf",
        "supports": "Section 2.1.8, PDF page 17: 112-bit ES frame, 56-bit ADS-B field.",
    },
    {
        "url": "https://www.faa.gov/sites/faa.gov/files/2021-12/Drummond-FAAAvianRadar-Jan212016.pdf",
        "supports": "Slide 28: 8 microsecond preamble and 112 microsecond data block.",
    },
]
ASSUMPTIONS = [
    "Hypothetical additional 1090ES frames; no allocated authentication message format is assumed.",
    "Seven ME bytes are an optimistic ceiling; subtract fragment overhead for type, group, index and key identifiers. Zero overhead assumes this metadata is available out of band.",
    "Public keys and trusted aircraft/key bindings are pre-provisioned; certificates, key rotation and revocation traffic are excluded.",
    "Loss is an independent Bernoulli event for each original message and each fragment copy at a hypothetical receiver; capture loss is unknown and not estimated from the received trace.",
    "All original messages and every distinct signature fragment must arrive; partial groups cannot be authenticated. Original messages are sent once.",
    "Redundancy repeats every whole fragment a fixed integer number of times, without acknowledgments or selective retransmission. No FEC or independence under correlated interference is assumed.",
    "Latency starts at a message's observed timestamp and includes group formation, configured signing and verification delay, all scheduled fragment copies, and inter-frame gaps. Clock, propagation, queuing and contention delays are excluded.",
    "Zero signing/verification times are optimistic unmeasured assumptions; experiment throughput does not benchmark airborne or receiver hardware. Receiver CPU capacity and buffering are not simulated.",
    "Airtime load is offered frame-envelope duration per trace duration, not measured RF occupancy; overlapping frames, other Mode S traffic, and uncaptured aircraft require further modeling. Background occupancy is additive.",
    "Budget results test necessary conditions under this scenario only; thresholds are analyst choices, not ADS-B certification or authentication requirements. Passing does not establish operational feasibility.",
    "ECDSA-P256 is a classical reference baseline; it is not evidence that deployed ADS-B uses ECDSA.",
]


def load_json(path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_jsonl(path):
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def indexed_unique(records, key, label):
    result = {}
    for record in records:
        identifier = record[key]
        if identifier in result:
            raise ValueError(f"Duplicate {key} {identifier} in {label}.")
        result[identifier] = record
    return result


def load_trace(path):
    return indexed_unique(load_jsonl(path), "trace_id", str(path))


def collect_group_files(groups_dir, intervals):
    result = {}
    for interval in intervals:
        path = groups_dir / f"authentication_groups_k{interval}.jsonl"
        result[interval] = indexed_unique(load_jsonl(path), "group_id", str(path))
    return result


def signature_by_algorithm(signatures_dir, intervals, algorithms):
    # Required files are never silently omitted: that would bias comparisons.
    return {
        interval: {
            algorithm: load_jsonl(signatures_dir / f"signatures_{algorithm}_k{interval}.jsonl")
            for algorithm in algorithms
        }
        for interval in intervals
    }


def finite_number(value, name, minimum=0, maximum=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number.")
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError(f"{name} must be between {minimum} and {maximum}.")
    return value


def positive_integer(value, name):
    finite_number(value, name, 1)
    if int(value) != value:
        raise ValueError(f"{name} must be an integer.")
    return int(value)


def compute_fragmentation(signature_bytes, payload_bytes, redundancy_factor=1.0, fragment_overhead_bytes=0):
    signature_bytes = positive_integer(signature_bytes, "signature_bytes")
    payload_bytes = positive_integer(payload_bytes, "payload_bytes")
    if payload_bytes > 7:
        raise ValueError("payload_bytes exceeds the 7-byte 1090ES ME field; 14 bytes is the entire frame.")
    copies = positive_integer(redundancy_factor, "redundancy_factor (whole-fragment copies)")
    finite_number(fragment_overhead_bytes, "fragment_overhead_bytes", 0, payload_bytes - 1)
    if int(fragment_overhead_bytes) != fragment_overhead_bytes:
        raise ValueError("fragment_overhead_bytes must be an integer.")
    effective_payload = payload_bytes - int(fragment_overhead_bytes)
    fragments = (signature_bytes + effective_payload - 1) // effective_payload
    return {
        "signature_bytes": signature_bytes,
        "payload_bytes": payload_bytes,
        "redundancy_factor": copies,
        "effective_payload_bytes": effective_payload,
        "required_fragments": fragments,
        "transmitted_fragments": fragments * copies,
        "bytes_per_fragment": effective_payload,
    }


def compute_single_message_feasibility(signature_bytes, payload_bytes):
    result = compute_fragmentation(signature_bytes, payload_bytes)
    return {**result, "fits_single_message": result["required_fragments"] == 1}


def compute_channel_utilization(frame_count, duration_s, frame_airtime_s):
    """Offered frame-envelope seconds per observation second; may exceed one."""
    finite_number(frame_count, "frame_count")
    finite_number(duration_s, "duration_s")
    finite_number(frame_airtime_s, "frame_airtime_s")
    if duration_s <= 0:
        raise ValueError("Trace must span a positive duration to estimate event rates.")
    return frame_count * frame_airtime_s / duration_s


def validate_groups(trace, groups, interval):
    """Validate coverage without changing grouping or signing semantics."""
    if not groups:
        raise ValueError(f"k={interval}: no authentication groups.")
    seen = set()
    complete = {}
    for group_id, group in groups.items():
        ids = group["trace_ids"]
        count = len(ids)
        if (group.get("group_id") != group_id or group.get("k") != interval
                or group.get("message_count") != count or not 0 < count <= interval
                or group.get("complete") is not (count == interval)):
            raise ValueError(f"k={interval}, group={group_id}: inconsistent group metadata.")
        times = []
        messages = []
        for trace_id in ids:
            if trace_id not in trace or trace_id in seen:
                raise ValueError(f"k={interval}: unknown or repeated trace ID {trace_id}.")
            seen.add(trace_id)
            record = trace[trace_id]
            if record["icao"] != group["icao"]:
                raise ValueError(f"k={interval}, group={group_id}: aircraft mismatch.")
            times.append(finite_number(record["relative_time_s"], "relative_time_s"))
            message = bytes.fromhex(record["raw_msg"])
            if len(message) != 14:
                raise ValueError(f"Trace ID {trace_id}: expected a 112-bit original frame.")
            messages.append(message)
        if times != sorted(times):
            raise ValueError(f"k={interval}, group={group_id}: timestamps are not ordered.")
        if (group["first_message_time_s"] != times[0] or group["last_message_time_s"] != times[-1]
                or (group["complete"] and group["group_formation_time_s"] != times[-1])):
            raise ValueError(f"k={interval}, group={group_id}: stale group timestamps.")
        if group["complete"]:
            complete[group_id] = {
                "group": group,
                "digest": hashlib.sha256(b"".join(messages)).hexdigest(),
                "formation_delay_ms": (times[-1] - times[0]) * 1000,
                "message_wait_sum_ms": sum((times[-1] - time) * 1000 for time in times),
            }
    if seen != set(trace):
        raise ValueError(f"k={interval}: authentication groups do not cover the entire trace.")
    if not complete:
        raise ValueError(f"k={interval}: no complete groups to evaluate.")
    return complete


def validate_signature_coverage(entries, complete, algorithm, interval):
    indexed = indexed_unique(entries, "group_id", f"{algorithm}, k={interval}")
    if set(indexed) != set(complete):
        missing = len(set(complete) - set(indexed))
        unexpected = len(set(indexed) - set(complete))
        raise ValueError(f"{algorithm}, k={interval}: incomplete signature coverage ({missing} missing, {unexpected} unexpected).")
    for group_id, entry in indexed.items():
        info = complete[group_id]
        group = info["group"]
        expected = {
            "algorithm": algorithm, "k": interval, "icao": group["icao"],
            "message_count": group["message_count"], "message_length_bytes": 14 * group["message_count"],
            "message_sha256": info["digest"], "group_formation_time_s": group["group_formation_time_s"],
        }
        if entry.get("verification_success") is not True or any(entry.get(key) != value for key, value in expected.items()):
            raise ValueError(f"{algorithm}, k={interval}, group={group_id}: invalid or stale signature metadata.")
        positive_integer(entry.get("signature_length_bytes"), "signature_length_bytes")
    return indexed


def analyze_algorithms(trace, groups_by_interval, signatures_by_interval, algorithms, intervals,
                       payload_bytes=7, bit_rate_bps=1000000.0, loss_probability=0.01,
                       redundancy_factor=1.0, *, fragment_overhead_bytes=0, frame_bits=112,
                       preamble_us=8.0, inter_frame_gap_us=0.0, receiver_verification_ms=0.0,
                       sender_signing_ms=0.0, background_occupancy=0.0,
                       max_channel_occupancy=None, max_auth_latency_ms=None,
                       min_auth_success_probability=None):
    """Compare complete, verified signature metadata under explicit assumptions."""
    if not trace or not algorithms or not intervals:
        raise ValueError("Trace, enabled algorithms and intervals must be nonempty.")
    if len(set(algorithms)) != len(algorithms) or len(set(intervals)) != len(intervals):
        raise ValueError("Algorithms and intervals must be unique.")
    for interval in intervals:
        positive_integer(interval, "interval")
    frag_options = compute_fragmentation(1, payload_bytes, redundancy_factor, fragment_overhead_bytes)
    finite_number(bit_rate_bps, "bit_rate_bps")
    if bit_rate_bps != 1000000 or frame_bits != 112 or preamble_us != 8:
        raise ValueError("1090ES requires 1000000 bit/s, a 112-bit frame and an 8-microsecond preamble.")
    finite_number(loss_probability, "loss_probability", 0, 1)
    for name, value in [("preamble_us", preamble_us), ("inter_frame_gap_us", inter_frame_gap_us),
                        ("receiver_verification_ms", receiver_verification_ms), ("sender_signing_ms", sender_signing_ms)]:
        finite_number(value, name)
    finite_number(background_occupancy, "background_occupancy", 0, 1)
    if max_channel_occupancy is not None:
        finite_number(max_channel_occupancy, "max_channel_occupancy", 0, 1)
    if max_auth_latency_ms is not None:
        finite_number(max_auth_latency_ms, "max_auth_latency_ms")
    if min_auth_success_probability is not None:
        finite_number(min_auth_success_probability, "min_auth_success_probability", 0, 1)
    times = [finite_number(record["relative_time_s"], "relative_time_s") for record in trace.values()]
    duration = max(times) - min(times)
    frame_airtime_s = frame_bits / bit_rate_bps + preamble_us / 1e6
    baseline_load = compute_channel_utilization(len(trace), duration, frame_airtime_s)
    rows, summaries = [], {}
    for interval in intervals:
        groups = groups_by_interval.get(interval, {})
        complete = validate_groups(trace, groups, interval)
        signed_count = sum(info["group"]["message_count"] for info in complete.values())
        summaries[interval] = {"interval_k": interval, "algorithms": {}}
        for algorithm in algorithms:
            entries = signatures_by_interval.get(interval, {}).get(algorithm)
            if entries is None:
                raise ValueError(f"Missing signatures for {algorithm}, k={interval}.")
            entries = validate_signature_coverage(entries, complete, algorithm, interval)
            lengths, fragment_counts, transmissions, spans, probabilities, latencies = [], [], [], [], [], []
            weighted_latency_sum = 0.0
            for group_id, entry in entries.items():
                info = complete[group_id]
                length = entry["signature_length_bytes"]
                fragments = compute_fragmentation(length, payload_bytes, redundancy_factor, fragment_overhead_bytes)
                tx = fragments["transmitted_fragments"]
                span_ms = tx * frame_airtime_s * 1000 + (tx - 1) * inter_frame_gap_us / 1000
                processing_ms = sender_signing_ms + receiver_verification_ms
                signature_probability = (1 - loss_probability ** frag_options["redundancy_factor"]) ** fragments["required_fragments"]
                lengths.append(length)
                fragment_counts.append(fragments["required_fragments"])
                transmissions.append(tx)
                spans.append(span_ms)
                probabilities.append(signature_probability)
                latencies.append(info["formation_delay_ms"] + span_ms + processing_ms)
                weighted_latency_sum += info["message_wait_sum_ms"] + interval * (span_ms + processing_ms)
            events = len(entries)
            added_load = compute_channel_utilization(sum(transmissions), duration, frame_airtime_s)
            total_load = baseline_load + added_load + background_occupancy
            group_probability = (1 - loss_probability) ** interval
            success_min = min(probabilities) * group_probability
            success_mean = sum(probabilities) / events * group_probability
            occupancy_ok = None if max_channel_occupancy is None else total_load <= max_channel_occupancy
            latency_ok = None if max_auth_latency_ms is None else max(latencies) <= max_auth_latency_ms
            reliability_ok = None if min_auth_success_probability is None else success_min >= min_auth_success_probability
            tests = [occupancy_ok, latency_ok, reliability_ok]
            decision = None if any(test is None for test in tests) else all(tests)
            row = {
                "algorithm": algorithm, "interval_k": interval,
                "signature_bytes": max(lengths), "signature_bytes_min": min(lengths),
                "signature_bytes_mean": sum(lengths) / events,
                "fits_single_message": max(fragment_counts) == 1,
                "required_fragments": max(fragment_counts), "required_fragments_mean": sum(fragment_counts) / events,
                "effective_payload_bytes": frag_options["effective_payload_bytes"],
                "fragment_copies": frag_options["redundancy_factor"],
                "total_signature_bytes_across_events": sum(lengths), "event_count": events,
                "incomplete_group_count": len(groups) - events, "unsigned_message_count": len(trace) - signed_count,
                "signed_message_fraction": signed_count / len(trace),
                "trace_duration_s": duration, "auth_events_per_second": events / duration,
                "frame_airtime_us": frame_airtime_s * 1e6,
                "total_fragment_transmissions": sum(transmissions),
                "additional_frames_per_second": sum(transmissions) / duration,
                "additional_frame_bits_per_second": sum(transmissions) * frame_bits / duration,
                "baseline_airtime_load": baseline_load, "additional_airtime_load": added_load,
                "total_offered_airtime_load": total_load,
                "exceeds_serial_channel_capacity": total_load > 1,
                "signature_recovery_probability_mean": sum(probabilities) / events,
                "signature_recovery_probability_min": min(probabilities),
                "group_message_recovery_probability": group_probability,
                "authentication_success_probability_mean": success_mean,
                "authentication_success_probability_min": success_min,
                "expected_authenticated_trace_fraction": success_mean * signed_count / len(trace),
                "group_formation_delay_ms_mean": sum(info["formation_delay_ms"] for info in complete.values()) / events,
                "group_formation_delay_ms_max": max(info["formation_delay_ms"] for info in complete.values()),
                "signature_delivery_span_ms_mean": sum(spans) / events,
                "signature_delivery_span_ms_max": max(spans),
                "auth_latency_ms_mean": weighted_latency_sum / signed_count,
                "auth_latency_ms_max": max(latencies),
                "channel_budget_met": occupancy_ok, "latency_budget_met": latency_ok,
                "reliability_budget_met": reliability_ok,
                "detached_auth_feasible": decision,
                "decision_scope": "necessary conditions only; unknown until all three scenario budgets are supplied",
            }
            rows.append(row)
            summaries[interval]["algorithms"][algorithm] = row
    return rows, summaries


def write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value):
    # JSON object keys are strings. Normalize before sorting: integer interval
    # keys [1, 5, 10, 20] otherwise sort differently after a file round trip.
    json_value = json.loads(json.dumps(value, allow_nan=False))
    return json.dumps(json_value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def build_provenance(args, algorithms, parameters):
    paths = [args.trace, args.config, Path(__file__).resolve()]
    for interval in args.intervals:
        paths.append(args.groups_dir / f"authentication_groups_k{interval}.jsonl")
        paths.extend(args.signatures_dir / f"signatures_{algorithm}_k{interval}.jsonl" for algorithm in algorithms)
    manifest = {
        "model_version": MODEL_VERSION, "parameters": parameters,
        "intervals": args.intervals, "algorithms": algorithms,
        "files": [{"path": str(path.resolve()), "sha256": sha256_file(path)} for path in paths],
    }
    return manifest, hashlib.sha256(canonical_json(manifest).encode()).hexdigest()


def outputs_match(summary_path, csv_path, report):
    if not summary_path.exists() or not csv_path.exists():
        return False
    try:
        previous = load_json(summary_path)
        checksum = previous.pop("csv_sha256", None)
        return checksum == sha256_file(csv_path) and canonical_json(previous) == canonical_json(report)
    except (ValueError, OSError, TypeError):
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["trace", "groups-dir", "signatures-dir", "config", "output-dir"]:
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--intervals", type=int, nargs="+", default=[1, 5, 10, 20])
    parser.add_argument("--payload-bytes", type=int, default=7)
    parser.add_argument("--bit-rate-bps", type=float, default=1000000.0)
    parser.add_argument("--loss-probability", type=float, default=0.01)
    parser.add_argument("--redundancy-factor", type=float, default=1.0, help="Integer copies of each fragment, including the first transmission.")
    parser.add_argument("--fragment-overhead-bytes", type=int, default=0)
    parser.add_argument("--frame-bits", type=int, default=112)
    parser.add_argument("--preamble-us", type=float, default=8.0)
    parser.add_argument("--inter-frame-gap-us", type=float, default=0.0)
    parser.add_argument("--receiver-verification-ms", type=float, default=0.0)
    parser.add_argument("--sender-signing-ms", type=float, default=0.0)
    parser.add_argument("--background-occupancy", type=float, default=0.0)
    parser.add_argument("--max-channel-occupancy", type=float)
    parser.add_argument("--max-auth-latency-ms", type=float)
    parser.add_argument("--min-auth-success-probability", type=float)
    parser.add_argument("--force", action="store_true", help="Explicitly replace existing feasibility outputs.")
    parser.add_argument("--validate-only", action="store_true", help="Validate inputs and existing results without writing files.")
    args = parser.parse_args()
    summary_path = args.output_dir / "operational_feasibility_summary.json"
    csv_path = args.output_dir / "feasibility_overview.csv"
    if args.force and args.validate_only:
        parser.error("--force and --validate-only are mutually exclusive.")
    config = load_json(args.config)
    algorithms = [name for name, value in config.items() if value.get("enabled", True)]
    parameters = {key: value for key, value in vars(args).items() if key not in {
        "trace", "groups_dir", "signatures_dir", "config", "output_dir", "intervals", "force", "validate_only",
    }}
    provenance, fingerprint = build_provenance(args, algorithms, parameters)
    rows, summaries = analyze_algorithms(
        load_trace(args.trace), collect_group_files(args.groups_dir, args.intervals),
        signature_by_algorithm(args.signatures_dir, args.intervals, algorithms),
        algorithms, args.intervals, **parameters,
    )
    report = {
        "model_version": MODEL_VERSION, "input_trace": str(args.trace),
        "intervals": args.intervals, "algorithms": algorithms, "parameters": parameters,
        "assumptions": ASSUMPTIONS, "sources": SOURCES, "summaries": summaries, "rows": rows,
        "metric_definitions": {
            "required_fragments": "Maximum distinct fragments for any signature; mean and totals use actual per-event lengths.",
            "signature_delivery_span_ms_mean": "Event mean of all fragment copies' airtime plus gaps; excludes signing, verification and group formation.",
            "signature_delivery_span_ms_max": "Maximum of that scheduled serialization span across authentication events.",
            "auth_latency_ms_mean": "Mean over messages in complete groups: wait for group formation plus serialization, signing and verification; incomplete groups excluded.",
            "auth_latency_ms_max": "Maximum over messages in complete groups of the same latency; excludes unmodeled queuing/contention.",
            "authentication_success_probability_min": "Worst event probability of receiving all original messages and all signature fragments under independent loss.",
            "total_offered_airtime_load": "Sum of baseline and added frame-envelope seconds divided by observed trace span, plus background load; not clipped to one.",
            "detached_auth_feasible": "Nullable necessary-condition test of all three configured budgets; does not certify operational feasibility.",
        },
        "validation_scope": "Exact complete-group coverage, signing-input digests and recorded verification_success; detached signatures are not persisted for independent cryptographic reverification.",
        "provenance": provenance, "input_fingerprint": fingerprint,
    }
    if outputs_match(summary_path, csv_path, report):
        print(f"VALIDATED: {len(rows)} feasibility rows match inputs, model, parameters and CSV digest; outputs preserved.")
        return
    if args.validate_only:
        parser.error("Existing feasibility outputs are missing or do not match the current inputs/model/parameters.")
    if not args.force and (summary_path.exists() or csv_path.exists()):
        parser.error("Existing feasibility outputs are incomplete, changed, or stale; use --force to explicitly replace them.")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    temporary_paths = []
    try:
        for destination in [summary_path, csv_path]:
            with tempfile.NamedTemporaryFile(dir=args.output_dir, prefix=f".{destination.name}.", delete=False) as handle:
                temporary_paths.append(Path(handle.name))
        write_csv(temporary_paths[1], rows)
        report["csv_sha256"] = sha256_file(temporary_paths[1])
        temporary_paths[0].write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        for temporary, destination in zip(temporary_paths, [summary_path, csv_path]):
            os.replace(temporary, destination)
    finally:
        for temporary in temporary_paths:
            temporary.unlink(missing_ok=True)
    print(f"Operational feasibility summary written to: {summary_path}")
    print(f"CSV summary written to: {csv_path}")


if __name__ == "__main__":
    main()
