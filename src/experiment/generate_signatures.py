#!/usr/bin/env python3

import argparse
import hashlib
import importlib
import importlib.metadata
import json
import platform
import statistics
from collections import Counter
from pathlib import Path


# ---------------------------------------------------------------------
# General utilities
# ---------------------------------------------------------------------


def sha256_file(path, chunk_size=1024 * 1024):
    """Calculate SHA-256 digest of a file."""
    digest = hashlib.sha256()

    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def sha256_bytes(data):
    """Calculate SHA-256 digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def package_version(package_name):
    """Return installed package version if available."""
    try:
        return importlib.metadata.version(
            package_name
        )
    except importlib.metadata.PackageNotFoundError:
        return None


def load_json(path):
    """Load JSON."""
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_jsonl(path):
    """Load JSONL."""
    records = []

    with path.open("r", encoding="utf-8") as f:
        for line_number, line in enumerate(f, start=1):
            try:
                records.append(
                    json.loads(line)
                )
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Malformed JSON in {path} "
                    f"at line {line_number}."
                ) from exc

    return records


def write_jsonl(path, records):
    """Write records to JSONL."""
    path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with path.open(
        "w",
        encoding="utf-8"
    ) as f:
        for record in records:
            f.write(
                json.dumps(
                    record,
                    separators=(",", ":")
                )
            )
            f.write("\n")


# ---------------------------------------------------------------------
# Experimental trace
# ---------------------------------------------------------------------


def load_trace(path):
    """Load canonical trace indexed by trace_id."""
    records = load_jsonl(path)

    trace = {}

    for record in records:
        trace_id = record["trace_id"]

        if trace_id in trace:
            raise ValueError(
                f"Duplicate trace_id {trace_id}."
            )

        trace[trace_id] = record

    return trace


def build_signing_input(group, trace):
    """
    Construct:

        M = m_1 || m_2 || ... || m_k

    directly from the empirical 112-bit DF17 messages.
    """
    parts = []

    for trace_id in group["trace_ids"]:
        if trace_id not in trace:
            raise KeyError(
                f"Trace ID {trace_id} not found."
            )

        raw_msg = trace[
            trace_id
        ]["raw_msg"]

        try:
            message = bytes.fromhex(
                raw_msg
            )
        except ValueError as exc:
            raise ValueError(
                f"Invalid raw_msg for "
                f"trace_id {trace_id}."
            ) from exc

        if len(message) != 14:
            raise ValueError(
                f"Trace ID {trace_id} has "
                f"{len(message)} bytes instead "
                f"of 14."
            )

        parts.append(message)

    signing_input = b"".join(parts)

    expected_length = (
        14 * group["message_count"]
    )

    if len(signing_input) != expected_length:
        raise RuntimeError(
            "Signing input length mismatch."
        )

    return signing_input


# ---------------------------------------------------------------------
# Algorithm loading
# ---------------------------------------------------------------------


def load_algorithm_module(config):
    """Dynamically load an algorithm implementation module."""
    module_name = config["module"]

    try:
        module = importlib.import_module(
            module_name
        )
    except ImportError as exc:
        raise RuntimeError(
            f"Could not import algorithm module "
            f"'{module_name}'."
        ) from exc

    if not hasattr(module, "Signer"):
        raise RuntimeError(
            f"Algorithm module '{module_name}' "
            "does not expose Signer."
        )

    return module


def validate_metadata(
    algorithm_name,
    config,
    signer
):
    """Validate implementation metadata against configuration."""
    metadata = signer.metadata()

    expected_pk = config.get(
        "expected_public_key_bytes"
    )

    actual_pk = metadata.get(
        "public_key_bytes"
    )

    if (
        expected_pk is not None
        and actual_pk != expected_pk
    ):
        raise RuntimeError(
            f"{algorithm_name}: expected "
            f"{expected_pk}-byte public key, "
            f"backend reports {actual_pk}."
        )

    expected_sig = config.get(
        "expected_signature_bytes"
    )

    actual_max_sig = metadata.get(
        "maximum_signature_bytes"
    )

    if (
        expected_sig is not None
        and actual_max_sig is not None
        and actual_max_sig != expected_sig
    ):
        raise RuntimeError(
            f"{algorithm_name}: expected "
            f"{expected_sig}-byte signature, "
            f"backend reports "
            f"{actual_max_sig}."
        )

    return metadata


# ---------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------


def create_aircraft_signers(
    aircraft,
    algorithm_module
):
    """Generate one persistent keypair per aircraft."""
    signers = {}

    total = len(aircraft)

    for index, icao in enumerate(
        sorted(aircraft),
        start=1
    ):
        signers[icao] = (
            algorithm_module.Signer()
        )

        if (
            index % 50 == 0
            or index == total
        ):
            print(
                f"    Keypairs: "
                f"{index}/{total}"
            )

    return signers


def close_signers(signers):
    """Release algorithm resources."""
    for signer in signers.values():
        signer.close()


# ---------------------------------------------------------------------
# Signing experiment
# ---------------------------------------------------------------------


def process_interval(
    algorithm_name,
    algorithm_config,
    k,
    groups,
    trace,
    signers,
):
    """Generate and verify every complete authentication event."""
    complete_groups = [
        group
        for group in groups
        if group["complete"]
    ]

    results = []
    signature_lengths = Counter()

    total = len(
        complete_groups
    )

    for index, group in enumerate(
        complete_groups,
        start=1
    ):
        signer = signers[
            group["icao"]
        ]

        message = build_signing_input(
            group,
            trace
        )

        signature = signer.sign(
            message
        )

        verified = signer.verify(
            message,
            signature
        )

        if not verified:
            raise RuntimeError(
                f"Verification failed: "
                f"algorithm={algorithm_name}, "
                f"k={k}, "
                f"group_id={group['group_id']}, "
                f"icao={group['icao']}."
            )

        signature_length = len(
            signature
        )

        signature_lengths[
            signature_length
        ] += 1

        results.append({
            "algorithm": algorithm_name,
            "k": k,
            "group_id": (
                group["group_id"]
            ),
            "icao": group["icao"],
            "message_count": (
                group["message_count"]
            ),
            "message_length_bytes": (
                len(message)
            ),
            "message_sha256": (
                sha256_bytes(message)
            ),
            "signature_length_bytes": (
                signature_length
            ),
            "signature_sha256": (
                sha256_bytes(signature)
            ),
            "verification_success": True,
            "group_formation_time_s": (
                group[
                    "group_formation_time_s"
                ]
            ),
        })

        if (
            index % 5000 == 0
            or index == total
        ):
            print(
                f"    k={k}: "
                f"{index:,}/{total:,} "
                "verified"
            )

    lengths = [
        result[
            "signature_length_bytes"
        ]
        for result in results
    ]

    if lengths:
        length_summary = {
            "minimum_bytes": min(
                lengths
            ),
            "maximum_bytes": max(
                lengths
            ),
            "mean_bytes": (
                statistics.mean(
                    lengths
                )
            ),
            "median_bytes": (
                statistics.median(
                    lengths
                )
            ),
            "distribution": {
                str(length): count
                for length, count
                in sorted(
                    signature_lengths.items()
                )
            },
        }
    else:
        length_summary = {
            "minimum_bytes": None,
            "maximum_bytes": None,
            "mean_bytes": None,
            "median_bytes": None,
            "distribution": {},
        }

    return results, {
        "k": k,
        "complete_groups": total,
        "signatures_generated": len(
            results
        ),
        "signatures_verified": len(
            results
        ),
        "verification_failures": 0,
        "signature_length": (
            length_summary
        ),
    }


# ---------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Generate and verify real signatures "
            "over empirical ADS-B authentication groups."
        )
    )

    parser.add_argument(
        "--trace",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--groups-dir",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--config",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--summary",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--intervals",
        type=int,
        nargs="+",
        default=[1, 5, 10, 20],
    )

    args = parser.parse_args()

    intervals = sorted(
        set(args.intervals)
    )

    algorithm_configs = load_json(
        args.config
    )

    enabled_algorithms = {
        name: config
        for name, config
        in algorithm_configs.items()
        if config.get(
            "enabled",
            True
        )
    }

    if not enabled_algorithms:
        raise RuntimeError(
            "No algorithms are enabled."
        )

    trace = load_trace(
        args.trace
    )

    aircraft = sorted({
        record["icao"]
        for record in trace.values()
    })

    print(
        "\n=== Real Signature Experiment ==="
    )

    print(
        f"Trace observations:       "
        f"{len(trace):,}"
    )

    print(
        f"Aircraft:                 "
        f"{len(aircraft):,}"
    )

    print(
        f"Enabled algorithms:       "
        f"{len(enabled_algorithms)}"
    )

    print(
        f"Intervals:                "
        f"{intervals}"
    )

    args.output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    experiment_summary = {
        "trace_file": str(
            args.trace
        ),
        "trace_sha256": (
            sha256_file(
                args.trace
            )
        ),
        "algorithm_config_file": str(
            args.config
        ),
        "algorithm_config_sha256": (
            sha256_file(
                args.config
            )
        ),
        "trace_records": len(
            trace
        ),
        "unique_aircraft": len(
            aircraft
        ),
        "authentication_intervals": (
            intervals
        ),
        "signing_input": {
            "source": (
                "raw 112-bit DF17 messages"
            ),
            "construction": (
                "byte concatenation in "
                "authentication-group order"
            ),
            "bytes_per_message": 14,
        },
        "key_model": {
            "one_keypair_per_aircraft_per_algorithm": True,
            "keypair_reused_across_intervals": True,
            "public_key_distribution_simulated": False,
        },
        "host_timing_used_as_avionics_model": False,
        "software": {
            "python": (
                platform.python_version()
            ),
            "platform": (
                platform.platform()
            ),
            "cryptography": (
                package_version(
                    "cryptography"
                )
            ),
            "liboqs_python": (
                package_version(
                    "liboqs-python"
                )
            ),
        },
        "algorithms": {},
    }

    for (
        algorithm_name,
        algorithm_config
    ) in enabled_algorithms.items():

        print(
            f"\n=== {algorithm_name} ==="
        )

        module = load_algorithm_module(
            algorithm_config
        )

        print(
            "Generating persistent "
            "aircraft keypairs..."
        )

        signers = (
            create_aircraft_signers(
                aircraft,
                module
            )
        )

        try:
            representative = signers[
                aircraft[0]
            ]

            metadata = validate_metadata(
                algorithm_name,
                algorithm_config,
                representative,
            )

            algorithm_summary = {
                "family": (
                    algorithm_config[
                        "family"
                    ]
                ),
                "paper_name": (
                    algorithm_config[
                        "paper_name"
                    ]
                ),
                "parameter_set": (
                    algorithm_config[
                        "parameter_set"
                    ]
                ),
                "module": (
                    algorithm_config[
                        "module"
                    ]
                ),
                "implementation": (
                    algorithm_config[
                        "implementation"
                    ]
                ),
                "implementation_metadata": (
                    metadata
                ),
                "aircraft_keypairs": len(
                    signers
                ),
                "intervals": {},
                "output_files": {},
            }

            if "implementation_note" in (
                algorithm_config
            ):
                algorithm_summary[
                    "implementation_note"
                ] = algorithm_config[
                    "implementation_note"
                ]

            for k in intervals:
                group_path = (
                    args.groups_dir
                    / (
                        f"authentication_groups_"
                        f"k{k}.jsonl"
                    )
                )

                groups = load_jsonl(
                    group_path
                )

                print(
                    f"\n  Processing k={k}"
                )

                results, interval_summary = (
                    process_interval(
                        algorithm_name,
                        algorithm_config,
                        k,
                        groups,
                        trace,
                        signers,
                    )
                )

                output_path = (
                    args.output_dir
                    / (
                        f"signatures_"
                        f"{algorithm_name}_"
                        f"k{k}.jsonl"
                    )
                )

                write_jsonl(
                    output_path,
                    results
                )

                algorithm_summary[
                    "intervals"
                ][str(k)] = (
                    interval_summary
                )

                algorithm_summary[
                    "output_files"
                ][str(k)] = {
                    "file": str(
                        output_path
                    ),
                    "sha256": (
                        sha256_file(
                            output_path
                        )
                    ),
                }

            experiment_summary[
                "algorithms"
            ][algorithm_name] = (
                algorithm_summary
            )

        finally:
            close_signers(
                signers
            )

    args.summary.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with args.summary.open(
        "w",
        encoding="utf-8"
    ) as f:
        json.dump(
            experiment_summary,
            f,
            indent=2
        )

    print(
        "\n=== Experiment Complete ==="
    )

    print(
        f"Summary written to: "
        f"{args.summary}"
    )


if __name__ == "__main__":
    main()