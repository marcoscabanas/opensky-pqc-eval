"""File, backend and durability helpers used by the main experiment."""

import hashlib
import importlib
import importlib.metadata
import json
import os
from pathlib import Path


def sha256_file(path, chunk_size=1024 * 1024):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def package_version(package_name):
    try:
        return importlib.metadata.version(package_name)
    except importlib.metadata.PackageNotFoundError:
        return None


def load_json(path):
    with path.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def load_jsonl(path):
    records = []
    with path.open("r", encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON in {path} at line {number}.") from exc
    return records


def load_trace(path):
    trace = {}
    for record in load_jsonl(path):
        trace_id = record["trace_id"]
        if trace_id in trace:
            raise ValueError(f"Duplicate trace_id {trace_id}.")
        trace[trace_id] = record
    return trace


def load_algorithm_module(config):
    name = config["module"]
    try:
        module = importlib.import_module(name)
    except ImportError as exc:
        raise RuntimeError(f"Could not import algorithm module '{name}'.") from exc
    if not hasattr(module, "Signer"):
        raise RuntimeError(f"Algorithm module '{name}' does not expose Signer.")
    return module


def validate_metadata(algorithm_name, config, signer):
    metadata = signer.metadata()
    expected_pk = config.get("expected_public_key_bytes")
    actual_pk = metadata.get("public_key_bytes")
    if expected_pk is not None and actual_pk != expected_pk:
        raise RuntimeError(f"{algorithm_name}: expected {expected_pk}-byte public key, backend reports {actual_pk}.")
    expected_sig = config.get("expected_signature_bytes")
    actual_sig = metadata.get("maximum_signature_bytes")
    if expected_sig is not None and actual_sig is not None and actual_sig != expected_sig:
        raise RuntimeError(f"{algorithm_name}: expected {expected_sig}-byte signature, backend reports {actual_sig}.")
    return metadata


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
