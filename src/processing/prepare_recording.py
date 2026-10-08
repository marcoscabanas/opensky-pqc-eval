"""Prepare one explicitly timed, observed Mode S recording for the experiment.

The supported input adapter is deliberately narrow: each nonempty JSONL row
contains numeric ``timestamp`` and a hexadecimal ``raw_msg`` of 56 or 112 bits.
``df`` and, for DF17, ``icao`` are optional; if supplied they must match the
message bits. Unknown input formats fail instead of silently removing traffic.
This adapter does not infer unseen transmissions, validate CRCs, or deduplicate
observations. A dataset assembled from several receivers must therefore be
converted to the intended observation domain before it is supplied here.
"""

import hashlib
import json
import math
import os
from pathlib import Path
import tempfile

from src.experiment.channel_trace import load_channel_trace, validate_coverage


FILENAMES = {
    "trace": "trace.jsonl",
    "channel": "channel.jsonl",
    "traffic": "traffic.json",
    "manifest": "manifest.json",
}


def prepared_paths(output_dir):
    """Return the four conventional preparation artifact paths."""
    directory = Path(output_dir)
    return {name: directory / filename for name, filename in FILENAMES.items()}


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _number(value, name, *, positive=False):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(f"{name} must be a finite numeric value, not a boolean.")
    if positive and value <= 0:
        raise ValueError(f"{name} must be positive.")
    return float(value)


def _parameters(metadata, target_duration_s, followup_s):
    if not isinstance(metadata, dict):
        raise ValueError("Recording metadata must be an object.")
    mode = metadata.get("timestamp_mode")
    if mode not in {"unix_seconds", "relative_seconds"}:
        raise ValueError("metadata.timestamp_mode must be 'unix_seconds' or 'relative_seconds'.")
    start = _number(metadata.get("recording_start"), "metadata.recording_start")
    end = _number(metadata.get("recording_end"), "metadata.recording_end")
    if mode == "relative_seconds" and start != 0:
        raise ValueError("relative_seconds requires recording_start=0; timestamps are relative to recording start.")
    if end <= start:
        raise ValueError("recording_end must be later than recording_start.")
    target = _number(target_duration_s, "target_duration_s", positive=True)
    followup = _number(followup_s, "followup_s")
    if followup < 0:
        raise ValueError("followup_s must be nonnegative.")
    duration = end - start
    if not math.isfinite(duration):
        raise ValueError("Declared recording duration must be finite.")
    if duration < target + followup:
        raise ValueError("Declared recording coverage must include the target window and authentication follow-up.")
    try:
        normalized_metadata = json.loads(json.dumps(metadata, sort_keys=True, allow_nan=False))
    except (TypeError, ValueError) as error:
        raise ValueError("Recording metadata must contain finite JSON values.") from error
    return {
        "adapter": "normalized_modes_jsonl_v1",
        "metadata": normalized_metadata,
        "target_duration_s": target,
        "followup_s": followup,
        "coverage_duration_s": duration,
        "target_selection": "DF17 frame start in [0, target_duration_s)",
        "preparation_source_sha256": _sha256(Path(__file__)),
    }


def validate_recording_metadata(metadata, target_duration_s=3600, followup_s=600):
    """Validate declared capture timing before any recording is processed.

    The public workflow checks every selected window first so a missing or
    invalid nighttime declaration cannot be discovered after hours of signing
    the daytime recording. This does not inspect the recording's actual rows.
    """
    return _parameters(metadata, target_duration_s, followup_s)


def _records(raw_path, parameters):
    metadata = parameters["metadata"]
    origin, coverage_end = metadata["recording_start"], parameters["coverage_duration_s"]
    with Path(raw_path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            prefix = f"Raw recording line {line_number}: "
            try:
                row = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(prefix + "invalid JSON.") from error
            if not isinstance(row, dict):
                raise ValueError(prefix + "expected an object with timestamp and raw_msg.")
            timestamp = _number(row.get("timestamp"), prefix + "timestamp")
            relative = timestamp - origin
            if relative < 0 or relative >= coverage_end:
                raise ValueError(prefix + "frame start lies outside declared [recording_start, recording_end) coverage.")
            raw = row.get("raw_msg")
            if not isinstance(raw, str) or len(raw) not in (14, 28):
                raise ValueError(prefix + "raw_msg must contain exactly 14 or 28 hexadecimal characters; an explicit adapter is needed for other formats.")
            try:
                message = bytes.fromhex(raw)
            except ValueError as error:
                raise ValueError(prefix + "raw_msg is not hexadecimal.") from error
            if len(message) * 2 != len(raw):
                raise ValueError(prefix + "raw_msg must not contain whitespace.")
            df = message[0] >> 3
            expected_length = 14 if df >= 16 else 7
            if len(message) != expected_length:
                raise ValueError(prefix + "DF bits disagree with short/long Mode S message length.")
            if "df" in row and (type(row["df"]) is not int or row["df"] != df):
                raise ValueError(prefix + "df disagrees with the raw message bits.")
            icao = message[1:4].hex().upper() if df == 17 else None
            if df == 17 and "icao" in row:
                supplied = row["icao"]
                if not isinstance(supplied, str) or supplied.upper() != icao:
                    raise ValueError(prefix + "icao disagrees with the DF17 address bits.")
            yield {
                "source_line": line_number,
                "timestamp": timestamp,
                "relative_time_s": relative,
                "df": df,
                "raw_msg": message.hex().upper(),
                "icao": icao,
                "typecode": message[4] >> 3 if df == 17 else None,
                "duration_s": 120e-6 if len(message) == 14 else 64e-6,
                "payload_bytes": len(message),
            }


def _write_json(path, value):
    with Path(path).open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")


def _write_row(handle, value):
    handle.write(json.dumps(value, separators=(",", ":"), allow_nan=False) + "\n")


def _traffic(bins, parameters, raw_digest):
    duration = parameters["coverage_duration_s"]
    bin_count = math.ceil(duration)
    time_s = [0.0] + [min(float(index), duration) for index in range(1, bin_count + 1)]
    cumulative, totals = {}, {}
    for df in sorted(bins):
        messages, payload = [0], [0]
        for index in range(bin_count):
            count, byte_count = bins[df].get(index, (0, 0))
            messages.append(messages[-1] + count)
            payload.append(payload[-1] + byte_count)
        cumulative[str(df)] = {"messages": messages, "payload_bytes": payload}
        totals[str(df)] = {"messages": messages[-1], "payload_bytes": payload[-1]}
    return {
        "schema_version": 1,
        "kind": "recorded_traffic",
        "input_sha256": raw_digest,
        "coverage_duration_s": duration,
        "target_duration_s": parameters["target_duration_s"],
        "bin_width_s": 1.0,
        "time_s": time_s,
        "cumulative_by_df": cumulative,
        "totals_by_df": totals,
        "counting_rule": "One row is one observed frame; no deduplication. Bins are [start,end); cumulative totals are shown at each bin end.",
        "payload_bytes_definition": "Encoded Mode S message bytes including parity, excluding preamble; neither JSON file size nor RF airtime.",
        "coverage_statement": "All supplied normalized Mode S observations, not proof of all real-world 1090 MHz emissions.",
    }


def prepare_recording(raw_path, output_dir, metadata, target_duration_s=3600, followup_s=600):
    """Validate and prepare immutable raw observations; publish manifest last.

    Coverage comes from explicit metadata, never the timestamp of the last
    received frame. All input frames remain in the channel trace, including
    DF17 frames in the follow-up. Only first-window DF17 frames are signed.
    """
    raw_path, output_dir = Path(raw_path), Path(output_dir)
    parameters = _parameters(metadata, target_duration_s, followup_s)
    if raw_path.resolve() in {path.resolve() for path in prepared_paths(output_dir).values()}:
        raise ValueError("Raw input must not be a preparation output path.")
    if prepared_paths(output_dir)["manifest"].exists():
        return validate_prepared_recording(raw_path, output_dir, metadata,
                                           target_duration_s, followup_s)
    raw_digest = _sha256(raw_path)
    targets, bins, total = [], {}, 0
    for row in _records(raw_path, parameters):
        total += 1
        df_bins = bins.setdefault(row["df"], {})
        index = int(row["relative_time_s"])
        count, byte_count = df_bins.get(index, (0, 0))
        df_bins[index] = (count + 1, byte_count + row["payload_bytes"])
        if row["df"] == 17 and row["relative_time_s"] < parameters["target_duration_s"]:
            targets.append({key: row[key] for key in (
                "timestamp", "relative_time_s", "icao", "raw_msg", "typecode", "source_line")})
    if not targets:
        raise ValueError("No DF17 targets occur in the selected first window.")
    targets.sort(key=lambda row: (row["relative_time_s"], row["source_line"]))
    by_source = {}
    for identifier, row in enumerate(targets, 1):
        row["trace_id"] = identifier
        by_source[row["source_line"]] = identifier
    traffic = _traffic(bins, parameters, raw_digest)
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".prepare-", dir=output_dir.parent) as temporary:
        staged = prepared_paths(temporary)
        with staged["trace"].open("w", encoding="utf-8") as handle:
            for row in targets:
                _write_row(handle, row)
        header = {
            "schema_version": 1, "kind": "channel_trace",
            "time_origin_timestamp": parameters["metadata"]["recording_start"],
            "coverage_start_s": 0.0,
            "coverage_end_s": parameters["coverage_duration_s"],
            "target_window_start_s": 0.0,
            "target_window_end_s": parameters["target_duration_s"],
            "acquisition": parameters["metadata"],
            "provenance": {"input_file": raw_path.name, "input_sha256": raw_digest,
                           "adapter": parameters["adapter"]},
        }
        with staged["channel"].open("w", encoding="utf-8") as handle:
            _write_row(handle, header)
            for row in _records(raw_path, parameters):
                event = {"event_id": f"raw-line-{row['source_line']}",
                         "source_line": row["source_line"], "df": row["df"],
                         "relative_time_s": row["relative_time_s"], "duration_s": row["duration_s"]}
                if row["source_line"] in by_source:
                    event["target_trace_id"] = by_source[row["source_line"]]
                _write_row(handle, event)
        channel = load_channel_trace(staged["channel"], targets)
        validate_coverage(channel, parameters["target_duration_s"] + parameters["followup_s"])
        if channel["summary"]["total_frames"] != total:
            raise RuntimeError("Channel preparation did not preserve all source frames.")
        _write_json(staged["traffic"], traffic)
        if _sha256(raw_path) != raw_digest:
            raise RuntimeError("Raw input changed during preparation; no outputs were published.")
        files = {key: {"path": FILENAMES[key], "sha256": _sha256(staged[key])}
                 for key in ("trace", "channel", "traffic")}
        manifest = {
            "schema_version": 1, "kind": "prepared_recording",
            "input_file": raw_path.name, "input_sha256": raw_digest,
            "output_file": FILENAMES["trace"], "output_sha256": files["trace"]["sha256"],
            "parameters": parameters, "files": files,
            "source_capture": {"total_records": total, "excluded_records": 0,
                               "deduplication": False, "totals_by_df": traffic["totals_by_df"]},
            "experimental_trace": {
                "records": len(targets), "unique_aircraft": len({row["icao"] for row in targets}),
                "start_timestamp": parameters["metadata"]["recording_start"],
                "end_timestamp": parameters["metadata"]["recording_start"] + parameters["target_duration_s"],
                "duration_seconds": parameters["target_duration_s"],
                "first_observation_s": targets[0]["relative_time_s"],
                "last_observation_s": targets[-1]["relative_time_s"],
            },
            "channel": channel["summary"],
            "validation": {"all_source_frames_retained": True, "targets_linked_exactly_once": True,
                           "declared_followup_coverage": True, "source_unchanged": True},
        }
        _write_json(staged["manifest"], manifest)
        output_dir.mkdir(parents=True, exist_ok=True)
        for key in ("trace", "channel", "traffic", "manifest"):
            os.replace(staged[key], prepared_paths(output_dir)[key])
    return manifest


def validate_prepared_recording(raw_path, output_dir, metadata, target_duration_s=3600, followup_s=600):
    """Check preparation provenance and all artifact hashes without rewriting."""
    paths = prepared_paths(output_dir)
    parameters = _parameters(metadata, target_duration_s, followup_s)
    try:
        with paths["manifest"].open("r", encoding="utf-8") as handle:
            manifest = json.load(handle)
        if not isinstance(manifest, dict):
            raise ValueError("Preparation manifest must be an object.")
        if type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1 or manifest.get("kind") != "prepared_recording":
            raise ValueError("Unsupported preparation manifest.")
        if manifest.get("parameters") != parameters:
            raise ValueError("Preparation settings or implementation changed; rerun preparation.")
        if manifest.get("input_sha256") != _sha256(raw_path):
            raise ValueError("Raw input checksum changed; rerun preparation.")
        for key in ("trace", "channel", "traffic"):
            entry = manifest["files"][key]
            if entry["path"] != FILENAMES[key] or entry["sha256"] != _sha256(paths[key]):
                raise ValueError(f"Prepared {key} checksum mismatch; rerun preparation.")
        if manifest.get("output_sha256") != manifest["files"]["trace"]["sha256"]:
            raise ValueError("Inconsistent preparation trace checksum.")
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise ValueError("Preparation is missing or invalid; run the prepare stage first.") from error
    return manifest
