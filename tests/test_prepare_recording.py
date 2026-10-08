import json
from pathlib import Path
import shutil
import tempfile
import unittest

from src.experiment.channel_trace import load_channel_trace
from src.processing.prepare_recording import (
    prepare_recording, prepared_paths, validate_prepared_recording,
)


def frame(df, address="ABCDEF"):
    length = 14 if df >= 16 else 7
    return (bytes([df << 3]) + bytes.fromhex(address) + bytes(length - 4)).hex().upper()


class PrepareRecordingTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.raw = self.directory / "recording.jsonl"
        self.output = self.directory / "prepared"
        self.metadata = {"timestamp_mode": "relative_seconds", "recording_start": 0,
                         "recording_end": 15, "source": "generated test observations"}

    def write(self, rows):
        self.raw.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    def prepare(self, rows=None, metadata=None):
        if rows is not None:
            self.write(rows)
        return prepare_recording(self.raw, self.output, self.metadata if metadata is None else metadata,
                                 target_duration_s=10, followup_s=5)

    def validate(self, metadata=None):
        return validate_prepared_recording(self.raw, self.output,
                                           self.metadata if metadata is None else metadata,
                                           target_duration_s=10, followup_s=5)

    def artifact(self, name):
        path = prepared_paths(self.output)[name]
        if path.suffix == ".jsonl":
            return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        return json.loads(path.read_text(encoding="utf-8"))

    def test_preserves_all_downlink_formats_and_repeats_and_links_only_target_window(self):
        rows = [{"timestamp": 2.0, "raw_msg": frame(df)} for df in (0, 4, 11, 17, 20, 21)]
        rows += [{"timestamp": 2.0, "raw_msg": frame(17)},
                 {"timestamp": 10.0, "raw_msg": frame(17)},
                 {"timestamp": 14.9, "raw_msg": frame(4)}]
        manifest = self.prepare(rows)
        targets, channel = self.artifact("trace"), self.artifact("channel")
        self.assertEqual([row["trace_id"] for row in targets], [1, 2])
        self.assertEqual([row["source_line"] for row in targets], [4, 7])
        self.assertEqual([row["icao"] for row in targets], ["ABCDEF", "ABCDEF"])
        self.assertEqual(len(channel) - 1, len(rows))
        self.assertEqual(sum("target_trace_id" in row for row in channel), 2)
        self.assertEqual(channel[1]["duration_s"], 64e-6)
        self.assertEqual(channel[4]["duration_s"], 120e-6)
        loaded = load_channel_trace(prepared_paths(self.output)["channel"], targets)
        self.assertEqual(loaded["summary"]["target_window_duration_s"], 10)
        self.assertEqual(loaded["summary"]["non_target_frames_within_target_window"], 5)
        self.assertIn(10.0, loaded["extra_starts"])
        self.assertEqual(manifest["source_capture"]["excluded_records"], 0)
        self.assertEqual(manifest["experimental_trace"]["duration_seconds"], 10)

    def test_traffic_cumulative_bins_include_every_df_and_count_encoded_bytes(self):
        self.prepare([{"timestamp": 0, "raw_msg": frame(0)},
                      {"timestamp": 1, "raw_msg": frame(17)},
                      {"timestamp": 1.8, "raw_msg": frame(17)},
                      {"timestamp": 14.99, "raw_msg": frame(20)}])
        traffic = self.artifact("traffic")
        self.assertEqual(traffic["time_s"], list(range(16)))
        self.assertEqual(traffic["cumulative_by_df"]["0"]["messages"][:3], [0, 1, 1])
        self.assertEqual(traffic["cumulative_by_df"]["17"]["messages"][:4], [0, 0, 2, 2])
        self.assertEqual(traffic["totals_by_df"]["0"], {"messages": 1, "payload_bytes": 7})
        self.assertEqual(traffic["totals_by_df"]["17"], {"messages": 2, "payload_bytes": 28})
        self.assertEqual(traffic["cumulative_by_df"]["20"]["messages"][-2:], [0, 1])

    def test_epoch_origin_and_stable_chronological_order(self):
        origin = 1_790_000_000.25
        metadata = {**self.metadata, "timestamp_mode": "unix_seconds",
                    "recording_start": origin, "recording_end": origin + 15}
        self.prepare([{"timestamp": origin + 8, "raw_msg": frame(17)},
                      {"timestamp": origin + 2, "raw_msg": frame(17, "000001")},
                      {"timestamp": origin + 2, "raw_msg": frame(17, "000002")}], metadata)
        trace = self.artifact("trace")
        self.assertEqual([row["relative_time_s"] for row in trace], [2, 2, 8])
        self.assertEqual([row["source_line"] for row in trace], [2, 3, 1])
        self.assertEqual(self.artifact("channel")[0]["time_origin_timestamp"], origin)
        self.validate(metadata)

    def test_exact_seventy_minute_recording_is_accepted_without_padding(self):
        metadata = {**self.metadata, "recording_end": 4200}
        self.write([{"timestamp": 0.1, "raw_msg": frame(17)},
                    {"timestamp": 3599.99999, "raw_msg": frame(17)},
                    {"timestamp": 4199.99999, "raw_msg": frame(11)}])
        manifest = prepare_recording(self.raw, self.output, metadata)
        self.assertEqual(manifest["parameters"]["coverage_duration_s"], 4200)
        self.assertEqual(manifest["experimental_trace"]["duration_seconds"], 3600)

    def test_missing_metadata_cannot_be_inferred_from_observed_frames(self):
        self.write([{"timestamp": 1, "raw_msg": frame(17)}])
        for field in ("timestamp_mode", "recording_start", "recording_end"):
            metadata = {key: value for key, value in self.metadata.items() if key != field}
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.prepare(metadata=metadata)
        self.assertFalse(self.output.exists())

    def test_incomplete_coverage_and_unknown_timestamp_modes_fail(self):
        self.write([{"timestamp": 1, "raw_msg": frame(17)}])
        variants = [{"recording_end": 14.99}, {"recording_end": float("inf")},
                    {"timestamp_mode": "milliseconds"}, {"recording_start": 100},
                    {"recording_end": True}]
        for update in variants:
            with self.subTest(update=update), self.assertRaises(ValueError):
                self.prepare(metadata={**self.metadata, **update})

    def test_unknown_or_malformed_rows_fail_instead_of_removing_interference(self):
        good = {"timestamp": 1, "raw_msg": frame(17)}
        bad_rows = [[], {"timestamp": "2", "raw_msg": frame(4)},
                    {"timestamp": True, "raw_msg": frame(4)},
                    {"timestamp": float("nan"), "raw_msg": frame(4)},
                    {"timestamp": 2, "hex": frame(4)},
                    {"timestamp": 2, "raw_msg": "0" * 13},
                    {"timestamp": 2, "raw_msg": "G" * 14},
                    {"timestamp": 2, "raw_msg": frame(17)[:14]},
                    {"timestamp": 2, "raw_msg": frame(4) + "0" * 14},
                    {"timestamp": 2, "raw_msg": frame(4), "df": 17},
                    {"timestamp": 2, "raw_msg": frame(0), "df": False},
                    {"timestamp": 2, "raw_msg": frame(17), "icao": "000001"},
                    {"timestamp": 15, "raw_msg": frame(4)},
                    {"timestamp": -0.01, "raw_msg": frame(4)}]
        for bad in bad_rows:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.prepare([good, bad])
        self.assertFalse(self.output.exists())

    def test_supplied_matching_fields_and_lowercase_hex_are_accepted(self):
        self.prepare([{"timestamp": 1, "raw_msg": frame(17).lower(), "df": 17, "icao": "abcdef"}])
        self.assertEqual(self.artifact("trace")[0]["icao"], "ABCDEF")

    def test_empty_capture_or_no_target_window_messages_fail(self):
        for rows in ([], [{"timestamp": 1, "raw_msg": frame(0)}],
                     [{"timestamp": 10, "raw_msg": frame(17)}]):
            with self.subTest(rows=rows), self.assertRaisesRegex(ValueError, "No DF17 targets"):
                self.prepare(rows)

    def test_prepared_artifacts_are_reusable_without_rewriting(self):
        manifest = self.prepare([{"timestamp": 1, "raw_msg": frame(17)}])
        paths = prepared_paths(self.output)
        stats = {key: path.stat().st_mtime_ns for key, path in paths.items()}
        self.assertEqual(self.prepare(), manifest)
        self.assertEqual(self.validate(), manifest)
        self.assertEqual({key: path.stat().st_mtime_ns for key, path in paths.items()}, stats)

    def test_changed_raw_or_settings_fail_without_overwriting_previous_outputs(self):
        self.prepare([{"timestamp": 1, "raw_msg": frame(17)}])
        previous = prepared_paths(self.output)["manifest"].read_bytes()
        with self.assertRaisesRegex(ValueError, "settings"):
            self.validate({**self.metadata, "source": "changed source"})
        self.write([{"timestamp": 2, "raw_msg": frame(17)}])
        with self.assertRaisesRegex(ValueError, "Raw input checksum changed"):
            self.prepare()
        self.assertEqual(prepared_paths(self.output)["manifest"].read_bytes(), previous)

    def test_changed_output_is_detected(self):
        self.prepare([{"timestamp": 1, "raw_msg": frame(17)}])
        with prepared_paths(self.output)["channel"].open("a", encoding="utf-8") as handle:
            handle.write("\n")
        with self.assertRaisesRegex(ValueError, "channel checksum mismatch"):
            self.validate()

    def test_portable_validation_after_moving_checkout(self):
        self.prepare([{"timestamp": 1, "raw_msg": frame(17)}])
        moved = self.directory / "other-checkout"
        shutil.copytree(self.output, moved)
        new_raw = self.directory / "renamed-recording.jsonl"
        shutil.copyfile(self.raw, new_raw)
        result = validate_prepared_recording(new_raw, moved, self.metadata, 10, 5)
        self.assertEqual(result["files"]["trace"]["path"], "trace.jsonl")

    def test_validate_requires_preparation_and_catches_inconsistent_manifest(self):
        self.write([{"timestamp": 1, "raw_msg": frame(17)}])
        with self.assertRaisesRegex(ValueError, "run the prepare stage"):
            self.validate()
        self.prepare()
        manifest = self.artifact("manifest")
        manifest["output_sha256"] = "different"
        prepared_paths(self.output)["manifest"].write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Inconsistent"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
