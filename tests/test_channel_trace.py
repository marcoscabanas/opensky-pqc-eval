import json
from pathlib import Path
import tempfile
import unittest

from src.experiment.channel_trace import FRAME_S, load_channel_trace, replay_window, validate_coverage


class ChannelTraceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "channel.jsonl"
        self.origin = 1790258578.187745
        self.trace = [
            {"trace_id": 1, "timestamp": self.origin, "relative_time_s": 0.0},
            {"trace_id": 2, "timestamp": self.origin + 1.0, "relative_time_s": 1.0},
        ]
        self.header = {"schema_version": 1, "kind": "channel_trace",
                       "time_origin_timestamp": self.origin, "coverage_start_s": 0,
                       "coverage_end_s": 61.01}
        self.events = [
            {"event_id": "target-1", "relative_time_s": 0, "duration_s": FRAME_S,
             "target_trace_id": 1},
            {"event_id": "target-2", "relative_time_s": 1, "duration_s": FRAME_S,
             "target_trace_id": 2},
        ]

    def load(self, *, events=None, header=None, trace=None):
        records = [self.header if header is None else header]
        records.extend(self.events if events is None else events)
        self.path.write_text("\n".join(json.dumps(row) for row in records) + "\n", encoding="utf-8")
        return load_channel_trace(self.path, self.trace if trace is None else trace)

    def test_mixed_observed_traffic_is_retained_without_decode_or_aircraft_fields(self):
        events = [
            {"event_id": 7, "relative_time_s": 2.0, "duration_s": 20.3e-6},
            *self.events,
            {"event_id": 8, "relative_time_s": 0.4, "duration_s": 64e-6, "raw_msg": "repeated"},
            {"event_id": 9, "relative_time_s": 0.4, "duration_s": 64e-6, "raw_msg": "repeated"},
            {"event_id": "7", "relative_time_s": 1.0, "duration_s": 120e-6},
        ]
        header = {**self.header, "acquisition": {"receiver": "example"}, "provenance": ["capture"]}
        result = self.load(events=events, header=header)
        self.assertEqual(result["extra_starts"], [2.0, 0.4, 0.4, 1.0])
        self.assertEqual(result["extra_durations_s"], [20.3e-6, 64e-6, 64e-6, 120e-6])
        summary = result["summary"]
        self.assertEqual((summary["total_frames"], summary["target_frames"], summary["non_target_frames"]), (6, 2, 4))
        self.assertEqual(summary["non_target_frames_within_target_window"], 3)
        self.assertAlmostEqual(summary["target_offered_airtime_s"], 240e-6)
        self.assertAlmostEqual(summary["non_target_offered_airtime_s"], 268.3e-6)
        self.assertAlmostEqual(summary["total_offered_airtime_within_target_window_s"], 488e-6)
        self.assertAlmostEqual(summary["total_offered_load"], 508.3e-6 / 61.01)
        self.assertAlmostEqual(summary["total_offered_load_within_target_window"], 488e-6)
        self.assertEqual(summary["acquisition"], header["acquisition"])
        self.assertEqual(summary["provenance"], header["provenance"])

    def test_duplicate_missing_unknown_or_multiply_referenced_targets_fail(self):
        variants = [
            (self.events + [self.events[0]], "Duplicate channel event_id"),
            (self.events[:1], "missing 1 target"),
            ([self.events[0], {**self.events[1], "target_trace_id": 3}], "Unknown target_trace_id"),
            (self.events + [{**self.events[0], "event_id": "another"}], "Duplicate target_trace_id"),
        ]
        for events, message in variants:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                self.load(events=events)

    def test_target_event_alignment_duration_and_clock_origin_are_checked(self):
        for update, message in [({"relative_time_s": 0.01}, "event time"),
                                ({"duration_s": 64e-6}, "duration_s")]:
            with self.subTest(update=update), self.assertRaisesRegex(ValueError, message):
                self.load(events=[{**self.events[0], **update}, self.events[1]])
        with self.assertRaisesRegex(ValueError, "time origin"):
            self.load(header={**self.header, "time_origin_timestamp": self.origin + 0.001})
        with self.assertRaisesRegex(ValueError, "time origin"):
            self.load(trace=[self.trace[0], {**self.trace[1], "timestamp": self.origin + 1.001}])

    def test_epoch_float_rounding_does_not_invalidate_matching_relative_times(self):
        trace = [self.trace[0], {"trace_id": 2, "timestamp": self.origin + 0.123456789,
                                "relative_time_s": 0.123456789}]
        events = [self.events[0], {**self.events[1], "relative_time_s": 0.123456789}]
        result = self.load(events=events, trace={row["trace_id"]: row for row in trace})
        self.assertEqual(result["summary"]["target_frames"], 2)

    def test_recording_coverage_is_not_inferred_from_last_event_and_must_cover_followup(self):
        result = self.load()
        validate_coverage(result, 61.00012)
        self.assertEqual(result["coverage_end_s"], 61.01)
        with self.assertRaisesRegex(ValueError, "including authentication follow-up"):
            validate_coverage(result, 62.0)
        with self.assertRaisesRegex(ValueError, "before the target trace"):
            self.load(header={**self.header, "coverage_end_s": 0.9})
        with self.assertRaisesRegex(ValueError, "outside declared recording coverage"):
            self.load(events=self.events + [{"event_id": "late", "relative_time_s": 61.02, "duration_s": 1e-5}])

    def test_accounting_counts_full_envelope_at_recording_end(self):
        extra = {"event_id": "last", "relative_time_s": 61.01, "duration_s": 120e-6}
        result = self.load(events=self.events + [extra])
        self.assertAlmostEqual(result["summary"]["non_target_offered_airtime_s"], 120e-6)
        self.assertEqual(result["summary"]["non_target_offered_airtime_within_target_window_s"], 0)

    def test_declared_target_window_accounts_for_quiet_edges_and_is_half_open(self):
        trace = [{**row, "relative_time_s": row["relative_time_s"] + 2,
                  "timestamp": row["timestamp"] + 2} for row in self.trace]
        events = [{**row, "relative_time_s": row["relative_time_s"] + 2} for row in self.events]
        events += [{"event_id": "before-first-target", "relative_time_s": 0.5, "duration_s": 64e-6},
                   {"event_id": "after-last-target", "relative_time_s": 9.5, "duration_s": 64e-6},
                   {"event_id": "followup-start", "relative_time_s": 10, "duration_s": 64e-6}]
        result = self.load(trace=trace, events=events,
                           header={**self.header, "target_window_start_s": 0, "target_window_end_s": 10})
        summary = result["summary"]
        self.assertTrue(summary["target_window_declared"])
        self.assertEqual(summary["target_window_duration_s"], 10)
        self.assertEqual(summary["non_target_frames_within_target_window"], 2)
        self.assertAlmostEqual(summary["total_offered_load_within_target_window"], (240e-6 + 128e-6) / 10)

    def test_invalid_declared_target_windows_fail(self):
        for updates in ({"target_window_start_s": 0},
                        {"target_window_end_s": 2},
                        {"target_window_start_s": 0, "target_window_end_s": 0},
                        {"target_window_start_s": 0.1, "target_window_end_s": 2},
                        {"target_window_start_s": 0, "target_window_end_s": 1},
                        {"target_window_start_s": 0, "target_window_end_s": 62}):
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                self.load(header={**self.header, **updates})

    def test_replay_window_preserves_legacy_and_uses_fixed_declared_cutoff(self):
        self.assertEqual(replay_window(self.trace, None, 60), (0, 1, 61 + FRAME_S))
        channel = self.load(header={**self.header, "target_window_start_s": 0,
                                    "target_window_end_s": 10})
        self.assertEqual(replay_window(self.trace, channel, 5, 2000), (0, 10, 15))
        validate_coverage(channel, replay_window(self.trace, channel, 5)[2])
        self.assertAlmostEqual(replay_window(self.trace, None, 60, 2000)[2], 63 + FRAME_S)

    def test_replay_window_rejects_invalid_durations_and_targets_outside_window(self):
        channel = {"summary": {"target_window_declared": True,
                               "target_window_start_s": 0, "target_window_end_s": 1}}
        with self.assertRaisesRegex(ValueError, "half-open"):
            replay_window(self.trace, channel, 5)
        for followup in (-1, True, float("nan")):
            with self.subTest(followup=followup), self.assertRaises(ValueError):
                replay_window(self.trace, None, followup)

    def test_invalid_header_event_numbers_and_identifiers_fail(self):
        headers = [{**self.header, key: value} for key, value in [
            ("schema_version", True), ("schema_version", 2), ("kind", "other"),
            ("time_origin_timestamp", float("nan")), ("coverage_start_s", 0.1),
            ("coverage_start_s", True), ("coverage_end_s", float("inf")),
        ]]
        for header in headers:
            with self.subTest(header=header), self.assertRaises(ValueError):
                self.load(header=header)
        updates = [
            {"event_id": True}, {"event_id": []}, {"event_id": ""},
            {"relative_time_s": True}, {"relative_time_s": -1},
            {"relative_time_s": float("nan")}, {"duration_s": False},
            {"duration_s": 0}, {"duration_s": -1}, {"duration_s": float("inf")},
            {"target_trace_id": True}, {"target_trace_id": 1.0}, {"target_trace_id": None},
        ]
        for update in updates:
            with self.subTest(update=update), self.assertRaises(ValueError):
                self.load(events=[{**self.events[0], **update}, self.events[1]])
        for horizon in (True, -1, float("nan")):
            with self.subTest(horizon=horizon), self.assertRaises(ValueError):
                validate_coverage({"coverage_end_s": 61.01}, horizon)

    def test_invalid_target_trace_and_empty_or_malformed_files_fail(self):
        for trace in ([], self.trace + [self.trace[0]],
                      [{**self.trace[0], "trace_id": True}],
                      [{**self.trace[0], "timestamp": None}]):
            with self.subTest(trace=trace), self.assertRaises(ValueError):
                self.load(trace=trace)
        for contents in ("", "not json\n", "[]\n"):
            self.path.write_text(contents, encoding="utf-8")
            with self.subTest(contents=contents), self.assertRaises(ValueError):
                load_channel_trace(self.path, self.trace)


if __name__ == "__main__":
    unittest.main()
