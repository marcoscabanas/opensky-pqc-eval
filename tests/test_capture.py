"""Acquisition tests use fake sockets and clocks; no receiver is contacted."""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "raw_capture", Path(__file__).resolve().parents[1] / "scripts" / "00_capture.py")
recorder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recorder)


class FakeClock:
    now = 0.0

    def monotonic(self):
        return self.now


class FakeSocket:
    def __init__(self, clock, events):
        self.clock = clock
        self.events = iter(events)
        self.timeouts = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def settimeout(self, seconds):
        self.timeouts.append(seconds)

    def recv(self, size):
        delay, result = next(self.events)
        self.clock.now += delay
        if isinstance(result, BaseException):
            raise result
        return result


class CaptureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.output = Path(temporary.name) / "daytime.beast"
        self.sidecar = self.output.with_suffix(".beast.json")

    def run_capture(self, events, *, duration_s=2):
        clock = FakeClock()
        stream = FakeSocket(clock, events)
        with patch.object(recorder.socket, "create_connection", return_value=stream) as connect, \
                patch.object(recorder.time, "monotonic", side_effect=clock.monotonic), \
                patch.object(recorder, "_utc_now", return_value="2026-10-12T09:30:00+00:00"), \
                patch.object(recorder.os, "fsync", wraps=recorder.os.fsync) as fsync:
            info = recorder.capture(self.output, duration_s=duration_s)
        connect.assert_called_once_with(("airsquitter.lr.tudelft.nl", 10004), timeout=10)
        self.assertEqual(fsync.call_count, 2)
        self.assertTrue(stream.closed)
        self.assertEqual(json.loads(self.sidecar.read_text()), info)
        saved = self.output.read_bytes()
        self.assertEqual(info["byte_count"], len(saved))
        self.assertEqual(info["sha256"], hashlib.sha256(saved).hexdigest())
        return info, stream

    def test_raw_bytes_preserved_across_tcp_chunks_until_monotonic_deadline(self):
        # Include an escape split across chunks and a Mode A/C-like prefix. The
        # recorder must not parse, filter, unescape or reconstruct either one.
        blocks = [b"\x1a\x31\x00\xff\x1a", b"\x1a\x32\xfe\x00\n"]
        info, stream = self.run_capture([(0.25, blocks[0]), (0.75, blocks[1]),
                                        (1.0, socket.timeout())])
        self.assertEqual(self.output.read_bytes(), b"".join(blocks))
        self.assertTrue(info["complete"])
        self.assertTrue(info["network_duration_completed"])
        self.assertEqual(info["network_elapsed_s"], 2)
        self.assertIn("NOT radio reception timestamps", info["host_clock_note"])
        self.assertIn("not verified", info["raw_format_assumption"])
        self.assertEqual(stream.timeouts, [1.0, 1.0, 1.0])

    def test_remote_eof_keeps_partial_capture_incomplete(self):
        info, _ = self.run_capture([(0.25, b"first bytes"), (0.25, b"")])
        self.assertFalse(info["complete"])
        self.assertFalse(info["network_duration_completed"])
        self.assertEqual(info["stop_reason"], "remote_eof")
        self.assertEqual(self.output.read_bytes(), b"first bytes")

    def test_interruption_saves_partial_recording_and_metadata(self):
        info, _ = self.run_capture([(0.25, b"partial"), (0.25, KeyboardInterrupt())])
        self.assertFalse(info["complete"])
        self.assertEqual(info["stop_reason"], "interrupted")
        self.assertEqual(self.output.read_bytes(), b"partial")

    def test_receive_error_saves_partial_recording_and_error(self):
        info, _ = self.run_capture([(0.25, b"partial"), (0.25, ConnectionResetError("connection reset"))])
        self.assertFalse(info["complete"])
        self.assertEqual(info["stop_reason"], "io_error")
        self.assertIn("ConnectionResetError", info["error"])

    def test_full_duration_without_bytes_is_not_a_complete_capture(self):
        info, _ = self.run_capture([(1.0, socket.timeout()), (1.0, socket.timeout())])
        self.assertFalse(info["complete"])
        self.assertTrue(info["network_duration_completed"])
        self.assertEqual(info["stop_reason"], "no_bytes_received")

    def test_connection_failure_saves_empty_incomplete_recording(self):
        with patch.object(recorder.socket, "create_connection", side_effect=OSError("unreachable")):
            info = recorder.capture(self.output)
        self.assertFalse(info["complete"])
        self.assertIsNone(info["network_elapsed_s"])
        self.assertIsNone(info["host_clock_connected_utc"])
        self.assertEqual(info["byte_count"], 0)
        self.assertEqual(info["sha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(json.loads(self.sidecar.read_text()), info)

    def test_neither_file_is_overwritten_and_no_connection_is_attempted(self):
        for existing in (self.output, self.sidecar):
            with self.subTest(existing=existing.name):
                existing.write_bytes(b"preserve this")
                with patch.object(recorder.socket, "create_connection") as connect:
                    with self.assertRaises(FileExistsError):
                        recorder.capture(self.output)
                    connect.assert_not_called()
                self.assertEqual(existing.read_bytes(), b"preserve this")
                other = self.sidecar if existing == self.output else self.output
                self.assertFalse(other.exists())
                existing.unlink()

    def test_dangling_symlinks_are_rejected_before_connecting(self):
        for existing in (self.output, self.sidecar):
            with self.subTest(existing=existing.name):
                existing.symlink_to(existing.parent / "missing")
                with patch.object(recorder.socket, "create_connection") as connect:
                    with self.assertRaises(FileExistsError):
                        recorder.capture(self.output)
                    connect.assert_not_called()
                self.assertTrue(existing.is_symlink())
                existing.unlink()

    def test_invalid_arguments_create_no_files_and_never_connect(self):
        for args in ({"duration_s": 0}, {"duration_s": float("nan")}, {"duration_s": float("inf")},
                     {"duration_s": True}, {"port": 0}, {"port": 65536}, {"port": True}, {"host": " "}):
            with self.subTest(args=args), patch.object(recorder.socket, "create_connection") as connect:
                with self.assertRaises(ValueError):
                    recorder.capture(self.output, **args)
                connect.assert_not_called()
                self.assertFalse(self.output.exists())
                self.assertFalse(self.sidecar.exists())

    def test_cli_defaults_and_exit_status_do_not_claim_incomplete_capture_succeeded(self):
        with contextlib.redirect_stdout(io.StringIO()), patch.object(recorder, "capture", return_value={
                "complete": False, "byte_count": 0, "stop_reason": "remote_eof"}) as capture:
            result = recorder.main(["--output", str(self.output)])
        self.assertEqual(result, 1)
        capture.assert_called_once_with(self.output, host="airsquitter.lr.tudelft.nl", port=10004,
                                        duration_s=4260)


if __name__ == "__main__":
    unittest.main()
