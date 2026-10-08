"""Scheduling tests use explicitly fake signatures; integration uses real ECDSA."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np

from src.experiment import signed_replay
from src.experiment.model_support import FRAME_S, form_groups
from src.experiment.replay_transport import Envelope, make_envelope
from tests.fixtures import ALGORITHM, profile_fixture, trace_fixture


class FakeSigner:
    def public_key_bytes(self):
        return b"fake-test-key"

    def sign(self, message):
        return hashlib.sha512(self.public_key_bytes() + message).digest()


class FakeVerifier:
    calls = 0

    def __call__(self, message, signature):
        type(self).calls += 1
        return signature == FakeSigner().sign(message)

    def close(self):
        pass


def workload_fixture(records, interval=1, max_wait=None):
    groups, _ = form_groups(records, interval, max_wait)
    result, covered = [], set()
    for icao, seq, entries, formed in groups:
        members = tuple(record["trace_id"] for record in entries)
        envelope = make_envelope(icao, seq, b"testsess",
                                 [(r["relative_time_s"], bytes.fromhex(r["raw_msg"])) for r in entries],
                                 ALGORITHM, FakeSigner())
        result.append({"descriptor": envelope.descriptor, "envelope": envelope,
                       "members": members, "formed_s": formed,
                       "public_key": FakeSigner().public_key_bytes()})
        covered.update(members)
    return {"groups": result,
            "unsigned_trace_ids": [record["trace_id"] for record in records if record["trace_id"] not in covered],
            "evidence": {"test_only_fake_signature": True}}


def replay(records=None, interval=1, profile=None, workload=None, channel_trace=None,
           replay_model="signed_before_send", seed=1, **options):
    records = records if records is not None else trace_fixture()
    profile = profile or profile_fixture()
    scenario = {"followup_s": 2, "coverage_thresholds_s": [1, 5],
                "auth_frames_per_second": 8000, "channel_mode": "independent",
                "loss": {"kind": "iid", "probability": 0}, "record_events": True, **options}
    workload = workload if workload is not None else workload_fixture(records, interval, scenario.get("max_batch_wait_s"))
    with patch.object(signed_replay, "verifier_for", side_effect=lambda *_: FakeVerifier()):
        return signed_replay.simulate(records, ALGORITHM, interval, workload, profile, profile,
                                      scenario, seed=seed, channel_trace=channel_trace, replay_model=replay_model)


class SignedReplayTest(unittest.TestCase):
    def test_receiver_retention_shortcut_matches_general_receiver_with_expiry(self):
        fast = signed_replay._ReplayReceiver(1, 0.1)
        reference = signed_replay.ReplayReceiver(1, 0.1)
        records = trace_fixture(count=4)
        for timestamp in (0, 0.5, 1.1, 1.100001, 2.5, 0.3):
            for record in records:
                raw = bytes.fromhex(record["raw_msg"])
                fast.observe_message(raw, timestamp)
                reference.observe_message(raw, timestamp)
                self.assertEqual(fast.observations, reference.observations)
        for raw, timestamp in ((b"short", 0), (bytes.fromhex(records[0]["raw_msg"]), -1),
                               (bytes.fromhex(records[0]["raw_msg"]), float("nan"))):
            for receiver in (fast, reference):
                with self.assertRaises(ValueError):
                    receiver.observe_message(raw, timestamp)

    def test_receiver_retention_shortcut_preserves_full_replay_outputs(self):
        for mode in ("signed_before_send", "signed_detached"):
            for collision in ("independent", "destructive_overlap"):
                options = {"replay_model": mode, "channel_mode": collision,
                           "receive_jitter_ms": 0.2, "fragment_copies": 2}
                actual = replay(**options)
                with patch.object(signed_replay, "_ReplayReceiver", signed_replay.ReplayReceiver):
                    expected = replay(**options)
                self.assertEqual(actual, expected)

    def test_compact_radio_runs_expand_exactly_and_preserve_group_offsets(self):
        groups = [signed_replay.Group({}, (), 0) for _ in range(3)]
        groups[0].chunks = [(0.1, 7, 0.00012), (0.5, 4, 0.01)]
        groups[0].sent = 11
        groups[2].chunks = [(0.2, 3, 0.1)]
        groups[2].sent = 3
        expected = np.concatenate([first + np.arange(count, dtype=float) * step
                                   for group in groups for first, count, step in group.chunks])
        with tempfile.TemporaryDirectory() as scratch, patch.object(signed_replay, "_MEMMAP_THRESHOLD", 1), \
                patch.object(signed_replay, "_ARRAY_CHUNK", 2):
            actual, offsets = signed_replay._flatten_radio(groups, 14, scratch)
            self.assertIsInstance(actual, np.memmap)
            np.testing.assert_array_equal(actual, expected)
            np.testing.assert_array_equal(offsets, [0, 11, 14])
            self.assertEqual([group.offset for group in groups], [0, 11, 11])
            self.assertTrue(all(not group.chunks for group in groups))
            del actual

    def test_disk_backed_schedule_matches_memory_for_jitter_and_fragment_copies(self):
        for jitter in (0, 0.2):
            options = {"receive_jitter_ms": jitter, "fragment_copies": 2,
                       "loss": {"kind": "iid", "probability": 0.1}}
            expected = replay(**options)
            with patch.object(signed_replay, "_MEMMAP_THRESHOLD", 1), \
                    patch.object(signed_replay, "_ARRAY_CHUNK", 3):
                actual = replay(**options)
            self.assertEqual(actual, expected)

    def test_declared_window_accounts_for_quiet_edges_and_boundary_followup(self):
        records = trace_fixture(count=2, spacing=6, aircraft=("ABCDEF",))
        for row in records:
            row["relative_time_s"] += 2
        channel = {"extra_starts": [0.5, 9.5, 10, 11.9],
                   "extra_durations_s": [FRAME_S] * 4, "coverage_end_s": 12,
                   "summary": {"target_window_declared": True,
                               "target_window_start_s": 0, "target_window_end_s": 10}}
        result = replay(records, interval=2, profile=profile_fixture(sign_ms=2000),
                        replay_model="signed_detached", channel_trace=channel, followup_s=2)
        summary = result["summary"]
        self.assertEqual(summary["capture_start_s"], 0)
        self.assertEqual(summary["capture_end_s"], 10)
        self.assertEqual(summary["trace_duration_s"], 10)
        self.assertEqual(summary["capture_duration_s"], 10)
        self.assertEqual(summary["followup_after_capture_s"], 2)
        self.assertEqual(summary["observation_horizon_s"], 12)
        self.assertEqual(result["events"][0]["auth_tx_start_s"], 10)
        self.assertEqual(summary["additional_offered_airtime_load"], 0)
        self.assertEqual(summary["auth_frames_after_observation"], summary["auth_frames_transmitted"])
        self.assertAlmostEqual(summary["non_target_offered_airtime_load"], 2 * FRAME_S / 10)
        self.assertAlmostEqual(summary["non_target_airtime_seconds_followup"], 2 * FRAME_S)
        self.assertAlmostEqual(summary["target_offered_airtime_load"], 2 * FRAME_S / 10)
        self.assertEqual(summary["backlog_samples"][0]["time_s"], 0)
        self.assertIn("declared_window_end_plus_followup", summary["horizon_policy"])

    def test_seventy_minute_cutoff_keeps_partial_authentication_frame_pending(self):
        records = trace_fixture(count=1, aircraft=("ABCDEF",))
        records[0]["relative_time_s"] = 3599.99999
        channel = {"extra_starts": [], "extra_durations_s": [], "coverage_end_s": 4200,
                   "summary": {"target_window_declared": True,
                               "target_window_start_s": 0, "target_window_end_s": 3600}}
        sign_ms = (4200 - records[0]["relative_time_s"] - FRAME_S / 2) * 1000
        FakeVerifier.calls = 0
        result = replay(records, profile=profile_fixture(sign_ms=sign_ms),
                        replay_model="signed_detached", channel_trace=channel,
                        followup_s=600, coverage_thresholds_s=[600])
        summary = result["summary"]
        self.assertEqual(summary["observation_horizon_s"], 4200)
        self.assertEqual(summary["augmented_original_received_messages"], 1)
        self.assertEqual(summary["auth_frames_transmitted"], 1)
        self.assertEqual(summary["auth_frames_received"], 0)
        self.assertEqual(summary["auth_frames_lost"], 0)
        self.assertEqual(summary["auth_frames_in_flight_at_horizon"], 1)
        self.assertEqual(summary["unresolved_messages"], 1)
        self.assertEqual(summary["definitive_failure_messages"], 0)
        self.assertEqual(FakeVerifier.calls, 0)
        coverage = summary["threshold_coverage"][0]
        self.assertEqual(coverage["source_eligible_messages"], 1)
        self.assertEqual(coverage["receipt_eligible_messages"], 0)
        self.assertTrue(result["events"][0]["outcome"].startswith("pending"))

    def test_declared_window_does_not_extend_cutoff_for_jitter_or_partial_ordinary_frame(self):
        records = trace_fixture(count=1, aircraft=("ABCDEF",))
        records[0]["relative_time_s"] = 9.99999
        channel = {"extra_starts": [], "extra_durations_s": [], "coverage_end_s": 10,
                   "summary": {"target_window_declared": True,
                               "target_window_start_s": 0, "target_window_end_s": 10}}
        result = replay(records, profile=profile_fixture(sign_ms=1000), replay_model="signed_detached",
                        channel_trace=channel, followup_s=0, receive_jitter_ms=100,
                        coverage_thresholds_s=[1])
        summary = result["summary"]
        self.assertEqual(summary["observation_horizon_s"], 10)
        self.assertEqual(summary["ordinary_frames_in_flight_at_horizon"], 1)
        self.assertEqual(summary["ordinary_frames_rf_lost"], 0)
        self.assertEqual(summary["augmented_original_received_messages"], 0)
        self.assertEqual(summary["ordinary_airtime_seconds_followup"], 0)
        self.assertEqual(summary["unresolved_messages"], 1)

    def test_detached_group_transmits_before_collection_and_signing_complete(self):
        records = trace_fixture(count=20, spacing=0.5, aircraft=("ABCDEF",))
        result = replay(records, interval=20, profile=profile_fixture(sign_ms=200),
                        replay_model="signed_detached")
        summary, event = result["summary"], result["events"][0]
        self.assertEqual(summary["replay_model"], "signed_detached")
        self.assertEqual(event["formed_s"], 9.5)
        self.assertEqual(event["sign_end_s"], 9.7)
        self.assertEqual(event["ordinary_transmission_starts_s"], [r["relative_time_s"] for r in records])
        self.assertEqual(event["auth_tx_start_s"], event["sign_end_s"])
        self.assertEqual(summary["ordinary_transmission_delay_ms_mean"], 0)
        self.assertEqual(summary["ordinary_radio_queue_ms_mean"], 0)
        self.assertEqual(summary["authenticated_messages"], 20)
        self.assertGreater(summary["receipt_to_auth_ms_mean"], 4000)

    def test_detached_signer_overload_does_not_hold_ordinary_messages(self):
        records = trace_fixture(count=2, spacing=1, aircraft=("ABCDEF",))
        result = replay(records, profile=profile_fixture(sign_ms=10000), followup_s=1,
                        replay_model="signed_detached")
        summary = result["summary"]
        self.assertEqual(summary["ordinary_frames_transmitted"], 2)
        self.assertEqual(summary["augmented_original_received_messages"], 2)
        self.assertEqual(summary["ordinary_messages_unsent_pending"], 0)
        self.assertEqual(summary["ordinary_transmission_delay_ms_max"], 0)
        self.assertEqual(summary["received_unresolved_messages"], 2)
        self.assertEqual(result["outcomes"], {"pending_signing": 1, "pending_sender_queue": 1})
        self.assertTrue(all(row["ordinary_waiting_messages"] == 0 for row in summary["backlog_samples"]))

    def test_detached_unsigned_tails_transmit_even_when_no_group_completes(self):
        records = trace_fixture(count=3, spacing=0.2, aircraft=("ABCDEF",))
        for interval, authenticated in ((2, 2), (20, 0)):
            with self.subTest(interval=interval):
                summary = replay(records, interval=interval, replay_model="signed_detached")["summary"]
                self.assertEqual(summary["ordinary_frames_transmitted"], 3)
                self.assertEqual(summary["augmented_original_received_messages"], 3)
                self.assertEqual(summary["ordinary_messages_withheld_definitively"], 0)
                self.assertEqual(summary["unsigned_tail_messages"], 3 - authenticated)
                self.assertEqual(summary["received_definitive_failure_messages"], 3 - authenticated)
                self.assertEqual(summary["authenticated_messages"], authenticated)

    def test_detached_sender_queue_overflow_does_not_drop_ordinary_messages(self):
        records = trace_fixture(count=4, spacing=1, aircraft=("ABCDEF",))
        summary = replay(records, profile=profile_fixture(sign_ms=10000), sender_queue_limit=1,
                         followup_s=1, replay_model="signed_detached")["summary"]
        self.assertEqual(summary["ordinary_frames_transmitted"], 4)
        self.assertEqual(summary["augmented_original_received_messages"], 4)
        self.assertEqual(summary["ordinary_messages_withheld_definitively"], 0)
        self.assertEqual(summary["message_outcomes"], {"pending_sender_queue": 1, "pending_signing": 1,
                                                      "sender_queue_overflow": 2})

    def test_detached_authentication_queue_overflow_does_not_drop_originals(self):
        records = trace_fixture(count=3, spacing=0.1, aircraft=("ABCDEF",))
        summary = replay(records, transmission_queue_limit=1, auth_frames_per_second=1,
                         replay_model="signed_detached")["summary"]
        self.assertEqual(summary["ordinary_frames_transmitted"], 3)
        self.assertEqual(summary["augmented_original_received_messages"], 3)
        self.assertEqual(summary["message_outcomes"], {"pending_transmission": 1,
                                                      "transmission_queue_overflow": 2})

    def test_detached_ordinary_waits_only_for_current_authentication_frame(self):
        records = trace_fixture(count=2, spacing=0.00018, aircraft=("ABCDEF",))
        result = replay(records, profile=profile_fixture(sign_ms=0.1),
                        auth_frames_per_second=1000, replay_model="signed_detached")
        self.assertAlmostEqual(result["events"][0]["auth_tx_start_s"], FRAME_S)
        self.assertAlmostEqual(result["events"][1]["ordinary_transmission_starts_s"][0], 2 * FRAME_S)
        self.assertAlmostEqual(result["summary"]["ordinary_transmission_delay_ms_max"], 0.06)
        self.assertAlmostEqual(result["summary"]["authentication_added_ordinary_delay_ms_max"], 0.06)
        self.assertEqual(result["summary"]["baseline_ordinary_radio_queue_ms_max"], 0)
        self.assertEqual(result["summary"]["authentication_added_ordinary_delay_positive_messages"], 1)

    def test_detached_source_time_ties_have_baseline_queue_but_no_authentication_added_delay(self):
        records = trace_fixture(count=4, spacing=0, aircraft=("ABCDEF",))
        records[-1]["relative_time_s"] = 0.1
        summary = replay(records, profile=profile_fixture(sign_ms=10000), followup_s=1,
                         replay_model="signed_detached")["summary"]
        self.assertAlmostEqual(summary["ordinary_transmission_delay_ms_max"], 0.24)
        self.assertAlmostEqual(summary["baseline_ordinary_radio_queue_ms_max"], 0.24)
        self.assertEqual(summary["authentication_added_ordinary_delay_ms_max"], 0)
        self.assertEqual(summary["authentication_added_ordinary_delay_positive_messages"], 0)
        self.assertEqual(summary["ordinary_delay_control_cohort_messages"], 4)

    def test_detached_no_authentication_radio_control_keeps_aircraft_independent(self):
        records = trace_fixture(count=2, spacing=0, aircraft=("ABCDEF", "ABC001"))
        summary = replay(records, profile=profile_fixture(sign_ms=10000), followup_s=1,
                         replay_model="signed_detached")["summary"]
        self.assertAlmostEqual(summary["baseline_ordinary_radio_queue_ms_max"], 0.12)
        self.assertEqual(summary["authentication_added_ordinary_delay_ms_max"], 0)

    def test_detached_finite_queue_counts_object_during_its_last_frame(self):
        records = trace_fixture(count=2, spacing=0.005425, aircraft=("ABCDEF",))
        result = replay(records, profile=profile_fixture(sign_ms=1), transmission_queue_limit=1,
                        replay_model="signed_detached")
        first, second = result["events"]
        self.assertGreater(second["sign_end_s"], first["auth_tx_end_s"] - FRAME_S)
        self.assertLess(second["sign_end_s"], first["auth_tx_end_s"])
        self.assertEqual(second["work_state"], "transmission_queue_overflow")
        self.assertEqual(result["summary"]["augmented_original_received_messages"], 2)

    def test_detached_ready_ordinary_frames_have_priority_over_authentication(self):
        # Frame 2 arrives during an auth frame; frame 3 arrives while frame 2
        # transmits. Both originals must finish before any further fragment.
        records = trace_fixture(count=3, spacing=0.00015, aircraft=("ABCDEF",))
        result = replay(records, replay_model="signed_detached")
        starts = [event["ordinary_transmission_starts_s"][0] for event in result["events"]]
        np.testing.assert_allclose(starts, [0, 2 * FRAME_S, 3 * FRAME_S], atol=1e-15)
        # A signing completion simultaneous with an original arrival also
        # gives the ordinary frame priority.
        simultaneous = replay(trace_fixture(count=2, spacing=0.001, aircraft=("ABCDEF",)),
                              profile=profile_fixture(sign_ms=1), replay_model="signed_detached")
        self.assertAlmostEqual(simultaneous["events"][0]["auth_tx_start_s"], 0.001 + FRAME_S)

    def test_detached_deterministic_scenarios_do_not_depend_on_random_seed(self):
        results = [replay(replay_model="signed_detached", seed=seed) for seed in (1, 7)]
        for result in results:
            result["summary"].pop("seed")
            result["summary"]["channel_summary"].pop("seed")
        self.assertEqual(*results)

    def test_detached_association_bound_covers_bursts_and_is_independent_of_signing(self):
        records = trace_fixture(count=12, spacing=0.00001, aircraft=("ABCDEF",))
        bounds = []
        for sign_ms, rate, interval in ((0.1, 8000, 1), (1000, 1, 2)):
            result = replay(records, profile=profile_fixture(sign_ms=sign_ms),
                            auth_frames_per_second=rate, interval=interval,
                            replay_model="signed_detached")
            tolerance = result["summary"]["receiver_association_tolerance_s"]
            bounds.append(tolerance)
            self.assertGreater(tolerance, 2 * FRAME_S)
            for event in result["events"]:
                first = (event["group_sequence"] - 1) * interval
                for offset, transmitted in enumerate(event["ordinary_transmission_starts_s"]):
                    self.assertLessEqual(transmitted + FRAME_S - records[first + offset]["relative_time_s"],
                                         tolerance)
        self.assertEqual(*bounds)
        sparse = trace_fixture(count=3, spacing=0.2, aircraft=("ABCDEF",))
        self.assertAlmostEqual(signed_replay._detached_association_tolerance(sparse, 0),
                               2 * FRAME_S + 1e-6)
        self.assertAlmostEqual(signed_replay._detached_association_tolerance(sparse, 0.003),
                               2 * FRAME_S + 0.003 + 1e-6)

    def test_detached_real_ecdsa_identical_repeats_authenticate_after_slow_signing(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("Optional cryptography package is not installed.")
        from src.experiment.signed_workload import build_or_load_workload
        records = trace_fixture(count=4, spacing=0.5, aircraft=("ABCDEF",))
        for record in records:
            record["raw_msg"] = records[0]["raw_msg"]
        profile = profile_fixture(sign_ms=2000)
        with tempfile.TemporaryDirectory() as temporary:
            for interval in (1, 2):
                with self.subTest(interval=interval):
                    workload = build_or_load_workload(records, ALGORITHM, interval, None, Path(temporary))
                    result = signed_replay.simulate(records, ALGORITHM, interval, workload, profile, profile,
                        {"followup_s": 10, "auth_frames_per_second": 8000,
                         "channel_mode": "independent", "loss": {"kind": "iid", "probability": 0}},
                        replay_model="signed_detached")
                    summary = result["summary"]
                    self.assertEqual(summary["augmented_original_received_messages"], 4)
                    self.assertEqual(summary["authenticated_messages"], 4)
                    self.assertEqual(summary["verification_completed_groups"], 4 // interval)
                    self.assertAlmostEqual(summary["receiver_association_tolerance_s"], 2 * FRAME_S + 1e-6)
                    self.assertGreater(summary["receiver_retention_s"], 10)

    def test_stage_counts_distinguish_crypto_success_failure_and_pending(self):
        records = trace_fixture(count=3, spacing=0.2, aircraft=("ABCDEF",))
        workload = workload_fixture(records)
        envelope = workload["groups"][0]["envelope"]
        workload["groups"][0]["envelope"] = Envelope(envelope.descriptor, b"X" + envelope.signature[1:])
        result = replay(records, workload=workload, replay_model="signed_detached")
        summary = result["summary"]
        for name in ("complete_authentication_object_groups", "reconstructed_signing_input_groups",
                     "verification_started_groups", "verification_completed_groups"):
            self.assertEqual(summary[name], 3, name)
        self.assertEqual(summary["cryptographically_valid_groups"], 2)
        self.assertEqual(summary["invalid_signature_groups"], 1)
        self.assertEqual(summary["authenticated_groups"], 2)
        self.assertEqual(summary["authentication_pending_groups"], 0)
        self.assertEqual(summary["authentication_definitive_failure_groups"], 1)
        self.assertEqual(summary["verification_pending_groups"], 0)
        pending = replay(records, profile=profile_fixture(verify_ms=10000),
                         replay_model="signed_detached")["summary"]
        self.assertEqual(pending["verification_completed_groups"], 0)
        self.assertEqual(pending["verification_pending_groups"], 3)
        self.assertEqual(pending["authentication_pending_groups"], 3)

    def test_actual_signature_lower_bound_is_separate_from_replayed_prototype(self):
        result = replay(trace_fixture(count=2, spacing=1, aircraft=("ABCDEF",)),
                        replay_model="signed_detached")
        summary = result["summary"]
        self.assertEqual(summary["actual_signature_bytes_total"], 128)
        self.assertEqual(summary["signature_only_7byte_lower_bound_frames"], 20)
        self.assertEqual(summary["signature_only_7byte_lower_bound_airtime_s"], 20 * FRAME_S)
        self.assertEqual(summary["prototype_required_authentication_frames"], 86)
        self.assertEqual(summary["auth_frames_transmitted"], 86)

    def test_unknown_replay_mode_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "replay model"):
            replay(replay_model="typo")

    def test_signing_delays_ordinary_message_but_reception_precedes_authentication(self):
        records = trace_fixture(count=2, spacing=1, aircraft=("ABCDEF",))
        result = replay(records, profile=profile_fixture(sign_ms=200))
        summary = result["summary"]
        self.assertEqual(summary["authenticated_messages"], 2)
        self.assertEqual(result["outcomes"], {"authenticated": 2})
        self.assertAlmostEqual(summary["ordinary_transmission_delay_ms_mean"], 200)
        self.assertAlmostEqual(summary["augmented_original_delivery_ms_mean"], 200.12)
        self.assertGreater(summary["receipt_to_auth_ms_mean"], 0)
        self.assertGreater(summary["source_to_auth_ms_mean"], summary["augmented_original_delivery_ms_mean"])
        self.assertEqual(summary["authentication_only_additional_rf_loss_messages"], 0)

    def test_grouping_wait_is_paid_before_any_member_is_transmitted(self):
        records = trace_fixture(count=2, spacing=1, aircraft=("ABCDEF",))
        result = replay(records, interval=2, profile=profile_fixture(sign_ms=200))
        self.assertEqual(result["summary"]["authenticated_messages"], 2)
        event = result["events"][0]
        self.assertEqual(event["formed_s"], 1)
        self.assertEqual(event["sign_end_s"], 1.2)
        self.assertAlmostEqual(event["ordinary_transmission_starts_s"][0], 1.2)
        self.assertAlmostEqual(event["ordinary_transmission_starts_s"][1], 1.2 + FRAME_S)
        self.assertAlmostEqual(result["summary"]["batch_formation_wait_ms_mean"], 500)
        self.assertAlmostEqual(result["summary"]["ordinary_transmission_delay_ms_max"], 1200)

    def test_overloaded_signer_leaves_unsent_pending_not_radio_losses(self):
        records = trace_fixture(count=2, spacing=1, aircraft=("ABCDEF",))
        result = replay(records, profile=profile_fixture(sign_ms=10000), followup_s=1)
        summary = result["summary"]
        self.assertEqual(summary["ordinary_frames_transmitted"], 0)
        self.assertEqual(summary["ordinary_frames_rf_lost"], 0)
        self.assertEqual(summary["ordinary_messages_unsent_pending"], 2)
        self.assertEqual(summary["unresolved_messages"], 2)
        self.assertEqual(summary["definitive_failure_messages"], 0)
        self.assertEqual(result["outcomes"], {"pending_signing": 1, "pending_sender_queue": 1})
        self.assertIsNone(summary["ordinary_transmission_delay_ms_mean"])
        self.assertAlmostEqual(summary["observation_horizon_s"], 2 + FRAME_S)

    def test_fixed_tails_are_withheld_and_timeout_tails_are_signed(self):
        records = trace_fixture(count=3, spacing=0.2, aircraft=("ABCDEF",))
        fixed = replay(records, interval=2)["summary"]
        bounded = replay(records, interval=2, max_batch_wait_s=0.5)["summary"]
        self.assertEqual(fixed["unsigned_tail_messages"], 1)
        self.assertEqual(fixed["ordinary_messages_withheld_definitively"], 1)
        self.assertEqual(fixed["authenticated_messages"], 2)
        self.assertEqual(bounded["unsigned_tail_messages"], 0)
        self.assertEqual(bounded["authenticated_messages"], 3)

    def test_actual_verifier_rejects_tampered_signature_after_real_byte_reassembly(self):
        records = trace_fixture(count=2, spacing=0.5, aircraft=("ABCDEF",))
        workload = workload_fixture(records)
        envelope = workload["groups"][0]["envelope"]
        workload["groups"][0]["envelope"] = Envelope(envelope.descriptor, b"X" + envelope.signature[1:])
        FakeVerifier.calls = 0
        result = replay(records, workload=workload)
        self.assertEqual(FakeVerifier.calls, 2)
        self.assertEqual(result["outcomes"], {"authenticated": 1, "invalid_signature": 1})
        self.assertEqual(result["summary"]["authenticated_messages"], 1)

    def test_missing_fragment_prevents_verification(self):
        channel = signed_replay.evaluate_shifted_channel
        def drop_one(*args, **kwargs):
            result = channel(*args, **kwargs)
            if len(result["auth_success"]):
                result["auth_success"][0] = False
            return result
        with patch.object(signed_replay, "evaluate_shifted_channel", side_effect=drop_one):
            result = replay()
        self.assertEqual(result["summary"]["authenticated_messages"], 5)
        self.assertEqual(result["outcomes"]["fragments_lost"], 1)

    def test_reception_threshold_cohorts_do_not_extend_fixed_horizon(self):
        records = trace_fixture(count=2, spacing=1, aircraft=("ABCDEF",))
        summary = replay(records, profile=profile_fixture(sign_ms=1000), followup_s=2,
                         coverage_thresholds_s=[2])["summary"]
        self.assertAlmostEqual(summary["observation_horizon_s"], 3 + FRAME_S)
        coverage = summary["threshold_coverage"][0]
        self.assertEqual(coverage["source_eligible_messages"], 2)
        self.assertLess(coverage["receipt_eligible_messages"], 2)

    def test_busy_auth_frame_finishes_before_new_ordinary_frame(self):
        # First ordinary ends at 220 us. First auth occupies [220,340] us.
        # The next signature becomes ready at 280 us and must wait to 340 us.
        records = trace_fixture(count=2, spacing=0.00018, aircraft=("ABCDEF",))
        result = replay(records, profile=profile_fixture(sign_ms=0.1),
                        auth_frames_per_second=1000, channel_mode="destructive_overlap")
        starts = result["events"][1]["ordinary_transmission_starts_s"]
        self.assertAlmostEqual(starts[0], 0.00034)
        self.assertEqual(result["summary"]["ordinary_frames_rf_lost"], 0)
        self.assertEqual(result["summary"]["authenticated_messages"], 2)

    def test_own_radio_never_overlaps_originals_and_fragments(self):
        records = trace_fixture(count=30, spacing=0.00023, aircraft=("ABCDEF",))
        channel = signed_replay.evaluate_shifted_channel
        captures = []
        def capture(source, shifted, aircraft, auth, **options):
            if len(auth):
                captures.append((shifted.copy(), auth.copy()))
            return channel(source, shifted, aircraft, auth, **options)
        for model in ("signed_before_send", "signed_detached"):
            with self.subTest(model=model):
                captures.clear()
                with patch.object(signed_replay, "evaluate_shifted_channel", side_effect=capture):
                    result = replay(records, channel_mode="destructive_overlap", replay_model=model)
                ordinary, auth = captures[0]
                frames = np.sort(np.concatenate([ordinary[np.isfinite(ordinary)], auth]))
                self.assertTrue(np.all(np.diff(frames) >= FRAME_S - 1e-12))
                self.assertEqual(result["summary"]["ordinary_frames_rf_lost"], 0)

    def test_observed_interference_is_retained_and_followup_is_required(self):
        records = trace_fixture(count=2, spacing=1, aircraft=("ABCDEF",))
        channel = {"extra_starts": [0.2], "extra_durations_s": [FRAME_S],
                   "coverage_end_s": 4, "summary": {"non_target_frames": 1}}
        result = replay(records, profile=profile_fixture(sign_ms=200), channel_trace=channel,
                        channel_mode="destructive_overlap")
        self.assertEqual(result["summary"]["baseline_original_received_messages"], 2)
        self.assertEqual(result["summary"]["ordinary_frames_rf_lost"], 1)
        # This loss was caused by the timing shift against observed traffic,
        # not by the added signature RF envelopes.
        self.assertEqual(result["summary"]["authentication_only_additional_rf_loss_messages"], 0)
        channel["coverage_end_s"] = 1
        with self.assertRaisesRegex(ValueError, "follow-up"):
            replay(records, channel_trace=channel)

    def test_event_guard_and_workload_policy_mismatch_fail_closed(self):
        with self.assertRaisesRegex(RuntimeError, "max_events"):
            replay(max_events=20)
        with self.assertRaisesRegex(ValueError, "grouping policy"):
            replay(interval=2, workload=workload_fixture(trace_fixture(), 1))

    def test_input_trace_and_workload_are_not_mutated(self):
        records = trace_fixture()
        workload = workload_fixture(records)
        before = copy.deepcopy((records, workload))
        replay(records, workload=workload)
        self.assertEqual((records, workload), before)

    def test_result_is_strict_json_and_uses_the_driver_model_identifier(self):
        result = replay()
        self.assertEqual(result["summary"]["replay_model"], "signed_before_send")
        self.assertEqual(json.loads(json.dumps(result, allow_nan=False)), result)

    def test_inflight_original_with_received_signature_remains_pending(self):
        records = trace_fixture(count=2, spacing=1, aircraft=("ABCDEF",))
        class FixedJitter:
            def __init__(self, seed):
                self.seed = seed
            def uniform(self, low, high, count):
                return np.full(count, 2.0 if self.seed == 7014 else 0.0)
        # Patch only the engine's jitter generator, preserving channel RNGs.
        original_rng = np.random.default_rng
        def rng(seed):
            return FixedJitter(seed) if seed in {7014, 8012} else original_rng(seed)
        with patch.object(signed_replay.np.random, "default_rng", side_effect=rng):
            result = replay(records, profile=profile_fixture(sign_ms=1000, verify_ms=1),
                            followup_s=0.5, receive_jitter_ms=2000,
                            auth_frames_per_second=100)
        self.assertEqual(result["summary"]["ordinary_frames_in_flight_at_horizon"], 1)
        self.assertEqual(result["summary"]["unresolved_messages"], 1)
        self.assertEqual(result["summary"]["definitive_failure_messages"], 0)
        self.assertEqual(result["outcomes"]["pending_original_messages"], 1)

    def test_new_identical_receipt_does_not_change_queued_verification_input(self):
        records = trace_fixture(count=2, spacing=0.2, aircraft=("ABCDEF",))
        records[1]["raw_msg"] = records[0]["raw_msg"]
        result = replay(records, profile=profile_fixture(verify_ms=500))
        self.assertEqual(result["summary"]["authenticated_messages"], 2)
        self.assertEqual(result["outcomes"], {"authenticated": 2})

    def test_invalid_signature_restores_reserved_observations_and_retries_waiters(self):
        records = trace_fixture(count=2, spacing=0.2, aircraft=("ABCDEF",))
        records[1]["raw_msg"] = records[0]["raw_msg"]
        workload = workload_fixture(records)
        envelope = workload["groups"][0]["envelope"]
        workload["groups"][0]["envelope"] = Envelope(envelope.descriptor, b"X" + envelope.signature[1:])
        channel = signed_replay.evaluate_shifted_channel
        def lose_second(*args, **kwargs):
            result = channel(*args, **kwargs)
            result["original_success_with_auth"][1] = False
            return result
        with patch.object(signed_replay, "evaluate_shifted_channel", side_effect=lose_second):
            result = replay(records, workload=workload, profile=profile_fixture(verify_ms=500))
        self.assertEqual(result["events"][0]["work_state"], "invalid_signature")
        self.assertEqual(result["events"][1]["work_state"], "ambiguous_message")
        self.assertEqual(result["summary"]["authenticated_messages"], 0)

    def test_real_ecdsa_workload_authenticates_without_fake_verifier(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("Optional cryptography package is not installed.")
        from src.experiment.signed_workload import build_or_load_workload
        records = trace_fixture(count=2, spacing=1, aircraft=("ABCDEF",))
        with tempfile.TemporaryDirectory() as temporary:
            workload = build_or_load_workload(records, ALGORITHM, 1, None, Path(temporary))
            for model in ("signed_before_send", "signed_detached"):
                with self.subTest(model=model):
                    result = signed_replay.simulate(records, ALGORITHM, 1, workload, profile_fixture(),
                        profile_fixture(), {"followup_s": 2, "auth_frames_per_second": 8000,
                            "channel_mode": "independent", "loss": {"kind": "iid", "probability": 0}},
                        replay_model=model)
                    self.assertEqual(result["summary"]["authenticated_messages"], 2)
                    self.assertEqual(result["summary"]["authenticated_groups"], 2)


if __name__ == "__main__":
    unittest.main()
