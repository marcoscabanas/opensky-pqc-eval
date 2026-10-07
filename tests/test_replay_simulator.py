import copy
import unittest
from unittest.mock import patch

from src.experiment.replay_simulator import FRAME_S, LossProcess, form_groups, simulate, validate_scenario
from src.experiment.replay_transport import ReplayReceiver, fragment_count, object_size_bytes


ALGORITHM = "ECDSA-P256"


def trace_fixture(count=3, spacing=0.2, aircraft=("ABCDEF", "123456"), offset=0.02):
    """Canonical 14-byte DF17 observations, with distinct payloads per aircraft."""
    return [
        {"trace_id": index * len(aircraft) + craft + 1, "icao": icao,
         "raw_msg": "8D" + icao + f"{index + 1:020X}",
         "relative_time_s": index * spacing + craft * offset}
        for index in range(count) for craft, icao in enumerate(aircraft)
    ]


def profile_fixture(sign_ms=0.1, verify_ms=0.1):
    return {
        "id": "test_constant_service",
        "algorithms": {ALGORITHM: {"operations": {
            operation: {"samples_ms": [duration], "sample_kind": "assumed_constant"}
            for operation, duration in (("sign", sign_ms), ("verify", verify_ms))
        }}},
    }


def replay(records=None, interval=1, profile=None, seed=1, **options):
    profile = profile or profile_fixture()
    scenario = {
        "max_auth_age_s": 5.0, "auth_frames_per_second": 8000,
        "loss": {"kind": "iid", "probability": 0.0}, "record_events": True,
        **options,
    }
    return simulate(trace_fixture() if records is None else records, ALGORITHM, interval,
                    [64], profile, profile, scenario, seed=seed)


class ReplaySimulatorTest(unittest.TestCase):
    def test_zero_loss_authenticates_complete_groups_and_accounts_for_fixed_tails(self):
        records = trace_fixture(count=5)
        result = replay(records, interval=2)
        summary = result["summary"]
        self.assertEqual(summary["trace_messages"], 10)
        self.assertEqual(summary["source_groups"], 4)
        self.assertEqual(summary["unsigned_tail_messages"], 2)
        self.assertEqual(summary["modeled_authenticated_groups"], 4)
        self.assertEqual(summary["modeled_authenticated_messages"], 8)
        self.assertEqual(result["outcomes"], {"modeled_authenticated": 4})
        self.assertEqual(summary["original_frames_received"], 10)
        self.assertEqual(summary["timely_authenticated_source_fraction"], 0.8)
        self.assertTrue(all(event["decision_s"] <= event["deadline_s"] for event in result["events"]))
        per_message = replay(records)
        self.assertEqual(per_message["summary"]["modeled_authenticated_messages"], 10)

    def test_surveillance_schedule_is_unchanged_by_signing_delay(self):
        records = trace_fixture()
        original = copy.deepcopy(records)
        observed_runs = []
        observe = ReplayReceiver.observe_message
        for sign_ms in (0.1, 500):
            seen = []

            def capture(receiver, raw, time):
                seen.append((raw.hex().upper(), time))
                observe(receiver, raw, time)

            with patch.object(ReplayReceiver, "observe_message", capture):
                replay(records, profile=profile_fixture(sign_ms=sign_ms))
            observed_runs.append(seen)
        expected = [(record["raw_msg"], record["relative_time_s"] + FRAME_S)
                    for record in sorted(records, key=lambda record: record["relative_time_s"])]
        self.assertEqual(observed_runs, [expected, expected])
        self.assertEqual(records, original)

    def test_missing_original_cannot_authenticate_despite_complete_fragments(self):
        records = trace_fixture(count=2)
        drop_first_original = lambda self, time, original=False: original and time == 0.0
        with patch.object(LossProcess, "lost", drop_first_original):
            result = replay(records, interval=2, fragment_copies=3)
        self.assertEqual(result["summary"]["source_groups"], 2)
        self.assertEqual(result["summary"]["modeled_authenticated_groups"], 1)
        self.assertEqual(result["summary"]["original_frames_lost"], 1)
        self.assertEqual(result["summary"]["auth_frames_lost"], 0)
        failed = next(event for event in result["events"] if event["icao"] == "ABCDEF")
        self.assertEqual(failed["message_count"], 2)
        self.assertEqual(failed["distinct_fragments_received"], failed["required_fragments"])
        self.assertEqual(failed["outcome"], "expired_waiting_original_messages")

    def test_groups_are_formed_at_sender_before_receiver_loss(self):
        records = trace_fixture(count=5)
        no_loss = replay(records, interval=2)
        lost = replay(records, interval=2, loss={"kind": "iid", "probability": 1.0})
        source_fields = lambda result: sorted(
            (row["icao"], row["group_sequence"], row["message_count"], row["formed_s"])
            for row in result["events"])
        self.assertEqual(source_fields(no_loss), source_fields(lost))
        self.assertEqual(lost["summary"]["unsigned_tail_messages"], 2)
        self.assertEqual(lost["summary"]["modeled_authenticated_groups"], 0)
        self.assertEqual(lost["summary"]["original_frames_received"], 0)

    def test_max_wait_flushes_partial_groups_including_final_tail(self):
        records = trace_fixture(count=3, spacing=1.0)
        fixed = replay(records, interval=5)
        bounded = replay(records, interval=5, max_batch_wait_s=0.25)
        self.assertEqual(fixed["summary"]["source_groups"], 0)
        self.assertEqual(fixed["summary"]["unsigned_tail_messages"], 6)
        self.assertEqual(bounded["summary"]["source_groups"], 6)
        self.assertEqual(bounded["summary"]["unsigned_tail_messages"], 0)
        self.assertEqual(bounded["summary"]["modeled_authenticated_messages"], 6)
        groups, unsigned = form_groups(records, 5, 0.25)
        self.assertEqual(unsigned, 0)
        for _, _, entries, formed in groups:
            self.assertEqual(len(entries), 1)
            self.assertAlmostEqual(formed, entries[0]["relative_time_s"] + 0.25)

    def test_sender_processing_backlog_creates_queue_delay_and_deadline_misses(self):
        records = trace_fixture(count=10, spacing=0.005, offset=0.0005)
        result = replay(records, profile=profile_fixture(sign_ms=20), max_auth_age_s=0.08)
        summary = result["summary"]
        self.assertGreater(summary["signing_queue_ms_max"], 0)
        self.assertGreater(summary["sender_queue_peak_per_aircraft"], 1)
        self.assertGreater(summary["modeled_authenticated_groups"], 0)
        self.assertLess(summary["modeled_authenticated_groups"], summary["source_groups"])
        self.assertTrue(any(outcome.startswith("expired_sender") or outcome == "expired_signing"
                            for outcome in result["outcomes"]))

    def test_receiver_processing_backlog_creates_queue_delay_and_deadline_misses(self):
        records = trace_fixture(count=10, spacing=0.005, offset=0.0005)
        result = replay(records, profile=profile_fixture(verify_ms=50), max_auth_age_s=0.1)
        summary = result["summary"]
        self.assertGreater(summary["receiver_queue_peak"], 1)
        self.assertGreater(summary["verification_queue_ms_max"], 0)
        self.assertLess(summary["modeled_authenticated_groups"], summary["source_groups"])
        self.assertGreater(result["outcomes"].get("expired_verification_queue", 0), 0)

    def test_frame_rate_limit_can_prevent_reassembly_before_expiry(self):
        result = replay(trace_fixture(count=2), auth_frames_per_second=1.0, max_auth_age_s=0.25)
        self.assertEqual(result["summary"]["modeled_authenticated_groups"], 0)
        self.assertGreater(result["summary"]["auth_frames_transmitted"], 0)
        self.assertTrue(all(row["distinct_fragments_received"] < row["required_fragments"]
                            for row in result["events"]))

    def test_loss_and_reception_jitter_are_seeded_for_iid_and_burst_scenarios(self):
        scenarios = [
            {"kind": "iid", "probability": 0.1},
            {"kind": "gilbert_elliott", "good_loss": 0.01, "bad_loss": 0.8,
             "mean_good_s": 0.2, "mean_bad_s": 0.05},
        ]
        for loss in scenarios:
            with self.subTest(kind=loss["kind"]):
                first = replay(trace_fixture(count=8), loss=loss, receive_jitter_ms=0.4, seed=723)
                second = replay(trace_fixture(count=8), loss=loss, receive_jitter_ms=0.4, seed=723)
                self.assertEqual(first, second)
                self.assertEqual(sum(first["outcomes"].values()), first["summary"]["source_groups"])

    def test_repetition_can_recover_fragments_without_recovering_originals(self):
        records = trace_fixture(count=4, spacing=1.0, aircraft=("ABCDEF",))
        single = replay(records, fragment_copies=1, loss={"kind": "iid", "probability": 0.1}, seed=2)
        repeated = replay(records, fragment_copies=3, loss={"kind": "iid", "probability": 0.1}, seed=2)
        self.assertEqual(single["summary"]["original_frames_lost"], 1)
        self.assertEqual(single["summary"]["original_frames_lost"], repeated["summary"]["original_frames_lost"])
        self.assertGreater(repeated["summary"]["modeled_authenticated_groups"], single["summary"]["modeled_authenticated_groups"])
        self.assertLessEqual(repeated["summary"]["modeled_authenticated_messages"], repeated["summary"]["original_frames_received"])

    def test_duplicate_fragments_do_not_schedule_verification_more_than_once(self):
        profile = profile_fixture(verify_ms=50)
        for copies in (1, 2, 3):
            with self.subTest(copies=copies):
                result = replay(profile=profile, fragment_copies=copies, receiver_workers=2)
                self.assertEqual(result["summary"]["modeled_authenticated_groups"], 6)
                self.assertAlmostEqual(result["summary"]["receiver_busy_seconds_all_workers"], 6 * 0.05)

    def test_receiver_acceptance_does_not_cancel_configured_sender_repetitions(self):
        records = trace_fixture(count=2, spacing=1.0, aircraft=("ABCDEF",))
        expected_frames = len(records) * fragment_count(object_size_bytes(1, 64)) * 3
        for verify_ms in (0.1, 10):
            with self.subTest(verify_ms=verify_ms):
                result = replay(records, profile=profile_fixture(verify_ms=verify_ms),
                                fragment_copies=3, auth_frames_per_second=1000)
                self.assertEqual(result["summary"]["modeled_authenticated_groups"], 2)
                self.assertEqual(result["summary"]["auth_frames_transmitted"], expected_frames)

    def test_expired_queued_work_releases_capacity_while_worker_remains_busy(self):
        records = trace_fixture(count=4, aircraft=("ABCDEF",))
        for record, time in zip(records, (0.0, 0.01, 0.02, 0.2)):
            record["relative_time_s"] = time
        cases = (
            (profile_fixture(sign_ms=500), {"sender_queue_limit": 2}, "expired_sender_queue"),
            (profile_fixture(verify_ms=500), {"receiver_queue_limit": 2}, "expired_verification_queue"),
        )
        for profile, limits, expected_outcome in cases:
            with self.subTest(expected_outcome=expected_outcome):
                result = replay(records, profile=profile, max_auth_age_s=0.1, **limits)
                later_group = next(row for row in result["events"] if row["group_sequence"] == 4)
                self.assertEqual(later_group["outcome"], expected_outcome)

    def test_queue_limits_produce_explicit_overflow_outcomes(self):
        records = trace_fixture(count=10, spacing=0.005, offset=0.0005)
        sender = replay(records, profile=profile_fixture(sign_ms=50), sender_queue_limit=1)
        receiver = replay(records, profile=profile_fixture(verify_ms=50), receiver_queue_limit=1)
        self.assertGreater(sender["outcomes"].get("sender_queue_overflow", 0), 0)
        self.assertGreater(receiver["outcomes"].get("receiver_queue_overflow", 0), 0)
        self.assertLessEqual(sender["summary"]["sender_queue_peak_per_aircraft"], 1)
        self.assertLessEqual(receiver["summary"]["receiver_queue_peak"], 1)

    def test_invalid_scenarios_fail_before_simulation(self):
        for scenario in [
            {"unknown": 1}, {"max_auth_age_s": 0}, {"max_batch_wait_s": -1},
            {"auth_frames_per_second": 10000}, {"receiver_workers": True},
            {"max_events": 0}, {"record_events": 1}, {"receive_jitter_ms": -0.1},
            {"loss": {"kind": "iid", "probability": 1.1}},
            {"loss": {"kind": "gilbert_elliott", "good_loss": 0, "bad_loss": 1,
                      "mean_good_s": 0, "mean_bad_s": 1}},
        ]:
            with self.subTest(scenario=scenario), self.assertRaises(ValueError):
                validate_scenario(scenario)

    def test_event_limit_raises_instead_of_returning_partial_results(self):
        with self.assertRaisesRegex(RuntimeError, "max_events"):
            replay(max_events=1)

    def test_invalid_trace_and_nonpositive_duration_are_rejected(self):
        for mutation in (
            lambda records: records[0].update(raw_msg="8D123456" + "00" * 10),
            lambda records: records[0].update(raw_msg="00" * 14),
            lambda records: records[0].update(relative_time_s=-1),
            lambda records: records[0].update(trace_id=records[1]["trace_id"]),
        ):
            records = trace_fixture()
            mutation(records)
            with self.assertRaises(ValueError):
                replay(records)
        with self.assertRaises(ValueError):
            replay(trace_fixture(count=1, aircraft=("ABCDEF",)))


if __name__ == "__main__":
    unittest.main()
