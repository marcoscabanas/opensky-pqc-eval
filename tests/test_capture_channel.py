"""Direct-overlap oracle and bounded-execution checks for capture sensitivity."""

import tempfile
import unittest
from unittest import mock

import numpy as np

from src.experiment import capture_channel as capture
from src.experiment.shared_channel import FRAME_S, evaluate_channel, evaluate_shifted_channel


def channel(originals=(), auth=(), **options):
    return evaluate_channel(
        originals, ["ABCDEF"] * len(originals), auth,
        loss=options.pop("loss", {"kind": "iid", "probability": 0}),
        seed=options.pop("seed", 7), horizon=options.pop("horizon", 2),
        channel_mode="observed_capture", **options,
    )


def oracle(originals, auth, observed, durations, seed):
    """Independent O(n**2) direct pair evaluation for small validation inputs."""
    key = capture._priority_key(seed)
    starts = np.concatenate((originals, auth, observed))
    ends = starts + np.concatenate((np.full(len(originals) + len(auth), FRAME_S), durations))
    ends -= 4 * np.spacing(ends)
    priorities = np.concatenate((capture._priorities(np.arange(len(originals)), 0, key),
                                 capture._priorities(np.arange(len(auth)), 1, key),
                                 capture._priorities(np.arange(len(observed)), 2, key)))
    is_auth = np.zeros(len(starts), dtype=bool)
    is_auth[len(originals):len(originals) + len(auth)] = True
    lost = np.zeros(len(starts), dtype=bool)
    for index in range(len(starts)):
        for other in range(len(starts)):
            if (is_auth[index] or is_auth[other]) and starts[index] < ends[other] and starts[other] < ends[index]:
                lost[index] |= priorities[other] > priorities[index]
    return lost[:len(originals)], lost[len(originals):len(originals) + len(auth)]


class ObservedCaptureTests(unittest.TestCase):
    def test_observed_overlaps_remain_received_in_baseline_and_without_authentication(self):
        result = channel([0, 0, 0.00003], observed_starts=[0, 0.00001],
                         observed_durations_s=[64e-6, FRAME_S])
        self.assertTrue(result["original_success_baseline"].all())
        self.assertTrue(result["original_success_with_auth"].all())
        self.assertEqual(result["summary"]["original_collision_losses_baseline"], 0)
        self.assertEqual(result["summary"]["baseline_reception_basis"], "conditioned_on_observed_success")

    def test_isolated_pair_has_exactly_one_survivor_and_both_outcomes_across_seeds(self):
        ordinary_wins = 0
        for seed in range(256):
            result = channel([0.1], [0.10001], seed=seed)
            self.assertEqual(int(result["original_success_with_auth"].sum())
                             + int(result["auth_success"].sum()), 1)
            ordinary_wins += int(result["original_success_with_auth"].sum())
        self.assertGreater(ordinary_wins, 95)
        self.assertLess(ordinary_wins, 161)

    def test_clique_retains_exactly_one_authentication_frame(self):
        result = channel(auth=[0.1] * 100, auth_run_offsets=[0, 100])
        self.assertEqual(result["auth_success"].sum(), 1)

    def test_chain_uses_direct_neighbors_and_losers_remain_interferers(self):
        starts = np.array([0, 100e-6, 200e-6])
        for priorities, expected in (([3, 2, 1], [True, False, False]),
                                     ([3, 1, 2], [True, False, True])):
            values = np.array(priorities, dtype=np.uint64)
            with mock.patch.object(capture, "_priorities", side_effect=lambda ids, domain, key: values[ids]):
                result = channel(auth=starts, auth_run_offsets=[0, 3])
            np.testing.assert_array_equal(result["auth_success"], expected)

    def test_random_bounded_runs_equal_direct_pairwise_oracle(self):
        rng = np.random.default_rng(8071)
        for trial in range(15):
            runs = [np.sort(rng.uniform(0, 0.01, count)) for count in (19, 7, 21, 11)]
            auth = np.concatenate(runs)
            offsets = np.concatenate(([0], np.cumsum([len(run) for run in runs])))
            originals = rng.uniform(0, 0.01, 23)
            observed = rng.uniform(0, 0.01, 17)
            durations = rng.uniform(10e-6, 0.004, len(observed))
            expected = oracle(originals, auth, observed, durations, trial)
            with mock.patch.multiple(capture, _CAPTURE_CHUNK=13, _CAPTURE_BUCKET_S=0.00031):
                result = channel(originals, auth, observed_starts=observed,
                                 observed_durations_s=durations, auth_run_offsets=offsets, seed=trial)
            np.testing.assert_array_equal(result["original_collision_with_auth"], expected[0])
            np.testing.assert_array_equal(result["auth_collision"], expected[1])
            reference = channel(originals, auth, observed_starts=observed,
                                observed_durations_s=durations, seed=trial)
            for name in ("original_success_with_auth", "auth_success"):
                np.testing.assert_array_equal(result[name], reference[name])

    def test_exact_touching_and_four_ulp_boundary_are_partition_invariant(self):
        for origin in (0.125, 1.0, 1000.0):
            for ulps in (0, 3, 8):
                auth = np.array([origin + FRAME_S - ulps * np.spacing(origin)])
                originals = np.array([origin])
                expected = oracle(originals, auth, np.array([]), np.array([]), 7)
                with mock.patch.multiple(capture, _CAPTURE_CHUNK=1, _CAPTURE_BUCKET_S=origin):
                    result = channel(originals, auth, auth_run_offsets=[0, 1], horizon=1001)
                np.testing.assert_array_equal(result["original_collision_with_auth"], expected[0])
                np.testing.assert_array_equal(result["auth_collision"], expected[1])
                if ulps < 4:
                    self.assertTrue(result["original_success_with_auth"][0])
                    self.assertTrue(result["auth_success"][0])

    def test_many_coincident_frames_remain_bounded_and_retain_priority_winner(self):
        auth = np.full(157, 0.1)
        originals = np.array([0.1, 0.1])
        expected = oracle(originals, auth, np.array([]), np.array([]), 7)
        real_argsort = np.argsort

        def limited_argsort(values, *args, **kwargs):
            self.assertLessEqual(len(values), 11)
            return real_argsort(values, *args, **kwargs)

        with mock.patch.multiple(capture, _CAPTURE_CHUNK=11), \
                mock.patch.object(capture.np, "argsort", side_effect=limited_argsort):
            result = channel(originals, auth, auth_run_offsets=[0, 79, 157])
        np.testing.assert_array_equal(result["original_collision_with_auth"], expected[0])
        np.testing.assert_array_equal(result["auth_collision"], expected[1])

    def test_readonly_memmap_and_partition_sizes_preserve_seeded_outcomes(self):
        auth = np.array([0.1, 0.10002, 0.7, 0, 0.10004, 0.8])
        with tempfile.TemporaryDirectory() as directory:
            np.save(directory + "/auth.npy", auth)
            values = np.load(directory + "/auth.npy", mmap_mode="r")
            reference = channel([0.10001], auth, auth_run_offsets=[0, 3, 6])
            with mock.patch.multiple(capture, _CAPTURE_CHUNK=2, _CAPTURE_BUCKET_S=0.10001):
                result = channel([0.10001], values, auth_run_offsets=[0, 3, 6])
            np.testing.assert_array_equal(values, auth)
            np.testing.assert_array_equal(result["auth_success"], reference["auth_success"])
            np.testing.assert_array_equal(result["original_success_with_auth"], reference["original_success_with_auth"])

    def test_shifted_originals_keep_source_priority_identity_when_an_earlier_target_is_unsent(self):
        for seed in range(12):
            options = dict(loss={"kind": "iid", "probability": 0}, seed=seed,
                           horizon=1, channel_mode="observed_capture")
            full = evaluate_shifted_channel([0, 0.5], [0, 0.2], [1, 2], [0.2], **options)
            missing = evaluate_shifted_channel([0, 0.5], [float("nan"), 0.2], [1, 2], [0.2], **options)
            self.assertEqual(full["original_success_with_auth"][1], missing["original_success_with_auth"][1])
            np.testing.assert_array_equal(full["auth_success"], missing["auth_success"])
            self.assertTrue(missing["original_success_baseline"].all())

    def test_new_observed_observed_overlap_after_shift_is_explicitly_exempt(self):
        result = evaluate_shifted_channel([0, 0.5], [0.2, 0.2], [1, 2], [],
            loss={"kind": "iid", "probability": 0}, seed=1, horizon=1,
            channel_mode="observed_capture", observed_starts=[0.2], observed_durations_s=[64e-6])
        self.assertTrue(result["original_success_with_auth"].all())
        self.assertEqual(result["summary"]["observed_observed_interference"], "excluded_including_shifted_targets")

    def test_conditioned_baseline_rejects_random_erasure_and_unobserved_background(self):
        for options in ({"loss": {"kind": "iid", "probability": 0.01}},
                        {"background_frames_per_second": 1}):
            with self.assertRaisesRegex(ValueError, "zero iid erasure"):
                channel([0], [0.1], **options)

    def test_priority_identity_has_no_ties_and_domain_order_does_not_select_the_winner(self):
        key = capture._priority_key(1)
        values = np.concatenate([capture._priorities(np.arange(500), domain, key) for domain in range(3)])
        self.assertEqual(len(np.unique(values)), len(values))
        self.assertTrue(np.any(values[:500] > values[500:1000]))
        self.assertTrue(np.any(values[:500] < values[500:1000]))


if __name__ == "__main__":
    unittest.main()
