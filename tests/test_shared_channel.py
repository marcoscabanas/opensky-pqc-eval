from array import array
import unittest

import numpy as np

from src.experiment.shared_channel import (
    FRAME_S, _burst_environment, evaluate_channel, evaluate_shifted_channel,
)


def channel(originals, auth=(), **options):
    return evaluate_channel(
        originals, ["ABCDEF"] * len(originals), auth,
        loss=options.pop("loss", {"kind": "iid", "probability": 0}),
        seed=options.pop("seed", 7), horizon=options.pop("horizon", 1.0), **options,
    )


class SharedChannelTests(unittest.TestCase):
    def test_authentication_overlap_destroys_both_frames_and_changes_paired_baseline(self):
        result = channel([0.0, 0.01], [FRAME_S / 2])
        np.testing.assert_array_equal(result["original_success_baseline"], [True, True])
        np.testing.assert_array_equal(result["original_success_with_auth"], [False, True])
        np.testing.assert_array_equal(result["auth_success"], [False])
        np.testing.assert_array_equal(result["additional_original_losses"], [True, False])
        self.assertEqual(result["summary"]["additional_original_losses_due_to_auth"], 1)

    def test_triple_chain_flags_every_participant_even_without_end_to_end_overlap(self):
        result = channel([0.0, 0.0002], [0.0001])
        self.assertFalse(np.any(result["original_collision_baseline"]))
        self.assertTrue(np.all(result["original_collision_with_auth"]))
        self.assertTrue(np.all(result["auth_collision"]))

    def test_exact_touching_is_allowed_and_substantial_partial_overlap_is_not(self):
        for offset in (0.0, 0.12345, 1000.0):
            with self.subTest(offset=offset):
                starts = [offset + index * FRAME_S for index in range(4)]
                result = channel(starts, horizon=1001.0)
                self.assertFalse(np.any(result["original_collision_baseline"]))
                overlap = channel([offset, offset + FRAME_S - 1e-8], horizon=1001.0)
                self.assertTrue(np.all(overlap["original_collision_baseline"]))

    def test_sparse_unsorted_frames_return_masks_in_original_input_order(self):
        result = channel([0.2, 0.0, 0.1], [0.20001, 0.9])
        np.testing.assert_array_equal(result["original_success_with_auth"], [False, True, True])
        np.testing.assert_array_equal(result["auth_success"], [False, True])

    def test_same_aircraft_original_overlap_is_retained(self):
        result = channel([0.0, 0.00001])
        self.assertTrue(np.all(result["original_collision_baseline"]))
        np.testing.assert_array_equal(result["original_success_baseline"], result["original_success_with_auth"])

    def test_independent_control_ignores_overlaps(self):
        result = channel([0.0, 0.0], [0.0, 0.0], channel_mode="independent")
        self.assertTrue(np.all(result["original_success_baseline"]))
        self.assertTrue(np.all(result["original_success_with_auth"]))
        self.assertTrue(np.all(result["auth_success"]))
        self.assertFalse(np.any(result["additional_original_losses"]))

    def test_original_exogenous_draws_are_paired_and_independent_of_auth_count(self):
        originals = np.linspace(0.0, 1.0, 1001)
        parameters = {"kind": "iid", "probability": 0.3}
        empty = channel(originals, loss=parameters)
        few = channel(originals, [0.01], loss=parameters)
        many = channel(originals, np.linspace(0.0, 1.0, 1500), loss=parameters)
        np.testing.assert_array_equal(empty["original_exogenous_loss"], few["original_exogenous_loss"])
        np.testing.assert_array_equal(empty["original_exogenous_loss"], many["original_exogenous_loss"])
        np.testing.assert_array_equal(empty["original_success_baseline"], many["original_success_baseline"])
        self.assertTrue(np.all(~many["original_success_with_auth"] | many["original_success_baseline"]))

    def test_already_exogenously_lost_original_is_not_counted_as_additional_loss(self):
        result = channel([0.0], [0.00001], loss={"kind": "iid", "probability": 1})
        self.assertTrue(result["auth_collision"][0])
        self.assertTrue(result["original_collision_with_auth"][0])
        self.assertFalse(result["additional_original_losses"][0])
        self.assertEqual(result["summary"]["additional_original_collisions_due_to_auth"], 1)
        self.assertEqual(result["summary"]["additional_original_losses_due_to_auth"], 0)

    def test_background_is_seeded_poisson_and_shared_across_paired_scenarios(self):
        originals = np.linspace(0.0, 1.0, 1001)
        empty = channel(originals, background_frames_per_second=1000)
        added = channel(originals, [0.123], background_frames_per_second=1000)
        np.testing.assert_array_equal(empty["background_starts"], added["background_starts"])
        np.testing.assert_array_equal(empty["original_collision_baseline"], added["original_collision_baseline"])
        self.assertGreater(empty["summary"]["original_collision_losses_baseline"], 0)
        self.assertGreater(empty["summary"]["background_frames"], 900)
        self.assertLess(empty["summary"]["background_frames"], 1100)
        self.assertFalse(np.any(empty["additional_original_losses"]))

    def test_observed_short_and_long_events_use_their_own_durations(self):
        short = channel([80e-6], observed_starts=[0], observed_durations_s=[64e-6])
        long = channel([80e-6], observed_starts=[0], observed_durations_s=[120e-6])
        self.assertTrue(short["original_success_baseline"][0])
        self.assertFalse(long["original_success_baseline"][0])
        self.assertFalse(long["additional_original_losses"][0])

    def test_nested_observed_event_reaches_past_shorter_adjacent_frames(self):
        result = channel(
            [0.009, 0.001, 0.003], [0.007, 0.02],
            observed_starts=[0.0], observed_durations_s=[0.01],
        )
        self.assertTrue(np.all(result["original_collision_baseline"]))
        self.assertTrue(np.all(result["original_collision_with_auth"]))
        np.testing.assert_array_equal(result["auth_collision"], [True, False])
        self.assertFalse(np.any(result["additional_original_losses"]))

    def test_variable_duration_chain_and_touching_boundaries(self):
        chain = channel([0], [390e-6], observed_starts=[100e-6], observed_durations_s=[300e-6])
        self.assertTrue(chain["original_collision_baseline"][0])
        self.assertTrue(chain["auth_collision"][0])
        for offset in (0.0, 0.12345, 1000.0):
            with self.subTest(offset=offset):
                for duration in (64e-6, 120e-6, 500e-6):
                    touching = channel(
                        [offset + duration], observed_starts=[offset],
                        observed_durations_s=[duration], horizon=1001.0,
                    )
                    overlap = channel(
                        [offset + duration - 1e-8], observed_starts=[offset],
                        observed_durations_s=[duration], horizon=1001.0,
                    )
                    self.assertFalse(touching["original_collision_baseline"][0])
                    self.assertTrue(overlap["original_collision_baseline"][0])

    def test_observed_trace_and_noise_are_identical_across_paired_scenarios(self):
        originals = np.linspace(0, 1, 1001)
        observed = np.linspace(0, 1, 351)
        durations = np.linspace(64e-6, 500e-6, len(observed))
        options = {
            "observed_starts": observed, "observed_durations_s": durations,
            "background_frames_per_second": 100, "loss": {"kind": "iid", "probability": 0.2},
        }
        baseline = channel(originals, **options)
        added = channel(originals, [0.01, 0.01001], **options)
        np.testing.assert_array_equal(baseline["observed_starts"], added["observed_starts"])
        np.testing.assert_array_equal(baseline["background_starts"], added["background_starts"])
        np.testing.assert_array_equal(baseline["original_exogenous_loss"], added["original_exogenous_loss"])
        np.testing.assert_array_equal(baseline["original_success_baseline"], added["original_success_baseline"])
        self.assertTrue(np.all(~added["original_success_with_auth"] | added["original_success_baseline"]))

    def test_independent_control_retains_observed_load_without_collisions(self):
        result = channel(
            [0], [0], channel_mode="independent", observed_starts=[0, 1],
            observed_durations_s=[0.25, 0.5],
        )
        self.assertTrue(result["original_success_baseline"][0])
        self.assertTrue(result["auth_success"][0])
        summary = result["summary"]
        self.assertEqual(summary["observed_frames"], 2)
        self.assertEqual(summary["background_frames"], 0)
        # The full duration of the event starting at the horizon is included.
        self.assertAlmostEqual(summary["observed_airtime_s"], 0.75)
        self.assertAlmostEqual(summary["total_offered_airtime_baseline_s"], 0.75 + FRAME_S)
        self.assertAlmostEqual(summary["total_offered_airtime_with_auth_s"], 0.75 + 2 * FRAME_S)

    def test_observed_interferers_remain_when_exogenous_loss_is_complete(self):
        result = channel(
            [0], [0.01], observed_starts=[0, 0.01], observed_durations_s=[64e-6, 64e-6],
            loss={"kind": "iid", "probability": 1},
        )
        self.assertTrue(result["original_collision_baseline"][0])
        self.assertTrue(result["auth_collision"][0])
        self.assertFalse(result["additional_original_losses"][0])

    def test_variable_duration_masks_match_bruteforce_for_unsorted_events(self):
        generator = np.random.default_rng(121)
        originals = generator.uniform(0, 0.1, 150)
        auth = generator.uniform(0, 0.1, 100)
        observed = generator.uniform(0, 0.1, 125)
        durations = generator.uniform(20e-6, 0.003, len(observed))
        result = channel(originals, auth, observed_starts=observed, observed_durations_s=durations)

        def brute(starts, lengths):
            ends = starts + lengths
            overlaps = ((starts[:, None] < ends[None, :])
                        & (starts[None, :] < ends[:, None]))
            np.fill_diagonal(overlaps, False)
            return np.any(overlaps, axis=1)

        baseline = brute(
            np.concatenate((originals, observed)),
            np.concatenate((np.full(len(originals), FRAME_S), durations)),
        )
        augmented = brute(
            np.concatenate((originals, auth, observed)),
            np.concatenate((np.full(len(originals) + len(auth), FRAME_S), durations)),
        )
        np.testing.assert_array_equal(result["original_collision_baseline"], baseline[:len(originals)])
        np.testing.assert_array_equal(result["original_collision_with_auth"], augmented[:len(originals)])
        np.testing.assert_array_equal(result["auth_collision"], augmented[len(originals):len(originals) + len(auth)])

    def test_empty_observed_arrays_preserve_original_masks_and_optional_reporting(self):
        options = {"background_frames_per_second": 100, "loss": {"kind": "iid", "probability": 0.1}}
        absent = channel([0, 0.01], [0.005], **options)
        empty = channel([0, 0.01], [0.005], observed_starts=[], observed_durations_s=[], **options)
        for name, value in absent.items():
            if isinstance(value, np.ndarray):
                np.testing.assert_array_equal(value, empty[name])
        for name, value in absent["summary"].items():
            if name != "assumptions":
                self.assertEqual(value, empty["summary"][name])
        self.assertNotIn("observed_frames", absent["summary"])
        self.assertEqual(empty["summary"]["observed_frames"], 0)
        self.assertAlmostEqual(empty["summary"]["total_offered_airtime_baseline_s"],
                               (2 + empty["summary"]["background_frames"]) * FRAME_S)

    def test_observed_arrays_are_not_mutated(self):
        starts = np.array([0.1, 0.0])
        durations = np.array([64e-6, 120e-6])
        starts.setflags(write=False)
        durations.setflags(write=False)
        channel([0.3], [0.2], observed_starts=starts, observed_durations_s=durations)
        np.testing.assert_array_equal(starts, [0.1, 0.0])
        np.testing.assert_array_equal(durations, [64e-6, 120e-6])

    def test_burst_environment_is_continuous_in_time_and_invariant_to_added_frames(self):
        parameters = {"kind": "gilbert_elliott", "good_loss": 0, "bad_loss": 1,
                      "mean_good_s": 2.0, "mean_bad_s": 0.5}
        starts = np.linspace(0.0, 100.0, 10001)
        original = channel(starts, loss=parameters, horizon=100.0, channel_mode="independent")
        paired = channel(starts, starts, loss=parameters, horizon=100.0, channel_mode="independent")
        np.testing.assert_array_equal(original["original_exogenous_loss"], paired["original_exogenous_loss"])
        # With state-conditional probabilities 0/1, both streams observe exactly
        # the same common bad intervals despite separate Bernoulli RNG streams.
        np.testing.assert_array_equal(paired["original_exogenous_loss"], paired["auth_exogenous_loss"])
        self.assertGreater(paired["summary"]["burst_transition_count"], 50)
        again = channel(starts, starts, loss=parameters, horizon=100.0, channel_mode="independent")
        np.testing.assert_array_equal(paired["auth_success"], again["auth_success"])

    def test_burst_holding_times_have_configured_means(self):
        parameters = {"kind": "gilbert_elliott", "good_loss": 0, "bad_loss": 1,
                      "mean_good_s": 2.0, "mean_bad_s": 0.5}
        transitions, initial_bad = _burst_environment(parameters, 12, 10000.0)
        durations = np.diff(np.concatenate(([0.0], transitions)))
        bad = np.arange(len(durations)) % 2 == (0 if initial_bad else 1)
        self.assertAlmostEqual(float(durations[bad].mean()), 0.5, delta=0.04)
        self.assertAlmostEqual(float(durations[~bad].mean()), 2.0, delta=0.12)

    def test_masks_match_bruteforce_overlap_for_random_unsorted_frames(self):
        generator = np.random.default_rng(91)
        originals, auth = generator.uniform(0, 0.005, 30), generator.uniform(0, 0.005, 40)
        result = channel(originals, auth)
        starts = np.concatenate((originals, auth))
        distance = np.abs(starts[:, None] - starts[None, :])
        overlap = (distance < FRAME_S) & ~np.eye(len(starts), dtype=bool)
        expected = np.any(overlap, axis=1)
        np.testing.assert_array_equal(result["original_collision_with_auth"], expected[:len(originals)])
        np.testing.assert_array_equal(result["auth_collision"], expected[len(originals):])

    def test_empty_arrays_zero_horizon_and_end_past_horizon(self):
        empty = channel([], [], horizon=0)
        self.assertEqual(empty["summary"]["original_frames"], 0)
        self.assertEqual(empty["auth_success"].dtype, np.bool_)
        final = channel([1.0], horizon=1.0)
        self.assertTrue(final["original_success_with_auth"][0])

    def test_compact_input_arrays_are_not_mutated_and_identifiers_can_be_omitted(self):
        originals, auth = array("d", [0.0, 0.1]), np.array([0.2, 0.3])
        result = evaluate_channel(originals, np.array([1, 2], dtype=np.int16), auth,
                                  loss={"kind": "iid", "probability": 0}, seed=0, horizon=1)
        np.testing.assert_array_equal(originals, [0.0, 0.1])
        np.testing.assert_array_equal(auth, [0.2, 0.3])
        self.assertTrue(np.all(result["auth_success"]))

    def test_invalid_lengths_times_loss_parameters_and_modes_fail(self):
        invalid_options = [
            {"channel_mode": "capture"}, {"seed": True}, {"horizon": -1},
            {"background_frames_per_second": float("inf")},
            {"loss": {"kind": "iid", "probability": 1.1}},
            {"loss": {"kind": "gilbert_elliott", "good_loss": 0, "bad_loss": 1,
                      "mean_good_s": 0, "mean_bad_s": 1}},
        ]
        for options in invalid_options:
            with self.subTest(options=options), self.assertRaises(ValueError):
                channel([0], **options)
        for starts in ([float("nan")], [-0.1], [1.1], [[0.1]]):
            with self.subTest(starts=starts), self.assertRaises(ValueError):
                channel(starts)
        with self.assertRaisesRegex(ValueError, "original_aircraft"):
            evaluate_channel([0], [], [], loss={}, seed=0, horizon=1)
        with self.assertRaisesRegex(ValueError, "auth_aircraft"):
            evaluate_channel([], [], [0], [], loss={}, seed=0, horizon=1)

    def test_invalid_observed_times_and_durations_fail(self):
        invalid_options = [
            {"observed_starts": []}, {"observed_durations_s": []},
            {"observed_starts": [0], "observed_durations_s": []},
            {"observed_starts": [0], "observed_durations_s": [[64e-6]]},
        ]
        invalid_options.extend({"observed_starts": [start], "observed_durations_s": [64e-6]}
                               for start in (-1, 1.01, float("nan"), float("inf")))
        invalid_options.extend({"observed_starts": [0], "observed_durations_s": [duration]}
                               for duration in (0, -1, float("nan"), float("inf")))
        invalid_options.append({"observed_starts": [1e308], "observed_durations_s": [1e308],
                                "horizon": 1e308})
        for options in invalid_options:
            with self.subTest(options=options), self.assertRaises(ValueError):
                channel([], **options)


def shifted_channel(originals, shifted, auth=(), **options):
    return evaluate_shifted_channel(
        originals, shifted, ["ABCDEF"] * len(originals), auth,
        loss=options.pop("loss", {"kind": "iid", "probability": 0}),
        seed=options.pop("seed", 7), horizon=options.pop("horizon", 1.0), **options,
    )


class ShiftedChannelTests(unittest.TestCase):
    def test_identical_schedules_match_existing_model(self):
        starts = np.linspace(0, 1, 401)
        auth = np.linspace(0.01, 0.99, 201)
        for mode in ("independent", "destructive_overlap"):
            for loss in (
                {"kind": "iid", "probability": 0.2},
                {"kind": "gilbert_elliott", "good_loss": 0.1, "bad_loss": 0.8,
                 "mean_good_s": 0.02, "mean_bad_s": 0.01},
            ):
                with self.subTest(mode=mode, loss=loss):
                    options = dict(
                        channel_mode=mode, loss=loss, background_frames_per_second=100,
                        observed_starts=[0.002, 0.123], observed_durations_s=[64e-6, 0.03],
                    )
                    old = channel(starts, auth, **options)
                    new = shifted_channel(starts, starts, auth, **options)
                    for name, value in old.items():
                        if isinstance(value, np.ndarray):
                            np.testing.assert_array_equal(value, new[name], err_msg=name)
                    for name, value in old["summary"].items():
                        if name != "assumptions":
                            self.assertEqual(value, new["summary"][name], name)

    def test_unsent_targets_do_not_interfere_and_are_not_rf_losses(self):
        result = shifted_channel([0, 0.01], [float("nan"), 0.01], [0])
        np.testing.assert_array_equal(result["original_transmitted_with_auth"], [False, True])
        np.testing.assert_array_equal(result["original_success_with_auth"], [False, True])
        self.assertTrue(result["auth_success"][0])
        self.assertFalse(np.any(result["original_collision_with_auth"]))
        self.assertFalse(np.any(result["original_exogenous_loss_with_auth"]))
        summary = result["summary"]
        self.assertEqual(summary["original_frames_deferred_with_auth"], 1)
        self.assertEqual(summary["original_rf_losses_with_auth"], 0)
        self.assertEqual(summary["additional_original_losses_deferred"], 1)
        self.assertEqual(summary["additional_original_losses_transmitted"], 0)

    def test_unsent_indices_do_not_shift_later_original_noise_draws(self):
        starts = np.linspace(0, 1, 1001)
        shifted = starts.copy()
        shifted[[0, 2, 18, 999]] = np.nan
        result = shifted_channel(
            starts, shifted, loss={"kind": "iid", "probability": 0.5},
            channel_mode="independent",
        )
        transmitted = result["original_transmitted_with_auth"]
        np.testing.assert_array_equal(
            result["original_exogenous_loss_baseline"][transmitted],
            result["original_exogenous_loss_with_auth"][transmitted],
        )
        self.assertFalse(np.any(result["original_exogenous_loss_with_auth"][~transmitted]))
        self.assertEqual(result["summary"]["original_reception_gains"], 0)

    def test_shifted_targets_can_gain_and_lose_reception_with_fixed_observed_events(self):
        result = shifted_channel(
            [0, 0.01, 0.02], [0.001, 0.011, 0.021], [0.02101],
            observed_starts=[0, 0.011], observed_durations_s=[64e-6, 0.0005],
        )
        np.testing.assert_array_equal(result["original_success_baseline"], [False, True, True])
        np.testing.assert_array_equal(result["original_success_with_auth"], [True, False, False])
        np.testing.assert_array_equal(result["original_reception_gains"], [True, False, False])
        np.testing.assert_array_equal(result["additional_original_losses"], [False, True, True])
        self.assertEqual(result["summary"]["net_original_reception_losses"], 1)
        self.assertTrue(result["auth_collision"][0])

    def test_shift_preserves_original_order_with_nested_variable_interferers(self):
        result = shifted_channel(
            [0.02, 0.01, 0], [0.025, 0.018, np.nan], [0.017, 0.04],
            observed_starts=[0.016], observed_durations_s=[0.004],
        )
        np.testing.assert_array_equal(result["original_collision_with_auth"], [False, True, False])
        np.testing.assert_array_equal(result["auth_collision"], [True, False])
        self.assertAlmostEqual(result["summary"]["total_offered_airtime_baseline_s"],
                               0.004 + 3 * FRAME_S)
        self.assertAlmostEqual(result["summary"]["total_offered_airtime_with_auth_s"],
                               0.004 + 4 * FRAME_S)

    def test_baseline_noise_and_background_do_not_depend_on_auth_or_shift(self):
        originals = np.linspace(0, 0.8, 500)
        options = dict(background_frames_per_second=100,
                       loss={"kind": "iid", "probability": 0.2})
        first = shifted_channel(originals, originals, **options)
        second = shifted_channel(originals, originals + 0.1, np.linspace(0, 1, 800), **options)
        for name in ("background_starts", "original_success_baseline",
                     "original_exogenous_loss_baseline", "original_collision_baseline"):
            np.testing.assert_array_equal(first[name], second[name])
        np.testing.assert_array_equal(first["original_exogenous_loss_with_auth"],
                                      second["original_exogenous_loss_with_auth"])

    def test_shifted_burst_noise_follows_shared_environment_at_actual_times(self):
        loss = {"kind": "gilbert_elliott", "good_loss": 0, "bad_loss": 1,
                "mean_good_s": 0.02, "mean_bad_s": 0.01}
        originals = np.linspace(0, 0.8, 500)
        shifted = originals + 0.1
        shifted[1::10] = np.nan
        result = shifted_channel(originals, shifted, shifted[np.isfinite(shifted)],
                                 loss=loss, channel_mode="independent")
        transitions, initial_bad = _burst_environment(loss, 7, 1.0)
        transmitted = np.isfinite(shifted)
        expected = (np.searchsorted(transitions, shifted[transmitted], side="right") % 2).astype(bool)
        if initial_bad:
            expected = ~expected
        np.testing.assert_array_equal(result["original_exogenous_loss_with_auth"][transmitted], expected)
        np.testing.assert_array_equal(result["auth_exogenous_loss"], expected)
        self.assertTrue(np.any(result["original_exogenous_loss_baseline"][transmitted] != expected))
        self.assertGreater(result["summary"]["original_reception_gains"], 0)
        self.assertGreater(result["summary"]["additional_original_losses_transmitted"], 0)

    def test_empty_all_unsent_and_final_frame_boundaries(self):
        empty = shifted_channel([], [], horizon=0)
        self.assertEqual(empty["summary"]["original_frames"], 0)
        deferred = shifted_channel([0, 0.1], [np.nan, np.nan], [0.2])
        self.assertEqual(deferred["summary"]["original_frames_deferred_with_auth"], 2)
        self.assertTrue(deferred["auth_success"][0])
        final = shifted_channel([0], [1.0], horizon=1.0)
        self.assertTrue(final["original_success_with_auth"][0])

    def test_inputs_are_not_mutated(self):
        originals = np.array([0, 0.2])
        shifted = np.array([np.nan, 0.3])
        auth = np.array([0.4])
        for values in (originals, shifted, auth):
            values.setflags(write=False)
        shifted_channel(originals, shifted, auth)
        np.testing.assert_array_equal(originals, [0, 0.2])
        np.testing.assert_array_equal(shifted, [np.nan, 0.3])
        np.testing.assert_array_equal(auth, [0.4])

    def test_invalid_shifted_and_auth_times_fail(self):
        for shifted in ([], [0, 0.1], [[0]], [float("inf")], [-float("inf")], [-0.1], [1.1]):
            with self.subTest(shifted=shifted), self.assertRaises(ValueError):
                shifted_channel([0], shifted)
        for auth in ([float("nan")], [1.1], [-1]):
            with self.subTest(auth=auth), self.assertRaises(ValueError):
                shifted_channel([0], [np.nan], auth)


if __name__ == "__main__":
    unittest.main()
