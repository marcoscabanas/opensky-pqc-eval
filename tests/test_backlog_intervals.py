import math
import unittest
from types import SimpleNamespace

import numpy as np

from src.experiment.backlog_intervals import interval_statistics, summarize_work_intervals


class BacklogIntervalsTest(unittest.TestCase):
    def test_short_jobs_between_snapshot_times_are_counted(self):
        rows = interval_statistics([10, 10.001, 40], [10.0059, 10.0069, 40.0059], 0, 120)
        self.assertEqual(rows[0]["completed"], 3)
        self.assertEqual(rows[0]["max"], 2)
        self.assertAlmostEqual(rows[0]["mean"] * 60, 3 * .0059)
        self.assertEqual(rows[1]["max"], 0)

    def test_touching_jobs_do_not_create_false_peak(self):
        row = interval_statistics([0, 10, 10], [10, 20, 20], 0, 60)[0]
        self.assertEqual(row["max"], 2)
        self.assertAlmostEqual(row["mean"], .5)

    def test_jobs_spanning_bins_and_pending_at_cutoff(self):
        rows = interval_statistics([-10, 30, math.inf], [90, math.inf, math.inf], 0, 130)
        self.assertEqual([r["max"] for r in rows], [2, 2, 1])
        self.assertEqual([r["completed"] for r in rows], [0, 1, 0])
        self.assertEqual([r["mean"] for r in rows], [1.5, 1.5, 1.0])

    def test_cutoff_completion_and_boundary_assignment(self):
        rows = interval_statistics([0, 60], [60, 120], 0, 120)
        self.assertEqual([r["completed"] for r in rows], [0, 2])
        self.assertEqual([r["mean"] for r in rows], [1, 1])
        self.assertEqual([r["max"] for r in rows], [1, 1])

    def test_empty_and_invalid_intervals(self):
        rows = interval_statistics([], [], 0, 61)
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r["max"] == r["completed"] == r["mean"] == 0 for r in rows))
        for starts, ends in [([2], [1]), ([math.nan], [1]), ([1], [])]:
            with self.assertRaises(ValueError):
                interval_statistics(starts, ends, 0, 60)

    def test_random_intervals_match_direct_time_integrals_and_event_peaks(self):
        rng = np.random.default_rng(903)
        for _ in range(10):
            starts = rng.uniform(-20, 150, 80)
            ends = starts + rng.uniform(0, 40, 80)
            ends[::11] = math.inf
            rows = interval_statistics(starts, ends, 3, 123, bin_s=17)
            for row in rows:
                left, right = row["start_s"], row["end_s"]
                area = np.maximum(np.minimum(ends, right) - np.maximum(starts, left), 0).sum()
                candidate_times = np.concatenate(([left], starts[(starts >= left) & (starts < right)]))
                peak = max(int(((starts <= time) & (time < ends)).sum()) for time in candidate_times)
                completed = int(((ends >= left) & ((ends <= right) if right == 123 else (ends < right))).sum())
                self.assertAlmostEqual(row["mean"] * (right - left), area)
                self.assertEqual(row["max"], peak)
                self.assertEqual(row["completed"], completed)

    def test_stage_summaries_keep_radio_work_after_fragment_loss_and_exclude_rejections(self):
        def group(formed, sign_end=math.inf, tx_end=math.inf, queued_at=math.inf,
                  verify_end=math.inf, state="pending", enqueued=False):
            return SimpleNamespace(formed=formed, sign_end=sign_end, tx_end=tx_end,
                                   queued_at=queued_at, verify_end=verify_end,
                                   state=state, enqueued=enqueued)

        groups = [
            group(10, 11, 12, 13, 14, state="invalid_signature", enqueued=True),
            group(20, state="sender_queue_overflow"),
            group(30, 31, state="transmission_queue_overflow"),
            group(40, 41, state="fragments_lost"),
            group(50, 51, 52, 53, state="pending_verification_queue", enqueued=True),
        ]
        row = summarize_work_intervals(groups, 0, 60)[0]
        # A failed receiver decision does not undo completed work. A lost
        # fragment also does not tell the transmitter to cancel unsent work.
        self.assertEqual(row["signing_completed_groups"], 4)
        self.assertEqual(row["transmission_completed_groups"], 2)
        self.assertEqual(row["verification_completed_groups"], 1)
        self.assertAlmostEqual(row["sender_unfinished_groups_mean"] * 60, 4)
        self.assertAlmostEqual(row["transmission_unfinished_groups_mean"] * 60, 21)
        self.assertAlmostEqual(row["receiver_unfinished_groups_mean"] * 60, 8)
        self.assertEqual(row["transmission_unfinished_groups_max"], 2)

    def test_instantaneous_jobs_count_completions_without_creating_backlog(self):
        rows = interval_statistics([0, 60, 120], [0, 60, 120], 0, 120)
        self.assertEqual([row["completed"] for row in rows], [1, 2])
        self.assertTrue(all(row["mean"] == row["max"] == 0 for row in rows))


if __name__ == "__main__":
    unittest.main()
