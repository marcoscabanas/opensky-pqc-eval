"""Time-weighted work summaries from every modeled job interval.

The reporting bins are not simulation steps. Every job contributes its exact
duration and every admission/completion contributes to the within-bin maximum.
Work intervals are half-open; completion counts use half-open bins except that
the final observation cutoff is included in the last bin.
"""

import math

import numpy as np


def interval_statistics(starts, ends, window_start, window_end, *, bin_s=60.0):
    """Summarize concurrent unfinished jobs, including jobs still in service."""
    if (not all(math.isfinite(x) for x in (window_start, window_end, bin_s))
            or window_end <= window_start or bin_s <= 0):
        raise ValueError("Positive finite reporting window and bin width required.")
    starts, ends = np.asarray(starts, dtype=float), np.asarray(ends, dtype=float)
    if (starts.ndim != 1 or ends.ndim != 1 or len(starts) != len(ends)
            or np.any(np.isnan(starts)) or np.any(np.isnan(ends))
            or np.any(ends < starts)):
        raise ValueError("Jobs require ordered start/end pairs without NaNs.")
    edges = np.arange(window_start, window_end, bin_s, dtype=float)
    edges = np.append(edges, window_end)
    bins = len(edges) - 1
    completion_mask = np.isfinite(ends) & (ends >= window_start) & (ends <= window_end)
    completion_bins = np.minimum(np.searchsorted(edges, ends[completion_mask], side="right") - 1, bins - 1)
    completions = np.bincount(completion_bins, minlength=bins)
    active = (starts < window_end) & (ends > window_start) & (ends > starts)
    left = np.maximum(starts[active], window_start)
    right = np.minimum(ends[active], window_end)
    events = np.concatenate((left, right, edges))
    deltas = np.concatenate((np.ones(len(left), dtype=np.int64),
                             -np.ones(len(right), dtype=np.int64),
                             np.zeros(len(edges), dtype=np.int64)))
    order = np.argsort(events, kind="stable")
    times, first = np.unique(events[order], return_index=True)
    occupancy = np.cumsum(np.add.reduceat(deltas[order], first))
    if np.any(occupancy < 0) or occupancy[-1] != 0:
        raise RuntimeError("Reporting job intervals do not conserve occupancy.")
    positions = np.searchsorted(edges, times[:-1], side="right") - 1
    area = np.bincount(positions, weights=np.diff(times) * occupancy[:-1], minlength=bins)
    maxima = np.zeros(bins, dtype=np.int64)
    np.maximum.at(maxima, positions, occupancy[:-1])
    return [{"start_s": float(edges[i]), "end_s": float(edges[i + 1]),
             "mean": float(area[i] / (edges[i + 1] - edges[i])),
             "max": int(maxima[i]), "completed": int(completions[i])}
            for i in range(bins)]


def summarize_work_intervals(groups, start, horizon, *, bin_s=60.0):
    """All-aircraft signing/transmission and shared-receiver job summaries."""
    stages = (
        ("sender_unfinished_groups", "signing_completed_groups", "formed", "sign_end",
         lambda g: g.state != "sender_queue_overflow"),
        ("transmission_unfinished_groups", "transmission_completed_groups", "sign_end", "tx_end",
         lambda g: g.state not in {"sender_queue_overflow", "transmission_queue_overflow"}),
        ("receiver_unfinished_groups", "verification_completed_groups", "queued_at", "verify_end",
         lambda g: g.enqueued),
    )
    output = None
    for prefix, completion_key, start_key, end_key, include in stages:
        eligible = [group for group in groups if include(group)]
        statistics = interval_statistics(
            [getattr(group, start_key) for group in eligible],
            [getattr(group, end_key) for group in eligible], start, horizon, bin_s=bin_s)
        if output is None:
            output = [{"start_s": row["start_s"], "end_s": row["end_s"]} for row in statistics]
        for target, row in zip(output, statistics):
            target[prefix + "_mean"] = row["mean"]
            target[prefix + "_max"] = row["max"]
            target[completion_key] = row["completed"]
    return output
