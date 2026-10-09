"""Seeded, observed-success-conditioned interference sensitivity.

Observed--observed interference is deliberately excluded, including after a
modeled target time shift. Every other overlap compares fixed per-frame random
priorities. A frame loses if any directly overlapping competitor has higher
priority, even when that competitor itself loses elsewhere. Thus an isolated
pair has one survivor; a connected multi-frame chain can have several local
maxima. This is an uncalibrated capture assumption, not received-power physics.

The full authentication timeline may be memory mapped and grouped into sorted
runs. Query cohorts and competing-frame batches are bounded. A NumPy range-max
segment tree computes exact direct-overlap maxima without per-frame Python
loops, a global authentication sort, or a full authentication priority array.
Very dense coincident cohorts can require repeated competitor scans, but do not
increase transient memory beyond the configured chunk and observed/run metadata.
"""

from __future__ import annotations

import math

import numpy as np

FRAME_S = 120e-6
_CAPTURE_CHUNK = 1_000_000
_CAPTURE_BUCKET_S = 10.0
_PRIORITY_DOMAIN = 1 << 62


def _priority_key(seed):
    return np.random.SeedSequence(int(seed)).generate_state(1, dtype=np.uint64)[0]


def _priorities(indices, domain, key):
    """Unique SplitMix64 priorities, stable by frame domain and input index.

    SplitMix64 is a permutation of uint64, so distinct identities never tie.
    SeedSequence mixes arbitrary-sized seed integers into its fixed-width key.
    The domain allocation supports fewer than 2**62 frames of each kind.
    """
    values = np.asarray(indices, dtype=np.uint64)
    if len(values) and np.max(values) >= _PRIORITY_DOMAIN:
        raise ValueError("Capture frame indices must be below 2**62.")
    values = (values | np.uint64(domain * _PRIORITY_DOMAIN)) ^ key
    with np.errstate(over="ignore"):
        values = values + np.uint64(0x9E3779B97F4A7C15)
        values = (values ^ (values >> np.uint64(30))) * np.uint64(0xBF58476D1CE4E5B9)
        values = (values ^ (values >> np.uint64(27))) * np.uint64(0x94D049BB133111EB)
    return values ^ (values >> np.uint64(31))


def _chunks(slices, limit=None):
    """Materialize bounded (start, duration, identity) batches from sorted runs."""
    limit = _CAPTURE_CHUNK if limit is None else limit
    times, durations, identities = [], [], []
    count = 0
    for values, lengths, identity, first, last in slices:
        while first < last:
            stop = min(last, first + limit - count)
            times.append(values[first:stop])
            durations.append(np.full(stop - first, lengths) if np.isscalar(lengths)
                             else lengths[first:stop])
            identities.append(np.arange(first, stop, dtype=np.int64) if identity is None
                              else identity[first:stop])
            count += stop - first
            first = stop
            if count == limit:
                yield np.concatenate(times), np.concatenate(durations), np.concatenate(identities)
                times, durations, identities, count = [], [], [], 0
    if count:
        yield np.concatenate(times), np.concatenate(durations), np.concatenate(identities)


class _RangeMaximum:
    """Range-max updates followed by one propagation to ordered query leaves."""

    def __init__(self, query_times):
        self.times = query_times
        self.ends = query_times + FRAME_S
        self.ends -= 4 * np.spacing(self.ends)
        self.size = 1 << max(0, (len(query_times) - 1).bit_length())
        self.tree = np.zeros(2 * self.size, dtype=np.uint64)

    def add(self, starts, durations, priorities):
        ends = starts + durations
        ends -= 4 * np.spacing(ends)
        # q_end > c_start and q_start < c_end, with the same endpoint
        # tolerance as the channel's variable-duration interval model.
        left = np.searchsorted(self.ends, starts, side="right")
        right = np.searchsorted(self.times, ends, side="left")
        keep = left < right
        left, right, priorities = left[keep] + self.size, right[keep] + self.size, priorities[keep]
        while len(left):
            odd = (left & 1).astype(bool)
            np.maximum.at(self.tree, left[odd], priorities[odd])
            left += odd
            odd = (right & 1).astype(bool)
            right -= odd
            np.maximum.at(self.tree, right[odd], priorities[odd])
            left //= 2
            right //= 2
            keep = left < right
            left, right, priorities = left[keep], right[keep], priorities[keep]

    def values(self):
        first = 1
        while first < self.size:
            parents = self.tree[first:2 * first]
            children = self.tree[2 * first:4 * first]
            np.maximum(children[::2], parents, out=children[::2])
            np.maximum(children[1::2], parents, out=children[1::2])
            first *= 2
        return self.tree[self.size:self.size + len(self.times)]


class _AuthRuns:
    def __init__(self, starts, offsets):
        self.times = starts
        self.order = None
        if offsets is None:
            # Existing small callers need not provide run metadata. Production
            # supplies it and never creates this full-size sorting workspace.
            self.order = np.argsort(starts, kind="stable")
            self.times = starts[self.order]
            offsets = np.array([0, len(starts)], dtype=np.int64)
        self.offsets = offsets
        self.minimum = self.times[offsets[:-1]]
        self.maximum = self.times[offsets[1:] - 1]

    def slices(self, lower, upper):
        selected = np.flatnonzero((self.minimum < upper) & (self.maximum >= lower))
        slices = []
        for run in selected:
            first, last = int(self.offsets[run]), int(self.offsets[run + 1])
            times = self.times[first:last]
            left = first + int(np.searchsorted(times, lower, side="left"))
            right = first + int(np.searchsorted(times, upper, side="left"))
            if left < right:
                slices.append((self.times, FRAME_S, self.order, left, right))
        return slices


def _ordered(starts, durations, identities):
    order = np.argsort(starts, kind="stable")
    return starts[order], durations[order] if not np.isscalar(durations) else durations, identities[order]


def _observed_slice(part, lower, upper, maximum_duration):
    times, durations, identities = part
    # The unadjusted upper envelope is a conservative candidate selection;
    # _RangeMaximum.add applies exact endpoint overlap and tolerance.
    lower = np.nextafter(lower - maximum_duration, -math.inf)
    first = int(np.searchsorted(times, lower, side="left"))
    last = int(np.searchsorted(times, upper, side="left"))
    return times, durations, identities, first, last


def capture_masks(originals, auth, observed, durations, seed, offsets=None, original_indices=None):
    """Return interference-loss masks for targets and authentication frames.

    Baseline observed transmissions are conditioned on successful reception;
    only edges involving authentication compete. Original indices remain stable
    if a caller removes unsent targets from an augmented schedule.
    """
    original_loss = np.zeros(len(originals), dtype=bool)
    auth_loss = np.zeros(len(auth), dtype=bool)
    if not len(auth):
        return original_loss, auth_loss
    key = _priority_key(seed)
    original_indices = (np.arange(len(originals), dtype=np.int64) if original_indices is None
                        else np.asarray(original_indices, dtype=np.int64))
    runs = _AuthRuns(auth, offsets)
    # Original query identities address the returned mask; their random identity
    # separately remains the original source index in a shifted replay.
    original_part = _ordered(originals, FRAME_S, np.arange(len(originals), dtype=np.int64))
    observed_part = _ordered(observed, durations, np.arange(len(observed), dtype=np.int64))
    maximum_observed_duration = float(np.max(durations)) if len(durations) else 0.0

    def process(auth_slices, original_slice):
        # Query identities put originals immediately after authentication IDs.
        query_slices = list(auth_slices)
        times, lengths, ids, first, last = original_slice
        if first < last:
            query_slices.append((times[first:last], lengths, ids[first:last] + len(auth), 0, last - first))
        for query_times, _, query_ids in _chunks(query_slices):
            order = np.argsort(query_times, kind="stable")
            query_times, query_ids = query_times[order], query_ids[order]
            is_original = query_ids >= len(auth)
            own_priority = np.empty(len(query_ids), dtype=np.uint64)
            own_priority[~is_original] = _priorities(query_ids[~is_original], 1, key)
            own_priority[is_original] = _priorities(
                original_indices[query_ids[is_original] - len(auth)], 0, key)
            lower = float(query_times[0])
            upper = float(query_times[-1] + FRAME_S)
            lower_auth = np.nextafter(lower - FRAME_S, -math.inf)
            competing_auth = runs.slices(lower_auth, upper)
            auth_maximum = _RangeMaximum(query_times)
            for starts, lengths, identities in _chunks(competing_auth):
                auth_maximum.add(starts, lengths, _priorities(identities, 1, key))
            lost = auth_maximum.values() > own_priority
            original_loss[query_ids[is_original] - len(auth)] = lost[is_original]
            if np.any(~is_original):
                auth_queries = query_times[~is_original]
                observed_maximum = _RangeMaximum(auth_queries)
                candidates = [
                    _observed_slice(original_part, float(auth_queries[0]),
                                    float(auth_queries[-1] + FRAME_S), FRAME_S),
                    _observed_slice(observed_part, float(auth_queries[0]),
                                    float(auth_queries[-1] + FRAME_S), maximum_observed_duration),
                ]
                for domain, candidate in enumerate(candidates):
                    for starts, lengths, identities in _chunks([candidate]):
                        identities = original_indices[identities] if domain == 0 else identities
                        observed_maximum.add(starts, lengths, _priorities(identities, 0 if domain == 0 else 2, key))
                lost_auth = lost[~is_original] | (observed_maximum.values() > own_priority[~is_original])
                auth_loss[query_ids[~is_original]] = lost_auth

    def visit(lower, upper):
        slices = runs.slices(lower, upper)
        otimes, odurations, oids = original_part
        first = int(np.searchsorted(otimes, lower, side="left"))
        last = int(np.searchsorted(otimes, upper, side="left"))
        original_slice = (otimes, odurations, oids, first, last)
        count = sum(right - left for _, _, _, left, right in slices) + last - first
        if not count:
            return
        populated = slices + ([original_slice] if first < last else [])
        minimum = min(float(times[left]) for times, _, _, left, _ in populated)
        maximum = max(float(times[right - 1]) for times, _, _, _, right in populated)
        if count > _CAPTURE_CHUNK and minimum < maximum:
            midpoint = minimum + (maximum - minimum) / 2
            if midpoint <= minimum:
                midpoint = float(np.nextafter(minimum, maximum))
            visit(lower, midpoint)
            visit(midpoint, upper)
        else:
            process(slices, original_slice)

    maximum = max(float(np.max(auth)), float(np.max(originals)) if len(originals) else 0.0)
    step = max(_CAPTURE_BUCKET_S, maximum / 4096)
    count_bins = max(1, int(math.ceil(maximum / step)))
    for bucket in range(count_bins):
        visit(bucket * step, (bucket + 1) * step if bucket + 1 < count_bins else math.inf)
    return original_loss, auth_loss
