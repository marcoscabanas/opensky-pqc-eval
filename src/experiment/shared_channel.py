"""Paired RF reception sensitivity model for detached authentication replay.

All input times are relative transmission starts in seconds. Original and
authentication frames occupy 120 microseconds. Optional observed interfering
events retain their supplied durations. ``independent`` is a collision-free control;
``destructive_overlap`` puts every transmitter in one collision domain and
destroys every frame with any temporal overlap. Exact touching is permitted,
with a four-ULP floating-point tolerance at interval boundaries. Same-aircraft
overlaps in the observational sender proxy are retained and treated identically.

The all-destroy rule is deliberately pessimistic and uncalibrated. It models no
capture effect, received-power differences, propagation, decoding capabilities,
antenna geometry, or range. NASA's ATOS description motivates partial temporal
overlap as a collision and gives 120 us for long Mode S frames (pp. 4--5):
https://ntrs.nasa.gov/api/citations/20040171487/downloads/20040171487.pdf
That source does not validate this model's single-domain all-destroy assumption.

Baseline-only and baseline-plus-authentication use identical original-message
noise draws. Authentication uses a separate random stream. Gilbert-Elliott loss
uses a shared continuous-time two-state environment with exponential good/bad
holding times and a stationary initial state; conditional erasure draws are
independent by original/authentication index. Its transitions do not depend on
the number of transmitted frames. Exogenous loss does not remove an interferer.

Optional synthetic background is a homogeneous Poisson stream of 120-us frames
over [0, horizon), identical in the paired scenarios. It is a sensitivity input,
not measured Mode A/C/S traffic: short replies and events outside that window
are not synthesized. Observed interfering events are additional non-target RF
events; callers must exclude original frames already included in the replay.
Default zero background and no observed events leave uncaptured traffic unmodeled.
Masks cover whole frames even if they end beyond the horizon; the caller decides
whether those arrivals are observable before its replay deadline.
"""

from __future__ import annotations

import math

import numpy as np


FRAME_S = 120e-6
SOURCE_URL = "https://ntrs.nasa.gov/api/citations/20040171487/downloads/20040171487.pdf"
_DRAW_CHUNK = 1_000_000
_MAX_TRANSITIONS = 2_000_000


def _number(value, name, *, positive=False):
    if isinstance(value, bool) or not isinstance(value, (int, float, np.number)):
        raise ValueError(f"{name} must be a finite number.")
    value = float(value)
    if not math.isfinite(value) or value < 0 or (positive and value == 0):
        raise ValueError(f"{name} must be finite and {'positive' if positive else 'nonnegative'}.")
    return value


def _starts(values, name, horizon):
    try:
        result = np.asarray(values, dtype=np.float64)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be a one-dimensional sequence of finite times.") from exc
    if result.ndim != 1 or not np.all(np.isfinite(result)):
        raise ValueError(f"{name} must be a one-dimensional sequence of finite times.")
    if np.any(result < 0) or np.any(result > horizon):
        raise ValueError(f"{name} must lie within [0, horizon].")
    return result


def _check_aircraft(values, expected, name):
    if values is not None:
        try:
            count = len(values)
        except TypeError as exc:
            raise ValueError(f"{name} must have one identifier per frame.") from exc
        if count != expected:
            raise ValueError(f"{name} must have one identifier per frame.")


def _durations(values, starts):
    try:
        result = np.asarray(values, dtype=np.float64)
    except (TypeError, ValueError) as exc:
        raise ValueError("observed_durations_s must contain one finite positive duration per observed event.") from exc
    if (result.ndim != 1 or len(result) != len(starts)
            or not np.all(np.isfinite(result)) or np.any(result <= 0)):
        raise ValueError("observed_durations_s must contain one finite positive duration per observed event.")
    with np.errstate(over="ignore"):
        ends = starts + result
    if not np.all(np.isfinite(ends)):
        raise ValueError("Observed event end times must be finite.")
    return result


def _loss_parameters(loss):
    if not isinstance(loss, dict):
        raise ValueError("loss must be a dictionary.")
    kind = loss.get("kind", "iid")
    if kind == "iid":
        if set(loss) - {"kind", "probability"}:
            raise ValueError("Unknown independent-loss parameter.")
        result = {"kind": kind, "probability": _number(loss.get("probability", 0), "probability")}
        probabilities = [result["probability"]]
    elif kind == "gilbert_elliott":
        expected = {"good_loss", "bad_loss", "mean_good_s", "mean_bad_s"}
        if not expected <= set(loss) or set(loss) - expected - {"kind"}:
            raise ValueError("Gilbert-Elliott loss requires good_loss, bad_loss, mean_good_s, and mean_bad_s.")
        result = {"kind": kind, **{
            name: _number(loss[name], name, positive=name.startswith("mean_"))
            for name in expected
        }}
        probabilities = [result["good_loss"], result["bad_loss"]]
    else:
        raise ValueError("loss.kind must be iid or gilbert_elliott.")
    if any(probability > 1 for probability in probabilities):
        raise ValueError("Loss probabilities must lie in [0, 1].")
    return result


def _rng(seed, stream):
    # Named integer streams keep original draws invariant to authentication size.
    return np.random.Generator(np.random.PCG64(np.random.SeedSequence([seed, stream])))


def _burst_environment(parameters, seed, horizon):
    if parameters["kind"] != "gilbert_elliott":
        return np.empty(0, dtype=np.float64), False
    good, bad = parameters["mean_good_s"], parameters["mean_bad_s"]
    if 2 * horizon / (good + bad) > _MAX_TRANSITIONS:
        raise ValueError("Burst timing would exceed the supported transition count.")
    rng = _rng(seed, 2)
    initial_bad = bool(rng.random() < bad / (good + bad))
    state_bad, time = initial_bad, 0.0
    transitions = []
    while True:
        following = time + float(rng.exponential(bad if state_bad else good))
        if following > horizon:
            break
        if following <= time or len(transitions) >= _MAX_TRANSITIONS:
            raise ValueError("Burst timing exceeds supported precision or transition count.")
        transitions.append(following)
        time, state_bad = following, not state_bad
    return np.asarray(transitions, dtype=np.float64), initial_bad


def _noise_mask(starts, parameters, seed, stream, transitions, initial_bad):
    result = np.empty(len(starts), dtype=np.bool_)
    if parameters["kind"] == "iid" and parameters["probability"] in (0, 1):
        result.fill(bool(parameters["probability"]))
        return result
    rng = _rng(seed, stream)
    # Limit transient uniform/state arrays even for tens of millions of frames.
    for first in range(0, len(starts), _DRAW_CHUNK):
        last = min(first + _DRAW_CHUNK, len(starts))
        if parameters["kind"] == "iid":
            probability = parameters["probability"]
        else:
            states = np.searchsorted(transitions, starts[first:last], side="right") % 2
            if initial_bad:
                states = 1 - states
            probability = np.where(states, parameters["bad_loss"], parameters["good_loss"])
        result[first:last] = rng.random(last - first) < probability
    return result


def _collision_mask(starts):
    """Equal-duration intervals collide iff either adjacent sorted gap overlaps."""
    collisions = np.zeros(len(starts), dtype=np.bool_)
    if len(starts) < 2:
        return collisions
    order = np.argsort(starts, kind="stable")
    ordered = starts[order]
    # Equal interval lengths make adjacent comparisons sufficient, including
    # arbitrary chains and simultaneous starts; no pairwise matrix is needed.
    endpoints = ordered[:-1] + FRAME_S
    endpoints -= 4 * np.spacing(np.maximum(np.abs(endpoints), np.abs(ordered[1:])))
    overlaps = ordered[1:] < endpoints
    collisions[order[:-1][overlaps]] = True
    collisions[order[1:][overlaps]] = True
    return collisions


def _variable_collision_mask(starts, durations):
    """Flag overlapping intervals in O(n log n), including nested intervals.

    A sorted interval overlaps a later interval iff it overlaps the next start.
    It overlaps an earlier interval iff that start precedes the maximum earlier
    endpoint. Adjacent endpoints alone would miss intervals nested inside long
    transmissions. Boundary tolerance is applied before the prefix maximum so
    that a floating-point binade boundary cannot make the comparison nonmonotone.
    """
    collisions = np.zeros(len(starts), dtype=np.bool_)
    if len(starts) < 2:
        return collisions
    order = np.argsort(starts, kind="stable")
    ordered = starts[order]
    endpoints = ordered + durations[order]
    # All times are nonnegative. If an endpoint can overlap a later start, it
    # exceeds that start, so spacing(endpoint) is the pair's boundary tolerance.
    endpoints -= 4 * np.spacing(endpoints)
    follows = ordered[1:] < endpoints[:-1]
    precedes = ordered[1:] < np.maximum.accumulate(endpoints[:-1])
    collisions[order[:-1][follows]] = True
    collisions[order[1:][precedes]] = True
    return collisions


def evaluate_channel(
    original_starts, original_aircraft, auth_starts, auth_aircraft=None, *,
    loss: dict, seed: int, horizon: float, channel_mode: str = "destructive_overlap",
    background_frames_per_second: float = 0.0,
    observed_starts=None, observed_durations_s=None,
) -> dict:
    """Return paired, input-order reception and attribution NumPy boolean masks.

    Aircraft identifiers are checked for matching lengths but do not exempt any
    overlap from collision. They may be integer arrays; ``auth_aircraft=None``
    avoids allocating an identifier per fragment. Every returned frame mask has
    the length of its corresponding input. Background times are returned only
    as a compact float array for reproducibility. No input array is mutated.

    ``observed_starts`` and ``observed_durations_s`` must be supplied together.
    These events are additional non-target transmissions, identical in the paired
    scenarios, and must not duplicate retained original frames. Their durations
    may differ, including short replies. Counts and full-envelope offered airtime
    are reported when supplied; airtime is a sum, not overlap-adjusted occupancy.
    """
    horizon = _number(horizon, "horizon")
    background_rate = _number(background_frames_per_second, "background_frames_per_second")
    if isinstance(seed, bool) or not isinstance(seed, (int, np.integer)) or seed < 0:
        raise ValueError("seed must be a nonnegative integer.")
    seed = int(seed)
    if channel_mode not in {"independent", "destructive_overlap"}:
        raise ValueError("channel_mode must be independent or destructive_overlap.")
    originals = _starts(original_starts, "original_starts", horizon)
    auth = _starts(auth_starts, "auth_starts", horizon)
    observed_supplied = observed_starts is not None or observed_durations_s is not None
    if (observed_starts is None) != (observed_durations_s is None):
        raise ValueError("observed_starts and observed_durations_s must be supplied together.")
    if observed_supplied:
        observed = _starts(observed_starts, "observed_starts", horizon)
        observed_durations = _durations(observed_durations_s, observed)
    else:
        observed = np.empty(0, dtype=np.float64)
        observed_durations = np.empty(0, dtype=np.float64)
    _check_aircraft(original_aircraft, len(originals), "original_aircraft")
    _check_aircraft(auth_aircraft, len(auth), "auth_aircraft")
    parameters = _loss_parameters(loss)
    transitions, initial_bad = _burst_environment(parameters, seed, horizon)
    original_noise = _noise_mask(originals, parameters, seed, 0, transitions, initial_bad)
    auth_noise = _noise_mask(auth, parameters, seed, 1, transitions, initial_bad)

    background_rng = _rng(seed, 3)
    expected_background = background_rate * horizon
    if not math.isfinite(expected_background):
        raise ValueError("Background rate times horizon must be finite.")
    background_count = int(background_rng.poisson(expected_background)) if expected_background else 0
    background = background_rng.uniform(0, horizon, size=background_count)
    count_original, count_auth = len(originals), len(auth)
    if channel_mode == "independent":
        baseline_collisions = np.zeros(count_original, dtype=np.bool_)
        original_collisions = np.zeros(count_original, dtype=np.bool_)
        auth_collisions = np.zeros(count_auth, dtype=np.bool_)
    else:
        def collisions_for(targets):
            if not len(observed):
                return _collision_mask(np.concatenate((*targets, background)))
            starts = np.concatenate((*targets, background, observed))
            durations = np.full(len(starts), FRAME_S, dtype=np.float64)
            durations[-len(observed):] = observed_durations
            return _variable_collision_mask(starts, durations)

        baseline_collisions = collisions_for((originals,))[:count_original].copy()
        if count_auth:
            combined = collisions_for((originals, auth))
            original_collisions = combined[:count_original].copy()
            auth_collisions = combined[count_original:count_original + count_auth].copy()
        else:
            original_collisions = baseline_collisions.copy()
            auth_collisions = np.zeros(0, dtype=np.bool_)
    baseline_success = ~(original_noise | baseline_collisions)
    original_success = ~(original_noise | original_collisions)
    auth_success = ~(auth_noise | auth_collisions)
    added_losses = baseline_success & ~original_success
    assumptions = [
        "All modeled frames last 120 microseconds; temporal touching is allowed with a four-ULP boundary tolerance.",
        "Independent is a collision-free control; destructive_overlap destroys every overlapping frame in one collision domain.",
        "No calibrated RF capture, received power, range, geometry, propagation, or decoder model is claimed.",
        "Observed original transmissions may be reception samples; same-aircraft overlaps are retained, not repaired.",
        "Paired runs share original erasure draws and background frames; authentication erasure draws use a separate random stream.",
        "Exogenously erased frames still interfere because reception failure does not remove a transmission.",
        "Synthetic background uses only 120-microsecond Poisson frames within the horizon; missing Mode A/C/S traffic and window-edge traffic remain unmodeled.",
    ]
    if parameters["kind"] == "gilbert_elliott":
        assumptions.append("Gilbert-Elliott is a common continuous-time receiver environment with exponential holding times and stationary initial state; per-frame loss is sampled at transmission start.")
    if observed_supplied:
        assumptions[0] = "Original, authentication, and synthetic background frames last 120 microseconds; observed interfering events retain supplied durations. Temporal touching is allowed with a four-ULP boundary tolerance."
        assumptions[4] = "Paired runs share original erasure draws, observed interfering events, and synthetic background frames; authentication erasure draws use a separate random stream."
        assumptions[6] = "Synthetic background uses only 120-microsecond Poisson frames within the horizon and is separate from observed interfering events. Traffic absent from both inputs and window-edge traffic remain unmodeled."
        assumptions.extend([
            "Observed interfering events are additional non-target RF transmissions and must exclude originals already included in the replay; their reception or decodability does not remove interference.",
            "Offered airtime sums full event durations, including event ends beyond the horizon; it is not measured channel occupancy and overlapping durations are counted separately.",
        ])
    result = {
        "original_success_baseline": baseline_success,
        "original_success_with_auth": original_success,
        "auth_success": auth_success,
        "original_exogenous_loss": original_noise,
        "auth_exogenous_loss": auth_noise,
        "original_collision_baseline": baseline_collisions,
        "original_collision_with_auth": original_collisions,
        "auth_collision": auth_collisions,
        "additional_original_losses": added_losses,
        "background_starts": background,
        "summary": {
            "channel_mode": channel_mode, "frame_duration_s": FRAME_S,
            "original_frames": count_original, "auth_frames": count_auth,
            "background_frames": background_count, "background_frames_per_second": background_rate,
            "original_received_baseline": int(np.count_nonzero(baseline_success)),
            "original_received_with_auth": int(np.count_nonzero(original_success)),
            "auth_received": int(np.count_nonzero(auth_success)),
            "original_noise_losses": int(np.count_nonzero(original_noise)),
            "auth_noise_losses": int(np.count_nonzero(auth_noise)),
            "original_collision_losses_baseline": int(np.count_nonzero(baseline_collisions)),
            "original_collision_losses_with_auth": int(np.count_nonzero(original_collisions)),
            "auth_collision_losses": int(np.count_nonzero(auth_collisions)),
            "additional_original_losses_due_to_auth": int(np.count_nonzero(added_losses)),
            "additional_original_collisions_due_to_auth": int(np.count_nonzero(original_collisions & ~baseline_collisions)),
            "loss": parameters, "burst_initial_bad": initial_bad,
            "burst_transition_count": len(transitions), "seed": seed,
            "random_generator": "NumPy PCG64", "numpy_version": np.__version__,
            "source_urls": [SOURCE_URL], "assumptions": assumptions,
        },
    }
    if observed_supplied:
        observed_airtime = math.fsum(observed_durations)
        baseline_airtime = observed_airtime + (count_original + background_count) * FRAME_S
        result["observed_starts"] = observed
        result["observed_durations_s"] = observed_durations
        result["summary"].update({
            "observed_frames": len(observed),
            "observed_airtime_s": observed_airtime,
            "total_offered_airtime_baseline_s": baseline_airtime,
            "total_offered_airtime_with_auth_s": baseline_airtime + count_auth * FRAME_S,
        })
    return result


def evaluate_shifted_channel(
    original_starts, augmented_original_starts, original_aircraft, auth_starts, *,
    loss: dict, seed: int, horizon: float, channel_mode: str = "destructive_overlap",
    observed_starts=None, observed_durations_s=None,
    background_frames_per_second: float = 0.0,
) -> dict:
    """Compare a recorded baseline with originals delayed by the sender model.

    The two original arrays have identical lengths and message order. A NaN in
    ``augmented_original_starts`` means that message has not been transmitted by
    the horizon; all finite values must lie in [0, horizon]. Unsent messages are
    neither interferers nor RF losses. Their success masks are false, and their
    deferred masks are true. Full-frame reception may finish beyond the horizon:
    as in ``evaluate_channel``, the caller must apply its observation cutoff.

    Original-message uniform noise draws retain their original message indices
    across the pair, even when earlier messages are unsent. Gilbert-Elliott
    probabilities are evaluated at each scenario's actual transmission times in
    the same temporal environment. Thus shifting messages can both gain and lose
    reception. Paired losses measure the combined effects of sender deferral,
    timing changes, and authentication interference, not authentication collisions
    alone. Observed non-target events and synthetic background remain identical.
    No input array is mutated.
    """
    # Reuse the established validation, baseline, and seeded environment inputs.
    # With no authentication input, evaluate_channel sorts the baseline only once.
    baseline = evaluate_channel(
        original_starts, original_aircraft, (), loss=loss, seed=seed,
        horizon=horizon, channel_mode=channel_mode,
        observed_starts=observed_starts, observed_durations_s=observed_durations_s,
        background_frames_per_second=background_frames_per_second,
    )
    horizon = float(horizon)
    originals = np.asarray(original_starts, dtype=np.float64)
    try:
        shifted = np.asarray(augmented_original_starts, dtype=np.float64)
    except (TypeError, ValueError) as exc:
        raise ValueError("augmented_original_starts must contain one finite time or NaN per original.") from exc
    if shifted.ndim != 1 or len(shifted) != len(originals) or np.any(np.isinf(shifted)):
        raise ValueError("augmented_original_starts must contain one finite time or NaN per original.")
    transmitted = np.isfinite(shifted)
    if np.any(shifted[transmitted] < 0) or np.any(shifted[transmitted] > horizon):
        raise ValueError("Finite augmented_original_starts must lie within [0, horizon].")
    auth = _starts(auth_starts, "auth_starts", horizon)
    parameters = baseline["summary"]["loss"]
    transitions, initial_bad = _burst_environment(parameters, int(seed), horizon)
    # Never subset before drawing noise: doing so would change every later
    # message's uniform variate when an earlier message has not yet transmitted.
    noise_times = np.where(transmitted, shifted, originals)
    shifted_noise = _noise_mask(noise_times, parameters, int(seed), 0, transitions, initial_bad)
    shifted_noise &= transmitted
    auth_noise = _noise_mask(auth, parameters, int(seed), 1, transitions, initial_bad)

    shifted_collisions = np.zeros(len(originals), dtype=np.bool_)
    auth_collisions = np.zeros(len(auth), dtype=np.bool_)
    count_transmitted = int(np.count_nonzero(transmitted))
    if channel_mode == "destructive_overlap":
        parts = (shifted[transmitted], auth, baseline["background_starts"])
        observed = baseline.get("observed_starts")
        if observed is not None and len(observed):
            starts = np.concatenate((*parts, observed))
            durations = np.full(len(starts), FRAME_S, dtype=np.float64)
            durations[-len(observed):] = baseline["observed_durations_s"]
            collisions = _variable_collision_mask(starts, durations)
        else:
            collisions = _collision_mask(np.concatenate(parts))
        shifted_collisions[transmitted] = collisions[:count_transmitted]
        auth_collisions = collisions[count_transmitted:count_transmitted + len(auth)].copy()

    baseline_success = baseline["original_success_baseline"]
    shifted_success = transmitted & ~(shifted_noise | shifted_collisions)
    auth_success = ~(auth_noise | auth_collisions)
    added_losses = baseline_success & ~shifted_success
    gains = shifted_success & ~baseline_success
    baseline_collisions = baseline["original_collision_baseline"]
    assumptions = list(baseline["summary"]["assumptions"])
    assumptions[3] = "Recorded target times define the baseline; sender-model target times define the augmented scenario. Aircraft identifiers do not exempt same-aircraft overlaps from collisions."
    assumptions[4] = "Paired runs share original-index uniform erasure draws, the temporal loss environment, observed interfering events, and synthetic background; authentication erasure draws use a separate random stream. Shifted times can encounter different environment states."
    assumptions.extend([
        "Additional target reception losses and gains include sender timing shifts and authentication traffic; deferred targets are counted separately from RF losses.",
        "NaN augmented starts denote targets not transmitted by the horizon; these targets create no interference and have neither collision nor exogenous-loss flags.",
        "Success masks describe full-frame RF reception for frames starting by the horizon; the caller separately applies its reception-completion deadline.",
    ])
    summary = dict(baseline["summary"])
    # Keep the familiar summary names for callers that also consume the original
    # API, while exposing the differing original noise masks and deferred counts.
    # Here 'due_to_auth' names the entire authentication system, not RF alone.
    summary.update({
        "sender_timing_model": "shifted_original_transmissions",
        "auth_frames": len(auth),
        "original_frames_transmitted_with_auth": count_transmitted,
        "original_frames_deferred_with_auth": len(originals) - count_transmitted,
        "original_received_with_auth": int(np.count_nonzero(shifted_success)),
        "auth_received": int(np.count_nonzero(auth_success)),
        "original_noise_losses_baseline": int(np.count_nonzero(baseline["original_exogenous_loss"])),
        "original_noise_losses_with_auth": int(np.count_nonzero(shifted_noise)),
        "auth_noise_losses": int(np.count_nonzero(auth_noise)),
        "original_collision_losses_with_auth": int(np.count_nonzero(shifted_collisions)),
        "auth_collision_losses": int(np.count_nonzero(auth_collisions)),
        "additional_original_losses_due_to_auth": int(np.count_nonzero(added_losses)),
        "additional_original_losses_transmitted": int(np.count_nonzero(added_losses & transmitted)),
        "additional_original_losses_deferred": int(np.count_nonzero(added_losses & ~transmitted)),
        "original_reception_gains": int(np.count_nonzero(gains)),
        "net_original_reception_losses": int(np.count_nonzero(added_losses)) - int(np.count_nonzero(gains)),
        "additional_original_collisions_due_to_auth": int(np.count_nonzero(shifted_collisions & ~baseline_collisions)),
        "original_rf_losses_with_auth": int(np.count_nonzero(transmitted & ~shifted_success)),
        "paired_loss_attribution": "sender deferral, shifted target timing, and added authentication traffic jointly",
        "assumptions": assumptions,
    })
    result = {
        "original_success_baseline": baseline_success,
        "original_success_with_auth": shifted_success,
        "original_transmitted_with_auth": transmitted,
        "original_deferred_with_auth": ~transmitted,
        "auth_success": auth_success,
        "original_exogenous_loss": baseline["original_exogenous_loss"],
        "original_exogenous_loss_baseline": baseline["original_exogenous_loss"],
        "original_exogenous_loss_with_auth": shifted_noise,
        "auth_exogenous_loss": auth_noise,
        "original_collision_baseline": baseline_collisions,
        "original_collision_with_auth": shifted_collisions,
        "auth_collision": auth_collisions,
        "additional_original_losses": added_losses,
        "original_reception_gains": gains,
        "background_starts": baseline["background_starts"],
        "summary": summary,
    }
    if "observed_starts" in baseline:
        result["observed_starts"] = baseline["observed_starts"]
        result["observed_durations_s"] = baseline["observed_durations_s"]
        summary["total_offered_airtime_with_auth_s"] = (
            summary["observed_airtime_s"]
            + (count_transmitted + len(auth) + summary["background_frames"]) * FRAME_S
        )
    return result
