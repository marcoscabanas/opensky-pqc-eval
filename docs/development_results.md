# Development results: reception first, authentication later

The corrected development experiment completed **64 replay cases and 16 screening rows**, then ran again from the raw capture in a fresh environment containing only the pinned replay/plotting dependencies. All scientific rows matched the first run within the comparison tolerances. Source/input/report/CSV hashes and outcome conservation passed. The reference environment records the test counts at the time of that historical run; current test commands are in the main README. See the [reference reports](../results/reference/development/README.md) and [recorded environment](../results/reference/development/environment.json).

These are results for 133,565 observed DF17 messages over 640.792 seconds, followed by a 60-second drain period. They use one seed, hypothetical fragment/radio/loss settings, and composite published embedded timing references. They are not the final one-hour study or measured aircraft performance.

## Plain-language reading

The ordinary message arrives first and can be read. A separate authentication status remains pending while signature fragments and verification work are outstanding. Some signatures finish much later; some cannot be reconstructed after a fragment or original is lost. A short ordinary delivery delay therefore says little about authentication coverage.

In the independent-loss control, adding authentication does not change ordinary reception by definition. In the collision sensitivity case, extra frames can destroy ordinary receptions from other aircraft. The harm appears as lost updates and older available information even though the surviving frames still arrive promptly.

## One signature for five messages, independent reception control

All four algorithms receive **98.987%** of ordinary observations in this control. The table uses received originals as the authentication/pending denominator. The 60-second column is anchored at each message’s own reception; the horizon column allows early messages the remaining capture plus follow-up.

| Algorithm | Authenticated by horizon | Authenticated within 60 s of receipt | Received but pending at horizon | Completed-authentication p95 |
| --- | ---: | ---: | ---: | ---: |
| ECDSA P-256 | 55.5661% (73,465 messages) | 55.2212% | 0.000% | 8.743 s |
| Falcon-512 lineage | 6.8753% (9,090 messages) | 5.2272% | 12.034% | 257.687 s |
| ML-DSA-44 | 0.0038% (5 messages) | 0.0000% | 48.123% | 254.423 s |
| SLH-DSA-SHA2-128s | 0.0000% (0 messages) | 0.0000% | 93.532% | No completions |

ECDSA authenticates more than half of received messages in this setting. Falcon completes a smaller fraction, with some long waits. ML-DSA has only five completed messages here, so its successful p95 summarizes a tiny surviving population. SLH-DSA completes none by the horizon, while most received messages remain queued or otherwise unfinished. Zero completions does not imply permanent failure of every pending message.

The embedded SLH signing reference is approximately 319 seconds per operation. It is a pre-standard SPHINCS+ lineage proxy, not a measurement of the exact SLH implementation on an aircraft. The [hardware notes](hardware_profiles.md) explain that qualification. Fragment loss compounds with large signatures; queued work also remains even when some groups are already known to be unrecoverable.

## Congestion sensitivity for the same five-message groups

With destructive overlap, the paired ordinary-only baseline receives **97.225%**. Every case below uses the same baseline original noise and transmissions; only authentication traffic is added.

| Algorithm | Ordinary observations received with authentication traffic | Additional originals lost versus paired baseline | Authenticated / received by horizon |
| --- | ---: | ---: | ---: |
| ECDSA P-256 | 57.002% | 53,723 | 0.2233% |
| Falcon-512 lineage | 12.105% | 113,690 | 0.0000% |
| ML-DSA-44 | 2.408% | 126,642 | 0.0000% |
| SLH-DSA-SHA2-128s | 81.207% | 21,394 | 0.0000% |

The large losses demonstrate a modeled congestion risk, not a prediction that a real receiver will lose these exact percentages. This channel destroys every overlapping frame, ignores capture/power/geometry/diversity, and uses observed traffic as a proxy for emitted traffic. Excluded DF11 and unseen background traffic are absent. RF calibration is needed before translating this into an aircraft-channel claim.

SLH’s higher ordinary reception in this table is not evidence of a useful authentication system: the slow signing reference limits how much authentication traffic reaches the channel, and no messages finish authentication. All algorithms must be judged on reception, authentication coverage, and pending work together.

## A one-second batch timeout changes the tradeoff

At maximum `k=5`, the timeout creates **53,345 groups**, compared with **26,549 complete fixed-count groups**. Smaller batches form sooner but need more signatures. In the independent ECDSA case, authenticated coverage rises to **59.585%** and successful p95 after receipt falls to **1.571 seconds** (from 8.743). In the collision case, ordinary reception falls to **38.411%** (from 57.002%) because of the additional traffic.

For Falcon, timeout batching gives **6.270%** horizon authentication coverage and **296.917 seconds** successful p95 in the independent case. Faster group formation does not ensure faster completion when signing, radio service, loss, and verification queues dominate. These comparisons are specific to the supplied sample and assumptions.

## Figures and complete results

- [Authentication coverage (PDF)](../results/reference/development/figures/authentication_coverage.pdf): reception-anchored delay thresholds, `k=5`.
- [Ordinary reception impact (PDF)](../results/reference/development/figures/surveillance_impact.pdf): all four algorithms and `k=1,5,10,20`.
- [Separate clocks and pending work (PDF)](../results/reference/development/figures/authentication_clocks_and_pending.pdf): conditional delays alongside full outcome fractions.
- [All replay rows (CSV)](../results/reference/development/replay_overview.csv) and [full report (JSON)](../results/reference/development/replay_summary.json).

SVG/PNG versions and a figure-integrity manifest are saved beside the PDFs. The [README](../README.md) gives exact reproduction commands. The comparison checker validates the complete matrix and all numerical fields, rather than only the selected examples above.

## What remains before a deployment conclusion

Ordinary added transmitter delay is zero by construction: the model assumes original surveillance has priority and signing does not block it. It does not establish actual onboard measurement-to-transmission compliance or CPU isolation. Conditional ordinary frame delivery is 120 microseconds here, but this is not a measured end-to-end surveillance latency.

The next experiment needs the real one-hour capture and acquisition record, more seeds, RF-calibrated loss/interference, measured exact-transcript hardware timings, realistic queue/memory limits, and an explicit application policy for unauthenticated observations. Retain separate reception and authentication measurements throughout. See [methodology](methodology.md) for the complete assumptions.
