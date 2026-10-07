> Historical document. See [the archive index](README.md) and [current methodology](../methodology.md). Commands below describe the earlier workflow.

# Development sample: screening results and replay conditions

All **48 development replay cases** have completed. Under the supplied embedded
reference profiles and five-second authentication deadline, one-second bounded
batching improves the modeled timely fraction for ECDSA and Falcon relative to
large fixed-count batches. ML-DSA and SLH-DSA achieve no timely authentication
in these particular cases. These are conditional simulation results, not a
finding that either algorithm is impossible to use on aircraft.

These figures come from the saved
[screening report](../results/development/replay/constraint_screening_summary.json)
and its [CSV](../results/development/replay/constraint_screening_overview.csv).
The development trace contains **133,565 DF17 observations over 640.792 seconds**,
from 417 distinct aircraft. The aircraft count is an observed population, not
a count of simultaneous users of one receiver's channel. Trace observations are
used as sender arrivals; unobserved transmissions and collection losses remain
unknown. The trace SHA256 is
`783ec055bb2027bc3fed18d8d33d587d30fb865518bfe8781ecfc72d1cbeea41`.

Screening is deterministic. The completed operational replay uses one seed
(`1`) across three scenarios; that is a development execution check, not an
estimate with confidence intervals. The following percentages come from the
saved [replay report](../results/development/replay/replay_summary.json) and
[CSV](../results/development/replay/replay_overview.csv). Their denominator is
all 133,565 source observations, including lost originals and unsigned tails.
Success requires receiver reconstruction and modeled verification completion
before the oldest message's five-second deadline.

| Scenario | Algorithm | `k=1` | `k=5` | `k=10` | `k=20` |
| --- | --- | ---: | ---: | ---: | ---: |
| Fixed-count, IID 1% loss | ECDSA-P256 | 31.43% | 43.33% | 23.81% | 4.30% |
| Fixed-count, IID 1% loss | Falcon-512 | 0.92% | 0.44% | 0.00% | 0.00% |
| One-second bounded batch, IID 1% loss | ECDSA-P256 | 31.43% | 58.86% | 58.04% | 58.04% |
| One-second bounded batch, IID 1% loss | Falcon-512 | 0.92% | 1.56% | 1.45% | 1.47% |
| One-second bounded batch, burst loss | ECDSA-P256 | 31.03% | 71.96% | 71.81% | 71.81% |
| One-second bounded batch, burst loss | Falcon-512 | 3.07% | 4.90% | 4.91% | 4.86% |

All 12 ML-DSA cases and all 12 SLH-DSA cases have **0%** timely source
authentication. ML-DSA predominantly expires while transmitting: even its
smallest modeled authentication object needs 828 fragments, requiring over
eight seconds at the assumed 100 frames/second/aircraft. SLH-DSA transmits
**zero authentication frames**: its approximately 319-second reference signing
service exceeds the five-second deadline, with other groups waiting or
expiring during formation. Zero transmitted load in this case is computational
expiry, not a low communication cost.

Falcon's bounded-batch cases at `k=5,10,20` offer approximately **166.6% additional
airtime**, or **169.1% including the observed originals**. The simulator does
not turn that offered load into collisions or extra losses. Its nonzero timely
fractions under those conditions are therefore optimistic with respect to RF
delivery, and cannot establish a physically feasible shared-channel result.

Burst loss produces a higher timely fraction for several rows despite its
higher stationary mean loss. A plausible explanation is that losses cluster
into some failed objects while cleaner intervals preserve other objects in
full; independent losses spread missing fragments across more signatures.
Receiver queueing also changes when more objects survive. This is an
interpretation of one realization, not a demonstrated general advantage of
burst loss. Matched-mean loss scenarios and multiple seeds are needed to test
that explanation.

The completed figures show
[timely authentication (PNG)](../results/development/replay/figures/timely_authentication.png)
([PDF](../results/development/replay/figures/timely_authentication.pdf)) and
[offered airtime (PNG)](../results/development/replay/figures/offered_airtime.png)
([PDF](../results/development/replay/figures/offered_airtime.pdf)).

For 6,486 complete groups at `k=20`, the additional demand is:

| Algorithm | Signature size used | Raw-signature additional airtime | Full-format additional airtime | Full-format total including observed originals |
| --- | --- | ---: | ---: | ---: |
| ECDSA-P256 | Configured 64 bytes | 1.21% | 11.42% | 13.92% |
| ML-DSA-44 | Configured 2,420 bytes | 42.03% | 106.77% | 109.27% |
| Falcon-512 (`FN-DSA-512` result key) | Measured distribution; mean 655.064 bytes | 11.42% | 35.31% | 37.81% |
| SLH-DSA-SHA2-128s | Configured 7,856 bytes | 136.40% | 326.85% | 329.36% |

The original observations alone contribute **2.5012% offered airtime**. Each
frame contributes 120 microseconds. The raw lower bound allocates all seven ME
bytes to a signature. The full format adds 56 bytes per authentication object,
eight association bytes per original message, and four header bytes per
fragment, leaving three stream bytes per fragment. Its frame count is
`ceil((56 + 8*k + signature_bytes) / 3)`. Neither column includes repetitions,
credential transport or unobserved background traffic. Falcon totals sum actual
per-group lengths; its observed `k=20` sizes range from 647 to 664 bytes.

These percentages are offered frame-envelope demand over the observed span,
not measured RF occupancy. A value above 100% fails the assumed serial-channel
airtime budget for serving that entire offered workload; it does not show that
every PQC authentication architecture is impossible. Values below 100% are
also insufficient evidence of successful delivery. The large per-message
overhead matters even for the classical reference: at `k=1`, ECDSA's full-format
additional demand is **107.55%**, compared with a **25.01%** raw-signature bound.

Fixed-count batching introduces the following observed formation delays:

| Group size | Complete groups | Median first-to-last wait | 95th-percentile wait | Unsigned tail messages |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 133,565 | 0 s | 0 s | 0 |
| 5 | 26,549 | 1.746 s | 16.944 s | 820 |
| 10 | 13,177 | 4.058 s | 38.502 s | 1,795 |
| 20 | 6,486 | 8.735 s | 71.568 s | 3,845 |

These are group-weighted formation percentiles, before signing, transmission
or verification. At `k=20`, at least half the complete groups already exceed
the illustrative five-second oldest-message deadline while forming. The 3,845
unsigned tail messages are another 2.879% of the sample. A one-second batch
timeout addresses formation delay but creates more, smaller authentication
objects; its resulting traffic and authentication outcomes require the replay.

Screening counts the demand to transmit every complete group's authentication
object. Replay can transmit fewer frames because signing, queues or expiry
prevent work from reaching the radio. A lower replay airtime figure therefore
needs its failure outcomes alongside it; it does not automatically mean the
scheme became more efficient.

The supplied replay conditions are a five-second oldest-message age limit,
100 authentication frames per second **per aircraft**, one verification worker,
32 waiting signing jobs per aircraft, and 512 waiting verification jobs.
The scenarios compare fixed-count batching with independent 1% loss,
one-second bounded batching with that same loss, and bounded batching with a
shared Gilbert-Elliott loss process. All budgets are analyst assumptions.
The burst process has a stationary mean loss of approximately **2.476%**
(`(2 * 0.001 + 0.1 * 0.5) / 2.1`), so its comparison with 1% IID loss changes
both average loss and correlation. An experiment isolating burst correlation
must match average loss separately.

The [embedded hardware reference](hardware_profiles.md) combines an nRF52840
P-256 implementation at 64 MHz with Cortex-M4 PQ references at 24 MHz.
Falcon uses a provisional FN-DSA timing proxy; SLH uses a pre-standard SPHINCS+
proxy. These are different implementations from the project backends. Published
means or rounded estimates are repeated constants, not measured timing
distributions or worst-case execution times. Applying the composite profile
to verification represents a constrained embedded receiver, not a ground
server. Screening above has no hardware dependency; the timing qualifications
apply to the operational replay.

The replay has no RF collision/capture model or mapping from offered traffic
to loss. Its outcomes model reconstruction and CPU completion, not fresh
cryptographic verification of every simulated group. It also uses logical
fragment sets rather than exercising finite binary-reassembly buffers for each
group. The [experimental design](experimental_design.md) documents these
boundaries, the separately tested real cryptographic transport, and the
metrics to report with completed replay results.

Validation completed with **101 passing tests**, including real cryptographic
transport and tampering checks for all four installed algorithm backends.
Saved screening and replay reports passed input, source, parameter, JSON and
CSV integrity validation. Across all 48 cases, outcome counts match source
groups, original and authentication reception/loss totals balance, and
successful authentication ages remain within 5,000 ms. A separate 42-message
trace completed all 48 cases using the portable size calibration with no
signature-result files, checking that the later capture can be replayed
without regenerating every signature. These software checks validate the
implemented model; the simulated decisions remain distinct from those
separate real cryptographic tests.

The final one-hour evaluation should preserve the calibration, freeze the
scenario matrix and software, and use multiple seeds in separate result
directories. The configured full pipeline prepares and runs the new capture:

```sh
python -m src.pipeline --config config/full.json
python -m src.pipeline --config config/full.json --validate-only
```

That configuration imports the development
[size calibration](../results/development/replay/signature_size_profile.json),
so no exhaustive new Falcon or SLH signing run is required. It initially uses
the same one-seed development scenarios. Once the full trace and groups exist,
the following standalone command runs an explicit five-seed replication set;
the final seed count and scenario coverage still need to match the study's
precision requirements:

```sh
python -m src.experiment.replay_experiment \
  --trace data/full/processed/experimental_trace.jsonl \
  --groups-dir data/full/processed/authentication_groups \
  --algorithms-config config/algorithms.json \
  --size-profile results/development/replay/signature_size_profile.json \
  --hardware-profiles config/hardware_profiles.json \
  --scenarios config/replay_scenarios.json \
  --intervals 1 5 10 20 --seeds 1 2 3 4 5 \
  --output-dir results/full/replay-replicates --mode all
```

Append `--validate-only` to the same standalone command to check input,
configuration, source and artifact integrity without rerunning cases. Use a
new output directory for changed scenarios or explicitly replace stale outputs
with `--force`. Reusing the calibration means resampling an observed size
distribution; it does not claim signatures were generated or verified for the
one-hour trace. Follow the final measurement and reporting steps in the
[experimental design](experimental_design.md) before treating these development
conditions as paper evidence.
