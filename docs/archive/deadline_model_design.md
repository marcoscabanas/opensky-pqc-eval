> Historical document. See [the archive index](README.md) and [current methodology](../methodology.md). Commands below describe the earlier workflow.

# Detached ADS-B authentication experiment

The implemented comparison has two modes: one signature per surveillance
message (`k=1`) and one signature per sender-formed batch (`k=5,10,20`). Original
surveillance emissions retain their trace timestamps. Authentication follows
in separate hypothetical frames. No sign-before-transmit mode is evaluated.

## Evidence and workflow

The development capture is a software-validation sample, not the final study.
Its 133,565 DF17 observations span about 640.792 seconds. Observations are used
as a proxy for sender emissions; capture losses, duplicate reception reports,
uncaptured aircraft and other Mode S traffic cannot be reconstructed from it.
The 417 distinct aircraft are not a simultaneous traffic-density measurement.

`config/development.json` now runs capture analysis, preprocessing, grouping,
analytical screening and replay. `config/full.json` uses the same stages for
the eventual one-hour capture. Exhaustive cryptographic generation remains
available with `--stage signatures`; the separate recovery configuration keeps
its original signing and feasibility workflow and resumable private keys.

```sh
python -m src.pipeline --config config/development.json
python -m src.pipeline --config config/development.json --validate-only
python -m src.experiment.plot_replay --results-dir results/development/replay \
  --output-dir results/development/replay/figures
```

The pipeline lock prevents overlapping pipeline invocations. While the recovery
signer is running, the independent replay command can read its **completed**
Falcon files without touching its checkpoints or launching another signer:

```sh
python -m src.experiment.replay_experiment \
  --trace "$PWD/data/development/processed/experimental_trace.jsonl" \
  --groups-dir "$PWD/data/development/processed/authentication_groups" \
  --algorithms-config "$PWD/config/algorithms.json" \
  --signatures-dir "$PWD/results/development/recovery/signatures" "$PWD/results/development/signatures" \
  --hardware-profiles "$PWD/config/hardware_profiles.json" \
  --scenarios "$PWD/config/replay_scenarios.json" \
  --output-dir "$PWD/results/development/replay" --mode all
```

Add `--validate-only` to audit hashes, parameters and output integrity without
recomputing. Stale results require an explicit `--force` or a new output directory.
Use the repository root as the working directory; absolute input paths match
the pipeline's provenance representation.
Each replay case prints progress. A result is published only after every case
finishes; exceeding the event limit fails without publishing a partial report.

## Screening before simulation

Screening reports two costs for complete fixed-count groups: a raw-signature
lower bound with all seven ME bytes available, and the cost of the explicit
illustrative transport below. Frame airtime is 120 microseconds (112 bits plus
an 8-microsecond preamble at 1 Mbit/s). Added airtime is the sum of transmitted
frame envelopes divided by trace duration, not measured RF occupancy. Values
above 100% are retained; lower values do not establish channel feasibility.

ECDSA, ML-DSA and SLH-DSA use configured fixed signature sizes. Falcon uses a
validated empirical frequency distribution, never an assumed fixed 666 bytes.
Screening exports a hashed `signature_size_profile.json` with algorithm identity,
distribution counts, and calibration provenance. The full configuration imports
this development calibration, so a one-hour trace does not require millions of
new signatures. The imported distribution is a modeling input, not evidence
that signatures on that trace have been generated or verified. Recalibrate if
the implementation/encoding changes; repeat a representative real-crypto sample
using the exact transcript and message sizes before final publication.

## Sender and receiver model

Each aircraft has a serial signing processor, bounded signing queue and FIFO
authentication transmitter. The authentication frame budget applies **per
aircraft**. Existing surveillance frames have priority on that aircraft's radio.
A separate receiver has a bounded verification queue and a configurable worker
count. CPU service times come from explicit sender and receiver profiles.
Queueing, batch formation, serialization, losses, reconstruction and verification
all contribute to authentication age. Deadlines apply to the oldest message in
each group; in-progress CPU work is not preempted at expiry. Expired queued work
releases capacity. Sender repetitions continue without receiver acknowledgments.

Fixed-count batching leaves incomplete tails unsigned. Bounded batching closes
at `k` messages or `max_batch_wait_s`, including a final timeout after capture.
Groups form at the sender before loss. The receiver only sees surviving original
messages and completed authentication metadata. It reconstructs from raw bytes,
time windows and association tags, without source trace IDs or group membership.
Successful acceptance consumes the corresponding observed occurrences; missing,
ambiguous, stale and repeated groups do not count as authenticated.

Loss is either independent Bernoulli reception loss or a time-based two-state
Gilbert-Elliott process shared by the modeled receiver. Both original and added
frames are subject to loss. Fragment repetitions cost additional airtime. There
is no RF collision, propagation, capture-effect or interference simulation, and
no mapping from offered load to packet loss. Background load is additive reporting
only. At high aggregate offered load these assumptions are optimistic; do not
interpret a high modeled success fraction as evidence of physical feasibility.

The supplied scenarios use an illustrative five-second authentication-age
budget, 100 added frames/second/aircraft, fixed-count or one-second-bounded
batching, and independent or burst loss. These are sensitivity assumptions,
not regulatory allocations. The default one seed validates execution; it
cannot supply confidence intervals. Set `--seeds 1 2 3 4 5` and a fresh output
directory for independent replications. Published timing means are constants,
so replay percentiles describe modeled traffic/queueing variation rather than
measured cryptographic timing tails.

## Explicit illustrative transport

The binary prototype uses a 52-byte signed descriptor: version/magic, aircraft
address, session, group sequence, first/last time, message count and key
fingerprint. It adds eight-byte SHA-256 association tags per original message,
a two-byte signature length, the signature itself, and a two-byte stream length.
Each seven-byte fragment contains a two-byte sequence and two-byte fragment
index, leaving three bytes for this stream. For `m` originals and an `s`-byte
signature, the required frames are `ceil((56 + 8*m + s) / 3)` before repetition.
For example, a 64-byte ECDSA signature covering one message needs 43 frames.

This defines measurable byte costs, not an allocated ADS-B message type or an
avionics-compatible extension. Sequence numbers are limited to 65,535 groups
per aircraft/session and encoded objects to 65,535 bytes; overflow fails. A
longer study would need explicit session rotation if those limits are exceeded.
Keys, identities and sessions are provisioned out of band; credential transport,
revocation and key discovery costs are absent. Shared clocks and bounded
reception jitter are assumed. Short tags support association, while signature
verification covers the complete context and original message bytes.

The real cryptographic prototype signs that context plus the originals. This
is a documented new transcript: legacy signatures cover only concatenated
original messages, so they cannot authenticate session, freshness or grouping
metadata. Legacy results remain intact and provide size calibration only.
Tests exercise real binary fragmentation, receiver reconstruction, successful
verification and signature tampering for all four installed implementations.

The large replay uses fragment counts and sampled sizes, with a clearly labeled
modeled verification decision after reconstruction and CPU service. It does not
generate or cryptographically verify a new signature per replay group. This
keeps traffic sweeps independent of exhaustive signing cost while preserving
the distinction between executable protocol tests and simulated outcomes.
The event simulator tracks logical fragment sets rather than running the binary
reassembler for each group. It does not measure reassembly-buffer capacity or
receiver expiry before the full descriptor is known. Binary-parser and buffer
behavior belong to the separate protocol tests; resource-exhaustion conclusions
would require extending the replay to exercise those limits explicitly.

## Hardware and paper interpretation

[Hardware profiles](hardware_profiles.md) document pinned published embedded
references. The composite combines platforms; provisional FN-DSA and SPHINCS+
measurements are explicit proxies for project Falcon and SLH-DSA. Sender and
receiver profiles are independent; using the composite receiver represents an
embedded receiver, not a ground server. Results include these qualifications.

The paper should report timely authenticated fractions over both source and
received observations, unsigned tails, failure outcomes, conditional successful
authentication-age percentiles, CPU/queue demand, and added offered airtime.
Compare fixed-count and timeout batching. Show the entire success/failure mix
alongside latency: low conditional latency alone can hide near-total failure.

Before the one-hour run, freeze the scenario matrix and software versions. Use
several seeds, authentication deadlines, radio budgets and receiver capacities
in separate result directories. Preserve calibration and capture hashes. Then
replace the sample capture at the configured full-data path and run:

```sh
python -m src.pipeline --config config/full.json
python -m src.pipeline --config config/full.json --validate-only
```

Multiprocessing can later shorten independent replay replications or offline
signature generation. It must not be interpreted as faster airborne execution.
For signing it needs worker-owned keys and native contexts, bounded tasks,
deterministic output ordering, and parent-owned durable checkpoints. Current
signing remains serial and resumable; signature-size reuse removes it from the
critical path for operational sweeps. A target-aircraft conclusion additionally
needs measurements of the exact implementation/transcript, memory and energy,
worst-case timing, integration constraints and key-management costs.

## Draft corrections and sources

- Describe ECDSA as a classical comparison baseline, not deployed ADS-B authentication.
- ML-DSA-44 is security category 2, so this set is not uniformly category 1:
  [FIPS 204, Table 1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf).
- Label the actual Falcon-512 backend explicitly. As checked on 2026-10-06,
  [NIST's selected-algorithms page](https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization/selected-algorithms)
  still lists its FIPS as forthcoming. Avoid claiming finalized FN-DSA conformance.
- Regulatory ADS-B Out transmission latency is distinct from this experiment's
  authentication-age budget:
  [14 CFR 91.227](https://www.ecfr.gov/current/title-14/chapter-I/subchapter-F/part-91/subpart-C/section-91.227).
- Frame/ME structure and waveform timing references:
  [ICAO technical guide](https://www.icao.int/SAM/Documents/SAMIG11/SAMIG11_NE06Rev2.pdf),
  [FAA-hosted waveform presentation](https://www.faa.gov/sites/faa.gov/files/2021-12/Drummond-FAAAvianRadar-Jan212016.pdf).

The draft PDFs are retained unchanged. These notes describe the implemented
methods and corrections for the next editable manuscript revision.
