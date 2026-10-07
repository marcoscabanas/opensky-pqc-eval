# Methodology: real signatures with detached authentication

The study asks what happens when **real signatures are added to recorded ADS-B traffic**. Each ordinary message becomes eligible for transmission at its observed trace time; a retained copy is used for signing. A group can only be signed after all its members exist, but those members do not wait for signing before transmission. The receiver reads successfully received messages immediately and authenticates them later, after receiving and verifying the signature.

The final workflow is `signed_detached`. Two planned one-hour windows provide separate recorded traffic scenarios, preferably moderate and high traffic if the acquisition supports that distinction. They are not statistical repetitions. The data have not yet been acquired or evaluated. `config/full_window_a.json` and `config/full_window_b.json` keep their inputs and outputs separate; `config/full.json` is a convenience configuration for window A. The frozen 64-case development experiment remains a different, calibrated-size validation reference, not results of this study.

## Recorded traffic and comparison schedules

Two aligned inputs serve different purposes:

- The **target trace** contains the actual 112-bit DF17 messages to authenticate, aircraft addresses, deterministic IDs, and observation timestamps. Preprocessing sorts observations and preserves repeated message contents. Identical contents alone do not establish a duplicate reception.
- The **channel trace** includes all recorded 1090 MHz events during the target window and follow-up: target and non-target ADS-B, other Mode S traffic, and Mode A/C or undecodable activity if the acquisition actually records them. Each event has a start time and justified duration, and every target links to exactly one channel event.

Capture timestamps are availability proxies, not onboard sensor-generation timestamps. The model therefore estimates added transmission delay, not actual sensor-to-transmission latency or standards compliance. Record acquisition provenance, receiver coverage, timestamp precision, filtering, detection losses, event durations, and any handling of multiple receivers. A decoded-packet log does not establish complete physical RF coverage or recover undecodable transmissions. An adapter for the actual future acquisition format remains necessary. See [channel input](channel_trace.md).

Three schedules separate effects:

1. **Recorded baseline:** all recorded transmissions at their observed times, with no authentication.
2. **Detached signed replay:** each target becomes ready at its observed time and uses the modeled aircraft radio; authentication fragments share that radio. The target's original event is replaced by its modeled transmission, not counted twice. Non-target events retain their observed times and durations.
3. **Timing-matched control:** the same target times as the signed replay, with authentication frames removed. This isolates the fragments' RF effect from transmission-time shifts caused by radio contention.

Timing shifts can create reception gains as well as losses. The baseline-to-replay comparison describes the complete modeled effect; the timing-matched comparison describes the fragments' interference effect. A collision causes a modeled loss, not waiting for the channel to become clear: the radio scheduler does not implement carrier sensing or automatic retransmission.

## Real signatures and exact-count grouping

The study compares ECDSA P-256, ML-DSA-44, Falcon-512, and SLH-DSA-SHA2-128s. The code's historical label `FN-DSA-512` selects the `Falcon-512` backend, not a finalized FN-DSA implementation. These schemes do not all represent the same security category.

Groups are formed independently per aircraft with **exactly `k = 1, 5, 10, or 20` messages and no timeout**. A group becomes eligible for signing when its last member appears. Thus `k=1` means per-message signing, not instantaneous authentication. Earlier members of a larger group wait longer for authentication, but their ordinary transmission proceeds independently. An incomplete final group remains unsigned; **its ordinary messages still transmit**. Follow-up traffic does not supply new target members to complete it.

Each aircraft has a real keypair within a cached algorithm/group-size workload. The host signs explicitly encoded group context followed by the ordered original message bytes. Conceptually this is `Sign(context || message_1 || ... || message_k)`, rather than a signature over raw messages alone. The context binds aircraft, algorithm, session, group sequence, first/last source time, message count, key fingerprint, and association tags. For `k=20`, the 280 bytes of original messages are only part of the current signed input; the raw-only transcript belongs to the historical workflow.

The workload cache contains encoded signed objects and public keys, with integrity and cryptographic checks on reuse. It does not publish private keys. Actual signature lengths determine frame counts, including variable Falcon lengths. The same objects are reused across rates and channel cases; no development size calibration is used. An interrupted unfinished workload restarts from scratch, while completed workloads are reusable. Preserving the cache is necessary for exact reproduction because regenerating keys/signatures may change bytes or lengths.

## Fragment transport and pacing

The prototype encoding makes every byte of overhead explicit:

All integer fields use unsigned big-endian encoding. The context layout is:

| Offset within context | Field | Bytes |
| ---: | --- | ---: |
| 0 | Format/version marker `OA01` | 4 |
| 4 | Algorithm code | 1 |
| 5 | Aircraft ICAO address | 3 |
| 8 | Session identifier | 8 |
| 16 | Group sequence | 2 |
| 18 | First source timestamp, integer microseconds | 8 |
| 26 | Last source timestamp, integer microseconds | 8 |
| 34 | Message count | 2 |
| 36 | First 16 bytes of SHA-256 of the encoded public key | 16 |
| 52 | Ordered tags: first 8 bytes of SHA-256 of each original | `8*k` |

The signing input is this `52 + 8*k` context followed by `14*k` original bytes, totaling `52 + 22*k` bytes. The fragmented stream has a two-byte envelope-length prefix, this context, a two-byte signature-length field, and the actual signature. Each fragment prepends the two-byte group sequence and two-byte fragment index to three successive stream bytes; only the final fragment is zero-padded. [The encoder](../src/experiment/replay_transport.py) is the executable specification.

| Component | Bytes |
| --- | ---: |
| Signed context, including eight-byte association tags | `52 + 8*k` |
| Signature-length field | 2 |
| Actual signature | `s` |
| Stream-length field | 2 |
| Fragment header: group sequence and fragment index | `2 + 2` per frame |
| Stream data within a seven-byte ME field | 3 per frame |

Consequently, the stream has `56 + 8*k + s` bytes and requires `ceil((56 + 8*k + s) / 3)` authentication frames. The ordinary message bytes are signed but not retransmitted inside the authentication object. Each hypothetical 1090ES frame occupies 120 microseconds including its preamble. Overflow is rejected rather than silently wrapping identifiers.

The signature-only quantity `ceil(s / 7)` is reported as an **analytical lower bound**. It assumes all seven ME bytes are available for signature data and ignores all identification, association, and reassembly overhead. It is not an executable seven-byte-payload protocol or an alternative receiver experiment.

Every aircraft has one modeled radio shared by target messages and authentication fragments. Ready ordinary messages have priority. A frame already on air completes before the next starts, so an ordinary message can wait for the remainder of an authentication frame. Authentication fragment starts are paced at **`r = 10, 50, or 100` frames/s/aircraft**. These are experimental rates, not regulatory allowances or measured channel capacities. One copy is sent without acknowledgments, retransmissions, or error correction.

Changing `r` changes scheduling and offered traffic intensity, not the total required signature bytes. A higher rate can shorten fragment delivery in the absence of contention, but can also increase collisions; successful authentication need not improve monotonically. Required authentication traffic, traffic actually emitted within the target window, and follow-up transmissions are reported separately.

This transport is a research encoding without an allocated operational ADS-B type. Keys and session information are provisioned out of band. Credential distribution, key validation/rotation traffic, and protocol deployment compatibility are outside the model.

## Processing and channel model

Each aircraft has one FIFO signing worker. A complete group waits for any earlier signing jobs and then consumes its configured service time. Collection, signing, and signer backlog affect authentication availability; they do not gate ordinary transmission. A single FIFO verification worker is the receiver baseline. If verification is a bottleneck, separately labeled two- and four-worker sensitivity cases can examine that assumption; these are not included in the default matrix.

The host generates and verifies real cryptographic objects. **Simulated processing times come from published embedded benchmarks**, independently of the host's execution time. ECDSA uses a Cortex-M4 implementation measured at 64 MHz; the selected pqm4 cycle counts are converted using its 24 MHz benchmark clock. These are mixed reference configurations, with explicit provisional FN-DSA and SPHINCS+ proxies for Falcon and SLH-DSA. They are not measurements of a common target avionics computer. Fixed representative times omit execution-time variability, message-length effects, and some externally supplied operations. See [hardware references](hardware_profiles.md). Energy, memory, competing onboard tasks, and certified timing bounds require separate measurements.

Each pacing rate is evaluated under two channel settings: a collision-free control (`independent`) and destructive temporal overlap in one collision domain (`destructive_overlap`). The latter erases overlapping frames using recorded event durations. It omits received power, capture effects, geometry, propagation, and receiver diversity, so it is an interference sensitivity model rather than a calibrated RF predictor. Non-target events interfere at the receiver but do not reserve the modeled aircraft radio for other transponder services.

**No additional random erasure, timing jitter, or synthetic background traffic is applied.** Fixed cached bytes, processing times, and scheduling therefore give one deterministic replay per configuration. The technical seed value `1` is retained by the interface but does not produce stochastic repetitions or confidence intervals. Random seeds would matter only for a separately declared stochastic extension.

## Receiver outcomes and metrics

The receiver separately records ordinary reception, authentication-object reconstruction, availability of the required original bytes, admission to verification, and successful or failed verification. It associates messages from received bytes and signed tags, without sender trace IDs. Missing fragments, missing originals, or ambiguous repeated observations can prevent authentication. Real verification occurs only after modeled receiver service finishes, and never changes the original reception time.

Observation retention and timestamp matching are separate. Observations remain available for the full authentication horizon, but matching does not search that entire horizon for identical bytes. For source arrivals `a_i` in each aircraft's order, a conservative ordinary-transmission bound is `b_i = max(a_i + F, b_(i-1) + F)`, with `F = 120 microseconds`. An ordinary frame can wait for at most one active authentication frame when its queue is empty; a continuous ordinary backlog has priority. The receiver is supplied the global allowance `max(b_i + F - a_i) + receive_jitter + 1 microsecond` for matching signed source-time intervals to receptions. This input-derived bound is fixed across algorithms, group sizes, and fragment rates for the same trace; it uses no realized loss or hidden message-membership outcomes. The final microsecond covers timestamp encoding/rounding. Reports record the allowance and full retention time. This assumes a shared reference clock, not measured operational clock accuracy. Identical observations whose bounded intervals still overlap remain conservatively ambiguous.

Retain `t0` (reference availability), `t_tx` (modeled transmission), `t_rx` (successful reception), and `t_auth` (successful verification). Added ordinary delay is `t_tx - t0`; receiver authentication delay is `t_auth - t_rx`. Also report source-to-authentication delay, since received-message delay alone omits non-receptions.

| Question | Measurements |
| --- | --- |
| Was ordinary surveillance affected? | Transmission delay, reception fraction, paired gains/losses, timing-matched fragment interference, and same-aircraft update gaps. |
| What did authentication require? | Actual signature/object sizes, frame counts, total required airtime, emitted airtime, and the seven-byte signature-only lower bound. |
| Could processors keep up? | Collection delay, signer and verifier queue waits, service demand/utilization, and unfinished work. |
| Where did authentication stop? | Fragment reconstruction, missing originals/association, verification failure, successful verification, and each pending processing/transmission stage. |
| How much was authenticated and when? | Coverage over all targets and received targets; source- and reception-anchored threshold coverage; completed-case median and tail delays with failure/pending counts. |

Offered airtime sums frame envelopes divided by the target-window duration. It is additive load, not measured occupancy, and can exceed one when transmissions overlap. Augmented load uses actual target starts and unchanged non-target events; boundary shifts mean it is not automatically baseline load plus fragments.

## Fixed follow-up and incomplete work

The observation horizon is **predeclared as target-window end plus 600 seconds and frame completion**. This gives an isolated largest selected SLH-DSA group at the slowest rate enough time for approximately 319.065 seconds of signing, 2,691 fragments at 10/s, and 0.311 seconds of verification: about 588.5 seconds before queueing. This is a design rationale for a fixed cutoff, not a guarantee that an overloaded workload will finish.

Each window starts with empty authentication and transmitter queues. The experiment measures a finite workload introduced during that window; it does not assume a pre-existing steady-state authentication backlog. During follow-up, ordinary recorded traffic continues as interference, while new authentication work from outside the target cohort is excluded. These boundary conditions must accompany interpretations of backlog and late completion.

Channel recording must continue throughout the ten-minute follow-up, including final frame completion; otherwise late fragments would be given an artificially empty channel. Continued ordinary traffic interferes but creates no new authentication targets. Acquisition must provide that coverage, and missing coverage is rejected.

Work still waiting at the cutoff is pending, not permanently failed or expired. Incomplete target groups are separately unsigned. Threshold coverage includes only targets with enough source- or reception-anchored follow-up and reports excluded counts. Completion percentiles include successes only; no completions produces `null`, not zero delay. The cutoff is not adjusted after inspecting final outcomes. Any later sensitivity run uses a separately declared horizon and sufficient additional recorded channel data.

## Reproducibility and status

Each window has four algorithms × four group sizes × three pacing rates × two channel settings: **96 replay cases using 16 actual signed workloads**. Two windows therefore produce **192 cases and 32 workloads**, without treating windows or seed values as random repetitions. Hashes identify raw/canonical inputs, configurations, source files, benchmark profiles, and cached signed objects. Native cryptography is required. See [the command walkthrough](reproduction_commands.md) and [README](../README.md).

The existing sample has 133,565 DF17 observations, 417 distinct aircraft, and a 640.792-second span. Its frozen development results use calibrated sizes and exclude DF11 from interference. They validate that historical workflow, not the new full-channel study. Final acquisition, channel-format adaptation, execution, and analysis remain pending. Parallel offline execution, if used, changes experiment runtime rather than the number of modeled onboard or receiver processors.
