# Complete observed 1090 MHz channel input

Each of the two planned one-hour study windows uses two aligned inputs: the DF17 messages selected for authentication and the complete observed 1090 MHz traffic used for interference. Filtering a message out of the authentication dataset must not remove its transmission from the channel baseline.

The baseline contains all observed channel events at their recorded times. In the final `signed_detached` workflow, each target ADS-B message becomes ready at its observed time and may wait for radio service; actual signature fragments share the modeled radio. Group formation and signing operate on retained copies and do not hold ordinary messages. Each target appears once in each schedule; its old recorded transmission is not retained as an extra interferer. All non-target traffic stays at its recorded times and durations. A further control uses the same delayed target schedule but removes authentication frames, isolating their RF cost from the timing shift. Only target ADS-B messages contribute to authentication coverage and surveillance reception metrics. Other transmissions include Mode S formats, Mode A/C replies, and undecoded events when their timing and duration were recorded. The relevance of both Mode S and Mode A/C interference is discussed in [NASA's ADS-B simulation study](https://ntrs.nasa.gov/citations/20040171487).

## Acquisition requirements

Use a defined receiver observation domain and preserve individual transmission times, durations, and capture coverage. Document the receiver(s), geographic coverage, timestamp convention and precision, message/pulse detection filters, acquisition losses, and any duplicate-reception handling. Normalize timestamps to frame **start** before replay. A network reception log containing only successfully decoded packets cannot demonstrate complete RF capture. Do not combine spatially separated receiver reports into one collision domain without a documented physical interpretation, or count multiple reports of the same emission as separate transmissions.

The channel input needs no decoded content or aircraft identity for a non-target event. Its `duration_s` must come from the recorded waveform or a documented message-format conversion. Do not assign 120 microseconds to every event simply because ADS-B and authentication fragments have that duration. The current interference model uses transmission envelopes; it does not resolve the pulses within a Mode A/C reply, received power, or capture effects.

Record the channel throughout the target evaluation window **and the authentication follow-up**. The predeclared follow-up is 600 seconds; allow at least 600 seconds plus frame completion beyond the final target. This cutoff accommodates an isolated largest selected SLH-DSA group at the slowest pacing rate, but does not guarantee that queues drain. No jitter is configured. Additional ADS-B observations during that period are channel interferers, not new authentication targets. Missing follow-up capture is rejected instead of interpreted as an empty channel. The input window begins at relative time zero; emissions starting before that boundary are not modeled, so document any acquisition margin and boundary treatment.

## Canonical JSONL format

The first nonempty line is a metadata object. Remaining lines each represent one observed transmission. This illustrative file matches a target trace containing observations 1 and 2 at relative times 0 and 1 second:

```jsonl
{"schema_version":1,"kind":"channel_trace","time_origin_timestamp":1700000000.0,"coverage_start_s":0,"coverage_end_s":602,"acquisition":{"receiver":"EXAMPLE ONLY","timestamp_convention":"frame start"}}
{"event_id":"event-1","relative_time_s":0,"duration_s":0.000120,"target_trace_id":1}
{"event_id":"event-2","relative_time_s":0.5,"duration_s":0.000064}
{"event_id":"event-3","relative_time_s":1,"duration_s":0.000120,"target_trace_id":2}
{"event_id":"event-4","relative_time_s":20,"duration_s":0.000120}
```

The example is a schema illustration, not an experimental dataset or a complete traffic claim.

- `time_origin_timestamp` is the same epoch used by the processed target trace: `timestamp - relative_time_s`. Its unit is seconds.
- `coverage_start_s` is zero. `coverage_end_s` declares how long recording continued, independently of the last event time. It must cover every replay scenario's horizon.
- Every `event_id` must be a unique nonempty string or integer. Repeated message contents alone are not grounds for removing an event.
- Each event supplies a nonnegative `relative_time_s` and a positive `duration_s` in seconds. Events need not be sorted.
- Every target `trace_id` must appear **exactly once** as `target_trace_id`, with matching time and a 120-microsecond duration. A missing, repeated, or unknown target link is rejected.
- Omit `target_trace_id` on all other traffic. Do not duplicate target transmissions as unlinked events. The loader checks the explicit links; it cannot identify an incorrectly relabeled duplicate without acquisition-level identity.
- Optional header `acquisition` and `provenance` values are preserved in results. Do not include private receiver credentials.

The loader validates alignment and declared coverage, not the completeness of the acquisition. Exporting this file from the future receiver/dataset will require an adapter for its actual format. The existing DF17 preprocessing command does **not** create a complete channel trace or recover transmissions missing from the source.

## Running the experiment

Complete [native cryptography setup](native_crypto.md), then prepare each target trace using the ordinary preprocessing workflow. For window A, supply the aligned channel file to the detached signed replay:

```bash
python -m src.experiment.signed_experiment \
  --trace runs/full/window_a/processed/experimental_trace.jsonl \
  --channel-trace data/full/window_a/raw/channel_trace.jsonl \
  --algorithms-config config/algorithms.json \
  --hardware-profiles config/hardware_profiles.json \
  --scenarios config/signed_replay_scenarios.json \
  --replay-model signed_detached \
  --output-dir runs/full/window_a/replay \
  --workloads-dir runs/full/window_a/signed_workloads \
  --intervals 1 5 10 20
```

Use the corresponding `window_b` paths for the second window. `config/full_window_a.json` and `config/full_window_b.json` select these paths; `config/full.json` is the window A convenience configuration. See [the complete two-window commands](reproduction_commands.md).

Replay forms exact-count groups without timeouts and generates/verifies actual signed objects before simulating delivery. It uses neither separate fixed-count group files nor the development signature-size calibration. Incomplete final groups remain unsigned but their originals still transmit. The cache is reused across pacing rates and channel settings. Preserve it because regenerating cryptographic keys/signatures can change bytes or lengths. Add `--validate-only` to inspect completed matching outputs without repeating replay.

There is no additional random loss, timing jitter, or synthetic background in the default study. Its single technical seed value does not create stochastic repetitions. The three pacing rates and two channel settings give 96 cases per window across the four algorithms and four group sizes.

Observed traffic cannot be combined with synthetic Poisson background in the same replay. Run separately labeled sensitivity cases for unobserved traffic. The `independent` control accepts and accounts for the channel input but deliberately ignores collisions; use `destructive_overlap` to study interference under the stated envelope model.

## Results and limits

Baseline offered airtime sums all recorded event durations whose starts fall within the target window, divided by that window's duration. The augmented load must use the **actually emitted, delayed target frames** plus authentication and unchanged non-target events. It is not necessarily baseline load plus authentication: some targets can be delayed into follow-up or remain unsent at the horizon. Authentication airtime and deferred ordinary work are therefore reported separately. These are additive offered loads, not the fraction of time the RF channel was occupied. Overlaps can make offered load exceed one.

Channel provenance records declared coverage and the source file hash. Event limits include the additional observed traffic. The original-baseline comparison measures the combined effects of delayed target transmission and signature traffic; shifted transmission times can create reception gains as well as losses. The timing-matched control isolates the added RF effect of the signature frames. Targets still waiting for radio service are not classified as radio erasures. Signing backlog delays authentication only; it never prevents ordinary eligibility in the detached model. Overlap losses do not cause carrier sensing, retransmission, or channel-induced waiting.

The current model measures target ADS-B reception and authentication; it does not quantify harm to other services. Each sender shares its modeled radio between target frames and authentication fragments, giving ready ordinary messages priority after any frame already on air finishes. Non-target events contribute receiver-side interference but do not reserve that sender's transponder. Scheduling other services on the same physical transponder, spatial interference, power, and receiver capture remain separate modeling work.

The frozen development results use the existing DF17-only baseline. They have not been relabeled as a complete-channel experiment. The two final windows and their acquisition provenance have not yet been supplied or evaluated.
