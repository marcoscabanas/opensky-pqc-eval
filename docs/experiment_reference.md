# Experiment reference

[Return to the reproduction guide](../README.md) · [Read the code map](../src/README.md)

This reference holds the acquisition details, scientific assumptions, resource notes and figure definitions. Follow the root README to reproduce the published experiment; use the new-recording instructions below only when conducting a separate study.

The completed experiment contains 240 replay cases per window, 480 total, and 5,678,094 verified signatures across 24 signed workloads using ECDSA P-256, ML-DSA-44 and Falcon-512. The daytime target cohort contains 752,053 first-hour DF17 messages from 798 aircraft; nighttime contains 651,084 from 412 aircraft. SLH-DSA has implementation tests and a separate analytical/diagnostic assessment, but no completed full-window replay matrix.

## Restoration and reproduction troubleshooting

The root README describes two workflows pairing software tag [`v1.0.0`](https://github.com/marcoscabanas/opensky-pqc-eval/tree/v1.0.0) with the artifacts uploaded under Zenodo DOI [10.5281/zenodo.23652076](https://doi.org/10.5281/zenodo.23652076). The tag preserves the exact archived files; the default branch can contain later documentation updates. `scripts/restore_artifacts.py` reads the download directory's `artifact_manifest.json`, checks the checkout against its code-file inventory, and restores the selected data without replacing the software. The recording manifest, `data/manifest.json`, is part of that checked GitHub release. Fresh restoration needs only the two raw recordings and artifact manifest; `metadata-and-results.zip` is additionally needed for the subsequent reference comparison. The code snapshot ZIP is an optional preservation copy; a GitHub checkout does not need to download it. Use this matched release rather than mixing files from different versions.

Zenodo labels the published dataset **v1**. Its frozen files still refer to `v0.1.0`, including the code ZIP filename and package metadata. The GitHub `v1.0.0` tag is an additional name for the exact same archived commit; the original `v0.1.0` tag remains valid. Neither the archive nor its checksums need changing.

| Situation | What to do |
| --- | --- |
| Unsure which files are needed | Run `python3 scripts/restore_artifacts.py --artifacts-dir ../zenodo-downloads --profile replay --dry-run` (or `fresh`). The preview checks the software and lists the required downloads without requiring the data files themselves. |
| Missing download or checksum mismatch | Download the named file from the matching deposit version. Do not rename a different file to satisfy the inventory or edit the manifest to bypass a mismatch. |
| Checkout does not match the archived code | Use a clean checkout of the release named by the artifact manifest. Keep development changes in a separate clone. Both workflows start from matching software even when generating new signatures. |
| Restoration was interrupted | Repeat the same command and profile. Matching restored files are reused; differing files are refused. An interrupted restoration is different from an interrupted experiment. |
| Restore refuses existing experiment outputs | Use a fresh clone for a new reproduction. Restoration is for placing inputs before a run; resume an interrupted experiment with its original experiment command instead. |
| Replay reports missing prepared inputs or signatures | Workflow A requires the `replay` restore profile. Workflow B starts with raw recordings and runs the complete pipeline, not `--stage replay` alone. |
| Want to check every downloaded deposit file | Run `python3 scripts/restore_artifacts.py --artifacts-dir ../zenodo-downloads --verify-only`. This requires the complete deposit, including its optional code snapshot and documentation, whereas profile restoration checks only the files it needs. |
| Reference comparison differs after fresh signing | Inspect the reported numerical and metadata differences. New keys and signatures change workload identities, and Falcon lengths can also change fragment counts and simulated outcomes. Use the saved-signature workflow for agreement with the frozen reference inputs. |

After a run, `--validate-only` checks the local pipeline's integrity; `scripts/08_compare_reference.py` separately compares generated numerical tables with verified archived tables. Neither command proves physical realism. Reference comparison leaves files unchanged and requires `metadata-and-results.zip` plus its matching manifest in the download directory. Integer counts are compared exactly; floating-point values use relative and absolute tolerances of `1e-9`. Case and CSV column order do not matter. A missing metric remains missing, not zero. Compare a separate fresh-signing run as a new realization of the procedure, not as an expected byte-for-byte copy of the reference experiment.

Download sizes are about 13.14 GB for saved-signature replay and 2.52 GB for fresh signing, excluding an optional code snapshot. An ordinary copy-based replay restoration needs about 26.3 GB for downloads and restored artifacts together, before the Python/native environment and new output or temporary files. The original signature caches occupy about 8.96 GB across both windows; fresh signing will also need substantial storage. No fixed completion time or RAM requirement is promised: these depend on hardware, cryptographic implementation, concurrent signing workers and the selected scenarios.

## Recorded inputs and optional new recordings

**For paper reproduction, restore the supplied recordings and manifests unchanged.** The metadata-entry examples below apply to a new recording, not to the archived daytime/nighttime study. Changes to inputs, configuration or scientific source files change the experiment identity and can invalidate cached outputs.


The workflow expects recordings at:

```text
data/daytime.jsonl
data/nighttime.jsonl
```

You can run daytime independently before nighttime is available. Do not replace an input under an existing completed run and assume its old outputs still apply: checksums will reject that reuse.

Each recording covers **70 minutes**:

- `[0, 3600)` seconds: DF17 messages selected for authentication, with all other recorded traffic retained as interference.
- `[3600, 4200)` seconds: recorded traffic continues as interference while authentication work from the first hour may complete. These later DF17 messages do not join the signed target cohort.
- At 4200 seconds, only completed receptions and verification count. Work or frame reception still in progress remains pending; no extra unrecorded channel time is invented.

The first and last observed messages do not establish when recording started or stopped. For a new recording, fill in `data/manifest.json` using acquisition metadata. For Unix timestamps, a window entry has this form (the `null` values are placeholders you must replace):

```json
{
  "status": "available",
  "timestamp_mode": "unix_seconds",
  "recording_start": null,
  "recording_end": null,
  "source": null,
  "observation_domain": null
}
```

Set the numeric end to the actual capture end, normally `recording_start + 4200`. `source` identifies the dataset/export; `observation_domain` describes the receiver or geographic selection. For timestamps already measured in seconds from the recording start, use `"timestamp_mode": "relative_seconds"`, `"recording_start": 0`, and `"recording_end": 4200`. Never label absolute timestamps as relative or infer missing coverage from silence.

### Supported input format

The current adapter accepts one Mode S frame per nonempty JSONL line:

```json
{"timestamp": 1700000000.125, "raw_msg": "8D40621D58C382D690C8AC2863A7"}
```

`timestamp` is numeric seconds in the declared time system. `raw_msg` is exactly 14 hexadecimal characters for a short frame or 28 for a long frame. Optional integer `df` and DF17 `icao` fields must agree with the encoded bits. The adapter derives DF and the DF17 address when absent. Every supplied DF is retained, including DF0, DF4, DF11, DF17, DF20 and DF21; only first-hour DF17 frames are signing targets.

The supplied daytime export matches this JSONL schema, but its timestamps failed the acquisition audit described in `results/daytime/input_audit.json`. Schema compatibility alone does not establish usable radio timing. For future formats, add an explicit adapter preserving the original recording and its provenance before running step 01. Unsupported or malformed rows currently stop preparation, rather than silently removing channel interference. This adapter does not handle undecoded RF pulses or non-Mode-S formats, check CRCs, or deduplicate observations from multiple receivers. Those acquisition properties must be documented; recorded frames do not prove that every real-world 1090 MHz transmission was captured.

### Current recordings: conditional simulation

Both recordings used the TU Delft Faculty of Aerospace Engineering rooftop receiver. The daytime recording was made on October 8, 2026 at approximately 09:30–10:40; the nighttime recording was made on October 8 at approximately 23:00 through October 9 at 00:10, local Netherlands time. These dates were confirmed by the dataset provider. The original command was (substitute `nighttime.jsonl` for the second recording):

```bash
uvx --with pyModeS modes live --network airsquitter.lr.tudelft.nl:10004 --dump-to daytime.jsonl
```

The matching cached pyModeS 3.6.0 implementation re-anchors each TCP burst to the computer's wall clock, discards original receiver counters in the JSONL export, and skips Mode A/C replies. [Network-reader source](https://github.com/junzis/pyModeS/blob/main/src/pyModeS/cli/_source.py). The local audit stores the exact source hashes and version evidence. This affects cross-burst radio timing, even though individual JSONL timestamps contain many decimal places. Sorting cannot recover the omitted receiver counters.

The issue is varying delay between network batches, not a constant delay through the VPN. For example, consider two modeled 120-microsecond frames that really start 250 microseconds apart: they do not overlap. If separate batch-clock adjustments make their recorded starts appear only 100 microseconds apart, the replay would infer an overlap that did not occur. This is an illustration, not a measurement of this recording's timing error. Accurate spacing within a batch does not restore the missing spacing between batches.

The file remains useful for recorded DF counts, message contents and the signing workload. The current simulation uses its supplied timestamps as an explicit assumption; the resulting collision percentages do not establish what would happen when adding signatures to the original radio timeline. Step 01 also produces the cumulative figure. The acquisition concerns remain in `experiment_blockers` in `data/manifest.json`. The default `analysis_mode` in `config/experiment.json` is explicitly `conditional_recorded_timing`, which permits this scoped simulation and carries these limitations into the saved replay identity and figure labels. Setting it to `validated_recording` prevents replay while those acquisition concerns remain. Neither mode changes the raw observations or repairs missing receiver timing.

The archived [daytime audit](../results/daytime/input_audit.json) and [nighttime audit](../results/nighttime/input_audit.json) preserve recording checksums, format and timestamp checks, and acquisition limitations. These historical evidence files are not required to execute the pipeline and are not regenerated by the normal workflow. Use `01_prepared/traffic.json` and `manifest.json` for final experimental counts: the daytime audit's explicitly provisional counts used an earlier window boundary. The audits are supplied with the Zenodo artifacts, not the code-only clone.

### Optional: preserve original receiver timing in a new recording

This step is not needed to reproduce the paper. If the original raw Beast stream is available, preserve it: it may avoid another recording. Otherwise, connect to the TU Delft VPN and run this **instead of the decoded JSONL dump**:

```bash
python scripts/00_capture.py --output data/daytime_receiver.beast
```

This records unmodified bytes from `airsquitter.lr.tudelft.nl:10004` for **4,260 seconds (71 minutes)**, plus a `.beast.json` metadata sidecar. The extra minute provides acquisition padding; the experiment still selects exactly 60 minutes plus 10 minutes of follow-up. The recorder never overwrites an existing file. Interrupted, disconnected or empty captures are marked incomplete. It does not filter receiver frame types or substitute computer-clock timestamps for receiver counters.

The recorder preserves only what the receiver exports; it cannot guarantee that Mode A/C export is enabled, recover undecoded RF energy, or establish complete physical spectrum occupancy. The sidecar's host start/end clocks describe the network recording, not individual RF reception times. After capture, receiver-counter units, wraps/resets, available frame types and 70-minute coverage must be checked before conversion to experiment JSONL. The current preparation adapter does **not** directly ingest `.beast` files; that conversion must preserve relative receiver timing and observed interference. No new receiver recording has been started automatically.

### Check computational resources before signing

After preparation, reproduce the allocation-free resource diagnostic:

```bash
python -m src.experiment.resource_preflight --window daytime
```

It saves `results/daytime/01_prepared/resource_preflight.json`, including frame/event bounds and estimated public-cache size. It reads installed backend metadata but does not create keys/signatures or run the scientific replay. Optional `host_benchmark.json` contains a short diagnostic probe; extrapolations from it are host-runtime estimates, not airborne benchmark results. The diagnostic is allowed for a blocked recording, with that limitation stated in its output.

SLH-DSA is not included in the completed full replay matrix. The former 20-million-event limit was an implementation guard, not an ADS-B requirement. It has been raised to **200 million events per case**. The resource diagnostic calculates bounds for each algorithm/grouping/scenario combination; repeating capture seeds does not increase the bound for an individual case. Inspect each window's diagnostic before replay. This is a simulator capacity issue, not evidence by itself of an airborne limitation.

Read the workload and machine identified in each diagnostic before using its runtime projection: a short signing probe does not measure the duration of preparing, verifying, replaying and plotting both recordings. The completed public signature caches occupy approximately **8.96 GB across both windows**, excluding other inputs and outputs. Run the diagnostic for each new recording or configuration. Signing uses bounded parallel workers and durable completed-aircraft checkpoints. Replay uses compact transmission schedules, disk-backed large timelines, bounded collision calculations and completed-case checkpoints. The guard alone is not a memory or runtime guarantee. Simulation cases run sequentially to limit peak memory.

### Resume and preserve the published workloads

Both input files are checked before a combined run starts; there is no fallback to sample data. Completed signed workloads are checked and reused. Signing uses up to four worker processes, adjustable with `ADSB_SIGNING_WORKERS`. Completed aircraft checkpoints are verified and reused after interruption; only an incomplete aircraft must restart. Private keys are never saved. Replay saves each completed case atomically, validates its inputs and signatures on restart, and reuses matching cases. Consolidated replay CSV and JSON files are written only when the requested matrix is finished.

Generating fresh keys and signatures reproduces the procedure but need not reproduce the frozen cache's exact values, particularly variable Falcon signature lengths. Exact cached replay requires matching scientific source and supported backend versions; incompatible identities fail explicitly. Replay seeds change assumed capture priorities, not signing randomness. To actually re-execute simulation, start with prepared inputs and public signed workloads but no completed replay output; the archive's `replay` restoration profile supplies this arrangement.

Virtual environments, logs, locks and restart checkpoints are generated locally and excluded from publication. Keep in-progress `02_signed/` checkpoints and `03_replay/cases/` when resuming an interrupted command. Completed case checkpoints duplicate rows in `replay_summary.json` and can be omitted once that summary is complete and validated. All generated scientific files belong in `results/`; the original recordings in `data/` remain immutable. Tests create temporary small inputs and do not leave sample experiment results in the study directories.


## Outputs and figure definitions


Each window has this structure after a complete run:

```text
results/daytime/
  01_prepared/
    trace.jsonl                First-hour DF17 targets with stable identifiers
    channel.jsonl              All supplied frames, including follow-up traffic
    traffic.json               Cumulative counts and encoded bytes by DF
    manifest.json              Input/output checksums, coverage and preparation rules
  02_signed/
    signatures_manifest.json   Inventory of algorithm/grouping workloads
    <content-hash>/             Signed objects, public keys and workload manifest
  03_replay/
    replay_summary.json        Full metrics, configuration and provenance
    replay_overview.csv        One row per experimental case
    cases/                     Generated restart checkpoints; omitted from the archive
  figures/                     PDF figures, numerical CSV tables and figure manifest
  input_audit.json              Historical recording-quality evidence supplied in the archive
```

The same paths exist for nighttime. The numerical tables contain per-case results and sensitivity summaries, while the PDFs show their graphical presentation. The complete metrics and provenance remain in `03_replay/`. A missing authentication delay is not zero: it means there were no eligible completed observations for that metric.

For the completed daytime run, [authentication outcomes](../results/daytime/figures/authentication_outcomes.csv) account for every source message, including authenticated messages, unsigned final groups, reception or association failures, and work still pending at the cutoff. [Deadline measurements](../results/daytime/figures/authentication_deadlines.csv) include their eligible and excluded population counts. Use these alongside [case metrics](../results/daytime/figures/case_metrics.csv) when interpreting delay: fast authentication among a few successful messages does not imply high overall coverage.

| Figure family | What it shows |
| --- | --- |
| `01_traffic_by_df` | Cumulative frame counts and cumulative encoded message bytes, separately for every observed DF over all 70 minutes; a marker separates the first hour and follow-up. Bytes include message parity, exclude the preamble, and are not JSON file size or RF airtime. |
| `02_signature_cost` | Actual signature sizes and required authentication fragment counts, for every active algorithm and grouping size. |
| `02_signature_airtime_lower_bound` | Optimistic signature-only airtime with seven payload bytes per frame and no metadata/header overhead. Active algorithms use real signature lengths; SLH is shown separately as an analytical size bound, with no full signing or replay claim. |
| `03_channel_load` | Recorded baseline load, added traffic actually transmitted, and total authentication demand, for every algorithm/grouping/rate/channel case. Offered airtime sums frame durations and can exceed 100% under overlap; it is not measured spectrum occupancy. |
| `04_ordinary_delivery` | Modeled baseline and augmented transmission-failure percentages, additional failures attributable to authentication, and authentication-added ordinary transmission delay versus the same radio carrying ordinary messages only. Total delay and baseline radio queueing remain in the CSV. Denominators are labeled in the figures and CSVs. |
| `05_authentication_deadlines` | Fraction authenticated within each specified delay, measured from source availability and separately from ordinary reception. Eligible/excluded counts accompany the percentages. |
| `06_backlog_timeline_*` | Unfinished signing, authentication transmission and verification work over time. Each one-minute bin integrates every modeled job: curves show time-weighted mean and exact peak, with completed-operation counts in the source table. Bins summarize continuous event times; they are not simulation time steps. |
| `07_window_comparison` | Matched daytime/nighttime differences under the same configuration; this appears in `results/comparison/`. |

Each family may have multiple panels/files to cover the complete case matrix. Figures are saved only as PDF, with their underlying numerical tables retained. There is no separate outcomes-at-cutoff figure; pending/failed counts remain available in the numerical results to interpret coverage and delays correctly.

### Compact figures for the paper

After generating both windows' numerical tables, create the four compact publication figures:

```bash
python scripts/06_paper_figures.py
```

This presentation step follows the simulation in both reproduction workflows. It reads the calculated results and writes PDFs to `results/paper/figures/`, with input checksums in its figure manifest. Use these PDFs with LaTeX. The complete diagnostic figures above remain available for inspecting every case.

| Paper figure | What it shows |
| --- | --- |
| `01_signature_airtime_bounds` | Daytime and nighttime optimistic signature-only airtime by algorithm and group size. SLH-DSA is analytical only. These bounds exclude ordinary traffic and transport metadata. |
| `02_recorded_traffic` | Cumulative decoded Mode S frame counts by DF, with matched daytime/nighttime axes and the first-hour/follow-up boundary. |
| `03_authentication_deadlines` | Authentication within each source-relative deadline under the no-interference control, at 50 authentication frames/s and one reference verification worker. |
| `04_verifier_capacity` | Per-message authentication coverage for ECDSA (the classical reference), Falcon and ML-DSA under three receiver-capacity assumptions, with ideal reception and 50 authentication frames/s. Daytime and nighttime panels use matched axes. Reference-worker service times are algorithm-specific. |

Generate the methodology diagrams and filled dataset table from both prepared recordings:

```bash
python scripts/07_methodology_figures.py
```

This separate presentation step writes `00_methodology_workflow.pdf` and `00_observation_window.pdf` to the same directory, together with `dataset_characteristics.csv` and `methodology_figure_manifest.json`. The workflow has two panels: sender scheduling with the alternative no-interference/capture channel assumptions, then the common receiver procedure. It shows original-message caching, fragment reassembly, reconstruction of the signed bytes, the provisioned public key, queued native verification, and authentication or incomplete/rejected outcomes. The timeline shows the 60-minute target window and 10-minute follow-up. Use the vector PDFs at full text width in the paper; the detailed workflow is 7 by 7.5 inches. The CSV counts first-hour decoded Mode S frames and DF17 targets; its peak-activity measure is the maximum number of distinct target ICAO addresses in a fixed, non-overlapping 60-second interval. The script checks prepared-input hashes and counts without generating signatures or rerunning replay.

Keep channel assumptions consistent in each comparison. A paper table of ordinary messages **received** and messages **authenticated** should use the same capture scenario and all first-hour targets as the denominator for both columns. Authentication is a subset of reception; the percentages are not categories to add together. The no-interference deadline and receiver figures above are separate controls, not capture-model results.

**Transmission-failure percentages are conditional sensitivity results.** Every observed frame is accepted in the no-authentication baseline: its baseline RF rejection is zero. The `observed_capture` model only introduces competition when at least one overlapping frame is added authentication traffic. Each frame has a seeded random priority; an isolated pair has one equally likely winner. A frame loses if a directly overlapping competitor has higher priority. Consistent priorities also handle multi-frame overlaps; losing frames remain interferers. Recorded-to-recorded overlaps are exempt, including after modeled local-radio timing shifts. This explicitly preserves observed success rather than reconstructing the original receiver's signal-strength decisions.

A chain of overlaps can have several surviving frames when those survivors do not directly overlap; the model does not choose just one winner for the entire connected chain.

The collision-free control accepts overlaps and isolates computation, pacing and queues. Capture scenarios repeat the **same traffic and cached signatures** with seeds 1–5: only the assumed capture priorities change. Tables and plots show means and observed minimum–maximum ranges across those five runs; ranges are not confidence intervals or measured RF uncertainty. Raw per-seed results remain available. No additional independent random erasure is imposed. Received power, geometry, receiver diversity and missing traffic are not reconstructed, so the outputs are not calibrated real-world loss probabilities.

Do not infer efficiency from low transmitted authentication traffic alone: a slow signer may simply have a large unfinished queue. Do not call daytime “high congestion” or nighttime “low congestion” until the recorded traffic and results support that description. Two windows provide a comparison, not a causal estimate of a general day/night effect.


## Experimental settings and interpretation


The main matrix includes **3 algorithms × 4 grouping sizes × 3 authentication rates × 5 capture seeds = 180 capture cases per window**, plus **36 collision-free controls**. Two extra receiver-capacity scenarios each cover all 12 algorithm/grouping combinations: collision-free at 50 authentication frames/s with either four reference-speed workers or one assumed 1 ms worker. These add **24 cases**, giving **240 per window, 480 for both**. Deterministic cases use seed 1 only. Each of the 12 signed workloads is reused across the applicable scenarios and seeds. The `algorithms` list in `config/experiment.json` selects this subset; it applies consistently to signing, replay, resource diagnostics and output tables. SLH-DSA is not included in the completed signing/replay matrix, with no placeholder signatures or simulated SLH results substituted. Step 04 also calculates an explicitly analytical signature-only airtime bound from its fixed 7,856-byte size ([FIPS 205, Table 2](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf)); this does not add SLH to the replay case matrix. For a separate full SLH-DSA experiment, add `"SLH-DSA-SHA2-128s"` to that list before starting a new run, then repeat the resource diagnostic. Changing the selection changes the study identity, so an existing completed inventory is not silently treated as the new study.

- Comparisons: unauthenticated ADS-B supplies the no-signature baseline; ECDSA P-256 supplies a classical public-key authentication reference, not a post-quantum candidate. ML-DSA-44 and Falcon-512 are the post-quantum algorithms in the completed replay. SLH-DSA-SHA2-128s is assessed analytically and remains available for a later full run. The historical code label `FN-DSA-512` selects Falcon-512; it is not a claim of a finalized FN-DSA implementation. The parameter sets do not all represent the same security category.
- Group sizes: `k = 1, 5, 10, 20`, independently per aircraft. Groups close only at exactly `k` messages, with no time-based flush. Incomplete final groups remain unsigned; their ordinary messages still transmit.
- Authentication fragments: an illustrative seven-byte ME allocation, with four header bytes and three data bytes per fragment. Signed metadata also consumes space. No approved ADS-B extension or assigned message type is claimed.
- Rates: 10, 50 and 100 authentication frames/second/aircraft. These are sensitivity settings, not authorized transmission rates or measured channel capacities.
- Processing: one serial signer per aircraft and one shared receiver verification worker in the main matrix. Receiver sensitivity additionally tests four reference-speed workers and one assumed 1 ms worker at 50 frames/s in the collision-free model. The 1 ms value is an analyst assumption, not a measured receiver benchmark. Source timestamps proxy message availability, not measured sensor-generation time. Published hardware-profile service estimates drive replay; offline host execution time does not.
- Hardware evidence: `config/hardware_profiles.json` stores source URLs, platform details and equivalence limitations for every algorithm. The defaults combine embedded reference measurements; Falcon and SLH-DSA include implementation-lineage proxies. They are not a measured common avionics or ground-receiver platform and do not establish worst-case execution times.
- Coverage: observed traffic throughout 70 minutes; a cold start with empty queues, first-hour target cohort, and a fixed observation cutoff. Authentication for messages outside the target cohort is not generated. This is not an indefinitely running steady-state simulation.
- Local radio scheduling: first-hour target DF17 messages share each modeled aircraft's transmitter with authentication fragments. Other recorded frames, including later DF17 traffic and Mode S replies, remain fixed interference. Their transmissions are not rescheduled through the same aircraft's radio, so the added-delay result does not represent full transponder arbitration.
- Loss: observed-success-conditioned random capture for added authentication, or a collision-free control. Independent erasure and receive jitter are zero. Seeds repeat assumed capture choices on unchanged data; the five-run range describes that assumption's sensitivity only.
- Trust and resources: provisioned public keys/session, shared time assumptions, no credential distribution traffic, no feedback retransmission, and unbounded default signing/transmission/verification queues. Backlog measures required work; it does not prove sufficient onboard memory, power or certification suitability.

The software is MIT licensed; the supplied recordings and generated experimental artifacts are CC BY 4.0. The experiment evaluates a research model, not an approved airborne authentication protocol.
