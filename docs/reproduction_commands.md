# Reproduce the current signed experiment

This guide covers the current `signed_detached` workflow: actual signatures, fragmented authentication transmissions, and recorded channel interference. Start with [the README](../README.md) for installation and the small demo. The [historical development reference](reproduce_development.md) uses different commands and assumptions.

**The final datasets are not available yet.** The executable workflow is ready for canonical inputs, but acquisition commands, source-specific conversion, and final reference results cannot be provided until the data are obtained. Do not substitute the short development sample or synthetic demo and label the result as the one-hour experiment.

## 1. Set up and verify the environment

Use Python 3.13, the pinned root `requirements.txt`, and the pinned native library as described in [the README](../README.md) and [native_crypto.md](native_crypto.md). Run all commands below from the repository root in the same activated shell. Confirm setup before attempting the expensive full study:

```bash
python -m pip check
./scripts/bootstrap_liboqs.sh --check
python -m tests.test_crypto
python -m src.pipeline --config config/demo.json
python -m src.pipeline --config config/demo.json --validate-only
python scripts/check_demo.py
```

The demo uses 21 synthetic targets from one artificial aircraft and 621 seconds of declared synthetic channel coverage. The workload counts per algorithm are 21, 4, 2, and 1 signatures for `k=1,5,10,20`: 112 actual signatures across 16 workloads. Its two DF11-shaped capture records are excluded from authentication and are retained as channel interferers. A further recorded synthetic event exercises the follow-up. None of these are observed aircraft traffic.

## 2. Obtain and document the two recorded windows

For each window, supply these two aligned files:

| File | Required contents |
| --- | --- |
| `adsb_capture.jsonl` | The one-hour target cohort in the [raw message schema](../data/README.md#raw-jsonl-format). DF17 records are selected for authentication. |
| `channel_trace.jsonl` | All recorded 1090 MHz events in the [channel schema](channel_trace.md#canonical-jsonl-format), including non-target traffic and follow-up. |

The target cohort ends after its selected hour. Channel recording must continue through **600 seconds after the final target, including completion of the last frame**. Follow-up traffic interferes but does not create new authentication groups. Missing follow-up is rejected rather than treated as silence.

Document the observation dates, window boundaries, geographic/receiver coverage, timestamp semantics and precision, acquisition method, event durations, filtering, duplicate-emission handling, input hashes, and data access/redistribution terms. Prefer windows with different measured traffic conditions; they are two scenarios, not random repetitions.

The channel file must link each preprocessed target `trace_id` to exactly one original channel event. Non-target events have no target link. Preprocessing sorts by timestamp and source line, so build these links against that canonical ordering. Repeated message bytes alone are not evidence of duplicate emissions. Use the actual source's emission identifiers or documented acquisition logic when combining receiver reports.

**The acquisition adapter is still pending.** DF17 preprocessing does not recover excluded traffic or produce a complete channel file. A decoded-packet log cannot demonstrate complete physical RF capture; include undecodable activity only if its timing and duration were actually recorded. Record these limits alongside the data.

Once the exports satisfy those schemas, replace the four example source paths below:

```bash
mkdir -p data/full/window_a/raw data/full/window_b/raw
cp /path/to/window-a-targets.jsonl data/full/window_a/raw/adsb_capture.jsonl
cp /path/to/window-a-channel.jsonl data/full/window_a/raw/channel_trace.jsonl
cp /path/to/window-b-targets.jsonl data/full/window_b/raw/adsb_capture.jsonl
cp /path/to/window-b-channel.jsonl data/full/window_b/raw/channel_trace.jsonl
```

These directories are ignored by Git. Preserve the source capture separately from any canonical export; record the conversion command and hashes in the release's acquisition documentation.

## 3. Preprocess and inspect a small case first

First create the capture summary required by preprocessing, then create the trace and its audit manifest. These steps do not sign messages:

```bash
python -m src.pipeline --config config/full_window_a.json --stage capture
python -m src.pipeline --config config/full_window_a.json --stage preprocess
python -m src.pipeline --config config/full_window_b.json --stage capture
python -m src.pipeline --config config/full_window_b.json --stage preprocess
```

Inspect `results/runs/full/window_a/analysis/preprocessing_manifest.json` and the corresponding window B file before proceeding. Confirm the intended duration, filtering, counts, and source identity against the acquisition record.

This initial window A case exercises channel validation, real signing, transport, and verification without running every algorithm and condition:

```bash
python -m src.experiment.signed_experiment \
  --trace "$PWD/results/runs/full/window_a/processed/experimental_trace.jsonl" \
  --channel-trace "$PWD/data/full/window_a/raw/channel_trace.jsonl" \
  --algorithms-config "$PWD/config/algorithms.json" \
  --hardware-profiles "$PWD/config/hardware_profiles.json" \
  --scenarios "$PWD/config/signed_replay_scenarios.json" \
  --replay-model signed_detached \
  --output-dir "$PWD/results/runs/full/window_a/quick-check" \
  --workloads-dir "$PWD/results/runs/full/window_a/signed_workloads" \
  --algorithm ECDSA-P256 --intervals 5 \
  --scenario detached_independent_r10
```

The quick check shares its completed workload with the later full run and uses a separate result directory. It is one case over the whole selected window, not a reduced-duration dataset. Add `--validate-only` to this exact command to audit it without replaying. The independent control ignores collisions; it alone cannot establish channel feasibility.

Budget signing time, RAM, and storage before the next step. The current builder is serial. SLH-DSA can make full-data signing take days; completing the small demo is not a runtime estimate for the full study. The driver loads one algorithm/group-size workload at a time and may hold many signatures in memory. Its default event guard is 20 million events per case. Plan explicit resource changes rather than truncating observed traffic to bypass the guard.

## 4. Run both windows

```bash
python -m src.pipeline --config config/full_window_a.json
python -m src.pipeline --config config/full_window_a.json --validate-only
python -m src.pipeline --config config/full_window_b.json
python -m src.pipeline --config config/full_window_b.json --validate-only
```

Each pipeline analyzes the capture, preprocesses target messages, generates real signed objects, and runs replay. Completed matching outputs and workloads are validated and reused. `config/full.json` is a convenience alias for window A; it does not combine both windows or create another experiment.

The default matrix is:

| Variable | Values |
| --- | --- |
| Algorithms | ECDSA P-256, ML-DSA-44, Falcon-512, SLH-DSA-SHA2-128s |
| Exact group size | 1, 5, 10, 20 messages per aircraft |
| Authentication fragment pacing | 10, 50, 100 frames/s/aircraft |
| Channel | Collision-free control; destructive temporal overlap |
| Recorded windows | A and B, evaluated separately |

That is **96 cases and 16 signed workloads per window; 192 cases and 32 workloads in total**. The same actual signatures are reused across the six pacing/channel cases. There is no one-second group timeout. Incomplete final groups remain unsigned, while their ordinary messages still transmit. No extra random loss, timing jitter, or synthetic background is added. The single interface seed is not a random replication or a cryptographic seed.

The sender and receiver each use their declared embedded reference processing profile, with one signing worker per aircraft and one receiver verification worker. These are reference scenarios, not measurements of a particular avionics computer or ground server. Actual host signing runtime is separate from the model's service time. See [hardware_profiles.md](hardware_profiles.md).

## 5. Find and interpret the outputs

| Output | Window A location |
| --- | --- |
| Capture and preprocessing diagnostics | `results/runs/full/window_a/analysis/` |
| Canonical target trace | `results/runs/full/window_a/processed/experimental_trace.jsonl` |
| Public signed-object cache | `results/runs/full/window_a/signed_workloads/` |
| Full report and provenance | `results/runs/full/window_a/replay/replay_summary.json` |
| Tabular case results | `results/runs/full/window_a/replay/replay_overview.csv` |

Replace `window_a` with `window_b` for the second window. Keep the windows separate in analysis and plotting.

Read ordinary reception and transmission delay first. Then inspect authentication coverage, completed delay, failures, and pending work together. The receiver's original message-reception timestamp does not move when verification finishes. A long authentication queue does not mean the ordinary message arrived that late. `null` completion delay means no successful completions, not zero delay.

The collision model erases overlapping frames; it does not make aircraft wait for a clear frequency. Added ordinary waiting comes from the modeled aircraft radio being occupied. The timing-matched control isolates fragment interference from changes in ordinary transmission times. Offered airtime is additive traffic demand, not measured RF occupancy. See [methodology.md](methodology.md) for exact metric definitions and limits.

The 600-second follow-up is fixed before inspecting final results. It covers an isolated largest selected SLH-DSA object under the slowest fragment pacing, but does not guarantee that queues drain. Work still waiting at the cutoff is pending. Additional time horizons or receiver worker counts belong in separately labeled sensitivity runs with sufficient recorded channel coverage.

## 6. Export the figures

```bash
python -m src.experiment.plot_signed_replay \
  --results-dir results/runs/full/window_a/replay \
  --output-dir results/runs/full/window_a/figures \
  --label "Recorded window A"
python -m src.experiment.plot_signed_replay \
  --results-dir results/runs/full/window_b/replay \
  --output-dir results/runs/full/window_b/figures \
  --label "Recorded window B"
```

Each command writes `ordinary_impact`, `authentication_outcomes`, and `completed_authentication_delay` in PDF, PNG, and SVG formats, plus `figure_manifest.json`. These are standard diagnostic figures for the current workflow. The final paper's figure/table mapping and any additional publication analyses must be recorded when the paper and real runs are finalized. Exported image bytes can differ across platforms even when underlying results agree.

## 7. Reproduce a published cache exactly

A fresh run generates fresh keys and signatures. Cryptographic randomness, including variable Falcon signature lengths, can change signature bytes and simulation results. To reproduce a particular published run, obtain its **public signed-object cache**, identical inputs, declared source revision, and matching dependencies. No private key is needed to verify or replay an existing signed workload.

On a fresh checkout with no run outputs, install the release's data at the paths above. Then copy the public workload directories before running the pipeline. These commands are a template for a future release; the final cache and download location do not exist yet:

```bash
mkdir -p results/runs/full/window_a results/runs/full/window_b
cp -R /path/to/release/window_a/signed_workloads results/runs/full/window_a/
cp -R /path/to/release/window_b/signed_workloads results/runs/full/window_b/
python -m src.pipeline --config config/full_window_a.json
python -m src.pipeline --config config/full_window_a.json --validate-only
python -m src.pipeline --config config/full_window_b.json
python -m src.pipeline --config config/full_window_b.json --validate-only
python scripts/compare_signed_results.py \
  --results-dir results/runs/full/window_a/replay \
  --reference-dir /path/to/release/window_a/replay
python scripts/compare_signed_results.py \
  --results-dir results/runs/full/window_b/replay \
  --reference-dir /path/to/release/window_b/replay
```

The modern pipeline checks the preprocessing manifest against the current raw-capture and processed-trace hashes, then verifies cached signatures against the exact source messages. The comparison checks report/CSV integrity, input/source/cache content identities, and scientific results while allowing filesystem locations to differ. Fresh independently generated workloads are not expected to pass an exact-cache comparison.

Copy the signed workloads, **not the old replay reports into the new output directory**: reports include paths in their run fingerprint. Recompute local reports from the preserved workload, and compare those reports with the frozen release. Do not edit stored hashes to make a relocated report pass validation.

## Changing scenarios or recovering an interrupted run

Rerun the same command for the same configuration. Completed matching reports and workloads are reused; an interrupted **unfinished signed workload restarts from scratch**. This differs from the legacy signature generator's resumable checkpoints. Keep completed public caches if a long run is interrupted.

To change scientific assumptions, copy the configuration/scenario file, give the scenario a distinct name, and use a fresh run directory for every output. A modern pipeline configuration's `run_directory` contains its declared outputs and lock. Preserve the original reports. For example, a receiver-capacity sensitivity can change `receiver_workers` to 2 or 4 in a copied scenario, while retaining the existing signed workload in a direct replay invocation. These cases are outside the default 192-case matrix.

Changed raw captures, altered processed traces, missing preprocessing manifests, and stale or incomplete reports are rejected. Use a fresh run directory when replacing input data. `--force` deliberately regenerates outputs; use it only after deciding to replace that run and preserving any evidence needed. Never run concurrent writers against the same outputs or signed-workload directory, or remove a live lock.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| `ModuleNotFoundError: src` | Enter the repository root and use `python -m ...`. |
| Missing Python dependency | Activate `.venv` and install root `requirements.txt`. |
| Native library or `oqs` cannot load | Follow [native setup](native_crypto.md), including shell exports and the loaded-path check. |
| Missing full-study files | Complete acquisition and channel conversion; the final datasets are not bundled yet. |
| Invalid target links or insufficient channel coverage | Check the canonical target IDs, timestamps, 120-microsecond target durations, and recorded follow-up. |
| Active lock | Wait for that run; use separate output and workload directories for independent work. |
| Stale or altered report | Inputs, source, configuration, paths, or files changed. Preserve it and use a fresh output location. |
| Event limit exceeded | Budget RAM and set an explicit larger limit in a copied scenario; do not silently drop traffic. |
| No completed authentications | Inspect failures, missing originals/fragments, and processing/transmission backlog. |
| Published-result comparison fails | Confirm identical data, public cache, source revision, dependencies, and scenarios. |
