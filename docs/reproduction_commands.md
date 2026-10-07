# Reproduction command walkthrough

Use the repository root and an activated environment with `requirements/replay.txt` installed, as in the [README](../README.md). Sections 1–5 reproduce the frozen development model through the individual stages dispatched by `python -m src.pipeline --config config/development.json`. They use no private key or native crypto library. The separate final-study command below **requires native cryptography** and real signatures.

## 1. Analyze the raw capture

```bash
python -m src.analysis.analyze_capture \
  data/development/raw/adsb_sample.jsonl \
  --output runs/development/analysis/capture_summary.json
python -m src.analysis.analyze_aircraft \
  data/development/raw/adsb_sample.jsonl \
  --summary runs/development/analysis/aircraft_analysis.json
python -m src.analysis.analyze_duplicates \
  data/development/raw/adsb_sample.jsonl \
  --summary runs/development/analysis/duplicate_analysis.json
```

## 2. Build the canonical trace

```bash
python -m src.processing.preprocess_capture \
  data/development/raw/adsb_sample.jsonl \
  --output runs/development/processed/experimental_trace.jsonl \
  --manifest runs/development/analysis/preprocessing_manifest.json
```

Expect 133,565 observations, 417 aircraft, and output SHA-256 `783ec055bb2027bc3fed18d8d33d587d30fb865518bfe8781ecfc72d1cbeea41`.

## 3. Build authentication groups

```bash
python -m src.processing.build_authentication_groups \
  runs/development/processed/experimental_trace.jsonl \
  --output-dir runs/development/processed/authentication_groups \
  --summary runs/development/analysis/authentication_group_summary.json \
  --intervals 1 5 10 20
```

The stored files include incomplete terminal groups; replay's fixed-count mode leaves their messages unsigned, while timeout groups are rebuilt during replay.

## 4. Run screening and replay

Absolute paths here match the pipeline's provenance representation. The same command with `--mode screening` runs only the 16 analytical rows; `--mode replay` runs only replay. `all` runs both.

```bash
python -m src.experiment.replay_experiment \
  --trace "$PWD/runs/development/processed/experimental_trace.jsonl" \
  --groups-dir "$PWD/runs/development/processed/authentication_groups" \
  --algorithms-config "$PWD/config/algorithms.json" \
  --size-profile "$PWD/data/calibration/signature_sizes.json" \
  --hardware-profiles "$PWD/config/hardware_profiles.json" \
  --scenarios "$PWD/config/delayed_replay_scenarios.json" \
  --output-dir "$PWD/runs/development/replay" \
  --intervals 1 5 10 20 --mode all
```

Add `--validate-only` to that exact command to validate without recomputing. The output path is locked independently; it must not be shared with another writer. This command can read separate completed inputs while a legacy signing pipeline holds the global pipeline lock. It never reads active `.partial` files or signing checkpoints.

The direct analysis/preprocessing commands write their destinations, so use fresh paths when preserving a previous experiment. Replay itself refuses stale or incomplete existing outputs unless `--force` is explicit. Do not use `--force` as a substitute for documenting changed assumptions.

## 5. Compare and plot

```bash
python scripts/check_reproduction.py \
  --results-dir runs/development/replay --reference-dir reference/development \
  --allow-model-change
python -m src.experiment.plot_delayed_replay \
  --results-dir runs/development/replay \
  --output-dir runs/development/figures --interval 5
```

## Select a small historical development case

After preprocessing/grouping, this single ECDSA case is a quick replay check. It has a different case matrix and therefore should not be compared with the 64-case reference checker.

```bash
python -m src.experiment.replay_experiment \
  --trace "$PWD/runs/development/processed/experimental_trace.jsonl" \
  --groups-dir "$PWD/runs/development/processed/authentication_groups" \
  --algorithms-config "$PWD/config/algorithms.json" \
  --size-profile "$PWD/data/calibration/signature_sizes.json" \
  --hardware-profiles "$PWD/config/hardware_profiles.json" \
  --scenarios "$PWD/config/delayed_replay_scenarios.json" \
  --output-dir "$PWD/runs/quick-check" --mode replay \
  --scenario fixed_k_independent --algorithm ECDSA-P256 --intervals 5 --seeds 1
```

## Run the detached signed study with two recorded windows

First complete [native cryptography setup](native_crypto.md). Provide two distinct one-hour target captures and their aligned [recorded channel inputs](channel_trace.md), each with 600 seconds of follow-up plus frame completion. The acquisition format is not yet known, so an appropriate channel-export adapter and its provenance remain prerequisites. Do not infer undecodable events from a decoded-only log.

### 1. Install the prepared input files

Replace the example source paths with the actual acquisition exports:

```bash
mkdir -p data/full/window_a/raw data/full/window_b/raw
cp /path/to/window-a-targets.jsonl data/full/window_a/raw/adsb_capture.jsonl
cp /path/to/window-a-channel.jsonl data/full/window_a/raw/channel_trace.jsonl
cp /path/to/window-b-targets.jsonl data/full/window_b/raw/adsb_capture.jsonl
cp /path/to/window-b-channel.jsonl data/full/window_b/raw/channel_trace.jsonl
```

The target files contain only the intended one-hour authentication cohorts. The channel files retain additional follow-up traffic as interference. Exact-count groups do not acquire new members from the follow-up. Each channel target link must match the deterministic trace IDs produced by preprocessing. Preserve repeated message contents; removing a network duplicate requires evidence of the same emission, not just identical bytes.

### 2. Run the full pipelines

```bash
python -m src.pipeline --config config/full_window_a.json
python -m src.pipeline --config config/full_window_a.json --validate-only
python -m src.pipeline --config config/full_window_b.json
python -m src.pipeline --config config/full_window_b.json --validate-only
```

Each pipeline performs capture/aircraft/duplicate analysis, preprocessing, and detached signed replay. `config/full.json` is the convenience window A configuration and writes the same destinations. The windows remain separate traffic scenarios, not statistical repetitions.

### 3. Alternatively, preprocess and replay explicitly

Use this route to inspect the trace and run a small case before the complete matrix, or to avoid the global pipeline lock held by a legacy job. The direct preprocess commands write their destinations, so preserve old inputs/results before rerunning with changes.

```bash
python -m src.processing.preprocess_capture \
  data/full/window_a/raw/adsb_capture.jsonl \
  --output runs/full/window_a/processed/experimental_trace.jsonl \
  --manifest runs/full/window_a/analysis/preprocessing_manifest.json
python -m src.processing.preprocess_capture \
  data/full/window_b/raw/adsb_capture.jsonl \
  --output runs/full/window_b/processed/experimental_trace.jsonl \
  --manifest runs/full/window_b/analysis/preprocessing_manifest.json
```

Now generate real signed objects and replay window A:

```bash
python -m src.experiment.signed_experiment \
  --trace "$PWD/runs/full/window_a/processed/experimental_trace.jsonl" \
  --channel-trace "$PWD/data/full/window_a/raw/channel_trace.jsonl" \
  --algorithms-config "$PWD/config/algorithms.json" \
  --hardware-profiles "$PWD/config/hardware_profiles.json" \
  --scenarios "$PWD/config/signed_replay_scenarios.json" \
  --replay-model signed_detached \
  --output-dir "$PWD/runs/full/window_a/replay" \
  --workloads-dir "$PWD/runs/full/window_a/signed_workloads" \
  --intervals 1 5 10 20
```

Run the second window separately:

```bash
python -m src.experiment.signed_experiment \
  --trace "$PWD/runs/full/window_b/processed/experimental_trace.jsonl" \
  --channel-trace "$PWD/data/full/window_b/raw/channel_trace.jsonl" \
  --algorithms-config "$PWD/config/algorithms.json" \
  --hardware-profiles "$PWD/config/hardware_profiles.json" \
  --scenarios "$PWD/config/signed_replay_scenarios.json" \
  --replay-model signed_detached \
  --output-dir "$PWD/runs/full/window_b/replay" \
  --workloads-dir "$PWD/runs/full/window_b/signed_workloads" \
  --intervals 1 5 10 20
```

Add `--validate-only` to either exact replay command to check a completed matching run without recomputing it. The direct route does not run the optional capture/aircraft/duplicate diagnostics; use the full pipeline for those summaries.

### 4. Select a small initial case if needed

After preprocessing, this uses its own output directory while sharing the completed workload cache with later cases:

```bash
python -m src.experiment.signed_experiment \
  --trace "$PWD/runs/full/window_a/processed/experimental_trace.jsonl" \
  --channel-trace "$PWD/data/full/window_a/raw/channel_trace.jsonl" \
  --algorithms-config "$PWD/config/algorithms.json" \
  --hardware-profiles "$PWD/config/hardware_profiles.json" \
  --scenarios "$PWD/config/signed_replay_scenarios.json" \
  --replay-model signed_detached \
  --output-dir "$PWD/runs/full/window_a/quick-check" \
  --workloads-dir "$PWD/runs/full/window_a/signed_workloads" \
  --algorithm ECDSA-P256 --intervals 5 \
  --scenario detached_independent_r10
```

The six main scenario names are `detached_independent_r10`, `detached_collision_r10`, `detached_independent_r50`, `detached_collision_r50`, `detached_independent_r100`, and `detached_collision_r100`. The independent cases are collision-free controls; the others discard temporal overlaps. No extra random erasure, jitter, or synthetic background is applied. The single technical seed value has no stochastic effect under these settings.

### Matrix, caching, and interpretation

Each window yields **96 cases**: four algorithms × four exact group sizes × three rates × two channel settings. Sixteen distinct real signed workloads are reused per window, giving **192 cases and 32 workloads** over both windows. No timeout closes undersized groups. Ordinary messages transmit independently of group completion/signing; incomplete tails remain ordinary transmissions without authentication.

Native signing can take many hours for large SLH-DSA workloads. An interrupted unfinished workload rebuilds from scratch; completed workloads are reusable. Preserve the completed cache for exact reproduction, because cryptographic key generation and randomized signing are not seeded by replay. Host wall time is separate from the embedded timing profile used inside the model. Changed inputs or settings require fresh result paths or an explicitly documented `--force` regeneration.

The fixed 600-second follow-up is predeclared, not tuned after reading final results, and may leave substantial signing/transmission/verification backlog. Pending work is distinct from failed reconstruction or verification. A single verification worker is the baseline. To study two or four workers, copy the scenario JSON, change `receiver_workers`, identify the new scenarios as sensitivity cases, and invoke the direct command with `--scenarios` pointing to that copy and a fresh `--output-dir`. The same workload cache may be reused. These cases are outside the main 192-case matrix.

The development reference checker and plotting command above do not apply to these study results. Inspect the new JSON/CSV reports for ordinary reception, fragment reconstruction, original-message association, verification, and pending work separately. Final data acquisition, analysis, and publication plots remain outstanding.

## Troubleshooting

| Symptom | Resolution |
| --- | --- |
| `ModuleNotFoundError: src` | Change to the repository root and use `python -m ...`; do not run files inside `src/` directly. |
| Missing NumPy/Matplotlib | Activate the intended environment and install `requirements/replay.txt`. |
| `oqs` is missing or a native library cannot load | Complete [native setup](native_crypto.md) for the signed experiment or crypto tests. Only the frozen development replay can run without it. |
| Global pipeline lock is held | Wait for the active pipeline, or use the independent module commands with separate destinations. Do not delete a live lock. |
| Stale/altered report | Inputs, source, paths, scenarios, or outputs differ. Preserve the old run and use fresh output paths; regenerate deliberately if appropriate. |
| `max_events` exceeded | No partial replay summary is published. Budget RAM and explicitly adjust a copied scenario, or select fewer/smaller cases. |
| No authenticated messages | Read failures and pending counts; `null` authentication delay is not a crash or zero delay. |
| Reference comparison mismatch | Confirm the exact sample, calibration, scenario matrix, source revision, and pinned environment. A copied report with rewritten path strings will fail its integrity digest. |

A source-code revision or relocated checkout intentionally invalidates a cached report fingerprint. Recompute locally and compare scientific values; do not edit a report's hashes to make it pass.
