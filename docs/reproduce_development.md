# Reproduce the historical development reference

This guide reproduces the **earlier calibrated-size experiment**: 64 replay cases and 16 analytical screening rows from 133,565 retained DF17 observations over 640.792 seconds. It is useful for checking the recorded sample and historical results. The current real-signature study and synthetic demo have [separate commands](reproduction_commands.md).

This workflow uses a portable signature-size calibration and published processing profiles. It does not sign every replay group afresh and does not represent all recorded 1090 MHz traffic: the excluded DF11 observations are absent from its channel baseline. Its settings include fixed-count/one-second timeout grouping, 1% extra random loss, 100 authentication frames/s, and 60 seconds of follow-up. These are historical settings, not the current study configuration.

Run commands from the repository root. Use Python 3.13, as in [the README](../README.md). This route requires no native cryptographic library or private signing keys.

## 1. Install and check the inputs

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r config/requirements/replay.txt
python -m pip check
python scripts/check_reproduction.py --inputs-only
```

If `.venv` already exists, activate it rather than creating it again. The checker validates the recorded capture and calibration against the manifest. Acquisition/redistribution fields that were never supplied remain explicitly unknown; see [data provenance](../data/README.md).

## 2. Run the pipeline

```bash
python -m src.pipeline --config config/development.json
```

This writes to `results/runs/development/` and leaves the frozen reference untouched. It analyzes the capture, preprocesses DF17 messages, builds groups, computes analytical screening, and runs replay. Replay prints progress for 64 cases. Allow several minutes and several GB of available memory, depending on the machine.

Expected grouping counts are:

| Group size | Complete groups | Messages in incomplete tails |
| ---: | ---: | ---: |
| 1 | 133,565 | 0 |
| 5 | 26,549 | 820 |
| 10 | 13,177 | 1,795 |
| 20 | 6,486 | 3,845 |

These are preprocessing/grouping checks, not authentication successes. Timeout groups are formed separately during replay.

## 3. Validate and compare scientific results

```bash
python -m src.pipeline --config config/development.json --validate-only
python scripts/check_reproduction.py \
  --results-dir results/runs/development/replay \
  --reference-dir results/reference/development \
  --allow-model-change
```

The first command validates the current run's input/config/source identities and report integrity. The second checks case coverage, outcome conservation, and scientific values against the frozen reference, allowing only tiny floating-point differences. Machine-specific path strings do not need to match.

`--allow-model-change` is explicit because shared code has gained complete-channel and detached-signature support since the reference was frozen. It permits a source-revision difference from the reference; it still requires the new run to match current sources and the reference scientific values. Without it, source identities must also match the reference. A comparison failure is not resolved by matching only the number of rows or rewriting report hashes.

## 4. Recreate the figures

```bash
python -m src.experiment.plot_delayed_replay \
  --results-dir results/runs/development/replay \
  --output-dir results/runs/development/figures \
  --interval 5
```

The command exports `authentication_coverage`, `surveillance_impact`, and `authentication_clocks_and_pending` in PNG, SVG, and PDF formats. `delayed_figure_manifest.json` records source and figure hashes. To plot another group size, use `--interval 1`, `10`, or `20` and a separate figure directory. Image bytes can differ across plotting platforms even when scientific rows agree.

Read [development_results.md](development_results.md) for interpretation. The development checker and this plotting module apply to the earlier model. Use `plot_signed_replay` for current signed runs.

## Individual commands

These commands perform the same stages with explicit paths. Use them when inspecting intermediate files. Analysis and preprocessing write their destinations; preserve any previous run that must remain unchanged.

```bash
python -m src.analysis.analyze_capture \
  data/development/raw/adsb_sample.jsonl \
  --output results/runs/development/analysis/capture_summary.json
python -m src.analysis.analyze_aircraft \
  data/development/raw/adsb_sample.jsonl \
  --summary results/runs/development/analysis/aircraft_analysis.json
python -m src.analysis.analyze_duplicates \
  data/development/raw/adsb_sample.jsonl \
  --summary results/runs/development/analysis/duplicate_analysis.json
python -m src.processing.preprocess_capture \
  data/development/raw/adsb_sample.jsonl \
  --output results/runs/development/processed/experimental_trace.jsonl \
  --manifest results/runs/development/analysis/preprocessing_manifest.json
python -m src.processing.build_authentication_groups \
  results/runs/development/processed/experimental_trace.jsonl \
  --output-dir results/runs/development/processed/authentication_groups \
  --summary results/runs/development/analysis/authentication_group_summary.json \
  --intervals 1 5 10 20
python -m src.experiment.replay_experiment \
  --trace "$PWD/results/runs/development/processed/experimental_trace.jsonl" \
  --groups-dir "$PWD/results/runs/development/processed/authentication_groups" \
  --algorithms-config "$PWD/config/algorithms.json" \
  --size-profile "$PWD/data/calibration/signature_sizes.json" \
  --hardware-profiles "$PWD/config/hardware_profiles.json" \
  --scenarios "$PWD/config/delayed_replay_scenarios.json" \
  --output-dir "$PWD/results/runs/development/replay" \
  --intervals 1 5 10 20 --mode all
```

The canonical trace has 417 aircraft and SHA-256 `783ec055bb2027bc3fed18d8d33d587d30fb865518bfe8781ecfc72d1cbeea41`. Absolute paths in the replay command match the pipeline's provenance representation. Add `--validate-only` to that command to audit matching reports without replaying them. `--mode screening` runs only the analytical rows; `--mode replay` runs only replay.

## Optional exhaustive signing of the development sample

This separate legacy step requires [native cryptography](native_crypto.md) and can run for days, especially with SLH-DSA. It is **not required to reproduce the frozen reference**.

```bash
python -m src.pipeline --config config/development.json --stage signatures
python -m src.pipeline --config config/development.json --stage signatures --validate-only
```

It signs concatenated original messages using the historical transcript, not the descriptor-bearing transcript of the current transport. Its resumable private `.checkpoints/` state must stay local. Reports record signature metadata and generation-time verification; they are not the public signed-object caches used by the current experiment.

`config/development_recovery.json`, `data/development/processed/`, and `results/development/` retain original paths for the existing recovery job. A reader reproducing the reference needs none of those private checkpoints. Do not run another writer against that job's outputs or remove a live lock.
