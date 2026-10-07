# OpenSky PQC evaluation

This repository studies **ordinary ADS-B reception and later authentication as two separate events**. Its final-study workflow takes recorded messages, generates real signatures, fragments them, and replays them alongside all recorded 1090 MHz traffic. Ordinary messages become ready at their original trace times; retained copies are grouped and signed independently. The receiver can read an ordinary message before its signature has arrived. Repeated message contents are preserved, and a documented bound on source-to-reception timing keeps late authentication from confusing unrelated repetitions.

It compares ECDSA P-256, ML-DSA-44, Falcon-512 (the historical `FN-DSA-512` code label), and SLH-DSA-SHA2-128s. A signature covers exactly 1, 5, 10, or 20 messages from one aircraft. Collection and signing delay authentication; ordinary messages wait only for the modeled transmitter. Measurements include ordinary delay and reception, authentication delay and coverage, processing backlog, and added airtime.

**Current study:** two planned one-hour traffic windows, each with 600 seconds of recorded channel follow-up. Three fragment rates and two channel settings give **96 deterministic cases per window, 192 in total**. No artificial random loss or stochastic repetitions are used. **Neither final window has been acquired or evaluated.**

**Historical reference:** 64 calibrated-size replay cases plus 16 analytical screening rows from 133,565 DF17 observations over 640.792 seconds. The old results and figures remain validation artifacts for that different workflow. Both workflows are research models, not approved ADS-B extensions or aircraft certification results.

Read the [methodology](docs/methodology.md), [development results](docs/development_results.md), and [hardware references](docs/hardware_profiles.md) for interpretation. Original incomplete manuscripts are in [paper/](paper/README.md).

## What the development reference does

| Stage | Purpose |
| --- | --- |
| `capture`, `aircraft`, `duplicates` | Describe the input capture, aircraft observations, and repeated raw messages. |
| `preprocess` | Retain DF17 observations, preserve duplicates, sort by timestamp and source line, assign deterministic trace IDs. |
| `groups` | Build per-aircraft groups for `k = 1, 5, 10, 20`. |
| `screening` | Compute signature, fragment, and offered-airtime costs. |
| `replay` | Schedule signing, detached frames, reception, reconstruction, and verification; compare ordinary-only and added-authentication traffic. |

This development workflow **does not generate a fresh signature for every replay group**. It reuses a small, versioned [signature-size calibration](data/calibration/signature_sizes.json) and published embedded timing profiles. The separate final-study workflow below requires native cryptography and generates actual signed objects; its real signatures are reused across pacing rates and channel conditions to avoid unnecessary repeated signing.

## Reproduce the development experiment

Run every command below from the repository root, in the same shell. Commands use Bash/Zsh syntax on macOS or Linux. The pinned replay dependencies require Python 3.12 or newer; use Python 3.13 to match the reference's 3.13.3 environment. The package's broader Python 3.11 minimum applies to other compatible dependency versions, not this pinned environment. Windows is not validated; use a Linux environment such as WSL.

### 1. Obtain the repository and create an environment

```bash
git clone https://github.com/marcoscabanas/opensky-pqc-eval.git
cd opensky-pqc-eval
python3.13 -m venv .venv
source .venv/bin/activate
python --version
```

If the repository is already checked out, start with `cd` instead of cloning. Install Python 3.13 first if `python3.13` is unavailable. On macOS with Homebrew: `brew install python@3.13`.

### 2. Install the replay and plotting dependencies

```bash
python -m pip install -r requirements/replay.txt
python -m pip check
```

This route needs NumPy and Matplotlib, **no native cryptographic build**. Run modules from the repository root; an editable package installation is unnecessary. The pinned file records the tested versions, rather than letting future dependency upgrades change the numerical environment. [Native cryptography setup](docs/native_crypto.md) is a separate optional step below.

### 3. Check the inputs

```bash
python scripts/check_reproduction.py --inputs-only
```

This checks the development capture hash and the portable calibration. The capture is `data/development/raw/adsb_sample.jsonl`; the calibration is `data/calibration/signature_sizes.json`. Neither an OpenSky account nor the author's private signing checkpoints are needed for this replay. See [data provenance and format](data/README.md) for the recorded acquisition information and data-license limitations.

### 4. Run the experiment

```bash
python -m src.pipeline --config config/development.json
```

The command creates fresh derived data and results under **`runs/development/`**, leaving the historical data/results and frozen reference untouched. It executes the seven stages listed above, in order. Replay prints `REPLAY 1/64` through `REPLAY 64/64`, then writes the completed report. Allow several minutes and several GB of available memory; runtime depends on the machine. A case can take a while before the next progress line.

There is no need to run `--stage signatures` for this experiment. A failed or interrupted replay does not publish a partial replay summary; rerun the same command to restart its replay cases. Finished matching replay reports are validated and reused. An incomplete report or changed input/model is rejected: use a new output directory, or deliberately use `--force` to regenerate after preserving anything needed.

### 5. Validate the run and compare it with the reference

```bash
python -m src.pipeline --config config/development.json --validate-only
python scripts/check_reproduction.py \
  --results-dir runs/development/replay \
  --reference-dir reference/development --allow-model-change
```

The first command checks source/input/config hashes and report/CSV integrity. The second checks the expected case matrix, outcome conservation, and scientific values against the frozen reference, allowing only tiny floating-point differences. It ignores machine-specific path strings when comparing content identity. `--allow-model-change` permits the model source revision to differ from the frozen reference because support for complete observed-channel input was added later; it still requires the new report to match the current source hashes and every reference scientific value. Without the flag, source revisions must also match the reference. A mismatch exits with an error; matching row counts alone are not sufficient evidence of reproduction.

Expected preprocessing counts:

| Batch size `k` | Complete fixed-count groups | Messages left in incomplete tails |
| ---: | ---: | ---: |
| 1 | 133,565 | 0 |
| 5 | 26,549 | 820 |
| 10 | 13,177 | 1,795 |
| 20 | 6,486 | 3,845 |

These are grouping checks. They are **not** counts of authenticated messages. Timeout batching is formed separately during replay and can close smaller groups.

### 6. Generate the figures

```bash
python -m src.experiment.plot_delayed_replay \
  --results-dir runs/development/replay \
  --output-dir runs/development/figures \
  --interval 5
```

This writes PNG, SVG, and PDF versions of:

- `authentication_coverage`: authentication within 1, 5, 10, 30, or 60 seconds after ordinary reception.
- `surveillance_impact`: ordinary reception with and without added authentication traffic, for every `k`.
- `authentication_clocks_and_pending`: ordinary delivery and authentication delays, beside completed/failed/pending fractions.

`delayed_figure_manifest.json` records source and figure hashes. To show a different batch size, change `--interval` to `1`, `10`, or `20`; use a separate output directory to keep both figure sets. Image bytes may differ across plotting platforms even when scientific rows match.

### 7. Run the tests

The following subset runs with only the replay dependencies installed:

```bash
python -m unittest \
  tests.test_delayed_metrics tests.test_delayed_replay \
  tests.test_shared_channel tests.test_channel_trace \
  tests.test_constraint_screening tests.test_hardware_profiles \
  tests.test_replay_experiment tests.test_pipeline \
  tests.test_signed_workload tests.test_signed_replay tests.test_signed_experiment \
  tests.test_reproduction_check -v
```

For the **complete suite**, including real cryptographic transport, first follow [native_crypto.md](docs/native_crypto.md) to build pinned liboqs, install `requirements/crypto.txt`, and verify the loaded library. Then run:

```bash
python -m tests.test_crypto
python -m unittest discover -s tests -v
```

The complete suite checks valid/tampered signatures, checkpoint recovery, raw-message association, fragments/repetition, queues, horizon censoring, and paired collisions. In the development reference, verification is modeled after reconstruction. The new signed workflow also performs actual cryptographic verification of reconstructed objects.

## Where to find the outputs

| Path | Contents |
| --- | --- |
| `runs/development/analysis/` | Capture, aircraft, duplicate, preprocessing, and grouping summaries. |
| `runs/development/processed/experimental_trace.jsonl` | Regenerated canonical DF17 trace. |
| `runs/development/processed/authentication_groups/` | Groups for the four fixed batch sizes. |
| `runs/development/replay/constraint_screening_summary.json` | 16 analytical rows, assumptions, and provenance. |
| `runs/development/replay/replay_summary.json` | 64 replay rows, source/config hashes, scenario parameters, timing evidence, and model limitations. |
| `runs/development/replay/replay_overview.csv` | The same replay rows in tabular form; nested fields are JSON strings. |
| `runs/development/figures/` | Exported figures and their manifest. |
| `reference/development/` | Frozen development results for comparison, not a cache to overwrite. |

For each replay case, read ordinary reception first, then authentication coverage and pending work. In particular:

- `augmented_original_received_fraction` answers how much ordinary traffic was received.
- `additional_original_loss_messages` measures messages received in the paired baseline but lost after authentication traffic was added.
- `threshold_coverage[*].receipt_authentication_fraction` answers how many eligible received messages were authenticated within a stated delay.
- `authenticated_received_fraction` is completion by the entire observation horizon, **not** a common per-message 60-second deadline.
- `receipt_to_auth_ms_p50/p95` describe completed authentications only; `null` means no completions, not zero delay.
- `received_unresolved_messages` and backlog fields show unfinished work. The simulator does not discard it at five seconds.

The collision case destroys every overlapping frame in one collision domain. It excludes capture effects, interference power, geometry, and unobserved traffic; treat it as an uncalibrated sensitivity case. **In these development results**, ordinary transmission has zero added sender delay by construction. The new detached signed workflow measures transmitter waiting, with group collection and signing outside the ordinary transmission path. Neither establishes aircraft measurement-to-transmission compliance from reception timestamps alone.

## Run individual stages or custom scenarios

For step-by-step commands equivalent to the pipeline, including an independent replay invocation, see [the command walkthrough](docs/reproduction_commands.md). Use those commands for separate output directories while a legacy signing job holds the pipeline lock. Never run two writers against the same directory or remove an active lock.

Configurations have distinct roles:

| File | Role |
| --- | --- |
| `config/development.json` | Development input/output paths and stage order. |
| `config/full_window_a.json`, `config/full_window_b.json` | Separate real-signature detached workflows for the two planned one-hour windows and their recorded channel follow-up. |
| `config/full.json` | Convenience copy of the window A configuration. |
| `config/delayed_replay_scenarios.json` | Current 64-case matrix: fixed-count/one-second timeout × independent/collision channel. |
| `config/signed_replay_scenarios.json` | Final-study matrix: three fragment rates × collision-free/overlap channel, exact-count groups, no random loss, 600-second follow-up. |
| `config/algorithms.json` | Algorithm identities and nominal fixed signature sizes. |
| `config/hardware_profiles.json` | Published service-time references and explicit sensitivity profiles. |
| `config/development_recovery.json` | Legacy exhaustive-signing recovery; separate outputs and private checkpoints. |
| `config/replay_scenarios.json` | Historical five-second-deadline model, retained for audit only. |

Copy a scenario/config before changing a published experiment, and use new output directories. Historical development settings remain seed 1, 1% exogenous loss, 100 added frames/s/aircraft, and 60 seconds of follow-up. The current final-study settings differ: fixed-count groups without timeouts, fragment rates 10/50/100, zero exogenous loss, one verification worker, unbounded queues, and a predeclared 600-second follow-up. Its technical seed value 1 has no stochastic effect with fixed cached signatures and service times. These are experimental conditions, not regulatory allowances.

## Run the planned two-window signed experiment

### 1. Prepare native cryptography

First complete [native cryptography setup](docs/native_crypto.md), including its commands to build pinned liboqs, install `requirements/crypto.txt`, and verify the loaded library. Native cryptography is required for this workflow. The development replay environment alone is insufficient.

### 2. Prepare each recorded window and its channel follow-up

Provide two separate one-hour target captures, ideally representing different measured traffic intensities. Record their collection dates, region, receiver coverage, timestamp semantics, filtering, source hashes, and actual durations. These are two traffic scenarios, not random repetitions. Do not concatenate or repeat the development sample to manufacture the data.

Each window also requires an aligned [channel trace](docs/channel_trace.md) containing all **recorded** 1090 MHz events, including non-target traffic, through **600 seconds after the final target plus frame completion**. Decoded-only logs do not establish complete physical RF coverage. Undecodable activity can only be included when actually detected and timed. Adapting the future acquisition format to the canonical channel schema remains a data-preparation task; DF17 preprocessing does not create this file.

Once these files have been prepared in the documented schemas, replace the example source paths below:

```bash
mkdir -p data/full/window_a/raw data/full/window_b/raw
cp /path/to/window-a-targets.jsonl data/full/window_a/raw/adsb_capture.jsonl
cp /path/to/window-a-channel.jsonl data/full/window_a/raw/channel_trace.jsonl
cp /path/to/window-b-targets.jsonl data/full/window_b/raw/adsb_capture.jsonl
cp /path/to/window-b-channel.jsonl data/full/window_b/raw/channel_trace.jsonl
```

### 3. Run and validate each window

```bash
python -m src.pipeline --config config/full_window_a.json
python -m src.pipeline --config config/full_window_a.json --validate-only
python -m src.pipeline --config config/full_window_b.json
python -m src.pipeline --config config/full_window_b.json --validate-only
```

The pipeline runs capture/aircraft/duplicate analysis, preprocessing, and signed replay. Preprocessing preserves repeated message contents. Each replay forms exact-count groups and generates **16 actual signed workloads** (four algorithms × four group sizes), then reuses them across **96 cases** (three rates × two channel settings per workload). No one-second timeout is used. Incomplete final groups remain unsigned, but their ordinary messages still transmit.

Outputs are kept separately:

| Window | Processed trace | Signed-object cache | Results |
| --- | --- | --- | --- |
| A | `runs/full/window_a/processed/experimental_trace.jsonl` | `runs/full/window_a/signed_workloads/` | `runs/full/window_a/replay/` |
| B | `runs/full/window_b/processed/experimental_trace.jsonl` | `runs/full/window_b/signed_workloads/` | `runs/full/window_b/replay/` |

Each result directory contains `replay_summary.json` and `replay_overview.csv`. The configuration `config/full.json` selects the same inputs and destinations as window A; it does not combine the windows.

**Preserve completed signed workloads for exact reproduction.** Keys/signatures are cryptographically generated, and regenerating them can change bytes or variable signature lengths. The replay's technical seed does not determine them. Cache loads verify content and signatures. An interrupted unfinished workload restarts from scratch; completed workloads remain reusable. Native SLH-DSA signing can take substantial time. This workflow uses neither the separate fixed-count `groups` stage nor development signature-size calibration.

### 4. Interpret and inspect the results

Ordinary messages become eligible at their recorded times and have priority over waiting authentication fragments. An already transmitting fragment finishes first. Signer queues affect authentication, not ordinary eligibility. Other recorded traffic stays at its observed times. A timing-matched control removes the fragments while retaining modeled ordinary transmission times, to isolate fragment interference. The destructive-overlap channel drops collisions; it does not make aircraft wait for a clear channel.

Actual host cryptography supplies valid objects; the [embedded profiles](docs/hardware_profiles.md) set modeled processing costs. The model tracks ordinary reception, object reconstruction, original-message availability/association, verification, and pending work separately. The seven-byte signature-only transport cost is an analytical lower bound, not a second executable protocol.

The fixed 600-second follow-up was selected before final runs to cover an isolated largest SLH-DSA group at the slowest configured rate (about 588.5 seconds of signing, fragment delivery, and verification before queues). It is not a guarantee that backlogs drain. Work unfinished at the cutoff remains pending; threshold coverage reports eligible cohorts and exclusions. Additional follow-up traffic interferes but creates no new authentication targets.

The development reference checker and plotting commands above apply to the frozen development results, not these new study outputs. Final data acquisition, analysis, and publication figures remain outstanding. [The walkthrough](docs/reproduction_commands.md) supplies individual preprocessing/replay commands, a small-case check, and optional receiver-worker sensitivity instructions.

Plan RAM, event counts, actual signing time, and storage before running the full study. The supplied `max_events` guard is 20 million per case. If the input exceeds it, explicitly budget resources and change a copied scenario/config rather than truncating recorded traffic. Two- or four-worker receiver cases may be run as separately labeled sensitivity analyses if the one-worker baseline becomes a bottleneck; they are not part of the 192-case default matrix.

## Optional exhaustive signing and legacy material

After native setup and the preprocessing/grouping stages:

```bash
python -m src.pipeline --config config/development.json --stage signatures
python -m src.pipeline --config config/development.json --stage signatures --validate-only
```

This writes new metadata to `runs/development/signatures/`. It is serial, resumable, and can be very slow for SLH-DSA. Re-running resumes validated checkpoints; completed outputs are preserved. Keys are private local `.checkpoints/` state and must not be published. Legacy signing covers concatenated originals; the binary transport prototype additionally signs its descriptor and association context. See [methodology](docs/methodology.md).

Historical derived data and signing outputs remain under `data/development/processed/` and `results/development/` for continuity with existing work. They are not inputs to the new reproduction workflow. Earlier deadline-model notes are clearly separated in [docs/archive/](docs/archive/README.md). The recovery configuration remains usable without moving an active job's files.

## Repository map and license

```text
config/                 Experiment parameters and workflow paths
data/                   Raw sample, provenance, portable calibration
src/analysis/           Capture diagnostics
src/processing/         Canonical trace and fixed-count groups
src/crypto/             Real cryptographic backends
src/experiment/         Screening, transport, replay, metrics, plotting
scripts/                Reproduction checks and native dependency bootstrap
tests/                  Unit, integration, and real cryptographic tests
requirements/           Pinned replay and optional crypto dependencies
docs/                   Current methods/results; explicitly archived older notes
paper/                  Original incomplete PDFs and planning notes
reference/development/  Frozen small result artifacts and environment record
runs/                   Ignored outputs from new experiments
results/development/    Historical artifacts and local recovery state
```

The software is [MIT licensed](LICENSE). Capture provenance and data-use terms are documented separately in [data/README.md](data/README.md); the software license does not establish permission to redistribute third-party data. The repository does not include a published final paper or claim completed final one-hour experiments.
