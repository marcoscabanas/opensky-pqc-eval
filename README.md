# ADS-B authentication experiment

**Start with two recorded 70-minute windows. Sign the first hour's ADS-B messages. Replay the original traffic together with fragmented signatures. Measure radio interference, ordinary-message delivery, authentication delay and processing backlog.**

An ordinary message is available to its receiver before authentication finishes. Signing retained copies does **not** hold the ordinary message. Ordinary messages and authentication fragments share each modeled aircraft's radio; an already transmitting fragment can delay an ordinary message.

**Status:** the final daytime and nighttime recordings have not been added. There are no final study results in this checkout. Old development data, results, figures, paper drafts and instructions have been moved to local `trash/`, which is ignored by Git and is not needed by any command below.

## 1. Understand the layout

```text
README.md                     This complete reproduction guide
run_experiment.py             Run all steps, or select one step

data/
  daytime.jsonl               Your original daytime recording (add later)
  nighttime.jsonl             Your original nighttime recording (add later)
  manifest.json               Explicit recording times, source and observation domain

config/
  experiment.json             Input/output paths, grouping sizes and window lengths
  algorithms.json             The four cryptographic implementations
  hardware_profiles.json      Sourced processing-time estimates and their limitations
  signed_replay_scenarios.json Radio rates, channel models and other assumptions
  requirements/               Pinned Python dependencies

scripts/
  bootstrap_liboqs.sh          Install/check the native cryptographic library
  01_prepare.py               Prepare inputs and draw cumulative traffic by DF
  02_sign.py                  Generate and verify the real signatures
  03_replay.py                Replay the signed workloads under all scenarios
  04_report.py                Validate results; generate figures, tables and report
  05_compare.py               Compare the two completed windows

src/                          Implementation shared by the numbered scripts
  main_experiment.py          Workflow, input checks and stage coordination
  processing/                 Original recording → target and channel traces
  crypto/                     Signature generation and verification backends
  experiment/                 Fragmentation, queues, channel, metrics and reporting
  runtime.py                  Locks and atomic file writing

tests/                        Automated implementation checks; temporary generated inputs

results/
  daytime/                    Prepared data, signatures, replay, figures and report
  nighttime/                  The same structure for the nighttime recording
  comparison/                 Matched daytime/nighttime figures and report

trash/                        Local historical material; excluded from publication
```

`data/` holds immutable recordings. All generated files go into `results/`. Tests generate tiny inputs in temporary directories; they do not require an old dataset or leave sample experiment results in the study directories.

## 2. Install the environment

Run the following from the repository root. Use **Python 3.13** for the pinned dependencies. macOS and Linux are supported; Windows users need a Linux environment such as WSL. You need Git, a C compiler, CMake and OpenSSL development files.

```bash
git clone https://github.com/marcoscabanas/opensky-pqc-eval.git
cd opensky-pqc-eval
```

On macOS, install the prerequisites if missing:

```bash
xcode-select --install
brew install cmake openssl@3 python@3.13
export OPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
```

On Ubuntu/Debian, install the native build prerequisites and ensure Python 3.13 is available:

```bash
sudo apt-get update
sudo apt-get install build-essential git cmake libssl-dev
python3.13 --version
```

Create the Python environment and build the pinned native library:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
./scripts/bootstrap_liboqs.sh
export OQS_INSTALL_PATH="$PWD/.deps/liboqs"
```

Set the library search path for your operating system:

```bash
# macOS
export DYLD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"

# Linux: use this instead of the macOS line
export LD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
```

Then install and check the Python packages:

```bash
python -m pip install -r requirements.txt
python -m pip check
./scripts/bootstrap_liboqs.sh --check
python -m tests.test_crypto
```

The last command signs and verifies a message with all four algorithms and checks rejection of a modified message. It writes no private keys. The pinned native library is liboqs **0.16.0**, with liboqs-python **0.16.0.1**. The bootstrap installs under `.deps/`; it does not install into system directories. `./scripts/bootstrap_liboqs.sh --dry-run` shows the build commands without running them.

In every new shell, reactivate `.venv` and repeat the `OQS_INSTALL_PATH` and operating-system library-path exports before signing, replaying or validating cryptography.

## 3. Add the original recordings and describe their coverage

Place the original recordings at:

```text
data/daytime.jsonl
data/nighttime.jsonl
```

You can run daytime independently before nighttime is available. Do not replace an input under an existing completed run and assume its old outputs still apply: checksums will reject that reuse.

Each recording covers **70 minutes**:

- `[0, 3600)` seconds: DF17 messages selected for authentication, with all other recorded traffic retained as interference.
- `[3600, 4200)` seconds: recorded traffic continues as interference while authentication work from the first hour may complete. These later DF17 messages do not join the signed target cohort.
- At 4200 seconds, only completed receptions and verification count. Work or frame reception still in progress remains pending; no extra unrecorded channel time is invented.

The first and last observed messages do not establish when recording started or stopped. Fill in `data/manifest.json` using acquisition metadata. For Unix timestamps, a window entry has this form (the `null` values are placeholders you must replace):

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

**The actual acquisition format has not yet been inspected.** If its fields differ, add an explicit adapter preserving the original recording and its provenance before running step 01. Unsupported or malformed rows currently stop preparation, rather than silently removing channel interference. This adapter does not handle undecoded RF pulses or non-Mode-S formats, check CRCs, or deduplicate observations from multiple receivers. Those acquisition properties must be documented; recorded frames do not prove that every real-world 1090 MHz transmission was captured.

## 4. Run the experiment

One command runs preparation, signing, replay and reporting for a window:

```bash
python run_experiment.py --window daytime
```

When the nighttime recording is available:

```bash
python run_experiment.py --window nighttime
python scripts/05_compare.py --window both
```

Alternatively, process both recordings and their comparison in one command:

```bash
python run_experiment.py --window both
```

Both input files are checked before a combined run starts. There is no automatic fallback to sample data. Completed signed workloads are checked and reused. The current signing builder is serial: a completed workload is reusable, but an interrupted unfinished workload starts again. Full SLH-DSA signing can be expensive; the time spent running this computer is distinct from the modeled aircraft processing time.

### Run and inspect each numbered step separately

These commands call the same functions as the combined runner. Replace `daytime` with `nighttime` for the other recording.

| Step | Command | What to inspect |
| --- | --- | --- |
| 01: Prepare | `python scripts/01_prepare.py --window daytime` | `01_prepared/manifest.json`, `traffic.json`, and the cumulative DF figure |
| 02: Sign | `python scripts/02_sign.py --window daytime` | `02_signed/signatures_manifest.json` and public signed workloads |
| 03: Replay | `python scripts/03_replay.py --window daytime` | `03_replay/replay_summary.json` and `replay_overview.csv` |
| 04: Report | `python scripts/04_report.py --window daytime` | `report.md`, `figures/` and figure source tables |
| 05: Compare | `python scripts/05_compare.py --window both` | `results/comparison/report.md` and its figures |

Each relative output in the table is inside `results/daytime/`. Step 01 produces its graph without waiting for signing. Step 03 requires step 02's completed caches; it cannot silently start a new signing workload. Step 04 checks existing replay inputs and signatures before presenting their results; it does not repeat the simulation or generate signatures.

The runner also accepts `--stage prepare`, `sign`, `replay`, `report` or `compare`. Use `--config PATH` on either the runner or numbered scripts to select an explicit alternative configuration; configured relative paths resolve from the repository root.

## 5. Read the outputs and figures

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
  figures/                     PNG, PDF, SVG and underlying metric tables
  report.md                    Figure gallery and interpretation notes
```

The same paths exist for nighttime. The report contains factual summaries and links to the figures; final paper conclusions require review of the actual results and model assumptions. A missing authentication delay is not zero: it means there were no eligible completed observations for that metric.

| Figure family | What it shows |
| --- | --- |
| `01_traffic_by_df` | Cumulative frame counts and cumulative encoded message bytes, separately for every observed DF over all 70 minutes; a marker separates the first hour and follow-up. Bytes include message parity, exclude the preamble, and are not JSON file size or RF airtime. |
| `02_signature_cost` | Actual signature sizes and required authentication fragment counts, for every algorithm and grouping size. |
| `03_channel_load` | Recorded baseline load, added traffic actually transmitted, and total authentication demand, for every algorithm/grouping/rate/channel case. Offered airtime sums frame durations and can exceed 100% under overlap; it is not measured spectrum occupancy. |
| `04_ordinary_delivery` | Modeled baseline and augmented transmission-failure percentages, additional failures attributable to authentication, and ordinary transmission delay. Denominators are labeled in the figures and CSVs. |
| `05_authentication_deadlines` | Fraction authenticated within each specified delay, measured from source availability and separately from ordinary reception. Eligible/excluded counts accompany the percentages. |
| `06_backlog` | Signing, authentication transmission and receiver work still unfinished, including backlog over time. Sampling is explicitly discrete, not a continuously observed queue trace. |
| `07_window_comparison` | Matched daytime/nighttime differences under the same configuration; this appears in `results/comparison/`. |

Each family may have multiple panels/files to cover the complete case matrix. Figures are saved in PNG for browsing and PDF/SVG for publication. There is no separate outcomes-at-cutoff figure; pending/failed counts remain available in the numerical results to interpret coverage and delays correctly.

**Transmission-failure percentages are model predictions.** In the destructive-overlap scenario, overlapping frame envelopes destroy the participating receptions in a single collision domain. The collision-free control removes that effect. We do not claim these percentages are calibrated real-world expected loss rates: received power, capture effects, geometry and receiver diversity are not modeled. In the declared study there is no additional arbitrary random erasure probability.

Do not infer efficiency from low transmitted authentication traffic alone: a slow signer may simply have a large unfinished queue. Do not call daytime “high congestion” or nighttime “low congestion” until the recorded traffic and results support that description. Two windows provide a comparison, not a causal estimate of a general day/night effect.

## 6. Verify and reproduce

Validate an existing complete window without signing, replaying or rewriting outputs:

```bash
python run_experiment.py --window daytime --validate-only
```

Validate both windows and their saved comparison:

```bash
python run_experiment.py --window both --validate-only
```

You can also validate one completed stage:

```bash
python scripts/02_sign.py --window daytime --validate-only
python scripts/04_report.py --window daytime --validate-only
```

Run automated implementation checks:

```bash
python -m unittest discover -s tests -v
```

The tests cover actual signatures, modified-message rejection, fragment reconstruction, receiver association, queues, overlap, cutoff boundaries, input provenance and report integrity. Tests generate temporary synthetic inputs; they establish implementation behavior, not aircraft feasibility.

**Reproduce the procedure from scratch:** use the paper's fixed source revision and dependency versions, obtain its original recordings, complete the matching manifest and run the commands above in a fresh checkout with empty result directories. This generates fresh keys/signatures and new outputs.

**Reproduce the published signed workloads:** obtain the release's original recordings, metadata and public `02_signed/` caches with their inventories, place them in the documented paths, then run the same workflow. It verifies and reuses them. Exact cached reproduction requires the same source and supported backend versions; incompatible identities fail explicitly. To rerun simulation from a preserved cache, use a fresh result tree containing the reproduced `01_prepared/` and published `02_signed/`, with no `03_replay/` output yet. Existing complete replay results are reused after validation, not silently recomputed.

Keys and some signatures use cryptographic randomness; Falcon signature lengths can vary. Therefore fresh signing reproduces the procedure but need not reproduce identical numbers from a frozen signature cache. The replay's compatibility seed does not control key generation or signing randomness. Private keys are never stored in the main signed cache.

Raw JSONL files, generated results and `trash/` are ignored by Git. When publishing the paper, distribute the recordings (subject to their redistribution terms), public signed caches, final results and checksums as a versioned research artifact, with an actual download link and source revision recorded here. **No final dataset or artifact download is available yet.** A code clone alone cannot reproduce data that has not been released or acquired.

## 7. Experimental settings and interpretation

The default matrix is **4 algorithms × 4 grouping sizes × 3 authentication rates × 2 channel models = 96 cases per window**, or 192 for both. The 16 signed workloads per window are reused across their six radio/channel cases.

- Algorithms: ECDSA P-256, ML-DSA-44, Falcon-512 and SLH-DSA-SHA2-128s. The historical code label `FN-DSA-512` selects Falcon-512; it is not a claim of a finalized FN-DSA implementation. The parameter sets do not all represent the same security category.
- Group sizes: `k = 1, 5, 10, 20`, independently per aircraft. Groups close only at exactly `k` messages, with no time-based flush. Incomplete final groups remain unsigned; their ordinary messages still transmit.
- Authentication fragments: an illustrative seven-byte ME allocation, with four header bytes and three data bytes per fragment. Signed metadata also consumes space. No approved ADS-B extension or assigned message type is claimed.
- Rates: 10, 50 and 100 authentication frames/second/aircraft. These are sensitivity settings, not authorized transmission rates or measured channel capacities.
- Processing: one serial signer per aircraft and one shared receiver verification worker. Source timestamps proxy message availability, not measured sensor-generation time. Published hardware-profile service estimates drive replay; offline host execution time does not.
- Hardware evidence: `config/hardware_profiles.json` stores source URLs, platform details and equivalence limitations for every algorithm. The defaults combine embedded reference measurements; Falcon and SLH-DSA include implementation-lineage proxies. They are not a measured common avionics or ground-receiver platform and do not establish worst-case execution times.
- Coverage: observed traffic throughout 70 minutes; a cold start with empty queues, first-hour target cohort, and a fixed observation cutoff. Authentication for messages outside the target cohort is not generated. This is not an indefinitely running steady-state simulation.
- Loss: recorded interference plus either destructive overlap or a collision-free control. Random erasure and receive jitter are zero. The single seed retained for compatibility is not a stochastic replication or an uncertainty estimate.
- Trust and resources: provisioned public keys/session, shared time assumptions, no credential distribution traffic, no feedback retransmission, and unbounded default signing/transmission/verification queues. Backlog measures required work; it does not prove sufficient onboard memory, power or certification suitability.

The software is MIT licensed; recording access and redistribution terms are separate. The experiment evaluates a research model, not an approved airborne authentication protocol.
