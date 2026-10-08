# OpenSky PQC evaluation

**What happens if aircraft add digital signatures to ADS-B traffic?** This repository takes recorded messages, generates real signatures, splits those signatures into additional transmissions, and simulates reception. It measures ordinary message delivery, time until authentication, authentication coverage, processor queues, and added channel load.

An ordinary message can be received and read before its authentication completes. Signing operates on retained copies; grouping and signing do not hold the original message. Authentication fragments share the modeled aircraft radio with ordinary messages.

## Start here

| What you want to do | Where to start |
| --- | --- |
| Explain the whole project to supervisors or new collaborators | Read the [plain-language meeting guide](docs/supervisor_meeting_guide.md). |
| Check the current experiment, including all four algorithms | Run the small demo below. |
| Run the planned two-window study | Follow [the full reproduction commands](docs/reproduction_commands.md). |
| Reproduce the historical development results | Follow [the separate development guide](docs/reproduce_development.md). |
| Understand the methods or input formats | Open [the documentation index](docs/README.md). |
| Prepare the paper's reproducibility release | Follow [the publication guide](docs/publication.md). |

**Study status:** the two final one-hour datasets have not yet been supplied or evaluated. The demo is synthetic implementation validation. The frozen development reference uses an earlier model and a short recorded sample. Neither is a completed final experiment. Dataset acquisition commands and paper-to-figure mappings will be recorded when the real data and paper are finalized.

## Run the current experiment on a small demo

Run these commands from the repository root in the same Bash or Zsh shell. macOS and Linux are supported; Windows users should use a Linux environment such as WSL. Use **Python 3.13** for the pinned environment. You also need Git, a C compiler, CMake, and OpenSSL development files; [native setup](docs/native_crypto.md) gives the operating-system installation commands.

### 1. Clone and create the Python environment

```bash
git clone https://github.com/marcoscabanas/opensky-pqc-eval.git
cd opensky-pqc-eval
python3.13 -m venv .venv
source .venv/bin/activate
```

If you already have a checkout, enter it instead of cloning again. An editable package installation is unnecessary; commands use `python -m` from this directory.

### 2. Install the pinned dependencies

The native build is needed for actual post-quantum signing and verification. It installs locally in `.deps/`.

```bash
./scripts/bootstrap_liboqs.sh
export OQS_INSTALL_PATH="$PWD/.deps/liboqs"
if [ "$(uname -s)" = "Darwin" ]; then
    export DYLD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
else
    export LD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi
python -m pip install -r requirements.txt
python -m pip check
./scripts/bootstrap_liboqs.sh --check
python -m tests.test_crypto
```

The last command signs, verifies, and rejects a modified message with each algorithm. The pinned versions are liboqs **0.16.0** and liboqs-python **0.16.0.1**. [Native setup](docs/native_crypto.md) also shows how to verify the loaded library path. In a new shell, reactivate `.venv` and repeat the `OQS_INSTALL_PATH` and platform-specific library-path exports.

### 3. Run the demo

```bash
python -m src.pipeline --config config/demo.json
```

The demo runs the same detached-authentication workflow and **96-case matrix** as one study window. Its 21 synthetic target messages produce **112 real signatures in 16 cached workloads**, using ECDSA P-256, ML-DSA-44, Falcon-512, and SLH-DSA-SHA2-128s. The code's historical label `FN-DSA-512` selects the Falcon-512 backend.

Each algorithm signs groups of 1, 5, 10, and 20 messages. The signatures are reused at 10, 50, and 100 authentication frames/s/aircraft, in a collision-free control and a destructive-overlap channel model. There is no group timeout, additional random loss, or stochastic repetition. See [methodology](docs/methodology.md) for the transport and timing assumptions.

This is a small functional check, not a traffic-capacity result. Host execution time is separate from modeled aircraft/receiver time.

### 4. Check the outputs

```bash
python -m src.pipeline --config config/demo.json --validate-only
python scripts/check_demo.py
```

Validation checks the saved run against its inputs and configuration. The demo checker additionally checks the expected case matrix and outcome consistency. An integrity check is not a substitute for evaluating the scientific assumptions.

### 5. Generate figures

```bash
python -m src.experiment.plot_signed_replay \
  --results-dir results/runs/demo/replay \
  --output-dir results/runs/demo/figures \
  --label "Synthetic implementation demo"
```

| Output | Location |
| --- | --- |
| Prepared messages | `results/runs/demo/processed/experimental_trace.jsonl` |
| Real signed objects and public keys | `results/runs/demo/signed_workloads/` |
| Full results and provenance | `results/runs/demo/replay/replay_summary.json` |
| Tabular results | `results/runs/demo/replay/replay_overview.csv` |
| Figures and their source manifest | `results/runs/demo/figures/` |

The three figures are `ordinary_impact`, `authentication_outcomes`, and `completed_authentication_delay`, each in PDF, PNG, and SVG format. Read pending and failed counts alongside delay percentiles: a missing delay value means no completed authentication, not zero delay.

### 6. Run the automated tests

```bash
python -m unittest discover -s tests -v
```

With native cryptography installed, the suite includes actual signatures, altered-message rejection, fragmentation, receiver association, queues, collisions, and result integrity. Test fixtures are not final-study results.

### 7. Run the real study when its inputs are available

Prepare the inputs described in [the full reproduction guide](docs/reproduction_commands.md), then run:

```bash
python -m src.pipeline --config config/full_window_a.json
python -m src.pipeline --config config/full_window_a.json --validate-only
python -m src.pipeline --config config/full_window_b.json
python -m src.pipeline --config config/full_window_b.json --validate-only
```

Each window requires its one-hour target messages **and aligned recorded 1090 MHz channel traffic through the subsequent 600 seconds plus frame completion**. The channel includes recorded non-target traffic. An acquisition-format adapter remains to be supplied with the real dataset; target preprocessing alone cannot construct this input.

The windows produce **192 cases in total**, under `results/runs/full/window_a/` and `results/runs/full/window_b/`. The guide includes their plotting commands. Plan resources before launching: full SLH-DSA workloads can take days and require substantial storage. The workload builder is currently serial; an unfinished workload restarts after interruption, while completed workloads are reused.

## Repository layout

```text
config/       Experiment settings and pinned dependency lists
data/         Input fixtures, recorded sample, calibration, and provenance
src/          Processing, cryptography, simulation, metrics, and plotting
scripts/      Setup and reproduction checks
tests/        Automated verification
docs/         Methods, instructions, paper material, and historical notes
results/      Frozen references, newly generated runs, and local archives
```

Start with `config/demo.json`; use `config/full_window_a.json` and `config/full_window_b.json` for the study. `config/full.json` is a window A alias. Historical configurations are explained in [the development guide](docs/reproduce_development.md).

New runs go in `results/runs/`; the frozen development reference is in `results/reference/development/`. Historical files needed by the existing signing recovery job retain their original locations. [The publication guide](docs/publication.md#where-previous-files-moved) records the moves and this exception.

## Reproducing a paper result

**Fresh signing reproduces the procedure, but need not reproduce identical signature bytes or sizes.** Keys and some signatures use cryptographic randomness. Exact reruns therefore need the published signed-object cache as well as the same recorded data, configuration, source revision, and environment. The replay seed does not fix cryptographic randomness. Public keys and signatures can be shared without private keys.

The final release will need the data access instructions, signed caches, frozen reports, and figure-to-paper mapping described in [publication.md](docs/publication.md). Those final artifacts do not exist yet. The existing [historical reference](results/reference/development/) already has its own validation workflow.

The software is [MIT licensed](LICENSE). Dataset provenance and redistribution terms are separate; see [data/README.md](data/README.md). These models are research experiments, not approved ADS-B protocol extensions or aircraft certification results.
