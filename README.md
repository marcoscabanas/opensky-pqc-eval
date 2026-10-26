# ADS-B authentication experiment

This repository reproduces a trace-driven experiment: prepare recorded Mode S traffic, sign the first hour's ADS-B messages, replay the traffic with fragmented signatures, and measure reception, authentication delay and processing backlog.

The completed study contains **480 replay cases**, **24 signed workloads**, and **5,678,094 verified signatures** across daytime and nighttime recordings, using ECDSA P-256, Falcon-512 and ML-DSA-44. The first-hour authentication targets are 752,053 daytime messages and 651,084 nighttime messages. ECDSA is the classical reference. SLH-DSA is implemented and tested, but its full replay matrix was not completed; its assessment is analytical and diagnostic.

**Code and data:** GitHub release [`v1.0.0`](https://github.com/marcoscabanas/opensky-pqc-eval/tree/v1.0.0) corresponds to **Zenodo version v1**, containing the recordings, signed workloads and reference results under DOI [10.5281/zenodo.23652076](https://doi.org/10.5281/zenodo.23652076). A code-only clone does not include the experimental data. Follow the tagged-clone instructions below to obtain the software that matches those artifacts.

## 1. Choose what to reproduce

| Workflow | What you do |
| --- | --- |
| **A. Reproduce the published results** | Use the original recordings and saved signatures, rerun the simulation, and generate results and figures |
| **B. Run everything from raw recordings** | Prepare the recordings, generate and verify new signatures, run the simulation, and generate results and figures |

**Choose A to reproduce the published simulation using its original signed inputs.** Workflow B reproduces the complete procedure, but new keys/signatures are randomized and Falcon signature lengths can change. A replay seed controls simulated capture priorities, not cryptographic randomness. Both workflows include figure generation after calculating the results.

## 2. Obtain the matching code and data

Use the **[GitHub `v1.0.0` tag](https://github.com/marcoscabanas/opensky-pqc-eval/tree/v1.0.0) and [Zenodo artifact version 10.5281/zenodo.23652076](https://doi.org/10.5281/zenodo.23652076)** together. The default branch may contain later documentation or development changes; the tag preserves the exact software files archived with the experiment. There is no continuous synchronization between the services: the release identifies the software, and `artifact_manifest.json` identifies the corresponding data and reference results. The restoration helper checks every archived code file, including the README, before placing data in the checkout.

**Version labels:** the immutable Zenodo files retain the original `v0.1.0` filenames, package version and metadata. Git tags `v1.0.0` and `v0.1.0` point to the same archived commit, `38eb299f7dfaa8ab6070b05ba88e104d8094cf8e`. Both names therefore select identical files; keep the downloaded filenames and metadata unchanged.

Clone the matching version. `--depth 1` avoids downloading historical development data:

```bash
git clone --depth 1 --branch v1.0.0 --single-branch https://github.com/marcoscabanas/opensky-pqc-eval.git
cd opensky-pqc-eval
mkdir -p ../zenodo-downloads
```

Download the following files from [the matching Zenodo deposit](https://doi.org/10.5281/zenodo.23652076) into `../zenodo-downloads/`. Do not substitute an unrelated deposit or mix artifact versions.

| Workflow | Required downloads | Approximate download size | Restore profile |
| --- | --- | ---: | --- |
| A | `artifact_manifest.json`, `metadata-and-results.zip`, and all 30 JSONL files (2 raw, 4 prepared, 24 signed) | 13.14 GB | `replay` |
| B | `artifact_manifest.json`, `metadata-and-results.zip`, `raw-daytime.jsonl`, `raw-nighttime.jsonl` | 2.52 GB | `fresh` |

Download the deposit's licence and provenance notes as well. The accompanying `code-snapshot-*.zip` is a preservation copy of the same release; it is **not required for a GitHub checkout**. If GitHub is unavailable, extract that snapshot into its own directory and follow the same commands from there.

Run **one** of these commands from the repository root:

```bash
# A: restore recordings, prepared inputs and the original saved signatures
python3 scripts/restore_artifacts.py --artifacts-dir ../zenodo-downloads --profile replay

# B: restore recordings and metadata; generate new signatures later
python3 scripts/restore_artifacts.py --artifacts-dir ../zenodo-downloads --profile fresh
```

The helper needs Python 3.9 or newer and no third-party packages. It checks download and extracted-file hashes and restores their original paths into this checkout. The recording description, `data/manifest.json`, already comes with the GitHub release. Both profiles omit completed replay outputs so the simulation actually runs. Fresh restoration needs only the two raw files and `artifact_manifest.json`; its listed `metadata-and-results.zip` download is used later for the reference comparison in step 6. Keep the download directory available until that comparison finishes.

Add `--dry-run` to preview the selected restoration. If you want to perform both workflows, use a separate clone for each: an existing cache or completed result is otherwise reused, so running B after A in the same tree would not generate fresh signatures.

**Storage:** an ordinary copy-based restore of A needs about **26.3 GB for downloads plus restored artifacts**, before dependencies, temporary files, restart checkpoints and new outputs. Workflow B initially downloads less, but the archived public signature caches alone occupy about **8.96 GB across both recordings**; freshly generated caches need comparable space. These are file-size estimates, not maximum disk or RAM requirements. Copy-on-write filesystems may initially use less physical space.

## 3. Install the environment

Use **Python 3.13** for the pinned experiment environment. The package metadata's minimum Python version is not the pinned reproduction environment. macOS and Linux are supported; Windows users need a Linux environment such as WSL.

Both workflows use the same environment. Install a C compiler, Git, CMake, OpenSSL development files and Python 3.13. On macOS, if missing:

```bash
xcode-select --install
brew install cmake openssl@3 python@3.13
export OPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
```

On Ubuntu/Debian, install the native prerequisites and ensure Python 3.13 is available:

```bash
sudo apt-get update
sudo apt-get install build-essential git cmake libssl-dev
python3.13 --version
```

Create the environment and install the pinned native library locally:

```bash
python3.13 -m venv .venv
source .venv/bin/activate
bash scripts/bootstrap_liboqs.sh
export OQS_INSTALL_PATH="$PWD/.deps/liboqs"
```

Run the library-path command for your operating system:

```bash
# macOS
export DYLD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"

# Linux: use this instead of the macOS command
export LD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
```

Install and check the Python dependencies:

```bash
python -m pip install -r requirements.txt
python -m pip check
bash scripts/bootstrap_liboqs.sh --check
python -m tests.test_crypto
```

The native library is liboqs **0.16.0**, with liboqs-python **0.16.0.1**. The check signs and verifies with all four algorithms and rejects modified messages. The bootstrap installs in `.deps/`, not system directories; `--dry-run` previews the build. In each new shell, activate `.venv` and repeat the `OQS_INSTALL_PATH` and operating-system library-path exports.

## 4. Run your chosen workflow

### A. Reproduce the published results using saved signatures

```bash
python run_experiment.py --window both --stage replay
python run_experiment.py --window both --stage report
python scripts/05_compare.py --window both
python scripts/06_paper_figures.py
python scripts/07_methodology_figures.py
```

The `replay` restoration profile supplies prepared traces and public signed workloads, but excludes saved replay results. The runner validates input hashes, source identity and supported backend versions before replay. It does not silently generate a replacement signed workload.

### B. Run everything from raw recordings

```bash
python run_experiment.py --window both
python scripts/06_paper_figures.py
python scripts/07_methodology_figures.py
```

The combined runner performs **steps 01–05**, including the daytime/nighttime comparison. Steps **06 and 07 are separate presentation commands**. To run one recording first, use `--window daytime` or `--window nighttime`; comparison and the paper figures need both completed windows.

Full runs are substantial jobs. Signing uses up to four processes; set `ADSB_SIGNING_WORKERS=2` to reduce concurrency. Replay scenarios run sequentially to limit peak memory. Existing matching signed workloads and completed replay cases are validated and reused after interruption; private keys are not saved. Keep in-progress checkpoints when resuming. Details and the resource-preflight command are in the [experiment reference](docs/experiment_reference.md#check-computational-resources-before-signing).

### Run individual stages

These commands call the same implementation as the combined runner. Output paths below are relative to `results/daytime/`, except comparison.

| Step | Command | Main output |
| --- | --- | --- |
| 01: Prepare | `python scripts/01_prepare.py --window daytime` | `01_prepared/` target/channel traces and traffic counts |
| 02: Sign | `python scripts/02_sign.py --window daytime` | `02_signed/` signatures, public keys and manifests |
| 03: Replay | `python scripts/03_replay.py --window daytime` | `03_replay/replay_summary.json` and CSV |
| 04: Tables and figures | `python scripts/04_report.py --window daytime` | `figures/` numerical CSV tables, PDF figures and figure manifest |
| 05: Compare | `python scripts/05_compare.py --window both` | `results/comparison/` numerical tables and PDF figures |

Replace `daytime` with `nighttime` as needed. `--config PATH` selects an alternative configuration; its relative paths resolve from the repository root. Changing scientific inputs or settings changes the experiment identity and is a separate run.

## 5. Find the code and outputs

```text
run_experiment.py   Combined experiment command
scripts/           Stage commands, artifact restoration, reference comparison and setup
src/               Scientific implementation (processing, cryptography, simulation)
config/            Study settings, hardware profiles and pinned dependencies
tests/             Automated implementation checks
docs/              Detailed experiment reference
data/              Recording manifest (GitHub); original recordings restored from Zenodo
results/
  daytime/         Prepared data, signatures, numerical results and PDF figures
  nighttime/       The same structure for nighttime
  comparison/      Matched daytime/nighttime results
  paper/           Compact paper figures, methodology diagrams and provenance
```

After running the experiment, open the PDF figures in [daytime](results/daytime/figures/), [nighttime](results/nighttime/figures/) and [comparison](results/comparison/figures/). Their numerical tables are saved alongside them; complete per-case metrics and provenance remain in each window's `03_replay/` CSV and JSON files. These outputs are absent from a code-only clone.

Each archived window also retains `input_audit.json`: a historical inspection of recording quality and timestamp limitations. It supports the study's provenance but is not required to execute the pipeline. Final traffic counts come from `01_prepared/`.

For code responsibilities, see the [code map](src/README.md). For every figure's meaning, acquisition details, scenario settings and limitations, see the [experiment reference](docs/experiment_reference.md). `scripts/00_capture.py` is optional acquisition tooling for a **new** study: it produces a raw `.beast` recording, which requires conversion before preparation. It is not a first step for reproducing the supplied recordings.

## 6. Verify the reproduction

With the full environment installed, check existing results without rewriting them:

```bash
python run_experiment.py --window both --validate-only
```

This validates internal consistency, provenance and cached inputs. To also compare your calculated results with the archived reference values, run:

```bash
python scripts/08_compare_reference.py --artifacts-dir ../zenodo-downloads
```

The comparison reads the reference tables directly from the verified archive; it does not overwrite your results. Workflow A should match the reference: integer counts must agree exactly, while floating-point values use relative and absolute tolerances of `1e-9`. It compares numbers and workload metadata, not the binary contents of PDFs; case and CSV column order do not matter. Run `python scripts/08_compare_reference.py --help` for the comparison rules and single-window option. In workflow B, fresh keys and signatures change workload identities; Falcon's variable signature lengths can also change the numerical results. A reported difference then identifies a change to inspect, rather than proving the implementation is wrong.

You can validate a single window or completed stage instead:

```bash
python run_experiment.py --window daytime --validate-only
python scripts/02_sign.py --window daytime --validate-only
python scripts/04_report.py --window daytime --validate-only
```

Run the implementation tests:

```bash
python -m unittest discover -s tests -v
```

Tests use temporary generated inputs and cover signatures, tampering, fragmentation, queues, reception, cutoff boundaries and provenance. They do not require historic sample datasets or establish aircraft feasibility. Existing complete replay results are checked and reused, not implicitly rerun; both restoration profiles initially omit those results. For setup or restart problems, see [restoration and reproduction troubleshooting](docs/experiment_reference.md#restoration-and-reproduction-troubleshooting).

## Interpretation and licensing

Both windows are **conditional simulations**, not calibrated operational RF-loss measurements. The decoded recordings omit original receiver counters, undecoded transmissions and Mode A/C replies; supplied timestamps are assumed transmission/message-availability times. Read the [recording limitations](docs/experiment_reference.md#current-recordings-conditional-simulation) and [model assumptions](docs/experiment_reference.md#experimental-settings-and-interpretation) before interpreting results.

Ordinary reception and authentication are separate: signing retained message copies does not hold ordinary transmission, although an already transmitting authentication fragment can delay a message sharing the aircraft's radio. Every recorded frame is accepted in the no-authentication baseline. Added-traffic capture results depend on seeded interference assumptions; no-interference controls isolate processing, transmission pacing and queues.

Software is [MIT licensed](LICENSE). Recordings and generated experimental artifacts are **CC BY 4.0**. Local environments, logs, locks and restart checkpoints are not publication artifacts. Use the matching software tag and Zenodo version linked above when citing or reproducing this release.

## Authors

This repository accompanies the paper *Trace-Driven Evaluation of Post-Quantum Authentication for ADS-B Using OpenSky Network Data*, by:

| Author | Affiliation(s) |
| --- | --- |
| **Marcos Cabañas Maldonado** | Faculty of Aerospace Engineering, Delft University of Technology, Delft, Netherlands |
| **Junzi Sun** | Faculty of Aerospace Engineering, Delft University of Technology, Delft, Netherlands; OpenSky Network, Burgdorf, Switzerland |
| **Martin Strohmeier** | Cyber-Defence Campus, armasuisse Science & Technology, Zurich, Switzerland; OpenSky Network, Burgdorf, Switzerland |

Corresponding author: Marcos Cabañas Maldonado — [marcoscabanas@outlook.com](mailto:marcoscabanas@outlook.com).

## Acknowledgements

This work is partially supported by the PostQat project, funded by the European Union’s Horizon Europe research and innovation program through the SESAR Joint Undertaking under grant no. **101286435**. Views and opinions expressed are those of the authors only and do not necessarily reflect those of the European Union or SESAR3 Joint Undertaking. Neither the European Union nor SESAR3 Joint Undertaking can be held responsible for them.
