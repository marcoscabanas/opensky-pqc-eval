# Publication and reproducibility evidence

The goal of a release is that a reader can start with the paper, find the corresponding inputs and configuration, rerun the computation, and compare the scientific outputs. Code alone is not enough to reproduce a particular result: the release also needs its data and signed objects.

## What can be reproduced now

| Material | Status and purpose |
| --- | --- |
| Current detached-authentication demo | Synthetic fixture; real signatures with all four algorithms; 96 cases. Follow [the README](../README.md). |
| Historical development reference | Recorded short sample; 64 earlier replay cases plus 16 analytical rows. Follow [the historical guide](reproduce_development.md). |
| Two-window final experiment | Configurations and executable workflow exist; real inputs, acquisition adapter, final results, and paper mappings are still pending. |
| Paper material | Incomplete drafts and methodology text in [docs/paper/](paper/README.md). No claim that the final paper or study is complete. |

The historical reference is frozen in `results/reference/development/`. Newly generated outputs go under `results/runs/`. Earlier local outputs are preserved separately and must not be relabeled as final results.

## Two kinds of reproduction

**Fresh signing:** obtain the same recorded input, install the stated environment, and run the pipeline without a workload cache. This independently performs real key generation, signing, verification, and replay. Fresh cryptographic randomness can change signature bytes and variable signature lengths; identical paper numbers are not guaranteed.

**Replay of published signed objects:** obtain the exact public workload cache in addition to the same input, source revision, and dependencies. The pipeline validates each cached signature against its messages and replays the same objects. This is the route for comparing a specific published result. Keys and signatures are not controlled by the replay seed. Private keys are unnecessary for verification and must not be included.

Reports contain both content hashes and local paths. A frozen report can be inspected as evidence, but copying it into a different checkout does not make it a valid local run. Recompute local reports from the published cache and use `scripts/compare_signed_results.py` to compare scientific values and content identity while allowing locations to differ. [The command guide](reproduction_commands.md#7-reproduce-a-published-cache-exactly) gives the exact sequence.

The comparison establishes computational agreement under the same model. It does not establish that the channel model or embedded reference profiles describe every physical receiver or aircraft.

## What to publish for the final paper

Prepare the following once the real experiments are complete:

| Evidence | Required contents |
| --- | --- |
| Source release | Immutable commit/tag and the code used to produce the reported results. |
| Environment | Python and package versions; native library/wrapper versions, source commit, build flags, and loaded library location; host platform for offline runtime claims. |
| Acquisition record | Data source/access procedure, dates, exact window boundaries, receiver/region, timestamp semantics, detection/filtering and duplicate handling, coverage limits, and redistribution terms. |
| Input data | Original authorized capture or stable access instructions, canonical target/channel exports, conversion code/commands, hashes, and the full recorded follow-up. |
| Experimental configuration | Both pipeline files, scenario matrix, hardware references, selected profile assumptions, and any separately labeled sensitivities. |
| Public signed objects | All 32 completed algorithm/group-size workloads across the two windows, including public keys, signed bytes, and integrity manifests. |
| Frozen reports | Both `replay_summary.json` and `replay_overview.csv` files, comparison instructions, and the validation/test record. |
| Figures and tables | Exported artifacts, their manifests, and a mapping from each paper item to the source rows and exact generation command. |

Large captures and signed caches may need a versioned external archive rather than Git. The release must provide the actual archive URL/identifier, hash, size, and extraction destination; a placeholder path is insufficient. If redistribution is unavailable, document the access process and whether readers can obtain the same immutable records. A different live query is not necessarily the same dataset.

The software's MIT license does not grant permission to redistribute third-party traffic data. Existing unknown acquisition fields must be resolved from the acquisition record rather than inferred from filenames or the repository name.

Keep private `.checkpoints/`, private keys, credentials, active locks, partial output, machine-local logs, `.venv/`, and native build products out of the public evidence bundle. Publish native build **metadata** needed to identify the environment. The current public signed-workload format contains public keys and signed objects; the legacy generator's private recovery state is a different artifact.

## Record the environment and validate the final runs

After a final run, these commands create a small local environment record. Run them from the repository root with the experiment environment activated:

```bash
mkdir -p results/runs/full/environment
git rev-parse HEAD > results/runs/full/environment/source-commit.txt
python --version > results/runs/full/environment/python-version.txt
python -m pip freeze > results/runs/full/environment/python-packages.txt
python -c "import platform; print(platform.platform()); print(platform.machine())" \
  > results/runs/full/environment/platform.txt
./scripts/bootstrap_liboqs.sh --check
python -m src.pipeline --config config/full_window_a.json --validate-only
python -m src.pipeline --config config/full_window_b.json --validate-only
python -m unittest discover -s tests -v
```

The source commit must identify the actual code that ran; uncommitted changes are not captured by `git rev-parse`. The result reports additionally record relevant source hashes. Preserve the native version/path verification and the bootstrap build metadata described in [native_crypto.md](native_crypto.md), together with the completed validation output.

Before freezing a release, perform a replay from its public cache in a fresh checkout, following the guide. Confirm both window comparisons and regenerate the figures. Package the evidence only after this check succeeds. The demo's successful run does not substitute for this full-data validation.

## Connect the paper to the outputs

The final mapping is pending because neither final window nor final paper figure numbering exists yet. Fill it with actual references after the study:

| Paper item | Dataset and cases | Exact source fields | Generation command/artifact |
| --- | --- | --- | --- |
| Pending final paper | Pending real windows | Pending analyzed rows | Pending release mapping |

Current plotting commands provide these diagnostic outputs for each window:

| Artifact stem | Purpose |
| --- | --- |
| `ordinary_impact` | Ordinary message delivery and additional delay under the modeled traffic. |
| `authentication_outcomes` | Authentication outcomes at the declared observation cutoff. |
| `completed_authentication_delay` | Median reception-to-authentication delay among completed authentications. |

Each is exported as PDF, PNG, and SVG and recorded in `figure_manifest.json`. The scenario columns and algorithm/group-size rows retain the case identities. Interpret completion delay together with coverage and pending outcomes; no-completion cells are not zero delay. Any additional paper plot or table must have an executable derivation rather than undocumented spreadsheet edits.

Final claims must state the recorded domain, processing profiles, channel assumptions, cold start, and fixed follow-up. Keep implementation validation, earlier reference findings, and final study results identifiable throughout the release.

## Validation of this cleanup (2026-10-08)

The reorganized workflow was checked locally on macOS with Python 3.13 and the
pinned installed dependencies:

- All **290 tests passed**, with native cryptography available.
- The synthetic demo generated and verified **112 signatures across all four algorithms** and completed **96 replay cases**.
- A clean copy containing only publication files independently ran fresh signing. A second run there reused the original public cache and matched all **96 scientific result rows** through the portable comparison tool.
- The historical experiment was regenerated from its raw capture. All **64 replay cases and 16 screening rows** matched the frozen reference, allowing the documented historical source-revision difference.
- Current and historical figure commands completed; moved reference/manuscript artifacts retained their original bytes.

The clean-copy check reused the installed pinned Python/native environment. It
was not a new dependency installation or a fresh native compilation. The native
bootstrap dry run was checked; the new Linux CI workflow has not yet been
observed running remotely. Repeat the release checks on the eventual final
source revision and real datasets.

## Where previous files moved

The cleanup consolidates paper material under documentation and generated artifacts under results:

| Previous location | Current location |
| --- | --- |
| `paper/` | `docs/paper/` |
| `reference/development/` | `results/reference/development/` |
| `requirements/replay.txt`, `requirements/crypto.txt` | `config/requirements/replay.txt`, `config/requirements/crypto.txt` |
| Previous local `runs/` contents | `results/archive/local_runs/` |
| New configured run outputs | `results/runs/` |

The root `requirements.txt` installs the pinned replay/plotting and cryptography dependency lists. The earlier large README's development commands now live in [reproduce_development.md](reproduce_development.md); the main README introduces the current workflow.

**Legacy recovery exception:** `config/development_recovery.json`, `data/development/processed/`, and `results/development/` retain their original locations because the existing exhaustive-signing recovery job uses them. Its private checkpoints and output state must not be moved underneath a live process. A new reader follows the demo, final-study, or historical-reference guide; none requires this local recovery state.

Archived outputs retain their original provenance, including historical paths. Moving an archive does not rewrite its evidence or make it a valid cache for new code. Reproduce the corresponding workflow into a new run directory rather than patching archived report hashes. See [results/README.md](../results/README.md) for the artifact inventory.
