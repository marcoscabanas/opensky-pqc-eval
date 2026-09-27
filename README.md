# OpenSky PQC Evaluation

A trace-driven evaluation framework for studying post-quantum signature overhead and feasibility in ADS-B authentication scenarios using OpenSky capture data.

This repository is structured to preserve the original scientific behavior while making the pipeline reusable and config-driven. The core pipeline is implemented as a package-based Python project under `src/`, with dataset and operational configuration separated into `config/`, `data/`, and `results/`.

## Project goal

The project evaluates whether candidate post-quantum digital signature schemes can operate under real ADS-B traffic conditions and how they affect:

- authentication event size
- channel occupancy
- latency
- receiver verification workload
- operational feasibility under realistic traffic density

The overall goal is not to invent a new protocol, but to perform a reproducible, trace-driven assessment of standardized and selected post-quantum signature schemes against real surveillance traffic.

## Scientific scope and constraints

The project works within the following assumptions:

- ADS-B 1090ES is a globally deployed broadcast surveillance protocol with tight operational constraints.
- The study focuses on source authentication and message integrity, not broader aviation security objectives such as jamming mitigation, GNSS spoofing defense, or PKI design.
- The pipeline is intentionally designed to preserve the original filtering, grouping, signing, hashing, key management, and validation logic.
- The refactor does not alter the scientific behavior of the underlying processing steps.

## Repository layout

```text
opensky-pqc-eval/
├── README.md
├── LICENSE
├── pyproject.toml
├── requirements.txt
├── .venv/
├── config/
│   ├── algorithms.json
│   ├── development.json
│   └── full.json
├── data/
│   ├── development/
│   │   ├── raw/
│   │   └── processed/
│   └── full/
├── results/
│   ├── development/
│   └── full/
├── src/
│   ├── __init__.py
│   ├── pipeline.py
│   ├── analysis/
│   │   ├── analyze_capture.py
│   │   ├── analyze_aircraft.py
│   │   └── analyze_duplicates.py
│   ├── processing/
│   │   ├── preprocess_capture.py
│   │   └── build_authentication_groups.py
│   ├── experiment/
│   │   └── generate_signatures.py
│   └── crypto/
│       ├── common.py
│       ├── ecdsa_p256.py
│       ├── ml_dsa_44.py
│       ├── fn_dsa_512.py
│       └── slh_dsa_sha2_128s.py
├── tests/
│   ├── __init__.py
│   ├── test_crypto.py
│   └── inspect_signature.py
└── layout.md
```

## Supported cryptographic algorithms

The current evaluation includes:

- `ECDSA-P256` as the classical reference baseline
- `ML-DSA-44` (module-lattice PQC)
- `FN-DSA-512` / Falcon-512 lineage
- `SLH-DSA-SHA2-128s` (hash-based PQC)

ECDSA is included as a non-quantum baseline for comparison only; it is not meant to imply that ADS-B currently authenticates traffic with ECDSA, and it should be interpreted as a reference point against which the PQC schemes are evaluated.

The active config is defined in `config/algorithms.json` and the module paths are package-based under `src.crypto.*`.

## Environment setup

Create and activate a Python virtual environment from the repo root:

```bash
cd /path/to/opensky-pqc-eval
python3 -m venv .venv
source .venv/bin/activate
```

Install the project dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### Native dependency note for liboqs

The project uses `liboqs-python`, which may require the native `liboqs` build toolchain. On macOS, the dependency is commonly resolved with:

```bash
brew install cmake
```

The project is also declared in `pyproject.toml` for package-based use.

## Recommended workflow

The intended normal workflow is:

```bash
source .venv/bin/activate
python -m src.pipeline --config config/development.json
```

For the eventual full dataset:

```bash
source .venv/bin/activate
python -m src.pipeline --config config/full.json
```

This is the supported project entry point and it orchestrates the stages in order.

## Pipeline stages

The pipeline is implemented in `src/pipeline.py` and follows this order:

1. `capture`
2. `aircraft`
3. `duplicates`
4. `preprocess`
5. `groups`
6. `signatures`

### Stage descriptions

- `capture`: analyzes the raw ADS-B capture and produces a capture summary.
- `aircraft`: summarizes aircraft-level detections and type statistics.
- `duplicates`: analyzes repeated or duplicated messages.
- `preprocess`: filters valid DF17 records, sorts deterministically, computes relative timing, and writes a canonical processed trace plus manifest.
- `groups`: builds per-aircraft authentication groups for configured intervals such as `1`, `5`, `10`, and `20`.
- `signatures`: signs the authentication groups for the enabled algorithms and writes per-algorithm signature outputs and experiment summaries.

## Config-driven execution

The repo uses JSON configs in `config/`.

### Development configuration

`config/development.json` contains the development dataset paths and settings:

```json
{
  "dataset_name": "development",
  "raw_capture": "data/development/raw/adsb_sample.jsonl",
  "processed_trace": "data/development/processed/experimental_trace.jsonl",
  "authentication_groups_dir": "data/development/processed/authentication_groups",
  "analysis_results_dir": "results/development/analysis",
  "signature_results_dir": "results/development/signatures",
  "authentication_intervals": [1, 5, 10, 20],
  "algorithms_config": "config/algorithms.json"
}
```

### Full configuration

`config/full.json` is reserved for the eventual full dataset configuration. It follows the same structure and allows the same refactored pipeline to run without changing the underlying scientific code.

## Data and result directories

### Input data

- `data/development/raw/` contains the development capture.
- `data/development/processed/` contains processed trace and authentication group outputs.
- `data/full/` is the target location for the eventual full experimental capture.

### Result artifacts

- `results/development/analysis/` contains summary JSON outputs from analysis stages.
- `results/development/signatures/` contains signature experiment summaries and algorithm outputs.
- The same pattern is used for the full dataset once it is available.

## Validation and reproducibility

The scientific behavior has been preserved across the refactor, and the project was validated against known development outputs.

### Verified development counts

The development pipeline produced the expected group counts:

- `k=1`: 133,565 complete groups
- `k=5`: 26,549 complete groups
- `k=10`: 13,177 complete groups
- `k=20`: 6,486 complete groups

These values match the previously validated scientific outputs.

### Cryptographic validation

The project’s crypto smoke tests confirm the original signing and verification behavior remains intact:

- ECDSA P-256 verification succeeds for valid data and fails for tampering
- ML-DSA-44 verification succeeds for valid data and fails for tampering
- FN-DSA-512 verification succeeds for valid data and fails for tampering
- SLH-DSA-SHA2-128s verification succeeds for valid data and fails for tampering

### Independent signature audit

The repository contains a direct audit script, `tests/inspect_signature.py`, which can inspect an aircraft authentication event and verify:

- hash match
- input length match
- aircraft match
- k match
- recorded verification status

The audit confirmed the expected results for a selected `k=20` event, including a matching SHA-256 digest and successful recorded verification.

## Direct test commands

The project supports running the tests from the repo root with the package on the Python path:

```bash
source .venv/bin/activate
PYTHONPATH=. python tests/test_crypto.py
PYTHONPATH=. python tests/inspect_signature.py \
  --trace data/development/processed/experimental_trace.jsonl \
  --groups data/development/processed/authentication_groups/authentication_groups_k20.jsonl \
  --signatures results/development/signatures/signatures_ECDSA-P256_k20.jsonl \
  --group-id 1
```

This resolves the `src` package correctly when the repository root is the working directory or when `PYTHONPATH` includes the project root.

## Key project principle

The repository was refactored to improve reuse and operational simplicity without changing scientific behavior. The logic for:

- filtering
- grouping
- signing
- hashing
- key handling
- verification

was preserved and the execution was standardized around `python -m src.pipeline` so the same code path can be used for both development and full-dataset runs.

## Example commands

### Run the full development pipeline

```bash
source .venv/bin/activate
python -m src.pipeline --config config/development.json
```

### Run only the preprocessing stage

```bash
source .venv/bin/activate
python -m src.pipeline --config config/development.json --stage preprocess
```

### Run only the group generation stage

```bash
source .venv/bin/activate
python -m src.pipeline --config config/development.json --stage groups --force
```

### Run only the signing stage

```bash
source .venv/bin/activate
python -m src.pipeline --config config/development.json --stage signatures --force
```

## Notes on execution model

The project is intended to be run from the repository root using the virtual environment. This ensures the module path and config path resolution work correctly for all stages.

The direct script pattern from older locations is not the supported execution path after the package refactor. If needed, use `PYTHONPATH=. python ...` or, preferably, use the package entry point via `python -m src.pipeline`.

## Summary

This project provides a reproducible OpenSky-based evaluation harness for ADS-B authentication using cryptographic signatures under constrained operational conditions. It preserves the validated scientific behavior, gives a clean package structure under `src/`, exposes a single orchestration entry point, and is configured for both development and full-data execution modes.

---

For the most current execution workflow, use the repository root and the following command pattern:

```bash
source .venv/bin/activate
python -m src.pipeline --config config/development.json
```
