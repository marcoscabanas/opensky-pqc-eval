# Frozen development reference

This directory contains the completed delayed-authentication sample experiment:
64 replay cases, 16 analytical screening rows, the exported calibration, figures,
and the producing Python environment. Follow [the main README](../../README.md)
to regenerate outputs under `runs/` and compare them here.

The reports and CSVs were copied verbatim from the validated run, preserving
integrity digests. Absolute paths inside them are provenance labels from the
producing checkout; new machines do not need those paths. Recompute locally and
use `scripts/check_reproduction.py` to compare content hashes and scientific
values. Do not rewrite a report's paths or hashes to make it look local.

The later complete-channel extension preserves the default scientific results
but changes the model's source hashes. Use the README's `--allow-model-change`
comparison command for a fresh run of that revision: it verifies current source
hashes and every frozen scientific value while permitting the source revision
to differ. These reference reports still represent DF17-only channel traffic.

`environment.json` records pinned package versions and validation scope. The
replay itself needed no native crypto installation. Real cryptographic transport
was checked separately with liboqs 0.16.0 / wrapper 0.16.0.1. Native bootstrap
syntax/safety behavior was checked, but this task did not build a new native
library or validate a Linux native compilation. The added CI workflow is intended
to run the replay-only subset on Linux; its remote execution has not been observed.

The one seed and development capture validate implementation and reproduction;
they do not provide confidence intervals, a final one-hour dataset, calibrated
RF loss, aircraft measurements, or a deployed protocol allocation. Read
[the results guide](../../docs/development_results.md) and
[methodology](../../docs/methodology.md) alongside the numbers.
