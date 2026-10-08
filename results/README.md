# Results: start here

| Directory | What it means | Published in Git? |
| --- | --- | --- |
| `runs/demo/` | Your small synthetic demonstration of the current signed experiment. | No; regenerate it. |
| `runs/full/window_a/`, `runs/full/window_b/` | Your two real-data experiments, once the inputs exist. | No; publish selected completed artifacts with the paper release. |
| `runs/development/` | Your reproduction of the older 64-case development experiment. | No; regenerate it. |
| [reference/development/](reference/development/README.md) | Frozen historical reports, figures, calibration, and environment. | Yes; compare against these, never overwrite them. |
| `development/` | Legacy analysis/signature metadata and local signing recovery. | Public historical metadata only; private recovery state is ignored. |
| `archive/local_runs/` | Local experiments and an old environment preserved during the layout cleanup. | No. |

Every new run puts its derived trace, analysis, public signed workloads, replay
reports, and figures in one directory under `runs/`. The repository-root
[README](../README.md) gives the exact commands and [publication guide](../docs/publication.md)
explains what to preserve for independent reproduction.

The two final one-hour windows have not been evaluated. The reference figures
are results of the historical model; the demo figures exercise the current
implementation using synthetic input. Neither is a substitute for final-study results.

The legacy recovery job uses `development/recovery/` together with
`data/development/processed/`. These paths are deliberately preserved. Its
private `.checkpoints/`, partial files, and logs must stay out of publication.
Legacy metadata stores signature digests and verification outcomes; the current
workflow instead stores complete signed objects and public keys.

Archived reports keep their original bytes and provenance paths. Moving a
directory does not turn an old report into a current run. Recreate outputs in
`runs/` using the documented commands. The archived Python environment is only
a preserved local artifact; create a new `.venv` rather than executing it.
