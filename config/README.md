# Experiment configurations

Run commands from the repository root. Paths inside JSON configs are relative to
that root, not to this directory. Start with the [main README](../README.md).

| File | Purpose |
| --- | --- |
| `demo.json` | Small synthetic example of the current workflow; all four algorithms and 96 cases. |
| `full_window_a.json`, `full_window_b.json` | The two planned one-hour experiments. Real input files must be supplied first. |
| `signed_replay_scenarios.json` | Current method: detached signing, exact groups, rates 10/50/100 frames/s, two channel settings, 600 s follow-up. |
| `algorithms.json` | Enabled algorithms and exact backend identities. The historical `FN-DSA-512` label means Falcon-512 here. |
| `hardware_profiles.json` | Published processing references and explicitly labeled sensitivity assumptions. |
| `requirements/` | Pinned Python dependencies; the root `requirements.txt` includes both files. |
| `development.json`, `delayed_replay_scenarios.json` | Older 64-case calibrated-size experiment. See [historical reproduction](../docs/reproduce_development.md). |
| `development_recovery.json` | Legacy exhaustive signing; keep its input/output paths intact while recovery is running. |
| `replay_scenarios.json` | Earliest deadline model, retained for historical audit. |
| `full.json` | Compatibility alias: identical to window A. It does not run both windows. |

Modern pipeline configs declare `run_directory` beneath `results/runs/` and keep
all generated paths there. Each run has its own lock, so the demo and the two
windows do not contend with legacy recovery. Configs targeting the same run share
that lock. A new configuration must use a new run directory and update all of its
output paths; the pipeline rejects generated paths outside the declared run.

Legacy configs without `run_directory` retain the original global pipeline lock.
Do not remove an active lock or run independent module writers against the same
outputs. Preserve reference configs and outputs when defining a new experiment.
