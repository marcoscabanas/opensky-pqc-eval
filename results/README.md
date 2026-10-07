# Historical outputs

Existing development analysis, signature metadata, and local recovery state are
preserved here for continuity. The recovery configuration still uses its original
paths. Private `.checkpoints/` directories, logs, partial files, and recovery
outputs are ignored and must not be included in a publication.

The default development/full configurations now write to **`runs/`**. Frozen
current replay results are in [reference/development/](../reference/development/).
The earlier `development/replay/` deadline model and the intermediate
`development/delayed_replay/` run are retained locally and ignored; they are not
the published reference. Stale summaries from the interrupted original signing
experiment were archived locally with hashes before this restructuring.

Use the [README](../README.md) to reproduce the current experiment. A historical
signature metadata file records sizes/timings/digests, not a transmitted signature
for the new context-bound transport.
