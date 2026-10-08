# Synthetic implementation demo

These small, artificial inputs exercise the **current detached-signature method**.
They are not OpenSky observations and must not be used as experimental evidence
about aircraft traffic or real channel capacity.

- `adsb_capture.jsonl`: 21 DF17-shaped records for artificial address `ABCDEF`
  during 20 seconds, plus two DF11-shaped records. Their bytes are structurally
  suitable for the replay; ADS-B semantics and CRC validity are not asserted.
- `channel_trace.jsonl`: all 21 target frames, the two additional frames, and
  one background frame during follow-up. Its synthetic recording coverage is
  explicitly 0–621 seconds, including the 600-second follow-up and frame completion.
- `manifest.json`: input SHA-256 hashes, expected populations and case inventory.

The repeated payload at two distinct times exercises message association.
With exact groups of 5, 10 or 20, one final ordinary message remains unsigned;
it must still be transmitted. Deliberately overlapping background traffic
exercises the collision model. The fixture contains no signatures or keys:
the pipeline generates real keys and signatures for all four algorithms.

From the repository root, after following the installation steps in the main
README:

```sh
python scripts/check_demo.py --inputs-only
python -m src.pipeline --config config/demo.json
python scripts/check_demo.py
python -m src.experiment.plot_signed_replay \
  --results-dir results/runs/demo/replay \
  --output-dir results/runs/demo/figures \
  --label 'Synthetic implementation demo'
```

The run contains 16 signed workloads (112 signatures) and 96 replay cases.
Some signatures cannot arrive by the modeled cutoff; the checker distinguishes
those expected modeled outcomes from invalid signatures or incomplete reports.
Outputs are generated under `results/runs/demo/`. Fresh runs generate new keys
and signatures; Falcon signature lengths can vary, so this is a checked workflow,
not a promise that newly generated plots will be byte-identical.
