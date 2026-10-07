# Data and calibration

The default input is `development/raw/adsb_sample.jsonl`, a 103,325,840-byte JSONL capture. The exact hash, expected counts, derived-file hashes, and acquisition fields are in [development/manifest.json](development/manifest.json). The capture contains 540,997 records: 407,432 DF11 and 133,565 retained DF17 observations. The DF17 trace spans 640.791918 seconds and 417 distinct ICAO addresses. Distinct aircraft over the capture are not a simultaneous traffic-density estimate.

Preprocessing retains repeated observations. Identical message bytes at different times can be genuine repeated transmissions; the trace alone cannot identify every network duplicate or unobserved transmission. It does not reconstruct messages already lost before capture. The development collision experiment uses retained DF17 observations as emission proxies and adds hypothetical authentication frames; it does not replay the excluded DF11 traffic as interference. Default extra background traffic is zero. The planned full study uses the separate channel input described below.

## Acquisition and redistribution

The original capture's receiver/query, acquisition method, and redistribution terms have not been recorded. They are explicitly `null` in the manifest. Its timestamps and hashes establish the supplied artifact's identity, not its collection provenance. Fill these fields from the actual acquisition record; do not infer them from the project's name.

The repository's MIT license applies to its software and does not establish a license for a third-party capture. If the input was obtained from OpenSky, the applicable [OpenSky data terms](https://opensky-network.org/about/terms-of-use) and [citation guidance](https://openskynetwork.github.io/opensky-api/index.html) must be considered for that dataset. No claim of verified redistribution permission is made here.

## Raw JSONL format

Each nonempty line is an object. Relevant fields are:

| Field | Meaning |
| --- | --- |
| `df` | Integer downlink format. Only `17` is retained for the experiment. |
| `icao` | Six hexadecimal aircraft-address characters. |
| `raw_msg` | Complete 112-bit DF17 frame as 28 hexadecimal characters, including the aircraft address. |
| `timestamp` | Numeric observation time in seconds; epoch timestamps are accepted. |
| `typecode` | Optional decoded ADS-B type code, used for descriptive analysis. |

A structurally illustrative record (not an additional observation in the sample):

```json
{"df":17,"icao":"40621D","raw_msg":"8D40621D58C382D690C8AC2863A7","timestamp":1000.0,"typecode":11}
```

Records are sorted by timestamp and original source line. Relative time starts at the first retained DF17 observation. Replay checks frame length, DF17 format, and address consistency; canonicalization does not establish a radio CRC or an authentic emitter. Onboard measurement time is unavailable.

Put the two future one-hour inputs at `full/window_a/raw/adsb_capture.jsonl` and `full/window_b/raw/adsb_capture.jsonl`. These directories are ignored. Keep each target cohort separate from its additional channel follow-up; do not add follow-up observations to target groups. Record its collection method, timestamp semantics, receiver coverage, and content hash before reporting results. New processed traces/groups go under `runs/`, while existing `development/processed/` files remain for historical comparisons and recovery compatibility.

## Portable signature-size calibration

[calibration/signature_sizes.json](calibration/signature_sizes.json) is a small, self-contained input. It contains nominal fixed sizes for ECDSA (64 bytes), ML-DSA-44 (2,420), and SLH-DSA-SHA2-128s (7,856), plus empirical Falcon size frequencies for each `k`. Fixed-size entries are configuration values, not claimed samples. Falcon counts preserve every observation's weight; they are not uniform draws over distinct observed lengths.

The file retains algorithm/module identities, original trace/group/signature-metadata hashes, and an integrity digest. Its provenance paths were made repository-relative for publication. `publication_export` records the prior profile/file hashes and that path-only transformation; distributions and source content hashes are unchanged. Historical source paths are provenance labels and need not exist on a new machine. Private signing keys are neither present nor required.

This calibration came from the legacy raw-message transcript. The explicit binary transport signs additional context; validate its length distribution on representative exact transcripts before final performance claims. Importing calibration does not prove that the current trace has been signed, authenticate an observation, or create a universal Falcon size bound.

## Full-study channel input

Each of the two planned one-hour windows requires an aligned observed 1090 MHz channel trace in addition to its target DF17 dataset. See [the channel schema and acquisition requirements](../docs/channel_trace.md). `config/full_window_a.json` and `config/full_window_b.json` expect `data/full/window_a/raw/channel_trace.jsonl` and `data/full/window_b/raw/channel_trace.jsonl`, respectively; `config/full.json` is the window A convenience configuration. Include all recorded non-target traffic and acquisition coverage through the fixed 600-second follow-up plus frame completion. The two windows should represent different measured traffic conditions where possible; they are not statistical repetitions.

Acquisition details remain unknown. A decoded-message log cannot establish that all physical 1090 MHz transmissions were captured. Include Mode A/C or undecodable activity only when actual acquisition provides its timing and duration, and document the remaining coverage limits. A format adapter will be required once the source is selected. Neither final dataset has yet been supplied or evaluated. The development input and frozen reference remain a DF17-only channel experiment.
