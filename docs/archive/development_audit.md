> Historical document. See [the archive index](README.md) and [current methodology](../methodology.md). Commands below describe the earlier workflow.

# Development artifact audit

Audit date: 2026-10-06. This records the artifacts present before the new
checkpointed signing run. No signing job was active at the initial process
inspection. The audit itself did not run signing or modify experiment results.

## Observed coverage

The canonical trace contains 133,565 observations from 417 ICAO addresses.
Every trace message is 14 bytes and DF17, its embedded ICAO matches its record,
trace IDs are contiguous, and timestamps are ordered. Raw-capture and trace
SHA-256 digests match the preprocessing manifest. All four group-file digests
match the group summary.

| k | Complete groups | Incomplete groups | ECDSA records | ML-DSA records | Falcon records | SLH-DSA records |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 133,565 | 0 | 133,565 | 133,565 | 133,565 | Missing |
| 5 | 26,549 | 332 | 26,549 | 26,549 | 26,549 | Missing |
| 10 | 13,177 | 370 | 13,177 | 13,177 | 13,177 | Missing |
| 20 | 6,486 | 397 | 6,486 | 6,486 | 6,486 | Missing |

There are 179,777 complete events per algorithm, 539,331 existing result
records, and 179,777 missing SLH-DSA events. For each k, groups cover every
trace ID exactly once and follow consecutive observations per aircraft.
Complete groups contain exactly k messages; incomplete groups have fewer.

Every existing signature record passes reconstruction of its signing-input
SHA-256 from the trace, algorithm/k/group/ICAO matching, message count and input
length checks, formation-time matching, and unique coverage of all complete
groups. Every stored `verification_success` flag is `true`.

ECDSA records report 64-byte signatures; ML-DSA records report 2,420 bytes.
Falcon sizes are variable:

| k | Current size range (bytes) | Current total bytes | Cached feasibility maximum | Cached feasibility total bytes |
|---|---:|---:|---:|---:|
| 1 | 646–666 | 87,491,739 | 665 | 87,490,868 |
| 5 | 647–664 | 17,390,701 | 665 | 17,391,220 |
| 10 | 647–664 | 8,631,971 | 665 | 8,631,606 |
| 20 | 648–663 | 4,248,290 | 663 | 4,248,494 |

## Stale summaries and limits

The two `signature_experiment_summary.json` files, under `analysis/` and
`signatures/`, are byte-identical and list only ECDSA. Their trace digest
matches, but their algorithm-config digest and all four ECDSA output digests
do not match the current files. They also retain paths from an earlier layout.

The stored algorithm-config digest is
`e66b6be714d340a1d9fd71dcb336bd6dcfca37b78c2e6845841e19cfb4d2a860`;
the current digest at audit time is
`5df11b029fda3c33e332ffba223c5e506c56fef3c78c3cfe41c949f03da0dcf8`.
The feasibility summary lists four algorithms at the top level but contains
only 12 rows for three algorithms. Its Falcon measurements are stale as shown
above. These cached feasibility outputs are not a complete four-algorithm run.

This is a metadata and signing-input integrity audit, **not cryptographic
reverification**. Legacy records store signature hashes and lengths, without
the signature bytes or public keys needed to independently reverify them.
Stored success flags show what the producing run recorded. Matching hashes
cannot establish the provenance of that run. Falcon measurements refer to
the configured Falcon-512 implementation; they do not establish conformance
to a finalized FN-DSA standard.

The existing `tests/inspect_signature.py` checks one event's reconstructed
input hash and stored verification flag. The audit above extends those checks
across all legacy records. The original unittest suite contains one pipeline
output-list test; the crypto smoke test is a separate executable script.

An initial one-event SLH-DSA benchmark measured approximately 0.468 seconds
for the event. Multiplying by 179,777 events gives about **23.37 hours**. This
is a rough estimate from one sample, not an observed full-run duration or a
guarantee; key generation, checkpoint writes, CPU load, and thermal effects
can change runtime.

## Reproducing the principal checks

Run from the repository root with Python 3. This reads the current artifacts;
after a new run, counts and hash-match results may differ from this snapshot.

```sh
python3 - <<'PY'
import hashlib
import json
from collections import Counter
from pathlib import Path

def read(path):
    return [json.loads(line) for line in Path(path).open() if line.strip()]

def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

trace_path = Path('data/development/processed/experimental_trace.jsonl')
trace = {r['trace_id']: r for r in read(trace_path)}
summary = json.loads(Path('results/development/signatures/signature_experiment_summary.json').read_text())
print('trace hash matches:', digest(trace_path) == summary['trace_sha256'])
print('config hash matches:', digest('config/algorithms.json') == summary['algorithm_config_sha256'])
for k in (1, 5, 10, 20):
    groups = read(f'data/development/processed/authentication_groups/authentication_groups_k{k}.jsonl')
    assert Counter(t for g in groups for t in g['trace_ids']) == Counter(trace.keys())
    complete = {g['group_id']: g for g in groups if g['complete']}
    inputs = {gid: b''.join(bytes.fromhex(trace[t]['raw_msg']) for t in g['trace_ids'])
              for gid, g in complete.items()}
    for alg in ('ECDSA-P256', 'ML-DSA-44', 'FN-DSA-512', 'SLH-DSA-SHA2-128s'):
        path = Path(f'results/development/signatures/signatures_{alg}_k{k}.jsonl')
        if not path.exists():
            print(alg, k, 'MISSING', len(complete))
            continue
        entries = read(path)
        assert Counter(r['group_id'] for r in entries) == Counter(complete.keys())
        for r in entries:
            g = complete[r['group_id']]
            message = inputs[r['group_id']]
            assert r['algorithm'] == alg and r['k'] == g['k'] == k
            assert r['icao'] == g['icao']
            assert all(trace[t]['icao'] == g['icao'] for t in g['trace_ids'])
            assert r['message_count'] == g['message_count'] == len(g['trace_ids']) == k
            assert r['message_length_bytes'] == len(message) == 14 * k
            assert r['message_sha256'] == hashlib.sha256(message).hexdigest()
            assert r['group_formation_time_s'] == g['group_formation_time_s']
            assert r['verification_success'] is True
        sizes = [r['signature_length_bytes'] for r in entries]
        stored = summary['algorithms'].get(alg, {}).get('output_files', {}).get(str(k), {})
        print(alg, k, len(entries), 'size range', min(sizes), max(sizes),
              'summary hash match', digest(path) == stored.get('sha256'))
PY
```
