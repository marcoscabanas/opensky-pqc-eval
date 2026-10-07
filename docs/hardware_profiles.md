# Hardware timing references

`config/hardware_profiles.json` supplies service times to the replay. Sender and
receiver profiles are selected independently. `embedded_reference` is a mixed
embedded reference scenario: it is not a measurement of a particular aircraft
computer or ground receiver. Its Falcon and SLH entries are explicitly marked
as approximate algorithm-lineage proxies. The experimental cryptographic
implementations and the benchmark implementations are different.

| Replay algorithm | Published implementation | Sign (ms) | Verify (ms) | Qualification |
| --- | --- | ---: | ---: | --- |
| ECDSA-P256 | P256-Cortex-M4 assembly | 5.9 | 15.3 | Same curve; digest and nonce supplied externally |
| ML-DSA-44 | pqm4 `ml-dsa-44 / m4f` | 164.297 | 59.234 | Same parameter set; different implementation |
| FN-DSA-512 | pqm4 `fndsa_provisional-512 / m4f` | 936.237 | 16.540 | Provisional lineage proxy for project Falcon-512 |
| SLH-DSA-SHA2-128s | pqm4 `sphincs-sha2-128s-simple / clean` | 319064.924 | 311.325 | Pre-standard SPHINCS+ proxy, not a FIPS 205 benchmark |

PQM4 values come from its [pinned benchmark table](https://github.com/mupq/pqm4/blob/90bfb630e53603b4e273a131cd09a025e51540a5/benchmarks.md).
The [matching README](https://github.com/mupq/pqm4/blob/90bfb630e53603b4e273a131cd09a025e51540a5/README.md)
specifies Cortex-M4, a 24 MHz benchmark clock and GCC 11.3.1. The table does not
identify the measured board or build flags, so these remain unspecified. The
[pinned harness](https://github.com/mupq/mupq/blob/ddcccedb2db9d0250856bd58ee5c46c61e506c5d/crypto_sign/speed.c)
uses 59-byte messages. Timings use `cycles / (clock_mhz * 1000)` to obtain
milliseconds. JSON retains key-generation, signing and verification statistics,
execution counts, and stack measurements; stack excludes caller buffers.

ECDSA uses the author's [pinned performance report](https://github.com/Emill/P256-Cortex-M4/blob/ecd3ec2222fc9e18b6b44c86bb7183971a2041fc/README.md):
nRF52840 at 64 MHz, instruction cache enabled, GCC with `-O2`. The rounded
published milliseconds are preserved; rounded cycle counts are metadata.
Its [API](https://github.com/Emill/P256-Cortex-M4/blob/ecd3ec2222fc9e18b6b44c86bb7183971a2041fc/p256-cortex-m4.h)
takes a hash and signing nonce from the caller, excluding their computation.

## Interpretation and sensitivity

These values define reproducible reference conditions, not the target aircraft
hardware. In particular, do not compare the four rows as measurements on one
identical processor configuration. Use the exact partial profiles
`pqm4_mldsa44_reference` and `ecdsa_m4_reference` for analyses that cannot accept
algorithm proxies. Missing algorithms raise an error instead of inheriting a
convenient default.

The default point estimates are repeated constants. A published mean is stored
as a one-element `samples_ms` list; the publication's minimum and maximum are
metadata, not two additional equally probable observations. Therefore the
resulting replay does not reproduce cryptographic execution-time variability.
A finite-run maximum is not worst-case execution time. Obtain raw benchmark
samples before making tail-latency claims about the cryptographic operation.
Message lengths and transcript formats also differ from this replay: the
constant service-time approximation must be reported, and final measurements
should cover the exact signed input sizes for each batch size.

Using `embedded_reference` for verification models an embedded receiver. It
does not claim a measured ground-server capability. `assumed_receiver_1ms`
supplies an explicitly assumed 1 ms verification service for every algorithm
to study queue capacity separately from airborne signing. It intentionally
has no signing or key-generation timing and must be labelled as a sensitivity
assumption in results. Parallel replay execution changes experiment runtime;
it does not automatically increase the simulated receiver's service capacity.

In the final detached study, signing operates on retained message copies;
collection and signing queues delay authentication without withholding ordinary
transmissions. One receiver verification worker is the baseline. If it becomes
a bottleneck, two- and four-worker configurations can be run as explicitly
separate sensitivity cases, reusing the same signed objects. Additional workers
change modeled service capacity; they do not change the per-operation benchmark.

With fixed point estimates, zero extra erasure, zero timing jitter, and cached
signatures, the default replay is deterministic. Its technical seed value does
not create independent repetitions or uncertainty estimates. Seeds become
relevant only in a separately declared model using empirical timing samples or
other stochastic effects.

CPU time is only one part of an aircraft hardware argument. These profiles
contain no energy measurements, mixed-criticality scheduling costs, interference
measurements or certified execution-time bounds. Report such gaps alongside
the experimental findings. Key generation remains separate from per-group
signing: key provisioning, validation and rotation need their own workload.

## Adding measured profiles

Use a new profile ID and preserve the original reference. For every algorithm,
record the exact implementation/revision, parameter set, compiler and flags,
processor/clock, message length, included operations, and source or measurement
artifact. Keep platform, provenance and limitations with the numbers. Record
signing and verification separately; include key generation when measured.

For repeated local measurements set `kind` to `measured_local`, store the raw
positive durations in `samples_ms`, and set `sample_kind` to `empirical`.
`source_urls` is still required for non-assumed algorithms; it can point to
the versioned public implementation or measurement methodology. Keep the
local measurement artifact and full environment details in additional
metadata. The replay may draw from these samples using its own seeded RNG.
Do not convert published minimum/mean/maximum summaries into fabricated
empirical samples. Mark cross-algorithm mappings as `lineage_proxy` and
analyst-selected constants as `assumed` with `assumed_constant` timings.

The loader rejects missing provenance, duplicate JSON keys, nonpositive or
nonfinite service times, invalid unit conversions, and inconsistent cycle
summaries. `timing_samples_ms(profile, algorithm, operation)` returns a fresh
list and has no timing, network, cryptographic, or global-randomness side effects.
