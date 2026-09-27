# Experimental Design: Operational Feasibility of ADS-B Authentication with Post-Quantum Signatures

## 1. Goal of the experiment

The objective of this experiment is to determine whether post-quantum digital signatures can be integrated into ADS-B authentication in a way that is operationally feasible under real traffic conditions.

The central question is not simply whether the signatures verify; it is whether they can be transmitted, reconstructed, and used for authentication without violating the operational constraints of ADS-B:

- real-time latency requirements
- messaging and protocol constraints
- bandwidth and channel occupancy limitations
- message-size restrictions
- loss and retransmission risk in a broadcast environment

This experiment is designed to evaluate cryptographic correctness and operational viability together.

---

## 2. Research questions

The experiment should answer the following questions:

1. Can each signature be transmitted in a single ADS-B transmission?
2. If not, how must the signature be fragmented to fit the ADS-B transmission model?
3. How much additional bandwidth and channel occupancy does each approach impose?
4. What latency is introduced by immediate vs detached authentication?
5. Does the received signature still allow for reliable message authentication under realistic loss conditions?
6. What is the effect of transmission loss on fragment recovery and overall authentication success?
7. Does detached authentication outperform immediate authentication for large signatures?
8. Which algorithm provides the best trade-off between cryptographic security and operational feasibility?
9. How does the best PQC scheme compare to the classical ECDSA baseline?
10. Is it possible to integrate PQC authentication within the current ADS-B operational envelope?
11. If it is not feasible, which protocol changes would be required to support authentication?

---

## 3. Experimental hypotheses

### H1: Immediate single-message transmission is feasible only for the smallest signatures
A scheme is operationally feasible in an immediate transmission model only if its signature size is small enough to fit within the practical transmission budget for an ADS-B message class.

### H2: Larger signatures require fragmentation
If a signature does not fit in a single transmission, then the system must fragment the signature across multiple ADS-B transmissions or rely on a detached authentication architecture.

### H3: Fragmentation increases latency and loss risk
Each extra transmission increases channel occupancy, potential collision risk, and the probability that a fragment is lost or delayed.

### H4: Detached authentication is more operationally realistic for large signatures
Detached authentication should provide a better trade-off when signature material is large, because it can decouple normal position broadcasts from the delayed verification process.

### H5: No scheme is operationally feasible under the current ADS-B envelope if the authentication overhead exceeds the tolerable latency and channel occupancy thresholds
This would imply that protocol changes are required rather than a purely software-based adaptation.

---

## 4. Scope and assumptions

This experiment is intentionally scoped to the development dataset and the existing pipeline, and it is designed to remain reusable for the eventual full capture.

### Included

- real trace-driven traffic from the OpenSky development dataset
- filtering and canonicalization of valid ADS-B messages
- per-aircraft grouping and message batching
- signature generation using the enabled algorithm set
- operational feasibility assessment using transmission and latency models
- immediate vs detached authentication comparison
- algorithm comparison against the classical ECDSA baseline

### Not included

- jamming resistance
- GNSS spoofing mitigation beyond authentication integrity
- full PKI or certificate-chain design
- aircraft-side key management lifecycle design
- complete protocol redesign beyond the feasibility analysis

### Key assumptions

- credentials are assumed to be provisioned and trusted in advance
- the system is evaluated for source authentication and message integrity
- the current ADS-B framing rules remain the operational constraints being tested
- all feasibility conclusions are based on the real trace and not a synthetic workload only

---

## 5. Experimental variables

### Independent variables

- signature scheme
  - ECDSA-P256
  - ML-DSA-44
  - FN-DSA-512/Falcon lineage
  - SLH-DSA-SHA2-128s
- authentication interval $k$
  - e.g. 1, 5, 10, 20
- authentication architecture
  - immediate authentication
  - detached authentication
- network conditions
  - nominal traffic
  - high-density traffic bursts
  - lossy transmission conditions
- fragment strategy
  - no fragmentation
  - simple chunking
  - repeated fragments
  - parity/redundancy approach

### Dependent variables

- signature size
- number of fragments required
- extra airtime consumed
- channel occupancy increase
- authentication latency
- probability of successful recovery under loss
- authentication success rate
- operational feasibility verdict

---

## 6. Data inputs

The experiment should use the existing architecture and data layout:

- [config/development.json](config/development.json)
- [config/algorithms.json](config/algorithms.json)
- [data/development/processed/experimental_trace.jsonl](data/development/processed/experimental_trace.jsonl)
- [data/development/processed/authentication_groups](data/development/processed/authentication_groups)
- [results/development/signatures](results/development/signatures)

The experiment should not use external synthetic traffic for the main evaluation. The development trace is the benchmark because it preserves actual timing and density characteristics.

---

## 7. Experimental model

### 7.1 Message size feasibility

For each scheme and each interval, compute:

$$
S_{sig} = \text{signature size in bytes}
$$

and test:

$$
S_{sig} \leq S_{ADS\text{-}B\_payload}
$$

If true, the scheme could in principle be transmitted in a single message. Otherwise, fragmentation is required.

### 7.2 Fragmentation model

If signature transmission must be split across multiple ADS-B transmissions, then:

$$
n_{frag} = \left\lceil \frac{S_{sig}}{S_{fragment}} \right\rceil
$$

where:
- $S_{fragment}$ is the usable payload size per fragment transmission
- $n_{frag}$ is the number of extra transmissions required

The experiment should consider multiple fragmentation policies:

- minimum fragmentation
- chunked fragments with integer payload units
- repetition of headers and critical fragments
- parity-based redundancy

### 7.3 Airtime and channel occupancy

Compute:

$$
T_{extra}=n_{frag} \cdot T_{frame}
$$

Then evaluate occupancy over the trace window:

$$
\text{occupancy} = \frac{T_{extra}}{T_{window}}
$$

This should be computed per aircraft, per interval, and globally under the observed trace.

### 7.4 Latency model

The latency for an authentication event should be modeled separately for immediate and detached architectures.

#### Immediate authentication latency

$$
L_{immediate}=T_{sig\_delivery}+T_{verify}
$$

#### Detached authentication latency

$$
L_{detached}=T_{message\_generation}+T_{fragment\_collection}+T_{verification}
$$

In practice, this should be evaluated against a threshold derived from ADS-B operational requirements for surveillance freshness.

### 7.5 Loss model

Because transmission is broadcast-based and lossy, the experiment should explicitly model fragment loss probability.

For a fragment set of size $n_{frag}$, if each fragment has loss probability $p$, then the probability that the full set succeeds is:

$$
P_{success}=(1-p)^{n_{frag}}
$$

For redundancy schemes, use:

$$
P_{recovery} = P(\text{enough fragments received})
$$

This allows comparison between:
- no redundancy
- duplicate fragment repetition
- parity/recovery redundancy
- detached multi-slot recovery window

---

## 8. Transmission strategies to evaluate

### Strategy A: Immediate single-message authentication
- attach the signature directly to the ADS-B frame or a tightly coupled follow-up transmission
- low delay if it fits
- very high burden if signature is too large
- poor fit for large PQC signatures

### Strategy B: Immediate fragmented authentication
- split the signature across several transmissions
- maintain a tight verification window
- higher loss risk and channel burden
- useful only if the scheme is small and the load remains acceptable

### Strategy C: Detached authentication with batch signing
- broadcast the original messages normally
- sign them in a batch or group later
- send the signature fragments in a separate recovery window
- lower immediate overhead
- higher latency and delayed trust

### Strategy D: Detached authentication with redundancy and repair
- send the signature fragments with replication or FEC
- allow recovery across several slots
- improves loss tolerance
- more complex and more expensive in airtime

### Strategy E: Protocol-level redesign
- reserve authenticated slots, use a dedicated authentication channel, or expand the payload envelope
- not a software-only fix
- best long-term option if the current ADS-B envelope is fundamentally too constrained

---

## 9. Loss and recovery handling

The reason fragmentation raises risk is that it creates a recoverability problem. If signature fragments are dropped, the receiver may never reconstruct the full signature, and the authentication event becomes invalid.

### Mitigation strategies

#### 1. Fragment repetition
Repeat the most important fragments and/or the final trailer fragment across neighboring ADS-B slots.

#### 2. Redundancy with parity
Use a small amount of parity information so that moderate losses can be recovered without full retransmission.

#### 3. Recovery window
Allow the receiver to collect fragments over a bounded time interval instead of requiring immediate completion.

#### 4. Hash-based fragment validation
Each fragment should carry a fragment index and a lightweight integrity check so corrupted or out-of-order fragments are detectable.

#### 5. Event-level replay recovery
If the signature cannot be reconstructed in time, the system may keep the event temporarily unverified rather than incorrectly authenticating it.

#### 6. Priority policy
Only authenticate high-priority events, while lower-priority traffic remains unauthenticated during overload conditions.

---

## 10. Evaluation criteria

A scheme should be considered operationally feasible only if it satisfies all of the following:

1. Can the signature be transmitted without violating transmission-size constraints?
2. Does fragmentation remain within acceptable channel occupancy limits?
3. Does the time-to-authentication remain below operationally relevant thresholds?
4. Can the receiver recover enough fragments under realistic loss conditions?
5. Does the recovery process preserve message-to-signature correspondence?
6. Does the design maintain strict integrity and authentication correctness?
7. Is the scheme better than the classical ECDSA baseline under the same conditions?

A scheme is not considered feasible simply because it can be cryptographically verified in isolation.

---

## 11. Algorithm comparison framework

Each scheme should be compared along the following axes:

- signature size
- overhead per authenticated event
- number of fragment transmissions required
- verification cost
- latency cost
- loss tolerance
- operational compatibility with ADS-B
- whether detached auth is necessary
- overall ranking under real traffic conditions

The comparison table should include:

- ECDSA-P256 baseline
- ML-DSA-44
- FN-DSA-512/Falcon-style
- SLH-DSA-SHA2-128s

This table should be the final analysis artifact for the paper.

---

## 12. Operational interpretation of results

The paper should interpret the results in three tiers:

### Tier 1: Operationally feasible
The scheme fits with a realistic immediate or detached deployment model without violating the latency and share-of-channel requirements.

### Tier 2: Operationally constrained
The scheme works under favorable conditions but becomes impractical under bursts, loss, or high traffic density.

### Tier 3: Not feasible under current ADS-B
The signature and recovery overhead exceed the operational envelope and require protocol redesign or a separate authentication channel.

---

## 13. What would have to change if the current ADS-B envelope cannot support authentication?

If the experiment concludes that no scheme is operationally feasible, the paper should explicitly define the required protocol changes.

Examples include:

- increasing per-message payload capacity
- reserving explicit authentication slots
- introducing a dedicated secure broadcast channel
- designing a protocol that carries signed summaries instead of full signatures per aircraft message
- using time-sliced authentication windows instead of per-message authentication
- separating the surveillance channel from the authentication channel

This is the important “if not possible within ADS-B as-is” conclusion.

---

## 14. Reproducibility requirements

The experimental design must be easy to reproduce from the repo and should not depend on private data or manual steps.

### Required reproducibility properties

- all inputs should be trace-driven and versioned under [data/](data)
- all configs should live under [config/](config)
- generated outputs should be saved under [results/](results)
- all scripts should read the config and generate deterministic outputs
- figures should be produced from saved data rather than ad hoc notebooks only
- the same pipeline should be rerunnable on the full dataset later without code changes

### Recommended output files

- `results/development/feasibility/feasibility_summary.json`
- `results/development/feasibility/fragmentation_summary.csv`
- `results/development/feasibility/latency_summary.csv`
- `results/development/feasibility/channel_occupancy.csv`
- `results/development/feasibility/architecture_comparison.csv`

These should be the data products the paper uses.

---

## 15. Recommended implementation order in the repo

1. Add a new feasibility stage in [src/pipeline.py](src/pipeline.py)
2. Create a new module under [src/experiment](src/experiment) for transmission feasibility
3. Compute per-scheme single-message feasibility
4. Compute fragmentation and redundancy requirements
5. Compute latency and occupancy under the observed trace
6. Compute loss-tolerance and authentication-success probability
7. Compare immediate vs detached authentication
8. Rank algorithms by operational viability
9. Generate final summary outputs and figures
10. Reuse the exact same flow for the full dataset later

---

## 16. Final interpretation to emphasize in the paper

The scientific contribution of this phase is not merely “a signature verifies.” It is the answer to a more important question:

“Under real lifecycle constraints of ADS-B, can a post-quantum signature remain useful long enough to authenticate the message without overwhelming the protocol?”

That is the operationally relevant experiment.

The strongest conclusion will come from the combination of:

- cryptographic validity
- real traffic density
- message-size constraints
- transmission overhead
- latency tolerance
- loss/recovery behaviour
- architecture choice (immediate vs detached)

This provides the full operational story that the paper needs.

---

## 17. Summary

This experiment should be framed as a transmission-and-latency feasibility study built on the already working development pipeline. It must compare schemes under realistic traffic, evaluate fragmentation and redundancy, and explicitly test whether authentication survives the loss and delay conditions of the ADS-B channel.

The final result should answer the central question: whether post-quantum authentication can be made operationally viable in ADS-B, and if not, what must change in the protocol to make it possible.
