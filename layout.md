Proposed paper structure

1. Introduction

This should probably be around 10 to 15% of the paper.

Start with the problem at the ADS-B level, rather than giving the broad quantum-computing introduction from the thesis. Something like:

ADS-B provides safety-relevant surveillance information through unauthenticated broadcasts. Cryptographic authentication has therefore long been proposed, but post-quantum signatures introduce communication objects that are dramatically larger than conventional ADS-B messages. Whether they are cryptographically secure is consequently a different question from whether they are operationally usable.

Then very briefly introduce the quantum motivation and NIST PQC transition.

The crucial next paragraph should explain why ADS-B 1090ES is being studied. This is where Reviewer 2 is addressed. I would deliberately avoid claiming:

ADS-B 1090ES will remain the primary surveillance technology.

That is unnecessarily strong and makes the paper defend a prediction it does not need.

Instead, the argument should be:

ADS-B 1090ES represents an important migration case because it is globally deployed, embedded in a long-lived installed base, and structurally difficult to modify. Even if future CNS architectures increasingly incorporate technologies such as LDACS, migration will involve prolonged coexistence with legacy surveillance infrastructure.

There is another useful distinction to make here: LDACS is fundamentally an air-ground communications system, whereas 1090ES ADS-B is a broadcast surveillance link. They may participate in a future integrated CNS architecture, but LDACS should not simply be presented as a drop-in successor to the current ADS-B broadcast function. The paper does not need an ADS-B versus LDACS comparative experiment.

Then establish the research gap. Your submitted abstract already says that the purpose is not to propose yet another authentication protocol, but to establish whether candidate algorithms can satisfy the operational constraints and quantify their implications under realistic traffic conditions. Abstract_Marcos_OpenSky_Symposium.pdf

I would end the introduction with three research questions:

RQ1: Which NIST-standardized or selected post-quantum digital-signature schemes are structurally compatible with ADS-B 1090ES authentication?

RQ2: What communication and computational overhead do compatible schemes introduce under observed ADS-B traffic conditions?

RQ3: How do authentication architecture, authentication interval, and traffic density affect authentication latency, channel occupancy, receiver workload, and authentication success?

Then state the contributions. The novelty should be phrased approximately as:

The contribution is not a new ADS-B authentication protocol, but a reproducible, trace-driven methodology connecting cryptographic properties to observed operational traffic.

That is much sharper than simply saying “we evaluate PQC for ADS-B.”

⸻

2. Background and Related Work

This section becomes much more important because of Reviewer 3. I would give it four subsections.

2.1 ADS-B 1090ES and Authentication Constraints

Condense the entire thesis ADS-B characterization into perhaps half a page to one page.

Only retain properties directly relevant to this experiment:

* 112-bit Extended Squitter frame
* 56-bit ME field
* fixed message semantics
* lack of native cryptographic authentication
* lack of generic fragmentation/reassembly
* asynchronous shared 1090 MHz channel
* transmission frequency / channel occupancy
* surveillance latency and update requirements
* long migration and interoperability horizon

Do not reproduce the entire seven-constraint characterization here.

Your thesis conclusion that message size/protocol and bandwidth are the blocking constraints, with message/protocol being primary, is exactly the justification for why the paper focuses on fragmentation, transmission overhead, occupancy, and authentication latency. The submitted abstract already communicates the essential version of this motivation. Abstract_Marcos_OpenSky_Symposium.pdf

2.2 Existing ADS-B Authentication Research

This directly answers Reviewer 3’s second request.

We should later do a dedicated literature review for this subsection. Conceptually, it should position the paper against:

* digital-signature-based ADS-B authentication
* delayed authentication / TESLA-like approaches
* symmetric authentication approaches
* authentication extensions using additional ADS-B/Mode S transmissions
* physical-layer and multilateration-based verification approaches, while clarifying that these are not equivalent to cryptographic source authentication

The goal is not to catalog everything. It is to establish:

Authentication of ADS-B is not a new research problem, but most existing proposals predate standardized PQC or evaluate classical cryptography, custom protocols, or synthetic traffic conditions.

2.3 Post-Quantum Cryptography in Aviation

This is where LDACS should appear prominently.

Discuss existing aviation PQC activity, including work on LDACS security, PQC-capable authentication/key establishment prototypes, SESAR research, and any aviation-specific PQC studies we find.

This answers both reviewers at once:

* Reviewer 2 sees that you understand alternative/future CNS architectures.
* Reviewer 3 gets the requested positioning against what has already been proposed or demonstrated in aviation.

Then explain the distinction:

Existing LDACS work demonstrates that PQC can be incorporated into a modern security-aware aeronautical data link. The problem investigated here is different: whether PQC authentication can be overlaid on a highly constrained, globally deployed broadcast surveillance protocol that was not designed to carry cryptographic material.

That distinction is potentially one of the strongest sentences in the paper.

2.4 Research Gap

End Section 2 with a very explicit gap statement:

What is missing is a system-level evaluation connecting standardized or selected PQC signature properties to the temporal and density characteristics of real ADS-B traffic.

Then lead directly into OpenSky.

⸻

3. Evaluation Framework

This section translates the thesis into the paper-specific experiment.

3.1 Security Objective and Scope

Define exactly what authentication means.

The paper evaluates:

* source authentication
* message integrity

Explicitly state what it does not solve:

* jamming
* GNSS spoofing producing legitimately signed false position data
* compromise of an aircraft’s private key
* malicious but credentialed transmitters
* complete PKI design

If credentials are assumed pre-provisioned, say so.

This will prevent reviewers from interpreting “secure ADS-B” too broadly.

3.2 Candidate Signature Selection

This is where Reviewer 3’s first criticism gets answered properly.

Your thesis now gives you a much stronger rationale than the abstract had. The selection rule can be summarized cleanly:

Primary digital-signature candidates are schemes either standardized or selected for standardization by NIST.

That produces:

Scheme	Family	Status	Role in paper
ECDSA	Elliptic curve	Classical	Comparison baseline
ML-DSA	Module lattice	FIPS 204	Standardized PQC candidate
SLH-DSA	Hash based	FIPS 205	Standardized alternative assumption
FN-DSA	NTRU lattice	Selected for standardization	Compact-signature PQC candidate

Then briefly explain why this set is informative rather than arbitrary:

ML-DSA provides the principal standardized lattice-based signature.

SLH-DSA provides a standardized scheme founded on hash-based security assumptions and very different size/performance trade-offs.

FN-DSA is particularly relevant to constrained communication because compact signatures are one of its defining advantages.

That is enough. You do not need the many pages of mathematical characterization from the thesis.

Two terminology corrections are worth making in the full paper. The abstract describes the study as evaluating “standardized PQC digital signatures”, but FN-DSA is selected for standardization rather than finalized in the same sense as FIPS 204/205. Abstract_Marcos_OpenSky_Symposium.pdf I would therefore consistently use “NIST-standardized and selected PQC signature schemes.”

Also, the abstract calls ECDSA the “currently deployed ECDSA signature scheme.” Abstract_Marcos_OpenSky_Symposium.pdf Unless you are referring to a very specific deployed ADS-B authentication implementation, that should become “classical ECDSA baseline.” ADS-B itself does not currently have native ECDSA authentication.

3.3 Authentication Architectures

This deserves a diagram.

Show the two approaches already defined in the abstract:

Immediate authentication

1. ADS-B data available
2. Signature generated
3. Data and authentication material transmitted
4. Receiver reconstructs and verifies

Detached authentication

1. ADS-B messages transmitted normally
2. Messages are accumulated/bound to an authentication event
3. Signature is generated/transmitted separately
4. Earlier traffic becomes authenticated retrospectively

The abstract already specifies this immediate versus detached distinction. Abstract_Marcos_OpenSky_Symposium.pdf

This subsection should define what exactly is signed, how signatures are associated with ADS-B messages, how fragmentation is sequenced, and what constitutes a complete authentication event.

3.4 Stage I: Analytical Constraint Screening

Here you formalize the first evaluation stage.

For each algorithm calculate things such as:

n_{\mathrm{frag}}
=
\left\lceil
\frac{S_{\mathrm{auth}}}{S_{\mathrm{payload}}}
\right\rceil

along with:

* security transmissions per authentication event
* airtime added
* overhead per authenticated ADS-B message
* theoretical authentication transmission duration
* protocol feasibility

This section should end with the Stage I screening result, not merely the procedure.

That is an important change from the abstract. The full paper needs findings.

⸻

4. Trace-Driven Experimental Methodology

This should be the reproducibility heart of the paper.

4.1 OpenSky Dataset

Specify precisely:

* dates
* geographical regions / receiver selection
* duration
* number of messages
* number of aircraft
* raw data source
* message filtering
* duplicate handling
* invalid-message handling
* how aircraft are identified
* how traffic density is measured
* how low/medium/high-density scenarios are defined

The abstract correctly emphasizes preserving the temporal characteristics of actual transmissions rather than generating synthetic traffic. Abstract_Marcos_OpenSky_Symposium.pdf

4.2 Replay Simulator

Describe the discrete-event simulator.

A single figure could show:

OpenSky trace → aircraft identity assignment → cryptographic event generation → computational delay injection → authentication fragmentation → channel replay → receiver reconstruction → verification → metrics

This is probably the paper’s central methodological figure.

4.3 Computational Model

Explain clearly that signing and verification are not benchmarked on the computer running the simulation.

Instead:

* published embedded / representative hardware benchmarks are used
* signing latency represents airborne processing
* verification latency represents receiver infrastructure
* these delays are injected into the replay timeline

That design choice is already clearly stated in the abstract and is a strong methodological feature. Abstract_Marcos_OpenSky_Symposium.pdf

4.4 Experimental Variables

The experimental matrix should contain:

Authentication algorithm:
ECDSA / ML-DSA / FN-DSA / SLH-DSA, subject to Stage I screening.

Authentication architecture:
Immediate / detached.

Authentication interval:
1 / 5 / 10 / 20 messages, as proposed in the abstract. Abstract_Marcos_OpenSky_Symposium.pdf

Traffic environment:
Multiple observed density regimes.

Possibly computational hardware profile:
One or several representative profiles if you have sufficient benchmark data.

4.5 Evaluation Metrics

Keep these exactly aligned with the abstract:

* authentication latency
* transmission overhead
* additional channel occupancy
* verification throughput / workload
* authentication-object reconstruction success
* authentication success

But define each mathematically. In particular, I would separate signature reconstruction success from cryptographic verification success, because otherwise “authentication success” can become ambiguous.

4.6 Reproducibility

This is worth making a real subsection rather than relegating it to the conclusion.

The abstract already commits to releasing the simulator, processing scripts, configurations, and generated datasets. Abstract_Marcos_OpenSky_Symposium.pdf

Document:

* repository
* software version
* experiment configuration
* algorithm parameters
* benchmark sources
* random seeds if applicable
* dataset identifiers / OpenSky retrieval procedure

This was specifically praised by Reviewer 3, so it should be visible in the paper.

⸻

5. Results

This should become the largest section of the paper.

The submitted abstract was understandably methodology-heavy and had an “Expected results” section because the experiment had not yet been completed. Abstract_Marcos_OpenSky_Symposium.pdf Reviewer 1 explicitly identified the absence of preliminary findings as the main weakness. The full paper therefore has to reverse the balance: methods establish credibility, results carry the paper.

I would structure the results as:

5.1 Analytical Screening Results

Which algorithms survive Stage I?

Present:

* signature size
* required fragment count
* resulting security-message count
* authentication transmission overhead

A compact table plus one figure could do most of the work.

5.2 Baseline OpenSky Traffic Characteristics

Before modifying anything, characterize the trace:

* aircraft density
* messages/s
* observed channel load proxy
* distribution over time

This gives the later overhead figures operational meaning.

5.3 Communication Overhead and Channel Occupancy

Probably one of your strongest result subsections.

Show how occupancy changes as a function of:

\text{algorithm}
\times
\text{authentication interval}
\times
\text{traffic density}.

5.4 Authentication Latency

Use distributions, not just averages.

Median, 95th percentile, 99th percentile, perhaps maximum where meaningful.

Compare immediate and detached authentication explicitly.

5.5 Authentication Reconstruction and Success

This is where fragmentation becomes operationally interesting.

How often is the complete authentication object reconstructed?

How does success degrade with:

* signature size
* fragment count
* traffic density
* authentication interval

This may ultimately be more informative than raw signature size alone.

5.6 Verification Workload

Show receiver-side:

* verifications/s
* peak workload
* throughput required
* effect of traffic density
* effect of authentication interval

If verification latency queues, show whether backlog occurs.

5.7 Sensitivity Analysis

Bring the previous results together.

Rather than declaring one universal “winner”, identify operating regions:

* configurations that remain plausible
* configurations dominated by communication overhead
* configurations dominated by latency
* configurations that fail reconstruction or computational requirements

This is much more scientifically useful than simply ranking algorithms.

⸻

6. Discussion

This is where you interpret rather than merely report.

6.1 What Actually Limits PQC Authentication?

Connect the experiment back to the thesis.

For example:

The thesis identified message/protocol capacity as the primary limiting constraint and bandwidth as the secondary constraint for ADS-B 1090ES. The trace-driven results now quantify how those constraints manifest under actual traffic.

That provides a very elegant bridge between thesis and paper.

6.2 Algorithm and Architecture Trade-offs

Explain why results differ.

For example:

* compact signatures reduce fragmentation
* faster signing may matter for immediate authentication
* fast verification matters at dense ground receivers
* detached authentication can trade authentication freshness for reduced interference with the primary surveillance path
* longer authentication intervals reduce overhead but increase the amount of unauthenticated traffic between authentication events

This is where the paper becomes more than a benchmarking exercise.

6.3 ADS-B, LDACS, and Future CNS Evolution

Address Reviewer 2 explicitly here again.

The conclusion should not be “1090ES forever.”

It should be closer to:

The results quantify the difficulty of retrofitting PQC into an installed legacy broadcast system. Future security-aware links such as LDACS provide substantially greater architectural flexibility, but they do not eliminate the near- and medium-term problem of authenticating surveillance information transmitted through existing 1090ES infrastructure.

This turns the reviewer’s concern into a broader system-design insight.

6.4 Limitations

This needs to be unusually transparent because the paper uses replay rather than an RF testbed.

Important limitations include:

* OpenSky observations represent received traffic, not every transmitted RF message.
* Replay does not reproduce every physical-layer collision mechanism unless explicitly modeled.
* computational times are injected from external benchmarks.
* cryptographic identities are synthetic.
* PKI distribution/revocation is outside scope.
* the study does not propose a standardized ADS-B authentication protocol.
* results depend on the assumed security-packet format and fragmentation architecture.
* one OpenSky region/time period may not represent every 1090 MHz environment.

These are not weaknesses to hide. They define exactly what the results can and cannot establish.

⸻

7. Conclusion

Short.

Answer the three research questions directly.

Then conclude with the larger point:

PQC feasibility in aviation cannot be inferred from cryptographic benchmarks alone. In ADS-B, the interaction between signature size, protocol fragmentation, traffic density, authentication timing, and receiver workload determines operational feasibility.

Then mention open release of the simulator and data-processing pipeline.

⸻

What I would reuse from the thesis

The ADS-B quantitative characterization, limiting-constraint conclusion, digital-signature candidate-selection rationale, and algorithm size/performance characterization should all feed directly into the paper.

What I would not transplant is equally important: the complete eight-system selection, KEM analysis, general cryptography tutorial, mathematical derivations of ML-DSA/FN-DSA/SLH-DSA, and the complete seven-category constraint framework. Those are valuable in the thesis, but they would bury the actual contribution of this paper.

The resulting narrative becomes very clean:

ADS-B is structurally difficult to authenticate → the most mature PQC signatures have radically different operational characteristics → analytical screening tells us what might fit → OpenSky traces tell us what actually happens under realistic traffic → the results reveal which trade-offs dominate deployment.

That, in my view, should be the spine of the full paper.
