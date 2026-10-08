# Documentation

Start with [the repository README](../README.md) to install the software and run the small, real-signature demo. The two final one-hour datasets have not yet been acquired or evaluated.

## Reproduce a run

| Guide | Use it for |
| --- | --- |
| [Current experiment: commands](reproduction_commands.md) | Preparing the two window inputs, running actual signing and replay, validating, and plotting. |
| [Native cryptography](native_crypto.md) | Installing pinned liboqs and checking which library Python loads. |
| [Historical development reference](reproduce_development.md) | Recreating the earlier 64-case replay and 16 analytical rows from the recorded sample. |
| [Publication and evidence](publication.md) | Distinguishing fresh signing from exact replay, preparing the paper's release, and finding relocated material. |

## Understand the experiment

| Document | Contents |
| --- | --- |
| [Supervisor meeting guide](supervisor_meeting_guide.md) | Plain-language repository tour, from-scratch commands, presentation outline, and answers to likely questions. |
| [Methodology](methodology.md) | Signed bytes, grouping, fragmentation, queues, channel assumptions, metrics, and limitations. |
| [Channel input](channel_trace.md) | Recorded 1090 MHz event schema, target links, acquisition coverage, and follow-up. |
| [Hardware profiles](hardware_profiles.md) | Embedded reference timings, their sources, and the distinction from host execution time. |
| [Data documentation](../data/README.md) | Input fields, sample hashes/provenance, and data-use information. |
| [Results index](../results/README.md) | Frozen references, current output locations, and historical local artifacts. |

The paper material is in [paper/](paper/README.md). Its incomplete drafts are context, not evidence that the final study has run. The [development results](development_results.md) interpret the earlier reference only. [Archived notes](archive/README.md) preserve superseded models and decisions; follow the current methodology when reproducing the planned study.
