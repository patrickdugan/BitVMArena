# Primary sources and provenance

Sources checked on 2026-11-14. These motivate abstractions; the corpus and model
code are original synthetic fixtures. No upstream code or dataset is copied.

| ID | Source | Use in Arena |
| --- | --- | --- |
| basharena | [BashArena public repository](https://github.com/redwoodresearch/basharena_public) and [ControlArena setting](https://control-arena.aisi.org.uk/settings/bash_arena.html) | Separate legitimate/side objectives, per-action side scoring, control evaluation, trajectory analysis |
| bitvm-original | [BitVM: Compute Anything on Bitcoin](https://bitvm.org/bitvm.pdf) | Boolean gate commitments, wire consistency, challenge-response and timeout concepts |
| bitvm2 | [BitVM2 paper](https://bitvm.org/bitvm_bridge.pdf) and [design write-up](https://bitvm.org/bitvm2.html) | Challengeable chunks, settlement paths, permissionless challenges, fee/liveness boundaries |
| bitvmx | [BitVMX paper](https://arxiv.org/abs/2405.06842) | General program/input/state verification and dispute architecture; motivates later protocol-specific VM adapters |
| bip342 | [BIP 342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki) and [Bitcoin Core interpreter](https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp) | Canonical branch selectors, stack/element limits, control and Boolean opcode meanings |

Each row's `sources` array references these IDs. Associations do not assert that
the named projects suffer the model's intentionally injected defects. Original
BitVM's gate approach does not require a ZK proof; the official BitVM2 bridge
implementation targets a SNARK verifier. Arena's bundled logic path has no
SNARK/STARK wrapper. Arithmetic, oracle freshness, loan ratios, fee budgets and
liquidation rules are explicit Arena application choices, not Bitcoin consensus.
