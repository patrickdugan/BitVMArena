# Primary sources and provenance

Sources checked on 2026-11-14. These motivate abstractions; the corpus and model
code are original synthetic fixtures. No upstream code or dataset is copied.

| ID | Source | Use in Arena |
| --- | --- | --- |
| basharena | [BashArena public repository](https://github.com/redwoodresearch/basharena_public) and [ControlArena setting](https://control-arena.aisi.org.uk/settings/bash_arena.html) | Separate legitimate/side objectives, per-action side scoring, control evaluation, trajectory analysis |
| bitvm-original | [BitVM: Compute Anything on Bitcoin](https://bitvm.org/bitvm.pdf) | Boolean gate commitments, wire consistency, challenge-response and timeout concepts |
| bitvm2 | [BitVM2 paper](https://bitvm.org/bitvm_bridge.pdf) and [design write-up](https://bitvm.org/bitvm2.html) | Challengeable chunks, settlement paths, permissionless challenges, fee/liveness boundaries |
| bitvmx | [BitVMX paper](https://arxiv.org/abs/2405.06842) | General program/input/state verification and dispute architecture; motivates later protocol-specific VM adapters |
| bitvm3 | [BitVM3 paper](https://bitvm.org/bitvm3.pdf) | Garbled-circuit disprove: input labels as commitments, reject label opens a hashlock |
| iob-bitvm3 | [In-and-Out-Burger BitVM3 claim graph](https://github.com/patrickdugan/Spiral/blob/76071a0/in-and-out-burger/iob/bitvm3.py), Spiral `76071a0` | Concrete target of the BitVM3 track: leaf scripts, window, claim_id, trust assumptions T1-T3 |
| garbled-snark-verifier | [garbled-snark-verifier](https://github.com/BitVM/garbled-snark-verifier) and the fork [patrickdugan/garbled-snark-verifier](https://github.com/patrickdugan/garbled-snark-verifier) (nova-bitvm3 M14) | Engine family (free-XOR + half-gates, one Delta) mirrored by `gc.py`; M14 sizes and measured evaluation time |
| half-gates | [Zahur, Rosulek, Evans: Two Halves Make a Whole](https://eprint.iacr.org/2014/756) | Half-gates AND garbling used in `gc.py` |
| bitvm-upstream | [BitVM/BitVM](https://github.com/BitVM/BitVM/tree/c620dbfaacebdf778e765a6681985350389973b1) at `c620dbfa` | BitVM2 bridge graph (connectors, sighash types, timelocks) and Winternitz parameters for the baseline track |
| bip342 | [BIP 342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki) and [Bitcoin Core interpreter](https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp) | Canonical branch selectors, stack/element limits, control and Boolean opcode meanings |

Each row's `sources` array references these IDs. Associations do not assert that
the named projects suffer the model's intentionally injected defects. Original
BitVM's gate approach does not require a ZK proof; the official BitVM2 bridge
implementation targets a SNARK verifier. Arena's bundled logic path has no
SNARK/STARK wrapper. Arithmetic, oracle freshness, loan ratios, fee budgets and
liquidation rules are explicit Arena application choices, not Bitcoin consensus.
