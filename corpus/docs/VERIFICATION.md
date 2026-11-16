# Release verification

This file records acceptance scope, not a claim of production bridge security.

Verified on 2026-11-14 with Python 3.12: **40 tests passed**, **336 corpus
replays met their declared expectations**, and the package built and installed
offline through pip. Hardened safety held for all 84 attack fixtures; all 84
attacks exposed their designated mutant. All 84 hardened benign tasks succeeded.

The frozen structural monitor prevented 22 of 28 exploitable held-out attacks and
interrupted 2 of 28 held-out benign trajectories. Its validation calibration used
14 benign trajectories, with zero interventions at the selected threshold.

| Requirement | Authoritative evidence |
| --- | --- |
| Executable trajectory library | Packaged JSON corpus, `corpus/manifest.json`, corpus regeneration test |
| Both stack and forward-chaining logic | Exhaustive Boolean/conditional tests; nested branch, MINIMALIF, closure and bound tests |
| Diverse DeFi corruptions | 42 named corruption sites across 14 families; paired benign/attack traces with two seeds |
| Behavioral attack labels | Both-profile replay assertions; first-harm tests; reference state/effect scoring |
| Separation of usefulness and security | Explicit main and side outcomes; expected rounding utility regression |
| Honest controls | Hardened benign replays deliver all requested model outcomes |
| Replay reliability | Determinism, conserved assets, atomic rejection, deadline boundaries, concurrent stale-state rejection, reorg revalidation |
| Prefix-only monitoring | Copy-isolation and leakage tests; interception occurs before action execution |
| Meaningful control metrics | Trajectory FPR, validation-only calibration, exploitability-conditioned prevention tests |
| Tamper detection | Hash/replay validation, fixture substitution and unexplained-truncation tests |
| Extensibility | Local JSONL adapter with independent observation audit, reset binding, timeout and output-bound tests |
| Installable distribution | Reproducible wheel, RECORD checksums, isolated installed-corpus import test |

`examples/validation.json` records both-profile corpus validation. The calibration
and held-out structural-monitor evaluation are saved alongside it. These are
results on synthetic model fixtures. The native tracks below are the separate,
Core-judged evidence; no deployed DeFi target was attacked.

## Native tracks (2026-11-16)

Python 3.12 unit suite with the live Core tests enabled (`BITVM_ARENA_BITCOIND` set to
Core 31.1): **76 tests passed**. They cover:
- primitives: the BIP340 vectors, the RIPEMD-160 fallback, Taproot commitments,
  SIGHASH_SINGLE scope and transaction round trips;
- garbling: garbled evaluation against plain evaluation, cut-and-choose detection, the
  Delta leak, table corruption and per-vault statement binding;
- graph shape: key-path and presignature scope, and the anchor and burn shapes;
- the design assessment;
- the episode presets, actions, scorer, audit and censorship bound;
- live catalog subsets for package relay and miner censorship, and live episodes;
- evidence: auditing of the committed reports, and tamper detection including a
  replaced transaction claimed as confirmed.

| Track | Core | Cases met | Confirmed / rejected txs | Offline audit |
| --- | --- | --- | --- | --- |
| primitive | 31.1.0 (GPG-verified) | 56/56 | 42 / 16 | 0 problems |
| bitvm3 | 31.1.0 (GPG-verified) | 80/80 | 159 / 43 | 0 problems |
| bitvm2 | 31.1.0 (GPG-verified) | 32/32 | 106 / 27 | 0 problems |
| bitvm3 | 31.2.0 (checksum-matched) | 80/80 | 159 / 43 | 0 problems; every step verdict identical to 31.1 |

The BitVM3 rows are the 20-recipe track. Its first ten recipes (40 trajectories) gave
the same per-step verdicts as the earlier 10-recipe evidence.

**Episodes (2026-11-16).** The 11 example episodes in
[`examples/episodes/reports/`](../examples/episodes/reports/) ran on Core 31.1 and each
audits clean. Their outcomes (attack succeeds where the design allows it, fails on the
bridge preset) are listed in [EPISODES.md](EPISODES.md#examples). The static check
`native assess` flags each recipe's mutant design and none of the hardened ones.

These are regtest results on fixture keys. The BitVM3 circuit is a toy statement
verifier, and its latency and censorship recipes use declared bounds ([BITVM3.md](BITVM3.md)).

Run the commands in the README to reproduce the evidence. Baseline numbers should
always be read with the model assumptions and dataset limitations in the linked
threat and evaluation documents.
