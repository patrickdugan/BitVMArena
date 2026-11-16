# Remaining goal work

The objective is a robust BashArena-like trajectory library for corruption and red-team
testing of BitVM-based DeFi. The focus is BitVM3, with BitVM2 kept as the baseline for
reasoning about which weaknesses BitVM3 introduces, removes or carries over.

Done:

- the model corpus (168 trajectories) with control evaluation;
- native Core-judged tracks: primitives (56), the BitVM2 baseline (32) and the BitVM3
  claim graph (80). The BitVM3 graph mirrors the In-and-Out-Burger graph at Spiral
  76071a0 and is decided by a real half-gates garbled circuit. Its 20 recipes cover
  garbling, data availability, statement binding, the presigned transaction graph,
  mempool and miners, liveness and economics. The BitVM2 baseline mirrors the BitVM/BitVM
  bridge graph at c620dbfa;
- mempool and miner dynamics on regtest: full-RBF replacement, TRUC/P2A package relay
  through `submitpackage`, and censoring miners through `generateblock`;
- a threat matrix for applications built on BitVM3 and a static design check
  (`native assess`) that maps a design to the recipes it is exposed to;
- interactive episodes (`native episode`): a red-team agent attacks an application
  preset or any `Config`, Core judges every transaction, and a value-flow scorer reports
  the outcome ([EPISODES.md](EPISODES.md)).

Next:

1. **BitVM3 at real scale.** Run the label-availability, seed-reuse, window and
   censorship recipes against the M14 garbler in garbled-snark-verifier instead of the
   toy adder, using the `m14-claim setup/evaluate` CLI and measured evaluation latency.
2. **The IOB fixes as hardened profiles on testnet4:** a burned claimant bond, a
   desk-presigned permissionless disprove with a P2A anchor, a window derived from
   measured evaluation time and the censorship bound, and one seed per claim. Only with
   explicit approval before any broadcast.
3. **Statement-only label commitment.** The input-label availability recipe with a
   512-bit statement on chain and data availability for the rest of the proof (about
   12k vB at the measured 23.5 vB per bit).
4. **Monitors on native episodes.** Calibrate the control monitors on episode
   transcripts, kept separate from model results.
5. **More attacker roles in episodes:** a malicious desk, a bribed watcher and a
   relayer, alongside the claimant.
6. **Multi-node mempools:** pinning and propagation races need more than one node's
   policy, which the single-node harness does not model.
