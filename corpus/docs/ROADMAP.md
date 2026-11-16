# Remaining goal work

The objective is a robust BashArena-like trajectory library for corruption and red-team
testing of BitVM-based DeFi. The focus is BitVM3, with BitVM2 kept as the baseline for
reasoning about which weaknesses BitVM3 introduces, removes or carries over.

Done:

- the model corpus (168 trajectories) with control evaluation;
- native Core-judged tracks: primitives (56), the BitVM2 baseline (32) and the BitVM3
  claim graph (96). The BitVM3 graph mirrors the In-and-Out-Burger graph at Spiral
  76071a0 and is decided by a real half-gates garbled circuit. Its 24 recipes cover
  garbling, data availability, statement binding, the presigned transaction graph and its
  signers, mempool and miners, liveness and economics. The BitVM2 baseline mirrors the
  BitVM/BitVM bridge graph at c620dbfa;
- BitVM3 at M14 scale (`bitvm3-m14`): the same claim graph decided by the complete garbled
  final verifier (785,442,492 gates) on the M16 mainnet payment proof, with recorded
  evaluation time and memory;
- mempool, miner and network dynamics on regtest: full-RBF replacement, TRUC/P2A package
  relay, anchor pinning under a congested fee floor, censoring miners through
  `generateblock`, and P2P relay between three owned loopback nodes for an eclipsed
  watcher;
- a threat matrix for applications built on BitVM3 and a static design check
  (`native assess`) that maps a design to the recipes it is exposed to;
- interactive episodes (`native episode`): a red-team agent plays the claimant, the desk,
  the watcher or a relayer against an application preset or any `Config`, Core judges
  every transaction, and an entitlement-based value-flow scorer reports the outcome
  ([EPISODES.md](EPISODES.md)).

Next:

1. **More recipes at M14 scale.** Seed reuse needs the evaluator's input labels, which
   `m14-claim` does not export; the window and censorship recipes need the evaluation
   time measured on the watcher hardware a deployment expects.
2. **The IOB fixes as hardened profiles on testnet4:** a desk-presigned refund disprove
   with a TRUC P2A anchor (closes the watcher redirect and the single-watcher point), a
   payout co-signed by the claimant, a burned claimant bond, a window derived from
   measured evaluation time and the censorship bound, and one seed per claim. Only with
   explicit approval before any broadcast.
3. **Statement-only label commitment.** The input-label availability recipe with a
   512-bit statement on chain and data availability for the rest of the proof (about
   12k vB at the measured 23.5 vB per bit).
4. **Monitors on native episodes.** Calibrate the control monitors on episode
   transcripts, kept separate from model results.
5. **Episodes on the multi-node cluster,** so an attacker can choose a topology, and a
   desk that signs disproves.
