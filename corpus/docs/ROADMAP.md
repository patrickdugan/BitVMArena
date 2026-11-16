# Remaining goal work

The objective is a robust BashArena-like trajectory library for corruption and red-team
testing of BitVM-based DeFi. The focus is now BitVM3, with BitVM2 kept as the baseline
for reasoning about which weaknesses BitVM3 introduces, removes or carries over.

Done:

- the model corpus (168 trajectories) with control evaluation;
- native Core-judged tracks: primitives (56), the BitVM3 claim graph (40) and the BitVM2
  baseline (32). The BitVM3 graph mirrors the In-and-Out-Burger graph at Spiral 76071a0
  and is decided by a real half-gates garbled circuit. The BitVM2 baseline mirrors the
  BitVM/BitVM bridge graph at c620dbfa.

Next:

1. **BitVM3 at real scale.** Run the label-availability, seed-reuse and window recipes
   against the M14 garbler in garbled-snark-verifier instead of the toy adder, using
   the `m14-claim setup/evaluate` CLI and measured evaluation latency.
2. **The IOB fixes as hardened profiles on testnet4:** a claimant bond, a desk-presigned
   permissionless disprove, a window derived from measured evaluation time, and one seed
   per claim. Only with explicit approval before any broadcast.
3. **Statement-only label commitment.** The input-label availability recipe with a
   512-bit statement on chain and data availability for the rest of the proof (about
   12k vB at the measured 23.5 vB per bit).
4. **Agent-facing native episodes.** Expose the native tracks through the `serve`/JSONL
   adapter, so red-team agents choose transactions and Core judges them. Then calibrate
   monitors on native trajectories, kept separate from model results.
5. **Mempool dynamics:** full-RBF races between an early payout and a disprove, pinning,
   and fee bumping. These are noted but not modeled.
