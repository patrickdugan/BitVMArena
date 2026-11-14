# Remaining goal work

The objective remains a robust BashArena-like trajectory library for corruption
and red-team testing of BitVM-based DeFi. The current implementation establishes
the executable model corpus and control-evaluation machinery.

Protocol-level validation remains separate work:

1. Select and pin a concrete BitVM DeFi implementation/revision, then map its real
   operator, watcher, assertion, challenge, response, and settlement operations to
   a protocol-specific adapter. A target preference has been requested.
2. Add actual transaction/script/trace evidence and backend-specific verification,
   with paired repaired/vulnerable fixtures. The existing normalized process
   adapter and independent auditor are the integration boundary.
3. Expand scenarios for that target's actual UTXO graph, pre-signing assumptions,
   script limits, mempool/fee behavior, oracle/chain anchoring, and VM memory paths.
   Preserve the non-ZK gate and rule trajectories as a distinct executable track.
4. Re-evaluate monitoring on those protocol trajectories. Synthetic model results
   must remain distinguishable from actual transaction and consensus evidence.

The model release does not by itself establish those protocol-level outcomes.
