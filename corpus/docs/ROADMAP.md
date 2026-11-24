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
  final verifier (792,546,673 gates) on the M16 mainnet payment proof, with recorded
  evaluation time and memory;
- mempool, miner and network dynamics on regtest: full-RBF replacement, TRUC/P2A package
  relay, anchor pinning under a congested fee floor, censoring miners through
  `generateblock`, and P2P relay between three owned loopback nodes for an eclipsed
  watcher;
- the IOB graph with every hardened fix at once (`bitvm3-iob`, 46 rows on regtest): no
  attack succeeds, the fixes compose (every attack but one takes its single-fix row's
  transaction steps), and 17 of the 23 attacks burn the claimant's bond;
- a threat matrix for applications built on BitVM3 and a static design check
  (`native assess`) that maps a design to the recipes it is exposed to;
- interactive episodes (`native episode`): a red-team agent plays the claimant, the desk,
  the watcher or a relayer against an application preset or any `Config`, Core judges
  every transaction, and an entitlement-based value-flow scorer reports the outcome
  ([EPISODES.md](EPISODES.md));
- testnet4 staging (`bitvm3-testnet4`, [TESTNET4.md](TESTNET4.md)): the hardened profiles
  (the IOB fixes) and their attacks broadcast on the public network.
  - **Wave 1:** 18 hardened rows; 17 met expectations.
  - **The eighteenth** was lost to a testnet4 reorg that the harness had not counted
    for. The session now re-checks depth through reorgs, and the rehearsal can reorganize.
  - **Wave 2:** nine mutant attacks plus that row; 10 of 10 met. Every flaw landed on the
    public network, and 13 transactions came through a reorg without a resend.
  - **Wave 3:** six mutant attacks on timing and on presigned transactions; 6 of 6 met.
    The absolute-timelock payout landed in its claim's block.
  - **Wave 4:** four mutant attacks on seeds, polarity, the bond and the garbling; 4 of 4
    met. The claimant's self-slash disprove replaced the watcher's under full RBF. The
    audit's chain re-check now covers the split and the vault fundings.
  - **Wave 5:** the last two mutant attacks (a ground Fiat-Shamir cut-and-choose, garbled
    tables handed over at claim time) and the hardened cut-and-choose; 3 of 3 met. Every
    mutant attack in the catalog has now landed on testnet4, and the hardened
    cut-and-choose claim was refused by public relay policy.
  - **Wave 6:** the hardened seed-reuse and late-tables attacks; 2 of 2 met. The griefing
    disprove failed its hashlock, and the watcher disproved the false claim from the tables
    checked at setup. Three consecutive blocks holding wave transactions were replaced, and
    nothing needed a resend.
  - **Wave 7:** the hardened payout against the relayer that redirects it; 1 of 1 met. The
    redirected payout failed its signature check and the honest payout landed. The split's
    own block was replaced, and real-difficulty block 161,882 mined the split and the
    funding together.
  - **Wave 8:** the 41 rows left (the benign row of every recipe under both profiles and
    the last two hardened attacks); 41 of 41 met. All 84 testnet4 rows have now met their
    expectations on the public network. Two minimum-difficulty branches traded the lead
    under the vault fundings, and real-difficulty blocks mined every claim and every
    payout.

Next:

1. **More recipes at M14 scale.** Seed reuse needs the evaluator's input labels, which
   `m14-claim` does not export; the window and censorship recipes need the evaluation
   time measured on the watcher hardware a deployment expects.
2. **What the testnet4 catalog leaves.**
   - The IOB-hardened wave `iob1` (21 attacks and the honest claim on the
     `bitvm3-iob-testnet4` track) is defined and its rehearsal met 22 of 22. It needs
     77,400 sats of coins plus the split, about 76,000 more than the staging wallet holds.
   - Wave 8's hardened `garbling_unchecked` vault (2,000 sats) waits for the desk's
     144-block reclaim, which opens at block 163,249 (`testnet4 recover`).
   - The cost is fees, about 780–1,020 sats per row (funding, claim, disprove, payout),
     plus a split per wave.
     - Wave 1 spent 17,740 of its 49,000 sats. It burned the hardened `bond_self_slash`
       bond (1,000 sats to the NUMS key), as that profile intends. It also left the
       reorg-lost row's claim output (1,771 sats) unpaid; `testnet4 recover` has since paid
       it out and returned 1,521.
     - Wave 2 spent 9,677, wave 3 6,478, wave 4 4,275, wave 5 2,493, wave 6 2,045,
       wave 7 1,034 and wave 8 34,029 (41 rows, about 830 per row).
     - Wave 5's hardened row left its 2,000-sat vault unspent, as a refused claim does.
       `testnet4 recover` sent the desk's reclaim (`cdee3580…`, 1,750 back) on
       2026-11-24.
     - Wave 8 needed a 102,000-sat top-up of the staging wallet, which held 69,729 sats
       when it ended.
   - Running all 84 rows at once would need about 163k sats of coins in flight. Waves sized
     to the wallet recycle the same coins.
   - The recipes that need a miner or a topology (`disprove_censored_by_miner`,
     `disprove_anchor_pinned`, `disprove_partitioned`) stay on regtest.
3. **Statement-only label commitment.** The input-label availability recipe with a
   512-bit statement on chain and data availability for the rest of the proof (about
   12k vB at the measured 23.5 vB per bit).
4. **Monitors on native episodes.** Calibrate the control monitors on episode
   transcripts, kept separate from model results.
5. **Episodes on the multi-node cluster,** so an attacker can choose a topology, and a
   desk that signs disproves.
