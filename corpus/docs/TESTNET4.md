# Staging BitVM3 on testnet4

The `bitvm3-testnet4` track runs the BitVM3 claim-graph trajectories on the public testnet4
network. Real peers relay the transactions, real testnet4 miners decide what confirms, and
real block arrival sets every timelock. The regtest track has a script decide all three.

## What runs

The trajectories are the regtest track's (`bitvm3.run_case`), unchanged. Only the session
underneath them is different ([`testnet4.py`](../bitvm_corpus/testnet4.py)):

| | Regtest track | Testnet4 staging |
| --- | --- | --- |
| Node | owned, P2P off, wallet mines | an existing testnet4 node with peers, and one wallet on it |
| Blocks | `generatetoaddress`, includes the whole mempool | waits for the network's blocks until every transaction the case broadcast is as deep in the best chain as regtest would have it, or displaced (18 blocks of patience); re-checked through reorgs |
| Keys | the public test secrets | fresh secrets per wave, kept in a state directory outside the repository |
| Garbling seeds | `sha256(case id : tag)` | `sha256(salt ‖ case id : tag)` with a fresh 16-byte salt per wave, published in the report |
| Amounts | vault 100,000, bond 20,000, fee 3,000 | vault 2,000, bond 1,000, fee 250, claim at 1.1 sat/vB |
| Cases | one after another | all cases of a wave at once, one thread each |
| Not available | — | `generateblock` (censoring miner, congested fee floor) and owned topologies |

The fees are set for testnet4's block producers. Most testnet4 blocks are
minimum-difficulty blocks, and those producers take about 1 sat/vB or more. So every staged
transaction pays at least 1.1 sat/vB, except the zero-fee presigned disprove, whose fee
comes from its anchor child. Every output stays above the 330-sat P2TR dust limit
(`test_testnet4_amounts_stay_above_dust`).

Three recipes need control that a public network does not give, and stay on regtest:
`disprove_censored_by_miner`, `disprove_anchor_pinned` and `disprove_partitioned`. That
leaves 21 recipes, 84 rows.

## Safety rails

- `StagingNode` refuses any chain but testnet4 (or regtest for a rehearsal). It never
  mines.
- `testnet4 run` needs `--broadcast`, an explicit wallet, and a new state directory
  outside the repository. The stage secrets are written there before anything is
  broadcast.
- The audit fails a report that carries stage secrets.
- Each wave's stage keys are imported into the staging wallet as `tr()` descriptors. So
  payouts, refunds and watcher rewards come back to the wallet that funds the next wave.

## Rehearsal first

`testnet4 rehearse` runs the same wave runner against an owned regtest node whose
"network" mines a block every 1.5 s, with fresh keys and the testnet4 amounts. Before any
testnet4 coins moved, all 84 rows were rehearsed:
- every expectation was met;
- every transaction step had the same outcome as the regtest catalog (same label, accepted
  or rejected, confirmed, reject reason);
- the report audits clean.

The CI regtest job reruns that rehearsal on Linux Core 31.1.

The rehearsal found three harness bugs a single-threaded regtest run cannot show:
- 84 concurrent cases overflowed Core's RPC work queue (HTTP 503). The client now caps
  concurrent calls and retries a 503.
- A transaction confirmed between "is it confirmed?" and "is it in the mempool?" was
  recorded as displaced.
- A block arriving between reading the tip for an absolute payout height and recording the
  setup step broke the CLTV audit. The public-network audit allows 2 blocks of slack.

Wave 5's rehearsals found two more:
- **An evicted coin split was never sent again.**
  - The wallet sets the split's nLockTime to the tip. A reorg that lowers the tip makes the
    split non-final, and in a rehearsal the split can also spend a coinbase that is
    immature again.
  - A reorg two seconds after the split did both. Core dropped it from the mempool, and the
    rehearsal waited six hours for a transaction that was gone.
  - The split is now sent again on every block until it is back, as the case transactions
    already were.
  - Testnet4 can lower the tip the same way, when a real-difficulty block replaces two
    minimum-difficulty blocks.
- **The bootstrap outlasted the RPC timeout.** On a machine at 100% CPU, the regtest node
  took about 0.8 s per block, and one `generatetoaddress 101` call outlasted the 30-second
  RPC timeout. It now mines ten blocks per call, and the rehearsal node uses the 60-second
  cap.

## Wave 1: 18 hardened rows on testnet4

[`examples/testnet4/wave1.json`](../examples/testnet4/wave1.json), broadcast on
2026-11-16 from a Core 31.1 node with 10 peers:
- **Funding:** 49,000 sats into the staging wallet, split into 19 coins in
  `059b6ef1…`.
- **Run:** the tip went from 161,695 to 161,729 between 13:25 and 18:15 UTC.
- **Transactions:** 38 confirmed and 23 refused by mempool policy. None was displaced or
  dropped.
- **Expectations:** 17 of 18 met. The eighteenth was lost to a testnet4 reorg, through a
  harness bug and not the graph (see below).
- **Audit:**
  - offline, clean;
  - the re-check against the node's best chain finds every confirmed transaction still
    in the chain, with the same bytes;
  - two payouts the report records in block 161,710 now sit in 161,712;
  - the second vault funding of `proof_replay_across_vaults`, recorded in 161,704
    (`00000000d7df…`), now sits in a sibling block at the same height
    (`000000000043948b…`). The re-check has covered vault fundings and the split since
    wave 4.

| Row (hardened) | Outcome | What testnet4 did |
| --- | --- | --- |
| `seed_reuse_across_claims` benign | paid | claim 161,704; payout 161,710 (now 161,712) |
| `output_polarity_swapped` attack | stopped | claim 161,704; disprove 161,712; payout refused `missing-inputs` |
| `labels_offchain_withheld` benign | paid | claim 161,704; payout 161,716 |
| `labels_offchain_withheld` attack | stopped | claim 161,704; disprove 161,712; payout refused `missing-inputs` |
| `window_below_latency` benign | paid | claim 161,704; payout 161,728 (24-block window) |
| `window_below_latency` attack | stopped | claim 161,704; early payout refused `non-BIP68-final`; disprove 161,712; payout refused `missing-inputs` |
| `single_watcher_disprove` attack | stopped | claim 161,704; disprove 161,712; payout refused `missing-inputs` |
| `disprove_watcher_redirect` attack | stopped | claim 161,704; redirected disprove refused (script); watcher's disprove 161,712; payout refused |
| `claimant_unbonded` attack | stopped | claim 161,704; disprove 161,705; payout refused `missing-inputs` |
| `bond_self_slash` attack | stopped | claim 161,704; disprove 161,705; self-slash replacement refused (script); payout refused |
| `disprove_unbumpable` attack | stopped | claim 161,704; zero-fee TRUC disprove `97175489…` and its P2A child `c0b31358…` both 161,705; payout refused |
| `desk_key_retained` attack | paid | claim 161,704; desk-signed payout refused `Invalid Schnorr signature`; cosigned payout 161,710 (now 161,712) |
| `reclaim_preempts_claim` attack | **not paid** | early reclaim refused `non-BIP68-final`; claim mined in 161,710, reorged, again in 161,712; payout at 161,715 refused `non-BIP68-final` |
| `proof_replay_across_vaults` attack | paid once | both claims 161,705; replayed claim disproven 161,712; first payout 161,716; second refused |
| `payout_csv_removed` attack | stopped | claim 161,704; early payout refused `non-BIP68-final`; disprove 161,705; payout refused |
| `claim_internal_key_spendable` attack | stopped | claim 161,704; key-path sweep refused (script); disprove 161,712; payout refused |
| `disprove_outputs_unbound` attack | stopped | claim 161,704; self-paying disprove refused (script); disprove 161,712; payout refused |
| `payout_absolute_timelock` attack | stopped | claim 161,704; early payout refused `non-BIP68-final`; disprove 161,705; payout refused |

What the public network showed:

1. **Package relay carries the presigned zero-fee disprove.** The TRUC disprove at zero
   fee and its P2A fee child went in through `submitpackage` and were mined together. A
   testnet4 miner took the one-parent-one-child package, so a desk can presign a disprove
   at zero fee and leave the fee to whoever broadcasts it.
2. **Policy refusals match regtest.** Each refused step gave the reject reason the regtest
   track records:
   - `non-BIP68-final` for early payouts and the early reclaim;
   - a script failure for the redirected, self-slashing, self-paying and key-path spends;
   - `Invalid Schnorr signature` for the payout signed with a retained desk key;
   - `missing-inputs` once a disprove had confirmed.
3. **Testnet4 blocks come from two kinds of producer.**
   - Of the 35 blocks from 161,695 to 161,729, five were real-difficulty blocks: 161,698,
     161,706, 161,712, 161,716 and 161,720. Their timestamps were close to wall-clock time.
   - The other 30 were minimum-difficulty blocks. Each was timestamped exactly 20 minutes
     after its parent, which put them up to about three hours ahead of the clock. Most
     carried only their coinbase.
   - Across the wave's 42 block waits, a block took a median of 461 s and a mean of 887 s.
4. **Minimum-difficulty blocks are reorganized routinely.**
   - A real-difficulty block carries about 1.6 × 10⁹ times the work of a
     minimum-difficulty block. Any run of minimum-difficulty blocks that the next
     real-difficulty block does not build on is replaced.
   - The node's chain tips list 24 stale branches between 161,695 and 161,729, up to 6
     blocks long.
   - The claim of `reclaim_preempts_claim` was mined in 161,710 (`00000000cd31847a…`) and
     161,711 on one branch. Block 161,712, a real-difficulty block, extended a sibling
     branch, and the claim confirmed again in 161,712.

### The row the reorg cost, and the fix

The session had cached the claim as confirmed the first time it saw it. So the 5-block wait
before the 6-block-CSV payout counted from 161,710. When the payout went out at 161,715 the
claim had 4 confirmations in the best chain, and Core refused the payout. The graph behaved
correctly; the honest claimant's software sent too early. Any watcher or claimant that
counts a timelock from the first block it sees a transaction in makes the same mistake on
testnet4. A BitVM3 deployment's software has to recount from the block that stays.

[`testnet4.py`](../bitvm_corpus/testnet4.py) now does that:
- Confirmations are never cached. Each check reads the best chain again, and the chain
  poller wakes on any change of tip hash, including a reorg that keeps the height.
- `mine(count)` waits until every broadcast of the case has at least the confirmations
  regtest would give it at that point. On regtest a broadcast confirms in the first block
  of the next `mine()` and each later block adds one. Before the fix, the wait ended once
  the tip had moved `count` blocks.
- A transaction that leaves the mempool without confirming is sent again, as its owner's
  software would. If the node refuses it, it was displaced.
- Decisions use the snapshot the wait was satisfied on, not a second read that the next
  reorg can contradict.
- A transaction that was mined into a block that a reorg later removed lists that block in
  `reorged_out_of`. The summary counts these (`reorged_transactions`) and rebroadcasts
  (`rebroadcast_transactions`).

The rehearsal can now reorganize too. `--reorg-every N` turns every Nth block of the
regtest "network" into the shape testnet4 showed: the tip is invalidated, its transactions
return to the mempool, and two empty blocks replace it.

N must be 0 or at least 3, and the harness refuses 1 and 2 before it starts a node:
- With N=2, the block each reorg invalidates is the only block since the previous reorg
  that carried transactions. No transaction is ever confirmed twice, and a full rehearsal
  with N=2 sat at its coin split for four hours.
- With N=1, no transaction is mined at all.
- Either setting is a censoring miner, which the regtest track already models as
  `disprove_censored_by_miner`.

Results:
- **Before the full fix,** the reorg rehearsal of all 84 rows exposed two more races, and
  each one lost cases:
  - a funding transaction read while a reorg was being applied (it is briefly in
    neither the mempool nor the active chain);
  - a payout that was confirmed when the final wait ended and back in the mempool by the
    time it was classified.
- **After it,** all 84 rows came through 10 reorgs:
  - 15 transactions were mined, reorged out and mined again;
  - every expectation was met;
  - every transaction step matched the regtest catalog;
  - the audit was clean.

One difference from regtest is real and stays: a block can land between two submits of
the same case. On the 1.5-second rehearsal timer this once turned the bond self-slash
replacement's script refusal into `missing-inputs`, because the watcher's disprove it was
meant to replace had already been mined. Testnet4's blocks are minutes apart, and wave 1
got the regtest outcome.

## Wave 2: the mutant attacks land on testnet4

[`examples/testnet4/wave2.json`](../examples/testnet4/wave2.json), broadcast on
2026-11-16 from the same node (10 peers):
- **Rows:** nine mutant attacks, each with the flaw its hardened profile closes, and the
  hardened `reclaim_preempts_claim` attack that wave 1 lost to a reorg, run again on the
  reorg-aware session.
- **Funding:** the 28,489 sats left after wave 1, split into 10 coins in `f69d6724…`
  (161,737).
- **Run:** the tip went from 161,735 to 161,759 between 18:35 and 20:59 UTC.
- **Transactions:** 19 confirmed and 11 refused by mempool policy. None was displaced,
  dropped or left unconfirmed.
  - 13 were mined, reorged out and mined again.
  - None had to be sent again.
- **Expectations:** 10 of 10 met.
  - Every attack the mutant profiles allow went through.
  - The hardened reclaim row paid the honest claim.
  - Every transaction step matched the regtest catalog.
- **Audit:**
  - offline, clean;
  - against the node's best chain, valid;
  - one note: the reclaim of `reclaim_preempts_claim` mutant, recorded in 161,743, now
    sits in 161,745 (below).
- **Cost:** 9,677 sats of fees, about 970 per row. Nothing was left in contract outputs.

| Row | Outcome | What testnet4 did |
| --- | --- | --- |
| `reclaim_preempts_claim` hardened attack | paid | early reclaim refused `non-BIP68-final`; claim 161,745; payout 161,756 |
| `reclaim_preempts_claim` mutant attack | **attack landed** | desk's early reclaim 161,743 (now 161,745); claim refused `missing-inputs` |
| `desk_key_retained` mutant attack | **attack landed** | claim 161,745; desk re-signed the payout alone, 161,751; claimant's payout refused `missing-inputs` |
| `disprove_watcher_redirect` mutant attack | **attack landed** | claim 161,745; watcher's disprove paying itself, 161,745; payout refused |
| `payout_csv_removed` mutant attack | **attack landed** | false claim and its payout both in 161,745; disprove refused `missing-inputs` |
| `claim_internal_key_spendable` mutant attack | **attack landed** | claim and its key-path sweep both in 161,745; disprove and payout refused |
| `disprove_outputs_unbound` mutant attack | **attack landed** | claim and the self-paying disprove both in 161,745; watcher's disprove and payout refused |
| `labels_offchain_withheld` mutant attack | **attack landed** | false claim 161,745, labels withheld; paid 161,751 |
| `claimant_unbonded` mutant attack | **attack landed** | false claim 161,745, disproven in 161,745; the claimant had nothing at stake |
| `disprove_unbumpable` mutant attack | **attack landed** | claim 161,745; zero-fee disprove without an anchor refused `min relay fee not met`; false claim paid 161,751 |

What the public network showed:

1. **The flaws do not depend on regtest.** Each mutant attack landed against real relay
   and real miners, with the transaction steps and reject reasons of the regtest catalog.
   In the final chain, three of them have the claim and the attacker's spend in the same
   block:
   - `payout_csv_removed`: the payout;
   - `claim_internal_key_spendable`: the key-path sweep;
   - `disprove_outputs_unbound`: the self-paying disprove.

   They had been in consecutive blocks before the reorg below, and 161,745 took both.
   Without the timelock the hardened profile adds, a miner can confirm the spend together
   with the claim, which leaves the watcher no block in which to answer.
2. **A real-difficulty block replaced the branch that held the attacks, and the fix held.**
   - Minimum-difficulty blocks 161,743 (`00000000000db372…`, 33 transactions) and
     161,744 (`0000000042d712bb…`, 8 transactions) held the claims of eight rows and five
     follow-up spends.
   - Real-difficulty block 161,745 (`0000000000000000521b…`) extended a sibling branch.
     All 13 transactions went back to the node's mempool, and 161,745 mined them with 38
     others.
   - The session counted every timelock again from 161,745, so no transaction was sent
     early and none had to be resent. The hardened reclaim row, which wave 1 lost the
     same way, paid at 161,756.
3. **A row can end before its block is replaced.**
   - The mutant `reclaim_preempts_claim` row was decided once its reclaim had a
     confirmation in 161,743 and the claim was refused.
   - The reorg came after that, and the reclaim confirmed again in 161,745. The report
     keeps the block the row ended on, and the audit's chain re-check notes the move.
   - The outcome stands, because the reclaim is still the spend of the vault.
4. **Most minimum-difficulty blocks carry nothing.**
   - Of the 25 blocks from 161,735 to 161,759, four were real-difficulty blocks: 161,738,
     161,745, 161,751 and 161,756.
   - 17 of the 21 minimum-difficulty blocks in the final chain held only their coinbase.
   - 29 of the wave's 30 transactions (the split, the 10 vault fundings and the 19
     confirmed steps) are in real-difficulty blocks. In wave 1, by contrast, 27 of 58
     stayed in minimum-difficulty blocks 161,704 and 161,705, because the next
     real-difficulty block built on them.
   - A timelock counts every block, but only 8 of the wave's 25 blocks carried any
     transaction. On testnet4, a window of N blocks gives a disprove fewer than N blocks
     that will take it. The window recipes are harder on the watcher here than on
     regtest, where every block takes the mempool.

## Wave 3: attacks on timing and on presigned transactions

[`examples/testnet4/wave3.json`](../examples/testnet4/wave3.json), broadcast on
2026-11-16:
- **Rows:** six mutant attacks whose outcome turns on public-network timing or on a
  presigned transaction that someone other than its signer can rewrite.
- **Funding:** the 18,812 sats left after wave 2, split into 7 coins in `e5243f11…`
  (161,765).
- **Run:** the tip went from 161,764 to 161,783 between 21:06 and 23:26 UTC.
- **Transactions:** 13 confirmed and 4 refused by mempool policy. None was displaced,
  dropped or left unconfirmed.
  - One was reorged during its row.
  - None had to be sent again.
- **Expectations:** 6 of 6 met. Every attack landed, and every transaction step matched
  the regtest catalog.
- **Audit:**
  - offline, clean;
  - against the node's best chain, valid;
  - six notes:
    - the split, recorded in 161,765, now sits in a sibling block at the same height
      (`00000000ae78151d…`);
    - three payouts recorded in 161,776 now sit in 161,778 (below);
    - the two `proof_replay_across_vaults` payouts, recorded in 161,783
      (`0000000026eb5d1e…`), now sit in a sibling block at the same height
      (`00000000006e060e…`). That block replaced the recorded one after the wave ended.
- **Cost:** 6,478 sats of fees, of which 1,274 were for the split, so about 870 per row.
  Wave 2 came to about 780 per row after its 1,866-sat split. Nothing was left in contract
  outputs.

| Row (mutant attack) | What testnet4 did |
| --- | --- |
| `payout_absolute_timelock` | late claim and its payout both in 161,772, a real-difficulty block; disprove refused `missing-inputs` |
| `window_below_latency` | claim 161,767; payout 161,776 (now 161,778) before the evaluation finished; disprove refused `missing-inputs` |
| `claim_sighash_none` | the claimant's rewrite of the presigned claim, paying the vault straight to itself, 161,767 |
| `payout_sighash_none` | claim 161,767; redirected payout 161,776 (now 161,778); honest payout refused `missing-inputs` |
| `proof_replay_across_vaults` | one payment proof claimed both vaults, 161,772; both paid 161,783 (since moved to a sibling block) |
| `single_watcher_disprove` | claim 161,767; a disprove by a reject-label holder other than the one authorized watcher refused `Invalid Schnorr signature`; false claim paid 161,776 (now 161,778) |

What the public network showed:

1. **An absolute payout height leaves no window at all.** A testnet4 miner confirmed the
   late claim and its payout in the same real-difficulty block, as the recipe describes.
   A watcher that saw the claim in the mempool had no block in which to answer.
2. **Block 161,776 was replaced twice.**
   - The `window_below_latency` payout was first mined in minimum-difficulty block
     161,776 (`000000006b0ffa9b…`). A sibling block at the same height replaced it, and
     the payout was mined again there (`000000000013f45d…`) with the other two payouts.
   - The rows ended on that block. Real-difficulty block 161,778 (`0000000000000000dc97…`)
     then extended a third branch and mined all three payouts again.
   - The audit's chain re-check notes each move. No outcome changed: on every branch,
     the payout was the transaction that spent the claim output.

## Wave 4: seeds, polarity, the bond and the garbling

[`examples/testnet4/wave4.json`](../examples/testnet4/wave4.json), broadcast on
2026-11-16 and 17:
- **Rows:** four mutant attacks:
  - a griefing disprove built from reused garbling seeds;
  - a disprove that the swapped output polarity refuses;
  - the bond self-slash replacement under full RBF;
  - a claim on a garbling nobody checked.
- **Funding:** the 12,334 sats left after wave 3, all eight coins, split into four coins
  (2,300 sats, and 3,300 for the bond row) in `1fc480a6…`. It was recorded in 161,784 and
  now sits in 161,786 (below).
- **Run:** the tip went from 161,783 to 161,799 between 23:35 UTC on the 16th and 01:05
  UTC on the 17th.
- **Transactions:** 8 confirmed, 3 refused by mempool policy, and 1 displaced. None was
  dropped or left unconfirmed.
  - The displaced one is the watcher's disprove in `bond_self_slash`. The claimant's
    self-slash disprove replaced it, as the recipe intends.
  - Four were reorged during their rows: all four claims (below).
  - None had to be sent again.
- **Expectations:** 4 of 4 met. Every attack landed, and every transaction step matched
  the regtest catalog.
- **Audit:**
  - offline, clean;
  - against the node's best chain, valid;
  - one note: the split.
- **Cost:** 4,275 sats of fees, of which 826 were for the eight-input split, so about 860
  per row. Nothing was left in contract outputs. The wallet holds 8,059 sats in six coins.

| Row (mutant attack) | What testnet4 did |
| --- | --- |
| `seed_reuse_across_claims` | honest claim 161,790; griefing disprove, carrying the reject label that the leaked Delta yields, 161,791; honest payout refused `missing-inputs` |
| `output_polarity_swapped` | false claim 161,790; the watcher's disprove refused (`OP_EQUALVERIFY` failed); false claim paid 161,797 |
| `bond_self_slash` | false claim 161,790; the watcher's disprove accepted, then replaced in the mempool by the claimant's self-slash disprove, mined 161,791; payout refused `missing-inputs` |
| `garbling_unchecked` | false claim 161,790; nothing could disprove it; paid 161,797 |

What the public network showed:

1. **Full-RBF replacement of a disprove reaches testnet4 miners.** The watcher's disprove
   of `bond_self_slash` was in the mempool first. The claimant's self-slash disprove
   spent the same claim output at a higher fee, replaced it, and was mined in 161,791.
   The bond went back to the claimant. A mutant bond that whoever disproves can take
   deters nothing: the garbler knows the reject label and can always outbid the watcher.
2. **A sibling block took all four claims.**
   - The claims were first mined in minimum-difficulty block 161,790
     (`0000000061f22a97…`).
   - A sibling minimum-difficulty block at the same height (`0000000000213be0…`), on the
     branch the next blocks built on, replaced it and mined all four claims again.
   - The replacement was at the same height, so no timelock count changed. The two
     payouts came at 161,797, seven blocks after their claims.
3. **The split moved, and the re-check now sees it.**
   - The split was recorded in minimum-difficulty block 161,784 (`00000000000f4602…`).
     Real-difficulty block 161,786 replaced the branch and mined it again.
   - Until wave 4 the audit's chain re-check covered only the steps of each case. Run
     against waves 1–3 after the change, it found two more moves the reports did not
     note: the wave 3 split, and a wave 1 vault funding (above).
4. **Most blocks still carry nothing.** Of the 17 blocks from 161,783 to 161,799, three
   were real-difficulty blocks (161,786, 161,793, 161,797), and 8 held only their coinbase.

## Wave 5: the cut-and-choose and the late tables

[`examples/testnet4/wave5.json`](../examples/testnet4/wave5.json), broadcast on
2026-11-17:
- **Rows:**
  - the last two mutant attacks: a ground Fiat-Shamir cut-and-choose, and garbled tables
    handed over at claim time;
  - the hardened cut-and-choose against the same grinding attack.
- **Funding:** the 8,059 sats left after wave 4, all six coins, split into three
  2,300-sat coins and 524 sats of change in `128e8e26…` (minimum-difficulty block
  161,844). It has not moved. The three vault fundings are in real-difficulty block
  161,845.
- **Run:** the tip went from 161,843 to 161,857 between 07:35 and 08:58 UTC.
- **Transactions:** 4 confirmed, 1 refused by mempool policy. None was displaced,
  dropped or left unconfirmed.
  - Two were reorged during their rows: both claims (below).
  - None had to be sent again.
- **Expectations:** 3 of 3 met, and every transaction step matched the regtest catalog.
- **Audit:**
  - offline, clean;
  - against the node's best chain, valid, with no notes.
- **Cost:** 2,493 sats of fees: 635 for the six-input split, 300 per vault funding, and
  479 for each claim and payout. That is about 830 per row with the split.
- **Locked:** the hardened row's vault, 2,000 sats in `ac3e3358…:0`, stays where it is
  until the desk's 144-block reclaim. That reclaim can first be mined in block 161,989,
  144 blocks after the funding block, and `testnet4 recover` sends it (below). The wallet
  holds 3,566 sats in three coins.

| Row | What testnet4 did |
| --- | --- |
| `cut_and_choose_grindable` (mutant attack) | three grinding attempts made the hash challenge keep the swapped instance 0; the three opened instances checked out and the desk presigned; false claim 161,851; the watcher's evaluation decoded to accept, so nothing disproved it; paid 161,857 |
| `tables_delivered_late` (mutant attack) | false claim 161,851; the claimant handed over tables committing to `58a33b0e…`, not the registered `ac7a6cce…`; the watcher's evaluation yielded neither label, so it had nothing to disprove with; paid 161,857 |
| `cut_and_choose_grindable` (hardened attack) | the challenge, drawn after the commitments, kept instance 2 and opened the swapped instance 0, whose check failed; the desk did not presign; the claim was refused (`Invalid Schnorr signature`) and the vault stayed unspent |

What the public network showed:

1. **The cut-and-choose fix holds on public relay policy.** No signature from the desk
   meant no spendable claim, and every testnet4 node the claim reached refused it. In
   the mutant case the claimant chose which instance survived the cut at no cost, and
   the desk presigned a garbling the watcher could not use. Three hash attempts were
   enough with four instances.
2. **Again a sibling block took the claims.**
   - Both claims were first mined in minimum-difficulty block 161,851
     (`00000000001ea46f…`, 21 transactions).
   - A sibling at the same height and with the same timestamp (`0000000048a08787…`,
     the coinbase and the two claims) replaced it.
   - As in wave 4, the replacement was at the same height, so no timelock count changed.
     The payouts came six blocks later, at 161,857.
3. **Block timestamps are no clock.**
   - Block 161,857 is stamped 10:58 UTC, about two hours after the run saw it at 08:58.
     Two hours is the furthest ahead a node accepts.
   - Real-difficulty block 161,853 is stamped 63 minutes before its parent.
   - The claim graph counts heights only, so none of this changed a row.
4. **Two real-difficulty blocks in 15.** They were 161,845 and 161,853. Eight of the 15
   blocks from 161,843 to 161,857 held only their coinbase.

## Wave 6: the hardened seeds and tables

[`examples/testnet4/wave6.json`](../examples/testnet4/wave6.json), broadcast on
2026-11-17:
- **Rows:** the hardened halves of two pairs whose mutant attacks landed in waves 4 and 5:
  - a fresh garbling seed per claim, against the watcher that derives Delta from two
    claims' labels;
  - garbled tables delivered and checked at setup, against the claimant that hands over
    other tables at claim time.
- **Funding:** the 5,087 sats in the wallet, all four coins (wave 5's three and the 1,521
  recovered from wave 1), split into two 2,300-sat coins in `561a28e6…` (real-difficulty
  block 161,860). The leftover was below the dust limit, so the wallet added it to the fee
  and made no change output. The split has not moved.
- **Run:** the tip went from 161,859 to 161,873 between 09:39 and 11:04 UTC.
- **Transactions:** 4 confirmed, 2 refused by mempool policy. None was displaced, dropped
  or left unconfirmed.
  - Three were reorged during their rows: both claims and the disprove (below).
  - None had to be sent again.
- **Expectations:** 2 of 2 met, and every transaction step matched the regtest catalog.
- **Audit:**
  - offline, clean;
  - against the node's best chain, valid, with one note per row: both vault fundings
    moved to another block at height 161,865 after they were recorded.
- **Cost:** 2,045 sats of fees: 487 for the four-input split, 300 per vault funding, 229
  per claim, and 250 for the payout and for the disprove. That is about 1,020 per row
  with the split.
- **Locked:** nothing. Both rows returned 1,521 sats to the wallet, which holds 3,042 sats
  in two coins.

| Row | What testnet4 did |
| --- | --- |
| `seed_reuse_across_claims` (hardened attack) | honest claim 161,866; the watcher took the labels of an earlier claim garbled from an independent seed and tried 32 candidates for the reject label; none matched, so the griefing disprove failed its hashlock (`OP_EQUALVERIFY`) and was refused; paid 161,873 |
| `tables_delivered_late` (hardened attack) | false claim 161,866; the claimant handed over tables committing to `8f884c5b…`, not the registered `f832397f…`; the watcher evaluated the tables checked at setup, got the reject label and disproved, 161,868; the claimant's payout was refused (`missing-inputs`) |

What the public network showed:

1. **Both fixes hold on testnet4.**
   - With one seed per claim, an earlier claim's labels say nothing about this claim's
     Delta. The griefing disprove that took the honest claim in wave 4 now fails its
     script.
   - With the tables fixed at setup, tables handed over late do not matter: the watcher
     never evaluates them.
2. **Three blocks in a row with wave transactions were replaced.**
   - The vault fundings were first mined in minimum-difficulty block 161,865
     (`00000000004968…`, 37 transactions). A sibling at the same height
     (`0000000001672991…`, 38 transactions) replaced it. The audit's chain re-check is
     what noticed: the report records the block a funding was in when its case started.
   - On the new 161,865, both claims went into 161,866 (`000000000065a2b8…`, 61
     transactions) and the disprove into 161,867 (`000000005b8fbfcc…`, 5 transactions).
   - A three-block branch with more work replaced those two: 161,866 (`0000000044b2b693…`,
     the coinbase and the two claims), a coinbase-only 161,867, and real-difficulty
     161,868, which holds the disprove.
   - The claims stayed at height 161,866, so the payout window counted the same blocks.
     Every transaction came back in the new blocks without a resend.
   - At 161,873 the node knew nine other chain tips from height 161,859 up.
3. **Real-difficulty block 161,868 is stamped 79 minutes before its parent.** The
   minimum-difficulty blocks around it are stamped 20 minutes apart and up to two hours
   ahead.
4. **Two real-difficulty blocks in 15.** They were 161,860 and 161,868. Seven of the 15
   blocks from 161,859 to 161,873 held only their coinbase.

## Wave 7: the hardened payout

[`examples/testnet4/wave7.json`](../examples/testnet4/wave7.json), broadcast on
2026-11-17:
- **Row:** the hardened payout, presigned with its outputs committed, against the relayer
  that redirects the presigned payout. Its mutant half landed in wave 3.
- **Funding:** the 3,042 sats in the wallet, both coins, split into one 2,300-sat coin and
  487 sats of change in `39fd067d…`. The split was first mined in minimum-difficulty
  block 161,881 and is now in real-difficulty block 161,882 (below).
- **Run:** the tip went from 161,880 to 161,895 between 11:14 and 12:56 UTC.
- **Transactions:** 2 confirmed, 1 refused by mempool policy. None was displaced, dropped,
  reorged during its row or left unconfirmed, and none had to be sent again.
- **Expectations:** 1 of 1 met, and every transaction step matched the regtest catalog.
- **Audit:**
  - offline, clean;
  - against the node's best chain, valid, with one note: the split moved to another block
    after it was recorded.
- **Cost:** 1,034 sats of fees: 255 for the split, 300 for the vault funding, 229 for the
  claim and 250 for the payout.
- **Locked:** nothing. The payout returned 1,521 sats, and the wallet holds 2,008 sats in
  two coins.

| Row | What testnet4 did |
| --- | --- |
| `payout_sighash_none` (hardened attack) | honest claim 161,885; the relayer's payout redirected to its own key was refused (`Invalid Schnorr signature`), because the presignature commits to the claimant's output; the claimant's payout 161,895 |

What the public network showed:

1. **The fix holds on testnet4.** A presignature over the outputs leaves a relayer nothing
   to rewrite. In wave 3 the mutant's `SIGHASH_NONE` payout went to the relayer.
2. **The split's own block was replaced.**
   - The split was mined in minimum-difficulty block 161,881 (`0000000001d5e3ea…`, 15
     transactions). The run then sent the vault funding, which spends it.
   - A coinbase-only sibling (`00000000caba2d71…`) replaced 161,881. That put the split
     and the funding back in the mempool together.
   - Real-difficulty block 161,882 mined both. Nothing was sent again, and the funding
     reached its depth before the claim went out.
   - The report's funding record still names the first block. The audit's chain re-check
     is what shows the move.
3. **Three real-difficulty blocks in 16.** They were 161,882, 161,886 and 161,891. Nine of
   the 16 blocks from 161,880 to 161,895 held only their coinbase. At 161,895 the node
   knew thirteen other chain tips from height 161,880 up.

## Wave 8: the benign rows and the last two hardened attacks

[`examples/testnet4/wave8.json`](../examples/testnet4/wave8.json), broadcast on
2026-11-24:
- **Rows:** the 41 left after wave 7:
  - the benign row of all 21 recipes under the mutant profile: an honest claim with nobody
    attacking it, which must be paid;
  - the 18 hardened benign rows that wave 1 did not run;
  - the last two hardened attacks, `garbling_unchecked` and `claim_sighash_none`.
- **Funding:** the wallet held 3,758 sats after wave 7 and wave 5's reclaim, so it received
  102,000 sats from another testnet4 wallet (`30665f6f…`). The split `5e74e9fe…` spent
  that and one 1,521-sat coin. It made 41 coins (36 of 2,300 sats, and 3,300 or 3,800 for
  the five bonded rows) plus 902 sats of change, and it is in minimum-difficulty block
  163,102.
- **Run:** the tip went from 163,100 to 163,126 between 06:58 and 10:45 UTC.
- **Transactions:** 80 confirmed, 3 refused by mempool policy. None was displaced, dropped,
  reorged during its row or left unconfirmed, and none had to be sent again.
- **Expectations:** 41 of 41 met, and every transaction step matched the regtest catalog.
- **Audit:**
  - offline, clean;
  - against the node's best chain, valid, with one note per row: all 41 vault fundings
    moved from block 163,106 to 163,105 after they were recorded (below).
- **Cost:** 34,029 sats of fees:
  - 2,319 for the split;
  - 300 per vault funding (12,300);
  - 9,410 for the 40 claims (229 to 312 sats each);
  - 250 per payout (9,750) and 250 for the disprove.

  That is about 830 per row with the split.
- **Locked:** the `garbling_unchecked` hardened vault (`d47ac670…:0`, 2,000 sats), as a
  refused claim leaves it. The desk's reclaim opens at block 163,249. The wallet holds
  69,729 sats in 45 coins.

| Row | What testnet4 did |
| --- | --- |
| `garbling_unchecked` (hardened attack) | the claimant registered a garbling whose output decoding is swapped; the desk's cut-and-choose caught it at setup and the desk withheld its presignature, so the claim was refused (`Invalid Schnorr signature`); the vault waits for the desk's reclaim |
| `claim_sighash_none` (hardened attack) | the claimant reused the desk's presignature with the outputs replaced, paying the vault to itself; refused (`Invalid Schnorr signature`), because the hardened presignature commits to the outputs; the canonical false claim 163,107; the watcher disproved it, 163,114; the claimant's payout was refused (`missing-inputs`) |
| the 39 benign rows | every claim in real-difficulty block 163,107 and every payout in real-difficulty block 163,122 |

What the public network showed:

1. **The last two fixes hold, and the catalog is complete.**
   - Every one of the 84 testnet4 rows has now run on the public network and met its
     expectation. Wave 1's reorg-lost row met it in wave 2.
   - In wave 4 the mutant `garbling_unchecked` claim was paid. Under the hardened profile
     the desk never presigns it.
   - In wave 3 the mutant `claim_sighash_none` rewrite took the vault. The hardened
     presignature leaves nothing to rewrite.
   - Every benign row paid its honest claim under both profiles, so none of the fixes stops
     an honest claimant.
2. **Two minimum-difficulty branches traded the lead.**
   - The top-up was first mined in 163,100 (`0000000000457e55…`), the tip when the wave
     started. A branch from 163,097 replaced the four blocks up to it. The top-up is now
     in 163,101 (`000000003878e08d…`).
   - Wave 5's reclaim moved with it: it was first in 163,099 (`000000000313c386…`) and is
     now in 163,100 (`000000004532497a…`).
   - The 41 vault fundings were recorded in 163,106 (`000000004628d502…`, 82
     transactions), the top of an eight-block branch from 163,099. The other branch, now
     the best chain, holds them in 163,105 (`0000000000a15c46…`, 89 transactions). The
     split is in both branches, and the report's block for it, 163,102
     (`000000008b4a8fb3…`), is still in the best chain.
   - Real-difficulty block 163,107 built on that other branch and mined all 40 claims.
     The move left the fundings one block deeper, nothing had to be sent again, and only
     the audit's chain re-check shows it.
   - At 163,126 the node knew fourteen other chain tips from height 163,100 up.
3. **Every claim and every payout landed in a real-difficulty block.**
   - All 40 claims went out at 163,106 and confirmed in 163,107, the disprove in 163,114,
     and all 39 payouts in 163,122 (190 transactions).
   - The payouts went out at 163,117 and 163,119 and waited through coinbase-only blocks.
     Every minimum-difficulty block from 163,108 to 163,113 and from 163,115 to 163,121
     held only its coinbase.
   - 163,107 is stamped 97 minutes before its parent, and 163,122 81 minutes before its
     parent.
4. **Three real-difficulty blocks in 27.** They were 163,107, 163,114 and 163,122. Sixteen
   of the 27 blocks from 163,100 to 163,126 held only their coinbase.

## Recovering what a wave leaves

A row can end with coins still in a contract output:
- a vault that no claim spent, as when the desk refused to presign a claim;
- a claim output that nobody paid out, as with wave 1's reorg-lost row.

`testnet4 recover` lists every such output of a report.
- **How it builds the spends:** it rebuilds each case's graphs from the wave's
  `stage.json` and pairs each output with the spend that returns it to the wallet:
  - a vault goes back through the desk's 144-block reclaim;
  - a claim output goes out through the presigned payout, once its window has passed.
- **Burned bonds:** a bond paid to the NUMS key is listed as burned. Nobody can spend it,
  and the hardened `bond_self_slash` profile intends that.
- **Checks:** every spend whose timelock has passed is checked with `testmempoolaccept`.
- **Broadcast:** only with `--broadcast`.

Recovered so far, and what is still waiting:

| Wave | Output | Spend | Result |
| --- | --- | --- | --- |
| 1 | `reclaim_preempts_claim` claim output `4bfcefd1…:0`, 1,771 sats | presigned payout `b81cec35…` | 1,521 back to the wallet, block 161,859 |
| 1 | `bond_self_slash` bond `6560a185…:1`, 1,000 sats | none | burned to the NUMS key |
| 5 | `cut_and_choose_grindable` hardened vault `ac3e3358…:0`, 2,000 sats | desk reclaim `cdee3580…` | sent 2026-11-24, 1,750 back to the wallet; first mined in block 163,099, which a branch replaced; now in 163,100 |
| 8 | `garbling_unchecked` hardened vault `d47ac670…:0`, 2,000 sats | desk reclaim `30b19e7d…` | opens at block 163,249; 1,750 back to the wallet |
| iob1 | `garbling_unchecked` vault `4a039c43…:0`, 2,000 sats | desk reclaim `5811f0bd…` | opens at block 163,294; 1,750 back to the wallet |
| iob1 | `cut_and_choose_grindable` vault `019617ce…:0`, 2,000 sats | desk reclaim `83e1b706…` | opens at block 163,294; 1,750 back to the wallet |
| iob1 | 15 bonds, 1,000 sats each | none | burned to the NUMS key |

The wave 1 payout has the same txid as the payout testnet4 refused as `non-BIP68-final`
during wave 1. The rebuilt graph is byte for byte the one the row signed.

## The IOB-hardened design

The second staging track, `bitvm3-iob-testnet4`, stages the `bitvm3-iob` rows: one design
with every hardened fix at once ([BITVM3.md](BITVM3.md#the-iob-graph-with-every-fix-bitvm3-iob)).
Its catalog is the regtest track's, renamed, without the three regtest-only recipes: 21
recipes, 42 rows. A wave runs the rows of one track, and each report records its track and
that track's catalog hash, so the reports of the first track audit unchanged.

Wave `iob1` holds the 21 attacks and the honest claim:
- **Coins:** every row is bonded, so each coin carries the 2,000-sat vault and the 1,000-sat
  bond. That is 22 coins of 3,300 sats, two for the replay attack's two vaults, plus 4,800
  for `disprove_unbumpable`, which also funds the watcher's fee coin: 77,400 sats and the
  split.
- **Cost:** on regtest, 15 of these attacks burn the claimant's bond: 15,000 sats on
  testnet4, on top of the fees. The two refused claims leave their vaults for the desk's
  144-block reclaim.
- **Rehearsal** with `--reorg-every 3`: 22 of 22 met. 42 transactions confirmed and 29
  were refused, and 18 went through one of 12 reorgs, none sent again. Every transaction step
  matches the regtest run, and the report audits clean.
- **Testnet4:** 22 of 22 met on 2026-11-24, every row step for step as on regtest (below).

### Wave `iob1` on testnet4

- **Funding:** the wallet held 3,758 sats, so it received 76,000 from another testnet4
  wallet (`6d8543e8…`, real-difficulty block 163,143). The split `67857223…` spent that and
  two coins of 1,750 and 1,521 sats. It made the 23 coins plus 411 sats of change.
  - It was recorded in minimum-difficulty block 163,148 (`000000007f32d962…`).
  - A sibling at the same height (`00000000add1c570…`) replaced that block, and it holds
    the split too.
- **Run:** 14:12 to 18:59 UTC, while the tip went from 163,148 to 163,184.
- **Transactions:** 42 confirmed, 29 refused by mempool policy, the rehearsal's counts.
  None was displaced, dropped, reorged during its row or left unconfirmed, and none had to
  be sent again.
- **Expectations:** 22 of 22 met. Every row took the same transaction steps as on regtest
  ([`bitvm3-iob-core31.1.json`](../examples/native/bitvm3-iob-core31.1.json)): the same
  verdicts, the same reject reasons and the same outcome.
- **Audit:** offline, clean. Against the node's best chain it is valid, with one note: the
  split moved to the sibling block.
- **Cost:** 37,550 sats of fees, about 1,710 per row:
  - 1,460 for the split;
  - 300 per vault funding (6,900 for 23);
  - 23,940 for the 21 claims, 1,140 sats each;
  - 250 per disprove (3,750 for 15) and per payout (1,500 for 6).

  On top of the fees, 15 bonds were burned: 15,000 sats to the NUMS key, the same 15 attacks
  that burn their bond on regtest.
- **Locked:** the vaults of the two refused claims, 2,000 sats each:
  - `garbling_unchecked` (`4a039c43…:0`);
  - `cut_and_choose_grindable` (`019617ce…:0`).

  The desk's reclaims open at block 163,294. The bonds of those two rows were never spent
  and are back in the wallet, which holds 23,208 sats in 26 coins.

| Row (IOB-hardened) | What testnet4 did |
| --- | --- |
| `labels_offchain_withheld`, `output_polarity_swapped`, `claimant_unbonded`, `tables_delivered_late`, `disprove_unbumpable` attacks | claim 163,155; the watcher's disprove 163,158, burning the bond; payout refused `missing-inputs` |
| `single_watcher_disprove` attack | claim 163,155; the watcher was offline, and another holder of the reject label disproved, 163,158, burning the bond; payout refused |
| `claim_internal_key_spendable`, `claim_sighash_none`, `disprove_outputs_unbound`, `bond_self_slash` attacks | the claimant's own transaction (key-path sweep, rewritten claim, self-paying disprove, self-slash) refused `Invalid Schnorr signature`; claim 163,155; the watcher's disprove 163,158, burning the bond; payout refused |
| `disprove_watcher_redirect` attack | claim 163,155; the watcher's disprove paying itself refused `Invalid Schnorr signature`; another holder of the reject label disproved, 163,158, burning the bond; payout refused |
| `payout_csv_removed`, `payout_absolute_timelock` attacks | early payout refused `non-BIP68-final`; claim 163,155; disprove 163,158, burning the bond; payout refused |
| `window_below_latency` attack | claim 163,155; the watcher's evaluation took 5 blocks; the early payout at 163,164 refused `non-BIP68-final`; disprove 163,167, 12 blocks after the claim and inside the 24-block window; payout refused |
| `proof_replay_across_vaults` attack | both claims 163,158; the replayed claim disproven 163,159, its bond burned; first payout 163,184; second refused `missing-inputs` |
| `garbling_unchecked`, `cut_and_choose_grindable` attacks | the desk's setup check failed and it did not presign; claim refused `Invalid Schnorr signature`; the vault waits for the reclaim |
| `seed_reuse_across_claims` attack | honest claim 163,155; griefing disprove refused (`OP_EQUALVERIFY` failed); payout 163,184 |
| `payout_sighash_none`, `desk_key_retained` attacks | honest claim 163,155; the redirected payout and the desk's lone payout refused `Invalid Schnorr signature`; the cosigned payout 163,184 |
| `reclaim_preempts_claim` attack | the desk's early reclaim refused `non-BIP68-final` at 163,156; claim 163,158; payout 163,184 |
| `labels_offchain_withheld` benign | claim 163,155; payout 163,184 |

What the public network showed:

1. **Every fix at once holds, step for step.**
   - No attack landed, and every honest claim was paid (six, counting the replay's first
     claim).
   - Every row did on the public network what it did on regtest. That includes
     `disprove_unbumpable`, whose single-fix row needs a zero-fee disprove and a fee
     child: here the disprove paid its own fee and confirmed in 163,158.
2. **An attack now costs the attacker.**
   - 15 of the 21 attacks burned the claimant's 1,000-sat bond, the replay's second claim
     included.
   - The single-fix rows on testnet4 burned one bond in all, wave 1's `bond_self_slash`.
     Only the two rows about the bond put one at stake there.
3. **The labels on chain are what the design pays for.**
   - Every IOB claim carries the input labels and spends the bond: 1,036 vB, 1,140 sats at
     1.1 sat/vB.
   - A single-fix hardened claim was 208 vB (229 sats), 283 vB with the bond, and 961 vB
     with the labels (wave 1's `labels_offchain_withheld` rows).
   - The claims are 64% of the wave's fees. Fees per row went from about 830 in wave 8 to
     about 1,710.
4. **The chain.**
   - The top-up (163,143), 22 of the 23 vault fundings (163,150) and all six payouts
     (163,184) landed in real-difficulty blocks.
   - The claims, disproves and the replay's second funding landed in minimum-difficulty
     blocks. 163,155 held 18 claims among 163 transactions.
   - 6 of the 37 blocks from 163,148 to 163,184 were real difficulty.
   - At 163,186 the node knew 27 other chain tips from height 163,142 up. The split was the
     only wave transaction that moved.

## Running a wave

```bash
python -m bitvm_corpus testnet4 rehearse --wave wave1 --reorg-every 3 --output rehearsal.json
python -m bitvm_corpus testnet4 run --wave wave1 --rpc-port 48332 --cookie <datadir>/testnet4/.cookie \
    --wallet bitvm-arena-staging --state <outside the repo>/wave1 --broadcast --output examples/testnet4/wave1.json
python -m bitvm_corpus testnet4 audit examples/testnet4/wave1.json [--rpc-port 48332 --cookie ...]
python -m bitvm_corpus testnet4 recover examples/testnet4/wave1.json --state <outside the repo>/wave1 \
    --rpc-port 48332 --cookie <datadir>/testnet4/.cookie --wallet bitvm-arena-staging [--broadcast]
```

With `--rpc-port`, `audit` also re-checks the split, every vault funding and every
confirmed transaction against a testnet4 node's current best chain: each must still be in
the chain, with the same bytes. A reorg into
another block is noted, not failed. A report records the block each transaction was in
when its case ended. On testnet4 that block can still be replaced, which is why the
re-check exists.
