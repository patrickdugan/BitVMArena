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
  - two payouts the report records in block 161,710 now sit in 161,712.

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

## Running a wave

```bash
python -m bitvm_corpus testnet4 rehearse --wave wave1 --reorg-every 3 --output rehearsal.json
python -m bitvm_corpus testnet4 run --wave wave1 --rpc-port 48332 --cookie <datadir>/testnet4/.cookie \
    --wallet bitvm-arena-staging --state <outside the repo>/wave1 --broadcast --output examples/testnet4/wave1.json
python -m bitvm_corpus testnet4 audit examples/testnet4/wave1.json [--rpc-port 48332 --cookie ...]
```

With `--rpc-port`, `audit` also re-checks every confirmed transaction against a testnet4
node's current best chain: it must still be in the chain, with the same bytes. A reorg into
another block is noted, not failed. A report records the block each transaction was in
when its case ended. On testnet4 that block can still be replaced, which is why the
re-check exists.
