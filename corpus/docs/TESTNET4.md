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
| Blocks | `generatetoaddress`, includes the whole mempool | waits for the network's blocks, and for every transaction the case broadcast to confirm or be displaced (18 blocks of patience) |
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

## Running a wave

```bash
python -m bitvm_corpus testnet4 rehearse --wave wave1 --output rehearsal.json
python -m bitvm_corpus testnet4 run --wave wave1 --rpc-port 48332 --cookie <datadir>/testnet4/.cookie \
    --wallet bitvm-arena-staging --state <outside the repo>/wave1 --broadcast --output examples/testnet4/wave1.json
python -m bitvm_corpus testnet4 audit examples/testnet4/wave1.json [--rpc-port 48332 --cookie ...]
```

With `--rpc-port`, `audit` also re-checks every confirmed transaction against a testnet4
node's current best chain: it must still be in the chain, with the same bytes. A reorg into
another block is noted, not failed.
