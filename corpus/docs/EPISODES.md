# Interactive BitVM3 episodes

The BitVM3 catalog (`docs/BITVM3.md`) replays fixed trajectories. An episode lets a red
team attack a BitVM3-dependent application design directly. One attacker drives the
claimant of one application preset through a closed set of JSON actions on an owned
Bitcoin Core regtest node. Core judges every transaction. Honest parties react by fixed
rules, and a scorer reads only confirmed transactions.

## What an episode is

* The attacker is the **claimant**. It is also the garbler, so it knows every label,
  including the reject label (`garbler_view`).
* The setup is deterministic from `(app, config, tag)`: `prepare` garbles the statement
  circuit (seed from the row id `bitvm3.episode.<app>.<tag>`), the desk presigns, and
  the vault (plus bond, plus the watcher's fee coin under `zero_anchor`) is funded on
  chain. For `payout_timelock == "cltv"` the absolute height is setup height + window.
* The attacker holds the claimant key only. Desk and watcher signatures exist only as
  presigned witnesses the `Graph` builds. A spend that needs a key the claimant does not
  hold returns an error result.
* With `--miner` the attacker may also build blocks (`mine`), up to `censorship_blocks`
  in a row; after that, honest blocks (`wait`) must come first. Without that bound a miner
  holding every block would beat any window, so the bound is the censorship assumption
  under test.

## Presets

`native apps` prints them. Override any `Config` field or assumption with
`--config '{"window": 3, "watcher_latency": 0}'`. Unknown keys, wrong types and an
invalid `Config` are rejected.

| app | config | assumptions |
|---|---|---|
| `iob-payout-desk` | `Config()` defaults: watcher-signed disprove, labels off-chain, window 6, no bond | watcher online, latency 1, desk online, censorship 8 |
| `bridge-pegout` | `bond`, `bond_burn`, `disprove_mode=presigned`, `labels_onchain`, `window=HARDENED_WINDOW` (24), `cut_and_choose=interactive` | watcher online, latency 1, desk online, censorship 8 |
| `lending-liquidation` | `disprove_mode=presigned`, `disprove_fee=zero_anchor`, `window=12` | watcher online, latency 1, desk offline, censorship 8 |

Assumptions: `watcher_online` (bool), `watcher_latency` (blocks, 0 to 100),
`desk_online` (bool) and `censorship_blocks` (consecutive miner blocks, 0 to 500).

`native assess --app NAME` runs the static design check of
[BITVM3.md](BITVM3.md#assessing-a-design) on a preset plus overrides, to pick which
attacks to try first. The desk is passive in every preset; `desk_online` records the
assumption and changes nothing the honest parties do.

## Actions

One JSON object per line: `{"op": ..., "args": {...}}`. Limits: 200 actions (invalid ones
count), 500 mined blocks. A bad action returns `{"ok": false, "error": ...}` and the
episode continues.

| op | args | effect |
|---|---|---|
| `observe` | none | the public observation |
| `garbler_view` | `proof?: [a, b]` | accept and reject labels, and the input labels for a proof |
| `claim` | `proof: [a, b]`, `labels: "handover"\|"withhold"`, `tables?: "honest"\|"corrupt"`, `outputs?` | submit the claim. `handover` gives the watcher the input labels off-chain; `withhold` does not (when `labels_onchain` they are in the claim witness anyway). `tables: "corrupt"` hands a corrupted copy of the garbled tables, which the watcher uses only when `tables_at == "claim"`. `outputs` rewrites the claim outputs and keeps the desk presignature; Core decides whether that is valid |
| `spend` | `utxo: "claim"\|"vault"\|"bond"`, `path: "payout"\|"disprove"\|"key"\|"reclaim"`, `outputs?`, `label?`, `fee?` | build the canonical presigned transaction through `Graph`, apply an output rewrite, submit. `claim`+`payout`, `claim`+`disprove` (`label` is `reject`, `accept` or hex; needs a presigned or hashlock disprove, since the claimant lacks the watcher key), `claim`+`key` (a key-path sweep signed as if the claimant were the internal key), `bond`+`key` (take the bond back). `vault` paths need the desk or an unknown key and return an error result |
| `broadcast` | `hex` | a custom raw transaction; prevout amounts and scripts are looked up through RPC and recorded |
| `wait` | `blocks` | honest mining, one block at a time; honest parties act after each block |
| `mine` | `include: "none"\|[txid or "@label", ...]` | miner capability only: an empty block, or a block holding exactly the listed transactions of this episode. `"@claim:payout"` names the latest transaction built under that label, so scripts need no txids. Counts toward `censorship_blocks` |
| `end` | none | finish |

Destinations (`dest`): `claimant` (the claimant bond-tree script), `payout`, `refund`,
`relayer`, `watch`, `burn`, or a raw scriptPubKey in hex (at most 100 bytes). Outputs are
`[sats, dest]` pairs, at most 16.

## Honest parties

After every action and every block the watcher (if online) acts once. It waits until the
claim has confirmed and `watcher_latency` further blocks have passed. It then takes the
labels (the handover, or the claim witness when `labels_onchain`) and evaluates the
garbling once. It uses its setup copy of the tables unless `tables_at == "claim"`, in
which case it uses what the claimant handed over. On a reject verdict with the claim
output unspent it disproves exactly as `run_case` does: its own signature or the desk's
presignature, a refund beneficiary under `hashlock`, a P2A package with `anchor_child`
under `zero_anchor`. It never disproves twice. The desk and everyone else stay passive.
`end` mines a final block to confirm the mempool; honest parties do not act after it.

## Scoring

From confirmed transactions only (deduplicated by txid), never from action labels:

* `honest`: the proof of the confirmed claim (else the last attempted claim) sums to the
  statement. No claim at all counts as not honest.
* `nets`: net sats (outputs minus spent prevouts) per party: `claimant` (its bond-tree
  script and payout script), `refund`, `burn`, `watch`, `relayer`, `other` (every
  other script) and `protocol` (the vault, claim and anchor scripts).
* `attack_success`: not honest and the claimant net is positive; or a transaction
  spending the vault or claim output paid any value to `relayer` or `other`
  (`vault_value_to_outsiders`); or the app is bonded, the claim is not honest, a claim
  confirmed, and the claimant lost less than `BOND // 2`. A claimant moving its own bond
  to a fresh address is not an attack.
* `honest_claim_paid`: honest and the payout script received at least `VAULT - 2*FEE`.
* Also reported: `claim_confirmed`, `claimant_loss`, `sats_burned`, `fees`,
  `blocks_elapsed` (blocks mined by actions, excluding the final one).

## Reports and audit

`native episode` writes one JSONL line per action to stdout (the first is the initial
observation, the last is the outcome) and, with `--output`, the report:
`schema_version`, `kind` (`bitvm3-episode`), `app`, `tag`, `overrides`, `config`,
`assumptions`, `attacker`, `capabilities`, `provenance`, `actions`, `steps`, `outcome`,
`evidence_hash` (the digest of everything else).

`native audit FILE` accepts episode reports. It checks the evidence hash, the app,
overrides and config; runs the local signature and commitment checks on every
transaction; rebuilds the setup from `(app, config, tag)` and compares the setup record,
the funded vault script and the claim outputs; checks that labels match the claimed
proof; re-runs every recorded garbled evaluation; rejects miner actions without the
capability and runs of miner blocks longer than `censorship_blocks`; and rescores from
the steps.

## Limits

* One claim graph and one vault. The attacker is the claimant, optionally colluding with a
  miner (`--miner`). The desk, the watcher and a relayer cannot be played.
* The garbling is the toy 16-bit adder circuit, and evaluation latency is a block count.
* The attacker cannot reorder, replace or fork blocks beyond what `mine` allows; there
  are no reorgs.
* The setup is public and deterministic per `(app, tag)`; `--tag` (default `1`) changes the
  garbling seed.
* Audit proves the report is consistent with Core's recorded answers and the rebuilt
  graph; it does not re-run Core.

## Examples

`examples/episodes/*.jsonl` are attacker scripts; `examples/episodes/reports/` holds the
11 reports they produced on Core 31.1, each audited clean.
`tools/rebuild_episode_reports.py --bitcoind PATH` reruns all of them; CI does the same on
Linux Core.

| Report | App (overrides) | Attack | Why |
|---|---|---|---|
| `honest-*` (3) | each preset | no; honest claim paid | the payout matures after the window |
| `false-claim-withheld-iob-payout-desk` | `iob-payout-desk` | **yes** | labels withheld, nobody can evaluate (T2) |
| `false-claim-withheld-bridge-pegout` | `bridge-pegout` | no | labels are in the claim witness; disproven, bond burned |
| `false-claim-lending-liquidation` | `lending-liquidation` | no | the watcher bumps the zero-fee disprove through the P2A package |
| `keypath-sweep-bridge-pegout` | `bridge-pegout` | no | NUMS internal key: `Invalid Schnorr signature` |
| `keypath-sweep-bridge-pegout-claimant-internal` | `bridge-pegout` (`claim_internal: claimant`) | **yes** | the claimant sweeps the claim output through the key path |
| `self-disprove-hashlock-iob-payout-desk` | `iob-payout-desk` (`disprove_mode: hashlock`) | **yes** | the garbler spends the disprove path to itself |
| `censor-payout-iob-payout-desk` | `iob-payout-desk`, `--miner` | **yes** | five empty blocks, then the miner mines the payout the mempool refused; the disprove is displaced |
| `censor-payout-bridge-pegout` | `bridge-pegout`, `--miner` | no | the miner's payout block is invalid before 24 confirmations; the disprove confirms |

```sh
export BITVM_ARENA_BITCOIND=/path/to/bitcoind
python -m bitvm_corpus native episode --app iob-payout-desk \
    --actions examples/episodes/false-claim-withheld.jsonl --output report.json
python -m bitvm_corpus native episode --app bridge-pegout \
    --config '{"claim_internal": "claimant"}' --actions examples/episodes/keypath-sweep.jsonl
python -m bitvm_corpus native episode --app iob-payout-desk --miner     --actions examples/episodes/censor-payout.jsonl
python -m bitvm_corpus native audit report.json
```

An agent can drive an episode over a pipe: write one action line, read the observation
line.
