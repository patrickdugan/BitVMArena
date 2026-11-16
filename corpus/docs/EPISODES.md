# Interactive BitVM3 episodes

The BitVM3 catalog (`docs/BITVM3.md`) replays fixed trajectories. An episode lets a red
team attack a BitVM3-dependent application design directly. One attacker drives the
claimant of one application preset through a closed set of JSON actions on an owned
Bitcoin Core regtest node. Core judges every transaction. Honest parties react by fixed
rules, and a scorer reads only confirmed transactions.

## What an episode is

* The attacker plays one role, chosen with `--attacker claimant|desk|watch|relayer`
  (default `claimant`). Every other role is scripted and honest (see Honest parties).
* The setup is deterministic from `(app, config, tag)`: `prepare` garbles the statement
  circuit (seed from the row id `bitvm3.episode.<app>.<tag>`), the desk presigns, and
  the vault (plus bond, plus the watcher's fee coin under `zero_anchor`) is funded on
  chain. For `payout_timelock == "cltv"` the absolute height is setup height + window.
* Each role holds its own keys and nothing else. The claimant holds the claimant key and
  is the garbler, so it knows every label (`garbler_view`). The desk holds the desk and
  refund keys. The watcher holds the watcher key and the labels it was handed (or read from
  the claim witness). The relayer holds no key; it can only rewrite transactions that other
  parties built, keeping their witnesses. Other signatures exist only as presigned
  witnesses the `Graph` builds. A `spend` or `rewrite` that needs a key the role lacks
  returns an error result.
* With `--miner` the attacker may also build blocks (`mine`), up to `censorship_blocks`
  in a row; after that, honest blocks (`wait`) must come first. Without that bound a miner
  holding every block would beat any window, so the bound is the censorship assumption
  under test. This holds for every role.

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
`desk_online` (bool), `censorship_blocks` (consecutive miner blocks, 0 to 500),
`claim_delay` (blocks after funding before a scripted claimant claims, 0 to 100, default
`PAYMENT_DELAY` = 3) and `claim_proof` (`"honest"` or `"false"`, the proof a scripted
claimant submits, default `"honest"`).

`native assess --app NAME` runs the static design check of
[BITVM3.md](BITVM3.md#assessing-a-design) on a preset plus overrides, to pick which
attacks to try first. The desk is passive unless it is the attacker; `desk_online` records
the assumption and changes nothing the honest parties do.

## Actions

One JSON object per line: `{"op": ..., "args": {...}}`. Limits: 200 actions (invalid ones
count), 500 mined blocks. A bad action returns `{"ok": false, "error": ...}` and the
episode continues.

Shared by every role:

| op | args | effect |
|---|---|---|
| `observe` | none | the public observation (the relayer's also lists the raw hex of every episode transaction in the mempool; the watcher's lists the labels it holds and its verdict) |
| `broadcast` | `hex` | a custom raw transaction; prevout amounts and scripts are looked up through RPC and recorded |
| `wait` | `blocks` | honest mining, one block at a time; scripted parties act after each block |
| `mine` | `include: "none"\|[txid or "@label", ...]` | miner capability only: an empty block, or a block holding exactly the listed transactions of this episode. `"@claim:payout"` names the latest transaction built under that label, so scripts need no txids. Counts toward `censorship_blocks` |
| `end` | none | finish |

Claimant:

| op | args | effect |
|---|---|---|
| `garbler_view` | `proof?: [a, b]` | accept and reject labels, and the input labels for a proof |
| `claim` | `proof: [a, b]`, `labels: "handover"\|"withhold"`, `tables?: "honest"\|"corrupt"`, `outputs?` | submit the claim. `handover` gives the watcher the input labels off-chain; `withhold` does not (when `labels_onchain` they are in the claim witness anyway). `tables: "corrupt"` hands a corrupted copy of the garbled tables, which the watcher uses only when `tables_at == "claim"`. `outputs` rewrites the claim outputs and keeps the desk presignature; Core decides whether that is valid |
| `spend` | `utxo: "claim"\|"vault"\|"bond"`, `path: "payout"\|"disprove"\|"key"\|"reclaim"`, `outputs?`, `label?`, `fee?` | build the canonical presigned transaction through `Graph`, apply an output rewrite, submit. `claim`+`payout`, `claim`+`disprove` (`label` is `reject`, `accept` or hex; needs a presigned or hashlock disprove, since the claimant lacks the watcher key), `claim`+`key` (a key-path sweep signed as if the claimant were the internal key), `bond`+`key` (take the bond back). `vault` paths need the desk or an unknown key and return an error result |

Desk:

| op | args | effect |
|---|---|---|
| `spend` | `utxo: "vault"`, `path: "reclaim"` | `reclaim_tx`: the desk reclaims the vault. Core decides whether the CSV is final |
| `spend` | `utxo: "claim"`, `path: "payout"`, `outputs?` or `fee?` | `desk_payout_tx`: the desk signs the matured payout itself, to `refund` by default or to the single output given. The default fee is `2*FEE`, so that it can replace a payout the claimant already broadcast. Under `payout_cosigned` it has no claimant signature and Core rejects it |

Watcher:

| op | args | effect |
|---|---|---|
| `spend` | `utxo: "claim"`, `path: "disprove"`, `outputs?`, `label?`, `fee?` | the disprove. `label` is hex or `computed` (the default: the output label the watcher gets by evaluating the labels it holds; the action errors when it holds none). With `disprove_mode == "watcher"` the watcher signs over `outputs` of its choosing. Under any presigned or hashlock mode `outputs` rewrites the desk's presigned transaction, which Core rejects when the signature commits to the outputs. Under `zero_anchor` the transaction goes out in a package with the fee child |

Relayer:

| op | args | effect |
|---|---|---|
| `rewrite` | `tx: txid or "@label"`, `outputs` | take any transaction submitted in this episode, keep its witnesses, replace its outputs and submit it. It is valid only where the signatures do not commit to the outputs (`SIGHASH_NONE`) and the replacement pays enough fee |

Destinations (`dest`): `claimant` (the claimant bond-tree script), `payout`, `refund`,
`desk`, `relayer`, `watch`, `burn`, or a raw scriptPubKey in hex (at most 100 bytes).
Outputs are `[sats, dest]` pairs, at most 16.

## Honest parties

After every action and every block the scripted parties act.

* **Scripted claimant** (unless the attacker is the claimant). `claim_delay` blocks after
  funding it claims with `HONEST_PROOF`, or `FALSE_PROOF` when `claim_proof` is `"false"`,
  and hands its labels to the watcher. If Core refuses the claim (for example the vault has
  already been spent) the claim is recorded as a rejected transaction and the claimant stops.
  Once the claim has confirmed and the window has matured (the payout is final in the next
  block) and the claim output is still unspent, it submits the canonical payout, with up to
  three attempts.
* **Watcher** (unless the attacker is the watcher, and only while `watcher_online`). It waits
  until the claim has confirmed and `watcher_latency` further blocks have passed. It then
  takes the labels (the handover, or the claim witness when `labels_onchain`) and evaluates
  the garbling once. It uses its setup copy of the tables unless `tables_at == "claim"`, in
  which case it uses what the claimant handed over. On a reject verdict with the claim
  output unspent it disproves exactly as `run_case` does: its own signature or the desk's
  presignature, a refund beneficiary under `hashlock`, a P2A package with `anchor_child`
  under `zero_anchor`. It never disproves twice.
* **Desk and relayer** stay passive unless one of them is the attacker.

`end` mines a final block to confirm the mempool; scripted parties do not act after it.

## Scoring

From confirmed transactions only (deduplicated by txid), never from action labels. One
entitlement rule decides the attack, whatever role the attacker plays.

* `honest`: the proof of the confirmed claim. If no claim confirmed, the scripted
  claimant's intended proof. With neither (a claimant attacker whose claim never
  confirmed), `False`.
* `entitled_party`: `claimant` (its bond-tree script and payout script) when honest,
  `refund` otherwise.
* `diverted_sats`: for every confirmed transaction that spends a vault or claim output, the
  sum of its outputs to any party that is not the entitled party, `protocol` (the vault and
  claim scripts and the P2A anchor) or `burn`. Parties are `claimant`, `desk`, `refund`,
  `watch`, `relayer`, `burn`, `protocol` and `other` (every other script). The anchor fee
  child, which spends only the P2A anchor and the watcher's own coin, is not counted. The
  watcher's bond reward is exempt, up to `BOND`, when the claim is not honest and the app
  has a bond that is not burned and `disprove_mode` is `watcher` or `presigned`. A bond paid
  back to the claimant is not a reward and counts.
* `attack_success`: `diverted_sats > 0`.
* `attacker_net`: the net (outputs minus spent prevouts) of the attacker role's scripts:
  `claimant`, `desk` plus `refund`, `watch`, or `relayer`.
* `nets`: that net for every party. `honest_claim_paid`: honest and the payout script
  received at least `VAULT - 2*FEE`.
* Also reported: `claim_confirmed`, `claimant_loss`, `sats_burned`, `fees`, `blocks_elapsed`
  (blocks mined by actions, excluding the final one).

## Reports and audit

`native episode` writes one JSONL line per action to stdout (the first is the initial
observation, the last is the outcome) and, with `--output`, the report:
`schema_version`, `kind` (`bitvm3-episode`), `app`, `tag`, `overrides`, `config`,
`assumptions`, `attacker` (`claimant`, `desk`, `watch` or `relayer`), `capabilities`, `provenance`, `actions`, `steps`, `outcome`,
`evidence_hash` (the digest of everything else).

`native audit FILE` accepts episode reports. It checks the evidence hash, the app,
overrides and config; runs the local signature and commitment checks on every
transaction; rebuilds the setup from `(app, config, tag)` and compares the setup record,
the funded vault script and the claim outputs; checks that labels match the claimed
proof; re-runs every recorded garbled evaluation; rejects miner actions without the
capability and runs of miner blocks longer than `censorship_blocks`; checks that every
transaction comes from the attacker or from a scripted party doing only what it is scripted
to do, and that a scripted claim carries the scripted proof after `claim_delay`; and rescores
from the steps with the recorded attacker role.

## Limits

* One claim graph and one vault. The attacker plays one role, optionally colluding with a
  miner (`--miner`); the others follow the scripts above. Roles do not collude with each other.
* The desk can reclaim or sign a payout, but not sign a disprove.
* The garbling is the toy 16-bit adder circuit, and evaluation latency is a block count.
* The attacker cannot reorder, replace or fork blocks beyond what `mine` allows; there
  are no reorgs.
* The setup is public and deterministic per `(app, tag)`; `--tag` (default `1`) changes the
  garbling seed.
* Audit proves the report is consistent with Core's recorded answers and the rebuilt
  graph; it does not re-run Core.

## Examples

`examples/episodes/*.jsonl` are attacker scripts; `examples/episodes/reports/` holds the
19 reports they produced on Core 31.1, each audited clean.
`tools/rebuild_episode_reports.py --bitcoind PATH` reruns all of them; CI does the same on
Linux Core.

| Report | App (overrides), role | Attack | Why |
|---|---|---|---|
| `honest-*` (3) | each preset, claimant | no; honest claim paid | the payout matures after the window |
| `false-claim-withheld-iob-payout-desk` | `iob-payout-desk`, claimant | **yes** | labels withheld, nobody can evaluate (T2) |
| `false-claim-withheld-bridge-pegout` | `bridge-pegout`, claimant | no | labels are in the claim witness; disproven, bond burned |
| `false-claim-lending-liquidation` | `lending-liquidation`, claimant | no | the watcher bumps the zero-fee disprove through the P2A package |
| `keypath-sweep-bridge-pegout` | `bridge-pegout`, claimant | no | NUMS internal key: `Invalid Schnorr signature` |
| `keypath-sweep-bridge-pegout-claimant-internal` | `bridge-pegout` (`claim_internal: claimant`), claimant | **yes** | the claimant sweeps the claim output through the key path |
| `self-disprove-hashlock-iob-payout-desk` | `iob-payout-desk` (`disprove_mode: hashlock`), claimant | **yes** | the garbler spends the disprove path to itself |
| `censor-payout-iob-payout-desk` | `iob-payout-desk`, claimant, `--miner` | **yes** | five empty blocks, then the miner mines the payout the mempool refused; the disprove is displaced |
| `censor-payout-bridge-pegout` | `bridge-pegout`, claimant, `--miner` | no | the miner's payout block is invalid before 24 confirmations; the disprove confirms |
| `desk-reclaim-iob-payout-desk-fast` | `iob-payout-desk` (`reclaim: 2`), desk | **yes** | the reclaim is final before the scripted claimant claims; the honest claim is diverted to the refund script |
| `desk-reclaim-iob-payout-desk` | `iob-payout-desk`, desk | no | the 144-block reclaim is non-BIP68-final; the claimant is paid |
| `desk-steals-payout-iob-payout-desk` | `iob-payout-desk`, desk | **yes** | the desk kept its key and replaces the claimant's payout with a higher-fee payout to refund |
| `desk-steals-payout-iob-payout-desk-cosigned` | `iob-payout-desk` (`payout_cosigned: true`), desk | no | the leaf needs the claimant signature the desk lacks; the claimant is paid |
| `watcher-redirect-iob-payout-desk` | `iob-payout-desk` (`claim_proof: false`), watch | **yes** | the watcher signs its own outputs, so the disprove pays the watcher instead of refund |
| `watcher-redirect-bridge-pegout` | `bridge-pegout` (`claim_proof: false`), watch | no | the disprove is presigned; the rewrite fails (`Invalid Schnorr signature`), the canonical disprove confirms and the bond is burned |
| `relayer-rewrite-iob-payout-desk-sighash-none` | `iob-payout-desk` (`payout_hash_type: 2`), relayer | **yes** | the desk signature does not commit to the outputs; the relayer replaces the payout with one to itself |
| `relayer-rewrite-iob-payout-desk` | `iob-payout-desk`, relayer | no | the rewrite fails (`Invalid Schnorr signature`); the claimant is paid |

```sh
export BITVM_ARENA_BITCOIND=/path/to/bitcoind
python -m bitvm_corpus native episode --app iob-payout-desk \
    --actions examples/episodes/false-claim-withheld.jsonl --output report.json
python -m bitvm_corpus native episode --app bridge-pegout \
    --config '{"claim_internal": "claimant"}' --actions examples/episodes/keypath-sweep.jsonl
python -m bitvm_corpus native episode --app iob-payout-desk --miner     --actions examples/episodes/censor-payout.jsonl
python -m bitvm_corpus native episode --app iob-payout-desk --attacker relayer \
    --config '{"payout_hash_type": 2}' --actions examples/episodes/relayer-rewrite.jsonl
python -m bitvm_corpus native audit report.json
```

An agent can drive an episode over a pipe: write one action line, read the observation
line.
