# BitVM3 track

The BitVM3 track runs a garbled-circuit claim graph on an owned Bitcoin Core regtest
node. A real (toy-sized) garbled circuit decides each claim; Core decides every
transaction, including package relay, replacement, miner-built blocks and relay between
nodes. Each of the 24 recipes changes one design decision of the graph. Every recipe runs in
four combinations (hardened or mutant, benign or attack), for 96 trajectories. A separate
track, [`bitvm3-m14`](#bitvm3-at-m14-scale), decides the same graph with the real M14 garbled
verifier. The [`bitvm3-setup`](SETUP.md) track puts a key and garbling setup ceremony in front of
the graph, runs every party as its own process, and lets two of them collude through covert
channels in the setup traffic.

The recipes cover the seven layers a BitVM3-dependent application exposes:

| Layer | Recipes |
| --- | --- |
| Garbling | `garbling_unchecked`, `cut_and_choose_grindable`, `seed_reuse_across_claims`, `output_polarity_swapped` |
| Data availability | `labels_offchain_withheld`, `tables_delivered_late` |
| Statement binding | `proof_replay_across_vaults` |
| Transaction graph | `payout_csv_removed`, `payout_absolute_timelock`, `payout_sighash_none`, `claim_sighash_none`, `claim_internal_key_spendable`, `reclaim_preempts_claim`, `disprove_outputs_unbound`, `disprove_watcher_redirect`, `desk_key_retained` |
| Mempool and miners | `disprove_unbumpable`, `disprove_anchor_pinned`, `disprove_censored_by_miner`, `disprove_partitioned` |
| Liveness | `single_watcher_disprove`, `window_below_latency` |
| Economics | `claimant_unbonded`, `bond_self_slash` |

The fixed catalog shows each failure in isolation. [Interactive episodes](EPISODES.md) let
a red-team agent attack a whole application design (a preset or any combination of
these decisions), with Core judging and a value-flow scorer.

## Target

The graph mirrors the In-and-Out-Burger BitVM3 claim graph,
[`in-and-out-burger/iob/bitvm3.py`](https://github.com/patrickdugan/Spiral/blob/76071a0/in-and-out-burger/iob/bitvm3.py)
at Spiral `76071a0`:

```text
vault V   NUMS + { claim:   <D> CHECKSIGVERIFY <C> CHECKSIG
                   reclaim: <144> CSV DROP <D> CHECKSIG }
   |  claim tx (D presigns at setup, the claimant C signs)
   v
claim K   NUMS + { payout:   <6> CSV DROP <D> CHECKSIG               -> P'   (D presigns)
                   disprove: SHA256 <H(reject)> EQUALVERIFY <W> CHECKSIG -> desk }
          + OP_RETURN "IOB3" || claim_id
```

The leaf scripts, window and reclaim delay are the same as the target's. The claim_id
framing is the target's, with the toy circuit identifier in place of M14's program key.
Every design decision is a field of `Config` in [`bitvm3.py`](../bitvm_corpus/bitvm3.py);
its defaults are the target graph as built.

**Garbling** ([`gc.py`](../bitvm_corpus/gc.py)): free-XOR plus half-gates, with one Δ per
garbling and point-and-permute. This is the construction family of the
garbled-snark-verifier engine behind M14, with SHA-256 as the gate hash. The circuit
accepts a proof `(a, b)` exactly when `a + b == statement` over 16 bits, with no carry
out. The statement is a circuit constant, as M14 pins its statement.

- Size: 103 gates, 32 of them AND (64 ciphertexts), and 32 input bits. M14 is
  792,546,673 gates with 8,635,080 input bits.
- A false claim is a proof that does not satisfy the statement. Evaluating the circuit
  on it yields the reject label, which is the preimage the disprove leaf asks for.
- The garbler made every label, so the claimant always knows the reject label of its own
  garbling. Two recipes (`disprove_outputs_unbound`, `bond_self_slash`) are about exactly
  that.

**What the auditor re-checks offline** (`bitvm-corpus native audit`):

- every transaction: txid, Taproot commitments, each script-path signature against the
  key its CHECKSIG names, and each key-path signature against the output key;
- that no two confirmed transactions spend the same outpoint, and that no transaction is
  recorded as both replaced and confirmed;
- that the setup rebuilt from the case id matches the recorded scripts, statements,
  commitments and absolute payout height;
- every recorded garbled evaluation, re-run from the recorded labels and from the tables
  the evaluator actually used;
- that the outcome follows from the confirmed transactions.

## Results (Bitcoin Core 31.1, regtest)

All 96 trajectories met the expectations declared in the catalog. The run confirmed 192
transactions, rejected 53 and took 3 min 18 s. Saved evidence:
[`examples/native/bitvm3-core31.1.json`](../examples/native/bitvm3-core31.1.json). Core 31.2
gave the same verdict at every step of all 96 trajectories. The 40 trajectories of the
first ten recipes also match the previous evidence file step for step.

The "IOB status" column names the target graph's own documented trust assumption or
parameter. Where it says "= mutant", the mutant profile is that assumption failing, not a
defect in the target code.

| Recipe | Mutant | IOB status | Hardened attack (Core's verdict) | Mutant attack |
| --- | --- | --- | --- | --- |
| `labels_offchain_withheld` | Input labels go off-chain; the claimant withholds them | T2: = mutant | The claim leaf requires 32 hashlock openings, so the labels appear in the witness. The watcher reads them, evaluates and disproves; the payout fails with `missing-inputs` | Nobody can evaluate; the false claim is paid |
| `tables_delivered_late` | Evaluators get the garbled tables at claim time; the claimant hands over a copy with every ciphertext corrupted | n/a | The tables were delivered and checked against the registered commitment at setup. The watcher evaluates its own copy and disproves | Evaluation decodes to neither label ("invalid"); nobody can disprove and the false claim is paid |
| `garbling_unchecked` | No cut-and-choose; the registered garbling swaps its output decoding | T1: = mutant | k=4 cut-and-choose: all 3 opened instances fail regarbling, so the desk withholds its presignature and the claim fails with `Invalid Schnorr signature` | The evaluator decodes "accept"; the false claim is paid |
| `cut_and_choose_grindable` | The kept index is sha256(commitments) mod k | n/a | The challenger draws randomness after the commitments. The bad instance is opened and the claim is rejected. Escape chance per attempt: 1/4 (this fixture records a caught draw) | The garbler ground its salt 3 times until the bad instance was kept; the false claim is paid |
| `seed_reuse_across_claims` | The prior claim used the same garbling seed | n/a | 32 Δ candidates, none matching; the griefing disprove fails `OP_EQUALVERIFY` and the honest payout confirms | One Δ candidate, reject = accept ⊕ Δ; the honest claim is disproven |
| `output_polarity_swapped` | The disprove leaf hashes the accept label | n/a | The disprove confirms and the payout fails | The disprove fails `OP_EQUALVERIFY`; the false claim is paid |
| `proof_replay_across_vaults` | Two vaults share one statement | n/a | Vault 2's statement folds in its instance (48,401). The replayed proof evaluates to reject there, vault 2's claim is disproven and only vault 1 pays | One honest payment proof is paid out of both vaults |
| `payout_csv_removed` | The payout leaf has no CSV | n/a | The early payout is `non-BIP68-final` and the disprove confirms | The payout confirms before evaluation; the disprove fails with `missing-inputs` |
| `payout_absolute_timelock` | The payout leaf uses CLTV at setup height + 6 | n/a (CSV) | CSV counts from the claim: a payout right behind the claim is `non-BIP68-final`, and the disprove confirms | The claimant claims after the setup height + 6, so claim and payout confirm in the same block |
| `payout_sighash_none` | The desk presigns the payout with SIGHASH_NONE | n/a | The rewritten output fails with `Invalid Schnorr signature`; P' is paid | A relayer redirects the payout to itself |
| `claim_sighash_none` | The desk presigns the claim with SIGHASH_NONE | n/a | The rewritten claim fails with `Invalid Schnorr signature`; the canonical claim is disproven | The claimant rewrites the claim to pay the vault straight to itself; no claim output, no dispute |
| `claim_internal_key_spendable` | The claim output's Taproot internal key is the claimant's key | n/a (NUMS) | The claimant's key-path signature fails with `Invalid Schnorr signature`; the false claim is disproven | The claimant sweeps K through the key path a block after the claim; the disprove fails with `missing-inputs` |
| `reclaim_preempts_claim` | The desk can reclaim the vault after 2 blocks | 144 blocks | The desk's reclaim is `non-BIP68-final`; the honest claim is paid | The desk reclaims while the honest claimant is still paying the user; the claim fails with `missing-inputs` |
| `disprove_outputs_unbound` | The disprove leaf is `SHA256 <H> EQUAL`, with no signature | W signs | The desk presigned the disprove over a refund-only output. The claimant's rewrite to itself fails with `Invalid Schnorr signature` | The garbler, who knows the reject label, spends K to itself through the disprove leaf a block after claiming |
| `disprove_watcher_redirect` | W signs the disprove when it broadcasts, so it chooses the outputs (the IOB graph as built) | W signs: = mutant | The desk presigned the disprove over a refund-only output; the watcher's rewrite to itself fails with `Invalid Schnorr signature`, and another label holder's refund confirms | The watcher disproves the false claim and pays the whole vault to itself |
| `desk_key_retained` | Only the desk signs the payout leaf, and it kept its key | D-only payout: = mutant | The payout leaf also needs C's signature; the desk's own payout fails with `Invalid Schnorr signature` and P' is paid | After the window the desk signs the payout to itself; the honest claim's payout fails with `missing-inputs` |
| `disprove_unbumpable` | The desk presigns the disprove at zero fee, without an anchor; the desk is offline | n/a | A version-3 disprove with a P2A anchor is rejected alone (`min relay fee not met`) and accepted as a package with the watcher's fee child | The disprove is rejected (`min relay fee not met`) and nobody can bump it; the false claim is paid |
| `disprove_anchor_pinned` | Congested blocks need 2 sat/vB. The zero-fee disprove's P2A anchor is in a version-2 transaction | n/a | TRUC refuses the claimant's 43,112 vB child (`TRUC-violation`). Its 153 vB child is replaced by the watcher's, and the disprove confirms in the first congested block | The claimant's 43,112 vB child pays 12,000 sats at 0.28 sat/vB. The watcher's bump needs more than that and holds 10,000: `insufficient fee`. Five congested blocks include nothing, then an 18,000-sat payout replaces the whole package |
| `disprove_censored_by_miner` | Window 6 against a colluding miner that censors up to 8 blocks | WINDOW=6: = mutant | With window 24, the miner's payout block after 8 empty blocks is invalid (`non-BIP68-final`); the disprove confirms once censorship ends | Five empty blocks, then the miner mines the payout itself (the mempool rejects it: `insufficient fee` against the waiting disprove); the disprove is evicted |
| `disprove_partitioned` | Three owned nodes over loopback P2P; the watcher's only peer is a blocks-only relay | n/a | With a direct link to the miner, the disprove reaches the miner's mempool in about 3 s and confirms | The disprove never reaches the miner (waited 30 s); the payout is mined and the disprove is displaced |
| `single_watcher_disprove` | Only W's signature opens the disprove leaf; W is offline | single W: = mutant | The desk presigns a disprove with a fixed refund output, and any label holder broadcasts it | The third party's disprove fails with `Invalid Schnorr signature`; the false claim is paid |
| `window_below_latency` | WINDOW 6 against a declared evaluation latency of 8 blocks | WINDOW=6: = mutant | With WINDOW 24, the payout at 6 confirmations is `non-BIP68-final` and the disprove at 8 confirms | The payout confirms at 6; the disprove at 8 fails with `missing-inputs` |
| `claimant_unbonded` | The claim carries no claimant bond | no bond: = mutant | The disproven false claim costs the claimant its 20,000-sat bond, which goes to the watcher | Disproven, but the claimant's loss is 0 sats |
| `bond_self_slash` | The bond goes to whoever disproves (desk presigns SIGHASH_SINGLE on the refund output) | no bond | The presigned disprove burns the bond to a NUMS key. The claimant's rewrite fails with `Invalid Schnorr signature`; its loss is 20,000 sats | The claimant replaces the watcher's disprove (full RBF) with one paying the bond back to itself; its loss is 3,000 sats in fees |

Every benign trajectory paid the honest claim in both profiles. None of these mutants
costs the honest path anything, which is why happy-path tests do not show them.

## Threats to BitVM3-dependent applications

The same claim graph sits under very different applications. The table says what each
recipe means for an application built on it, and what to check in its design. "Bridge"
means operator reimbursement after a peg-out; "desk" a proof-gated payout desk such as
IOB; "lending" a liquidation that releases collateral on a proven price or health
statement; "settlement" an oracle, prediction-market or cross-chain release gated on a
proven external fact.

| Recipe | Application impact | Check in your design |
| --- | --- | --- |
| `labels_offchain_withheld` | All: a false claim is paid without anyone being able to evaluate it | Labels on-chain, or a data-availability guarantee whose failure blocks the payout |
| `tables_delivered_late` | All: corrupt tables leave the evaluator without a reject label | Tables delivered and checked against the commitment before anyone presigns |
| `garbling_unchecked`, `cut_and_choose_grindable` | All: a bad garbling is invisible on-chain | Cut-and-choose with challenger randomness drawn after the commitments |
| `seed_reuse_across_claims` | Bridge and desk with repeated claims: Δ leaks, and honest claims can be griefed | One fresh seed per claim, derived from instance-unique data |
| `output_polarity_swapped` | All: the disprove leaf checks the wrong label | Test the disprove leaf against an actually false proof, not only the honest path |
| `proof_replay_across_vaults` | Bridge (one peg-out proof, many vaults), lending (one price proof, many positions), settlement (one event, many markets) | The statement binds the vault outpoint or instance, the amount and the recipient |
| `payout_csv_removed`, `payout_absolute_timelock` | All: the window shrinks to nothing | Relative timelocks (CSV) on every payout, counted from the claim |
| `payout_sighash_none`, `claim_sighash_none` | All: presigned transactions can be redirected | SIGHASH_DEFAULT/ALL on every presignature that moves value; SINGLE/ANYONECANPAY only where the free part carries no value |
| `claim_internal_key_spendable` | All: a key path bypasses the whole dispute | NUMS (or a key nobody controls alone) as the internal key of every graph output |
| `reclaim_preempts_claim` | Bridge (the operator fronts the peg-out), desk: the vault owner reclaims after the claimant has paid | A reclaim delay longer than the claimant's payment-plus-claim deadline |
| `disprove_outputs_unbound` | All: the garbler always knows the reject label | Disprove outputs fixed by a presignature or a signature the claimant does not control |
| `disprove_watcher_redirect` | All with a designated watcher; the claimant can hand it the reject label, so collusion costs one false claim | Disprove outputs fixed by the vault owner's presignature, not chosen by whoever disproves |
| `desk_key_retained` | Bridge and desk: the committee that presigned can re-sign after setup | The claimant co-signs the payout leaf, or the committee's key deletion is enforced (per-graph keys, secure hardware) |
| `disprove_unbumpable` | Lending and settlement, where the vault owner may be passive at dispute time | Zero-fee presigned transactions carry an anchor (P2A, TRUC) that a third party can spend |
| `disprove_anchor_pinned` | All with presigned zero-fee disproves, in a fee market where blocks are full | TRUC (version 3) for every presigned transaction with an anchor; a watcher fee budget for the replacement rules that remain |
| `disprove_censored_by_miner` | All, more so for high-value vaults that make miner bribery pay | Window longer than the censorship you assume, in blocks |
| `disprove_partitioned` | All: one watcher node behind attacker-controlled peers never reaches miners | Watchers broadcast through several independent peers or services, and check that miners received the disprove |
| `single_watcher_disprove`, `window_below_latency` | All: liveness of the dispute decides safety | Permissionless disprove; window longer than evaluation plus label transfer plus broadcast |
| `claimant_unbonded`, `bond_self_slash` | Bridge and lending, where each false claim forces an expensive evaluation | A bond that a disproven claimant cannot recover; burn it, or pay only a capped reward |

### Assessing a design

`bitvm3.assess(config, assumptions)` checks a design statically: it maps the graph
decisions in `Config` to the recipes whose failure modes they expose. Each finding names
the mutant trajectory that shows that failure on Core.

```bash
python -m bitvm_corpus native assess --config '{"window": 12, "bond": true}' \
  --assume '{"censorship_blocks": 8, "evaluation_latency_blocks": 8}'
```

The assumptions (`evaluation_latency_blocks`, `censorship_blocks`, `claim_deadline_blocks`,
`desk_online_at_dispute`, `watchers`, `claims_per_garbling_seed`, `vaults_per_statement`,
`desk_keys_deleted`) carry what the graph alone cannot show. A test checks that every
recipe's mutant design is flagged for that recipe and its hardened design is not. The
IOB graph as built is flagged for eight: off-chain labels, unchecked garbling, a 6-block
window against both the censorship bound and the evaluation latency, the single watcher,
no bond, the watcher choosing the disprove's outputs, and a payout only the desk signs
(with `desk_keys_deleted` false, its default). The static check only selects what to try. Confirmation comes from
replaying the named trajectory, or from an [episode](EPISODES.md) against the full
design.

## BitVM3 at M14 scale

The `bitvm3-m14` track ([`m14.py`](../bitvm_corpus/m14.py)) runs the same claim graph,
decided by M14, the complete garbled final verifier: 792,546,673 gates and 8,635,080
input bits per instance. The garbler is `m14-claim` from
patrickdugan/garbled-snark-verifier at `25c6c23` (binary sha256 `2cf5daf6…`), the revision
pinned in [`tools/m14_record.json`](../tools/m14_record.json). The proof is
the M16 mainnet SPV payment proof (wrap v2, sha256 `97871e86…`); the vault statements are
the M16 statement and, as a different statement, c4's. Each vault's disprove leaf commits
to its garbling's real reject-label hash. A disprove spends with the label the M14
evaluator produced, and Core checks that hash.

The M14 runs are recorded once in [`examples/m14/`](../examples/m14/) with public fixture
seeds. The workflow [`m14-record.yml`](../../.github/workflows/m14-record.yml) builds
`m14-claim` at the pinned revision on a hosted runner, runs `tools/m14_runs.sh` and
publishes each run's record as an annotation; `tools/m14_collect.py --ci RUN_ID` reads
them back. The Core
trajectories replay them. The audit checks that every recorded output label hashes to its
garbling's committed accept or reject label, that garbler and evaluator saw the same
ciphertext stream, and that the setup run committed to the same labels and stream before
the tampered-proof evaluation.

| Run | Seed | Verdict | Wall time | Peak RSS |
| --- | --- | --- | --- | --- |
| setup (tampered-proof instance) | `9844fd70…` | commits accept/reject hashes | 158 s | 10.6 GB |
| honest M16 proof, M16 statement | `ff1f4762…` | accept | 279 s | 15.5 GB |
| same proof, one input bit flipped | `9844fd70…` | reject, the label the setup committed | 244 s | 15.6 GB |
| same proof, c4 statement | `582c650d…` | reject | 237 s | 15.6 GB |
| same proof, second vault for the M16 statement | `e0565615…` | accept | 260 s | 15.6 GB |

Measured on a GitHub-hosted runner (ubuntu-latest, 16 GB of RAM plus 16 GB of swap) by
[workflow run 45374706843](https://github.com/patrickdugan/BitVMArena/actions/runs/45374706843).
Evaluate runs the garbler and evaluator together. Every run streamed 792,546,673 ciphertexts.

The track's first recording was of the `04b6d3e` build (785,442,492 gates) on one laptop, in
WSL with a 20 GB memory cap: 627–1,330 s and 16.7–18.6 GB per evaluation, swapping. The IOB
testnet4 runs of that binary on the same laptop took 348–401 s.

| Recipe | Hardened attack | Mutant attack |
| --- | --- | --- |
| `m14_false_claim` | The watcher holds the 8,635,080 labels (138 MB, off-chain), gets the real reject label and disproves; the payout fails with `missing-inputs` | The labels are withheld; nobody can evaluate and the false claim is paid |
| `m14_statement_binding` | Vault 2 is garbled for the c4 statement; the M16 proof evaluates to reject there and vault 2 is disproven | Vault 2 is garbled for the M16 statement too; one mainnet payment proof is paid out of both vaults |

All 8 trajectories met their expectations on Core 31.1 (20 confirmed, 2 rejected).
Evidence: [`examples/native/bitvm3-m14-core31.1.json`](../examples/native/bitvm3-m14-core31.1.json).

These runs are of the circuit with the public-values digest check (finding 10). Until
2026-11-24 the track replayed runs of the `04b6d3e` build, which lacks it. The two recipes
here do not depend on the check: a flipped input bit and a proof for another statement are
rejected by both circuits. What the earlier circuit accepted is a proof whose public values
were replaced before proving, and no recipe here builds one.

What M14 scale adds to the toy track's numbers:
- each claim instance streams 792,546,673 ciphertexts, 12.68 GB at 16 bytes, which the
  evaluator must have. That is `tables_delivered_late` at full size;
- the input-label handover is 138 MB, `labels_offchain_withheld` at full size;
- evaluation takes 4 to 22 minutes depending on memory: 237–279 s on a 16 GB hosted runner,
  6–22 minutes on one laptop (finding 2).

## What BitVM3 changes relative to BitVM2

The BitVM2 baseline track ([`bitvm2.py`](../bitvm_corpus/bitvm2.py), 32 trajectories, all
met; evidence in [`examples/native/bitvm2-core31.1.json`](../examples/native/bitvm2-core31.1.json))
mirrors the bridge graph in BitVM/BitVM at `c620dbfa`:

- **Graph:** kick-off, a challenge on connector A (presigned SINGLE|ANYONECANPAY),
  take 1 after connector 3's timelock, assert, and take 2 after connector 4's timelock.
- **Commitments:** the assert carries Winternitz commitments (HASH160, base 16).
- **Disprove:** input 0 is presigned SIGHASH_SINGLE, which fixes only the burn output.
  The connector C chunk re-verifies the WOTS values and checks an adder.

Both tracks run under the same harness, so each weakness class can be lined up on both:

| Weakness class | BitVM2 baseline (mutant attack) | BitVM3 / IOB graph | What changed |
| --- | --- | --- | --- |
| Reimbursement before the dispute window | `take1_csv_removed`: take 1 confirms, and the late challenge fails with `missing-inputs` | `payout_csv_removed`, `payout_absolute_timelock`, `window_below_latency` | **Carried and widened.** BitVM3's window also has to cover off-chain evaluation (6–22 min for M14 on one laptop, more on weaker hardware). A BitVM2 watcher only needs on-chain data and one transaction build |
| Reimbursement not bound to the dispute | `take1_unbound_connector_a` and `take2_unbound_disprove`: the operator is paid after a successful challenge or disprove | Payout and disprove are two leaves of the same claim output | **Removed by construction.** Spending one leaf consumes the other, unless a key path or a rewritten claim bypasses the output (`claim_internal_key_spendable`, `claim_sighash_none`) |
| Challenge crowdfunding | `challenge_sighash_all`: the challenger cannot attach funds, and take 1 goes through | No challenge transaction | **Removed** (fewer moving parts, one less presigned policy) |
| Correctness of the disprove computation | `chunk_carry_dropped`: a buggy on-chain chunk lets a wrapped sum stand and also disproves the honest operator | `garbling_unchecked`, `cut_and_choose_grindable`, `output_polarity_swapped` | **Changed.** Correctness moves off-chain into the garbling. Script only checks a hash, so a bad circuit is invisible on-chain and can be caught only by cut-and-choose, which must use challenger randomness |
| Commitment to the inputs | `wots_checksum_unchecked`: commitments are on-chain, so availability is guaranteed. Forgery needs a dropped checksum (here it griefs an honest operator) | `labels_offchain_withheld`, `tables_delivered_late`, `seed_reuse_across_claims` | **Introduced.** Inputs are labels and the program is a table set. Off-chain delivery of either creates a withholding attack, and label secrecy (Δ) becomes a new asset |
| Who can produce the disprove witness | Only someone who finds a wrong assertion | `disprove_outputs_unbound`, `bond_self_slash` | **Introduced.** The garbler knows the reject label in advance. Disprove outputs must be fixed, and a bond must not flow back to whoever disproves |
| Statement binding | The Groth16 public input binds the peg-out | `proof_replay_across_vaults` | **Carried.** The statement is a circuit constant here, so the binding has to happen at setup |
| Deterrence | `disprove_burn_sighash_none`: a lying operator self-disproves and recovers its stake | `claimant_unbonded`, `bond_self_slash` | **Changed.** IOB has no stake to burn, so a false claim costs only fees, and the vault pays those. Adding a bond reintroduces BitVM2's burn requirement |
| Disprove reward front-running | `disprove_reward_unbound`: **inherent**, confirmed in both profiles. Input 0's SINGLE commits only the burn output, so a relayer rewrites the reward | `single_watcher_disprove`, `bond_self_slash` | **Traded.** IOB requires W's signature, which removes front-running but adds single-watcher liveness. A desk-presigned disprove with fixed outputs keeps both properties |
| Fee bumping, pinning, censorship and propagation | Presigned transactions with anchors; challenge windows in blocks | `disprove_unbumpable`, `disprove_anchor_pinned`, `disprove_censored_by_miner`, `disprove_partitioned` | **Carried** |
| Who chooses the disprove's outputs | Input 0 presigned SINGLE fixes the burn output | `disprove_watcher_redirect` | **Changed.** IOB's watcher signs at broadcast, so the refund to the desk is a convention, not a rule |
| Signing committee after setup | n-of-n presigns, then deletes its keys | `desk_key_retained` | **Carried.** A single desk key that survives setup can re-sign the payout |
| Presigned output binding | (presigned ALL in the baseline) | `payout_sighash_none`, `claim_sighash_none` | **Carried** |

New in BitVM3, with no BitVM2 counterpart: input-label and table withholding, unchecked
garbling and grindable cut-and-choose, Δ or seed reuse, the garbler's knowledge of the
reject label, and evaluation latency racing the window. IOB's simpler graph removes
three BitVM2 hazards: crowdfunding, connector binding and reward front-running. It
removes front-running only by adding a single watcher.

## Findings for the IOB graph

Findings 1 to 9 are design observations about the concrete target. None of them is an
exploit of the deployed testnet4 vaults, and nothing was broadcast outside regtest. Finding
10 is a flaw in the verifier circuit those vaults were garbled from; it was not exercised
against them.

1. **Label delivery (T2) decides safety, not only liveness.** A claimant who withholds
   labels is paid for a false claim, because the window simply runs out.
   - Putting the labels on-chain closes this at toy scale. The claim grows from 208 to
     961 vB for 32 input bits, about 23.5 vB per bit.
   - At that rate, M14's 8,635,080 input bits would need about 203M vB, far over the
     100k-vB standard limit.
   - A 512-bit statement-only commitment would be about 12k vB. That is the arithmetic
     behind the "statement on-chain, rest by data availability or a succinct wrapper"
     direction in the S6 notes.
2. **The window has to fit the slowest honest watcher.** Measured M14 evaluation on one
   laptop ranges from 348–401 s (IOB runs) to 627–1,330 s (this track's first recording,
   swapping under a 20 GB memory cap); an earlier note recorded about 60 minutes. A hosted
   runner with 16 GB takes 237–279 s. At mainnet block rates
   (Poisson, 6 blocks per hour) the chance that a 6-block window ends before the
   evaluation finishes:

   | Evaluation time | Window 3 | Window 6 | Window 9 | Window 12 |
   | --- | --- | --- | --- | --- |
   | 401 s (no swap) | 0.031 | 0.00007 | <0.000001 | <0.000001 |
   | 1,330 s (swapping) | 0.38 | 0.026 | 0.0005 | 0.000004 |
   | 60 min | 0.94 | 0.55 | 0.15 | 0.020 |

   That is before label and table transfer (138 MB and 12.68 GB per claim) and broadcast.
   Testnet4's minimum-difficulty blocks shorten the window further. Staging wave 1 measured
   a median of 461 s per block over 42 waits. From the claim's block (161,704) to the tip at
   which a 6-block-CSV payout is accepted (161,709) took 36 minutes. Minimum-difficulty blocks are also reorganized routinely: a claim mined in
   161,710 was mined again in 161,712, which restarts every relative timelock that counts
   from it. Watcher and claimant software has to recount from the block that stays
   ([TESTNET4.md](TESTNET4.md)). The same 6 blocks are also the censorship budget: a miner that can withhold the disprove for 6 blocks gets the
   payout through (`disprove_censored_by_miner`).

3. **A single watcher is a liveness and bribery point.** Only W can open the disprove
   leaf. A desk-presigned disprove (`SHA256 <H(reject)> EQUALVERIFY <D> CHECKSIG`, with
   D's presignature over a fixed refund output) lets anyone holding the reject label
   stop a false claim. Because the output stays fixed, it does not bring back BitVM2's
   reward front-running. If it is presigned at zero fee for a desk that may be offline,
   it needs a P2A anchor (`disprove_unbumpable`).
4. **A false claim is free.** The vault pays the claim fee, so a disproven claimant loses
   nothing, while each claim forces an M14 evaluation (4–22 min and 16–18 GB measured) and a
   fresh setup. A claimant bond input on the claim tx makes lying cost something, but
   only if a disproven bond is burned or paid to a fixed party: a bond that goes to
   whoever disproves comes back to the claimant, who knows the reject label
   (`bond_self_slash`).
5. **One seed per claim.** Free-XOR labels differ by the garbling's Δ. If two claims are
   garbled from the same seed and their handed-over labels differ in any input bit,
   whoever holds both handovers learns Δ. That party can turn the accept label into the
   reject label and disprove an honest claim. Derive each seed from data that is unique
   per claim, such as the vault outpoint and instance name.
6. **Cut-and-choose has to use the challenger's randomness.** Garbling correctness (T1)
   is unchecked today. If a cut-and-choose is added, its kept index must not be a hash
   of the garbler's own commitments: with k=4 the garbler needed 3 salt trials to keep
   its bad instance.
7. **The statement must bind the instance.** M14 pins one statement per garbling. If two
   desk vaults are set up for the same statement, one payment proof drains both
   (`proof_replay_across_vaults`; at M14 scale, `m14_statement_binding`). Fold the vault
   outpoint into the statement.
8. **The watcher chooses where a disproven vault goes.** The disprove leaf is
   `SHA256 <H(reject)> EQUALVERIFY <W> CHECKSIG`, and `signed_disprove` signs at broadcast
   with W's key alone. The refund to the desk is the code's choice, not something the
   script enforces. A bribed or malicious W can pay the vault to itself whenever a false
   claim appears. Because the claimant knows the reject label, a claimant and a W who
   collude can stage a false claim and take the vault one block after the claim
   (`disprove_watcher_redirect`). A desk presignature over the refund output (finding 3)
   closes this as well.
9. **The desk alone signs the payout.** The payout leaf `<6> CSV DROP <D> CHECKSIG` lets a
   desk that kept its key re-sign the matured payout to itself (`desk_key_retained`). The
   committee trust model in the IOB README depends on key deletion. Adding the claimant's
   signature to the payout leaf removes the dependence for this path.
10. **M14 before 2026-11-24 did not bind the statement to the proof.** This one is a
    soundness flaw in the verifier circuit, not in the graph. SP1's wrap machine constrains
    8 of its 187 public values, the `digest` slots; the wrap program computes that digest
    in-circuit over the guest key, the committed-values digest, the exit code, the recursion
    key root and the proof nonce. M13's `verify_final` and the M14 circuit compared those
    fields with the pins and did not recompute the digest. A claimant who runs the wrap
    step can take any valid SP1 proof, write the pinned guest key and the vault's statement
    digest into the public values before proving, and the result evaluates to the committed
    **accept** label. No watcher can disprove it, whatever its hardware and however long the
    window: the reject label never appears. Cost to the claimant: one shrink and one wrap
    (minutes on a laptop). Every instance garbled from the `04b6d3e` circuit, including the
    ones this track replayed until 2026-11-24 and those of the IOB testnet4 demonstration, has this
    property.
    - Fixed in garbled-snark-verifier `2137266` (M13) and `c39a3ec` (M14, +7,104,181 gates
      for SP1's Poseidon2 over 53 elements) and in the zk-rusto-no-bitcoino mirror
      (`d618707`, `43ff07c`). Both repositories' CI builds a wrap proof with replaced public
      values, checks that its STARK verifies, and requires the final verifier to refuse it.
    - It was found by reading the verifier against SP1 6.9.0's own
      (`is_root_public_values_valid`), not by a trajectory here, and nothing was broadcast.
      No recipe in this corpus exercises it: the toy circuit does not model proof soundness
      ([Fidelity limits](#fidelity-limits)), and an M14-scale recipe needs a forged wrap
      proof and an evaluation against the old and the fixed circuit.
    - For a design under assessment: pin the verifier revision in the instance, not only
      the statement, and treat any garbling from before the fix as paying whoever asks.

## The IOB graph with every fix (`bitvm3-iob`)

The hardened profile above closes one recipe's flaw per row and leaves the rest of the graph
as IOB built it. The `bitvm3-iob` track ([`iob.py`](../bitvm_corpus/iob.py)) runs one design
that carries every hardened fix at once (`bitvm3.iob_config`):
- input labels in the claim witness;
- a disprove presigned by the desk: any label holder can broadcast it, nobody can choose
  its outputs, and it pays its own fee;
- the 24-block window;
- a bond, burned when the claim is disproven;
- interactive cut-and-choose;
- a payout leaf the claimant co-signs.

The other `Config` fields already hold the hardened choice by default: reject polarity, a
CSV payout, SIGHASH_DEFAULT presignatures, a NUMS internal key, the 144-block reclaim, one
statement per vault, tables checked at setup, a fresh seed per claim and independent watcher
peers. `native assess` flags nothing for this design. A test checks that it takes every
field in which a recipe's hardened and mutant designs differ, except the anchor on a zero-fee
disprove, which this design does not need.

Each recipe's benign and attack trajectories run unchanged against it: 23 recipes, 46 rows.
`disprove_anchor_pinned` is left out, because its mechanism is a zero-fee disprove with an
anchor, and this disprove pays its own fee. The expectations are the hardened rows'.

Results on Core 31.1 ([`examples/native/bitvm3-iob-core31.1.json`](../examples/native/bitvm3-iob-core31.1.json)):
- **46 of 46 met.** 90 transactions confirmed and 32 were refused. No attack succeeds, and
  every honest claim the hardened rows pay is paid.
- **The fixes compose.** 22 of the 23 attacks take the same transaction steps as their
  single-fix hardened rows: the same labels, the same accept or refuse verdicts with the
  same reject reasons, the same confirmations. None of the fixes blocks a transaction
  another fix relies on. The 23rd, `disprove_unbumpable`, needs no fee child, because the
  disprove pays its own fee.
- **What changes is what an attack costs.**
  - In the single-fix rows, a disproven false claim costs the claimant nothing, except in
    the two rows about the bond.
  - Here 17 of the 23 attacks burn the claimant's bond. That includes the replay attack:
    the claim on the first vault is paid, and the replayed claim on the second vault is
    disproven and its bond burned.
  - The other six burn nothing:
    - in two, the desk never presigned, so the claim was refused and the bond stayed with
      the claimant (`garbling_unchecked`, `cut_and_choose_grindable`);
    - in four, someone other than the claimant attacks an honest claim (seed reuse, the
      payout presignature, the early reclaim, the retained desk key).

The testnet4 wave for this design, `iob1` (21 attacks and the honest claim), met 22 of 22 on
the public network ([TESTNET4.md](TESTNET4.md#wave-iob1-on-testnet4)).
- Every row took the same transaction steps as here.
- 15 bonds were burned, the 15 attacks that burn one on regtest.
- Every claim carries the labels and the bond, so each one is 1,036 vB and paid 1,140 sats
  at 1.1 sat/vB. The claims were most of the wave's fees.

## Fidelity limits

- The circuit is a 16-bit adder check, not a SNARK verifier, so the label counts and
  timings above are scaled. Proof soundness is not modelled: any `(a, b)` that sums to
  the statement is a valid proof.
- In the toy track the latency recipe's delay and the censorship bound are declared, and
  the garbled evaluation finishes instantly. The M14 track measures evaluation time, but
  replays recorded runs instead of evaluating during the trajectory.
- One test key stands for the desk committee, and every key is public and deterministic.
- Window, bond and fee values are regtest parameters.
- Replacement, package relay and pinning run through Core 31.1's mempool policy (full-RBF,
  TRUC, P2A, ephemeral dust). Congestion is a declared fee floor that the miner applies to
  ancestor packages, not a market of other users' transactions.
- Propagation is real P2P relay between three owned nodes on loopback, and one topology
  per profile. There is no latency model, no adversarial peer software beyond Core's
  blocks-only mode, and no competing miners.
- A miner is modelled by `generateblock`, which builds blocks with exactly the listed
  transactions. Hash power and bribery costs are outside the model.
