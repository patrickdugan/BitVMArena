# BitVM3 track

The BitVM3 track runs a garbled-circuit claim graph on an owned Bitcoin Core regtest
node. A real (toy-sized) garbled circuit decides each claim; Core decides every
transaction. Each of the 10 recipes changes one design decision of the target graph,
and every recipe runs in four combinations (hardened or mutant, benign or attack), for
40 trajectories.

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

**Garbling** ([`gc.py`](../bitvm_corpus/gc.py)): free-XOR plus half-gates, with one Δ per
garbling and point-and-permute. This is the construction family of the
garbled-snark-verifier engine behind M14, with SHA-256 as the gate hash. The circuit
accepts a proof `(a, b)` exactly when `a + b == statement` over 16 bits, with no carry
out. The statement is a circuit constant, as M14 pins its statement.

- Size: 103 gates, 32 of them AND (64 ciphertexts), and 32 input bits. M14 is
  785,442,492 gates with 8,635,080 input bits.
- A false claim is a proof that does not satisfy the statement. Evaluating the circuit
  on it yields the reject label, which is the preimage the disprove leaf asks for.

**What the auditor re-checks offline** (`bitvm-corpus native audit`):

- every transaction: txid, Taproot commitments, and each signature against the key its
  CHECKSIG names;
- that the setup rebuilt from the case id matches the recorded scripts and commitments;
- every recorded garbled evaluation, re-run from the recorded labels;
- that the outcome follows from the confirmed transactions.

## Results (Bitcoin Core 31.1, regtest)

All 40 trajectories met the expectations declared in the catalog. The run confirmed 76
transactions, rejected 19 and took 52 s. Saved evidence:
[`examples/native/bitvm3-core31.1.json`](../examples/native/bitvm3-core31.1.json).

The "IOB status" column names the target graph's own documented trust assumption. Where
it says "= mutant", the mutant profile is that assumption failing, not a defect in the
target code.

| Recipe | Mutant | IOB status | Hardened attack (Core's verdict) | Mutant attack |
| --- | --- | --- | --- | --- |
| `labels_offchain_withheld` | Input labels go off-chain; the claimant withholds them | T2: = mutant | The claim leaf requires 32 hashlock openings, so the labels appear in the witness. The watcher reads them, evaluates and disproves; the payout fails with `missing-inputs` | Nobody can evaluate; the false claim is paid |
| `garbling_unchecked` | No cut-and-choose; the registered garbling swaps its output decoding | T1: = mutant | k=4 cut-and-choose: all 3 opened instances fail regarbling, so the desk withholds its presignature and the claim fails with `Invalid Schnorr signature` | The evaluator decodes "accept"; the false claim is paid |
| `cut_and_choose_grindable` | The kept index is sha256(commitments) mod k | n/a | The challenger draws randomness after the commitments. The bad instance is opened and the claim is rejected. Escape chance per attempt: 1/4 (this fixture records a caught draw) | The garbler ground its salt 3 times until the bad instance was kept; the false claim is paid |
| `seed_reuse_across_claims` | The prior claim used the same garbling seed | n/a | 32 Δ candidates, none matching; the griefing disprove fails `OP_EQUALVERIFY` and the honest payout confirms | One Δ candidate, reject = accept ⊕ Δ; the honest claim is disproven |
| `output_polarity_swapped` | The disprove leaf hashes the accept label | n/a | The disprove confirms and the payout fails | The disprove fails `OP_EQUALVERIFY`; the false claim is paid |
| `single_watcher_disprove` | Only W's signature opens the disprove leaf; W is offline | single W: = mutant | The desk presigns a disprove with a fixed refund output, and any label holder broadcasts it | The third party's disprove fails with `Invalid Schnorr signature`; the false claim is paid |
| `window_below_latency` | WINDOW 6 against a declared evaluation latency of 8 blocks | WINDOW=6: = mutant | With WINDOW 24, the payout at 6 confirmations is `non-BIP68-final` and the disprove at 8 confirms | The payout confirms at 6; the disprove at 8 fails with `missing-inputs` |
| `payout_csv_removed` | The payout leaf has no CSV | n/a | The early payout is `non-BIP68-final` and the disprove confirms | The payout confirms before evaluation; the disprove fails with `missing-inputs` |
| `payout_sighash_none` | The desk presigns the payout with SIGHASH_NONE | n/a | The rewritten output fails with `Invalid Schnorr signature`; P' is paid | A relayer redirects the payout to itself |
| `claimant_unbonded` | The claim carries no claimant bond | no bond: = mutant | The disproven false claim costs the claimant its 20,000-sat bond, which goes to the watcher | Disproven, but the claimant's loss is 0 sats |

Every benign trajectory paid the honest claim in both profiles. None of these mutants
costs the honest path anything, which is why they would not show up in happy-path
tests.

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
| Reimbursement before the dispute window | `take1_csv_removed`: take 1 confirms, and the late challenge fails with `missing-inputs` | `payout_csv_removed`, `window_below_latency` | **Carried and widened.** BitVM3's window also has to cover off-chain evaluation (about 60 min for M14). A BitVM2 watcher only needs on-chain data and one transaction build |
| Reimbursement not bound to the dispute | `take1_unbound_connector_a` and `take2_unbound_disprove`: the operator is paid after a successful challenge or disprove | Payout and disprove are two leaves of the same claim output | **Removed by construction.** Spending one leaf consumes the other |
| Challenge crowdfunding | `challenge_sighash_all`: the challenger cannot attach funds, and take 1 goes through | No challenge transaction | **Removed** (fewer moving parts, one less presigned policy) |
| Correctness of the disprove computation | `chunk_carry_dropped`: a buggy on-chain chunk lets a wrapped sum stand and also disproves the honest operator | `garbling_unchecked`, `cut_and_choose_grindable`, `output_polarity_swapped` | **Changed.** Correctness moves off-chain into the garbling. Script only checks a hash, so a bad circuit is invisible on-chain and can be caught only by cut-and-choose, which must use challenger randomness |
| Commitment to the inputs | `wots_checksum_unchecked`: commitments are on-chain, so availability is guaranteed. Forgery needs a dropped checksum (here it griefs an honest operator) | `labels_offchain_withheld`, `seed_reuse_across_claims` | **Introduced.** Inputs are labels. Off-chain delivery creates a withholding attack, and label secrecy (Δ) becomes a new asset: a Δ leak lets a holder forge the reject label and grief honest claims |
| Deterrence | `disprove_burn_sighash_none`: a lying operator self-disproves and recovers its stake | `claimant_unbonded` | **Changed.** IOB has no stake to burn, so a false claim costs only fees, and the vault pays those |
| Disprove reward front-running | `disprove_reward_unbound`: **inherent**, confirmed in both profiles. Input 0's SINGLE commits only the burn output, so a relayer rewrites the reward | `single_watcher_disprove` | **Traded.** IOB requires W's signature, which removes front-running but adds single-watcher liveness. A desk-presigned disprove with a fixed output keeps both properties |
| Presigned output binding | (presigned ALL in the baseline) | `payout_sighash_none` | **Carried** |

New in BitVM3, with no BitVM2 counterpart: input-label withholding, unchecked garbling
and grindable cut-and-choose, Δ or seed reuse, and evaluation latency racing the window.
IOB's simpler graph removes three BitVM2 hazards: crowdfunding, connector binding and
reward front-running. It removes front-running only by adding a single watcher.

## Findings for the IOB graph

These are design observations about the concrete target. None of them is an exploit of
the deployed testnet4 vaults, and nothing was broadcast outside regtest.

1. **Label delivery (T2) decides safety, not only liveness.** A claimant who withholds
   labels is paid for a false claim, because the window simply runs out.
   - Putting the labels on-chain closes this at toy scale. The claim grows from 208 to
     961 vB for 32 input bits, about 23.5 vB per bit.
   - At that rate, M14's 8,635,080 input bits would need about 203M vB, far over the
     100k-vB standard limit.
   - A 512-bit statement-only commitment would be about 12k vB. That is the arithmetic
     behind the "statement on-chain, rest by data availability or a succinct wrapper"
     direction in the S6 notes.
2. **The window is close to the evaluation time.** M14 evaluation was measured at about
   60 minutes. At mainnet block rates (Poisson, 6 blocks per hour), the chance that 6
   blocks arrive within 60 minutes is **0.554**. That is before label transfer and
   broadcast. Testnet4's minimum-difficulty blocks can make it worse.

   | Window (blocks) | P(window ends within a 60-min evaluation) | Within 120 min |
   | --- | --- | --- |
   | 6 | 0.554 | 0.980 |
   | 9 | 0.153 | 0.845 |
   | 12 | 0.020 | 0.538 |
   | 18 | 0.0001 | 0.063 |
   | 24 | <0.0001 | 0.0015 |

3. **A single watcher is a liveness and bribery point.** Only W can open the disprove
   leaf. A desk-presigned disprove (`SHA256 <H(reject)> EQUALVERIFY <D> CHECKSIG`, with
   D's presignature over a fixed refund output) lets anyone holding the reject label
   stop a false claim. Because the output stays fixed, it does not bring back BitVM2's
   reward front-running.
4. **A false claim is free.** The vault pays the claim fee, so a disproven claimant loses
   nothing, while each claim forces an M14 evaluation (60 min and 18.4 GB measured) and a
   fresh setup. A claimant bond input on the claim tx, paid to the watcher on disprove,
   makes lying cost something.
5. **One seed per claim.** Free-XOR labels differ by the garbling's Δ. If two claims are
   garbled from the same seed and their handed-over labels differ in any input bit,
   whoever holds both handovers learns Δ. That party can turn the accept label into the
   reject label and disprove an honest claim. Derive each seed from data that is unique
   per claim, such as the vault outpoint and instance name.
6. **Cut-and-choose has to use the challenger's randomness.** Garbling correctness (T1)
   is unchecked today. If a cut-and-choose is added, its kept index must not be a hash
   of the garbler's own commitments: with k=4 the garbler needed 3 salt trials to keep
   its bad instance.

## Fidelity limits

- The circuit is a 16-bit adder check, not a SNARK verifier, so the label counts and
  timings above are scaled.
- The latency recipe's delay is declared, not measured. The garbled evaluation itself
  finishes instantly here.
- One test key stands for the desk committee, and every key is public and deterministic.
- Window and bond values are regtest parameters.
- A relayer that rewrites a payout is assumed to mine its own rewrite. Under full-RBF, an
  unconfirmed early payout can also be replaced by a higher-fee disprove. Neither the fee
  market nor pinning is modeled.
- Regtest uses mainnet standardness rules for these transaction types, but no mempool
  outside the single node exists.
