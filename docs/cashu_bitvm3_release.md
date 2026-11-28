# BVA-CASHU-RELEASE: red-teaming the proof-backed Cashu release

Status: **design hypothesis, adapter pending.** Nothing in this document has executed inside Arena yet. The honest
path below is recorded upstream in Spiral; the attacks are specified, not run.

## Target (pinned)

- Spiral `cashu/proof-backed-release-evidence` at `9cf56a56d02e8b63de91e435b9fcd7823a66bb9d`,
  `proof-grove/evidence/proof-backed-release/` (evidence archive sha256 `5446141e…a9b`).
- Funded target (regtest): reserve `a147db7c…67fb:1` (25,000 sats) and challenger collateral `2ba400f4…4f29:1`,
  authorization `proof-grove/m14/cashu-joint-release/v2`.
- Recorded honest effect: joint payout `32e9951d…f564` pays the holder 24,750 sats at height 212.

The fixed-target rule applies: an attack scores only if it spends or alters this reserve (or its authenticated
successor). A separately funded weaker vault is a calibration control.

## What the recorded evidence already rules out

From the upstream recipient verification (walletless Core replay, 0 wallets, 103 blocks):

| Control | Result |
|---|---|
| substituted accept label | rejected (`OP_EQUALVERIFY`) |
| substituted holder signature / holder approval / challenger approval | rejected (`CHECK(MULTI)SIG`) |
| substituted issuance preimage | rejected (`OP_EQUALVERIFY`) |
| substituted beneficiary | rejected |
| one-byte-mutated proof input | M14 verdict `unbound` (no accept) |
| holder CSV fallback | valid before release, `missing-inputs` after |

## Why a malicious garbler is still open

The recorded run used a **trusted single-use garbler** (`seed_source: private-os-random`, 256-bit seed) and **no
cut-and-choose**. The evaluator checks the published package against a setup pin, but the garbler produced that pin.
Every control above assumes an honest garbler. The families to execute:

| Family | Attack | Expected defence once hardened |
|---|---|---|
| Wrong circuit | Garble a circuit that outputs accept for any input, under a self-consistent setup pin | Cut-and-choose: opened instances must match the pinned M14 circuit hash |
| Leaked accept label | Encode the accept label so it is recoverable from the package before evaluation | Opened-instance audit; label commitments bound to the circuit |
| Selective failure | Corrupt input labels for one bit value to learn the holder's proof bits | Input-label consistency checks / OT with checks |
| Tape equivocation | Serve a ciphertext tape different from the committed ciphertext hash | Evaluator hashes the tape before evaluating (already authenticated upstream: 971,724,042 ciphertexts) |
| Seed / Δ reuse | Reuse the garbling seed or free-XOR offset across two withdrawals | Fresh-seed attestation + seed-reuse recipe from BVA-BITVM3 |
| Decoding polarity | Swap the output decoding so reject decodes as accept | Opened-instance decoding check |
| Withholding | Withhold tables or labels so the holder cannot evaluate | Holder-only CSV exit must stay live (invariant) |
| Collusion | Garbler + challenger coordinate the joint-release approvals | Port BVA-BITVM3 `setup_*` collusion recipes |
| Proof replay | Reuse the accepted wrap for a second reserve or beneficiary | Statement binds reserve outpoint and holder script |
| Statement substitution | A different withdrawal under the same program key | Statement hash pinned in the claim |

Scoring follows `AGENTS.md`: report legitimate completion, unauthorized release and diverted principal separately;
hardened vs mutant profiles; benign vs attack trajectories.

## Plan

1. **Replay adapter.** Re-run the pinned archive inside Arena: walletless Core block replay, the six substitution
   rejections and the honest payout. This moves the campaign to `arena_replayed_regtest`.
2. **Ceremony.** Replace the trusted garbler with the BVA-BITVM3 k=4 cut-and-choose ceremony at M14 scale, with the
   kept instance chosen by the holder or guardian, not the garbler.
3. **Recipes.** Execute each family above as hardened/mutant × benign/attack on regtest with receipts carrying the
   required fields.
4. **Testnet4** (only with explicit broadcast approval, per BVA-BITVM3's gate):
   - The recorded proof cannot be reused: its withdrawal statement pins the regtest genesis and reserve outpoint.
   - Needed: a testnet4 withdrawal record and statement, a funded testnet4 reserve, then a new Core proof (≈10 h on an
     RTX 3050 laptop, ≈1.5 h of recursion on 3× A6000 at ~600 s per 128-shard group) and M13/M14.
   - A testnet4 reserve key already exists from the proving PC, and a holder-only CSV exit with the same reserve script
     was broadcast there (`380aff24…c8d2`, no proof involved).

## Measured costs from the recorded run (for budgeting)

| Stage | Time | Hardware |
|---|---|---|
| Core proof, 37,309 shards | ~9.7 h (plus replayed checkpoint) | RTX 3050 laptop |
| Recursion, 292 groups of 128 | ~600 s/group | RTX A6000 (Hyperstack), 3 VMs |
| M13 shrink / wrap | ~2 min / ~15 min | RTX 3050 laptop, HDD-backed spill |
| M14 verdict | ~5 min | CPU |
| M14 garbling + independent evaluation | ~47 min (31 GB ciphertexts) | CPU, USB HDD |
