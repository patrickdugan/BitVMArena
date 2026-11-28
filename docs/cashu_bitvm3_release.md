# BVA-CASHU-RELEASE: red-teaming the proof-backed Cashu release

Status: **replayed and reconstructed on isolated Bitcoin Core 31.1 regtest.**
- **Pinned archive replay (`cashu-release-replay`):** executed (`arena_replayed_regtest`), 10/10 cases met, 0 wallets loaded, offline audit 0 problems (`corpus/examples/native/cashu-release-replay-core31.1.json`).
- **k=4 cut-and-choose ceremony + 10 malicious-garbler attack families (`cashu-release`):** executed (`arena_reconstruction_regtest`), 40/40 trajectories met on Bitcoin Core 31.1 regtest, offline audit 0 problems (`corpus/examples/native/cashu-release-core31.1.json`). Two findings: a single-instance cheat escapes k=4 cut-and-choose 1 time in 4 (the recorded `decoding_polarity_flip` hardened draw did, and the release confirmed), and three hardened families are stopped only by the holder and guardian refusing to sign.
- **Still design hypotheses (not executed):** full-scale 4×971,724,042-gate M14 cut-and-choose execution and re-proved testnet4 release.

## Target (pinned)

- Spiral `cashu/proof-backed-release-evidence` at `9cf56a56d02e8b63de91e435b9fcd7823a66bb9d`,
  `proof-grove/evidence/proof-backed-release/` (evidence archive sha256 `5446141e6c12c5ce4681f9c07a82ad7f1607a7accaadc51726492350db556a9b`).
- Funded target (regtest): reserve `a147db7c…67fb:1` (25,000 sats) and challenger collateral `2ba400f4…4f29:1` (25,250 sats),
  authorization `proof-grove/m14/cashu-joint-release/v2`.
- Recorded honest effect: joint payout `32e9951df57f6cf0687b4682427bcafa5b7f5cc11f4f71f618082cc71884f564` pays the holder 24,750 sats at height 212.

The fixed-target rule applies: an attack scores only if it spends or alters the originally funded reserve (or its authenticated successor). A separately funded weaker vault is a calibration control.

## What executed in Arena

### 1. Pinned archive replay (`arena_replayed_regtest`)

Adapter: `corpus/bitvm_corpus/cashu_replay.py`. Five controls substitute a witness element; `substituted_beneficiary` substitutes an output. The offline audit ties every case's outcome to Core's recorded `testmempoolaccept`/block result (honest txid and block 212, fallback acceptance, `missing-inputs` after release, each control's reject reason) and checks `/Satoshi:31.1.0/`.
Receipt: `corpus/examples/native/cashu-release-replay-core31.1.json` (evidence hash `5d81e7059d1626dc3fc0d5b08957adf750825283289539a766f65ca2e97cd1ea`, Bitcoin Core `/Satoshi:31.1.0/`, `wallets_loaded: 0`, offline audit `0` problems).

| Case | Execution layer | Result | Observed on Core 31.1 |
|---|---|---|---|
| `honest_payout` | `arena_replayed_regtest` | `legitimate_completion=True`, `attacker_success=False` | Confirmed in block 212 (`32e9951d…f564`), 24,750 sats to holder |
| `holder_fallback_before_release` | `arena_replayed_regtest` | `legitimate_completion=True`, `attacker_success=False` | `084310bd…c9e5` accepted at height 211 |
| `holder_fallback_after_release` | `arena_replayed_regtest` | `legitimate_completion=False`, `attacker_success=False` | Rejected (`missing-inputs`) after block 212 |
| `substituted_accept_label` | `arena_replayed_regtest` | `attacker_success=False` | Rejected (`OP_EQUALVERIFY`, wtxid `9bf0adf3…`) |
| `substituted_holder_signature` | `arena_replayed_regtest` | `attacker_success=False` | Rejected (`CHECK(MULTI)SIG`, wtxid `d4b8b7a6…`) |
| `substituted_issuance_preimage` | `arena_replayed_regtest` | `attacker_success=False` | Rejected (`OP_EQUALVERIFY`, wtxid `d15b4a65…`) |
| `substituted_challenger_approval` | `arena_replayed_regtest` | `attacker_success=False` | Rejected (`CHECK(MULTI)SIG`, wtxid `184d72ca…`) |
| `substituted_holder_approval` | `arena_replayed_regtest` | `attacker_success=False` | Rejected (`CHECK(MULTI)SIG`, wtxid `d924cd85…`) |
| `substituted_beneficiary` | `arena_replayed_regtest` | `attacker_success=False` | Rejected (`CHECK(MULTI)SIG`) |
| `reorg_and_timeout_fork` | `arena_replayed_regtest` | `legitimate_completion=True`, `attacker_success=False` | Reorg restored both UTXOs; height 219 fork (`084310bd…` + `95dce011…`) excluded joint release |

### 2. Ported k=4 cut-and-choose ceremony & 10 malicious-garbler attack families (`arena_reconstruction_regtest`)

Module: `corpus/bitvm_corpus/cashu_release.py`
Receipt: `corpus/examples/native/cashu-release-core31.1.json` (evidence hash `20c718b2a23ff2c6d43d299651432cac9ef5f64628c517c794cde58e35d68cba`, Bitcoin Core `/Satoshi:31.1.0/`, 40/40 expectations met, 36 confirmed / 11 rejected transactions, offline audit `0` problems).

The ceremony ports BVA-BITVM3's `k=4` cut-and-choose (`ceremony.py`, `gc.py`, `m14.py`) to the Cashu joint-release contract. The holder and guardian each commit to a reveal keyed by their own secret, the garbler commits to 4 instances, and one draw over both reveals and all 4 commitments picks the kept instance; the other 3 are opened and regarbled. A garbler cheating on one instance escapes exactly when that instance is kept (1/4); cheating on more always leaves a bad instance among the opened ones. Existing `bitvm-arena/...` hash domain tags in `gc.py`, `bitvm2.py`, and `bitvm3.py` are unchanged.

How the receipt separates what Bitcoin decides from what the parties decide:
- Every on-chain verdict is Core's `testmempoolaccept`/block result; the audit rechecks each step against Core's recorded mempool result.
- When the holder or guardian withholds a signature, a non-broadcast `cosigned probe` first asks Core what it would do had both signed. `defense_layer` is `cosigner_veto` when that probe is accepted (only the refusal stopped the release) and `bitcoin_script` when Core rejects it on the label or pin.
- `diverted_principal_sats` is the sum of confirmed outputs paying the attacker's script, read from the raw transactions.
- The selective-failure leak is off-chain: the evaluator's abort is compared between bit 0 and bit 1 of the probed wire, and the audit recomputes it.

| Family | Hardened attack (`leg` / `att` / `unauth` / `diverted`) | Stopped by | Mutant attack (`leg` / `att` / `unauth` / `diverted`) | Benign (both profiles) |
|---|---|---|---|---|
| `wrong_circuit_under_pin` | `F / F / F / 0` | co-signer veto (all 4 instances bad, opening fails; co-signed probe accepted) | `F / T / T / 0` (`k=1` always-accept confirms) | `leg=T, att=F` |
| `leaked_accept_label` | `F / F / F / 0` | Bitcoin script (probe fails `OP_EQUALVERIFY`) | `F / T / T / 0` (label extracted from package) | `leg=T, att=F` |
| `selective_failure` | `T / F / F / 0`, no leak | opening catches the bad instance before evaluation; holder CSV exit | `T / T / F / 0`, bit leaked (abort only for bit 1); release rejected `OP_EQUALVERIFY`, holder CSV exit confirms | `leg=T, att=F` |
| `tape_equivocation` | `F / F / F / 0` | co-signer veto (tables hash mismatch; co-signed probe accepted) | `F / T / T / 0` | `leg=T, att=F` |
| `seed_delta_reuse` | `F / F / F / 0` | Bitcoin script (forged label fails `OP_EQUALVERIFY`) | `F / T / T / 0` (`Delta` recovered, forged accept confirms) | `leg=T, att=F` |
| `decoding_polarity_flip` | **`F / T / T / 0`** | **not stopped**: the draw kept the swapped instance (the 1/4 case) | `F / T / T / 0` | `leg=T, att=F` |
| `withholding` | `T / F / F / 0` | unilateral holder 6-CSV exit confirms 24,750 | `F / T / F / 0` (exit needs challenger, fails `CHECKSIG`) | `leg=T, att=F` |
| `garbler_challenger_collusion` | `F / F / F / 0` | co-signer veto (draw kept the bad instance; holder never signs outputs to the attacker) | `F / T / T / 24750` (steered `kept`, no holder/guardian keys) | `leg=T, att=F` |
| `proof_replay` | `T / F / F / 0` | Bitcoin script (Reserve 2 rejects the replayed label) | `T / T / T / 0` (replayed label releases Reserve 2 to its holder: unauthorized release, no diversion) | `leg=T, att=F` |
| `statement_substitution` | `F / F / F / 0` | Bitcoin script (bound circuit gives the reject label; probe fails `OP_EQUALVERIFY`) | `F / T / T / 24750` (circuit ignores the holder script **and** the reserve leaf drops the holder key) | `leg=T, att=F` |

`proof_replay` scores on a second, separately funded reserve; under the fixed-target rule above it is a calibration control, not an attack on the pinned reserve.

## What remains a design hypothesis (not executed)

1. **Full 971M-gate M14 `k=4` cut-and-choose at scale.** The live `k=4` ceremony in `cashu_release.py` uses `gc.py` free-XOR + half-gates (32 AND gates per instance) standing in for M14's 971,724,042 non-free gates (~1,700 s and ~15.5 GB ciphertext tape per instance in the upstream run).
2. **Testnet4 proof-backed release** (only with explicit broadcast approval, per BVA-BITVM3's gate):
   - The recorded proof cannot be reused: its withdrawal statement pins the regtest genesis and reserve outpoint.
   - Needed: a testnet4 withdrawal record and statement, a funded testnet4 reserve, then a new Core proof (~10 h on an RTX 3050 laptop, ~1.5 h of recursion on 3× A6000 at ~600 s per 128-shard group) and M13/M14.
   - A separate holder-only CSV exit with the same reserve script was broadcast on testnet4 (`380aff24…c8d2`, no proof involved).

## Measured costs from the recorded run (for budgeting)

| Stage | Time | Hardware |
|---|---|---|
| Core proof, 37,309 shards | ~9.7 h (plus replayed checkpoint) | RTX 3050 laptop |
| Recursion, 292 groups of 128 | ~600 s/group | RTX A6000 (Hyperstack), 3 VMs |
| M13 shrink / wrap | ~2 min / ~15 min | RTX 3050 laptop, HDD-backed spill |
| M14 verdict | ~5 min | CPU |
| M14 garbling + independent evaluation | ~47 min (31 GB ciphertexts) | CPU, USB HDD |
