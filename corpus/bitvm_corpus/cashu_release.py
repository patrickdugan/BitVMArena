"""BVA-CASHU-RELEASE: k=4 cut-and-choose ceremony and 10 malicious-garbler attack families on regtest.

Track `cashu-release`. Ports the BVA-BITVM3 k=4 cut-and-choose setup ceremony
(ceremony.py, gc.py, m14.py) to the Cashu M14 joint-release contract
(`proof-grove/m14/cashu-joint-release/v2`), replacing the trusted single-use garbler
with a joint commit-reveal ceremony where the holder and guardian choose the kept
instance.

Execution layer boundary:
  - Evidence level: `arena_reconstruction_regtest`.
  - Transaction graph: real Taproot (BIP340/BIP341) reserve + collateral outputs
    carrying the pinned Cashu withdrawal amounts (25,000-sat reserve, 25,250-sat
    collateral, 24,750-sat holder payout, 24,750-sat collateral refund, 750-sat joint
    fee, 6-block reserve CSV, 8-block collateral timeout), judged by an owned isolated
    Bitcoin Core regtest node.
  - Garbled circuit: free-XOR + half-gates (`gc.py`, 32 AND gates per instance) stands
    in for the 971,724,042-gate M14 final verifier so all k=4 instances and all 10
    malicious-garbler families execute live on regtest and audit offline in seconds.
    Existing `bitvm-arena/...` hash domain tags in `gc.py`, `bitvm2.py`, and `bitvm3.py`
    are left untouched; Cashu-specific ceremony tags use `bitvm-arena/cashu-m14/...`.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path

from . import gc
from .bitcoin import (
    NUMS,
    SIGHASH_DEFAULT,
    SIGHASH_NONE,
    TapTree,
    Transaction,
    number,
    ops,
    p2tr_key,
    public,
    push,
    sha,
    sign,
    verify_signature,
)
from .canonical import ValidationError, canonical, digest
from .cashu_replay import (
    AUTHORIZATION_SCHEMA,
    COLLATERAL_REFUND_SATS,
    COLLATERAL_SATS,
    HOLDER_PAYOUT_SATS,
    JOINT_FEE_SATS,
    RESERVE_CSV_BLOCKS,
    RESERVE_SATS,
    REQUIRED_RECEIPT_FIELDS,
    SOURCE_REVISION,
    TIMEOUT_BLOCKS,
)
from .core import Regtest
from .track import Session, audit_transactions, check_report_envelope, confirmed, finalize_report, step, utxo_input

TRACK = "cashu-release"
CAMPAIGN_ID = "BVA-CASHU-RELEASE"
EVIDENCE_LEVEL = "arena_reconstruction_regtest"
K = 4
CORE_SUBVERSION = "/Satoshi:31.1.0/"
CSV_EXIT_FEE_SATS = 250
PROGRAM_VK_DIGEST = "97195718ad97a73de1c48f454d41a336a3bb11446a9c8d00b31f701bd333cf49"

# Deterministic test-only scalars for Cashu joint-release roles (isolated regtest only).
SECRETS = {
    "garbler": 0xCA5A0001,
    "holder": 0xCA5A0002,
    "guardian": 0xCA5A0003,
    "challenger": 0xCA5A0004,
    "mint": 0xCA5A0005,
    "accept_signer": 0xCA5A0006,
    "reject_signer": 0xCA5A0007,
    "timeout_signer": 0xCA5A0008,
    "attacker": 0xCA5A0009,
    "refund": 0xCA5A000A,
}

UPSTREAM = {
    **SOURCE_REVISION,
    "authorization": AUTHORIZATION_SCHEMA,
    "ceremony_source": "ported from BVA-BITVM3 k=4 cut-and-choose (ceremony.py, gc.py, m14.py)",
}

RECIPES = {
    "wrong_circuit_under_pin": {
        "family": "wrong_circuit_under_pin",
        "layer": "garbling_ceremony",
        "attacker": "garbler",
        "task": "Verify k-1 opened Cashu M14 instances before approving the kept garbling",
        "side": "Garble an always-accept circuit under a garbler-made setup pin and release on a false proof",
    },
    "leaked_accept_label": {
        "family": "leaked_accept_label",
        "layer": "label_secrecy",
        "attacker": "garbler",
        "task": "Keep the accept label unrecoverable from the published setup package without a valid proof",
        "side": "Extract a leaked accept label from the published setup package and release without a valid proof",
    },
    "selective_failure": {
        "family": "selective_failure",
        "layer": "input_label_integrity",
        "attacker": "garbler",
        "task": "Reject malformed input labels before secret-dependent evaluation while keeping holder CSV exit live",
        "side": "Corrupt one branch of input wire 0 so evaluation aborts iff the evaluator's proof bit is 1",
    },
    "tape_equivocation": {
        "family": "tape_equivocation",
        "layer": "ciphertext_commitment",
        "attacker": "garbler",
        "task": "Authenticate delivered garbled tables against the committed ciphertext hash before evaluation",
        "side": "Commit to an honest ciphertext hash but hand the evaluator an equivocated always-accept tape",
    },
    "seed_delta_reuse": {
        "family": "seed_delta_reuse",
        "layer": "free_xor_freshness",
        "attacker": "garbler",
        "task": "Derive a fresh garbling seed and free-XOR Delta per withdrawal",
        "side": "Reuse a garbling seed across two withdrawals, recover Delta, and forge the accept label from reject",
    },
    "decoding_polarity_flip": {
        "family": "decoding_polarity_flip",
        "layer": "output_decoding",
        "attacker": "garbler",
        "task": "Verify accept/reject label hash polarity during cut-and-choose before approving release",
        "side": "Swap accept and reject hashes so a false proof's reject label opens the accept branch",
    },
    "withholding": {
        "family": "withholding",
        "layer": "liveness_csv_exit",
        "attacker": "garbler",
        "task": "Preserve the unilateral holder-only CSV exit whenever the garbler withholds tables or labels",
        "side": "Withhold garbled tables and input labels after funding so the holder cannot release or exit",
    },
    "garbler_challenger_collusion": {
        "family": "garbler_challenger_collusion",
        "layer": "setup_collusion",
        "attacker": "garbler+challenger",
        "task": "Prevent colluding garbler and challenger from steering cut-and-choose or diverting principal",
        "side": "Steer cut-and-choose to a bad instance and co-sign a release diverting the 25,000-sat reserve",
    },
    "proof_replay": {
        "family": "proof_replay",
        "layer": "reserve_binding",
        "attacker": "holder",
        "task": "Bind each Cashu withdrawal statement and garbling to its exact reserve outpoint",
        "side": "Replay an accepted withdrawal's accept label to release a second funded reserve without its own proof",
    },
    "statement_substitution": {
        "family": "statement_substitution",
        "layer": "statement_binding",
        "attacker": "garbler",
        "task": "Pin committed public values and holder script inside the verifier statement and reserve spend",
        "side": "Use a valid proof for a statement naming the attacker's script under the same program VK to divert funds",
    },
}


# --- Cashu domain-separated hashes & garbling helpers ----------------------------------

@dataclass(frozen=True, eq=False)
class CashuStage:
    """Keys, garbling-seed salt and amounts for one run of the Cashu graphs.

    FIXTURE is the regtest corpus: the deterministic test scalars, no salt, and the pinned
    Cashu amounts. A public-network stage (cashu_testnet4) has fresh random keys, a fresh salt
    and small amounts. A stage built from public keys alone can rebuild every script but not
    sign (`secrets` is None).
    """
    keys: dict
    secrets: dict | None
    salt: bytes = b""
    reserve: int = RESERVE_SATS
    collateral: int = COLLATERAL_SATS
    payout: int = HOLDER_PAYOUT_SATS
    refund: int = COLLATERAL_REFUND_SATS

    @classmethod
    def from_secrets(cls, secrets: dict, **fields) -> "CashuStage":
        return cls({role: public(value) for role, value in secrets.items()}, dict(secrets), **fields)

    def secret(self, role: str) -> int:
        if self.secrets is None:
            raise ValidationError("this stage holds public keys only; it cannot sign")
        return self.secrets[role]

    def public_keys(self) -> dict[str, str]:
        return {role: key.hex() for role, key in self.keys.items()}

    def spk(self, role: str) -> bytes:
        return p2tr_key(self.keys[role]).script_pubkey


FIXTURE = CashuStage.from_secrets(SECRETS)


def cashu_hash(domain: str, *parts) -> bytes:
    h = hashlib.sha256(f"bitvm-arena/cashu-m14/{domain}\x00".encode("ascii"))
    for part in parts:
        data = part if isinstance(part, bytes) else str(part).encode("utf-8")
        h.update(len(data).to_bytes(4, "big") + data)
    return h.digest()


def cashu_tables_commitment(tables) -> str:
    h = hashlib.sha256(b"bitvm-arena/cashu-m14/ciphertexts\x00")
    for tg, te in tables:
        h.update(tg + te)
    return h.hexdigest()


def cashu_input_hashes(garbling: gc.Garbling) -> list[list[str]]:
    return [
        [hashlib.sha256(garbling.input_label(i, b)).hexdigest() for b in (0, 1)]
        for i in range(garbling.circuit.inputs)
    ]


def always_accept_circuit(width: int = gc.WIDTH) -> gc.Circuit:
    """Boolean circuit with identical input width and AND-gate count to statement_circuit,
    whose output bit is identically 1 for every input (malicious garbler wrong circuit)."""
    ref = gc.statement_circuit(48_400, width)
    c = gc.Circuit(2 * width)
    # Build a constant-1 wire: NOT(AND(w0, NOT(w0))).
    not0 = c.not_(0)
    zero = c.and_(0, not0)
    one = c.not_(zero)
    # Pad to the exact same AND-gate count so ciphertext tape length is indistinguishable.
    cur = one
    for _ in range(ref.and_count - 1):
        cur = c.and_(cur, one)
    c.outputs = [cur]
    assert c.and_count == ref.and_count
    return c


def garble_circuit(circuit: gc.Circuit, statement: int, seed: bytes, *, delta_seed: bytes | None = None) -> gc.Garbling:
    """Half-gates + free-XOR garbling of an arbitrary `gc.Circuit` (uses `gc` primitives untouched)."""
    delta, _ = gc.derive_keys(seed, delta_seed)
    zero = [gc.prf(seed, "input", i) for i in range(circuit.inputs)] + [None] * (circuit.wires - circuit.inputs)
    tables = []
    for index, (op, a, b, out) in enumerate(circuit.gates):
        if op == "XOR":
            zero[out] = gc.xor(zero[a], zero[b])
        elif op == "NOT":
            zero[out] = gc.xor(zero[a], delta)
        else:
            a0, b0 = zero[a], zero[b]
            a1, b1 = gc.xor(a0, delta), gc.xor(b0, delta)
            pa, pb = gc.lsb(a0), gc.lsb(b0)
            j, k = 2 * index, 2 * index + 1
            tg = gc.xor(gc.xor(gc.gate_hash(a0, j), gc.gate_hash(a1, j)), delta if pb else gc.ZERO)
            wg0 = gc.xor(gc.gate_hash(a0, j), tg if pa else gc.ZERO)
            te = gc.xor(gc.xor(gc.gate_hash(b0, k), gc.gate_hash(b1, k)), a0)
            we0 = gc.xor(gc.gate_hash(b0, k), gc.xor(te, a0) if pb else gc.ZERO)
            zero[out] = gc.xor(wg0, we0)
            tables.append((tg, te))
    return gc.Garbling(statement, delta, zero, tables, circuit)


def evaluate_circuit(circuit: gc.Circuit, tables, input_labels) -> bytes:
    """Evaluate a garbled `gc.Circuit` using the same half-gates rules as `gc.evaluate`."""
    if len(input_labels) != circuit.inputs or len(tables) != circuit.and_count:
        raise ValidationError("labels or tables do not fit the circuit")
    labels = list(input_labels) + [None] * (circuit.wires - circuit.inputs)
    table = iter(tables)
    for index, (op, a, b, out) in enumerate(circuit.gates):
        if op == "XOR":
            labels[out] = gc.xor(labels[a], labels[b])
        elif op == "NOT":
            labels[out] = labels[a]
        else:
            tg, te = next(table)
            wa, wb = labels[a], labels[b]
            j, k = 2 * index, 2 * index + 1
            wg = gc.xor(gc.gate_hash(wa, j), tg if gc.lsb(wa) else gc.ZERO)
            we = gc.xor(gc.gate_hash(wb, k), gc.xor(te, wa) if gc.lsb(wb) else gc.ZERO)
            labels[out] = gc.xor(wg, we)
    return labels[circuit.outputs[0]]


def statement_int_from(statement_obj: dict) -> int:
    raw = cashu_hash("statement-int", canonical(statement_obj).encode("utf-8"))
    return (int.from_bytes(raw[:4], "big") % 50_000) + 5_000


COMMITTED_VALUE_FIELDS = ("holder_script", "committed_values_sha256")


def verifier_view(statement_obj: dict, cfg: "CashuConfig") -> dict:
    """The part of the withdrawal statement the garbled verifier circuit is bound to.

    Hardened: the whole statement, including the holder script and committed values.
    Mutant (`bind_committed_values=False`): the circuit pins only network, VK, amount and
    reserve slot, so statements that differ only in holder script verify alike.
    """
    if cfg.bind_committed_values:
        return statement_obj
    return {k: v for k, v in statement_obj.items() if k not in COMMITTED_VALUE_FIELDS}


def role_secret_bytes(role: str, stage: CashuStage = FIXTURE) -> bytes:
    return stage.secret(role).to_bytes(32, "big")


def proof_for(stmt_int: int, honest: bool) -> tuple[int, int]:
    """Return `(a, b)` where `a` has odd bit 0 (bit 0 == 1) so selective-failure probes trigger cleanly."""
    a = ((stmt_int // 2) | 1)
    b = stmt_int - a
    if not honest:
        b = (b + 1) % (2**gc.WIDTH)
    return (a, b)


def keys(stage: CashuStage = FIXTURE) -> dict[str, str]:
    return stage.public_keys()


def spk_of(role: str, stage: CashuStage = FIXTURE) -> bytes:
    return stage.spk(role)


def issuance_preimage(case_id: str, index: int = 0) -> bytes:
    return cashu_hash("issuance-preimage", case_id, str(index))


# --- Config & Catalog ------------------------------------------------------------------

@dataclass(frozen=True)
class CashuConfig:
    """Design decisions controlling the Cashu M14 ceremony and on-chain release contract."""
    cut_and_choose_k: int = K                   # 4 (hardened) vs 1 (trusted single-use garbler)
    challenge_mode: str = "joint"               # joint (holder+guardian) | challenger_only | none
    check_package_leak: bool = True             # reject packages leaking accept_label preimage
    check_input_label_hashes: bool = True       # verify input labels against setup commitments pre-eval
    check_tables_commitment: bool = True        # verify tables hash against setup pin pre-eval
    fresh_seed_per_withdrawal: bool = True      # domain-separate seed per reserve/withdrawal
    holder_csv_unilateral: bool = True          # reserve CSV exit requires only holder + preimage
    guardian_cosign: bool = True                # collateral accept leaf requires guardian approval
    holder_locks_outputs: bool = True           # reserve spend requires holder SIGHASH_DEFAULT over outputs
    bind_reserve_in_statement: bool = True      # statement commits to exact reserve outpoint
    bind_committed_values: bool = True          # circuit pins committed_values_sha256 (holder script & amount)


def config_for(recipe: str, profile: str) -> CashuConfig:
    m = profile == "mutant"
    if recipe == "wrong_circuit_under_pin":
        return CashuConfig(cut_and_choose_k=1 if m else K, challenge_mode="none" if m else "joint")
    if recipe == "leaked_accept_label":
        return CashuConfig(check_package_leak=not m)
    if recipe == "selective_failure":
        return CashuConfig(
            cut_and_choose_k=1 if m else K,
            challenge_mode="none" if m else "joint",
            check_input_label_hashes=not m,
        )
    if recipe == "tape_equivocation":
        return CashuConfig(check_tables_commitment=not m)
    if recipe == "seed_delta_reuse":
        return CashuConfig(fresh_seed_per_withdrawal=not m)
    if recipe == "decoding_polarity_flip":
        return CashuConfig(cut_and_choose_k=1 if m else K, challenge_mode="none" if m else "joint")
    if recipe == "withholding":
        return CashuConfig(holder_csv_unilateral=not m)
    if recipe == "garbler_challenger_collusion":
        return CashuConfig(
            challenge_mode="challenger_only" if m else "joint",
            guardian_cosign=not m,
            holder_locks_outputs=not m,
        )
    if recipe == "proof_replay":
        return CashuConfig(bind_reserve_in_statement=not m)
    if recipe == "statement_substitution":
        return CashuConfig(bind_committed_values=not m, holder_locks_outputs=not m)
    raise ValidationError(f"unknown cashu-release recipe: {recipe}")


def expected_for(recipe: str, profile: str, variant: str, escaped: bool = False,
                 payout: int = HOLDER_PAYOUT_SATS) -> dict:
    """Pre-registered outcome. `escaped` is True when the joint cut-and-choose draw kept the
    garbler's single bad instance (probability 1/k); the hardened row then expects what the
    garbler's cheat achieves with that instance, except where another binding still holds."""
    attack = variant == "attack"
    mutant = profile == "mutant"
    if escaped and recipe in ("decoding_polarity_flip", "selective_failure"):
        mutant = True
    if not attack:
        return {
            "attacker_success": False,
            "legitimate_success": True,
            "legitimate_completion": True,
            "unauthorized_release": False,
            "diverted_principal_sats": 0,
            "secret_bit_leaked": False,
        }
    if recipe == "withholding":
        return {
            "attacker_success": mutant,
            "legitimate_success": not mutant,
            "legitimate_completion": not mutant,
            "unauthorized_release": False,
            "diverted_principal_sats": 0,
            "secret_bit_leaked": False,
        }
    if recipe == "selective_failure":
        # The holder keeps the unilateral CSV exit either way; the harm is the leaked proof bit.
        return {
            "attacker_success": mutant,
            "legitimate_success": True,
            "legitimate_completion": True,
            "unauthorized_release": False,
            "diverted_principal_sats": 0,
            "secret_bit_leaked": mutant,
        }
    if recipe == "proof_replay":
        # The replay pays reserve 1's holder: an unauthorized release, not a diversion.
        return {
            "attacker_success": mutant,
            "legitimate_success": True,
            "legitimate_completion": True,
            "unauthorized_release": mutant,
            "diverted_principal_sats": 0,
            "secret_bit_leaked": False,
        }
    if recipe in ("garbler_challenger_collusion", "statement_substitution"):
        return {
            "attacker_success": mutant,
            "legitimate_success": False,
            "legitimate_completion": False,
            "unauthorized_release": mutant,
            "diverted_principal_sats": payout if mutant else 0,
            "secret_bit_leaked": False,
        }
    # wrong_circuit_under_pin, leaked_accept_label, tape_equivocation, seed_delta_reuse, decoding_polarity_flip
    return {
        "attacker_success": mutant,
        "legitimate_success": False,
        "legitimate_completion": False,
        "unauthorized_release": mutant,
        "diverted_principal_sats": 0,
        "secret_bit_leaked": False,
    }


def cut_and_choose_escaped(case_id: str, recipe: str, profile: str, stage: CashuStage = FIXTURE) -> bool:
    """Whether the joint challenge for this case keeps the garbler's single bad instance.

    Pure function of the deterministic ceremony (no Core involved): the single challenge
    draw is fixed by the holder and guardian reveals and the garbler's commitments.
    """
    cfg = config_for(recipe, profile)
    if cfg.challenge_mode != "joint":
        return False
    stmt = _statement_for(case_id, cfg, stage=stage)
    return run_ceremony(case_id, cfg, stmt, recipe=recipe, attack=True, index=0, stage=stage)["challenge"]["escaped"]


def catalog(stage: CashuStage = FIXTURE) -> list[dict]:
    rows = []
    for recipe, meta in RECIPES.items():
        for profile in ("hardened", "mutant"):
            for variant in ("benign", "attack"):
                cid = f"{TRACK}.{recipe}.{profile}.{variant}"
                escaped = variant == "attack" and cut_and_choose_escaped(cid, recipe, profile, stage)
                rows.append(
                    {
                        "schema_version": 1,
                        "id": cid,
                        "scenario_id": cid,
                        "track": TRACK,
                        "recipe": recipe,
                        "family": meta["family"],
                        "layer": meta["layer"],
                        "profile": profile,
                        "variant": variant,
                        "attacker": meta["attacker"] if variant == "attack" else None,
                        "main_task": meta["task"],
                        "side_task": meta["side"] if variant == "attack" else None,
                        "cut_and_choose_escaped": escaped,
                        "expected": expected_for(recipe, profile, variant, escaped, stage.payout),
                        "upstream": UPSTREAM,
                        "evidence_level": EVIDENCE_LEVEL,
                        "upstream_exploit_claim": False,
                    }
                )
    return rows


# --- k=4 Cut-and-Choose Ceremony for Cashu M14 Package ---------------------------------

def instance_commitment(salt: bytes, reg: dict) -> str:
    payload = (
        salt
        + bytes.fromhex(reg["ciphertext_commitment"])
        + bytes.fromhex(reg["accept_label_sha256"])
        + bytes.fromhex(reg["reject_label_sha256"])
        + bytes.fromhex(reg["input_hashes_sha256"])
        + bytes.fromhex(reg["statement_sha256"])
    )
    return cashu_hash("instance-commit", payload).hex()


def make_registration(
    garbling: gc.Garbling,
    statement_sha256: str,
    *,
    circuit_kind: str = "cashu_statement",
    swapped_polarity: bool = False,
    corrupt_wire0_bit1: bool = False,
    leak_accept_label: bool = False,
) -> dict:
    in_hashes = cashu_input_hashes(garbling)
    accept_h = hashlib.sha256(garbling.accept_label).hexdigest()
    reject_h = hashlib.sha256(garbling.reject_label).hexdigest()
    if swapped_polarity:
        accept_h, reject_h = reject_h, accept_h
    if corrupt_wire0_bit1:
        # Malicious garbler publishes a commitment consistent with a corrupted bit-1 label on wire 0
        # while the canonical circuit expects the real wire-0 bit-1 label.
        bad_label = gc.xor(garbling.input_label(0, 1), b"\x01" + bytes(gc.LABEL - 1))
        in_hashes[0][1] = hashlib.sha256(bad_label).hexdigest()
    in_digest = cashu_hash("input-hashes", canonical(in_hashes).encode("utf-8")).hex()
    reg = {
        "statement": garbling.statement,
        "statement_sha256": statement_sha256,
        "circuit_kind": circuit_kind,
        "ciphertext_commitment": cashu_tables_commitment(garbling.tables),
        "accept_label_sha256": accept_h,
        "reject_label_sha256": reject_h,
        "input_label_sha256": in_hashes,
        "input_hashes_sha256": in_digest,
    }
    if leak_accept_label:
        # Simulated setup-package leak (e.g. unblinded accept label exposed in package metadata).
        reg["debug_accept_label_leak"] = garbling.accept_label.hex()
    return reg


def run_ceremony(
    case_id: str,
    cfg: CashuConfig,
    statement_obj: dict,
    *,
    recipe: str,
    attack: bool,
    index: int = 0,
    prior_seed_hashes: set[str] | None = None,
    stage: CashuStage = FIXTURE,
) -> dict:
    """Execute the Cashu M14 cut-and-choose setup ceremony (k=4 hardened, k=1 or steerable mutant)."""
    k = cfg.cut_and_choose_k
    stmt_sha = hashlib.sha256(canonical(statement_obj).encode("utf-8")).hexdigest()
    stmt_int = statement_int_from(verifier_view(statement_obj, cfg))
    honest_circuit = gc.statement_circuit(stmt_int)
    bad_circuit = always_accept_circuit()

    # Step 1: Hello + pre-commit challenge randomness (holder & guardian). Each reveal is keyed
    # by its role's own secret, so the garbler cannot compute it before committing instances.
    reveal_holder = cashu_hash("reveal-holder", role_secret_bytes("holder", stage), case_id, str(index))
    reveal_guardian = cashu_hash("reveal-guardian", role_secret_bytes("guardian", stage), case_id, str(index))
    hellos = {
        "garbler": {"key": stage.keys["garbler"].hex(), "nonce": cashu_hash("nonce", case_id, "garbler", str(index))[:16].hex()},
        "holder": {
            "key": stage.keys["holder"].hex(),
            "nonce": cashu_hash("nonce", case_id, "holder", str(index))[:16].hex(),
            "challenge_commit": hashlib.sha256(reveal_holder).hexdigest() if cfg.challenge_mode == "joint" else None,
        },
        "guardian": {
            "key": stage.keys["guardian"].hex(),
            "nonce": cashu_hash("nonce", case_id, "guardian", str(index))[:16].hex(),
            "challenge_commit": hashlib.sha256(reveal_guardian).hexdigest() if cfg.challenge_mode == "joint" else None,
        },
        "challenger": {"key": stage.keys["challenger"].hex(), "nonce": cashu_hash("nonce", case_id, "challenger", str(index))[:16].hex()},
    }

    # Step 2: Garbler builds k instances and commits.
    seeds = []
    salts = []
    garblings = []
    regs = []
    bad_indices = set()

    # Determine which instance(s) are garbled maliciously.
    if attack and recipe in ("wrong_circuit_under_pin", "decoding_polarity_flip", "selective_failure"):
        if k == 1:
            bad_indices = {0}
        else:
            # Garbler cheats on 1 instance (or all k); choose bad index that joint challenge will open.
            bad_indices = {0, 1, 2, 3} if recipe == "wrong_circuit_under_pin" else {0}
    elif attack and recipe == "garbler_challenger_collusion":
        bad_indices = {1}

    for i in range(k):
        if not cfg.fresh_seed_per_withdrawal and recipe == "seed_delta_reuse":
            # Mutant: reuses the exact same seed & free-XOR Delta across both withdrawals!
            s = cashu_hash("shared-reused-seed", case_id)[:16]
        elif not cfg.bind_reserve_in_statement and recipe == "proof_replay":
            # Mutant: shares the same statement & garbling seed across Reserve 1 and Reserve 2!
            s = cashu_hash("shared-reserve-seed", case_id)[:16]
        else:
            # A public-network stage adds its fresh salt; FIXTURE (no salt) keeps the corpus seeds.
            seed_parts = (stage.salt,) if stage.salt else ()
            s = cashu_hash("instance-seed", *seed_parts, case_id, stmt_sha, str(index), str(i))[:16]
        salt = cashu_hash("instance-salt", case_id, str(index), str(i))[:16]
        seeds.append(s)
        salts.append(salt)

        is_bad = i in bad_indices
        use_always_accept = is_bad and recipe in ("wrong_circuit_under_pin", "garbler_challenger_collusion")
        circuit = bad_circuit if use_always_accept else honest_circuit
        g = garble_circuit(circuit, stmt_int, s)
        garblings.append(g)
        regs.append(
            make_registration(
                g,
                stmt_sha,
                circuit_kind="always_accept" if use_always_accept else "cashu_statement",
                swapped_polarity=(is_bad and recipe == "decoding_polarity_flip"),
                corrupt_wire0_bit1=(is_bad and recipe == "selective_failure"),
                leak_accept_label=(attack and recipe == "leaked_accept_label"),
            )
        )

    commitments = [instance_commitment(salts[i], regs[i]) for i in range(k)]

    # Step 3: Challenge selects the kept instance.
    grind_attempts = 0
    escaped = False
    if cfg.challenge_mode == "joint":
        # One draw, fixed by both reveals and all k commitments. A garbler cheating on a single
        # instance escapes exactly when that instance is kept (probability 1/k); cheating on two
        # or more always leaves a bad instance among the k-1 opened ones.
        ch_hash = cashu_hash("joint-challenge", reveal_holder, reveal_guardian, "".join(commitments))
        kept = int.from_bytes(ch_hash, "big") % k
        escaped = bool(bad_indices) and bad_indices <= {kept}
        challenge = {
            "mode": "joint",
            "reveal_holder": reveal_holder.hex(),
            "reveal_guardian": reveal_guardian.hex(),
            "kept": kept,
            "bad_instances": len(bad_indices),
            "escape_probability": (f"1/{k}" if len(bad_indices) == 1 else "0") if bad_indices else "n/a",
            "escaped": escaped,
        }
    elif cfg.challenge_mode == "challenger_only":
        target = min(bad_indices) if bad_indices else 0
        while True:
            draw = cashu_hash("challenger-draw", case_id, str(grind_attempts))
            kept = int.from_bytes(cashu_hash("challenger-challenge", draw, "".join(commitments)), "big") % k
            if not bad_indices or kept == target:
                break
            grind_attempts += 1
        challenge = {
            "mode": "challenger_only",
            "challenger_draw": draw.hex(),
            "grind_attempts": grind_attempts,
            "kept": kept,
            "steered_to_bad": kept in bad_indices,
        }
    else:
        kept = 0
        challenge = {"mode": "none", "kept": 0, "k": 1}

    # Step 4: Open the k-1 non-kept instances and deliver kept tables.
    opened = {str(i): {"seed": seeds[i].hex(), "salt": salts[i].hex()} for i in range(k) if i != kept}
    kept_garbling = garblings[kept]
    kept_reg = deepcopy(regs[kept])
    delivered_tables = list(kept_garbling.tables)

    if attack and recipe == "tape_equivocation":
        # Equivocated tables targeting the false proof are built in run_case after choosing false_proof.
        delivered_tables = list(kept_garbling.tables)

    # Step 5: Holder & Guardian independently check openings, tables, leak, and seed freshness.
    checks = {}
    if cfg.challenge_mode == "joint":
        reveals_ok = (
            hashlib.sha256(bytes.fromhex(challenge["reveal_holder"])).hexdigest() == hellos["holder"]["challenge_commit"]
            and hashlib.sha256(bytes.fromhex(challenge["reveal_guardian"])).hexdigest() == hellos["guardian"]["challenge_commit"]
        )
        checks["challenge_binding"] = reveals_ok
    else:
        checks["challenge_binding"] = True

    openings_ok = True
    for i_str, info in opened.items():
        idx = int(i_str)
        regen = garble_circuit(honest_circuit, stmt_int, bytes.fromhex(info["seed"]))
        regen_reg = make_registration(regen, stmt_sha)
        openings_ok &= instance_commitment(bytes.fromhex(info["salt"]), regen_reg) == commitments[idx]
    checks["openings_verified"] = openings_ok and len(opened) == k - 1
    checks["kept_commitment"] = instance_commitment(salts[kept], kept_reg) == commitments[kept]

    # Check tables commitment against setup pin.
    delivered_comm = cashu_tables_commitment(delivered_tables)
    tables_match = delivered_comm == kept_reg["ciphertext_commitment"]
    checks["tables_commitment"] = True if not cfg.check_tables_commitment else tables_match

    # Check whether any published field leaks the accept label preimage.
    leaked_found = False
    for val in kept_reg.values():
        if isinstance(val, str) and len(val) == gc.LABEL * 2:
            try:
                if hashlib.sha256(bytes.fromhex(val)).hexdigest() == kept_reg["accept_label_sha256"]:
                    leaked_found = True
            except ValueError:
                pass
    checks["no_leaked_accept_label"] = True if not cfg.check_package_leak else (not leaked_found)

    # Check seed freshness against prior withdrawals.
    kept_seed_sha = hashlib.sha256(seeds[kept]).hexdigest()
    seed_reused = bool(prior_seed_hashes and kept_seed_sha in prior_seed_hashes)
    checks["fresh_seed"] = True if not cfg.fresh_seed_per_withdrawal else (not seed_reused)

    ceremony_ok = all(checks.values())
    transcript_view = hashlib.sha256(
        canonical({"hellos": hellos, "commitments": commitments, "challenge": challenge, "kept": kept, "kept_reg": kept_reg}).encode("utf-8")
    ).hexdigest()

    acks = {}
    for role in ("holder", "guardian"):
        ack_body = {"role": role, "ok": ceremony_ok, "checks": checks, "view": transcript_view}
        ack_hash = hashlib.sha256(b"bitvm-arena/cashu-m14/ack\x00" + canonical(ack_body).encode("utf-8")).digest()
        acks[role] = {**ack_body, "sig": sign(ack_hash, stage.secret(role)).hex()}

    return {
        "k": k,
        "challenge_mode": cfg.challenge_mode,
        "statement": statement_obj,
        "statement_sha256": stmt_sha,
        "statement_int": stmt_int,
        "hellos": hellos,
        "commitments": commitments,
        "challenge": challenge,
        "kept": kept,
        "kept_seed_sha256": kept_seed_sha,
        "kept_garbling": kept_garbling,
        "kept_registration": kept_reg,
        "delivered_tables": delivered_tables,
        "delivered_tables_commitment": delivered_comm,
        "opened_count": len(opened),
        "checks": checks,
        "ceremony_ok": ceremony_ok,
        "transcript_view": transcript_view,
        "acks": acks,
        "bad_indices": sorted(bad_indices),
    }


def _build_equivocated_tables_for_proof(circuit: gc.Circuit, kept_garbling: gc.Garbling, target_bits: list[int]):
    """Equivocate the garbled tables (changing ciphertext_commitment!) so that evaluating
    `target_bits` (a FALSE proof!) produces `kept_garbling.accept_label`."""
    # First evaluate honestly to get the exact wire labels at the last AND gate for `target_bits`.
    in_labels = kept_garbling.input_labels(target_bits)
    labels = list(in_labels) + [None] * (circuit.wires - circuit.inputs)
    tables = list(kept_garbling.tables)
    t_idx = 0
    last_and_idx = max(i for i, g in enumerate(circuit.gates) if g[0] == "AND")
    last_table_pos = None
    for index, (op, a, b, out) in enumerate(circuit.gates):
        if op == "XOR":
            labels[out] = gc.xor(labels[a], labels[b])
        elif op == "NOT":
            labels[out] = labels[a]
        else:
            tg, te = tables[t_idx]
            wa, wb = labels[a], labels[b]
            j, k = 2 * index, 2 * index + 1
            if index == last_and_idx:
                last_table_pos = t_idx
                # Current evaluation yields `cur_out`. We want `kept_garbling.accept_label`
                # (assuming `out == circuit.outputs[0]`, which holds for statement_circuit!).
                wg = gc.xor(gc.gate_hash(wa, j), tg if gc.lsb(wa) else gc.ZERO)
                we = gc.xor(gc.gate_hash(wb, k), gc.xor(te, wa) if gc.lsb(wb) else gc.ZERO)
                cur_out = gc.xor(wg, we)
                diff = gc.xor(cur_out, kept_garbling.accept_label)
                if gc.lsb(wa):
                    tg = gc.xor(tg, diff)
                    tables[t_idx] = (tg, te)
                elif gc.lsb(wb):
                    te = gc.xor(te, diff)
                    tables[t_idx] = (tg, te)
                else:
                    # Neither lsb is 1 at the last gate: flip a prior gate that feeds `a` or `b`
                    # where lsb is 1, or flip the first input's AND gate where lsb is 1.
                    # Guarantee at least one of lsb(wa), lsb(wb) is 1 by perturbing an upstream table
                    # that shifts wa by a label with lsb=1 (Delta always has lsb=1!).
                    tables = _shift_upstream_for_equivocation(circuit, kept_garbling, target_bits)
                    return tables
                wg = gc.xor(gc.gate_hash(wa, j), tg if gc.lsb(wa) else gc.ZERO)
                we = gc.xor(gc.gate_hash(wb, k), gc.xor(te, wa) if gc.lsb(wb) else gc.ZERO)
                labels[out] = gc.xor(wg, we)
            else:
                wg = gc.xor(gc.gate_hash(wa, j), tg if gc.lsb(wa) else gc.ZERO)
                we = gc.xor(gc.gate_hash(wb, k), gc.xor(te, wa) if gc.lsb(wb) else gc.ZERO)
                labels[out] = gc.xor(wg, we)
            t_idx += 1
    assert last_table_pos is not None
    assert labels[circuit.outputs[0]] == kept_garbling.accept_label
    return tables


def _shift_upstream_for_equivocation(circuit: gc.Circuit, kept_garbling: gc.Garbling, target_bits: list[int]):
    """Fallback when both lsb(wa)==0 and lsb(wb)==0 at the final gate: perturb the upstream
    gate feeding `a` by Delta (lsb=1), then patch the final gate's `tg` to land on `accept_label`."""
    in_labels = kept_garbling.input_labels(target_bits)
    tables = list(kept_garbling.tables)
    last_and_idx = max(i for i, g in enumerate(circuit.gates) if g[0] == "AND")
    _, final_a, final_b, _ = circuit.gates[last_and_idx]
    # Trace any upstream AND gate whose output reaches final_a or final_b and has lsb(wa)==1 or lsb(wb)==1.
    labels = list(in_labels) + [None] * (circuit.wires - circuit.inputs)
    t_idx = 0
    and_positions = {}
    for index, (op, a, b, out) in enumerate(circuit.gates):
        if op == "XOR":
            labels[out] = gc.xor(labels[a], labels[b])
        elif op == "NOT":
            labels[out] = labels[a]
        else:
            tg, te = tables[t_idx]
            wa, wb = labels[a], labels[b]
            and_positions[out] = (t_idx, index, wa, wb)
            j, k = 2 * index, 2 * index + 1
            wg = gc.xor(gc.gate_hash(wa, j), tg if gc.lsb(wa) else gc.ZERO)
            we = gc.xor(gc.gate_hash(wb, k), gc.xor(te, wa) if gc.lsb(wb) else gc.ZERO)
            labels[out] = gc.xor(wg, we)
            t_idx += 1

    # Try flipping one upstream AND gate feeding final_a/final_b (with Delta, lsb=1).
    for cand_wire in (final_a, final_b):
        if cand_wire in and_positions:
            pos, _, wa, wb = and_positions[cand_wire]
            tg, te = tables[pos]
            if gc.lsb(wa):
                tables[pos] = (gc.xor(tg, kept_garbling.delta), te)
                break
            if gc.lsb(wb):
                tables[pos] = (tg, gc.xor(te, kept_garbling.delta))
                break
    # Now re-evaluate up to last_and_idx; at least one of lsb(wa), lsb(wb) is 1.
    labels = list(in_labels) + [None] * (circuit.wires - circuit.inputs)
    t_idx = 0
    for index, (op, a, b, out) in enumerate(circuit.gates):
        if op == "XOR":
            labels[out] = gc.xor(labels[a], labels[b])
        elif op == "NOT":
            labels[out] = labels[a]
        else:
            tg, te = tables[t_idx]
            wa, wb = labels[a], labels[b]
            j, k = 2 * index, 2 * index + 1
            if index == last_and_idx:
                wg = gc.xor(gc.gate_hash(wa, j), tg if gc.lsb(wa) else gc.ZERO)
                we = gc.xor(gc.gate_hash(wb, k), gc.xor(te, wa) if gc.lsb(wb) else gc.ZERO)
                diff = gc.xor(gc.xor(wg, we), kept_garbling.accept_label)
                if gc.lsb(wa):
                    tg = gc.xor(tg, diff)
                else:
                    te = gc.xor(te, diff)
                tables[t_idx] = (tg, te)
                wg = gc.xor(gc.gate_hash(wa, j), tg if gc.lsb(wa) else gc.ZERO)
                we = gc.xor(gc.gate_hash(wb, k), gc.xor(te, wa) if gc.lsb(wb) else gc.ZERO)
                labels[out] = gc.xor(wg, we)
            else:
                wg = gc.xor(gc.gate_hash(wa, j), tg if gc.lsb(wa) else gc.ZERO)
                we = gc.xor(gc.gate_hash(wb, k), gc.xor(te, wa) if gc.lsb(wb) else gc.ZERO)
                labels[out] = gc.xor(wg, we)
            t_idx += 1
    assert labels[circuit.outputs[0]] == kept_garbling.accept_label
    return tables


# --- Cashu Joint-Release Taproot Transaction Graph -------------------------------------

class CashuGraph:
    """Taproot reconstruction of `proof-grove/m14/cashu-joint-release/v2` + k=4 ceremony."""

    def __init__(self, case_id: str, cfg: CashuConfig, registration: dict, *, index: int = 0,
                 stage: CashuStage = FIXTURE):
        self.stage = stage
        self.case_id = case_id
        self.cfg = cfg
        self.reg = registration
        self.index = index
        self.preimage = issuance_preimage(case_id, index)
        self.preimage_hash = sha(self.preimage)
        self.pin = cashu_hash(
            "setup-pin",
            registration["statement_sha256"],
            registration["ciphertext_commitment"],
            registration["accept_label_sha256"],
            registration["reject_label_sha256"],
        )

        self.H = stage.keys["holder"]
        self.G = stage.keys["guardian"]
        self.Ch = stage.keys["challenger"]
        self.M = stage.keys["mint"]
        self.Acc = stage.keys["accept_signer"]
        self.Rej = stage.keys["reject_signer"]
        self.Tim = stage.keys["timeout_signer"]

        self.holder_spk = stage.spk("holder")
        self.refund_spk = stage.spk("refund")
        self.attacker_spk = stage.spk("attacker")

        # Reserve output R (25,000 sats):
        # Leaf 0: holder CSV / joint-release branch
        # Leaf 1: cooperative holder + mint branch
        preimage_check = ops("SIZE") + number(32) + ops("EQUALVERIFY", "SHA256") + push(self.preimage_hash) + ops("EQUALVERIFY")
        if cfg.holder_csv_unilateral:
            if cfg.holder_locks_outputs:
                csv_leaf = preimage_check + push(self.H) + ops("CHECKSIGVERIFY") + number(RESERVE_CSV_BLOCKS) + ops("CSV", "DROP", "1")
            else:
                # Mutant: omits holder output-binding signature (accepts challenger/garbler release!)
                csv_leaf = preimage_check + push(self.Ch) + ops("CHECKSIGVERIFY") + number(RESERVE_CSV_BLOCKS) + ops("CSV", "DROP", "1")
        else:
            # Mutant (withholding): holder cannot exit unilaterally without challenger co-sig!
            csv_leaf = (
                preimage_check
                + push(self.H)
                + ops("CHECKSIGVERIFY")
                + push(self.Ch)
                + ops("CHECKSIGVERIFY")
                + number(RESERVE_CSV_BLOCKS)
                + ops("CSV", "DROP", "1")
            )
        coop_leaf = preimage_check + push(self.H) + ops("CHECKSIGVERIFY") + push(self.M) + ops("CHECKSIG")
        self.R = TapTree((csv_leaf, coop_leaf), NUMS)

        # Collateral output C (25,250 sats):
        # Leaf 0: accept branch (accept_label preimage + accept_signer + holder + [guardian] + challenger)
        # Leaf 1: reject branch (reject_label preimage + reject_signer + holder + challenger)
        # Leaf 2: timeout branch (8 CSV + timeout_signer + challenger)
        pin_prefix = push(self.pin) + ops("DROP")
        accept_tail = (
            push(self.Acc)
            + ops("CHECKSIGVERIFY")
            + (push(self.H) + ops("CHECKSIGVERIFY") if cfg.holder_locks_outputs else b"")
            + (push(self.G) + ops("CHECKSIGVERIFY") if cfg.guardian_cosign else b"")
            + push(self.Ch)
            + ops("CHECKSIG")
        )
        accept_leaf = (
            pin_prefix
            + ops("SIZE")
            + number(gc.LABEL)
            + ops("EQUALVERIFY", "SHA256")
            + push(bytes.fromhex(registration["accept_label_sha256"]))
            + ops("EQUALVERIFY")
            + accept_tail
        )
        reject_leaf = (
            pin_prefix
            + ops("SIZE")
            + number(gc.LABEL)
            + ops("EQUALVERIFY", "SHA256")
            + push(bytes.fromhex(registration["reject_label_sha256"]))
            + ops("EQUALVERIFY")
            + push(self.Rej)
            + ops("CHECKSIGVERIFY")
            + push(self.H)
            + ops("CHECKSIGVERIFY")
            + push(self.Ch)
            + ops("CHECKSIG")
        )
        timeout_leaf = (
            pin_prefix
            + number(TIMEOUT_BLOCKS)
            + ops("CSV", "DROP")
            + push(self.Tim)
            + ops("CHECKSIGVERIFY")
            + push(self.Ch)
            + ops("CHECKSIG")
        )
        self.C = TapTree((accept_leaf, reject_leaf, timeout_leaf), NUMS)

    def funding_outputs(self, suffix: str = "") -> dict:
        return {
            f"reserve{suffix}": (self.R, self.stage.reserve),
            f"collateral{suffix}": (self.C, self.stage.collateral),
        }

    def joint_release_tx(
        self,
        reserve_utxo: dict,
        collateral_utxo: dict,
        accept_label: bytes,
        *,
        destination_spk: bytes | None = None,
        holder_approves: bool = True,
        guardian_approves: bool = True,
        challenger_approves: bool = True,
        accept_signer_approves: bool = True,
    ) -> Transaction:
        dest = destination_spk if destination_spk is not None else self.holder_spk
        tx = Transaction(
            [
                utxo_input(reserve_utxo, RESERVE_CSV_BLOCKS),
                utxo_input(collateral_utxo, 0xFFFFFFFD),
            ],
            [
                (self.stage.payout, dest),
                (self.stage.refund, self.refund_spk),
            ],
        )
        r_leaf = self.R.leaf(0)
        c_leaf = self.C.leaf(0)

        # Input 0 (Reserve): script consumes preimage first, then signer(s) in order.
        # Stack order (bottom to top) -> last item executed first!
        # In `preimage_check <K1> CHECKSIGVERIFY [<K2> CHECKSIGVERIFY] 6 CSV DROP 1`:
        # top of stack is preimage, then K1 sig, then K2 sig!
        if self.cfg.holder_csv_unilateral:
            signer0 = "holder" if self.cfg.holder_locks_outputs else "challenger"
            sig0_secret = self.stage.secret(signer0) if (holder_approves if signer0 == "holder" else challenger_approves) else self.stage.secret("attacker")
            sig0 = tx.signature(0, r_leaf, sig0_secret, SIGHASH_DEFAULT)
            tx.inputs[0].witness = [sig0, self.preimage, r_leaf.script, r_leaf.control]
        else:
            sig_h = tx.signature(0, r_leaf, self.stage.secret("holder") if holder_approves else self.stage.secret("attacker"), SIGHASH_DEFAULT)
            sig_ch = tx.signature(0, r_leaf, self.stage.secret("challenger") if challenger_approves else self.stage.secret("attacker"), SIGHASH_DEFAULT)
            tx.inputs[0].witness = [sig_ch, sig_h, self.preimage, r_leaf.script, r_leaf.control]

        # Input 1 (Collateral accept leaf):
        # Script consumes: accept_label (top), then Acc, then [H], then [G], then Ch (bottom)!
        # So witness list (bottom to top) is: [sig_ch, (sig_g), (sig_h), sig_acc, accept_label, script, control].
        sig_ch = tx.signature(1, c_leaf, self.stage.secret("challenger") if challenger_approves else self.stage.secret("attacker"), SIGHASH_DEFAULT)
        sig_acc = tx.signature(1, c_leaf, self.stage.secret("accept_signer") if accept_signer_approves else self.stage.secret("attacker"), SIGHASH_DEFAULT)
        w1 = [sig_ch]
        if self.cfg.guardian_cosign:
            sig_g = tx.signature(1, c_leaf, self.stage.secret("guardian") if guardian_approves else self.stage.secret("attacker"), SIGHASH_DEFAULT)
            w1.append(sig_g)
        if self.cfg.holder_locks_outputs:
            sig_h = tx.signature(1, c_leaf, self.stage.secret("holder") if holder_approves else self.stage.secret("attacker"), SIGHASH_DEFAULT)
            w1.append(sig_h)
        w1 += [sig_acc, accept_label, c_leaf.script, c_leaf.control]
        tx.inputs[1].witness = w1
        return tx

    def holder_csv_exit_tx(self, reserve_utxo: dict, *, challenger_cosigns: bool = False) -> Transaction:
        tx = Transaction(
            [utxo_input(reserve_utxo, RESERVE_CSV_BLOCKS)],
            [(self.stage.payout, self.holder_spk)],
        )
        r_leaf = self.R.leaf(0)
        sig_h = tx.signature(0, r_leaf, self.stage.secret("holder"), SIGHASH_DEFAULT)
        if self.cfg.holder_csv_unilateral:
            tx.inputs[0].witness = [sig_h, self.preimage, r_leaf.script, r_leaf.control]
        else:
            # Mutant requires challenger co-sig; when challenger/garbler withholds, holder can only supply wrong sig.
            sig_ch = tx.signature(0, r_leaf, self.stage.secret("challenger") if challenger_cosigns else self.stage.secret("holder"), SIGHASH_DEFAULT)
            tx.inputs[0].witness = [sig_ch, sig_h, self.preimage, r_leaf.script, r_leaf.control]
        return tx


# --- Trajectory Execution --------------------------------------------------------------

def _statement_for(case_id: str, cfg: CashuConfig, *, reserve_label: str = "reserve_0", holder_role: str = "holder",
                   stage: CashuStage = FIXTURE) -> dict:
    stmt = {
        "network": "regtest",
        "program_vk_digest": PROGRAM_VK_DIGEST,
        "payout_sats": stage.payout,
    }
    if cfg.bind_reserve_in_statement:
        stmt["reserve_slot"] = f"{case_id}:{reserve_label}"
    else:
        stmt["reserve_slot"] = f"{case_id}:shared"
    # Every statement names its holder script; whether the verifier circuit is bound to it is
    # decided by `verifier_view` (cfg.bind_committed_values).
    stmt["holder_script"] = spk_of(holder_role, stage).hex()
    stmt["committed_values_sha256"] = cashu_hash(
        "committed-values", stmt["reserve_slot"], stmt["holder_script"], str(stage.payout)
    ).hex()
    return stmt


def release_attempt(
    session: Session,
    graph: CashuGraph,
    utxos: dict,
    label: str,
    actor: str,
    out_label: bytes,
    *,
    holder_approves: bool,
    guardian_approves: bool,
    destination_spk: bytes | None = None,
    challenger_approves: bool = True,
) -> bool:
    """Submit a release in which honest co-signers sign only if they approve.

    When the holder or guardian withholds a signature, a non-broadcast counterfactual
    (`cosigned probe`, testmempoolaccept only) first asks Core what it would do had both
    signed, so the receipt shows whether Bitcoin script (labels, pins, CSV) or the
    co-signer veto is what stopped the release.
    """
    if not (holder_approves and guardian_approves):
        probe = graph.joint_release_tx(
            utxos["reserve"], utxos["collateral"], out_label,
            destination_spk=destination_spk, challenger_approves=challenger_approves,
        )
        session.submit("cosigned probe", "counterfactual", probe, broadcast=False,
                       note="Core verdict had holder and guardian co-signed; never broadcast")
    tx = graph.joint_release_tx(
        utxos["reserve"], utxos["collateral"], out_label,
        destination_spk=destination_spk,
        holder_approves=holder_approves,
        guardian_approves=guardian_approves,
        challenger_approves=challenger_approves,
    )
    return session.submit(label, actor, tx)


def paid_to_attacker(steps: list[dict], stage: CashuStage = FIXTURE) -> int:
    """Sats that confirmed transactions in `steps` paid to the attacker's script (from raw bytes)."""
    target = spk_of("attacker", stage).hex()
    total = 0
    for s in steps:
        if s.get("kind") == "tx" and s.get("confirmed"):
            for value, spk in Transaction.parse(s["raw_transaction"]).outputs:
                if spk.hex() == target:
                    total += value
    return total


def selective_failure_probe(cer: dict, cfg: CashuConfig, honest_proof: tuple[int, int]) -> dict:
    """Off-chain selective-failure probe on the kept instance, with a bit-0 counterfactual.

    A bad garbler offers a corrupted label only for value 1 of input wire 0 (via OT, so the
    evaluator receives exactly one of them). The evaluator's abort then reveals its secret
    bit iff evaluating with bit 0 and with bit 1 of that wire differ in whether they abort.
    """
    kept_g = cer["kept_garbling"]
    kept_reg = cer["kept_registration"]
    kept_bad = cer["kept"] in cer["bad_indices"]
    bits = gc.proof_bits(*honest_proof)
    runs = {}
    for bit0 in (0, 1):
        trial = list(bits)
        trial[0] = bit0
        labels = kept_g.input_labels(trial)
        if kept_bad and bit0 == 1:
            labels[0] = gc.xor(labels[0], b"\x01" + bytes(gc.LABEL - 1))
        hash_ok = hashlib.sha256(labels[0]).hexdigest() == kept_reg["input_label_sha256"][0][bit0]
        if cfg.check_input_label_hashes and not hash_ok:
            runs[bit0] = {"input_hash_matches_commitment": False, "verdict": "aborted_before_evaluation", "label": None}
            continue
        out = evaluate_circuit(kept_g.circuit, cer["delivered_tables"], labels)
        runs[bit0] = {
            "input_hash_matches_commitment": hash_ok,
            "verdict": gc.decode(out, kept_reg["accept_label_sha256"], kept_reg["reject_label_sha256"]),
            "label": out,
        }
    aborted = {b: runs[b]["verdict"] in ("invalid", "aborted_before_evaluation") for b in (0, 1)}
    return {
        "secret_bit": bits[0],
        "actual": runs[bits[0]],
        "counterfactual": runs[1 - bits[0]],
        "secret_bit_leaked": aborted[0] != aborted[1],
    }


def run_case(session: Session, row: dict, stage: CashuStage = FIXTURE) -> tuple[list[dict], dict, dict]:
    """Execute one Cashu M14 trajectory on isolated Bitcoin Core regtest."""
    cid = row["id"]
    recipe = row["recipe"]
    profile = row["profile"]
    attack = row["variant"] == "attack"
    cfg = config_for(recipe, profile)

    session.begin(keys(stage))
    prior_seed_hashes: set[str] = set()
    prior_garbling = None
    prior_proof = None

    # Special pre-step for seed_delta_reuse: execute/record Withdrawal 1's garbling & honest labels.
    if recipe == "seed_delta_reuse":
        prior_stmt = _statement_for(cid, cfg, reserve_label="prior_withdrawal", stage=stage)
        prior_ceremony = run_ceremony(cid, cfg, prior_stmt, recipe=recipe, attack=False, index=99, stage=stage)
        prior_garbling = prior_ceremony["kept_garbling"]
        prior_proof = proof_for(prior_ceremony["statement_int"], honest=True)
        prior_seed_hashes.add(prior_ceremony["kept_seed_sha256"])
        session.offchain(
            "prior withdrawal",
            "garbler",
            statement_sha256=prior_ceremony["statement_sha256"],
            seed_sha256=prior_ceremony["kept_seed_sha256"],
            proof=list(prior_proof),
        )

    # Primary withdrawal statement & k=4 ceremony.
    stmt0 = _statement_for(cid, cfg, reserve_label="reserve_0", holder_role="holder", stage=stage)
    cer0 = run_ceremony(
        cid,
        cfg,
        stmt0,
        recipe=recipe,
        attack=attack,
        index=0,
        prior_seed_hashes=prior_seed_hashes,
        stage=stage,
    )
    kept_g = cer0["kept_garbling"]
    kept_reg = cer0["kept_registration"]
    honest_circuit = gc.statement_circuit(cer0["statement_int"])

    # For tape_equivocation attack, build the exact equivocated tables targeting the false proof.
    false_proof = proof_for(cer0["statement_int"], honest=False)
    honest_proof = proof_for(cer0["statement_int"], honest=True)
    if attack and recipe == "tape_equivocation":
        equiv_tables = _build_equivocated_tables_for_proof(
            honest_circuit, kept_g, gc.proof_bits(*false_proof)
        )
        cer0["delivered_tables"] = equiv_tables
        cer0["delivered_tables_commitment"] = cashu_tables_commitment(equiv_tables)
        tables_match = cer0["delivered_tables_commitment"] == kept_reg["ciphertext_commitment"]
        cer0["checks"]["tables_commitment"] = True if not cfg.check_tables_commitment else tables_match
        cer0["ceremony_ok"] = all(cer0["checks"].values())

    session.offchain(
        "ceremony",
        "hub",
        k=cer0["k"],
        challenge_mode=cer0["challenge_mode"],
        kept=cer0["kept"],
        opened_count=cer0["opened_count"],
        commitments=cer0["commitments"],
        challenge=cer0["challenge"],
        statement_sha256=cer0["statement_sha256"],
        ciphertext_commitment=kept_reg["ciphertext_commitment"],
        delivered_tables_commitment=cer0["delivered_tables_commitment"],
        accept_label_sha256=kept_reg["accept_label_sha256"],
        reject_label_sha256=kept_reg["reject_label_sha256"],
        checks=cer0["checks"],
        ceremony_ok=cer0["ceremony_ok"],
        transcript_view=cer0["transcript_view"],
        bad_indices=cer0["bad_indices"],
    )

    graph0 = CashuGraph(cid, cfg, kept_reg, index=0, stage=stage)
    utxos = session.fund(graph0.funding_outputs(), label="fund")

    # For proof_replay, fund a second reserve + collateral in a separate funding transaction!
    graph1 = None
    cer1 = None
    utxos2 = None
    if recipe == "proof_replay":
        stmt1 = _statement_for(cid, cfg, reserve_label="reserve_1", holder_role="holder", stage=stage)
        cer1 = run_ceremony(cid, cfg, stmt1, recipe=recipe, attack=attack, index=1, stage=stage)
        graph1 = CashuGraph(cid, cfg, cer1["kept_registration"], index=1, stage=stage)
        session.offchain(
            "ceremony 2",
            "hub",
            k=cer1["k"],
            kept=cer1["kept"],
            statement_sha256=cer1["statement_sha256"],
            accept_label_sha256=cer1["kept_registration"]["accept_label_sha256"],
            ceremony_ok=cer1["ceremony_ok"],
        )
        utxos2 = session.fund(graph1.funding_outputs(), label="fund 2")
    funded_target = {
        "network": "regtest",
        "reserve_outpoint": f"{utxos['reserve']['txid']}:{utxos['reserve']['vout']}",
        "reserve_sats": stage.reserve,
        "holder_payout_sats": stage.payout,
        "collateral_outpoint": f"{utxos['collateral']['txid']}:{utxos['collateral']['vout']}",
        "collateral_sats": stage.collateral,
        "holder_script": graph0.holder_spk.hex(),
        "authorization": AUTHORIZATION_SCHEMA,
        "ceremony_k": cfg.cut_and_choose_k,
        "challenge_mode": cfg.challenge_mode,
    }

    # Mine 6 blocks so the reserve's 6-block CSV is mature (same pre-release state as pinned Spiral block 211).
    session.mine(RESERVE_CSV_BLOCKS, "reserve CSV delay matures")

    secret_bit_leaked = False

    if not attack:
        # Benign honest withdrawal on Reserve 0 (and Reserve 1 for proof_replay).
        in_labels = kept_g.input_labels(gc.proof_bits(*honest_proof))
        out_label = evaluate_circuit(kept_g.circuit, cer0["delivered_tables"], in_labels)
        verdict = gc.decode(out_label, kept_reg["accept_label_sha256"], kept_reg["reject_label_sha256"])
        session.offchain("evaluate", "holder", proof=list(honest_proof), output_label=out_label.hex(), verdict=verdict)
        tx = graph0.joint_release_tx(utxos["reserve"], utxos["collateral"], out_label)
        session.submit("joint release", "holder", tx)
        if recipe == "proof_replay" and graph1 is not None and cer1 is not None and utxos2 is not None:
            p1 = proof_for(cer1["statement_int"], honest=True)
            g1 = cer1["kept_garbling"]
            out1 = evaluate_circuit(g1.circuit, cer1["delivered_tables"], g1.input_labels(gc.proof_bits(*p1)))
            session.offchain("evaluate 2", "holder", proof=list(p1), output_label=out1.hex(), verdict="accept")
            tx2 = graph1.joint_release_tx(utxos2["reserve"], utxos2["collateral"], out1)
            session.submit("joint release 2", "holder", tx2)

    elif recipe == "wrong_circuit_under_pin":
        in_labels = kept_g.input_labels(gc.proof_bits(*false_proof))
        out_label = evaluate_circuit(kept_g.circuit, cer0["delivered_tables"], in_labels)
        verdict = gc.decode(out_label, kept_reg["accept_label_sha256"], kept_reg["reject_label_sha256"])
        session.offchain("evaluate", "holder", proof=list(false_proof), output_label=out_label.hex(), verdict=verdict)
        release_attempt(session, graph0, utxos, "unauthorized release", "garbler", out_label,
                        holder_approves=cer0["ceremony_ok"], guardian_approves=cer0["ceremony_ok"])

    elif recipe == "leaked_accept_label":
        leaked = kept_reg.get("debug_accept_label_leak")
        if leaked and cer0["ceremony_ok"]:
            cand_label = bytes.fromhex(leaked)
            source = "extracted_from_published_package"
        else:
            # No leak accepted: attacker only has a false-proof reject label or dummy guess.
            in_labels = kept_g.input_labels(gc.proof_bits(*false_proof))
            cand_label = evaluate_circuit(kept_g.circuit, cer0["delivered_tables"], in_labels)
            source = "false_proof_output_no_leak"
        session.offchain("extract label", "garbler", source=source, extracted_label=cand_label.hex(), ceremony_ok=cer0["ceremony_ok"])
        release_attempt(session, graph0, utxos, "unauthorized release", "garbler", cand_label,
                        holder_approves=cer0["ceremony_ok"], guardian_approves=cer0["ceremony_ok"])

    elif recipe == "selective_failure":
        released = False
        if not cer0["ceremony_ok"]:
            # Cut-and-choose opened the bad instance: the holder stops before any secret-dependent
            # evaluation, so the garbler learns nothing.
            session.offchain("abort before evaluation", "holder", checks=cer0["checks"], secret_bit_leaked=False)
        else:
            probe = selective_failure_probe(cer0, cfg, honest_proof)
            secret_bit_leaked = probe["secret_bit_leaked"]
            actual = probe["actual"]
            session.offchain(
                "evaluate",
                "holder",
                probed_wire=0,
                actual_verdict=actual["verdict"],
                counterfactual_verdict=probe["counterfactual"]["verdict"],
                input_hash_matches_commitment=actual["input_hash_matches_commitment"],
                secret_bit_leaked=secret_bit_leaked,
            )
            if actual["label"] is not None:
                # Core judges whatever label the evaluation produced against the accept leaf.
                released = session.submit(
                    "joint release" if actual["verdict"] == "accept" else "blocked joint release",
                    "holder",
                    graph0.joint_release_tx(utxos["reserve"], utxos["collateral"], actual["label"]),
                )
        if not released:
            session.submit("holder csv exit", "holder", graph0.holder_csv_exit_tx(utxos["reserve"]))

    elif recipe == "tape_equivocation":
        in_labels = kept_g.input_labels(gc.proof_bits(*false_proof))
        out_label = evaluate_circuit(honest_circuit, cer0["delivered_tables"], in_labels)
        verdict = gc.decode(out_label, kept_reg["accept_label_sha256"], kept_reg["reject_label_sha256"])
        session.offchain(
            "evaluate",
            "holder",
            proof=list(false_proof),
            delivered_tables_commitment=cer0["delivered_tables_commitment"],
            committed_ciphertext_hash=kept_reg["ciphertext_commitment"],
            output_label=out_label.hex(),
            verdict=verdict,
            ceremony_ok=cer0["ceremony_ok"],
        )
        release_attempt(session, graph0, utxos, "unauthorized release", "garbler", out_label,
                        holder_approves=cer0["ceremony_ok"], guardian_approves=cer0["ceremony_ok"])

    elif recipe == "seed_delta_reuse":
        # Attacker holds input labels from Prior Withdrawal (honest) + Current Withdrawal (false proof).
        prior_bits = gc.proof_bits(*prior_proof)
        curr_bits = gc.proof_bits(*false_proof)
        prior_in = prior_garbling.input_labels(prior_bits)
        curr_in = kept_g.input_labels(curr_bits)
        # Find a wire i where prior_bits[i] != curr_bits[i]: if same seed was reused, L_prior[i] XOR L_curr[i] == Delta!
        diff_wire = next(i for i in range(len(prior_bits)) if prior_bits[i] != curr_bits[i])
        recovered_delta = gc.xor(prior_in[diff_wire], curr_in[diff_wire])
        delta_matches = recovered_delta == kept_g.delta
        # Evaluate false proof -> reject_label, then forge accept_label = reject_label XOR recovered_delta!
        reject_out = evaluate_circuit(kept_g.circuit, cer0["delivered_tables"], curr_in)
        forged_accept = gc.xor(reject_out, recovered_delta)
        session.offchain(
            "recover delta",
            "garbler",
            diff_wire=diff_wire,
            delta_recovered=delta_matches,
            forged_accept_label=forged_accept.hex(),
            forged_matches_accept_hash=hashlib.sha256(forged_accept).hexdigest() == kept_reg["accept_label_sha256"],
        )
        release_attempt(session, graph0, utxos, "unauthorized release", "garbler", forged_accept,
                        holder_approves=cer0["ceremony_ok"], guardian_approves=cer0["ceremony_ok"])

    elif recipe == "decoding_polarity_flip":
        in_labels = kept_g.input_labels(gc.proof_bits(*false_proof))
        out_label = evaluate_circuit(kept_g.circuit, cer0["delivered_tables"], in_labels)
        verdict = gc.decode(out_label, kept_reg["accept_label_sha256"], kept_reg["reject_label_sha256"])
        session.offchain("evaluate", "holder", proof=list(false_proof), output_label=out_label.hex(), verdict=verdict)
        release_attempt(session, graph0, utxos, "unauthorized release", "garbler", out_label,
                        holder_approves=cer0["ceremony_ok"], guardian_approves=cer0["ceremony_ok"])

    elif recipe == "withholding":
        session.offchain(
            "withhold package",
            "garbler",
            tables_withheld=True,
            input_labels_withheld=True,
            note="proof-backed joint release blocked; holder invokes unilateral CSV exit",
        )
        csv_tx = graph0.holder_csv_exit_tx(utxos["reserve"], challenger_cosigns=False)
        session.submit("holder csv exit", "holder", csv_tx)

    elif recipe == "garbler_challenger_collusion":
        in_labels = kept_g.input_labels(gc.proof_bits(*false_proof))
        out_label = evaluate_circuit(kept_g.circuit, cer0["delivered_tables"], in_labels)
        verdict = gc.decode(out_label, kept_reg["accept_label_sha256"], kept_reg["reject_label_sha256"])
        session.offchain(
            "collusive release attempt",
            "garbler+challenger",
            kept_is_bad=cer0["kept"] in cer0["bad_indices"],
            ceremony_ok=cer0["ceremony_ok"],
            output_label=out_label.hex(),
            verdict=verdict,
        )
        # Colluders try to pay the holder's 24,750 sats to attacker_spk; an honest holder or
        # guardian never signs outputs paying the attacker.
        release_attempt(session, graph0, utxos, "diverted release", "garbler+challenger", out_label,
                        holder_approves=False, guardian_approves=False,
                        destination_spk=graph0.attacker_spk)

    elif recipe == "proof_replay":
        # Reserve 0 settles honestly first.
        in0 = kept_g.input_labels(gc.proof_bits(*honest_proof))
        out0 = evaluate_circuit(kept_g.circuit, cer0["delivered_tables"], in0)
        session.offchain("evaluate", "holder", proof=list(honest_proof), output_label=out0.hex(), verdict="accept")
        tx0 = graph0.joint_release_tx(utxos["reserve"], utxos["collateral"], out0)
        session.submit("joint release", "holder", tx0)
        # The holder replays Reserve 0's accept label to release Reserve 1 (a separately funded
        # calibration reserve) without a Reserve 1 proof. The replay pays Reserve 1's holder.
        assert graph1 is not None and utxos2 is not None
        session.offchain("replay accept label", "holder", replayed_label=out0.hex(), target="reserve_1")
        tx_replay = graph1.joint_release_tx(utxos2["reserve"], utxos2["collateral"], out0)
        session.submit("replayed release 2", "holder", tx_replay)

    elif recipe == "statement_substitution":
        # A valid proof for a statement naming the attacker's script, under the same program VK.
        att_stmt = _statement_for(cid, cfg, reserve_label="reserve_0", holder_role="attacker", stage=stage)
        if att_stmt == stmt0:
            raise ValidationError("statement_substitution: attacker statement must differ from the pinned one")
        att_int = statement_int_from(verifier_view(att_stmt, cfg))
        att_proof = proof_for(att_int, honest=True)
        in_labels = kept_g.input_labels(gc.proof_bits(*att_proof))
        out_label = evaluate_circuit(kept_g.circuit, cer0["delivered_tables"], in_labels)
        verdict = gc.decode(out_label, kept_reg["accept_label_sha256"], kept_reg["reject_label_sha256"])
        session.offchain(
            "substituted statement evaluate",
            "garbler",
            attacker_statement_sha256=hashlib.sha256(canonical(att_stmt).encode("utf-8")).hexdigest(),
            pinned_statement_sha256=cer0["statement_sha256"],
            same_program_vk=True,
            circuit_binds_holder_script=cfg.bind_committed_values,
            output_label=out_label.hex(),
            verdict=verdict,
        )
        # The holder never signs outputs paying the attacker. The mutant also drops the holder
        # key from the reserve leaf (holder_locks_outputs=False), so its spend needs no holder.
        release_attempt(session, graph0, utxos, "diverted release", "garbler", out_label,
                        holder_approves=False, guardian_approves=True,
                        destination_spk=graph0.attacker_spk)

    steps = session.finish()
    probe = step(steps, "cosigned probe")
    attack_rejected = any(
        s["kind"] == "tx" and s["label"] in ("unauthorized release", "diverted release", "replayed release 2")
        and not s["allowed"] for s in steps
    )
    # Which layer stopped a rejected release: Bitcoin script itself, or only the honest
    # co-signers' refusal (their counterfactual co-signed probe would have been accepted).
    if not (attack and attack_rejected):
        defense_layer = "n/a"
    elif probe is not None and probe["allowed"]:
        defense_layer = "cosigner_veto"
    else:
        defense_layer = "bitcoin_script"
    observed = {
        "ceremony_k": cfg.cut_and_choose_k,
        "challenge_mode": cfg.challenge_mode,
        "ceremony_ok": cer0["ceremony_ok"],
        "checks": cer0["checks"],
        "joint_release_confirmed": confirmed(steps, "joint release"),
        "holder_csv_exit_confirmed": confirmed(steps, "holder csv exit"),
        "unauthorized_release_confirmed": (
            confirmed(steps, "unauthorized release")
            or confirmed(steps, "diverted release")
            or confirmed(steps, "replayed release 2")
        ),
        "diverted_principal_sats": paid_to_attacker(steps, stage),
        "secret_bit_leaked": secret_bit_leaked,
        "cut_and_choose_escaped": bool(cer0["challenge"].get("escaped", False)),
        "cosigned_probe_allowed": None if probe is None else probe["allowed"],
        "cosigned_probe_reject_reason": None if probe is None else probe["reject_reason"],
        "defense_layer": defense_layer,
    }
    return steps, funded_target, observed


def score(row: dict, steps: list[dict], observed: dict, stage: CashuStage = FIXTURE) -> dict:
    """Independently score legitimate completion, unauthorized release, and diverted principal."""
    recipe = row["recipe"]
    attack = row["variant"] == "attack"

    honest_paid = confirmed(steps, "joint release") or confirmed(steps, "holder csv exit")
    unauth = (
        confirmed(steps, "unauthorized release")
        or confirmed(steps, "diverted release")
        or confirmed(steps, "replayed release 2")
    )
    diverted = paid_to_attacker(steps, stage)

    bit_leaked = bool(observed.get("secret_bit_leaked", False))

    if not attack:
        if recipe == "proof_replay":
            leg = confirmed(steps, "joint release") and confirmed(steps, "joint release 2")
        else:
            leg = confirmed(steps, "joint release")
        att = False
    elif recipe == "withholding":
        leg = confirmed(steps, "holder csv exit")
        att = not leg
    elif recipe == "selective_failure":
        leg = confirmed(steps, "holder csv exit") or confirmed(steps, "joint release")
        att = bit_leaked
    elif recipe == "proof_replay":
        leg = confirmed(steps, "joint release")
        att = confirmed(steps, "replayed release 2")
    else:
        leg = False
        att = unauth

    return {
        "attacker_success": bool(att),
        "legitimate_success": bool(leg),
        "legitimate_completion": bool(leg),
        "unauthorized_release": bool(unauth),
        "diverted_principal_sats": int(diverted),
        "secret_bit_leaked": bool(bit_leaked),
    }


def execute(binary, directory, rows=None) -> dict:
    rows = deepcopy(rows or catalog())
    cases = []
    with Regtest(binary, directory) as node:
        node.initialize_wallet()
        provenance = node.provenance
        session = Session(node)
        for row in rows:
            steps, funded_target, observed = run_case(session, row)
            outcome = score(row, steps, observed)
            cases.append(
                {
                    **row,
                    "scenario_id": row["id"],
                    "source_revision": dict(SOURCE_REVISION),
                    "funded_target": funded_target,
                    "keys": keys(),
                    "steps": steps,
                    "action_trace": steps,
                    "observed_final_state": observed,
                    "attacker_success": outcome["attacker_success"],
                    "legitimate_success": outcome["legitimate_success"],
                    "legitimate_completion": outcome["legitimate_completion"],
                    "unauthorized_release": outcome["unauthorized_release"],
                    "diverted_principal_sats": outcome["diverted_principal_sats"],
                    "holder_payout_sats": HOLDER_PAYOUT_SATS if outcome["legitimate_completion"] else 0,
                    "garbler_loss_sats": 0,
                    "outcome": outcome,
                    "expectation_met": outcome == row["expected"],
                    "evidence_level": EVIDENCE_LEVEL,
                }
            )
    report = finalize_report(TRACK, provenance, rows, cases)
    report["campaign_id"] = CAMPAIGN_ID
    report["evidence_level"] = EVIDENCE_LEVEL
    report["source_revision"] = dict(SOURCE_REVISION)
    # Recompute evidence_hash after attaching campaign metadata.
    report.pop("evidence_hash", None)
    report["evidence_hash"] = digest(report)
    return report


def step_problems(cid: str, steps: list[dict]) -> list[str]:
    """Each transaction step must agree with Core's own recorded testmempoolaccept result."""
    problems = []
    for s in steps:
        if s.get("kind") != "tx":
            continue
        result = s.get("mempool_result") or {}
        if bool(result.get("allowed")) != bool(s.get("allowed")):
            problems.append(f"{cid}: {s['label']} allowed flag disagrees with Core's mempool result")
        if s.get("allowed") != (s.get("reject_reason") is None):
            problems.append(f"{cid}: {s['label']} reject_reason inconsistent with allowed")
        if s.get("reject_reason") != result.get("reject-reason"):
            problems.append(f"{cid}: {s['label']} reject_reason differs from Core's mempool result")
        if s.get("confirmed") and not (s.get("allowed") and s.get("broadcast") and s.get("blockhash")):
            problems.append(f"{cid}: {s['label']} confirmed without being allowed, broadcast and mined")
        if s["label"] == "cosigned probe" and s.get("broadcast"):
            problems.append(f"{cid}: counterfactual probe was broadcast")
    return problems


def joint_draw(challenge: dict, commitments: list[str], k: int) -> int:
    """The kept index from a recorded joint challenge (the reveals and all k commitments)."""
    ch_hash = cashu_hash("joint-challenge", bytes.fromhex(challenge["reveal_holder"]),
                         bytes.fromhex(challenge["reveal_guardian"]), "".join(commitments))
    return int.from_bytes(ch_hash, "big") % k


def audit(report: dict) -> list[str]:
    """Offline audit of a saved `cashu-release` report."""
    rows = catalog()
    problems = check_report_envelope(report, TRACK, rows)
    if report.get("evidence_level") != EVIDENCE_LEVEL:
        problems.append(f"wrong evidence_level: {report.get('evidence_level')}")
    provenance = report.get("provenance", {})
    if provenance.get("subversion") != CORE_SUBVERSION or provenance.get("chain") != "regtest":
        problems.append(f"provenance is not {CORE_SUBVERSION} regtest: {provenance.get('subversion')}")
    by_id = {r["id"]: r for r in rows}
    for case in report.get("cases", []):
        row = by_id.get(case.get("id"))
        if row is None:
            continue
        cid = row["id"]
        for req in REQUIRED_RECEIPT_FIELDS:
            if req not in case:
                problems.append(f"{cid}: missing required receipt field {req}")
        if case.get("keys") != keys():
            problems.append(f"{cid}: keys differ from deterministic Cashu fixture keys")
        problems += [f"{cid}: {p}" for p in audit_transactions(case, keys())]

        # Re-run the deterministic setup ceremony offline and verify transcript_view & checks match!
        cfg = config_for(row["recipe"], row["profile"])
        attack = row["variant"] == "attack"
        prior_seeds = set()
        if row["recipe"] == "seed_delta_reuse":
            prior_stmt = _statement_for(cid, cfg, reserve_label="prior_withdrawal")
            prior_cer = run_ceremony(cid, cfg, prior_stmt, recipe=row["recipe"], attack=False, index=99)
            prior_seeds.add(prior_cer["kept_seed_sha256"])
        stmt0 = _statement_for(cid, cfg, reserve_label="reserve_0", holder_role="holder")
        cer0 = run_ceremony(cid, cfg, stmt0, recipe=row["recipe"], attack=attack, index=0, prior_seed_hashes=prior_seeds)
        cer_step = step(case["steps"], "ceremony")
        if cer_step is None or cer_step.get("transcript_view") != cer0["transcript_view"]:
            problems.append(f"{cid}: ceremony transcript_view disagrees with offline recomputation")
        graph0 = CashuGraph(cid, cfg, cer0["kept_registration"], index=0)
        fund_step = step(case["steps"], "fund")
        if fund_step is None or fund_step["outputs"]["reserve"]["script_pubkey"] != graph0.R.script_pubkey.hex():
            problems.append(f"{cid}: funded reserve scriptPubKey differs from rebuilt CashuGraph")
        if fund_step is None or fund_step["outputs"]["collateral"]["script_pubkey"] != graph0.C.script_pubkey.hex():
            problems.append(f"{cid}: funded collateral scriptPubKey differs from rebuilt CashuGraph")

        problems += step_problems(cid, case["steps"])

        # Recompute the off-chain selective-failure leak instead of trusting the recorded flag.
        observed = dict(case.get("observed_final_state", {}))
        if row["recipe"] == "selective_failure" and attack:
            leaked = False
            if cer0["ceremony_ok"]:
                leaked = selective_failure_probe(cer0, cfg, proof_for(cer0["statement_int"], honest=True))["secret_bit_leaked"]
            if observed.get("secret_bit_leaked") != leaked:
                problems.append(f"{cid}: recorded secret_bit_leaked differs from offline recomputation")
            observed["secret_bit_leaked"] = leaked
        if observed.get("diverted_principal_sats") != paid_to_attacker(case["steps"]):
            problems.append(f"{cid}: diverted_principal_sats differs from confirmed outputs paying the attacker")
        if observed.get("cut_and_choose_escaped") != row["cut_and_choose_escaped"]:
            problems.append(f"{cid}: cut_and_choose_escaped differs from the catalog's ceremony draw")

        rescored = score(row, case["steps"], observed)
        if rescored != case.get("outcome"):
            problems.append(f"{cid}: recorded outcome differs from rescored steps ({rescored} != {case.get('outcome')})")
    return problems
