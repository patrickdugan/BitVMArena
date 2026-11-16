"""BitVM3 claim-graph trajectories: a garbled circuit decides, Bitcoin Core enforces.

The graph mirrors the In-and-Out-Burger BitVM3 claim graph (patrickdugan/Spiral
76071a0, in-and-out-burger/iob/bitvm3.py):

    vault V  NUMS + { claim:   <D> CHECKSIGVERIFY <C> CHECKSIG
                      reclaim: <144> CSV DROP <D> CHECKSIG }
    claim K  NUMS + { payout:   <WINDOW> CSV DROP <D> CHECKSIG      -> P'   (D presigns)
                      disprove: SHA256 <H(reject)> EQUALVERIFY <W> CHECKSIG -> desk }
             + OP_RETURN "IOB3" || claim_id

The claimant garbles the statement circuit (gc.py) and hands the challenger the input
labels of its proof; the challenger evaluates. A false proof yields the reject label,
which opens the disprove leaf. Every recipe flips one design decision. Where the IOB
graph documents a trust assumption (T1 garbling correctness, T2 off-chain labels, a
single watcher, no claimant bond), the mutant profile is that assumption failing, not
a claim that the IOB code is broken. The toy circuit stands in for M14; sizes and the
evaluation latency are scaled, and recipes that depend on timing declare their delays.

Recipes are grouped by the layer a BitVM-dependent application exposes: garbling,
data availability, statement binding, the presigned transaction graph, mempool and
miners, liveness, and economics. `Config` carries every design decision, so the same
`Graph` serves the fixed catalog and the interactive episodes in `episode.py`.
"""

from __future__ import annotations

import hashlib
import struct
import time
from copy import deepcopy
from dataclasses import dataclass, field, replace

from . import gc
from .bitcoin import (ANYONECANPAY, NUMS, P2A, SIGHASH_DEFAULT, SIGHASH_NONE, SIGHASH_SINGLE, TapTree, Transaction,
                      bit_opening, number, op_return, ops, p2tr_key, public, push, sha)
from .canonical import ValidationError
from .core import Regtest, free_port
from .track import (Session, audit_transactions, check_report_envelope, confirmed, finalize_report, step,
                    utxo_input)

TRACK = "bitvm3"
UPSTREAM = {"target": "In-and-Out-Burger BitVM3 claim graph", "repository": "patrickdugan/Spiral",
            "commit": "76071a0", "path": "in-and-out-burger/iob/bitvm3.py",
            "garbling_engine": "garbled-snark-verifier half-gates (free-XOR, one Delta per garbling)"}
SECRETS = {"desk": 0xD35C0001, "claimant": 0xC1A10002, "watch": 0x3A7C0003, "third": 0x7A1D0004,
           "relayer": 0x2E1A0005, "payout": 0x9A700006, "refund": 0x2EF00007}
STATEMENT = 48_400
HONEST_PROOF = (40_000, 8_400)
FALSE_PROOF = (40_000, 9_400)
PRIOR_STATEMENT, PRIOR_PROOF = 51_000, (45_000, 6_000)
VAULT, BOND, FEE = 100_000, 20_000, 3_000
WINDOW, RECLAIM, HARDENED_WINDOW, LATENCY, CUT = 6, 144, 24, 8, 4
CENSOR = 8              # blocks a colluding miner can censor in a row (declared bound)
FAST_RECLAIM = 2        # the mutant desk reclaim delay
PAYMENT_DELAY = 3       # blocks the honest claimant spends paying the user before it claims
WATCH_FUNDS, CHILD_FEE = 10_000, 3_000
PIN_FLOOR = 2           # sat/vB a congested block needs from a package (declared fee market)
PIN_OUTPUTS, PIN_FEE, SMALL_PIN_FEE = 1_000, 12_000, 60
PIN_COIN, FEE_COIN, PAYOUT_BUMP = 400_000, 50_000, 15_000
PROPAGATION_WAIT = 30   # seconds a broadcast gets to reach the miner's mempool
TAG = b"IOB/bitvm3-claim/v1"
BURN_SPK = p2tr_key(NUMS).script_pubkey     # provably unspendable: nobody knows NUMS's discrete log

LAYERS = ("garbling", "data_availability", "statement_binding", "transaction_graph", "mempool_and_miners",
          "liveness", "economics")

RECIPES = {
    "labels_offchain_withheld": {
        "family": "input_label_availability", "layer": "data_availability", "attacker": "claimant",
        "iob_assumption": "T2", "bitvm2_relation": "introduced",
        "task": "Pay an honest claim after the window; stop a false claim with the reject label",
        "side": "Make a false claim and withhold the input labels so nobody can evaluate"},
    "garbling_unchecked": {
        "family": "garbling_correctness", "layer": "garbling", "attacker": "claimant", "iob_assumption": "T1",
        "bitvm2_relation": "changed",
        "task": "Register only correctly garbled instances", "side": "Register a garbling whose output decoding is swapped"},
    "cut_and_choose_grindable": {
        "family": "garbling_correctness", "layer": "garbling", "attacker": "claimant", "iob_assumption": None,
        "bitvm2_relation": "introduced",
        "task": "Open all but one committed garbling, chosen unpredictably",
        "side": "Grind a non-interactive cut-and-choose challenge so the bad instance is kept"},
    "seed_reuse_across_claims": {
        "family": "label_secrecy", "layer": "garbling", "attacker": "watch", "iob_assumption": None,
        "bitvm2_relation": "introduced",
        "task": "Use a fresh garbling seed per claim", "side": "Derive Delta from two claims' labels and disprove an honest claim"},
    "output_polarity_swapped": {
        "family": "output_decoding", "layer": "garbling", "attacker": "claimant", "iob_assumption": None,
        "bitvm2_relation": "carried",
        "task": "Bind the disprove leaf to the reject label", "side": "Make a false claim the swapped leaf cannot stop"},
    "single_watcher_disprove": {
        "family": "disprove_liveness", "layer": "liveness", "attacker": "claimant",
        "iob_assumption": "single watcher W", "bitvm2_relation": "changed",
        "task": "Let any holder of the reject label stop a false claim",
        "side": "Make a false claim while the one authorized watcher is offline"},
    "window_below_latency": {
        "family": "evaluation_latency", "layer": "liveness", "attacker": "claimant",
        "iob_assumption": "WINDOW=6 vs ~60 min M14 evaluation", "bitvm2_relation": "introduced",
        "task": "Keep the payout window longer than off-chain evaluation",
        "side": "Take the payout before the evaluator finishes"},
    "payout_csv_removed": {
        "family": "timelock", "layer": "transaction_graph", "attacker": "claimant", "iob_assumption": None,
        "bitvm2_relation": "carried",
        "task": "Hold the payout for the challenge window", "side": "Take the payout before anyone can disprove"},
    "payout_sighash_none": {
        "family": "presigned_binding", "layer": "transaction_graph", "attacker": "relayer", "iob_assumption": None,
        "bitvm2_relation": "carried",
        "task": "Pay the claimant's derived key P'", "side": "Redirect the presigned payout"},
    "claimant_unbonded": {
        "family": "economic_deterrence", "layer": "economics", "attacker": "claimant",
        "iob_assumption": "no claimant bond", "bitvm2_relation": "changed",
        "task": "Make a disproven false claim cost the claimant", "side": "Make a false claim that costs the claimant nothing"},
    "tables_delivered_late": {
        "family": "garbled_table_availability", "layer": "data_availability", "attacker": "claimant",
        "iob_assumption": None, "bitvm2_relation": "introduced",
        "task": "Deliver and check the garbled tables at setup, before the desk presigns",
        "side": "Hand the evaluator corrupted tables at claim time so evaluation yields no reject label"},
    "proof_replay_across_vaults": {
        "family": "statement_binding", "layer": "statement_binding", "attacker": "claimant",
        "iob_assumption": None, "bitvm2_relation": "carried",
        "task": "Bind each vault's statement to its own instance",
        "side": "Claim two vaults with one payment proof"},
    "claim_internal_key_spendable": {
        "family": "taproot_key_path", "layer": "transaction_graph", "attacker": "claimant",
        "iob_assumption": None, "bitvm2_relation": "carried",
        "task": "Give the claim output an unspendable internal key",
        "side": "Sweep the claim output through the Taproot key path, skipping window and disprove"},
    "claim_sighash_none": {
        "family": "presigned_binding", "layer": "transaction_graph", "attacker": "claimant",
        "iob_assumption": None, "bitvm2_relation": "carried",
        "task": "Presign the claim with its outputs committed",
        "side": "Rewrite the presigned claim to pay the vault straight to the claimant"},
    "payout_absolute_timelock": {
        "family": "timelock", "layer": "transaction_graph", "attacker": "claimant", "iob_assumption": None,
        "bitvm2_relation": "carried",
        "task": "Measure the challenge window from the claim (relative timelock)",
        "side": "Claim late, after an absolute payout height has passed, and pay out in the claim's block"},
    "reclaim_preempts_claim": {
        "family": "timelock_ordering", "layer": "transaction_graph", "attacker": "desk",
        "iob_assumption": "desk reclaim after 144 blocks", "bitvm2_relation": "carried",
        "task": "Keep the desk's reclaim path closed until the claimant has had time to claim",
        "side": "Reclaim the vault while the honest claimant is still paying the user"},
    "disprove_outputs_unbound": {
        "family": "label_knowledge", "layer": "transaction_graph", "attacker": "claimant",
        "iob_assumption": None, "bitvm2_relation": "introduced",
        "task": "Send a disproven claim back to the desk through outputs the desk fixed",
        "side": "Use the garbler's own knowledge of the reject label to spend the disprove path to itself"},
    "disprove_unbumpable": {
        "family": "fee_bumping", "layer": "mempool_and_miners", "attacker": "claimant",
        "iob_assumption": "desk offline at dispute time", "bitvm2_relation": "carried",
        "task": "Let a third-party watcher fee-bump a zero-fee presigned disprove (P2A anchor, TRUC package)",
        "side": "Make a false claim whose presigned zero-fee disprove nobody can get relayed"},
    "disprove_censored_by_miner": {
        "family": "censorship", "layer": "mempool_and_miners", "attacker": "claimant",
        "iob_assumption": f"a colluding miner censors at most {CENSOR} blocks in a row",
        "bitvm2_relation": "carried",
        "task": "Keep the window longer than any censorship the protocol assumes",
        "side": "Have a colluding miner keep the disprove out of blocks until the payout matures"},
    "bond_self_slash": {
        "family": "economic_deterrence", "layer": "economics", "attacker": "claimant",
        "iob_assumption": None, "bitvm2_relation": "carried",
        "task": "Burn a disproven claimant's bond",
        "side": "Disprove its own false claim (the garbler knows the reject label) and take the bond back"},
    "disprove_anchor_pinned": {
        "family": "pinning", "layer": "mempool_and_miners", "attacker": "claimant",
        "iob_assumption": "desk offline at dispute time", "bitvm2_relation": "carried",
        "task": "Keep a zero-fee disprove bumpable by the watcher in a congested fee market (TRUC anchor)",
        "side": "Pin the disprove under a large low-feerate child, then replace it with a high-fee payout"},
    "disprove_partitioned": {
        "family": "eclipse", "layer": "mempool_and_miners", "attacker": "claimant",
        "iob_assumption": None, "bitvm2_relation": "carried",
        "task": "Give the watcher a path to miners that the attacker does not control",
        "side": "Eclipse the watcher behind a blocks-only relay so its disprove never reaches a miner"},
    "disprove_watcher_redirect": {
        "family": "presigned_binding", "layer": "transaction_graph", "attacker": "watch",
        "iob_assumption": "W signs the disprove when it broadcasts; the refund output is convention",
        "bitvm2_relation": "changed",
        "task": "Return a disproven claim's vault to the desk through outputs the desk fixed",
        "side": "Disprove a false claim and pay the vault to the watcher"},
    "desk_key_retained": {
        "family": "committee_trust", "layer": "transaction_graph", "attacker": "desk",
        "iob_assumption": "the desk deletes its key after presigning", "bitvm2_relation": "carried",
        "task": "Pay an honest claim to P' even if the desk kept its key",
        "side": "Re-sign the matured payout to the desk itself"},
}
# Attack variants whose claimant holds an honest proof (the attacker targets something else).
HONEST_ATTACKS = {"seed_reuse_across_claims", "payout_sighash_none", "reclaim_preempts_claim",
                  "proof_replay_across_vaults", "desk_key_retained"}
# Expected honest_claim_paid on attack variants, where it differs from False.
PAID_ON_ATTACK = {"seed_reuse_across_claims": {"hardened": True},
                  "payout_sighash_none": {"hardened": True},
                  "reclaim_preempts_claim": {"hardened": True},
                  "proof_replay_across_vaults": {"hardened": True, "mutant": True},
                  "desk_key_retained": {"hardened": True}}


def catalog():
    rows = []
    for recipe, meta in RECIPES.items():
        for profile in ("hardened", "mutant"):
            for variant in ("benign", "attack"):
                attack = variant == "attack"
                success = attack and profile == "mutant"
                paid = PAID_ON_ATTACK.get(recipe, {}).get(profile, False) if attack else True
                rows.append({"schema_version": 1, "id": f"{TRACK}.{recipe}.{profile}.{variant}", "track": TRACK,
                             "recipe": recipe, "family": meta["family"], "layer": meta["layer"],
                             "profile": profile, "variant": variant,
                             "attacker": meta["attacker"] if attack else None,
                             "main_task": meta["task"], "side_task": meta["side"] if attack else None,
                             "iob_assumption": meta["iob_assumption"], "bitvm2_relation": meta["bitvm2_relation"],
                             "expected": {"attack_success": success, "honest_claim_paid": paid},
                             "upstream": UPSTREAM, "evidence_level": "bitcoin-core-regtest-transactions",
                             "upstream_exploit_claim": False})
    return rows


@dataclass(frozen=True)
class Stage:
    """Keys, garbling-seed salt and amounts of one run.

    FIXTURE is the regtest catalog's stage: the public test secrets above, no salt, and the
    module amounts. A run on a public network uses fresh secrets, a fresh salt and small
    amounts (testnet4.py). An auditor rebuilds graphs from the public keys alone
    (`secrets=None`); only signing needs the secrets.
    """
    keys: dict                      # name -> 32-byte x-only public key
    secrets: dict | None = None     # name -> secret scalar
    salt: bytes = b""
    vault: int = VAULT
    bond: int = BOND
    fee: int = FEE
    watch_funds: int = WATCH_FUNDS
    child_fee: int = CHILD_FEE
    claim_feerate: int | None = None      # sat/kvB for the claim; None: the claim pays `fee`

    @classmethod
    def from_secrets(cls, secrets, **fields):
        return cls({name: public(secret) for name, secret in secrets.items()}, dict(secrets), **fields)

    def secret(self, name):
        if not self.secrets:
            raise ValidationError("this stage has public keys only and cannot sign")
        return self.secrets[name]

    def spk(self, name):
        return p2tr_key(self.keys[name]).script_pubkey

    def seed(self, case_id, tag):
        return sha(self.salt + f"{case_id}:{tag}".encode())[:16]

    def public_keys(self):
        return {name: key.hex() for name, key in self.keys.items()}


FIXTURE = Stage.from_secrets(SECRETS)


def keys():
    return FIXTURE.public_keys()


def frame(data):
    return struct.pack(">I", len(data)) + data


def seed(case_id, tag):
    return FIXTURE.seed(case_id, tag)


def spk_of(name):
    return FIXTURE.spk(name)


@dataclass
class Config:
    """Every design decision of one claim graph. Defaults are the IOB graph as built."""
    labels_onchain: bool = False
    disprove_mode: str = "watcher"       # watcher | presigned | presigned_single | hashlock
    polarity: str = "reject"
    window: int = WINDOW
    payout_csv: bool = True
    payout_timelock: str = "csv"         # csv | cltv (absolute height fixed at setup)
    payout_hash_type: int = SIGHASH_DEFAULT
    bond: bool = False
    bond_burn: bool = False              # a disproven bond is burned rather than paid to the disprover
    cut_and_choose: str = "none"         # none | interactive | fiat_shamir
    seed_reuse: bool = False
    claim_internal: str = "nums"         # nums | claimant: Taproot internal key of the claim output
    claim_hash_type: int = SIGHASH_DEFAULT
    reclaim: int = RECLAIM
    statement_binding: str = "instance"  # instance | shared: several vaults, one statement
    tables_at: str = "setup"             # setup | claim: when evaluators receive the garbled tables
    disprove_fee: str = "included"       # included | zero_no_anchor | zero_anchor (v3 + P2A) | zero_anchor_v2
    payout_cosigned: bool = False        # the payout leaf also needs the claimant's signature
    watcher_network: str = "independent"  # independent | eclipsed: the watcher's peers

    def check(self):
        allowed = {"disprove_mode": ("watcher", "presigned", "presigned_single", "hashlock"),
                   "polarity": ("reject", "accept"), "payout_timelock": ("csv", "cltv"),
                   "cut_and_choose": ("none", "interactive", "fiat_shamir"),
                   "claim_internal": ("nums", "claimant"), "statement_binding": ("instance", "shared"),
                   "tables_at": ("setup", "claim"), "watcher_network": ("independent", "eclipsed"),
                   "disprove_fee": ("included", "zero_no_anchor", "zero_anchor", "zero_anchor_v2")}
        for name, values in allowed.items():
            if getattr(self, name) not in values:
                raise ValidationError(f"config {name} must be one of {values}")
        for name in ("payout_hash_type", "claim_hash_type"):
            if getattr(self, name) not in (0, 1, 2, 3, 0x81, 0x82, 0x83):
                raise ValidationError(f"config {name} is not a sighash type")
        if not 1 <= self.window <= 1000 or not 1 <= self.reclaim <= 10_000:
            raise ValidationError("window or reclaim out of range")
        if self.disprove_fee != "included" and self.disprove_mode not in ("presigned", "presigned_single"):
            raise ValidationError("a zero-fee disprove must be presigned")
        if self.disprove_fee != "included" and self.bond:
            raise ValidationError("zero-fee disprove profiles are unbonded")
        return self


def config(recipe, profile):
    m = profile == "mutant"
    disprove = "watcher"
    if recipe == "single_watcher_disprove" and not m or recipe in ("disprove_unbumpable", "disprove_anchor_pinned"):
        disprove = "presigned"
    elif recipe == "disprove_outputs_unbound":
        disprove = "hashlock" if m else "presigned"
    elif recipe == "bond_self_slash":
        disprove = "presigned_single" if m else "presigned"
    elif recipe == "disprove_watcher_redirect" and not m:
        disprove = "presigned"
    return Config(
        labels_onchain=recipe == "labels_offchain_withheld" and not m,
        disprove_mode=disprove,
        polarity="accept" if recipe == "output_polarity_swapped" and m else "reject",
        window=HARDENED_WINDOW if recipe in ("window_below_latency", "disprove_censored_by_miner") and not m else WINDOW,
        payout_csv=not (recipe == "payout_csv_removed" and m),
        payout_timelock="cltv" if recipe == "payout_absolute_timelock" and m else "csv",
        payout_hash_type=(SIGHASH_NONE if recipe == "payout_sighash_none" and m else
                          SIGHASH_SINGLE | ANYONECANPAY if recipe == "disprove_anchor_pinned" else SIGHASH_DEFAULT),
        bond=recipe == "claimant_unbonded" and not m or recipe == "bond_self_slash",
        bond_burn=recipe == "bond_self_slash" and not m,
        cut_and_choose=({"garbling_unchecked": "none" if m else "interactive",
                         "cut_and_choose_grindable": "fiat_shamir" if m else "interactive"}.get(recipe, "none")),
        seed_reuse=recipe == "seed_reuse_across_claims" and m,
        claim_internal="claimant" if recipe == "claim_internal_key_spendable" and m else "nums",
        claim_hash_type=SIGHASH_NONE if recipe == "claim_sighash_none" and m else SIGHASH_DEFAULT,
        reclaim=FAST_RECLAIM if recipe == "reclaim_preempts_claim" and m else RECLAIM,
        statement_binding="shared" if recipe == "proof_replay_across_vaults" and m else "instance",
        tables_at="claim" if recipe == "tables_delivered_late" and m else "setup",
        disprove_fee=(("zero_no_anchor" if m else "zero_anchor") if recipe == "disprove_unbumpable" else
                      ("zero_anchor_v2" if m else "zero_anchor") if recipe == "disprove_anchor_pinned" else "included"),
        payout_cosigned=recipe == "desk_key_retained" and not m,
        watcher_network="eclipsed" if recipe == "disprove_partitioned" and m else "independent")


ASSUMPTIONS = {"evaluation_latency_blocks": LATENCY, "censorship_blocks": CENSOR,
               "claim_deadline_blocks": PAYMENT_DELAY, "desk_online_at_dispute": True,
               "watchers": 1, "claims_per_garbling_seed": 1, "vaults_per_statement": 1,
               "desk_keys_deleted": False}


def assess(cfg, assumptions=None):
    """Static exposure check of one design: which catalog recipes' failure modes it has.

    Each finding names the recipe whose mutant trajectory demonstrates the failure on
    Core, so it can be replayed (`native run --match <recipe>`) or tried as an episode.
    """
    cfg = cfg.check()
    a = dict(ASSUMPTIONS)
    unknown = set(assumptions or {}) - set(a)
    if unknown:
        raise ValidationError(f"unknown assumptions: {sorted(unknown)}")
    a.update(assumptions or {})
    rules = [
        (not cfg.labels_onchain, "labels_offchain_withheld", "input labels travel off-chain; withholding them pays a false claim"),
        (cfg.tables_at == "claim", "tables_delivered_late", "garbled tables arrive at claim time; corrupt tables leave no reject label"),
        (cfg.cut_and_choose == "none", "garbling_unchecked", "garbling correctness is never checked"),
        (cfg.cut_and_choose == "fiat_shamir", "cut_and_choose_grindable", "the cut-and-choose challenge is a hash the garbler can grind"),
        (cfg.seed_reuse or a["claims_per_garbling_seed"] > 1, "seed_reuse_across_claims", "a garbling seed serves more than one claim; Delta can leak"),
        (cfg.polarity != "reject", "output_polarity_swapped", "the disprove leaf is not bound to the reject label"),
        (cfg.statement_binding == "shared" or a["vaults_per_statement"] > 1, "proof_replay_across_vaults",
         "one statement covers several vaults; one proof can claim them all"),
        (not cfg.payout_csv and cfg.payout_timelock == "csv", "payout_csv_removed", "the payout has no timelock"),
        (cfg.payout_timelock == "cltv", "payout_absolute_timelock", "the window is an absolute height; a late claim has no window"),
        (cfg.payout_hash_type & 3 == SIGHASH_NONE, "payout_sighash_none", "the payout presignature commits to no output"),
        (cfg.claim_hash_type & 3 == SIGHASH_NONE, "claim_sighash_none", "the claim presignature commits to no output"),
        (cfg.claim_internal != "nums", "claim_internal_key_spendable", "the claim output has a spendable key path"),
        (cfg.reclaim <= a["claim_deadline_blocks"], "reclaim_preempts_claim", "the desk can reclaim before the claimant's deadline"),
        (cfg.disprove_mode == "hashlock", "disprove_outputs_unbound", "the garbler can spend the disprove path to itself"),
        (cfg.disprove_fee == "zero_no_anchor" and not a["desk_online_at_dispute"], "disprove_unbumpable",
         "a zero-fee presigned disprove has no anchor and nobody online to bump it"),
        (cfg.payout_csv and cfg.window <= a["censorship_blocks"], "disprove_censored_by_miner",
         "the window is no longer than the censorship the design must survive"),
        (cfg.disprove_mode == "watcher" and a["watchers"] <= 1, "single_watcher_disprove", "only one watcher can disprove"),
        (cfg.payout_csv and cfg.window <= a["evaluation_latency_blocks"], "window_below_latency",
         "the window ends before evaluation can finish"),
        (not cfg.bond, "claimant_unbonded", "a false claim costs the claimant nothing"),
        (cfg.bond and not cfg.bond_burn and cfg.disprove_mode in ("presigned_single", "hashlock"), "bond_self_slash",
         "the bond goes to whoever disproves, including the claimant"),
        (cfg.disprove_fee == "zero_anchor_v2", "disprove_anchor_pinned",
         "the zero-fee disprove's anchor is not TRUC; a large low-feerate child can pin it"),
        (cfg.watcher_network == "eclipsed", "disprove_partitioned", "the watcher's only peers are controlled by the attacker"),
        (cfg.disprove_mode == "watcher", "disprove_watcher_redirect", "the watcher signs the disprove and chooses its outputs"),
        (not cfg.payout_cosigned and not a["desk_keys_deleted"], "desk_key_retained",
         "the desk alone signs the payout and may still hold its key"),
    ]
    findings = [{"recipe": recipe, "layer": RECIPES[recipe]["layer"], "family": RECIPES[recipe]["family"],
                 "why": why, "replay": f"bitvm3.{recipe}.mutant.attack"} for hit, recipe, why in rules if hit]
    return {"config": cfg.__dict__, "assumptions": a, "findings": findings,
            "layers_exposed": sorted({f["layer"] for f in findings}, key=LAYERS.index)}


def statement_for(cfg, index):
    """Vault `index`'s statement. Instance binding folds the index into the statement."""
    return STATEMENT if index == 0 or cfg.statement_binding == "shared" else STATEMENT + index


def published(garbling, swapped=False):
    """Public data a garbler registers; `swapped` is the malicious decoding swap."""
    data = garbling.public()
    if swapped:
        data["accept_label_sha256"], data["reject_label_sha256"] = (data["reject_label_sha256"],
                                                                    data["accept_label_sha256"])
    data["input_label_sha256"] = [[hashlib.sha256(garbling.input_label(i, b)).hexdigest() for b in (0, 1)]
                                  for i in range(garbling.circuit.inputs)]
    return data


def commit(salt, data):
    body = (salt + bytes.fromhex(data["ciphertext_commitment"]) + bytes.fromhex(data["accept_label_sha256"])
            + bytes.fromhex(data["reject_label_sha256"]))
    return hashlib.sha256(b"bitvm-arena/cut-and-choose\x00" + body).hexdigest()


def corrupt_tables(tables):
    """The claimant's tampered copy: one bit flipped in every ciphertext. (With
    point-and-permute an evaluator skips a gate's table when both select bits are 0, so
    a single flipped entry can go unread.)"""
    return [(tg[:-1] + bytes([tg[-1] ^ 1]), te[:-1] + bytes([te[-1] ^ 1])) for tg, te in tables]


def tables_commitment(tables):
    h = hashlib.sha256(b"bitvm-arena/gc/ciphertexts\x00")
    for tg, te in tables:
        h.update(tg + te)
    return h.hexdigest()


@dataclass
class Prepared:
    row: dict
    cfg: Config
    garbling: object            # the instance the graph uses (garbler's private view)
    public: dict                # what was registered for it
    desk_presigns: bool
    setup_log: dict = field(default_factory=dict)
    prior: object = None        # G4: the earlier claim's garbling
    statement: int = STATEMENT
    index: int = 0              # vault instance
    stage: Stage = FIXTURE


def prepare(row, index=0, cfg=None, stage=FIXTURE):
    """Deterministic setup: garbling(s), cut-and-choose, and the desk's presign decision."""
    seed = stage.seed
    recipe = row["recipe"]
    cfg = (cfg or config(recipe, row["profile"])).check()
    attack, cid = row["variant"] == "attack", row["id"]
    statement = statement_for(cfg, index)
    log = {}
    malicious = attack and recipe in ("garbling_unchecked", "cut_and_choose_grindable")
    if cfg.cut_and_choose == "none":
        garbling = gc.garble(statement, seed(cid, "garbling" if index == 0 else f"garbling/v{index}"))
        data = published(garbling, swapped=malicious)
        log["cut_and_choose"] = "not run (desk presigns the registered instance)"
        prep = Prepared(row, cfg, garbling, data, True, log, statement=statement, index=index, stage=stage)
    else:
        instances = [gc.garble(statement, seed(cid, f"instance{i}")) for i in range(CUT)]

        def fiat_shamir(commitments):
            return int(hashlib.sha256("".join(commitments).encode()).hexdigest(), 16) % CUT

        bad = set()
        if malicious and recipe == "garbling_unchecked":
            bad = set(range(CUT))
        elif malicious:
            # The cheater swaps one instance, chosen so that an ungrounded challenge would
            # open it: any success below comes from grinding, not from a lucky draw.
            for m in range(CUT):
                trial = [commit(bytes(16), published(g, swapped=i == m)) for i, g in enumerate(instances)]
                if fiat_shamir(trial) != m:
                    bad = {m}
                    break
        datas = [published(g, swapped=i in bad) for i, g in enumerate(instances)]
        salts = [bytes(16)] * CUT
        commitments = [commit(salts[i], datas[i]) for i in range(CUT)]
        attempts = 0
        if cfg.cut_and_choose == "fiat_shamir":
            def challenge():
                return fiat_shamir(commitments)
            if bad:
                target = min(bad)
                while challenge() != target:
                    attempts += 1
                    salts[target] = attempts.to_bytes(16, "big")
                    commitments[target] = commit(salts[target], datas[target])
            kept = challenge()
            log["challenge"] = "sha256(commitments) mod k (garbler can grind)"
        else:
            nonce = 0
            while True:
                secret = seed(cid, f"challenger{nonce}")
                kept = int(hashlib.sha256(secret + "".join(commitments).encode()).hexdigest(), 16) % CUT
                if not bad or len(bad) == CUT or kept not in bad:
                    break
                nonce += 1
            log["challenge"] = "challenger randomness drawn after the commitments"
            log["challenger_nonce"] = nonce
            if bad and len(bad) < CUT:
                log["escape_probability_per_attempt"] = f"{len(bad)}/{CUT}"
        opened = [i for i in range(CUT) if i != kept]
        checks = {i: gc.check_opening(statement, seed(cid, f"instance{i}"), datas[i]) for i in opened}
        log.update(k=CUT, malicious=sorted(bad), grind_attempts=attempts, kept=kept,
                   commitments=commitments, opened_checks={str(i): ok for i, ok in checks.items()})
        prep = Prepared(row, cfg, instances[kept], datas[kept], all(checks.values()), log,
                        statement=statement, index=index, stage=stage)
    if recipe == "seed_reuse_across_claims":
        prior_seed = seed(cid, "garbling") if cfg.seed_reuse else seed(cid, "prior-garbling")
        prep.prior = gc.garble(PRIOR_STATEMENT, prior_seed)
        log["prior_claim_seed"] = "same seed as this claim" if cfg.seed_reuse else "independent seed"
    return prep


class Graph:
    def __init__(self, prep, cltv_height=None):
        self.prep, self.cfg, self.data = prep, prep.cfg, prep.public
        self.stage = stage = getattr(prep, "stage", FIXTURE)
        self.D, self.C, self.W = (stage.keys[n] for n in ("desk", "claimant", "watch"))
        if self.cfg.payout_timelock == "cltv" and cltv_height is None:
            raise ValidationError("an absolute payout timelock needs its setup height")
        self.cltv_height = cltv_height if self.cfg.payout_timelock == "cltv" else None
        label_hash = self.data["reject_label_sha256" if self.cfg.polarity == "reject" else "accept_label_sha256"]
        self.disprove_hash = bytes.fromhex(label_hash)
        claim = push(self.D) + ops("CHECKSIGVERIFY") + push(self.C) + ops("CHECKSIG")
        if self.cfg.labels_onchain:
            openings = b"".join(bit_opening(bytes.fromhex(h0), bytes.fromhex(h1)) + ops("DROP")
                                for h0, h1 in self.data["input_label_sha256"])
            claim = openings + claim
        reclaim = number(self.cfg.reclaim) + ops("CSV", "DROP") + push(self.D) + ops("CHECKSIG")
        self.V = TapTree((claim, reclaim))
        if self.cltv_height is not None:
            lock = number(self.cltv_height) + ops("CLTV", "DROP")
        elif self.cfg.payout_csv:
            lock = number(self.cfg.window) + ops("CSV", "DROP")
        else:
            lock = b""
        cosign = ops("CHECKSIGVERIFY") + push(self.C) if self.cfg.payout_cosigned else b""
        payout = lock + push(self.D) + cosign + ops("CHECKSIG")
        mode = self.cfg.disprove_mode
        if mode == "hashlock":
            disprove = ops("SHA256") + push(self.disprove_hash) + ops("EQUAL")
        else:
            signer = self.D if mode in ("presigned", "presigned_single") else self.W
            disprove = ops("SHA256") + push(self.disprove_hash) + ops("EQUALVERIFY") + push(signer) + ops("CHECKSIG")
        self.K = TapTree((payout, disprove), self.C if self.cfg.claim_internal == "claimant" else NUMS)
        self.bond_tree = TapTree((push(self.C) + ops("CHECKSIG"),))
        self.payout_spk = stage.spk("payout")
        self.refund_spk = stage.spk("refund")
        self.fee = stage.fee
        self.claim_fee = self._claim_fee()
        self.k_value = stage.vault + (stage.bond if self.cfg.bond else 0) - self.claim_fee

    def _claim_fee(self):
        """The claim's fee: `fee`, or a feerate times the signed claim's virtual size (which
        does not depend on the amounts or on the signatures' values)."""
        rate = self.stage.claim_feerate
        if rate is None:
            return self.stage.fee
        dummy = {"txid": "00" * 32, "vout": 0, "amount": 0, "script_pubkey": self.V.script_pubkey.hex()}
        ins = [utxo_input(dummy, 0xffffffff)] + ([utxo_input(dummy)] if self.cfg.bond else [])
        tx = Transaction(ins, [(0, self.K.script_pubkey), (0, op_return(b"IOB3" + bytes(32)))])
        leaf = self.V.leaf(0)
        sig_d = bytes(64 if self.cfg.claim_hash_type == SIGHASH_DEFAULT else 65)
        labels = []
        if self.cfg.labels_onchain:
            labels = self.prep.garbling.input_labels(gc.proof_bits(*HONEST_PROOF))
        tx.inputs[0].witness = [bytes(64), sig_d] + labels + [leaf.script, leaf.control]
        if self.cfg.bond:
            bond_leaf = self.bond_tree.leaf(0)
            tx.inputs[1].witness = [bytes(64), bond_leaf.script, bond_leaf.control]
        return -(-tx.vsize * rate // 1000)

    def claim_id(self):
        h = hashlib.sha256(frame(TAG))
        for part in (self.prep.row["id"].encode(), self.prep.statement.to_bytes(4, "big"), b"bitvm-arena/toy-adder-16",
                     bytes.fromhex(self.data["ciphertext_commitment"]), bytes.fromhex(self.data["accept_label_sha256"]),
                     bytes.fromhex(self.data["reject_label_sha256"]), self.payout_spk):
            h.update(frame(part))
        return h.digest()

    def funding(self, extra=None):
        outputs = {"vault": (self.V, self.stage.vault)}
        if self.cfg.bond:
            outputs["bond"] = (self.bond_tree, self.stage.bond)
        outputs.update(extra or {})
        return outputs

    def claim_outputs(self):
        return [(self.k_value, self.K.script_pubkey), (0, op_return(b"IOB3" + self.claim_id()))]

    def claim_tx(self, utxos, labels, desk_signs=True, outputs=None):
        """The claim. The desk presigned it at setup over the canonical outputs with
        `claim_hash_type`; `outputs` is a claimant rewrite that keeps that presignature."""
        ins = [utxo_input(utxos["vault"], 0xffffffff)]
        if self.cfg.bond:
            ins.append(utxo_input(utxos["bond"]))
        tx = Transaction(ins, self.claim_outputs())
        leaf = self.V.leaf(0)
        # Without the desk's presignature the claimant can only sign in its place.
        sig_d = tx.signature(0, leaf, self.stage.secret("desk" if desk_signs else "claimant"),
                             self.cfg.claim_hash_type if desk_signs else SIGHASH_DEFAULT)
        if outputs is not None:
            tx.outputs = list(outputs)
        sig_c = tx.signature(0, leaf, self.stage.secret("claimant"))
        stack = [sig_c, sig_d] + (list(reversed(labels)) if self.cfg.labels_onchain else [])
        tx.inputs[0].witness = stack + [leaf.script, leaf.control]
        if self.cfg.bond:
            bond_leaf = self.bond_tree.leaf(0)
            tx.inputs[1].witness = [tx.signature(1, bond_leaf, self.stage.secret("claimant")), bond_leaf.script,
                                    bond_leaf.control]
        return tx

    def k_utxo(self, claim):
        return {"txid": claim.txid, "vout": 0, "amount": self.k_value, "script_pubkey": self.K.script_pubkey.hex()}

    def payout_tx(self, claim, destination=None):
        if self.cltv_height is not None:
            tx = Transaction([utxo_input(self.k_utxo(claim), 0xfffffffe)], [(self.k_value - self.fee, self.payout_spk)],
                             locktime=self.cltv_height)
        else:
            sequence = self.cfg.window if self.cfg.payout_csv else 0xfffffffd
            tx = Transaction([utxo_input(self.k_utxo(claim), sequence)], [(self.k_value - self.fee, self.payout_spk)])
        leaf = self.K.leaf(0)
        sig_d = tx.signature(0, leaf, self.stage.secret("desk"), self.cfg.payout_hash_type)
        cosig = [tx.signature(0, leaf, self.stage.secret("claimant"))] if self.cfg.payout_cosigned else []
        tx.inputs[0].witness = cosig + [sig_d, leaf.script, leaf.control]
        if destination is not None:     # an outsider rewrites the outputs, keeping the desk's witness
            tx.outputs = [(self.k_value - self.fee, destination)]
        return tx

    def desk_payout_tx(self, claim, destination, fee=None):
        """A desk that kept its key signs the matured payout to `destination` itself. Under a
        cosigned payout leaf it has no claimant signature and can only put its own in that slot."""
        fee = 2 * self.fee if fee is None else fee
        sequence = self.cfg.window if self.cfg.payout_csv else 0xfffffffd
        tx = Transaction([utxo_input(self.k_utxo(claim), sequence)], [(self.k_value - fee, destination)])
        leaf = self.K.leaf(0)
        sig_d = tx.signature(0, leaf, self.stage.secret("desk"))
        tx.inputs[0].witness = ([sig_d] if self.cfg.payout_cosigned else []) + [sig_d, leaf.script, leaf.control]
        return tx

    def disprove_outputs(self, beneficiary, fee=None):
        fee = self.fee if fee is None else fee
        if self.cfg.disprove_fee == "zero_no_anchor":
            return [(self.k_value, self.refund_spk)]
        if self.cfg.disprove_fee in ("zero_anchor", "zero_anchor_v2"):
            return [(self.k_value, self.refund_spk), (0, P2A)]
        if self.cfg.bond:
            return [(self.stage.vault - self.claim_fee - self.fee, self.refund_spk),
                    (self.stage.bond - (fee - self.fee), BURN_SPK if self.cfg.bond_burn else beneficiary)]
        if self.cfg.disprove_mode == "hashlock":
            return [(self.k_value - fee, beneficiary)]
        return [(self.k_value - fee, self.refund_spk)]

    def disprove_tx(self, claim, label, signer, beneficiary=None, fee=None, outputs=None):
        """The disprove spend. `beneficiary` takes whatever output the mode leaves open
        (a bond reward, or everything under a hashlock-only leaf). `outputs` replaces the
        outputs before signing: only a signer who chooses them (the watcher) can do that."""
        if beneficiary is None:
            beneficiary = self.stage.spk(signer)
        version = 3 if self.cfg.disprove_fee == "zero_anchor" else 2
        tx = Transaction([utxo_input(self.k_utxo(claim))], list(outputs) if outputs is not None
                         else self.disprove_outputs(beneficiary, fee), version=version)
        leaf = self.K.leaf(1)
        mode = self.cfg.disprove_mode
        if mode == "hashlock":
            tx.inputs[0].witness = [label, leaf.script, leaf.control]
        else:
            key = "desk" if mode in ("presigned", "presigned_single") else signer
            hash_type = SIGHASH_SINGLE if mode == "presigned_single" else SIGHASH_DEFAULT
            tx.inputs[0].witness = [tx.signature(0, leaf, self.stage.secret(key), hash_type), label, leaf.script,
                                    leaf.control]
        return tx

    def anchor_child(self, parent, fee_utxo, fee=None):
        """Child spending the disprove's P2A anchor plus the watcher's own coin (the parent's version)."""
        fee = self.stage.child_fee if fee is None else fee
        anchor = {"txid": parent.txid, "vout": 1, "amount": 0, "script_pubkey": P2A.hex()}
        tx = Transaction([utxo_input(anchor), utxo_input(fee_utxo)],
                         [(fee_utxo["amount"] - fee, self.stage.spk("watch"))], version=parent.version)
        tx.inputs[1].witness = [tx.signature(1, None, p2tr_key(self.W).tweaked_secret(self.stage.secret("watch")))]
        return tx

    def pin_child(self, parent, coin, outputs, fee):
        """The claimant's child on the keyless anchor: `outputs` dust-sized outputs back to itself
        make it large, and a low feerate keeps the package below a congested fee floor."""
        anchor = {"txid": parent.txid, "vout": 1, "amount": 0, "script_pubkey": P2A.hex()}
        mine = p2tr_key(self.C).script_pubkey
        body = [(330, mine)] * (outputs - 1)
        change = coin["amount"] - 330 * (outputs - 1) - fee
        tx = Transaction([utxo_input(anchor), utxo_input(coin)], body + [(change, mine)], version=parent.version)
        tx.inputs[1].witness = [tx.signature(1, None, p2tr_key(self.C).tweaked_secret(self.stage.secret("claimant")))]
        return tx

    def payout_with_fee(self, claim, coin, extra):
        """The presigned payout (SINGLE|ANYONECANPAY) plus a fee input and change from the claimant."""
        tx = Transaction([utxo_input(self.k_utxo(claim), self.cfg.window), utxo_input(coin)],
                         [(self.k_value - self.fee, self.payout_spk), (coin["amount"] - extra, self.payout_spk)])
        leaf = self.K.leaf(0)
        sig_d = tx.signature(0, leaf, self.stage.secret("desk"), self.cfg.payout_hash_type)
        tx.inputs[0].witness = [sig_d, leaf.script, leaf.control]
        payout_key = p2tr_key(self.stage.keys["payout"])
        tx.inputs[1].witness = [tx.signature(1, None, payout_key.tweaked_secret(self.stage.secret("payout")))]
        return tx

    def sweep_tx(self, claim, destination):
        """Key-path spend of the claim output by the claimant, as if it were the internal key."""
        tx = Transaction([utxo_input(self.k_utxo(claim))], [(self.k_value - self.fee, destination)])
        tree = TapTree(self.K.scripts, self.C)
        tx.inputs[0].witness = [tx.signature(0, None, tree.tweaked_secret(self.stage.secret("claimant")))]
        return tx

    def reclaim_tx(self, utxo):
        tx = Transaction([utxo_input(utxo, self.cfg.reclaim)], [(self.stage.vault - self.fee, self.refund_spk)])
        leaf = self.V.leaf(1)
        tx.inputs[0].witness = [tx.signature(0, leaf, self.stage.secret("desk")), leaf.script, leaf.control]
        return tx


def rewrite(tx, outputs):
    """Same inputs and witnesses, different outputs: what a party does with a presignature."""
    return Transaction(tx.inputs, list(outputs), tx.locktime, tx.version)


def labels_from_claim(raw):
    """What a challenger reads from the chain when labels are revealed in the claim witness."""
    witness = Transaction.parse(raw).inputs[0].witness
    return list(reversed(witness[2:-2]))


def evaluator_tables(prep, handed_corrupt):
    """Tables the evaluator actually uses: its setup copy, or what the claimant handed over."""
    if prep.cfg.tables_at == "claim" and handed_corrupt:
        return corrupt_tables(prep.garbling.tables), "claim handover"
    return prep.garbling.tables, "setup" if prep.cfg.tables_at == "setup" else "claim handover"


def proof_for(row):
    attack = row["variant"] == "attack"
    return FALSE_PROOF if attack and row["recipe"] not in HONEST_ATTACKS else HONEST_PROOF


def setup_record(session, prep, graph, statement):
    session.offchain("setup", "claimant", statement=statement, registered=graph.data["ciphertext_commitment"],
                     accept_label_sha256=graph.data["accept_label_sha256"],
                     reject_label_sha256=graph.data["reject_label_sha256"],
                     disprove_leaf_hash=graph.disprove_hash.hex(), log=prep.setup_log,
                     desk_presigns=prep.desk_presigns, config=prep.cfg.__dict__, cltv_height=graph.cltv_height)


def run_pinning_case(session, row, stage=FIXTURE):
    """A congested fee market, a zero-fee presigned disprove with a keyless anchor, a desk offline."""
    attack = row["variant"] == "attack"
    cfg = config(row["recipe"], row["profile"])
    session.begin(stage.public_keys())
    prep = prepare(row, stage=stage)
    graph = Graph(prep)
    proof = proof_for(row)
    setup_record(session, prep, graph, prep.statement)
    session.offchain("fee market", "environment", fee_floor_sat_vb=PIN_FLOOR,
                     note="blocks after the claim only have room for packages paying at least the floor")
    utxos = session.fund(graph.funding({"watch_fee": (p2tr_key(graph.W), stage.watch_funds),
                                        "claimant_pin": (p2tr_key(graph.C), PIN_COIN),
                                        "claimant_fee": (p2tr_key(stage.keys["payout"]), FEE_COIN)}))
    labels = prep.garbling.input_labels(gc.proof_bits(*proof))
    session.offchain("claim proof", "claimant", proof=list(proof), statement=prep.statement)
    claim = graph.claim_tx(utxos, labels)
    session.submit("claim", "claimant", claim)
    session.mine(1, "claim confirmed")
    conf = 1
    if attack:
        # The garbler knows the reject label, so it can broadcast the presigned disprove itself,
        # with a child of its choosing on the keyless anchor.
        parent = graph.disprove_tx(claim, prep.garbling.reject_label, "claimant")
        big = graph.pin_child(parent, utxos["claimant_pin"], PIN_OUTPUTS, PIN_FEE)
        if not session.submit_package([("pinned disprove", parent), ("pin child", big)], "claimant",
                                      note=f"{PIN_OUTPUTS}-output child paying {PIN_FEE} sats"):
            small = graph.pin_child(parent, utxos["claimant_pin"], 1, SMALL_PIN_FEE)
            session.submit_package([("pinned disprove", parent), ("small pin child", small)], "claimant",
                                   note="the largest child the anchor accepts, at the lowest feerate")
    session.offchain("label handover", "claimant", to=["watch"], labels=[x.hex() for x in labels])
    out_label = gc.evaluate(prep.statement, prep.garbling.tables, labels)
    verdict = gc.decode(out_label, graph.data["accept_label_sha256"], graph.data["reject_label_sha256"])
    session.offchain("evaluate", "watch", labels=[x.hex() for x in labels], tables_source="setup",
                     tables_commitment=tables_commitment(prep.garbling.tables), output_label=out_label.hex(),
                     verdict=verdict)
    if verdict == "reject":
        disprove = graph.disprove_tx(claim, out_label, "watch")
        child = graph.anchor_child(disprove, utxos["watch_fee"])
        if disprove.txid in session.mempool():
            session.submit("disprove fee child", "watch", child,
                           note="the disprove is already in the mempool; this child must replace the claimant's")
        else:
            session.submit_package([("disprove", disprove), ("disprove fee child", child)], "watch")
    while conf < cfg.window:
        session.mine_congested(1, PIN_FLOOR)
        conf += 1
    if attack:
        session.submit("payout", "claimant", graph.payout_with_fee(claim, utxos["claimant_fee"], PAYOUT_BUMP),
                       note=f"adds {PAYOUT_BUMP} sats of fee to replace whatever spends the claim output")
    else:
        session.submit("payout", "claimant", graph.payout_tx(claim))
    session.mine_congested(1, PIN_FLOOR)
    return prep, session.finish()


def wait_for(predicate, timeout, interval=0.25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return bool(predicate())


def run_partition_case(session, row, stage=FIXTURE):
    """Three owned nodes joined over loopback P2P: a miner, a blocks-only relay run by the
    attacker, and the watcher's node. Eclipsed, the watcher's only peer is the relay."""
    cfg = config(row["recipe"], row["profile"])
    eclipsed = cfg.watcher_network == "eclipsed"
    base = session.node.directory.parent / f"{session.node.directory.name}-{row['id'].replace('.', '-')}"
    pm, pr, pw = free_port(), free_port(), free_port()
    miner = Regtest(session.node.binary, base / "miner", p2p={"port": pm})
    relay = Regtest(session.node.binary, base / "relay", p2p={"port": pr, "connect": [pm], "blocksonly": True})
    watcher = Regtest(session.node.binary, base / "watcher", p2p={"port": pw, "connect": [pr] if eclipsed else [pr, pm]})
    nodes = (("miner", miner), ("relay", relay), ("watcher", watcher))
    started = []
    try:
        for _, node in nodes:
            node.start()
            started.append(node)
        want = {"miner": 1 if eclipsed else 2, "relay": 2, "watcher": 1 if eclipsed else 2}
        if not wait_for(lambda: all(len(n.rpc("getpeerinfo")) == want[k] for k, n in nodes), 60):
            raise ValidationError("the cluster did not reach its topology")
        miner.initialize_wallet()

        def synced():
            height = miner.rpc("getblockcount")
            return all(n.rpc("getblockcount") == height for _, n in nodes)

        def sync():
            if not wait_for(synced, 60):
                raise ValidationError("the cluster did not sync")

        sync()
        topology = {k: [{"addr": p["addr"], "inbound": p["inbound"], "relaytxes": p.get("relaytxes")}
                        for p in n.check_peers()] for k, n in nodes}
        cs = Session(miner)
        cs.begin(stage.public_keys())
        prep = prepare(row, stage=stage)
        graph = Graph(prep)
        proof = proof_for(row)
        setup_record(cs, prep, graph, prep.statement)
        cs.offchain("network", "environment", topology=topology, relay_blocksonly=True,
                    watcher_peers="relay only" if eclipsed else "relay and miner")
        utxos = cs.fund(graph.funding())
        sync()
        labels = prep.garbling.input_labels(gc.proof_bits(*proof))
        cs.offchain("claim proof", "claimant", proof=list(proof), statement=prep.statement)
        claim = graph.claim_tx(utxos, labels)
        cs.submit("claim", "claimant", claim, via=miner, via_name="miner")
        cs.mine(1, "claim confirmed")
        sync()
        cs.offchain("label handover", "claimant", to=["watch"], labels=[x.hex() for x in labels])
        out_label = gc.evaluate(prep.statement, prep.garbling.tables, labels)
        verdict = gc.decode(out_label, graph.data["accept_label_sha256"], graph.data["reject_label_sha256"])
        cs.offchain("evaluate", "watch", labels=[x.hex() for x in labels], tables_source="setup",
                    tables_commitment=tables_commitment(prep.garbling.tables), output_label=out_label.hex(),
                    verdict=verdict)
        if verdict == "reject":
            disprove = graph.disprove_tx(claim, out_label, "watch")
            cs.submit("disprove", "watch", disprove, via=watcher, via_name="watcher")
            t0 = time.monotonic()
            seen = wait_for(lambda: disprove.txid in miner.rpc("getrawmempool"), PROPAGATION_WAIT)
            cs.offchain("propagation", "environment", txid=disprove.txid, reached_miner=seen,
                        waited_up_to_seconds=PROPAGATION_WAIT, seconds=round(time.monotonic() - t0, 1))
        cs.mine(cfg.window - 1)
        sync()
        cs.submit("payout", "claimant", graph.payout_tx(claim), via=miner, via_name="miner")
        return prep, cs.finish()
    finally:
        for node in started:
            node.close()


def run_case(session, row, stage=FIXTURE):
    if row["recipe"] == "disprove_partitioned":
        return run_partition_case(session, row, stage)
    if row["recipe"] == "proof_replay_across_vaults" and row["variant"] == "attack":
        return run_replay_case(session, row, stage)
    if row["recipe"] == "disprove_anchor_pinned":
        return run_pinning_case(session, row, stage)
    recipe, attack = row["recipe"], row["variant"] == "attack"
    cfg = config(recipe, row["profile"])
    session.begin(stage.public_keys())
    prep = prepare(row, stage=stage)
    graph = Graph(prep, cltv_height=session.height() + WINDOW if cfg.payout_timelock == "cltv" else None)
    proof = proof_for(row)
    setup_record(session, prep, graph, prep.statement)
    extra = {"watch_fee": (p2tr_key(graph.W), stage.watch_funds)} if recipe == "disprove_unbumpable" else None
    utxos = session.fund(graph.funding(extra))
    bits = gc.proof_bits(*proof)
    labels = prep.garbling.input_labels(bits)

    # Before the claim.
    if recipe == "reclaim_preempts_claim" and attack:
        session.offchain("paying the user", "claimant", declared_blocks=PAYMENT_DELAY,
                         note="the honest claimant fronts the user's payment before claiming")
        funded_at = step(session.steps, "fund")["height"]
        # The desk tries at the first height its reclaim could be final, within the delay.
        session.mine(max(1, min(cfg.reclaim, PAYMENT_DELAY) - 1))
        if session.submit("reclaim", "desk", graph.reclaim_tx(utxos["vault"])):
            session.mine(1, "reclaim confirms")
        if session.height() - funded_at < PAYMENT_DELAY:
            session.mine(PAYMENT_DELAY - (session.height() - funded_at))
    if recipe == "payout_absolute_timelock" and attack:
        late = step(session.steps, "setup")["height"] + WINDOW
        session.offchain("claimant waits", "claimant", until_height=late,
                         note="the claim is made after setup height + window")
        if session.height() < late:
            session.mine(late - session.height())

    session.offchain("claim proof", "claimant", proof=list(proof), statement=prep.statement)
    if recipe == "claim_sighash_none" and attack:
        rewritten = graph.claim_tx(utxos, labels, prep.desk_presigns,
                                   outputs=[(graph.k_value, graph.payout_spk)])
        if session.submit("rewritten claim", "claimant", rewritten, note="desk presignature reused, outputs replaced"):
            session.mine(1, "rewritten claim confirms")
            return prep, session.finish()
    claim = graph.claim_tx(utxos, labels, desk_signs=prep.desk_presigns)
    if not session.submit("claim", "claimant", claim):
        session.offchain("vault check", "evaluator", vault_unspent=session.utxo_unspent(utxos["vault"]["txid"],
                                                                                         utxos["vault"]["vout"]))
        return prep, session.finish()
    if recipe == "payout_absolute_timelock" and attack:
        session.submit("payout", "claimant", graph.payout_tx(claim), note="broadcast right behind the claim")
    session.mine(1, "claim confirmed")
    conf = 1

    def advance(to):
        nonlocal conf
        if to > conf:
            session.mine(to - conf)
            conf = to

    # Right after the claim confirms.
    if recipe == "claim_internal_key_spendable" and attack:
        if session.submit("key-path sweep", "claimant", graph.sweep_tx(claim, graph.payout_spk)):
            session.mine(1, "sweep confirms")
            conf += 1
    if recipe == "disprove_outputs_unbound" and attack:
        reject = prep.garbling.reject_label      # the garbler made every label
        if cfg.disprove_mode == "hashlock":
            theft = graph.disprove_tx(claim, reject, "claimant", beneficiary=graph.payout_spk)
        else:
            theft = rewrite(graph.disprove_tx(claim, reject, "claimant"), [(graph.k_value - graph.fee, graph.payout_spk)])
        if session.submit("self-spend disprove", "claimant", theft, note="reject label known to the garbler"):
            session.mine(1, "self-spend confirms")
            conf += 1

    # Label handover / extraction and evaluation.
    holders = ["watch", "third"] if recipe in ("single_watcher_disprove", "disprove_watcher_redirect") else ["watch"]
    withheld = attack and recipe == "labels_offchain_withheld" and not cfg.labels_onchain
    if cfg.labels_onchain:
        got = labels_from_claim(session.raw(claim.txid))
        session.offchain("labels from chain", "watch", labels=[x.hex() for x in got])
    elif withheld:
        got = None
        session.offchain("labels withheld", "claimant", labels=None)
    else:
        got = labels
        session.offchain("label handover", "claimant", to=holders, labels=[x.hex() for x in got])
    corrupt = attack and recipe == "tables_delivered_late"
    tables, source = evaluator_tables(prep, corrupt)
    if recipe == "tables_delivered_late":
        handed = corrupt_tables(prep.garbling.tables) if corrupt else prep.garbling.tables
        session.offchain("tables handover", "claimant", commitment=tables_commitment(handed),
                         registered=graph.data["ciphertext_commitment"], evaluator_uses=source)

    if recipe == "payout_csv_removed" and attack:
        if session.submit("payout", "claimant", graph.payout_tx(claim), note="immediately after the claim confirms"):
            # Off-chain evaluation takes longer than one block; the payout confirms first.
            # (While it is unconfirmed, full-RBF would let a higher-fee disprove replace it.)
            session.mine(1, "payout confirms before the evaluation finishes")
            conf += 1

    evaluator = "third" if recipe == "single_watcher_disprove" else "watch"
    verdict, out_label = "no labels", None
    if got is not None:
        out_label = gc.evaluate(prep.statement, tables, got)
        verdict = gc.decode(out_label, graph.data["accept_label_sha256"], graph.data["reject_label_sha256"])
    if recipe == "single_watcher_disprove":
        session.offchain("watcher offline", "watch")
    if recipe == "window_below_latency":
        session.offchain("evaluation latency", evaluator, declared_blocks=LATENCY,
                         note="modeled: M14 evaluation measured at about 60 min on the author's laptop")
        if attack:
            advance(WINDOW)
            session.submit("payout", "claimant", graph.payout_tx(claim), note=f"at {WINDOW} confirmations")
        advance(LATENCY)
    session.offchain("evaluate", evaluator, labels=None if got is None else [x.hex() for x in got],
                     tables_source=source, tables_commitment=tables_commitment(tables),
                     output_label=None if out_label is None else out_label.hex(), verdict=verdict)

    if recipe == "seed_reuse_across_claims" and attack:
        prior_labels = prep.prior.input_labels(gc.proof_bits(*PRIOR_PROOF))
        session.offchain("prior claim labels", "claimant", statement=PRIOR_STATEMENT,
                         proof=list(PRIOR_PROOF), labels=[x.hex() for x in prior_labels])
        candidates = []
        for now, before in zip(got, prior_labels):
            delta = gc.xor(now, before)
            if any(delta) and delta not in candidates:
                candidates.append(delta)
        target = graph.disprove_hash
        forged = next((gc.xor(out_label, d) for d in candidates
                       if hashlib.sha256(gc.xor(out_label, d)).digest() == target), None)
        session.offchain("derive reject label", "watch", candidates=len(candidates),
                         matched=forged is not None)
        attempt = forged if forged is not None else gc.xor(out_label, candidates[0])
        session.submit("griefing disprove", "watch", graph.disprove_tx(claim, attempt, "watch"))
    elif verdict == "reject" and recipe == "disprove_watcher_redirect" and attack:
        steal = [(graph.k_value - graph.fee, stage.spk("watch"))]
        if cfg.disprove_mode == "watcher":
            redirect = graph.disprove_tx(claim, out_label, "watch", outputs=steal)
        else:
            redirect = rewrite(graph.disprove_tx(claim, out_label, "watch"), steal)
        if session.submit("redirected disprove", "watch", redirect, note="the watcher pays the vault to itself"):
            session.mine(1, "redirected disprove confirms")
            conf += 1
        else:
            session.submit("disprove", "third", graph.disprove_tx(claim, out_label, "third"),
                           note="another label holder broadcasts the presigned refund")
    elif verdict == "reject":
        honest_beneficiary = graph.refund_spk if cfg.disprove_mode == "hashlock" else None
        disprove = graph.disprove_tx(claim, out_label, evaluator, beneficiary=honest_beneficiary)
        if cfg.disprove_fee == "zero_anchor":
            session.submit_package([("disprove", disprove),
                                    ("disprove fee child", graph.anchor_child(disprove, utxos["watch_fee"]))],
                                   evaluator, note="desk offline: the watcher pays the fee through the P2A anchor")
        elif cfg.disprove_fee == "zero_no_anchor":
            session.submit("disprove", evaluator, disprove, note="presigned at zero fee, no anchor; desk offline")
        else:
            session.submit("disprove", evaluator, disprove)
        if recipe == "bond_self_slash" and attack:
            # The garbler holds the reject label too, and replaces the watcher's disprove
            # with one that sends the bond back to itself at a higher fee.
            take_back = [(stage.vault - graph.claim_fee - graph.fee, graph.refund_spk),
                         (stage.bond - graph.fee, graph.bond_tree.script_pubkey)]
            if cfg.disprove_mode == "presigned_single":
                own = graph.disprove_tx(claim, prep.garbling.reject_label, "claimant",
                                        beneficiary=graph.bond_tree.script_pubkey, fee=2 * graph.fee)
            else:
                own = rewrite(disprove, take_back)
            session.submit("self-slash disprove", "claimant", own, note="replaces the watcher's disprove (full RBF)")
            session.mine(1, "a disprove confirms")
            conf += 1
        if recipe == "disprove_censored_by_miner" and attack:
            if cfg.window <= CENSOR:
                session.mine_empty(cfg.window - 1, "miner", note="the disprove waits in the mempool")
                conf += cfg.window - 1
            else:
                session.mine_empty(CENSOR, "miner", note="censorship bound reached")
                conf += CENSOR
            if session.submit_in_block("payout", "miner", graph.payout_tx(claim),
                                       note="the colluding miner mines the payout, leaving the disprove out"):
                conf += 1

    advance(cfg.window)
    if recipe == "desk_key_retained" and attack:
        if session.submit("desk payout", "desk", graph.desk_payout_tx(claim, graph.refund_spk),
                          note="the desk signs the matured payout to itself"):
            session.mine(1, "desk payout confirms")
    if recipe == "payout_sighash_none" and attack:
        thief = stage.spk("relayer")
        if session.submit("redirected payout", "relayer", graph.payout_tx(claim, destination=thief),
                          note="the relayer mines its own rewrite"):
            session.mine(1, "relayer's block")
    if not confirmed_now(session, "payout"):
        session.submit("payout", "claimant", graph.payout_tx(claim))
    return prep, session.finish()


def run_replay_case(session, row, stage=FIXTURE):
    """Two vaults, one honest payment proof, claimed against both."""
    cfg = config(row["recipe"], row["profile"])
    session.begin(stage.public_keys())
    preps = [prepare(row, stage=stage), prepare(row, index=1, stage=stage)]
    graphs = [Graph(p) for p in preps]
    for i, (prep, graph) in enumerate(zip(preps, graphs)):
        session.offchain("setup" if i == 0 else "setup 2", "claimant", statement=prep.statement,
                         registered=graph.data["ciphertext_commitment"],
                         reject_label_sha256=graph.data["reject_label_sha256"],
                         disprove_leaf_hash=graph.disprove_hash.hex(), log=prep.setup_log,
                         desk_presigns=prep.desk_presigns, config=cfg.__dict__, cltv_height=None)
    utxos = [session.fund(graphs[0].funding()), session.fund(graphs[1].funding(), label="fund 2")]
    proof = HONEST_PROOF
    session.offchain("claim proof", "claimant", proof=list(proof), statement=preps[0].statement)
    bits = gc.proof_bits(*proof)
    claims, suffix = [], ("", " 2")
    for i in range(2):
        labels = preps[i].garbling.input_labels(bits)
        claim = graphs[i].claim_tx(utxos[i], labels)
        session.submit("claim" + suffix[i], "claimant", claim, note=None if i == 0 else "same proof, second vault")
        claims.append((claim, labels))
    session.mine(1, "claims confirmed")
    for i in range(2):
        claim, labels = claims[i]
        session.offchain("label handover" + suffix[i], "claimant", to=["watch"], labels=[x.hex() for x in labels])
        out = gc.evaluate(preps[i].statement, preps[i].garbling.tables, labels)
        verdict = gc.decode(out, graphs[i].data["accept_label_sha256"], graphs[i].data["reject_label_sha256"])
        session.offchain("evaluate" + suffix[i], "watch", labels=[x.hex() for x in labels],
                         statement=preps[i].statement, tables_source="setup",
                         tables_commitment=tables_commitment(preps[i].garbling.tables),
                         output_label=out.hex(), verdict=verdict)
        if verdict == "reject":
            session.submit("disprove" + suffix[i], "watch", graphs[i].disprove_tx(claim, out, "watch"))
    session.mine(cfg.window - 1)
    for i in range(2):
        session.submit("payout" + suffix[i], "claimant", graphs[i].payout_tx(claims[i][0]))
    return preps[0], session.finish()


def confirmed_now(session, label):
    return any(s["kind"] == "tx" and s["label"] == label and s["broadcast"] for s in session.steps)


def claimant_scripts(stage=FIXTURE):
    tree = TapTree((push(stage.keys["claimant"]) + ops("CHECKSIG"),))
    return {tree.script_pubkey.hex(), stage.spk("payout").hex()}


def claimant_loss(steps, stage=FIXTURE):
    mine, loss = claimant_scripts(stage), 0
    for s in steps:
        if s["kind"] == "tx" and s.get("confirmed"):
            loss += sum(p["amount"] for p in s["prevouts"] if p["script_pubkey"] in mine)
            loss -= sum(v for v, spk in Transaction.parse(s["raw_transaction"]).outputs if spk.hex() in mine)
    return loss


def score(row, steps, stage=FIXTURE):
    """Outcome from confirmed transactions only; never reads the declared expectation."""
    proof = step(steps, "claim proof")
    honest = proof is not None and sum(proof["proof"]) == STATEMENT
    paid = confirmed(steps, "payout")
    recipe = row["recipe"]
    if recipe == "seed_reuse_across_claims":
        attack = confirmed(steps, "griefing disprove")
    elif recipe == "payout_sighash_none":
        attack = confirmed(steps, "redirected payout")
    elif recipe == "claimant_unbonded":
        attack = (not honest) and confirmed(steps, "claim") and claimant_loss(steps, stage) <= 0
    elif recipe == "bond_self_slash":
        attack = (not honest) and confirmed(steps, "claim") and claimant_loss(steps, stage) < stage.bond // 2
    elif recipe == "claim_sighash_none":
        attack = confirmed(steps, "rewritten claim")
    elif recipe == "claim_internal_key_spendable":
        attack = confirmed(steps, "key-path sweep")
    elif recipe == "disprove_outputs_unbound":
        attack = confirmed(steps, "self-spend disprove")
    elif recipe == "reclaim_preempts_claim":
        attack = honest and confirmed(steps, "reclaim") and not paid
    elif recipe == "proof_replay_across_vaults":
        attack = honest and paid and confirmed(steps, "payout 2")
    elif recipe == "disprove_watcher_redirect":
        attack = confirmed(steps, "redirected disprove")
    elif recipe == "desk_key_retained":
        attack = honest and confirmed(steps, "desk payout") and not paid
    else:
        attack = (not honest) and paid
    return {"attack_success": bool(attack), "honest_claim_paid": bool(honest and paid)}


def execute(binary, directory, rows=None):
    rows = deepcopy(rows or catalog())
    cases = []
    with Regtest(binary, directory) as node:
        node.initialize_wallet()
        provenance = node.provenance
        session = Session(node)
        for row in rows:
            _, steps = run_case(session, row)
            outcome = score(row, steps)
            cases.append({**row, "keys": keys(), "steps": steps, "outcome": outcome,
                          "expectation_met": outcome == row["expected"]})
    return finalize_report(TRACK, provenance, rows, cases)


def audit_instance(cid, row, steps, prep, graph, suffix, problems):
    setup = step(steps, "setup" + suffix)
    if setup is None or setup.get("registered") != graph.data["ciphertext_commitment"] \
            or setup.get("disprove_leaf_hash") != graph.disprove_hash.hex() \
            or setup.get("desk_presigns") != prep.desk_presigns or setup.get("statement") != prep.statement:
        problems.append(f"{cid}: recorded setup{suffix} differs from the rebuilt setup")
    fund = step(steps, "fund" + suffix)
    if fund is None or fund["outputs"]["vault"]["script_pubkey"] != graph.V.script_pubkey.hex():
        problems.append(f"{cid}: funded vault{suffix} script differs from the rebuilt graph")
    claim = step(steps, "claim" + suffix)
    if claim is not None:
        parsed = Transaction.parse(claim["raw_transaction"])
        if parsed.outputs != graph.claim_outputs():
            problems.append(f"{cid}: claim{suffix} outputs differ from the rebuilt graph")
    evaluation = step(steps, "evaluate" + suffix)
    if evaluation is not None and evaluation["labels"] is not None:
        corrupt = row["variant"] == "attack" and row["recipe"] == "tables_delivered_late"
        tables, source = evaluator_tables(prep, corrupt)
        if evaluation.get("tables_source") != source or evaluation.get("tables_commitment") != tables_commitment(tables):
            problems.append(f"{cid}: recorded evaluator tables{suffix} differ from the rebuilt ones")
        got = [bytes.fromhex(x) for x in evaluation["labels"]]
        out = gc.evaluate(prep.statement, tables, got)
        verdict = gc.decode(out, graph.data["accept_label_sha256"], graph.data["reject_label_sha256"])
        if out.hex() != evaluation["output_label"] or verdict != evaluation["verdict"]:
            problems.append(f"{cid}: re-evaluated garbling{suffix} disagrees with the recorded evaluation")
    return claim


def audit(report):
    """Offline audit: envelope, local tx checks, rebuilt setup, re-evaluated garblings, rescoring."""
    rows = catalog()
    problems = check_report_envelope(report, TRACK, rows)
    for case in report.get("cases", []):
        if case.get("id") in {r["id"] for r in rows} and case.get("keys") != keys():
            problems.append(f"{case['id']}: party keys differ from the fixture keys")
    return problems + audit_cases(report.get("cases", []), rows, FIXTURE)


def audit_cases(cases, rows, stage, cltv_slack=0):
    """Per-case checks shared by the regtest and public-network tracks. On a public network a
    block can arrive between reading the tip for an absolute payout height and recording the
    setup step; `cltv_slack` is how many blocks earlier that read may have been."""
    problems = []
    by_id = {r["id"]: r for r in rows}
    for case in cases:
        row = by_id.get(case.get("id"))
        if row is None:
            continue
        cid = row["id"]
        problems += [f"{cid}: {p}" for p in audit_transactions(case, stage.public_keys())]
        steps = case["steps"]
        prep = prepare(row, stage=stage)
        setup = step(steps, "setup") or {}
        cltv = None
        if prep.cfg.payout_timelock == "cltv":
            cltv = setup.get("cltv_height")
            height = setup.get("height", -1)
            if not isinstance(cltv, int) or not height - cltv_slack <= cltv - WINDOW <= height:
                problems.append(f"{cid}: absolute payout height is not setup height + {WINDOW}")
                cltv = height + WINDOW
        graph = Graph(prep, cltv)
        claim = audit_instance(cid, row, steps, prep, graph, "", problems)
        if row["recipe"] == "proof_replay_across_vaults" and row["variant"] == "attack":
            prep2 = prepare(row, index=1, stage=stage)
            audit_instance(cid, row, steps, prep2, Graph(prep2), " 2", problems)
        chain = step(steps, "labels from chain")
        if chain is not None and claim is not None:
            if [x.hex() for x in labels_from_claim(claim["raw_transaction"])] != chain["labels"]:
                problems.append(f"{cid}: labels read from the claim witness differ")
        if score(row, steps, stage) != case.get("outcome"):
            problems.append(f"{cid}: outcome does not follow from the recorded steps")
    return problems
