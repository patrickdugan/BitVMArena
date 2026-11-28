"""The `shz-batcher` track: the Lightninger DLC batcher's BitVM3 claim graph, as built.

Target: patrickdugan/SatsHedgeZero at a852b320, `research/lightninger_dlc_batcher` (the claim
graph of `src/bin/dlc_batcher.rs`, phase B) and `research/lightninger_dlc_batch_gc` (the garbled
Groth16 verifier instances). The graph is rebuilt here from the target's own regtest keys and
recorded garbled instances, and every script is compared byte for byte with the target's
recorded `artifacts/regtest/claim_graph.json` before anything is funded:

    vault V   NUMS + { claim:   <D> CHECKSIGVERIFY <O> CHECKSIG
                       reclaim: <144> CSV DROP <D> CHECKSIG }
       |  claim tx: D presigns at setup, the operator O signs
       v
    claim K   NUMS + { payout:   <6> CSV DROP <D> CHECKSIG               -> operator (D presigned)
                       disprove: SHA256 <H(reject)> EQUALVERIFY <W> CHECKSIG -> pool }
              + OP_RETURN "SHZC" || claim_id

Every row runs against that one design (profile `as_built`); Bitcoin Core decides every
transaction. The garbled circuit is not re-run: the rows use the labels and label hashes the
target recorded for its two instances (seed 101, the mined settlement's statement, accept;
seed 202, the tampered settlement's statement, reject). The one computation on them is the
Free-XOR offset, which gsv derives from the garbling seed and the target publishes.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib

from .bitcoin import NUMS, TapTree, Transaction, number, op_return, ops, public, push, sha
from .canonical import ValidationError
from .core import Regtest
from .track import (Session, audit_transactions, check_report_envelope, confirmed, finalize_report, step,
                    utxo_input)

TRACK = "shz-batcher"
CAMPAIGN_ID = "BVA-PROVERS"
EVIDENCE_LEVEL = "arena_reconstruction_regtest"
UPSTREAM = {"target": "Lightninger DLC batcher BitVM3 claim graph", "repository": "patrickdugan/SatsHedgeZero",
            "commit": "a852b320f0a9940b6ba23607537f4e4192197979",
            "paths": ["research/lightninger_dlc_batcher/src/bin/dlc_batcher.rs",
                      "research/lightninger_dlc_batch_gc/src/main.rs",
                      "research/lightninger_dlc_batcher/artifacts/regtest/claim_graph.json",
                      "research/lightninger_dlc_batcher/artifacts/regtest/garbled/claim_honest.json",
                      "research/lightninger_dlc_batcher/artifacts/regtest/garbled/claim_wrong.json"],
            "garbler": {"repository": "patrickdugan/garbled-snark-verifier",
                        "commit": "f80c364fad9a0d0000426c2f208de03708e6e268",
                        "path": "src/circuit/modes/garble_mode.rs"}}

# The target's regtest-only keys (dlc_batcher.rs: POOL_SK, OPERATOR_SK, WATCH_SK).
SECRETS = {"pool": int.from_bytes(b"\xd0" * 32, "big"), "operator": int.from_bytes(b"\x0b" * 32, "big"),
           "watch": int.from_bytes(b"\xee" * 32, "big")}
RELAYER_SECRET = 0x7E1A0005          # a third party with no role in the graph
RECLAIM_BLOCKS, WINDOW_BLOCKS = 144, 6
VAULT_SATS, FEE = 3_564, 400         # the recorded reimbursement and the graph's per-transaction fee
K_SATS, PAYOUT_SATS = VAULT_SATS - FEE, VAULT_SATS - 2 * FEE
CLAIM_TAG = b"LIGHTNINGER/DLC-BATCH/BITVM3-CLAIM/V1"
EVALUATION_SECONDS = (1218.0816478, 1276.6876553)    # the target's recorded regarble-and-evaluate times

# The target's two recorded garbled instances (artifacts/regtest/garbled/claim_{honest,wrong}.json).
INSTANCES = {
    "honest": {
        "statement_sha256": "b05dccf54f9308ce47317ebf4b767f4570fb0ab186105ef1260c5ba1e9c4cf32",
        "vk_sha256": "2cadec567dc84ef9c649b69f4e705181bcfe430b7ab8d0475942af7f2d2a594b",
        "ciphertext_commitment_blake3": "25971ff20f96244a7cfb41722fe7f06ea5b4087bbb97a2793d20543060c786cb",
        "accept_label_sha256": "ca8f21f33fe5ed10f03e94953626001d0240484dcbe5c31f3b90ff7dc35d7fdc",
        "reject_label_sha256": "25ce3da9dc2d59c34640ee1c825a18ce3526e513c4ee512b329cc7e458915257",
        "evaluated_label_hex": "ccc9f3b7b6a17222fd0c950bdb8e73f8", "evaluated": "accept", "garbling_seed": 101},
    "wrong": {
        "statement_sha256": "313b611c080b6496d8dd40e49e2a199aaeb3e9a18469ffdd3f00b7a680d602ce",
        "vk_sha256": "2cadec567dc84ef9c649b69f4e705181bcfe430b7ab8d0475942af7f2d2a594b",
        "ciphertext_commitment_blake3": "1dd8e8f0be7e0d73b0042e001a2241407aa783ba49d7021b015b0e3a965707d4",
        "accept_label_sha256": "87f6ba08d24b9b27b8798b15aae18071dc696b5abf9ce9274cb668ce5e4540b1",
        "reject_label_sha256": "6ed44de5e60e52719da4b5cd3720469a69fad7322f085c3a048c477c4b5e5a86",
        "evaluated_label_hex": "0dfb48d8e8b413042b3c50bc4da29d02", "evaluated": "reject", "garbling_seed": 202},
}

# What the target recorded in artifacts/regtest/claim_graph.json; the rebuilt graph must equal it.
RECORDED = {
    "claim_graph_sha256": "c5bf5e566e50453bec6475e13afc258b043fefb7bd05ea0eda3fd1d110675d27",
    "keys": {"pool": "6144373d5c39a77d1a5d1a2cb28c3ab2685d4b053440451800ae51647c399874",
             "operator": "552c630b64b54bf50210c9e253d38bd4949c72e22873500f6285c2bede312a84",
             "watch": "a706ad8f73115f90500266f273f7571df9429a4cfb4bbfbcd825227202dabad1"},
    "vault_spk": "51208dcfbccd4e32bc4224b2d187df93e4d82f0050028b061b76cb89a031f363be29",
    "operator_spk": "5120b6f2ee25e85dac4bdd134ebea5f96766cae0f8625e56a97c491966d722dc0e92",
    "pool_spk": "512019faf521e21cc42c7b3798d9d864522d1a2836936c1a3ac847d21977927cf0d9",
    "honest": {"k_spk": "5120e6e525b2750840b970415db43be665616bae7b57a79aa02d081116be0bc9e9f0",
               "claim_id": "f212ae607c7925b5b83cd286979b540ca39457074b122ceb9313899a111fae87"},
    "wrong": {"k_spk": "5120ba5932e4a07e8bb3d61eea3e117a09fc140d793f123172383f5bc1a2e64a661b",
              "claim_id": "e69cfa495cbcc5b11106ccd1bde864a35e221f3819a16416c17de5f64a785082"},
}

RECIPES = {
    # recipe: (family, variant, instance, attacker, task, documented_by_target)
    "honest_claim": ("honest_path", "benign", "honest", None,
                     "Reimburse the operator for the mined settlement after the 6-block window", None),
    "wrong_statement_disproved": (
        "dispute", "attack", "wrong", "operator",
        "Return the vault to the pool when the operator claims a statement the proof does not support", None),
    "disprove_wrong_label": (
        "dispute", "attack", "honest", "watcher",
        "Refuse a disprove of an honest claim that does not open the reject label", None),
    "seed_reject_label_grief": (
        "garbling", "attack", "honest", "watcher",
        "Keep an honest claim's reject label out of reach of the party that signs the disprove", None),
    "seed_reject_label_theft": (
        "garbling", "attack", "honest", "watcher",
        "Keep an honest operator's reimbursement from the watcher", None),
    "watcher_redirects_disprove": (
        "transaction_graph", "attack", "wrong", "watcher",
        "Return a disproven claim's sats to the pool, not to whoever disproves", None),
    "committee_repays_itself": (
        "transaction_graph", "attack", "honest", "pool_committee",
        "Pay an undisputed claim to the operator that fronted the settlement",
        "docs/SHZ_DLC_BATCHER.md §6 T3 (the committee's presigned graph stands in for a covenant)"),
    "payout_rewritten_by_relayer": (
        "transaction_graph", "attack", "honest", "relayer",
        "Keep the presigned payout bound to the operator's script", None),
    "claim_rewritten_by_operator": (
        "transaction_graph", "attack", "wrong", "operator",
        "Keep the presigned claim bound to the claim output", None),
    "tables_withheld_past_window": (
        "data_availability", "attack", "wrong", "operator",
        "Stop a false claim when the watcher cannot finish evaluating within the window",
        "docs/SHZ_DLC_BATCHER.md §6 T2 and 'one honest watcher online within 6 blocks'"),
    "statement_replayed_on_second_vault": (
        "statement_binding", "attack", "honest", "operator",
        "Reimburse one settlement once", None),
}

EXPECTED = {
    # recipe: (legitimate_completion, attacker_success, diverted_sats, defense_layer)
    "honest_claim": (True, False, 0, None),
    "wrong_statement_disproved": (True, False, 0, "bitcoin_script"),
    "disprove_wrong_label": (True, False, 0, "bitcoin_script"),
    "seed_reject_label_grief": (False, True, 0, "none"),
    "seed_reject_label_theft": (False, True, PAYOUT_SATS, "none"),
    "watcher_redirects_disprove": (False, True, PAYOUT_SATS, "none"),
    "committee_repays_itself": (False, True, PAYOUT_SATS, "none"),
    "payout_rewritten_by_relayer": (True, False, 0, "bitcoin_script"),
    "claim_rewritten_by_operator": (True, False, 0, "bitcoin_script"),
    "tables_withheld_past_window": (False, True, PAYOUT_SATS, "none"),
    "statement_replayed_on_second_vault": (False, True, PAYOUT_SATS, "none"),
}


def catalog():
    rows = []
    for recipe, (family, variant, instance, attacker, task, documented) in RECIPES.items():
        legitimate, success, diverted, layer = EXPECTED[recipe]
        rows.append({"schema_version": 1, "id": f"{TRACK}.{recipe}", "track": TRACK, "recipe": recipe,
                     "family": family, "profile": "as_built", "variant": variant, "instance": instance,
                     "attacker": attacker, "main_task": task, "documented_by_target": documented,
                     # The replay row scores on a second vault the pool funds with the same script:
                     # under the campaign's fixed-target rule that is a calibration control.
                     "fixed_target": recipe != "statement_replayed_on_second_vault",
                     "expected": {"legitimate_completion": legitimate, "attacker_success": success,
                                  "diverted_sats": diverted, "defense_layer": layer},
                     "evidence_level": EVIDENCE_LEVEL, "upstream_exploit_claim": False})
    return rows


# --- gsv's seed schedule ------------------------------------------------------------------

_M32, _M64 = 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF


def _seed_from_u64(state):
    """rand_core 0.6 `SeedableRng::seed_from_u64`: a PCG32 stream filling the 32-byte seed."""
    out = b""
    for _ in range(8):
        state = (state * 6364136223846793005 + 11634580027462260723) & _M64
        shifted, rot = (((state >> 18) ^ state) >> 27) & _M32, state >> 59
        out += (((shifted >> rot) | (shifted << ((32 - rot) & 31))) & _M32).to_bytes(4, "little")
    return out


def _chacha20_block(key, counter):
    def rotl(value, bits):
        return ((value << bits) | (value >> (32 - bits))) & _M32

    def quarter(s, a, b, c, d):
        s[a] = (s[a] + s[b]) & _M32; s[d] = rotl(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & _M32; s[b] = rotl(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & _M32; s[d] = rotl(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & _M32; s[b] = rotl(s[b] ^ s[c], 7)

    init = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    init += [int.from_bytes(key[i:i + 4], "little") for i in range(0, 32, 4)]
    init += [counter & _M32, (counter >> 32) & _M32, 0, 0]
    state = list(init)
    for _ in range(10):
        quarter(state, 0, 4, 8, 12); quarter(state, 1, 5, 9, 13)
        quarter(state, 2, 6, 10, 14); quarter(state, 3, 7, 11, 15)
        quarter(state, 0, 5, 10, 15); quarter(state, 1, 6, 11, 12)
        quarter(state, 2, 7, 8, 13); quarter(state, 3, 4, 9, 14)
    return [(x + y) & _M32 for x, y in zip(state, init)]


def gsv_seed_schedule(seed):
    """The first two 128-bit draws of gsv's `GarbleMode::new(capacity, seed, ..)`.

    `ChaChaRng::seed_from_u64(seed)`, then `H::from_rng` (the AES gate hasher's salt) and
    `Delta::generate` (the Free-XOR offset): every wire's two labels differ by that offset.
    """
    if type(seed) is not int or not 0 <= seed <= _M64:
        raise ValidationError("the gsv garbling seed is a u64")
    words = _chacha20_block(_seed_from_u64(seed), 0)
    draws = [sum(words[4 * i + j] << (32 * j) for j in range(4)) for i in range(2)]
    return {"gate_hasher_salt": draws[0].to_bytes(16, "big").hex(), "delta": draws[1].to_bytes(16, "big").hex()}


def opposite_label(instance):
    """The output label the evaluator did not get: evaluated label XOR the seed's delta."""
    delta = bytes.fromhex(gsv_seed_schedule(instance["garbling_seed"])["delta"])
    return bytes(a ^ b for a, b in zip(bytes.fromhex(instance["evaluated_label_hex"]), delta))


# --- the graph ------------------------------------------------------------------------------

def keys():
    return {name: public(secret).hex() for name, secret in SECRETS.items()} | \
        {"relayer": public(RELAYER_SECRET).hex()}


def key_output(key):
    """The target's `key_output`: NUMS internal key and one `<k> CHECKSIG` leaf."""
    return TapTree((push(key) + ops("CHECKSIG"),))


def spk_of(name):
    secret = RELAYER_SECRET if name == "relayer" else SECRETS[name]
    return key_output(public(secret)).script_pubkey


def own_wallet_spk(name):
    """A script only `name` controls and no graph names: a key-path output of its key."""
    return TapTree((), public(SECRETS[name])).script_pubkey


def vault_tree():
    d, o = public(SECRETS["pool"]), public(SECRETS["operator"])
    return TapTree((push(d) + ops("CHECKSIGVERIFY") + push(o) + ops("CHECKSIG"),
                    number(RECLAIM_BLOCKS) + ops("CSV", "DROP") + push(d) + ops("CHECKSIG")))


def claim_tree(instance):
    d, w = public(SECRETS["pool"]), public(SECRETS["watch"])
    return TapTree((number(WINDOW_BLOCKS) + ops("CSV", "DROP") + push(d) + ops("CHECKSIG"),
                    ops("SHA256") + push(bytes.fromhex(instance["reject_label_sha256"])) + ops("EQUALVERIFY")
                    + push(w) + ops("CHECKSIG")))


def claim_id(instance, payout_spk):
    data = CLAIM_TAG + bytes.fromhex(instance["statement_sha256"])
    for field in ("vk_sha256", "ciphertext_commitment_blake3", "accept_label_sha256", "reject_label_sha256"):
        data += bytes.fromhex(instance[field])
    return sha(data + payout_spk)


def check_against_target():
    """The rebuilt keys, scripts and claim ids equal what the target recorded; returns the record."""
    built = {"keys": {name: public(secret).hex() for name, secret in SECRETS.items()},
             "vault_spk": vault_tree().script_pubkey.hex(), "operator_spk": spk_of("operator").hex(),
             "pool_spk": spk_of("pool").hex()}
    for name, instance in INSTANCES.items():
        built[name] = {"k_spk": claim_tree(instance).script_pubkey.hex(),
                       "claim_id": claim_id(instance, spk_of("operator")).hex()}
    expected = {key: value for key, value in RECORDED.items() if key != "claim_graph_sha256"}
    if built != expected:
        raise ValidationError("the rebuilt claim graph differs from the target's recorded graph")
    return built


class Graph:
    """One vault's presigned graph, built as the target's `build_graph` builds it."""

    def __init__(self, instance, vault):
        self.instance, self.vault = instance, vault
        self.v, self.k = vault_tree(), claim_tree(instance)
        self.claim = Transaction([utxo_input(vault, 0xffffffff)],
                                 [(K_SATS, self.k.script_pubkey),
                                  (0, op_return(b"SHZC" + claim_id(instance, spk_of("operator"))))])
        leaf = self.v.leaf(0)
        operator = self.claim.signature(0, leaf, SECRETS["operator"])
        pool = self.claim.signature(0, leaf, SECRETS["pool"])
        self.claim.inputs[0].witness = [operator, pool, leaf.script, leaf.control]
        self.k_utxo = {"txid": self.claim.txid, "vout": 0, "amount": K_SATS,
                       "script_pubkey": self.k.script_pubkey.hex()}
        self.payout = self.payout_to(spk_of("operator"))

    def payout_to(self, script, fee=FEE):
        """A payout through the D-only leaf; the committee's key signs whatever output it is given."""
        tx = Transaction([utxo_input(self.k_utxo, WINDOW_BLOCKS)], [(K_SATS - fee, script)])
        leaf = self.k.leaf(0)
        tx.inputs[0].witness = [tx.signature(0, leaf, SECRETS["pool"]), leaf.script, leaf.control]
        return tx

    def disprove(self, label, script, fee=FEE):
        """The watcher signs when it broadcasts, so it names the output."""
        tx = Transaction([utxo_input(self.k_utxo)], [(K_SATS - fee, script)])
        leaf = self.k.leaf(1)
        tx.inputs[0].witness = [tx.signature(0, leaf, SECRETS["watch"]), label, leaf.script, leaf.control]
        return tx


def rewrite(tx, outputs):
    """A copy of a signed transaction with other outputs and the same witnesses."""
    copy = Transaction.parse(tx.serialize())
    for new, old in zip(copy.inputs, tx.inputs):
        new.amount, new.script_pubkey = old.amount, old.script_pubkey
    copy.outputs = list(outputs)
    return copy


def run_case(session, row):
    recipe, instance = row["recipe"], INSTANCES[row["instance"]]
    session.begin(keys())
    session.offchain("target graph check", "evaluator", rebuilt=check_against_target(),
                     recorded_claim_graph_sha256=RECORDED["claim_graph_sha256"], upstream=UPSTREAM)
    vault = session.fund({"vault": (vault_tree(), VAULT_SATS)})["vault"]
    graph = Graph(instance, vault)
    evaluated = bytes.fromhex(instance["evaluated_label_hex"])
    session.offchain("setup", "pool_committee", instance=row["instance"], statement=instance["statement_sha256"],
                     claim_id=claim_id(instance, spk_of("operator")).hex(), k_script_pubkey=graph.k.script_pubkey.hex(),
                     presigned=["claim (D half)", "payout to the operator"])
    if recipe == "claim_rewritten_by_operator":
        # The operator swaps the claim output for its own script; D's presignature covers the outputs.
        direct = rewrite(graph.claim, [(K_SATS, own_wallet_spk("operator"))])
        leaf = graph.v.leaf(0)
        direct.inputs[0].witness[0] = direct.signature(0, leaf, SECRETS["operator"])
        session.submit("claim rewritten", "operator", direct, note="vault paid straight to the operator")
    session.submit("claim", "operator", graph.claim)
    session.mine(1)
    session.offchain("evaluation", "watcher", evaluated_label=evaluated.hex(), verdict=instance["evaluated"],
                     evaluated_label_sha256=sha(evaluated).hex(), source="the target's recorded instance",
                     recorded_seconds=list(EVALUATION_SECONDS))

    if recipe == "honest_claim":
        session.submit("payout early", "operator", graph.payout, note="one block after the claim")
        session.mine(WINDOW_BLOCKS - 1)
        session.submit("payout", "operator", graph.payout)
    elif recipe == "wrong_statement_disproved":
        session.submit("disprove", "watcher", graph.disprove(evaluated, spk_of("pool")))
        session.mine(WINDOW_BLOCKS)
        session.submit("payout", "operator", graph.payout)
    elif recipe == "disprove_wrong_label":
        flipped = bytes([evaluated[0] ^ 1]) + evaluated[1:]
        session.submit("disprove accept label", "watcher", graph.disprove(evaluated, spk_of("pool")))
        session.submit("disprove flipped label", "watcher", graph.disprove(flipped, spk_of("pool")))
        session.mine(WINDOW_BLOCKS - 1)
        session.submit("payout", "operator", graph.payout)
    elif recipe in ("seed_reject_label_grief", "seed_reject_label_theft"):
        schedule, reject = gsv_seed_schedule(instance["garbling_seed"]), opposite_label(instance)
        session.offchain("derive reject label", "watcher", garbling_seed=instance["garbling_seed"],
                         seed_source="artifacts/regtest/garbled/claim_honest.json `garbling_seed`; the "
                                     "evaluator derives its gate hasher from the same seed (dlc_batch_gc main.rs)",
                         **schedule, evaluated_label=evaluated.hex(), derived_label=reject.hex(),
                         derived_label_sha256=sha(reject).hex(),
                         matches_disprove_leaf=sha(reject).hex() == instance["reject_label_sha256"])
        to = spk_of("pool") if recipe.endswith("grief") else own_wallet_spk("watch")
        session.submit("disprove", "watcher", graph.disprove(reject, to),
                       note="an honest claim, disproven with a label computed from the seed")
        session.mine(WINDOW_BLOCKS)
        session.submit("payout", "operator", graph.payout)
    elif recipe == "watcher_redirects_disprove":
        session.submit("disprove", "watcher", graph.disprove(evaluated, own_wallet_spk("watch")),
                       note="the watcher names its own script as the output")
        session.mine(WINDOW_BLOCKS)
        session.submit("payout", "operator", graph.payout)
    elif recipe == "committee_repays_itself":
        session.mine(WINDOW_BLOCKS - 1)
        session.submit("payout to committee", "pool_committee",
                       graph.payout_to(own_wallet_spk("pool")),
                       note="the committee kept D and signs a second payout")
        session.mine(1)
        session.submit("payout", "operator", graph.payout)
    elif recipe == "payout_rewritten_by_relayer":
        session.mine(WINDOW_BLOCKS - 1)
        session.submit("payout rewritten", "relayer", rewrite(graph.payout, [(PAYOUT_SATS, spk_of("relayer"))]))
        session.submit("payout", "operator", graph.payout)
    elif recipe == "claim_rewritten_by_operator":
        session.submit("disprove", "watcher", graph.disprove(evaluated, spk_of("pool")))
        session.mine(WINDOW_BLOCKS)
        session.submit("payout", "operator", graph.payout)
    elif recipe == "tables_withheld_past_window":
        session.offchain("tables withheld", "operator", declared=True,
                         note="the operator streams the tables after the window; nothing on chain waits for them",
                         recorded_evaluation_seconds=list(EVALUATION_SECONDS), window_blocks=WINDOW_BLOCKS)
        session.mine(WINDOW_BLOCKS - 1)
        session.submit("payout", "operator", graph.payout)
        session.mine(1)
        session.submit("disprove", "watcher", graph.disprove(evaluated, spk_of("pool")),
                       note="the reject label, one block after the payout")
    elif recipe == "statement_replayed_on_second_vault":
        session.mine(WINDOW_BLOCKS - 1)
        session.submit("payout", "operator", graph.payout)
        session.mine(1)
        second = session.fund({"vault": (vault_tree(), VAULT_SATS)}, label="fund second vault")["vault"]
        replay = Graph(instance, second)
        session.offchain("setup second vault", "pool_committee", statement=instance["statement_sha256"],
                         claim_id=claim_id(instance, spk_of("operator")).hex(),
                         note="the same statement, instance and claim id; the statement's assertion fields are zero")
        session.submit("claim second vault", "operator", replay.claim)
        session.mine(WINDOW_BLOCKS)
        session.submit("payout second vault", "operator", replay.payout)
    else:
        raise ValidationError("unknown recipe")
    return session.finish()


def paid(steps, script):
    """Confirmed sats to `script` from transactions that spend a graph output."""
    total = 0
    for s in steps:
        if s["kind"] == "tx" and s.get("confirmed"):
            total += sum(value for value, spk in Transaction.parse(s["raw_transaction"]).outputs if spk == script)
    return total


def score(row, steps):
    recipe = row["recipe"]
    operator, pool = paid(steps, spk_of("operator")), paid(steps, spk_of("pool"))
    attacker_scripts = {"watcher": own_wallet_spk("watch"), "pool_committee": own_wallet_spk("pool"),
                        "relayer": spk_of("relayer"), "operator": own_wallet_spk("operator")}
    diverted = paid(steps, attacker_scripts[row["attacker"]]) if row["attacker"] else 0
    honest_instance = row["instance"] == "honest"
    refused = [s["label"] for s in steps if s["kind"] == "tx" and not s["allowed"]]
    if recipe == "statement_replayed_on_second_vault":
        # One settlement entitles the operator to one reimbursement.
        legitimate, success, diverted = operator == PAYOUT_SATS, operator > PAYOUT_SATS, operator - PAYOUT_SATS
    elif recipe == "tables_withheld_past_window":
        legitimate, success, diverted = pool == PAYOUT_SATS, operator > 0, operator
    elif honest_instance:
        legitimate = operator == PAYOUT_SATS
        success = not legitimate if row["variant"] == "attack" else False
    else:
        legitimate = pool == PAYOUT_SATS and operator == 0
        success = not legitimate
    layer = None if row["variant"] == "benign" else "none" if success else "bitcoin_script"
    return {"legitimate_completion": legitimate, "attacker_success": success, "diverted_sats": diverted,
            "defense_layer": layer, "operator_sats": operator, "pool_sats": pool, "refused": refused}


def outcome_of(row, steps):
    full = score(row, steps)
    return {key: full[key] for key in ("legitimate_completion", "attacker_success", "diverted_sats",
                                       "defense_layer")}, full


def execute(binary, directory, rows=None):
    rows = deepcopy(rows or catalog())
    cases = []
    with Regtest(binary, directory) as node:
        node.initialize_wallet()
        provenance = {**node.provenance, "upstream": UPSTREAM}
        session = Session(node)
        for row in rows:
            steps = run_case(session, row)
            outcome, detail = outcome_of(row, steps)
            cases.append({**row, "keys": keys(), "steps": steps, "outcome": outcome, "detail": detail,
                          "expectation_met": outcome == row["expected"]})
    report = finalize_report(TRACK, provenance, rows, cases)
    return report


def audit(report):
    rows = catalog()
    problems = check_report_envelope(report, TRACK, rows)
    try:
        rebuilt = check_against_target()
    except ValidationError as exc:
        return problems + [str(exc)]
    by_id = {r["id"]: r for r in rows}
    for case in report.get("cases", []):
        row = by_id.get(case.get("id"))
        if row is None:
            continue
        cid, steps = row["id"], case["steps"]
        problems += [f"{cid}: {p}" for p in audit_transactions(case)]
        if case.get("keys") != keys():
            problems.append(f"{cid}: party keys differ from the target's regtest keys")
        check = step(steps, "target graph check")
        if check is None or check.get("rebuilt") != rebuilt:
            problems.append(f"{cid}: recorded graph check differs from the rebuilt graph")
        fund = step(steps, "fund")
        if fund is None or fund["outputs"]["vault"]["script_pubkey"] != RECORDED["vault_spk"]:
            problems.append(f"{cid}: the funded vault is not the target's vault script")
        instance = INSTANCES[row["instance"]]
        claim = step(steps, "claim")
        if claim is None:
            problems.append(f"{cid}: no claim")
        else:
            outputs = Transaction.parse(claim["raw_transaction"]).outputs
            wanted = [(K_SATS, bytes.fromhex(RECORDED[row["instance"]]["k_spk"])),
                      (0, op_return(b"SHZC" + bytes.fromhex(RECORDED[row["instance"]]["claim_id"])))]
            if outputs != wanted:
                problems.append(f"{cid}: the claim's outputs are not the target's claim output and claim id")
        derive = step(steps, "derive reject label")
        if derive is not None:
            schedule = gsv_seed_schedule(derive["garbling_seed"])
            label = opposite_label(instance)
            if (derive["delta"], derive["gate_hasher_salt"]) != (schedule["delta"], schedule["gate_hasher_salt"]) \
                    or derive["derived_label"] != label.hex() \
                    or hashlib.sha256(label).hexdigest() != instance["reject_label_sha256"] \
                    or derive["matches_disprove_leaf"] is not True:
                problems.append(f"{cid}: the derived label does not follow from the seed")
            disprove = step(steps, "disprove")
            if disprove is None or Transaction.parse(disprove["raw_transaction"]).inputs[0].witness[1] != label:
                problems.append(f"{cid}: the disprove does not carry the derived label")
        outcome, detail = outcome_of(row, steps)
        if outcome != case.get("outcome") or detail != case.get("detail"):
            problems.append(f"{cid}: outcome does not follow from the recorded steps")
    return problems
