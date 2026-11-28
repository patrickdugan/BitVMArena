"""UTXO-Ref V2 referee and BitVM assertion graph, run from the target's own code on regtest.

Track `utxoref-v2`. The target is the JavaScript in `bitvm3/utxo_referee` of
github.com/patrickdugan/UTXO-Ref at the pinned commit. A Node driver
(`tools/utxoref_v2_driver.cjs`) loads the target's modules from a local checkout and builds
and signs every template, graph, settlement, recovery and disprove with them; this module
funds the target's assertion output on an owned Bitcoin Core regtest node, submits the
target-built transactions and scores from what Core confirmed.

Evidence level `target_code_regtest`: the target's code built and signed every transaction,
Arena's Core judged them. Three kinds of transaction are not the target's API output and are
marked as such in each step's `source`: byte-level rewrites by a relayer (no keys), spends
of a committed leaf that the target's builders refuse to produce (assembled by the driver
from the target's transaction serializer, script-path sighash and BIP340 signer), and a
recovery re-signed by the operator through the target's own three-step ceremony.

The audit runs offline, without Core or Node. It rebuilds every leaf script from the
recorded public data, checks each control block against the funded scriptPubKey and the
network NUMS key, re-executes each spent leaf (hashlocks, BIP340 signatures, BIP68) and
compares the result with Core's recorded verdict, and rescores every case from the raw
transactions. It does not recheck the Ed25519 signature on the state checkpoint (the
standard library has no Ed25519) and it cannot rerun the target's JavaScript verifiers: for
the verifier-level rows it checks that the recorded verdicts are about the recorded objects
and that those objects have the stated properties.
"""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

from .bitcoin import (Transaction, check_signature, leaf_hash, lift, number, p2tr_key, public, sha,
                      verify_commitment)
from .canonical import ValidationError, digest
from .core import Regtest
from .track import Session, audit_transactions, check_report_envelope, finalize_report, step

TRACK = "utxoref-v2"
EVIDENCE_LEVEL = "target_code_regtest"
TARGET_COMMIT = "f848cbfb61fb8cec5988227887594054669ec292"
TARGET = {"repository": "github.com/patrickdugan/UTXO-Ref", "commit": TARGET_COMMIT,
          "directory": "bitvm3/utxo_referee",
          "modules": ["utxoref_v2.js", "bitvm_assertion_graph_v2.js", "bitvm_trace_v2.js"]}
DRIVER = Path(__file__).resolve().parents[1] / "tools" / "utxoref_v2_driver.cjs"
DEFAULT_NODE = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "nodejs" / "node.exe"
DEFAULT_CHECKOUT = Path(r"C:\Users\patri\wt\sr-utxoref")

NETWORK = "regtest"
DOMAIN = "bitvm-arena/utxoref-v2/"
NUMS_DOMAIN = "UTXORef BitVM assertion NUMS internal key v2"
# The target's minimum challenge window, and the shortest recovery window above it that
# leaves room to act between the two (the target's defaults are 144 and 2016).
CHALLENGE_CSV, RECOVERY_CSV = 6, 12
MAX_STATE_AGE = 6
STALE_BLOCKS = 20
FEE, RECOVERY_FEE, RESIGNED_RECOVERY_FEE, DISPROVE_FEE = 1_000, 500, 2_000, 400
# Signed PNL rows: A and C are long from 2100 to 2200 against B for these quantities.
QUANTITIES = {"vault": {"A": 300, "C": 200}, "epoch_n": {"A": 300, "C": 200}, "epoch_n1": {"A": 350, "C": 250}}
EPOCHS = {"vault": 91, "epoch_n": 91, "epoch_n1": 92}
PAYOUT_TOTAL = 100 * (QUANTITIES["vault"]["A"] + QUANTITIES["vault"]["C"])
VAULT = PAYOUT_TOTAL + FEE
IN_STATE, IN_PAYOUT, OUT = "state_checkpoint_valid", "payout_vector_exact", "settlement_authorized"
HONEST, GATE_FRAUD = (1, 1, 1), (1, 1, 0)

# Test-only scalars for the scripts that receive money and for the forger's commitment keys.
OWNER_SECRETS = {"payee_a": 0x55520A01, "payee_c": 0x55520C01, "operator_wallet": 0x55520D01,
                 "operator_other": 0x55520D02, "challenger_wallet": 0x55520E01, "relayer": 0x55520F01,
                 "colluders": 0x55520F02, "forger": 0x55520F03, "forged_operator": 0x55520F04,
                 "forged_challenger": 0x55520F05}

# Verdict vocabulary: Core's reject reasons by class, the target's refusal reasons verbatim.
CONFIRMED, OK, BUILT = "confirmed", "ok", "built"
BIP68, MISSING = "non-BIP68-final", "missing-inputs"
BAD_SIGNATURE, HASHLOCK, COMMITMENT = "invalid_signature", "hashlock_mismatch", "taproot_commitment_mismatch"
REJECT_CLASSES = (("non-BIP68-final", BIP68), ("missing-inputs", MISSING),
                  ("Invalid Schnorr signature", BAD_SIGNATURE), ("OP_EQUALVERIFY", HASHLOCK),
                  ("Witness program hash mismatch", COMMITMENT))
NO_FRAUD = "the public trace contains no constructible fraud proof"
STALE_SETTLEMENT = "state verification failed: state checkpoint is stale"
STALE_GRAPH = "settlement verification failed: " + STALE_SETTLEMENT
BINDING_MISMATCH = "public trace binding mismatch"
KEYS_MISMATCH = "settlement signer keys do not match the assertion tree"


def _expected(completion, success, diverted, defense, verdicts):
    return {"legitimate_completion": completion, "attacker_success": success, "diverted_sats": diverted,
            "defense_layer": defense, "verdicts": verdicts}


# recipe -> variant, family, layer, attacker, the role whose script counts as diverted, the
# public trace bits, the steps that are the attack, and the outcome predicted from the source.
RECIPES = {
    "honest_settlement": {
        "variant": "benign", "family": "settlement", "layer": "on_chain", "attacker": None, "attacker_script": None,
        "trace": HONEST, "attack_steps": [],
        "task": "Pay the signed payout vector once the challenge window has passed",
        "side": None,
        "expected": _expected(True, False, 0, "n/a", {
            "graph vault": OK, "settlement before window": BIP68, "settlement one block early": BIP68,
            "settlement": CONFIRMED})},
    "disprove_valid_trace": {
        "variant": "attack", "family": "disprove", "layer": "on_chain", "attacker": "challenger",
        "attacker_script": "challenger_wallet", "trace": HONEST,
        "attack_steps": ["forged disprove on wrong-bit output leaf", "forged disprove on gate leaf"],
        "task": "Keep an honest trace unchallengeable",
        "side": "Spend a disprove leaf of an honest trace with the revealed preimages",
        "expected": _expected(True, False, 0, "bitcoin_script", {
            "graph vault": OK, "target disprove builder": NO_FRAUD,
            "forged disprove on wrong-bit output leaf": HASHLOCK, "forged disprove on gate leaf": HASHLOCK,
            "settlement": CONFIRMED})},
    "disprove_fraud_to_challenger": {
        "variant": "attack", "family": "disprove", "layer": "on_chain", "attacker": "challenger",
        "attacker_script": "challenger_wallet", "trace": GATE_FRAUD, "attack_steps": ["disprove"],
        "task": "Keep the payees' funds for the payees when the operator's trace is fraudulent",
        "side": "Disprove the operator's fraudulent trace and pay the whole vault to the challenger's script",
        "expected": _expected(False, True, VAULT - DISPROVE_FEE, "none", {
            "graph vault": OK, "target disprove builder": BUILT, "disprove": CONFIRMED,
            "settlement after disprove": MISSING})},
    "disprove_third_party_redirect": {
        "variant": "attack", "family": "disprove", "layer": "on_chain", "attacker": "relayer",
        "attacker_script": "relayer", "trace": GATE_FRAUD, "attack_steps": ["redirected disprove"],
        "task": "Bind a broadcast-ready disprove to the script its signer chose",
        "side": "Rewrite the output of a signed disprove to the relayer's script",
        "expected": _expected(False, False, 0, "bitcoin_script", {
            "graph vault": OK, "target disprove builder": BUILT, "redirected disprove": BAD_SIGNATURE,
            "disprove": CONFIRMED})},
    "recovery_before_window": {
        "variant": "attack", "family": "recovery", "layer": "on_chain", "attacker": "operator",
        "attacker_script": "operator_wallet", "trace": HONEST,
        "attack_steps": ["recovery before window", "recovery at settlement maturity"],
        "task": "Hold the operator's recovery behind the recovery window",
        "side": "Sweep the vault with the pre-signed recovery before recoveryCsv",
        "expected": _expected(True, False, 0, "bitcoin_script", {
            "graph vault": OK, "recovery before window": BIP68, "recovery at settlement maturity": BIP68,
            "settlement": CONFIRMED})},
    "recovery_after_stalled_settlement": {
        "variant": "attack", "family": "recovery", "layer": "on_chain", "attacker": "operator",
        "attacker_script": "operator_wallet", "trace": HONEST, "attack_steps": ["recovery"],
        "task": "Pay the signed payout vector even when nobody broadcasts the settlement in time",
        "side": "Wait out recoveryCsv with the settlement unbroadcast and sweep the vault with the recovery",
        "expected": _expected(False, True, VAULT - RECOVERY_FEE, "none", {
            "graph vault": OK, "recovery": CONFIRMED, "settlement after recovery": MISSING})},
    "recovery_resigned_to_other_script": {
        "variant": "attack", "family": "recovery", "layer": "on_chain", "attacker": "operator",
        "attacker_script": "operator_other", "trace": HONEST, "attack_steps": ["resigned recovery"],
        "task": "Bind the recovery destination and fee to the graph the challenger co-signed",
        "side": "Re-sign the recovery alone to another script at a higher fee and sweep after recoveryCsv",
        "expected": _expected(False, True, VAULT - RESIGNED_RECOVERY_FEE, "none", {
            "graph vault": OK, "resign recovery": OK, "resigned recovery": CONFIRMED,
            "recovery from the co-signed graph": MISSING, "settlement after recovery": MISSING})},
    "settlement_keys_from_own_commitment": {
        "variant": "attack", "family": "verifier_binding", "layer": "verifier", "attacker": "forger",
        "attacker_script": None, "trace": HONEST,
        "attack_steps": ["settlement verifier on forged settlement", "settlement verifier on key-swapped settlement"],
        # verifyUtxoRefSettlementV2 is exported, but the target calls it only from the graph functions
        # (bitvm_assertion_graph_v2.js:553 and :777), which compare the keys with the template.
        "contained_by": ["graph verifier with forged settlement", "graph verifier with key-swapped settlement"],
        "task": "Accept a settlement only when it is the one enforceable on the funded assertion output",
        "side": "Pass verifyUtxoRefSettlementV2 with a settlement whose commitment names the forger's keys, fee, "
                "windows and funding",
        "expected": _expected(None, False, 0, "target_verifier", {
            "graph vault": OK, "settlement verifier on honest settlement": OK,
            "settlement verifier on forged settlement": OK, "graph verifier with forged settlement": BINDING_MISMATCH,
            "settlement verifier on key-swapped settlement": OK,
            "graph verifier with key-swapped settlement": KEYS_MISMATCH})},
    "stale_state_without_height": {
        "variant": "attack", "family": "verifier_binding", "layer": "verifier", "attacker": "operator",
        "attacker_script": None, "trace": HONEST,
        "attack_steps": ["settlement verifier without currentHeight", "graph verifier without currentHeight"],
        "task": "Refuse a signed checkpoint older than the maximum state age",
        "side": "Get a stale checkpoint accepted by a caller that omits currentHeight",
        "expected": _expected(None, True, 0, "none", {
            "graph vault": OK, "settlement verifier without currentHeight": OK,
            "settlement verifier with currentHeight": STALE_SETTLEMENT,
            "graph verifier without currentHeight": OK, "graph verifier with currentHeight": STALE_GRAPH})},
    "settlement_output_rewrite": {
        "variant": "attack", "family": "settlement", "layer": "on_chain", "attacker": "relayer",
        "attacker_script": "relayer", "trace": HONEST, "attack_steps": ["rewritten settlement"],
        "task": "Bind the pre-signed settlement to the signed payout scripts",
        "side": "Replace one payout script in the pre-signed settlement with the relayer's script",
        "expected": _expected(True, False, 0, "bitcoin_script", {
            "graph vault": OK, "rewritten settlement": BAD_SIGNATURE, "settlement": CONFIRMED})},
    "epoch_replay_same_vault_keys": {
        "variant": "attack", "family": "replay", "layer": "on_chain", "attacker": "relayer",
        "attacker_script": None, "trace": HONEST,
        "attack_steps": ["epoch N witness on epoch N+1 vault", "epoch N signatures under epoch N+1 leaf"],
        "task": "Bind each epoch's pre-signed settlement to its own assertion output",
        "side": "Spend the epoch N+1 vault (same keys) with the epoch N settlement witness",
        "expected": _expected(True, False, 0, "bitcoin_script", {
            "graph epoch_n": OK, "graph epoch_n1": OK, "epoch N witness on epoch N+1 vault": COMMITMENT,
            "epoch N signatures under epoch N+1 leaf": BAD_SIGNATURE, "settlement epoch N": CONFIRMED,
            "settlement epoch N+1": CONFIRMED})},
    "collusion_opposite_preimage_sweep": {
        "variant": "attack", "family": "collusion", "layer": "on_chain", "attacker": "operator+challenger",
        "attacker_script": "colluders", "trace": HONEST, "attack_steps": ["sweep with leaked opposite preimage"],
        "task": "Keep an honest trace unchallengeable for the whole challenge window",
        "side": "The operator hands the challenger the unrevealed preimage of the terminal wire; the challenger "
                "spends the output-binding leaf at once",
        "expected": _expected(False, True, VAULT - DISPROVE_FEE, "none", {
            "graph vault": OK, "target disprove builder": NO_FRAUD, "sweep with leaked opposite preimage": CONFIRMED,
            "settlement after sweep": MISSING})},
    "cosigned_settlement_to_other_outputs": {
        "variant": "attack", "family": "collusion", "layer": "on_chain", "attacker": "operator+challenger",
        "attacker_script": "colluders", "trace": HONEST, "attack_steps": ["co-signed spend to other outputs"],
        "task": "Bind the settlement leaf's outputs to the signed payout vector",
        "side": "Operator and challenger co-sign a settlement-leaf spend that pays their own script",
        "expected": _expected(False, True, VAULT - FEE, "none", {
            "graph vault": OK, "co-signed spend before window": BIP68, "co-signed spend to other outputs": CONFIRMED,
            "settlement after co-signed spend": MISSING})},
}


# Rows whose weakness the target's own notes already state (path, heading).
DOCUMENTED = {
    "recovery_after_stalled_settlement":
        "PILOT_MERGE_NOTES.md, 'BVM-6 and blocker #6: payees depend on data the operator holds'",
    "recovery_resigned_to_other_script":
        "PILOT_MERGE_NOTES.md, 'BVM-6 and blocker #6' (the recovery leaf is the operator's alone)",
    "collusion_opposite_preimage_sweep":
        "PILOT_MERGE_NOTES.md, 'BVM-2: settlement does not depend on the circuit' (operator and challenger together)",
    "cosigned_settlement_to_other_outputs":
        "PILOT_MERGE_NOTES.md, 'BVM-2: settlement does not depend on the circuit'",
    "stale_state_without_height":
        "the live driver btc_testnet4_utxoref_v2_live.js requires --current-height; the library default does not",
}


def catalog():
    return [{"schema_version": 1, "id": f"{TRACK}.{recipe}.as_built.{meta['variant']}", "track": TRACK,
             "recipe": recipe, "family": meta["family"], "layer": meta["layer"], "profile": "as_built",
             "variant": meta["variant"], "attacker": meta["attacker"], "main_task": meta["task"],
             "side_task": meta["side"], "expected": deepcopy(meta["expected"]), "target": dict(TARGET),
             "documented_by_target": DOCUMENTED.get(recipe),
             "evidence_level": EVIDENCE_LEVEL, "upstream_exploit_claim": False}
            for recipe, meta in RECIPES.items()]


def _target_key(role):
    """The driver's fixed operator/challenger key, rederived here so the audit does not trust it."""
    return public(int.from_bytes(sha((DOMAIN + role).encode()), "big")).hex()


def keys():
    return {"operator": _target_key("operator"), "challenger": _target_key("challenger"),
            "forged_operator": public(OWNER_SECRETS["forged_operator"]).hex(),
            "forged_challenger": public(OWNER_SECRETS["forged_challenger"]).hex()}


def scripts():
    return {role: p2tr_key(public(secret)).script_pubkey.hex() for role, secret in OWNER_SECRETS.items()
            if not role.startswith("forged_")}


# --- driver ----------------------------------------------------------------------------

def tool_paths():
    node = Path(os.environ.get("BVA_NODE") or DEFAULT_NODE)
    checkout = Path(os.environ.get("BVA_UTXOREF") or DEFAULT_CHECKOUT)
    if not node.is_file():
        raise ValidationError(f"Node.js not found at {node}; set BVA_NODE")
    if not all((checkout / TARGET["directory"] / name).is_file() for name in TARGET["modules"]):
        raise ValidationError(f"UTXO-Ref checkout not found at {checkout}; set BVA_UTXOREF")
    if not DRIVER.is_file():
        raise ValidationError(f"driver script missing: {DRIVER}")
    return node, checkout


class Driver:
    """The Node process that runs the target's modules; one JSON line per call."""

    def __init__(self, node, checkout):
        self.counter = 0
        self.process = subprocess.Popen(
            [str(node), str(DRIVER), str(checkout)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8",
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        try:
            self.hello = self.call("hello")
            commit = self.hello["target"]["commit"]
            if commit != TARGET_COMMIT:
                raise ValidationError(f"UTXO-Ref checkout HEAD is {commit}; this track is pinned to {TARGET_COMMIT}")
            if {role: self.hello["keys"][role] for role in ("operator", "challenger")} != \
                    {role: _target_key(role) for role in ("operator", "challenger")}:
                raise ValidationError("driver keys differ from the track's fixed test keys")
        except BaseException:
            self.close()
            raise

    def call(self, op, params=None):
        self.counter += 1
        try:
            self.process.stdin.write(json.dumps({"id": self.counter, "op": op, "params": params or {}}) + "\n")
            self.process.stdin.flush()
            line = self.process.stdout.readline()
        except OSError:
            line = ""
        if not line:
            self.process.wait(timeout=10)
            raise ValidationError("UTXO-Ref driver exited: " + self.process.stderr.read()[-2000:])
        reply = json.loads(line)
        if reply.get("id") != self.counter:
            raise ValidationError("driver reply out of order")
        if not reply.get("ok"):
            raise ValidationError(f"driver {op}: {reply.get('error')}")
        return reply["result"]

    def close(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.close()
                self.process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait(timeout=5)
        for stream in (self.process.stdout, self.process.stderr):
            stream.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# --- running a case --------------------------------------------------------------------

def raw_output(script_pubkey_hex):
    """A funding target for Session.fund from a raw P2TR scriptPubKey supplied by the target."""
    spk = bytes.fromhex(script_pubkey_hex)
    if len(spk) != 34 or spk[:2] != b"\x51\x20":
        raise ValidationError("the target's assertion output is not a P2TR scriptPubKey")
    return SimpleNamespace(output_key=spk[2:], script_pubkey=spk)


def target_transaction(raw, utxo):
    """A target-built transaction, byte for byte, annotated with the prevout it spends."""
    tx = Transaction.parse(raw)
    if tx.serialize().hex() != raw:
        raise ValidationError("target transaction does not round-trip through the local serializer")
    if len(tx.inputs) != 1 or (tx.inputs[0].txid, tx.inputs[0].vout) != (utxo["txid"], utxo["vout"]):
        raise ValidationError("target transaction does not spend the funded assertion output")
    tx.inputs[0].amount, tx.inputs[0].script_pubkey = utxo["amount"], bytes.fromhex(utxo["script_pubkey"])
    return tx


class Run:
    """One case: driver calls are recorded as off-chain steps, transactions go through the session."""

    def __init__(self, session, driver, row, genesis):
        self.session, self.driver, self.row, self.genesis = session, driver, row, genesis
        self.meta = RECIPES[row["recipe"]]
        self.scripts = scripts()
        self.setups, self.utxos, self.graphs = {}, {}, {}

    def ctx(self, tag):
        return f"{self.row['id']}/{tag}"

    def call(self, step_label, actor, op, tag="vault", **params):
        params = {"ctx": self.ctx(tag), **params}
        result = self.driver.call(op, params)
        self.session.offchain(step_label, actor, driver_op=op, params=params, result=result)
        return result

    def setup(self, tag="vault", stale_blocks=0):
        node = self.session.node
        snapshot = self.session.height() - stale_blocks
        self.setups[tag] = self.call(
            f"setup {tag}", "operator", "setup", tag, contract=self.row["id"], seed=self.ctx(tag), network=NETWORK,
            genesisHash=self.genesis, epochId=EPOCHS[tag], snapshotHeight=snapshot,
            snapshotBlockHash=node.rpc("getblockhash", snapshot),
            payees={"A": self.scripts["payee_a"], "C": self.scripts["payee_c"]}, quantities=QUANTITIES[tag],
            feeSats=FEE, values=list(self.meta["trace"]), challengeCsvBlocks=CHALLENGE_CSV,
            recoveryCsvBlocks=RECOVERY_CSV)
        return self.setups[tag]

    def fund(self):
        self.utxos = self.session.fund({tag: (raw_output(setup["p2trScriptPubKey"]), int(setup["amountSats"]))
                                        for tag, setup in self.setups.items()})
        self.fund_height = self.session.height()

    def graph(self, tag="vault", with_height=True):
        utxo = self.utxos[tag]
        self.graphs[tag] = self.call(
            f"graph {tag}", "operator+challenger", "graph", tag,
            outpoint={"txid": utxo["txid"], "vout": utxo["vout"], "amountSats": utxo["amount"],
                      "scriptPubKeyHex": utxo["script_pubkey"]},
            recoveryFeeSats=RECOVERY_FEE, recoveryScriptPubKeyHex=self.scripts["operator_wallet"],
            verification=self.verification(with_height))
        return self.graphs[tag]

    def open(self, **options):
        self.setup(stale_blocks=options.get("stale_blocks", 0))
        self.fund()
        return self.graph(with_height=options.get("with_height", True))

    def verification(self, with_height=True):
        return {"currentHeight": self.session.height()} if with_height else {}

    def mine_until(self, lock, short=0, note=None):
        """Mine until a spend with relative lock `lock` is `short` blocks from mempool acceptance."""
        blocks = self.fund_height + lock - 1 - short - self.session.height()
        if blocks > 0:
            self.session.mine(blocks, note)

    def submit(self, label, actor, tx, source, field, mutation=None, note=None):
        allowed = self.session.submit(label, actor, tx, note=note)
        self.session.steps[-1]["source"] = {"step": source, "field": field, "mutation": mutation}
        return allowed

    def settle(self, label, tag="vault", actor="operator"):
        tx = target_transaction(self.graphs[tag]["settlementWitnessTxHex"], self.utxos[tag])
        return self.submit(label, actor, tx, f"graph {tag}", "settlementWitnessTxHex")

    def recover(self, label):
        tx = target_transaction(self.graphs["vault"]["recoveryWitnessTxHex"], self.utxos["vault"])
        return self.submit(label, "operator", tx, "graph vault", "recoveryWitnessTxHex")

    def disprove(self, label="target disprove builder"):
        return self.call(label, "challenger", "disprove", feeSats=DISPROVE_FEE,
                         challengeScriptPubKeyHex=self.scripts["challenger_wallet"])

    def leaf_spend(self, label, actor, leaf, signers, stack, script_role, fee, sequence):
        result = self.call(f"build {label}", actor, "leaf_spend", leafId=leaf, signers=signers, stackItems=stack,
                           outputs=[{"valueSats": str(self.utxos["vault"]["amount"] - fee),
                                     "scriptPubKeyHex": self.scripts[script_role]}], sequence=sequence)
        return target_transaction(result["witnessTxHex"], self.utxos["vault"]), f"build {label}"


def _honest_settlement(run):
    run.open()
    run.settle("settlement before window")
    run.mine_until(CHALLENGE_CSV, short=1)
    run.settle("settlement one block early")
    run.session.mine(1, "challenge window matures")
    run.settle("settlement")


def _disprove_valid_trace(run):
    run.open()
    run.disprove()
    reveals = run.setups["vault"]["reveals"]
    for label, leaf, wires in (("forged disprove on wrong-bit output leaf", f"output:{OUT}:0", [OUT]),
                               ("forged disprove on gate leaf", "gate:0:11:0", [IN_STATE, IN_PAYOUT, OUT])):
        tx, source = run.leaf_spend(label, "challenger", leaf, ["challenger"],
                                    [reveals[wire]["preimage"] for wire in wires], "challenger_wallet",
                                    DISPROVE_FEE, 0xfffffffd)
        run.submit(label, "challenger", tx, source, "witnessTxHex",
                   note="the challenger holds only the preimages the honest trace revealed")
    run.mine_until(CHALLENGE_CSV)
    run.settle("settlement")


def _disprove_fraud_to_challenger(run):
    run.open()
    built = run.disprove()
    tx = target_transaction(built["witnessTxHex"], run.utxos["vault"])
    run.submit("disprove", "challenger", tx, "target disprove builder", "witnessTxHex")
    run.session.mine(1, "disprove confirms")
    run.mine_until(CHALLENGE_CSV)
    run.settle("settlement after disprove")


def _disprove_third_party_redirect(run):
    run.open()
    built = run.disprove()
    redirected = target_transaction(built["witnessTxHex"], run.utxos["vault"])
    redirected.outputs = [(redirected.outputs[0][0], bytes.fromhex(run.scripts["relayer"]))]
    run.submit("redirected disprove", "relayer", redirected, "target disprove builder", "witnessTxHex",
               "output_script", "the relayer has no key; it only rewrites the output script")
    tx = target_transaction(built["witnessTxHex"], run.utxos["vault"])
    run.submit("disprove", "challenger", tx, "target disprove builder", "witnessTxHex")


def _recovery_before_window(run):
    run.open()
    run.recover("recovery before window")
    run.mine_until(CHALLENGE_CSV, note="settlement matures; recovery does not")
    run.recover("recovery at settlement maturity")
    run.settle("settlement")


def _recovery_after_stalled_settlement(run):
    run.open()
    run.mine_until(RECOVERY_CSV, note="nobody broadcasts the settlement")
    run.recover("recovery")
    run.session.mine(1, "recovery confirms")
    run.settle("settlement after recovery", actor="payee")


def _recovery_resigned_to_other_script(run):
    run.open()
    resigned = run.call("resign recovery", "operator", "resign_recovery", recoveryFeeSats=RESIGNED_RECOVERY_FEE,
                        recoveryScriptPubKeyHex=run.scripts["operator_other"])
    run.mine_until(RECOVERY_CSV, note="nobody broadcasts the settlement")
    tx = target_transaction(resigned["recoveryWitnessTxHex"], run.utxos["vault"])
    run.submit("resigned recovery", "operator", tx, "resign recovery", "recoveryWitnessTxHex")
    run.session.mine(1, "resigned recovery confirms")
    run.recover("recovery from the co-signed graph")
    run.settle("settlement after recovery", actor="payee")


def _settlement_keys_from_own_commitment(run):
    graph = run.open()
    trust = run.verification()
    forger = keys()
    run.call("settlement verifier on honest settlement", "payee", "verify_settlement",
             settlement=graph["settlement"], verification=trust)
    for name, fields in (
            ("forged", {"feeSats": 7 * FEE, "challengeCsvBlocks": 1, "recoveryCsvBlocks": 2,
                        "traceRoot": "ab" * 32, "assertionTreeRoot": "cd" * 32,
                        "funding": {"txid": "ee" * 32, "vout": 7, "scriptPubKeyHex": run.scripts["forger"]}}),
            ("key-swapped", {})):
        forged = run.call(f"forge {name} settlement", "forger", "forge_settlement",
                          operatorXonly=forger["forged_operator"], challengerXonly=forger["forged_challenger"],
                          **fields)["settlement"]
        run.call(f"settlement verifier on {name} settlement", "payee", "verify_settlement",
                 settlement=forged, verification=trust)
        run.call(f"graph verifier with {name} settlement", "payee", "verify_graph",
                 settlement=forged, verification=trust)


def _stale_state_without_height(run):
    graph = run.open(stale_blocks=STALE_BLOCKS, with_height=False)
    now = run.verification()
    run.call("settlement verifier without currentHeight", "payee", "verify_settlement",
             settlement=graph["settlement"], verification={})
    run.call("settlement verifier with currentHeight", "payee", "verify_settlement",
             settlement=graph["settlement"], verification=now)
    run.call("graph verifier without currentHeight", "payee", "verify_graph", verification={})
    run.call("graph verifier with currentHeight", "payee", "verify_graph", verification=now)


def _settlement_output_rewrite(run):
    graph = run.open()
    run.mine_until(CHALLENGE_CSV)
    rewritten = target_transaction(graph["settlementWitnessTxHex"], run.utxos["vault"])
    rewritten.outputs[0] = (rewritten.outputs[0][0], bytes.fromhex(run.scripts["relayer"]))
    run.submit("rewritten settlement", "relayer", rewritten, "graph vault", "settlementWitnessTxHex",
               "output_script", "the relayer has no key; it only rewrites one payout script")
    run.settle("settlement")


def _epoch_replay_same_vault_keys(run):
    for tag in ("epoch_n", "epoch_n1"):
        run.setup(tag)
    run.fund()
    for tag in ("epoch_n", "epoch_n1"):
        run.graph(tag)
    run.mine_until(CHALLENGE_CSV)
    old, new = run.utxos["epoch_n"], run.utxos["epoch_n1"]
    replay = target_transaction(run.graphs["epoch_n"]["settlementWitnessTxHex"], old)
    txin = replay.inputs[0]
    txin.txid, txin.vout, txin.amount, txin.script_pubkey = (new["txid"], new["vout"], new["amount"],
                                                             bytes.fromhex(new["script_pubkey"]))
    run.submit("epoch N witness on epoch N+1 vault", "relayer", replay, "graph epoch_n", "settlementWitnessTxHex",
               "outpoint", "epoch N settlement, witness unchanged, pointed at the epoch N+1 outpoint")
    fresh = target_transaction(run.graphs["epoch_n1"]["settlementWitnessTxHex"], new)
    txin.witness = txin.witness[:-2] + fresh.inputs[0].witness[-2:]
    run.submit("epoch N signatures under epoch N+1 leaf", "relayer", replay, "graph epoch_n",
               "settlementWitnessTxHex", "outpoint_and_leaf",
               "epoch N signatures and outputs with the epoch N+1 settlement leaf and control block")
    run.settle("settlement epoch N", "epoch_n")
    run.settle("settlement epoch N+1", "epoch_n1")


def _collusion_opposite_preimage_sweep(run):
    run.open()
    run.disprove()
    leaked = run.call("leak opposite preimage", "operator", "leak_preimage", label=OUT, bit=0)
    tx, source = run.leaf_spend("sweep with leaked opposite preimage", "challenger", f"output:{OUT}:0",
                                ["challenger"], [leaked["preimage"]], "colluders", DISPROVE_FEE, 0xfffffffd)
    run.submit("sweep with leaked opposite preimage", "challenger", tx, source, "witnessTxHex",
               note="first block after funding: no relative lock on a disprove leaf")
    run.session.mine(1, "sweep confirms")
    run.mine_until(CHALLENGE_CSV)
    run.settle("settlement after sweep", actor="payee")


def _cosigned_settlement_to_other_outputs(run):
    run.open()
    tx, source = run.leaf_spend("co-signed spend to other outputs", "operator+challenger", "settlement",
                                ["challenger", "operator"], [], "colluders", FEE, CHALLENGE_CSV)
    run.submit("co-signed spend before window", "operator+challenger", tx, source, "witnessTxHex")
    run.mine_until(CHALLENGE_CSV)
    run.submit("co-signed spend to other outputs", "operator+challenger", tx, source, "witnessTxHex")
    run.session.mine(1, "co-signed spend confirms")
    run.settle("settlement after co-signed spend", actor="payee")


RUNNERS = {
    "honest_settlement": _honest_settlement,
    "disprove_valid_trace": _disprove_valid_trace,
    "disprove_fraud_to_challenger": _disprove_fraud_to_challenger,
    "disprove_third_party_redirect": _disprove_third_party_redirect,
    "recovery_before_window": _recovery_before_window,
    "recovery_after_stalled_settlement": _recovery_after_stalled_settlement,
    "recovery_resigned_to_other_script": _recovery_resigned_to_other_script,
    "settlement_keys_from_own_commitment": _settlement_keys_from_own_commitment,
    "stale_state_without_height": _stale_state_without_height,
    "settlement_output_rewrite": _settlement_output_rewrite,
    "epoch_replay_same_vault_keys": _epoch_replay_same_vault_keys,
    "collusion_opposite_preimage_sweep": _collusion_opposite_preimage_sweep,
    "cosigned_settlement_to_other_outputs": _cosigned_settlement_to_other_outputs,
}


def run_case(session, driver, row, genesis):
    session.begin(keys())
    RUNNERS[row["recipe"]](Run(session, driver, row, genesis))
    return session.finish()


# --- scoring ---------------------------------------------------------------------------

def reject_class(reason):
    return next((name for needle, name in REJECT_CLASSES if needle in (reason or "")), reason)


def verdict(s):
    """What Core or the target decided at one step; None for steps that decide nothing."""
    if s["kind"] == "tx":
        if s.get("confirmed"):
            return CONFIRMED
        return "accepted_unconfirmed" if s["allowed"] else reject_class(s["reject_reason"])
    if s["kind"] != "offchain":
        return None
    op, result = s.get("driver_op"), s.get("result") or {}
    if op == "disprove":
        return BUILT if result.get("built") else result.get("reason")
    if op in ("verify_settlement", "verify_graph"):
        return OK if result.get("ok") else result.get("reason")
    if op in ("graph", "resign_recovery"):
        return OK if result.get("verify", {}).get("ok") else result.get("verify", {}).get("reason")
    return None


def verdicts(steps):
    return {s["label"]: verdict(s) for s in steps if verdict(s) is not None}


def confirmed_outputs(steps):
    for s in steps:
        if s["kind"] == "tx" and s.get("confirmed"):
            yield s, [[value, spk.hex()] for value, spk in Transaction.parse(s["raw_transaction"]).outputs]


def paid_to(steps, script_hex):
    """Confirmed sats to one script, read from the raw transactions."""
    return sum(value for _, outputs in confirmed_outputs(steps) for value, spk in outputs if spk == script_hex)


def payees_paid(steps):
    """Every funded vault was spent by a confirmed transaction whose outputs are exactly its payout vector."""
    fund = step(steps, "fund")
    if fund is None or not fund["outputs"]:
        return False
    for tag, utxo in fund["outputs"].items():
        setup = step(steps, f"setup {tag}")
        vector = [[int(p["valueSats"]), p["scriptPubKeyHex"]] for p in setup["result"]["payouts"]]
        if not any(outputs == vector and [(p["txid"], p["vout"]) for p in s["prevouts"]] == [(utxo["txid"], utxo["vout"])]
                   for s, outputs in confirmed_outputs(steps)):
            return False
    return True


def score(row, steps):
    meta = RECIPES[row["recipe"]]
    seen = verdicts(steps)
    attack = [s for s in steps if s["label"] in meta["attack_steps"]]
    success = any(seen.get(s["label"]) in (CONFIRMED, OK) for s in attack)
    contained = meta.get("contained_by")
    if success and contained and all(seen.get(label) not in (CONFIRMED, OK) for label in contained):
        # A lone library function accepted, and the check every target path makes refused.
        success = False
    if row["variant"] == "benign":
        defense = "n/a"
    elif success:
        defense = "none"
    elif any(s["kind"] == "tx" and not s["allowed"] for s in attack):
        defense = "bitcoin_script"
    else:
        defense = "target_verifier"
    role = meta["attacker_script"]
    return {"legitimate_completion": None if meta["layer"] == "verifier" else payees_paid(steps),
            "attacker_success": success, "diverted_sats": paid_to(steps, scripts()[role]) if role else 0,
            "defense_layer": defense, "verdicts": seen}


def execute(binary, directory, rows=None):
    rows = deepcopy(rows or catalog())
    node_path, checkout = tool_paths()
    cases = []
    with Driver(node_path, checkout) as driver, Regtest(binary, directory) as node:
        node.initialize_wallet()
        provenance = {**node.provenance,
                      "target": {**TARGET, "commit_observed": driver.hello["target"]["commit"],
                                 "file_sha256": driver.hello["target"]["files"],
                                 "state_signer_key_id": driver.hello["keys"]["stateSignerKeyId"],
                                 "defaults": driver.hello["defaults"]},
                      "driver": {"script": "tools/" + DRIVER.name,
                                 "sha256": hashlib.sha256(DRIVER.read_bytes()).hexdigest(),
                                 "node": driver.hello["node"]}}
        session = Session(node)
        genesis = node.rpc("getblockhash", 0)
        for row in rows:
            steps = run_case(session, driver, row, genesis)
            outcome = score(row, steps)
            meta = RECIPES[row["recipe"]]
            cases.append({**row, "keys": keys(), "scripts": scripts(),
                          "attacker_script": scripts()[meta["attacker_script"]] if meta["attacker_script"] else None,
                          "steps": steps, "outcome": outcome,
                          "legitimate_completion": outcome["legitimate_completion"],
                          "attacker_success": outcome["attacker_success"],
                          "diverted_sats": outcome["diverted_sats"], "defense_layer": outcome["defense_layer"],
                          "expectation_met": outcome == row["expected"]})
    report = finalize_report(TRACK, provenance, rows, cases)
    report["evidence_level"] = EVIDENCE_LEVEL
    report["summary"]["attacks_confirmed"] = [c["id"] for c in cases if c["attacker_success"]]
    report["summary"]["diverted_sats"] = sum(c["diverted_sats"] for c in cases)
    report.pop("evidence_hash")
    report["evidence_hash"] = digest(report)
    return report


# --- offline audit ---------------------------------------------------------------------

def nums_key(network):
    """The target's per-network NUMS internal key, rederived."""
    for counter in range(1024):
        candidate = sha(f"{NUMS_DOMAIN}:{network}:{counter}".encode())
        try:
            lift(candidate)
            return candidate
        except ValidationError:
            continue
    raise ValidationError("no NUMS key")


def expected_leaves(setup):
    """Every leaf script of the assertion tree, rebuilt from the recorded public data."""
    wires, operator, challenger = setup["publicWires"], setup["operatorXonly"], setup["challengerXonly"]

    def commitment(label, bit):
        return wires[label][f"hash{bit}"]

    def reveal(hashes):
        locks = "".join("a820" + item + "88" for item in reversed(hashes))
        return locks + "20" + challenger + "ac"

    leaves = {f"gate:0:{a}{b}:{1 - (a & b)}": reveal([commitment(IN_STATE, a), commitment(IN_PAYOUT, b),
                                                      commitment(OUT, 1 - (a & b))])
              for a in (0, 1) for b in (0, 1)}
    for kind, label in (("input", IN_STATE), ("input", IN_PAYOUT), ("output", OUT)):
        leaves[f"{kind}:{label}:0"] = reveal([commitment(label, 0)])
    leaves["trace-commitment"] = "6a20" + setup["traceRoot"]
    leaves["settlement"] = (number(setup["challengeCsvBlocks"]).hex() + "b27520" + operator + "ad20"
                            + challenger + "ac")
    leaves["recovery"] = number(setup["recoveryCsvBlocks"]).hex() + "b27520" + operator + "ac"
    return leaves


def run_leaf(tx, script, control, stack):
    """Re-execute a spent leaf of this tree (pushes, SHA256, EQUALVERIFY, CSV, DROP, CHECKSIG[VERIFY])."""
    leaf = SimpleNamespace(leaf_hash=leaf_hash(script, control[0] & 0xfe))
    stack, offset = list(stack), 0
    try:
        while offset < len(script):
            opcode = script[offset]
            offset += 1
            if 1 <= opcode <= 75:
                stack.append(script[offset:offset + opcode])
                offset += opcode
            elif 0x51 <= opcode <= 0x60:
                stack.append(bytes([opcode - 0x50]))
            elif opcode == 0xa8:
                stack.append(sha(stack.pop()))
            elif opcode == 0x88:
                if stack.pop() != stack.pop():
                    return HASHLOCK
            elif opcode == 0xb2:
                lock, sequence = int.from_bytes(stack[-1], "little"), tx.inputs[0].sequence
                if tx.version < 2 or sequence & 0x80000000 or (sequence & 0xffff) < lock:
                    return "csv_not_satisfied"
            elif opcode == 0x75:
                stack.pop()
            elif opcode in (0xac, 0xad):
                key, signature = stack.pop(), stack.pop()
                if not signature or not check_signature(tx, 0, leaf, key, signature):
                    return BAD_SIGNATURE
                if opcode == 0xac:
                    stack.append(b"\x01")
            else:
                return "unsupported_script"
    except IndexError:
        return "stack_underflow"
    return "accepted" if stack == [b"\x01"] else "unclean_stack"


def local_verdict(steps, index, funded):
    """What Core should say to transaction step `index`, from the recorded steps alone."""
    s = steps[index]
    tx = Transaction.parse(s["raw_transaction"])
    prev = s["prevouts"][0]
    outpoint = (prev["txid"], prev["vout"])
    for position in range(index):
        earlier = steps[position]
        if earlier["kind"] == "tx" and earlier.get("broadcast") and \
                outpoint in [(p["txid"], p["vout"]) for p in earlier["prevouts"]]:
            mined = any(m["kind"] == "mine" for m in steps[position + 1:index])
            return MISSING if mined else "mempool_conflict"
    if outpoint not in funded:
        return MISSING
    txin = tx.inputs[0]
    txin.amount, txin.script_pubkey = prev["amount"], bytes.fromhex(prev["script_pubkey"])
    if tx.version >= 2 and not txin.sequence & 0x80000000:
        if txin.sequence & 0x00400000:
            return "unsupported_time_lock"
        if s["height"] + 1 < funded[outpoint] + (txin.sequence & 0xffff):
            return BIP68
    if len(txin.witness) < 2:
        return "no_script_path"
    script, control = txin.witness[-2], txin.witness[-1]
    if not verify_commitment(txin.script_pubkey, script, control):
        return COMMITMENT
    return run_leaf(tx, script, control, txin.witness[:-2])


def _mutation_problem(tx, base, mutation):
    same_witness = [i.witness for i in tx.inputs] == [i.witness for i in base.inputs]
    same_outpoint = [(i.txid, i.vout) for i in tx.inputs] == [(i.txid, i.vout) for i in base.inputs]
    same_shell = (tx.version, tx.locktime, [i.sequence for i in tx.inputs]) == \
                 (base.version, base.locktime, [i.sequence for i in base.inputs])
    if not same_shell:
        return "version, locktime or sequence differs from the target transaction"
    if mutation == "output_script":
        changed = sum(1 for new, old in zip(tx.outputs, base.outputs) if new[1] != old[1])
        if not (same_witness and same_outpoint and len(tx.outputs) == len(base.outputs) and changed == 1
                and [v for v, _ in tx.outputs] == [v for v, _ in base.outputs]):
            return "is not the target transaction with exactly one output script replaced"
    elif mutation == "outpoint":
        if not (same_witness and not same_outpoint and tx.outputs == base.outputs):
            return "is not the target transaction with only its outpoint replaced"
    elif mutation == "outpoint_and_leaf":
        if same_outpoint or tx.outputs != base.outputs or \
                tx.inputs[0].witness[:-2] != base.inputs[0].witness[:-2]:
            return "does not carry the target transaction's signatures and outputs"
    else:
        return f"unknown mutation {mutation}"
    return None


def _vault_problems(row, case):
    """Funding, tree and trace of every vault in the case."""
    problems, steps = [], case["steps"]
    fund = step(steps, "fund")
    if fund is None:
        return ["no funding step"], {}
    funding, funded = Transaction.parse(fund["raw_transaction"]), {}
    if funding.txid != fund["txid"]:
        problems.append("funding txid does not match its raw transaction")
    for tag, utxo in fund["outputs"].items():
        setup_step, graph_step = step(steps, f"setup {tag}"), step(steps, f"graph {tag}")
        if setup_step is None or graph_step is None:
            problems.append(f"{tag}: setup or graph step missing")
            continue
        setup, params = setup_step["result"], setup_step["params"]
        funded[(utxo["txid"], utxo["vout"])] = fund["height"]
        spk = bytes.fromhex(setup["p2trScriptPubKey"])
        payout_total = sum(int(p["valueSats"]) for p in setup["payouts"])
        if utxo["txid"] != fund["txid"] or utxo["vout"] >= len(funding.outputs) or \
                funding.outputs[utxo["vout"]] != (utxo["amount"], spk) or utxo["script_pubkey"] != spk.hex():
            problems.append(f"{tag}: funded output is not the target's assertion script at the recorded amount")
        if utxo["amount"] != int(setup["amountSats"]) or utxo["amount"] != payout_total + params["feeSats"]:
            problems.append(f"{tag}: vault amount is not payout total plus fee")
        if [p["scriptPubKeyHex"] for p in setup["payouts"]] != [scripts()["payee_a"], scripts()["payee_c"]]:
            problems.append(f"{tag}: payout scripts are not the payees' scripts")
        if tuple(params["values"]) != RECIPES[row["recipe"]]["trace"] or \
                [setup["reveals"][w]["bit"] for w in (IN_STATE, IN_PAYOUT, OUT)] != params["values"]:
            problems.append(f"{tag}: public trace bits differ from the recipe")
        if (setup["operatorXonly"], setup["challengerXonly"]) != (keys()["operator"], keys()["challenger"]) or \
                (setup["challengeCsvBlocks"], setup["recoveryCsvBlocks"]) != (CHALLENGE_CSV, RECOVERY_CSV):
            problems.append(f"{tag}: template keys or windows differ from the track's")
        recorded = {leaf["id"]: leaf["scriptHex"] for leaf in setup["leaves"]}
        if recorded != expected_leaves(setup):
            problems.append(f"{tag}: leaf scripts do not rebuild from the recorded keys, windows and wire hashes")
        internal = nums_key(params["network"])
        for leaf in setup["leaves"]:
            control = bytes.fromhex(leaf["controlBlock"])
            if control[1:33] != internal or not verify_commitment(spk, bytes.fromhex(leaf["scriptHex"]), control):
                problems.append(f"{tag}: leaf {leaf['id']} is not committed by the funded output under the NUMS key")
        for label, reveal in setup["reveals"].items():
            if sha(bytes.fromhex(reveal["preimage"])).hex() != setup["publicWires"][label][f"hash{reveal['bit']}"]:
                problems.append(f"{tag}: revealed preimage of {label} does not open its commitment")
        outpoint = graph_step["params"]["outpoint"]
        if (outpoint["txid"], outpoint["vout"], outpoint["amountSats"], outpoint["scriptPubKeyHex"]) != \
                (utxo["txid"], utxo["vout"], utxo["amount"], utxo["script_pubkey"]):
            problems.append(f"{tag}: graph was built on another outpoint than the funded one")
        core = graph_step["result"]["commitmentCore"]
        if (core["operatorXonly"], core["challengerXonly"], core["assertionTreeRoot"], core["traceRoot"]) != \
                (setup["operatorXonly"], setup["challengerXonly"], setup["assertionTreeRoot"], setup["traceRoot"]):
            problems.append(f"{tag}: honest settlement commitment does not name the template's keys and roots")
    return problems, funded


def _transaction_problems(case, funded):
    """Each transaction: where it came from, and whether Core's verdict follows from the steps."""
    problems, steps = [], case["steps"]
    for index, s in enumerate(steps):
        if s["kind"] != "tx":
            continue
        label, result = s["label"], s.get("mempool_result") or {}
        if bool(result.get("allowed")) != bool(s["allowed"]) or s.get("reject_reason") != result.get("reject-reason"):
            problems.append(f"{label}: verdict differs from Core's recorded mempool result")
        if s.get("confirmed") and not (s["allowed"] and s.get("broadcast") and s.get("blockhash")):
            problems.append(f"{label}: confirmed without being allowed, broadcast and mined")
        source = s.get("source") or {}
        origin = step(steps, source.get("step"))
        base_hex = ((origin or {}).get("result") or {}).get(source.get("field"))
        if base_hex is None:
            problems.append(f"{label}: no recorded target transaction it derives from")
        elif source["mutation"] is None:
            if s["raw_transaction"] != base_hex:
                problems.append(f"{label}: differs from the transaction the target built")
        else:
            reason = _mutation_problem(Transaction.parse(s["raw_transaction"]), Transaction.parse(base_hex),
                                       source["mutation"])
            if reason:
                problems.append(f"{label}: {reason}")
        predicted = local_verdict(steps, index, funded)
        observed = "accepted" if s["allowed"] else reject_class(s["reject_reason"])
        if predicted != observed:
            problems.append(f"{label}: Core said {observed}, the recorded steps give {predicted}")
    return problems


def _verifier_problems(row, case):
    """Verifier-level rows: the recorded verdicts are about the recorded objects."""
    problems, steps, recipe = [], case["steps"], row["recipe"]
    if any(s["kind"] == "tx" for s in steps):
        problems.append("verifier-level case carries a transaction step")
    graph_step, setup_step = step(steps, "graph vault"), step(steps, "setup vault")
    if graph_step is None or setup_step is None:
        return problems + ["setup or graph step missing"]
    honest = graph_step["result"]["settlement"]
    vector = [[int(p["valueSats"]), p["scriptPubKeyHex"]] for p in setup_step["result"]["payouts"]]

    def call(label):
        found = step(steps, label)
        if found is None:
            problems.append(f"{label}: step missing")
        return found or {"params": {}, "result": {}}

    if recipe == "settlement_keys_from_own_commitment":
        for name in ("forged", "key-swapped"):
            forged = call(f"forge {name} settlement")["result"].get("settlement") or {}
            core = (forged.get("commitment") or {}).get("core") or {}
            if forged.get("stateEnvelope") != honest["stateEnvelope"]:
                problems.append(f"{name}: forged settlement is not for the same signed state")
            if (core.get("operatorXonly"), core.get("challengerXonly")) != \
                    (keys()["forged_operator"], keys()["forged_challenger"]):
                problems.append(f"{name}: forged commitment does not name the forger's keys")
            outputs = [[v, spk.hex()] for v, spk in Transaction.parse(forged.get("unsignedTxHex", "")).outputs] \
                if forged.get("unsignedTxHex") else None
            if outputs != vector:
                problems.append(f"{name}: forged settlement transaction does not pay the signed payout vector")
            same = {field: core.get(field) == honest["commitment"]["core"][field]
                    for field in ("feeSats", "challengeCsvBlocks", "recoveryCsvBlocks", "traceRoot",
                                  "assertionTreeRoot", "fundingRoot")}
            if any(same.values()) if name == "forged" else not all(same.values()):
                problems.append(f"{name}: forged commitment fields are not as described")
            for label in (f"settlement verifier on {name} settlement", f"graph verifier with {name} settlement"):
                probe = call(label)["params"]
                if probe.get("settlement") != forged or "currentHeight" not in (probe.get("verification") or {}):
                    problems.append(f"{label}: not a check of the forged object under the honest trust options")
        if call("settlement verifier on honest settlement")["params"].get("settlement") != honest:
            problems.append("control is not a check of the honest settlement")
    else:
        snapshot = setup_step["params"]["snapshotHeight"]
        if honest["stateEnvelope"]["body"]["snapshotHeight"] != snapshot:
            problems.append("signed checkpoint height differs from the setup")
        if "currentHeight" in graph_step["params"]["verification"]:
            problems.append("stale graph was built with a current height")
        for kind in ("settlement", "graph"):
            without = call(f"{kind} verifier without currentHeight")["params"]
            with_height = call(f"{kind} verifier with currentHeight")["params"]
            if without.get("verification") != {}:
                problems.append(f"{kind}: the call without a height carries verification options")
            height = (with_height.get("verification") or {}).get("currentHeight")
            if height is None or height - snapshot <= MAX_STATE_AGE:
                problems.append(f"{kind}: the checkpoint is not older than the maximum state age at the given height")
            if kind == "settlement" and not (without.get("settlement") == with_height.get("settlement") == honest):
                problems.append("settlement: the two calls do not check the same settlement object")
    return problems


def audit(report):
    rows = catalog()
    problems = check_report_envelope(report, TRACK, rows)
    if report.get("evidence_level") != EVIDENCE_LEVEL:
        problems.append(f"wrong evidence_level: {report.get('evidence_level')}")
    provenance = report.get("provenance", {})
    if provenance.get("chain") != "regtest" or not provenance.get("subversion"):
        problems.append("provenance does not name a regtest Core and its subversion")
    target = provenance.get("target", {})
    if target.get("commit") != TARGET_COMMIT or target.get("commit_observed") != TARGET_COMMIT:
        problems.append("provenance does not name the pinned target commit")
    by_id = {r["id"]: r for r in rows}
    for case in report.get("cases", []):
        row = by_id.get(case.get("id"))
        if row is None:
            continue
        cid, meta = row["id"], RECIPES[row["recipe"]]
        found = [f"{cid}: {p}" for p in audit_transactions(case)]
        if case.get("keys") != keys() or case.get("scripts") != scripts():
            found.append(f"{cid}: keys or scripts differ from the track's fixed test values")
        attacker_script = scripts()[meta["attacker_script"]] if meta["attacker_script"] else None
        if case.get("attacker_script") != attacker_script:
            found.append(f"{cid}: wrong attacker script")
        vault_problems, funded = _vault_problems(row, case)
        found += [f"{cid}: {p}" for p in vault_problems]
        found += [f"{cid}: {p}" for p in _transaction_problems(case, funded)]
        if meta["layer"] == "verifier":
            found += [f"{cid}: {p}" for p in _verifier_problems(row, case)]
        outcome = score(row, case["steps"])
        if outcome != case.get("outcome"):
            found.append(f"{cid}: outcome does not follow from the recorded steps")
        if any(case.get(field) != outcome[field] for field in
               ("legitimate_completion", "attacker_success", "diverted_sats", "defense_layer")):
            found.append(f"{cid}: case score fields differ from the outcome")
        if attacker_script is not None and case.get("diverted_sats") != paid_to(case["steps"], attacker_script):
            found.append(f"{cid}: diverted_sats is not the confirmed value paid to the attacker script")
        problems += found
    summary = report.get("summary", {})
    cases = report.get("cases", [])
    if summary.get("attacks_confirmed") != [c.get("id") for c in cases if c.get("attacker_success")] or \
            summary.get("diverted_sats") != sum(c.get("diverted_sats") or 0 for c in cases):
        problems.append("summary attack totals inconsistent with the cases")
    return problems
