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
evaluation latency are scaled, and the latency recipe declares its delay explicitly.
"""

from __future__ import annotations

import hashlib
import struct
from copy import deepcopy
from dataclasses import dataclass, field

from . import gc
from .bitcoin import (SIGHASH_DEFAULT, SIGHASH_NONE, TapTree, Transaction, bit_opening, number, op_return,
                      ops, p2tr_key, public, push, sha)
from .canonical import ValidationError
from .core import Regtest
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
TAG = b"IOB/bitvm3-claim/v1"

RECIPES = {
    "labels_offchain_withheld": {
        "family": "input_label_availability", "attacker": "claimant", "iob_assumption": "T2",
        "bitvm2_relation": "introduced",
        "task": "Pay an honest claim after the window; stop a false claim with the reject label",
        "side": "Make a false claim and withhold the input labels so nobody can evaluate"},
    "garbling_unchecked": {
        "family": "garbling_correctness", "attacker": "claimant", "iob_assumption": "T1",
        "bitvm2_relation": "changed",
        "task": "Register only correctly garbled instances", "side": "Register a garbling whose output decoding is swapped"},
    "cut_and_choose_grindable": {
        "family": "garbling_correctness", "attacker": "claimant", "iob_assumption": None,
        "bitvm2_relation": "introduced",
        "task": "Open all but one committed garbling, chosen unpredictably",
        "side": "Grind a non-interactive cut-and-choose challenge so the bad instance is kept"},
    "seed_reuse_across_claims": {
        "family": "label_secrecy", "attacker": "watch", "iob_assumption": None,
        "bitvm2_relation": "introduced",
        "task": "Use a fresh garbling seed per claim", "side": "Derive Delta from two claims' labels and disprove an honest claim"},
    "output_polarity_swapped": {
        "family": "output_decoding", "attacker": "claimant", "iob_assumption": None,
        "bitvm2_relation": "carried",
        "task": "Bind the disprove leaf to the reject label", "side": "Make a false claim the swapped leaf cannot stop"},
    "single_watcher_disprove": {
        "family": "disprove_liveness", "attacker": "claimant", "iob_assumption": "single watcher W",
        "bitvm2_relation": "changed",
        "task": "Let any holder of the reject label stop a false claim",
        "side": "Make a false claim while the one authorized watcher is offline"},
    "window_below_latency": {
        "family": "evaluation_latency", "attacker": "claimant", "iob_assumption": "WINDOW=6 vs ~60 min M14 evaluation",
        "bitvm2_relation": "introduced",
        "task": "Keep the payout window longer than off-chain evaluation",
        "side": "Take the payout before the evaluator finishes"},
    "payout_csv_removed": {
        "family": "timelock", "attacker": "claimant", "iob_assumption": None, "bitvm2_relation": "carried",
        "task": "Hold the payout for the challenge window", "side": "Take the payout before anyone can disprove"},
    "payout_sighash_none": {
        "family": "presigned_binding", "attacker": "relayer", "iob_assumption": None, "bitvm2_relation": "carried",
        "task": "Pay the claimant's derived key P'", "side": "Redirect the presigned payout"},
    "claimant_unbonded": {
        "family": "economic_deterrence", "attacker": "claimant", "iob_assumption": "no claimant bond",
        "bitvm2_relation": "changed",
        "task": "Make a disproven false claim cost the claimant", "side": "Make a false claim that costs the claimant nothing"},
}
EXPECTED_HONEST_PAID_ON_ATTACK = {"seed_reuse_across_claims", "payout_sighash_none"}


def catalog():
    rows = []
    for recipe, meta in RECIPES.items():
        for profile in ("hardened", "mutant"):
            for variant in ("benign", "attack"):
                attack = variant == "attack"
                success = attack and profile == "mutant"
                if attack:
                    paid = recipe in EXPECTED_HONEST_PAID_ON_ATTACK and profile == "hardened"
                else:
                    paid = True
                rows.append({"schema_version": 1, "id": f"{TRACK}.{recipe}.{profile}.{variant}", "track": TRACK,
                             "recipe": recipe, "family": meta["family"], "profile": profile, "variant": variant,
                             "attacker": meta["attacker"] if attack else None,
                             "main_task": meta["task"], "side_task": meta["side"] if attack else None,
                             "iob_assumption": meta["iob_assumption"], "bitvm2_relation": meta["bitvm2_relation"],
                             "expected": {"attack_success": success, "honest_claim_paid": paid},
                             "upstream": UPSTREAM, "evidence_level": "bitcoin-core-regtest-transactions",
                             "upstream_exploit_claim": False})
    return rows


def keys():
    return {name: public(secret).hex() for name, secret in SECRETS.items()}


def frame(data):
    return struct.pack(">I", len(data)) + data


def seed(case_id, tag):
    return sha(f"{case_id}:{tag}".encode())[:16]


@dataclass
class Config:
    labels_onchain: bool = False
    disprove_mode: str = "watcher"
    polarity: str = "reject"
    window: int = WINDOW
    payout_csv: bool = True
    payout_hash_type: int = SIGHASH_DEFAULT
    bond: bool = False
    cut_and_choose: str = "none"     # none | interactive | fiat_shamir
    seed_reuse: bool = False


def config(recipe, profile):
    m = profile == "mutant"
    return Config(
        labels_onchain=recipe == "labels_offchain_withheld" and not m,
        disprove_mode="presigned" if recipe == "single_watcher_disprove" and not m else "watcher",
        polarity="accept" if recipe == "output_polarity_swapped" and m else "reject",
        window=HARDENED_WINDOW if recipe == "window_below_latency" and not m else WINDOW,
        payout_csv=not (recipe == "payout_csv_removed" and m),
        payout_hash_type=SIGHASH_NONE if recipe == "payout_sighash_none" and m else SIGHASH_DEFAULT,
        bond=recipe == "claimant_unbonded" and not m,
        cut_and_choose=({"garbling_unchecked": "none" if m else "interactive",
                         "cut_and_choose_grindable": "fiat_shamir" if m else "interactive"}.get(recipe, "none")),
        seed_reuse=recipe == "seed_reuse_across_claims" and m)


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


@dataclass
class Prepared:
    row: dict
    cfg: Config
    garbling: object            # the instance the graph uses (garbler's private view)
    public: dict                # what was registered for it
    desk_presigns: bool
    setup_log: dict = field(default_factory=dict)
    prior: object = None        # G4: the earlier claim's garbling


def prepare(row):
    """Deterministic setup: garbling(s), cut-and-choose, and the desk's presign decision."""
    recipe, cfg = row["recipe"], config(row["recipe"], row["profile"])
    attack, cid = row["variant"] == "attack", row["id"]
    log = {}
    malicious = attack and recipe in ("garbling_unchecked", "cut_and_choose_grindable")
    if cfg.cut_and_choose == "none":
        garbling = gc.garble(STATEMENT, seed(cid, "garbling"))
        data = published(garbling, swapped=malicious)
        log["cut_and_choose"] = "not run (desk presigns the registered instance)"
        prep = Prepared(row, cfg, garbling, data, True, log)
    else:
        instances = [gc.garble(STATEMENT, seed(cid, f"instance{i}")) for i in range(CUT)]

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
        checks = {i: gc.check_opening(STATEMENT, seed(cid, f"instance{i}"), datas[i]) for i in opened}
        log.update(k=CUT, malicious=sorted(bad), grind_attempts=attempts, kept=kept,
                   commitments=commitments, opened_checks={str(i): ok for i, ok in checks.items()})
        prep = Prepared(row, cfg, instances[kept], datas[kept], all(checks.values()), log)
    if recipe == "seed_reuse_across_claims":
        prior_seed = seed(cid, "garbling") if cfg.seed_reuse else seed(cid, "prior-garbling")
        prep.prior = gc.garble(PRIOR_STATEMENT, prior_seed)
        log["prior_claim_seed"] = "same seed as this claim" if cfg.seed_reuse else "independent seed"
    return prep


class Graph:
    def __init__(self, prep):
        self.prep, self.cfg, self.data = prep, prep.cfg, prep.public
        self.D, self.C, self.W = (public(SECRETS[n]) for n in ("desk", "claimant", "watch"))
        label_hash = self.data["reject_label_sha256" if self.cfg.polarity == "reject" else "accept_label_sha256"]
        self.disprove_hash = bytes.fromhex(label_hash)
        claim = push(self.D) + ops("CHECKSIGVERIFY") + push(self.C) + ops("CHECKSIG")
        if self.cfg.labels_onchain:
            openings = b"".join(bit_opening(bytes.fromhex(h0), bytes.fromhex(h1)) + ops("DROP")
                                for h0, h1 in self.data["input_label_sha256"])
            claim = openings + claim
        reclaim = number(RECLAIM) + ops("CSV", "DROP") + push(self.D) + ops("CHECKSIG")
        self.V = TapTree((claim, reclaim))
        payout = (number(self.cfg.window) + ops("CSV", "DROP") if self.cfg.payout_csv else b"") + push(self.D) + ops("CHECKSIG")
        signer = self.D if self.cfg.disprove_mode == "presigned" else self.W
        disprove = ops("SHA256") + push(self.disprove_hash) + ops("EQUALVERIFY") + push(signer) + ops("CHECKSIG")
        self.K = TapTree((payout, disprove))
        self.bond_tree = TapTree((push(self.C) + ops("CHECKSIG"),))
        self.payout_spk = p2tr_key(public(SECRETS["payout"])).script_pubkey
        self.refund_spk = p2tr_key(public(SECRETS["refund"])).script_pubkey
        self.k_value = VAULT + (BOND if self.cfg.bond else 0) - FEE

    def claim_id(self):
        h = hashlib.sha256(frame(TAG))
        for part in (self.prep.row["id"].encode(), STATEMENT.to_bytes(4, "big"), b"bitvm-arena/toy-adder-16",
                     bytes.fromhex(self.data["ciphertext_commitment"]), bytes.fromhex(self.data["accept_label_sha256"]),
                     bytes.fromhex(self.data["reject_label_sha256"]), self.payout_spk):
            h.update(frame(part))
        return h.digest()

    def funding(self):
        outputs = {"vault": (self.V, VAULT)}
        if self.cfg.bond:
            outputs["bond"] = (self.bond_tree, BOND)
        return outputs

    def claim_tx(self, utxos, labels, desk_signs=True):
        ins = [utxo_input(utxos["vault"], 0xffffffff)]
        if self.cfg.bond:
            ins.append(utxo_input(utxos["bond"]))
        tx = Transaction(ins, [(self.k_value, self.K.script_pubkey), (0, op_return(b"IOB3" + self.claim_id()))])
        leaf = self.V.leaf(0)
        sig_c = tx.signature(0, leaf, SECRETS["claimant"])
        # Without the desk's presignature the claimant can only sign in its place.
        sig_d = tx.signature(0, leaf, SECRETS["desk"] if desk_signs else SECRETS["claimant"])
        stack = [sig_c, sig_d] + (list(reversed(labels)) if self.cfg.labels_onchain else [])
        tx.inputs[0].witness = stack + [leaf.script, leaf.control]
        if self.cfg.bond:
            bond_leaf = self.bond_tree.leaf(0)
            tx.inputs[1].witness = [tx.signature(1, bond_leaf, SECRETS["claimant"]), bond_leaf.script, bond_leaf.control]
        return tx

    def k_utxo(self, claim):
        return {"txid": claim.txid, "vout": 0, "amount": self.k_value, "script_pubkey": self.K.script_pubkey.hex()}

    def payout_tx(self, claim, destination=None):
        sequence = self.cfg.window if self.cfg.payout_csv else 0xfffffffd
        tx = Transaction([utxo_input(self.k_utxo(claim), sequence)], [(self.k_value - FEE, self.payout_spk)])
        leaf = self.K.leaf(0)
        tx.inputs[0].witness = [tx.signature(0, leaf, SECRETS["desk"], self.cfg.payout_hash_type), leaf.script, leaf.control]
        if destination is not None:     # an outsider rewrites the outputs, keeping the desk's witness
            tx.outputs = [(self.k_value - FEE, destination)]
        return tx

    def disprove_tx(self, claim, label, signer):
        tx = Transaction([utxo_input(self.k_utxo(claim))], [])
        if self.cfg.bond:
            tx.outputs = [(VAULT - 2 * FEE, self.refund_spk), (BOND, p2tr_key(public(SECRETS[signer])).script_pubkey)]
        else:
            tx.outputs = [(self.k_value - FEE, self.refund_spk)]
        leaf = self.K.leaf(1)
        key = "desk" if self.cfg.disprove_mode == "presigned" else signer
        tx.inputs[0].witness = [tx.signature(0, leaf, SECRETS[key]), label, leaf.script, leaf.control]
        return tx


def labels_from_claim(raw):
    """What a challenger reads from the chain when labels are revealed in the claim witness."""
    witness = Transaction.parse(raw).inputs[0].witness
    return list(reversed(witness[2:-2]))


def run_case(session, row):
    prep = prepare(row)
    graph = Graph(prep)
    recipe, attack, cfg = row["recipe"], row["variant"] == "attack", prep.cfg
    proof = FALSE_PROOF if attack and recipe not in EXPECTED_HONEST_PAID_ON_ATTACK else HONEST_PROOF
    session.begin(keys())
    session.offchain("setup", "claimant", statement=STATEMENT, registered=graph.data["ciphertext_commitment"],
                     accept_label_sha256=graph.data["accept_label_sha256"],
                     reject_label_sha256=graph.data["reject_label_sha256"],
                     disprove_leaf_hash=graph.disprove_hash.hex(), log=prep.setup_log,
                     desk_presigns=prep.desk_presigns, config=cfg.__dict__)
    utxos = session.fund(graph.funding())
    bits = gc.proof_bits(*proof)
    labels = prep.garbling.input_labels(bits)
    session.offchain("claim proof", "claimant", proof=list(proof), statement=STATEMENT)
    claim = graph.claim_tx(utxos, labels, desk_signs=prep.desk_presigns)
    if not session.submit("claim", "claimant", claim):
        session.offchain("vault check", "evaluator", vault_unspent=session.utxo_unspent(utxos["vault"]["txid"],
                                                                                         utxos["vault"]["vout"]))
        return prep, session.finish()
    session.mine(1, "claim confirmed")
    conf = 1

    def advance(to):
        nonlocal conf
        if to > conf:
            session.mine(to - conf)
            conf = to

    # Label handover / extraction and evaluation.
    holders = ["watch", "third"] if recipe == "single_watcher_disprove" else ["watch"]
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

    if recipe == "payout_csv_removed" and attack:
        if session.submit("payout", "claimant", graph.payout_tx(claim), note="immediately after the claim confirms"):
            # Off-chain evaluation takes longer than one block; the payout confirms first.
            # (While it is unconfirmed, full-RBF would let a higher-fee disprove replace it.)
            session.mine(1, "payout confirms before the evaluation finishes")
            conf += 1

    evaluator = "third" if recipe == "single_watcher_disprove" else "watch"
    verdict, out_label = "no labels", None
    if got is not None:
        out_label = gc.evaluate(STATEMENT, prep.garbling.tables, got)
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
    elif verdict == "reject":
        session.submit("disprove", evaluator, graph.disprove_tx(claim, out_label, evaluator))

    advance(cfg.window)
    if recipe == "payout_sighash_none" and attack:
        thief = p2tr_key(public(SECRETS["relayer"])).script_pubkey
        if session.submit("redirected payout", "relayer", graph.payout_tx(claim, destination=thief),
                          note="the relayer mines its own rewrite"):
            session.mine(1, "relayer's block")
    if not confirmed_now(session, "payout"):
        session.submit("payout", "claimant", graph.payout_tx(claim))
    return prep, session.finish()


def confirmed_now(session, label):
    return any(s["kind"] == "tx" and s["label"] == label and s["broadcast"] for s in session.steps)


def claimant_scripts():
    tree = TapTree((push(public(SECRETS["claimant"])) + ops("CHECKSIG"),))
    return {tree.script_pubkey.hex(), p2tr_key(public(SECRETS["payout"])).script_pubkey.hex()}


def claimant_loss(steps):
    mine, loss = claimant_scripts(), 0
    for s in steps:
        if s["kind"] == "tx" and s.get("confirmed"):
            loss += sum(p["amount"] for p in s["prevouts"] if p["script_pubkey"] in mine)
            loss -= sum(v for v, spk in Transaction.parse(s["raw_transaction"]).outputs if spk.hex() in mine)
    return loss


def score(row, steps):
    """Outcome from confirmed transactions only; never reads the declared expectation."""
    proof = step(steps, "claim proof")
    honest = proof is not None and sum(proof["proof"]) == proof["statement"]
    paid = confirmed(steps, "payout")
    recipe = row["recipe"]
    if recipe == "seed_reuse_across_claims":
        attack = confirmed(steps, "griefing disprove")
    elif recipe == "payout_sighash_none":
        attack = confirmed(steps, "redirected payout")
    elif recipe == "claimant_unbonded":
        attack = (not honest) and confirmed(steps, "claim") and claimant_loss(steps) <= 0
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


def audit(report):
    """Offline audit: envelope, local tx checks, rebuilt setup, re-evaluated garblings, rescoring."""
    rows = catalog()
    problems = check_report_envelope(report, TRACK, rows)
    by_id = {r["id"]: r for r in rows}
    for case in report.get("cases", []):
        row = by_id.get(case.get("id"))
        if row is None:
            continue
        cid = row["id"]
        if case.get("keys") != keys():
            problems.append(f"{cid}: party keys differ from the fixture keys")
        problems += [f"{cid}: {p}" for p in audit_transactions(case, keys())]
        prep = prepare(row)
        graph = Graph(prep)
        steps = case["steps"]
        setup = step(steps, "setup")
        if setup is None or setup.get("registered") != graph.data["ciphertext_commitment"] \
                or setup.get("disprove_leaf_hash") != graph.disprove_hash.hex() \
                or setup.get("desk_presigns") != prep.desk_presigns:
            problems.append(f"{cid}: recorded setup differs from the rebuilt setup")
        fund = step(steps, "fund")
        if fund is None or fund["outputs"]["vault"]["script_pubkey"] != graph.V.script_pubkey.hex():
            problems.append(f"{cid}: funded vault script differs from the rebuilt graph")
        claim = step(steps, "claim")
        if claim is not None:
            parsed = Transaction.parse(claim["raw_transaction"])
            if parsed.outputs[0][1] != graph.K.script_pubkey or parsed.outputs[1][1] != op_return(b"IOB3" + graph.claim_id()):
                problems.append(f"{cid}: claim outputs differ from the rebuilt graph")
        evaluation = step(steps, "evaluate")
        if evaluation is not None and evaluation["labels"] is not None:
            got = [bytes.fromhex(x) for x in evaluation["labels"]]
            out = gc.evaluate(STATEMENT, prep.garbling.tables, got)
            verdict = gc.decode(out, graph.data["accept_label_sha256"], graph.data["reject_label_sha256"])
            if out.hex() != evaluation["output_label"] or verdict != evaluation["verdict"]:
                problems.append(f"{cid}: re-evaluated garbling disagrees with the recorded evaluation")
        chain = step(steps, "labels from chain")
        if chain is not None and claim is not None:
            if [x.hex() for x in labels_from_claim(claim["raw_transaction"])] != chain["labels"]:
                problems.append(f"{cid}: labels read from the claim witness differ")
        if score(row, steps) != case.get("outcome"):
            problems.append(f"{cid}: outcome does not follow from the recorded steps")
    return problems
