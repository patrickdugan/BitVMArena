"""BitVM2 baseline trajectories: the reference bridge's spending conditions at regtest scale.

The graph mirrors the BitVM2 bridge in BitVM/BitVM (pinned commit c620dbfa): a deposit
output reimbursed by take_1 (optimistic, after a timelock, only if nobody challenged) or
take_2 (after an assertion survived the disprove window), a challenge that spends
connector A with an operator presignature the challenger can extend (SIGHASH_SINGLE |
ANYONECANPAY), an assertion that commits the operator's Winternitz-signed claim, and a
disprove whose script verifies those signatures and a chunk computation. It exists to
compare against the BitVM3 track under the same harness and report format.

Declared simplifications: one test key stands for the MuSig2 n-of-n; connectors 3 and 4
are taproot leaves (upstream P2WSH); kick-off 1 and 2 are merged into one kick-off
funded from an operator UTXO; the start-time and superblock (disprove chain) paths,
connector D and the f_1/f_2 transactions are omitted; assert_initial/commit/final are
merged into one assert transaction; timelocks of 3 days and 2 weeks are scaled to 6
blocks each; the chunk is a non-ZK adder (x + y == z over 8-, 8- and 12-bit Winternitz
values) instead of Groth16 chunks. Every recipe flips one design decision; the mutant
profile is that decision removed, not a claim that the upstream code is broken.
"""

from __future__ import annotations

import hashlib
from copy import deepcopy
from dataclasses import dataclass

from . import wots
from .bitcoin import (ANYONECANPAY, NUMS, SIGHASH_ALL, SIGHASH_DEFAULT, SIGHASH_NONE, SIGHASH_SINGLE, TapTree,
                      Transaction, number, ops, p2tr_key, public, push, sha)
from .core import Regtest
from .track import (Session, audit_transactions, check_report_envelope, confirmed, finalize_report, step,
                    utxo_input)

TRACK = "bitvm2"
UPSTREAM = {"target": "BitVM2 bridge spending conditions", "repository": "BitVM/BitVM",
            "commit": "c620dbfaacebdf778e765a6681985350389973b1",
            "path": "bitvm/src/bridge/ and bitvm/src/signatures/winternitz.rs",
            "scale": "regtest: 6-block timelocks, adder chunk, one key for the n-of-n"}
SECRETS = {"nofn": 0xB1720001, "operator": 0xB1720002, "challenger": 0xB1720003, "relayer": 0xB1720004,
           "payout": 0xB1720005}
MASTERS = {name: sha(f"bitvm-arena/bitvm2/wots/{name}".encode())[:20] for name in ("x", "y", "z")}
N0 = {"x": 2, "y": 2, "z": 3}
DEP, CA, C3, CB, C4, C5, CC, CROWD, BURN, FEE = (100_000, 6_000, 4_000, 21_000, 4_000, 6_000, 9_000, 10_000,
                                                   9_000, 2_000)
OPF = CA + C3 + CB + FEE
T1 = T2 = 6
FINAL = 0xfffffffd
HONEST = (100, 50, 150)
FALSE_Z = 151
WRAP = (200, 100)          # x + y >= 256 for the chunk-carry recipe

RECIPES = {
    "take1_csv_removed": {
        "family": "timelock", "attacker": "operator", "bitvm3_relation": "carried",
        "task": "Hold take_1 until the challenge window has passed",
        "side": "Kick off a false claim and take the reimbursement before a challenger can react"},
    "take1_unbound_connector_a": {
        "family": "unbound_connector", "attacker": "operator", "bitvm3_relation": "removed",
        "note": "the IOB BitVM3 graph has no challenge step",
        "task": "Make take_1 depend on the unchallenged challenge connector",
        "side": "Take the reimbursement after the claim was challenged"},
    "challenge_sighash_all": {
        "family": "presigned_binding", "attacker": "operator", "bitvm3_relation": "removed",
        "note": "the IOB BitVM3 graph has no challenge step",
        "task": "Let a challenger add crowdfunding inputs to the presigned challenge",
        "side": "Presign the challenge so that it cannot be completed, then take_1 after the window"},
    "take2_unbound_disprove": {
        "family": "unbound_connector", "attacker": "operator", "bitvm3_relation": "carried",
        "task": "Make take_2 depend on the disprove connectors being unspent",
        "side": "Assert a false value, get disproved, and still collect take_2"},
    "chunk_carry_dropped": {
        "family": "chunk_correctness", "attacker": "operator", "bitvm3_relation": "changed",
        "note": "circuit correctness moves from on-chain chunk scripts to garbling correctness and cut-and-choose",
        "task": "Compute the full sum in the disprove chunk",
        "side": "Assert a wrapped sum the carry-dropping chunk accepts"},
    "wots_checksum_unchecked": {
        "family": "winternitz_checksum", "attacker": "challenger", "bitvm3_relation": "changed",
        "note": "BitVM3 inputs are labels, not Winternitz signatures, and IOB delivers them off-chain",
        "task": "Accept only Winternitz signatures whose checksum balances",
        "side": "Hash-forward an honest operator's signature and disprove an honest assertion"},
    "disprove_burn_sighash_none": {
        "family": "presigned_binding", "attacker": "operator", "bitvm3_relation": "changed",
        "note": "IOB has no burn and no operator stake",
        "task": "Fix the burn output of the disprove with SIGHASH_SINGLE",
        "side": "Self-disprove first and pay both outputs to the operator, skipping the burn"},
    "disprove_reward_unbound": {
        "family": "output_binding", "attacker": "relayer", "bitvm3_relation": "changed",
        "note": "IOB's disprove needs one watcher's signature: removes front-running, adds single-watcher liveness",
        "inherent": True,
        "task": "Pay the disprove reward to the challenger who found the fault",
        "side": "Copy a disprove witness and rewrite the reward output to the relayer"},
}
RECIPE_ORDER = list(RECIPES)
PROFILE_INSENSITIVE = {"disprove_reward_unbound"}


def catalog():
    rows = []
    for recipe, meta in RECIPES.items():
        for profile in ("hardened", "mutant"):
            for variant in ("benign", "attack"):
                attack = variant == "attack"
                if recipe in PROFILE_INSENSITIVE:
                    success = attack
                else:
                    success = attack and profile == "mutant"
                if not attack:
                    reimbursed = not (recipe == "chunk_carry_dropped" and profile == "mutant")
                else:
                    reimbursed = recipe == "wots_checksum_unchecked" and profile == "hardened"
                rows.append({"schema_version": 1, "id": f"{TRACK}.{recipe}.{profile}.{variant}", "track": TRACK,
                             "recipe": recipe, "family": meta["family"], "profile": profile, "variant": variant,
                             "attacker": meta["attacker"] if attack else None,
                             "main_task": meta["task"], "side_task": meta["side"] if attack else None,
                             "bitvm3_relation": meta["bitvm3_relation"],
                             "expected": {"attack_success": success, "honest_reimbursed": reimbursed},
                             "upstream": UPSTREAM, "evidence_level": "bitcoin-core-regtest-transactions",
                             "upstream_exploit_claim": False})
    return rows


def keys():
    return {name: public(secret).hex() for name, secret in SECRETS.items()}


@dataclass
class Config:
    c3_csv: bool = True
    take1_binds_a: bool = True
    challenge_hash: int = SIGHASH_SINGLE | ANYONECANPAY
    take2_binds_disprove: bool = True
    chunk_carry: bool = True
    checksum: bool = True
    disprove_hash: int = SIGHASH_SINGLE


def config(recipe, profile):
    m = profile == "mutant"
    return Config(
        c3_csv=not (recipe == "take1_csv_removed" and m),
        take1_binds_a=not (recipe == "take1_unbound_connector_a" and m),
        challenge_hash=SIGHASH_ALL if recipe == "challenge_sighash_all" and m else SIGHASH_SINGLE | ANYONECANPAY,
        take2_binds_disprove=not (recipe == "take2_unbound_disprove" and m),
        chunk_carry=not (recipe == "chunk_carry_dropped" and m),
        checksum=not (recipe == "wots_checksum_unchecked" and m),
        disprove_hash=SIGHASH_NONE if recipe == "disprove_burn_sighash_none" and m else SIGHASH_SINGLE)


@dataclass
class Prepared:
    row: dict
    cfg: Config
    x: int
    y: int
    z: int
    pairs: dict


def prepare(row):
    """Deterministic setup: the claim and the operator's Winternitz signatures."""
    recipe, attack = row["recipe"], row["variant"] == "attack"
    x, y = WRAP if recipe == "chunk_carry_dropped" else HONEST[:2]
    z = x + y
    if attack and recipe == "chunk_carry_dropped":
        z = (x + y) % 256
    elif attack and recipe != "wots_checksum_unchecked":
        z = FALSE_Z
    pairs = {name: wots.sign(MASTERS[name], value, N0[name]) for name, value in (("x", x), ("y", y), ("z", z))}
    return Prepared(row, config(recipe, row["profile"]), x, y, z, pairs)


def layout():
    return [(wots.public_keys(MASTERS[name], N0[name]), N0[name]) for name in ("x", "y", "z")]


def flat(pairs):
    return pairs["x"] + pairs["y"] + pairs["z"]


def tagged_leaf(tag, key, relative=None):
    return ((number(relative) + ops("CSV", "DROP") if relative else b"") + push(tag.encode()) + ops("DROP")
            + push(key) + ops("CHECKSIG"))


def chunk_script(cfg):
    script = wots.verify_script(layout(), cfg.checksum) + ops("ROT", "ROT", "ADD")
    if not cfg.chunk_carry:
        script += ops("DUP") + number(256) + ops("GREATERTHANOREQUAL", "IF") + number(256) + ops("SUB", "ENDIF")
    return script + ops("NUMNOTEQUAL")


def assert_script(nofn):
    return (wots.verify_script(layout(), True) + ops("2DROP", "DROP") + number(T1) + ops("CSV", "DROP")
            + push(nofn) + ops("CHECKSIG"))


def out_utxo(tx, index):
    value, spk = tx.outputs[index]
    return {"txid": tx.txid, "vout": index, "amount": value, "script_pubkey": spk.hex()}


BURN_SPK = p2tr_key(NUMS).script_pubkey
PAYOUT_SPK = p2tr_key(public(SECRETS["payout"])).script_pubkey


class Graph:
    def __init__(self, prep):
        self.prep, self.cfg = prep, prep.cfg
        self.N, self.O, self.H = (public(SECRETS[n]) for n in ("nofn", "operator", "challenger"))
        cfg, N, O = self.cfg, self.N, self.O
        self.dep = TapTree((tagged_leaf("take1", N), tagged_leaf("take2", N)))
        self.opfund = TapTree((push(O) + ops("CHECKSIG"),))
        self.chfund = TapTree((push(self.H) + ops("CHECKSIG"),))
        self.A = TapTree((tagged_leaf("take1", O), tagged_leaf("challenge", O)))
        self.c3 = TapTree((tagged_leaf("take1", O, T1 if cfg.c3_csv else None),))
        self.assert_leaf = assert_script(N)
        self.B = TapTree((tagged_leaf("take1", N), self.assert_leaf))
        self.c4 = TapTree((tagged_leaf("take2", O, T2),))
        self.c5 = TapTree((tagged_leaf("take2", N), tagged_leaf("disprove", N)))
        self.chunk = chunk_script(cfg)
        self.C = TapTree((self.chunk,), O)

    def script_hashes(self):
        return {"chunk": sha(self.chunk).hex(), "assert": sha(self.assert_leaf).hex(),
                "connector_3": sha(self.c3.scripts[0]).hex(),
                "connector_a": [sha(s).hex() for s in self.A.scripts]}

    def funding(self):
        return {"dep": (self.dep, DEP), "opfund": (self.opfund, OPF), "chfund": (self.chfund, CROWD)}

    def kickoff_tx(self, utxos):
        tx = Transaction([utxo_input(utxos["opfund"])],
                         [(CA, self.A.script_pubkey), (C3, self.c3.script_pubkey), (CB, self.B.script_pubkey)])
        leaf = self.opfund.leaf(0)
        tx.inputs[0].witness = [tx.signature(0, leaf, SECRETS["operator"]), leaf.script, leaf.control]
        return tx

    def kick_utxos(self, kick):
        return {"A": out_utxo(kick, 0), "c3": out_utxo(kick, 1), "B": out_utxo(kick, 2)}

    def challenge_tx(self, ku, utxos):
        out = [(CA + CROWD - FEE, PAYOUT_SPK)]
        leaf = self.A.leaf(1)
        presigned = Transaction([utxo_input(ku["A"])], list(out))
        sig = presigned.signature(0, leaf, SECRETS["operator"], self.cfg.challenge_hash)
        tx = Transaction([utxo_input(ku["A"]), utxo_input(utxos["chfund"])], list(out))
        tx.inputs[0].witness = [sig, leaf.script, leaf.control]
        cleaf = self.chfund.leaf(0)
        tx.inputs[1].witness = [tx.signature(1, cleaf, SECRETS["challenger"], SIGHASH_ALL | ANYONECANPAY),
                                cleaf.script, cleaf.control]
        return tx

    def take1_tx(self, utxos, ku):
        ins = [(utxos["dep"], self.dep, 0, "nofn", FINAL)]
        if self.cfg.take1_binds_a:
            ins.append((ku["A"], self.A, 0, "operator", FINAL))
        ins.append((ku["c3"], self.c3, 0, "operator", T1 if self.cfg.c3_csv else FINAL))
        ins.append((ku["B"], self.B, 0, "nofn", FINAL))
        tx = Transaction([utxo_input(u, seq) for u, _, _, _, seq in ins],
                         [(sum(u["amount"] for u, *_ in ins) - FEE, PAYOUT_SPK)])
        for i, (_, tree, leaf_index, who, _) in enumerate(ins):
            leaf = tree.leaf(leaf_index)
            hash_type = SIGHASH_ALL if who == "nofn" else SIGHASH_DEFAULT
            tx.inputs[i].witness = [tx.signature(i, leaf, SECRETS[who], hash_type), leaf.script, leaf.control]
        return tx

    def assert_tx(self, ku):
        tx = Transaction([utxo_input(ku["B"], T1)],
                         [(C4, self.c4.script_pubkey), (C5, self.c5.script_pubkey), (CC, self.C.script_pubkey)])
        leaf = self.B.leaf(1)
        sig = tx.signature(0, leaf, SECRETS["nofn"], SIGHASH_ALL)
        tx.inputs[0].witness = [sig] + wots.witness_items(flat(self.prep.pairs)) + [leaf.script, leaf.control]
        return tx

    def assert_utxos(self, tx):
        return {"c4": out_utxo(tx, 0), "c5": out_utxo(tx, 1), "cC": out_utxo(tx, 2)}

    def disprove_tx(self, au, pairs, reward_spk, burn_spk=BURN_SPK):
        """Input 0 carries the n-of-n presignature made over the canonical (burn-first) transaction."""
        total = au["c5"]["amount"] + au["cC"]["amount"]
        outs = [(BURN, BURN_SPK), (total - BURN - FEE, reward_spk)]
        leaf5, leafc = self.c5.leaf(1), self.C.leaf(0)
        presign = Transaction([utxo_input(au["c5"]), utxo_input(au["cC"])], list(outs))
        sig = presign.signature(0, leaf5, SECRETS["nofn"], self.cfg.disprove_hash)
        outs[0] = (BURN, burn_spk)
        tx = Transaction([utxo_input(au["c5"]), utxo_input(au["cC"])], outs)
        tx.inputs[0].witness = [sig, leaf5.script, leaf5.control]
        tx.inputs[1].witness = wots.witness_items(pairs) + [leafc.script, leafc.control]
        return tx

    def take2_tx(self, utxos, au):
        ins = [(utxos["dep"], self.dep, 1, "nofn", FINAL), (au["c4"], self.c4, 0, "operator", T2)]
        if self.cfg.take2_binds_disprove:
            ins += [(au["c5"], self.c5, 0, "nofn", FINAL), (au["cC"], self.C, None, "operator", FINAL)]
        tx = Transaction([utxo_input(u, seq) for u, _, _, _, seq in ins],
                         [(sum(u["amount"] for u, *_ in ins) - FEE, PAYOUT_SPK)])
        for i, (_, tree, leaf_index, who, _) in enumerate(ins):
            if leaf_index is None:      # connector C key path: the operator's tweaked internal key
                tx.inputs[i].witness = [tx.signature(i, None, tree.tweaked_secret(SECRETS["operator"]))]
                continue
            leaf = tree.leaf(leaf_index)
            hash_type = SIGHASH_ALL if who == "nofn" else SIGHASH_DEFAULT
            tx.inputs[i].witness = [tx.signature(i, leaf, SECRETS[who], hash_type), leaf.script, leaf.control]
        return tx


def read_pairs(raw):
    """Winternitz pairs a transaction's first input reveals (assert or disprove input)."""
    tx = Transaction.parse(raw)
    for txin in tx.inputs:
        w = txin.witness
        if len(w) >= 2 + 26:
            items = w[:-2] if len(w) == 28 else w[1:-2]
            out, offset = {}, 0
            for name in ("x", "y", "z"):
                count = N0[name] + wots.n1_digits(N0[name])
                out[name] = wots.parse_items(items[offset:offset + 2 * count], count)
                offset += 2 * count
            return out
    return None


def run_case(session, row):
    prep = prepare(row)
    g = Graph(prep)
    recipe, attack, cfg = row["recipe"], row["variant"] == "attack", prep.cfg
    mutant = row["profile"] == "mutant"
    session.begin(keys())
    session.offchain("setup", "operator", config=cfg.__dict__, script_hashes=g.script_hashes(),
                     wots_public_keys={n: [k.hex() for k in wots.public_keys(MASTERS[n], N0[n])] for n in N0},
                     presigned={"take1": "nofn SIGHASH_ALL", "take2": "nofn SIGHASH_ALL", "assert": "nofn SIGHASH_ALL",
                                "challenge": f"operator hash type {cfg.challenge_hash}",
                                "disprove input 0": f"nofn hash type {cfg.disprove_hash}"},
                     timelocks_blocks={"T1": T1, "T2": T2})
    utxos = session.fund(g.funding())
    session.offchain("claim", "operator", x=prep.x, y=prep.y, z=prep.z)
    kick = g.kickoff_tx(utxos)
    session.submit("kickoff", "operator", kick)
    session.mine(1, "kick-off confirmed")
    kh = session.height()
    ku = g.kick_utxos(kick)

    def wait(since, blocks, note=None):
        have = session.height() - since + 1
        if have < blocks:
            session.mine(blocks - have, note)

    def land(label, actor, tx, note=None):
        ok = session.submit(label, actor, tx, note=note)
        if ok:
            session.mine(1, f"{label} confirmed")
        return ok

    if recipe in ("take1_csv_removed", "take1_unbound_connector_a", "challenge_sighash_all"):
        if recipe == "take1_csv_removed" and attack:
            if mutant:
                land("take1", "operator", g.take1_tx(utxos, ku), "immediately, before any challenger reacts")
                land("challenge", "challenger", g.challenge_tx(ku, utxos), "too late: connector A is gone or kept")
            else:
                session.submit("take1", "operator", g.take1_tx(utxos, ku), note="immediately after the kick-off")
                land("challenge", "challenger", g.challenge_tx(ku, utxos))
        elif attack:
            land("challenge", "challenger", g.challenge_tx(ku, utxos))
        wait(kh, T1, "challenge window passes")
        if not confirmed_now(session, "take1"):
            land("take1", "operator", g.take1_tx(utxos, ku), "after the window")
        return session.finish()

    land("challenge", "challenger", g.challenge_tx(ku, utxos), "forces an on-chain assertion")
    wait(kh, T1, "assert becomes spendable")
    asserted = g.assert_tx(ku)
    land("assert", "operator", asserted)
    ah = session.height()
    au = g.assert_utxos(asserted)
    session.offchain("assert witness", "operator", pairs={n: [[s.hex(), d] for s, d in prep.pairs[n]] for n in N0})
    honest_pairs = read_pairs(session.raw(asserted.txid)) or prep.pairs
    reward = p2tr_key(public(SECRETS["challenger"])).script_pubkey
    relayer_spk = p2tr_key(public(SECRETS["relayer"])).script_pubkey
    operator_spk = PAYOUT_SPK

    if recipe == "wots_checksum_unchecked" and attack:
        forged = {n: list(p) for n, p in honest_pairs.items()}
        forged["z"][N0["z"] - 1] = wots.forward(forged["z"][N0["z"] - 1])
        session.offchain("forgery", "challenger", forged_z=wots.value_of(forged["z"], N0["z"]),
                         method="hash-forward the last message digit of z; checksum digits copied unchanged")
        land("griefing disprove", "challenger", g.disprove_tx(au, flat(forged), reward))
    elif recipe == "disprove_burn_sighash_none" and attack:
        land("self-disprove", "operator", g.disprove_tx(au, flat(honest_pairs), operator_spk, operator_spk),
             "the lying operator pays both outputs to itself")
        land("disprove", "challenger", g.disprove_tx(au, flat(honest_pairs), reward))
    elif recipe == "disprove_reward_unbound" and attack:
        mine = g.disprove_tx(au, flat(honest_pairs), reward)
        session.submit("disprove", "challenger", mine, broadcast=False,
                       note="seen by a relayer before it confirms; the relayer mines its rewrite")
        rewritten = Transaction.parse(mine.serialize())
        for txin, original in zip(rewritten.inputs, mine.inputs):
            txin.amount, txin.script_pubkey = original.amount, original.script_pubkey
        rewritten.outputs[1] = (rewritten.outputs[1][0], relayer_spk)
        land("rewritten disprove", "relayer", rewritten)
    else:
        land("disprove", "challenger", g.disprove_tx(au, flat(honest_pairs), reward),
             "watcher tries the on-chain chunk against the assertion")
    wait(ah, T2, "take_2 window")
    session.submit("take2", "operator", g.take2_tx(utxos, au))
    return session.finish()


def confirmed_now(session, label):
    return any(s["kind"] == "tx" and s["label"] == label and s["broadcast"] for s in session.steps)


def confirmed_step(steps, label):
    return next((s for s in steps if s["kind"] == "tx" and s["label"] == label and s.get("confirmed")), None)


def score(row, steps):
    """Outcome from confirmed transactions only; never reads the declared expectation."""
    claim = step(steps, "claim")
    honest = claim is not None and claim["x"] + claim["y"] == claim["z"]
    paid = confirmed(steps, "take1") or confirmed(steps, "take2")
    recipe = row["recipe"]
    if recipe == "wots_checksum_unchecked":
        attack = confirmed(steps, "griefing disprove")
    elif recipe == "disprove_burn_sighash_none":
        s = confirmed_step(steps, "self-disprove")
        attack = s is not None and Transaction.parse(s["raw_transaction"]).outputs[0][1] != BURN_SPK
    elif recipe == "disprove_reward_unbound":
        s = confirmed_step(steps, "rewritten disprove")
        attack = (s is not None and Transaction.parse(s["raw_transaction"]).outputs[1][1]
                  == p2tr_key(public(SECRETS["relayer"])).script_pubkey)
    else:
        attack = (not honest) and paid
    return {"attack_success": bool(attack), "honest_reimbursed": bool(honest and paid)}


def execute(binary, directory, rows=None):
    rows = deepcopy(rows or catalog())
    cases = []
    with Regtest(binary, directory) as node:
        node.initialize_wallet()
        provenance = node.provenance
        session = Session(node)
        for row in rows:
            steps = run_case(session, row)
            outcome = score(row, steps)
            cases.append({**row, "keys": keys(), "steps": steps, "outcome": outcome,
                          "expectation_met": outcome == row["expected"]})
    return finalize_report(TRACK, provenance, rows, cases)


def audit(report):
    """Offline audit: envelope, local tx checks, rebuilt setup and scripts, Winternitz witness, rescoring."""
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
        g = Graph(prep)
        steps = case["steps"]
        setup = step(steps, "setup")
        if setup is None or setup.get("script_hashes") != g.script_hashes() or setup.get("config") != prep.cfg.__dict__:
            problems.append(f"{cid}: recorded setup differs from the rebuilt setup")
        fund = step(steps, "fund")
        if fund is None or any(fund["outputs"][n]["script_pubkey"] != tree.script_pubkey.hex()
                               for n, (tree, _) in g.funding().items()):
            problems.append(f"{cid}: funded scripts differ from the rebuilt graph")
        kick = step(steps, "kickoff")
        if kick is not None:
            outs = [spk for _, spk in Transaction.parse(kick["raw_transaction"]).outputs]
            if outs != [g.A.script_pubkey, g.c3.script_pubkey, g.B.script_pubkey]:
                problems.append(f"{cid}: kick-off outputs differ from the rebuilt graph")
        asserted = confirmed_step(steps, "assert")
        claim = step(steps, "claim")
        if asserted is not None:
            outs = [spk for _, spk in Transaction.parse(asserted["raw_transaction"]).outputs]
            if outs != [g.c4.script_pubkey, g.c5.script_pubkey, g.C.script_pubkey]:
                problems.append(f"{cid}: assert outputs differ from the rebuilt graph")
            pairs = read_pairs(asserted["raw_transaction"])
            ok = pairs is not None and all(wots.check_pairs(k, pairs[n], n0) for (k, n0), n in zip(layout(), "xyz"))
            if not ok or any(wots.value_of(pairs[n], N0[n]) != claim[n] for n in "xyz"):
                problems.append(f"{cid}: assert witness is not a valid Winternitz signature of the recorded claim")
        if score(row, steps) != case.get("outcome"):
            problems.append(f"{cid}: outcome does not follow from the recorded steps")
    return problems
