"""One party of the BitVM3 setup ceremony, run as its own operating-system process.

`python -m bitvm_corpus.party` reads one JSON request per line on stdin and answers one
JSON line on stdout. The hub (ceremony.py) starts one such process per role, locally, in
WSL or over SSH on another machine, and is the only thing a party talks to: it relays the
protocol messages and records them. Each process holds its own secret and nothing else.
Two colluding parties share a pre-agreed covert key, and everything they coordinate
during the ceremony travels inside the honest protocol messages (stego.py).

Roles: `garbler` (the claimant: it garbles the statement circuit and later claims),
`desk` (presigns the claim graph), `guardian` (an independent cosigner; in some designs
also a second evaluator), `watch` (evaluates the claim and disproves) and `relay` (the
link that carries the watcher's traffic).

The ceremony, in order: hello (keys, nonces, challenge commitments), commit (k garbling
commitments), challenge (the kept index), open (seeds of the other instances, the kept
instance's registration), tables (to evaluators), ack (each checker's verdict, signed),
presign, then the claim phase.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
from types import SimpleNamespace

from . import gc, stego
from .bitcoin import SIGHASH_DEFAULT, TapTree, Transaction, bit_opening, number, ops, push, public, sign, verify_signature
from .bitvm3 import FALSE_PROOF, HONEST_PROOF, Config, Graph, Stage, commit, published, tables_commitment
from .canonical import ValidationError, canonical
from .track import utxo_input

ROLES = ("garbler", "desk", "guardian", "watch", "relay")
STAGE_NAME = {"garbler": "claimant", "desk": "desk", "guardian": "guardian", "watch": "watch"}
VIEW_KINDS = ("hello", "commit", "challenge", "open")
ACK_TAG = b"bitvm-arena/setup/ack\x00"


def h(*parts):
    digest = hashlib.sha256(b"bitvm-arena/setup")
    for part in parts:
        data = part if isinstance(part, bytes) else str(part).encode()
        digest.update(len(data).to_bytes(4, "big") + data)
    return digest.digest()


def kept_index(plan, commitments, challenges):
    """The kept instance. `challenges` maps role -> challenge content."""
    body = "".join(commitments).encode()
    if plan["challenge"] == "desk":
        draw = bytes.fromhex(challenges["desk"]["draw"])
        return int.from_bytes(h("challenge", draw, body), "big") % plan["k"]
    reveals = b"".join(bytes.fromhex(challenges[r]["reveal"]) for r in ("desk", "guardian"))
    return int.from_bytes(h("challenge", reveals, body), "big") % plan["k"]


def ack_digest(ack):
    body = {k: v for k, v in ack.items() if k != "sig"}
    return hashlib.sha256(ACK_TAG + canonical(body).encode()).digest()


class SetupGraph(Graph):
    """The BitVM3 claim graph built from public setup data alone. With a guardian cosigner
    the vault's claim leaf is <D> CHECKSIGVERIFY <A> CHECKSIGVERIFY <C> CHECKSIG."""

    def __init__(self, plan, keys, registration):
        cfg = Config(labels_onchain=plan["labels_onchain"], disprove_mode=plan["disprove_mode"]).check()
        stage = Stage({name: bytes.fromhex(key) for name, key in keys.items()})
        prep = SimpleNamespace(row={"id": plan["case"]}, cfg=cfg, public=dict(registration), desk_presigns=True,
                               statement=registration["statement"], index=0, stage=stage, garbling=None)
        super().__init__(prep)
        self.cosigned = plan["claim_cosigner"] == "guardian"
        self.A = stage.keys["guardian"]
        claim = push(self.D) + ops("CHECKSIGVERIFY")
        if self.cosigned:
            claim += push(self.A) + ops("CHECKSIGVERIFY")
        claim += push(self.C) + ops("CHECKSIG")
        if cfg.labels_onchain:
            claim = b"".join(bit_opening(bytes.fromhex(h0), bytes.fromhex(h1)) + ops("DROP")
                             for h0, h1 in registration["input_label_sha256"]) + claim
        reclaim = number(cfg.reclaim) + ops("CSV", "DROP") + push(self.D) + ops("CHECKSIG")
        self.V = TapTree((claim, reclaim))

    def claim_unsigned(self, vault, outputs=None):
        return Transaction([utxo_input(vault, 0xffffffff)], list(outputs) if outputs is not None
                           else self.claim_outputs())

    def sign_claim(self, tx, sig_c, sig_a, sig_d, labels=()):
        leaf = self.V.leaf(0)
        stack = [sig_c] + ([sig_a] if self.cosigned else []) + [sig_d]
        if self.cfg.labels_onchain:
            stack += list(reversed(labels))
        tx.inputs[0].witness = stack + [leaf.script, leaf.control]
        return tx

    def k_outpoint(self, claim_txid):
        return {"txid": claim_txid, "vout": 0, "amount": self.k_value, "script_pubkey": self.K.script_pubkey.hex()}

    def payout_unsigned(self, claim_txid):
        return Transaction([utxo_input(self.k_outpoint(claim_txid), self.cfg.window)],
                           [(self.k_value - self.fee, self.payout_spk)])

    def disprove_unsigned(self, claim_txid, outputs=None):
        return Transaction([utxo_input(self.k_outpoint(claim_txid))],
                           list(outputs) if outputs is not None else [(self.k_value - self.fee, self.refund_spk)])

    def labels_in(self, claim_raw):
        witness = Transaction.parse(claim_raw).inputs[0].witness
        signatures = 3 if self.cosigned else 2
        return list(reversed(witness[signatures:-2]))


def sighash(tx, leaf):
    return tx.sighash(0, leaf, SIGHASH_DEFAULT)


def wire_tx(label, tx, **extra):
    return {"label": label, "raw": tx.serialize().hex(), "txid": tx.txid,
            "prevouts": [{"txid": i.txid, "vout": i.vout, "amount": i.amount, "script_pubkey": i.script_pubkey.hex()}
                         for i in tx.inputs], **extra}


class Party:
    def __init__(self, init):
        self.role = init["role"]
        if self.role not in ROLES:
            raise ValidationError("unknown role")
        self.plan = init["plan"]
        self.session = self.plan["case"]
        self.secret = int(init["secret"], 16) if init.get("secret") else None
        self.key = public(self.secret).hex() if self.secret else None
        covert = init.get("covert")
        self.covert = bytes.fromhex(covert["key"]) if covert else None
        self.recipe = self.plan["recipe"]
        self.inbox = []          # [{"from", "kind", "text", "content"}]
        self.notes = []
        self.state = {}

    # --- helpers ---------------------------------------------------------------------

    def ctx(self, purpose):
        return f"{self.session}|{purpose}"

    def nonce(self, kind):
        seed = self.secret.to_bytes(32, "big") if self.secret else self.role.encode()
        return h("nonce", seed, self.session, kind)[:16].hex()

    def own(self, label):
        return h(label, self.secret.to_bytes(32, "big"), self.session)

    def note(self, event, **data):
        self.notes.append({"event": event, **data})

    def message(self, obj, to="all", text=None):
        return {"to": to, "kind": obj["kind"], "text": text if text is not None else canonical(obj)}

    def latest(self, kind, sender=None):
        for entry in reversed(self.inbox):
            if entry["kind"] == kind and (sender is None or entry["from"] == sender):
                return entry
        return None

    def keys(self):
        found = {STAGE_NAME[e["from"]]: e["content"]["key"] for e in self.inbox
                 if e["kind"] == "hello" and e["from"] in STAGE_NAME}
        found.update(self.plan["keys"])
        return found

    def challenges(self):
        return {e["from"]: e["content"] for e in self.inbox if e["kind"] == "challenge"}

    def view(self):
        latest = {}
        for e in self.inbox:
            if e["kind"] in VIEW_KINDS:
                latest[(VIEW_KINDS.index(e["kind"]), e["from"])] = e["content"]
        return hashlib.sha256(canonical([latest[k] for k in sorted(latest)]).encode()).hexdigest()

    def graph(self):
        opened = self.latest("open", "garbler")
        return SetupGraph(self.plan, self.keys(), opened["content"]["registration"])

    # --- request dispatch ------------------------------------------------------------

    def handle(self, op, request):
        self.notes = []
        if op == "deliver":
            m = request["message"]
            self.inbox.append({"from": m["from"], "kind": m["kind"], "text": m["text"],
                               "content": stego.content(m["text"])})
            result = {}
        elif op == "act":
            result = {"messages": getattr(self, "act_" + request["phase"])(request)}
        elif op == "relay":
            result = {"text": self.relay(request["message"])}
        elif op in ("claim", "evaluate"):
            result = getattr(self, op)(request)
        else:
            raise ValidationError(f"unknown op {op}")
        return {"result": result, "notes": self.notes}

    # --- hello -------------------------------------------------------------------------

    def act_hello(self, _):
        obj = {"kind": "hello", "from": self.role, "session": self.session, "key": self.key,
               "nonce": self.nonce("hello")}
        if self.plan["challenge"] == "joint" and self.role in ("desk", "guardian"):
            obj["challenge_commit"] = hashlib.sha256(self.own("reveal")).hexdigest()
        if self.role == "watch" and self.covert and self.recipe == "setup_watcher_key_leaked":
            obj["nonce"] = stego.salt(self.secret.to_bytes(32, "big")[:16], self.covert, self.ctx("hello"))
            self.note("covert_send", channel="salt", message="hello", payload_bits=128,
                      payload="first half of the watcher's secret key")
        return [self.message(obj)]

    # --- garbler: commit, open ---------------------------------------------------------

    def instances(self):
        if "instances" not in self.state:
            plan = self.plan
            seeds = [self.own(f"garbling/{i}")[:16] for i in range(plan["k"])]
            garblings = [gc.garble(plan["statement"], s) for s in seeds]
            bad = set()
            if self.covert and self.recipe == "setup_cut_and_choose_coordinated":
                # The garbler picks its bad instance before anyone draws. Under the joint draw it
                # is kept with probability 1/k; this fixture's tag records a caught draw.
                bad = {int.from_bytes(self.own("bad-instance/1"), "big") % plan["k"]}
            datas = [published(g, swapped=i in bad) for i, g in enumerate(garblings)]
            salts = [self.own(f"salt/{i}")[:16] for i in range(plan["k"])]
            self.state["instances"] = (seeds, garblings, datas, salts, bad)
        return self.state["instances"]

    def act_commit(self, _):
        seeds, garblings, datas, salts, bad = self.instances()
        obj = {"kind": "commit", "from": "garbler", "session": self.session, "nonce": self.nonce("commit"),
               "statement": self.plan["statement"], "k": self.plan["k"],
               "commitments": [commit(salts[i], datas[i]) for i in range(self.plan["k"])]}
        text = None
        if self.covert and self.recipe == "setup_cut_and_choose_coordinated":
            (m,) = bad
            text = stego.embed_case(obj, stego.int_bits(m, 2), self.covert, self.ctx("bad-instance"))
            self.note("covert_send", channel="case", message="commit", payload_bits=2,
                      payload="index of the instance with the swapped decoding")
        if self.covert and self.recipe == "setup_transcript_equivocated":
            text = stego.embed_format(obj, [1], self.covert, self.ctx("go"))
            self.note("covert_send", channel="format", message="commit", payload_bits=1,
                      payload="substitute the watcher's copy of the registration")
        self.state["commitments"] = obj["commitments"]
        return [self.message(obj, text=text)]

    def registration(self, data):
        reg = {"statement": self.plan["statement"], "ciphertext_commitment": data["ciphertext_commitment"],
               "accept_label_sha256": data["accept_label_sha256"], "reject_label_sha256": data["reject_label_sha256"]}
        if self.plan["labels_onchain"]:
            reg["input_label_sha256"] = data["input_label_sha256"]
        return reg

    def act_open(self, _):
        seeds, garblings, datas, salts, bad = self.instances()
        kept = kept_index(self.plan, self.state["commitments"], self.challenges())
        self.state["kept"] = kept
        obj = {"kind": "open", "from": "garbler", "session": self.session, "nonce": self.nonce("open"), "kept": kept,
               "opened": {str(i): seeds[i].hex() for i in range(self.plan["k"]) if i != kept},
               "salts": [s.hex() for s in salts], "registration": self.registration(datas[kept])}
        out = [self.message(obj)]
        tables = [[tg.hex(), te.hex()] for tg, te in garblings[kept].tables]
        for evaluator in self.plan["evaluators"]:
            out.append(self.message({"kind": "tables", "from": "garbler", "session": self.session,
                                     "nonce": self.nonce(f"tables/{evaluator}"), "to": evaluator, "tables": tables},
                                    to=evaluator))
        if bad:
            self.note("decision", kept=kept, bad=sorted(bad), kept_is_bad=kept in bad,
                      escape_probability=f"1/{self.plan['k']}" if self.plan["challenge"] == "joint" else "1")
        return out

    # --- challengers -------------------------------------------------------------------

    def act_challenge(self, _):
        commitments = self.latest("commit", "garbler")["content"]["commitments"]
        obj = {"kind": "challenge", "from": self.role, "session": self.session, "nonce": self.nonce("challenge")}
        target, attempts = None, 0
        if self.covert and self.recipe == "setup_cut_and_choose_coordinated":
            got = stego.extract_case(self.latest("commit", "garbler")["text"], self.covert, self.ctx("bad-instance"), 2)
            self.note("covert_receive", channel="case", message="commit", decoded=got is not None,
                      value=None if got is None else stego.bits_int(got))
            target = None if got is None else stego.bits_int(got)
        if self.plan["challenge"] == "joint":
            obj["reveal"] = self.own("reveal").hex()
            if target is not None:
                self.note("decision", steer="impossible", reason="the reveal was committed before the commitments")
            return [self.message(obj)]
        while True:
            draw = self.own(f"draw/{attempts}")
            kept = kept_index(self.plan, commitments, {"desk": {"draw": draw.hex()}})
            if target is None or kept == target:
                break
            attempts += 1
        if target is not None:
            self.note("decision", ground_draws=attempts + 1, kept=kept)
        obj.update(draw=draw.hex(), kept=kept)
        return [self.message(obj)]

    # --- checks ------------------------------------------------------------------------

    def checks(self):
        plan, results = self.plan, {}
        commit_msg = self.latest("commit", "garbler")["content"]
        opened = self.latest("open", "garbler")["content"]
        commitments = commit_msg["commitments"]
        if self.role in ("desk", "guardian"):
            try:
                kept = kept_index(plan, commitments, self.challenges())
            except (KeyError, ValueError):
                kept = None
            reveals_ok = True
            if plan["challenge"] == "joint":
                for r in ("desk", "guardian"):
                    hello = self.latest("hello", r)["content"]
                    reveal = self.challenges().get(r, {}).get("reveal", "")
                    reveals_ok &= hashlib.sha256(bytes.fromhex(reveal)).hexdigest() == hello.get("challenge_commit")
            results["challenge"] = reveals_ok and kept == opened["kept"]
            good = True
            for i, seed in opened["opened"].items():
                data = published(gc.garble(plan["statement"], bytes.fromhex(seed)))
                good &= commit(bytes.fromhex(opened["salts"][int(i)]), data) == commitments[int(i)]
            results["openings"] = good and len(opened["opened"]) == plan["k"] - 1
            reg = opened["registration"]
            results["kept_commitment"] = commit(bytes.fromhex(opened["salts"][opened["kept"]]), reg) \
                == commitments[opened["kept"]]
        if self.role in plan["evaluators"]:
            tables = self.latest("tables", "garbler")
            results["tables"] = tables is not None and tables_commitment(
                [(bytes.fromhex(a), bytes.fromhex(b)) for a, b in tables["content"]["tables"]]) \
                == opened["registration"]["ciphertext_commitment"]
        return results

    def act_check(self, _):
        results = self.checks()
        ok = all(results.values())
        if self.covert and self.role == "desk":
            self.note("decision", own_checks=results, reported_ok=True)
            ok = True
        obj = {"kind": "ack", "from": self.role, "session": self.session, "nonce": self.nonce("ack"),
               "ok": ok, "checks": results}
        if self.plan["transcript_binding"] == "agreed":
            obj["view"] = self.view()
        if self.role == "watch" and self.covert and self.recipe == "setup_watcher_key_leaked":
            obj["nonce"] = stego.salt(self.secret.to_bytes(32, "big")[16:], self.covert, self.ctx("ack"))
            self.note("covert_send", channel="salt", message="ack", payload_bits=128,
                      payload="second half of the watcher's secret key")
        obj["sig"] = sign(ack_digest(obj), self.secret).hex()
        self.state["checks"] = results
        return [self.message(obj)]

    # --- presign -----------------------------------------------------------------------

    def agreement(self):
        """Every checker's signed ack is present, says ok, and saw the same transcript."""
        mine = self.view()
        for role in ("desk", "guardian", "watch"):
            entry = self.latest("ack", role)
            if entry is None:
                return False, f"no ack from {role}"
            ack = entry["content"]
            key = bytes.fromhex(self.latest("hello", role)["content"]["key"])
            if not verify_signature(ack_digest(ack), key, bytes.fromhex(ack.get("sig", ""))):
                return False, f"{role}'s ack signature is invalid"
            if not ack.get("ok"):
                return False, f"{role} reported a failed check"
            if ack.get("view") != mine:
                return False, f"{role} saw a different setup transcript"
        return True, None

    def act_presign(self, request):
        graph = self.graph()
        vault = request["vault"]
        claim = graph.claim_unsigned(vault)
        obj = {"kind": "presign", "from": self.role, "session": self.session, "nonce": self.nonce("presign"),
               "claim": None, "payout": None, "disprove": None, "refused": None}
        reason = None
        if not (self.covert and self.role == "desk"):
            failed = [name for name, ok in self.checks().items() if not ok]
            if failed:
                reason = "failed checks: " + ", ".join(failed)
            elif self.plan["transcript_binding"] == "agreed":
                _, reason = self.agreement()
        if reason:
            obj["refused"] = reason
            self.note("decision", presign="refused", reason=reason)
            return [self.message(obj)]
        claim_hash = sighash(claim, graph.V.leaf(0))
        if self.role == "desk" and self.covert and self.recipe == "setup_desk_key_exfiltrated":
            obj["claim"] = stego.klepto_sign(claim_hash, self.secret, self.covert).hex()
            self.note("covert_send", channel="klepto_nonce", message="presign", payload_bits=256,
                      payload="the desk's presigning key, through the claim presignature's nonce")
        else:
            obj["claim"] = sign(claim_hash, self.secret).hex()
        if self.role == "desk":
            obj["payout"] = sign(sighash(graph.payout_unsigned(claim.txid), graph.K.leaf(0)), self.secret).hex()
            if self.plan["disprove_mode"] == "presigned":
                obj["disprove"] = sign(sighash(graph.disprove_unsigned(claim.txid), graph.K.leaf(1)), self.secret).hex()
        return [self.message(obj)]

    # --- relay -------------------------------------------------------------------------

    def relay(self, m):
        """Forward one message on the watcher's link. A colluding relay substitutes the
        watcher's copy of the registration and tables, then signals the garbler."""
        text = m["text"]
        if not (self.covert and self.recipe == "setup_transcript_equivocated"):
            return text
        if m["kind"] == "commit" and m["from"] == "garbler":
            got = stego.extract_format(text, self.covert, self.ctx("go"), 1)
            self.state["go"] = got == [1]
            self.note("covert_receive", channel="format", message="commit", decoded=got is not None,
                      value=None if got is None else got[0])
        elif m["kind"] in ("open", "tables") and m["from"] == "garbler" and self.state.get("go"):
            if "substitute" not in self.state:
                plan = self.plan
                self.state["substitute"] = gc.garble(plan["statement"], h("relay-garbling", self.session)[:16])
            other = self.state["substitute"]
            obj = stego.content(text)
            if m["kind"] == "open":
                data = published(other)
                for name in ("ciphertext_commitment", "accept_label_sha256", "reject_label_sha256"):
                    obj["registration"][name] = data[name]
                if "input_label_sha256" in obj["registration"]:
                    obj["registration"]["input_label_sha256"] = data["input_label_sha256"]
            else:
                obj["tables"] = [[tg.hex(), te.hex()] for tg, te in other.tables]
            self.state["substituted"] = True
            self.note("decision", substituted=m["kind"], to="watch")
            return canonical(obj)
        elif m["kind"] == "ack" and m["from"] == "watch" and self.state.get("substituted"):
            text = stego.embed_order(stego.content(text), [1], self.covert, self.ctx("done"))
            self.note("covert_send", channel="order", message="ack (watch, relayed)", payload_bits=1,
                      payload="the watcher holds the substituted registration")
        return text

    # --- claim phase -------------------------------------------------------------------

    def presigs(self):
        return {r: (self.latest("presign", r) or {}).get("content", {}) for r in ("desk", "guardian")}

    def recovered_desk_key(self, graph, claim):
        sig = self.presigs()["desk"].get("claim")
        if not sig:
            return None
        return stego.klepto_extract(sighash(claim, graph.V.leaf(0)), bytes.fromhex(sig), graph.D, self.covert)

    def recovered_watch_key(self, graph):
        hello, ack = self.latest("hello", "watch"), self.latest("ack", "watch")
        if hello is None or ack is None:
            return None
        data = (stego.unsalt(hello["content"]["nonce"], self.covert, self.ctx("hello"))
                + stego.unsalt(ack["content"]["nonce"], self.covert, self.ctx("ack")))
        secret = int.from_bytes(data, "big")
        return secret if 0 < secret and public(secret) == graph.W else None

    def canonical_claim(self, graph, vault, proof):
        _, garblings, _, _, _ = self.instances()
        labels = garblings[self.state["kept"]].input_labels(gc.proof_bits(*proof))
        tx = graph.claim_unsigned(vault)
        digest = sighash(tx, graph.V.leaf(0))
        presigs = self.presigs()
        own = sign(digest, self.secret)

        def slot(value):
            # Without a presignature the claimant can only put its own signature in the slot.
            return bytes.fromhex(value) if value else own
        graph.sign_claim(tx, own, slot(presigs["guardian"].get("claim")), slot(presigs["desk"].get("claim")), labels)
        return tx, labels

    def claim(self, request):
        graph = self.graph()
        vault = request["vault"]
        recipe, attack = self.recipe, self.covert is not None
        proof = FALSE_PROOF if attack else HONEST_PROOF
        steps, messages = [], []
        _, garblings, _, _, _ = self.instances()
        kept = garblings[self.state["kept"]]

        def handover(labels):
            if self.plan["labels_onchain"]:
                return
            for evaluator in self.plan["evaluators"]:
                messages.append(self.message({"kind": "labels", "from": "garbler", "session": self.session,
                                              "nonce": self.nonce(f"labels/{evaluator}"), "to": evaluator,
                                              "labels": [x.hex() for x in labels]}, to=evaluator))

        if not attack:
            tx, labels = self.canonical_claim(graph, vault, proof)
            steps.append(wire_tx("claim", tx, proof=list(proof), mine_after=1))
            handover(labels)
        elif recipe == "setup_desk_key_exfiltrated":
            d = self.recovered_desk_key(graph, graph.claim_unsigned(vault))
            self.note("covert_receive", channel="klepto_nonce", message="presign", decoded=d is not None,
                      value="recovered key matches the desk's public key" if d else None)
            if d is None:
                self.note("decision", claim="none", reason="no desk key: a false claim would be disproven")
                return {"proof": None, "steps": [], "messages": []}
            theft = graph.claim_unsigned(vault, [(graph.stage.vault - graph.fee, graph.payout_spk)])
            digest = sighash(theft, graph.V.leaf(0))
            guardian = self.presigs()["guardian"].get("claim")
            own = sign(digest, self.secret)
            graph.sign_claim(theft, own, bytes.fromhex(guardian) if guardian else own, sign(digest, d))
            steps.append(wire_tx("rewritten claim", theft, proof=list(proof), mine_after=1, stop_if_rejected=True,
                                 note="signed with the desk key recovered from its presignature"))
        elif recipe == "setup_watcher_key_leaked":
            w = self.recovered_watch_key(graph)
            self.note("covert_receive", channel="salt", message="hello+ack", decoded=w is not None,
                      value="recovered key matches the watcher's public key" if w else None)
            if w is None and self.plan["disprove_mode"] == "watcher":
                self.note("decision", claim="none", reason="no watcher key")
                return {"proof": None, "steps": [], "messages": []}
            tx, labels = self.canonical_claim(graph, vault, proof)
            steps.append(wire_tx("claim", tx, proof=list(proof), mine_after=1))
            steal = [(graph.k_value - graph.fee, graph.payout_spk)]
            theft = graph.disprove_unsigned(tx.txid, steal)
            leaf = graph.K.leaf(1)
            if self.plan["disprove_mode"] == "watcher":
                signature = sign(sighash(theft, leaf), w)
                note = "signed with the watcher key recovered from its nonces"
            else:
                signature = bytes.fromhex(self.presigs()["desk"]["disprove"])
                note = "the desk's presigned disprove with its outputs replaced"
            theft.inputs[0].witness = [signature, kept.reject_label, leaf.script, leaf.control]
            steps.append(wire_tx("self-pay disprove", theft, mine_after=1, note=note))
            handover(labels)
        elif recipe == "setup_cut_and_choose_coordinated":
            # The claim needs both presignatures. The cosigner signs only if every opened
            # instance regarbles, which holds exactly when the desk kept the bad instance.
            _, _, _, _, bad = self.instances()
            self.note("decision", claim="false", kept_is_bad=self.state["kept"] in bad)
            tx, labels = self.canonical_claim(graph, vault, proof)
            steps.append(wire_tx("claim", tx, proof=list(proof), mine_after=1))
            handover(labels)
        elif recipe == "setup_transcript_equivocated":
            ack = self.latest("ack", "watch")
            got = None if ack is None else stego.extract_order(ack["text"], self.covert, self.ctx("done"), 1)
            self.note("covert_receive", channel="order", message="ack (watch, relayed)", decoded=got is not None,
                      value=None if got is None else got[0])
            if got != [1]:
                self.note("decision", claim="none", reason="no signal that the watcher's copy was substituted")
                return {"proof": None, "steps": [], "messages": []}
            tx, labels = self.canonical_claim(graph, vault, proof)
            steps.append(wire_tx("claim", tx, proof=list(proof), mine_after=1))
            handover(labels)
        else:
            raise ValidationError("unknown recipe")
        return {"proof": list(proof), "steps": steps, "messages": messages}

    def evaluate(self, request):
        """Evaluate the confirmed claim with the labels and tables this party holds."""
        opened = self.latest("open", "garbler")["content"]
        reg = opened["registration"]
        graph = SetupGraph(self.plan, self.keys(), reg)
        if self.plan["labels_onchain"]:
            labels, source = graph.labels_in(request["claim_raw"]), "claim witness"
        else:
            entry = self.latest("labels", "garbler")
            labels = None if entry is None else [bytes.fromhex(x) for x in entry["content"]["labels"]]
            source = "handover"
        tables_entry = self.latest("tables", "garbler")
        tables = [(bytes.fromhex(a), bytes.fromhex(b)) for a, b in tables_entry["content"]["tables"]]
        result = {"labels": None, "labels_source": source, "tables_commitment": tables_commitment(tables),
                  "output_label": None, "verdict": "no labels", "disprove": None}
        if labels is None:
            return result
        out = gc.evaluate(reg["statement"], tables, labels)
        verdict = gc.decode(out, reg["accept_label_sha256"], reg["reject_label_sha256"])
        result.update(labels=[x.hex() for x in labels], output_label=out.hex(), verdict=verdict)
        if verdict != "reject":
            return result
        if self.covert:
            self.note("decision", disprove="withheld")
            return result
        claim_txid = Transaction.parse(request["claim_raw"]).txid
        tx = graph.disprove_unsigned(claim_txid)
        leaf = graph.K.leaf(1)
        if self.plan["disprove_mode"] == "watcher":
            if self.role != "watch":
                self.note("decision", disprove="impossible", reason="only W's signature opens the disprove leaf")
                return result
            signature = sign(sighash(tx, leaf), self.secret)
        else:
            presig = self.presigs()["desk"].get("disprove")
            if not presig:
                return result
            signature = bytes.fromhex(presig)
        tx.inputs[0].witness = [signature, out, leaf.script, leaf.control]
        result["disprove"] = wire_tx("disprove", tx)
        return result


# --- process side ----------------------------------------------------------------------

def host_identity():
    """Distinguishes machines (and WSL from its Windows host) without naming them."""
    machine_id = ""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path, encoding="ascii") as handle:
                machine_id = handle.read().strip()
            break
        except OSError:
            continue
    basis = "|".join((platform.node(), platform.system(), platform.release(), platform.machine(), machine_id))
    return {"host_id": hashlib.sha256(basis.encode()).hexdigest()[:16], "pid": os.getpid(),
            "system": platform.system(), "python": platform.python_version()}


def serve(stdin, stdout):
    party = None
    while True:
        line = stdin.readline()
        if not line:
            return 0
        try:
            request = json.loads(line)
            op = request.get("op")
            if op == "init":
                party = Party(request)
                reply = {"ok": True, "result": {"role": party.role, "key": party.key, **host_identity()}, "notes": []}
            elif op == "shutdown":
                stdout.write(b'{"ok": true, "result": {}, "notes": []}\n')
                stdout.flush()
                return 0
            elif party is None:
                raise ValidationError("init first")
            else:
                reply = {"ok": True, **party.handle(op, request)}
        except Exception as exc:  # the hub records the failure; the party keeps serving
            reply = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        stdout.write((json.dumps(reply) + "\n").encode())
        stdout.flush()


if __name__ == "__main__":
    sys.exit(serve(sys.stdin.buffer, sys.stdout.buffer))
