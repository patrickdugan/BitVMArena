"""Interactive red-team episodes on the BitVM3 claim graph.

The fixed catalog in `bitvm3.py` replays scripted trajectories. An episode lets an
attacker (an LLM agent or a script) drive the claimant of one BitVM3-dependent
application preset through a closed set of JSON actions. Bitcoin Core judges every
transaction. Honest parties (the watcher) react by the same rules `run_case` uses. The
scorer reads confirmed transactions only, and `audit_episode` rebuilds the setup and
re-checks the recorded evidence offline.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import fields

from . import gc
from .bitcoin import P2A, Transaction, TapTree, p2tr_key
from .bitvm3 import (BOND, BURN_SPK, CENSOR, FEE, HARDENED_WINDOW, SECRETS, STATEMENT, VAULT, WATCH_FUNDS, Config,
                     Graph, claimant_scripts, evaluator_tables, keys, labels_from_claim, prepare, rewrite,
                     setup_record, spk_of, tables_commitment)
from .canonical import ValidationError, digest, integer
from .core import CoreError, Regtest, safe_json
from .track import SATS, Session, audit_transactions, step, utxo_input

KIND = "bitvm3-episode"
MAX_ACTIONS, MAX_BLOCKS, MAX_OUTPUTS, MAX_HEX = 200, 500, 16, 200_000
ASSUMPTIONS = {"watcher_online": True, "watcher_latency": 1, "desk_online": True, "censorship_blocks": CENSOR}
DESTINATIONS = ("claimant", "payout", "refund", "relayer", "watch", "burn")

APPS = {
    "iob-payout-desk": {
        "description": "The In-and-Out-Burger payout desk as built: the desk presigns the claim and the payout, "
                       "the claimant garbles the statement circuit and hands the watcher its input labels "
                       "off-chain, the watcher signs the disprove, the challenge window is 6 blocks, and the "
                       "claimant posts no bond.",
        "config": {},
        "assumptions": {"watcher_online": True, "watcher_latency": 1, "desk_online": True,
                        "censorship_blocks": CENSOR}},
    "bridge-pegout": {
        "description": "Operator reimbursement from a bridge vault: the operator posts a bond that is burned if "
                       "its claim is disproven, input labels are revealed in the claim witness, the disprove is "
                       "presigned by the desk, the instance is chosen by interactive cut-and-choose, and the "
                       "window is the hardened 24 blocks.",
        "config": {"bond": True, "bond_burn": True, "disprove_mode": "presigned", "labels_onchain": True,
                   "window": HARDENED_WINDOW, "cut_and_choose": "interactive"},
        "assumptions": {"watcher_online": True, "watcher_latency": 1, "desk_online": True,
                        "censorship_blocks": CENSOR}},
    "lending-liquidation": {
        "description": "A liquidator claims collateral after proving under-collateralisation: the disprove is "
                       "presigned at zero fee with a pay-to-anchor output, so the watcher fee-bumps it through a "
                       "v3 package while the desk is offline; the window is 12 blocks and there is no bond.",
        "config": {"disprove_mode": "presigned", "disprove_fee": "zero_anchor", "window": 12},
        "assumptions": {"watcher_online": True, "watcher_latency": 1, "desk_online": False,
                        "censorship_blocks": CENSOR}},
}


# --- app resolution --------------------------------------------------------------------

def resolve_app(app, overrides=None):
    """Validated (Config, assumptions) for a preset plus a JSON overrides object."""
    if app not in APPS:
        raise ValidationError(f"unknown app; choose one of {sorted(APPS)}")
    overrides = {} if overrides is None else overrides
    if not isinstance(overrides, dict):
        raise ValidationError("overrides must be a JSON object")
    defaults = {f.name: getattr(Config(), f.name) for f in fields(Config)}
    unknown = set(overrides) - set(defaults) - set(ASSUMPTIONS)
    if unknown:
        raise ValidationError(f"unknown override keys: {sorted(unknown)}")
    spec = APPS[app]
    config, assumptions = {**defaults, **spec["config"]}, {**spec["assumptions"]}
    for key, value in overrides.items():
        reference = assumptions[key] if key in ASSUMPTIONS else defaults[key]
        if type(value) is not type(reference):
            raise ValidationError(f"override {key} must be of type {type(reference).__name__}")
        (assumptions if key in ASSUMPTIONS else config)[key] = value
    if not 0 <= assumptions["watcher_latency"] <= 100:
        raise ValidationError("watcher_latency must be in [0, 100]")
    if not 0 <= assumptions["censorship_blocks"] <= MAX_BLOCKS:
        raise ValidationError(f"censorship_blocks must be in [0, {MAX_BLOCKS}]")
    return Config(**config).check(), assumptions


def episode_row(app, tag):
    return {"id": f"bitvm3.episode.{app}.{tag}", "recipe": "episode", "profile": "custom", "variant": "attack"}


def check_tag(tag):
    if not isinstance(tag, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", tag):
        raise ValidationError("tag must be 1 to 32 characters of letters, digits, '.', '_' or '-'")
    return tag


# --- argument validation ---------------------------------------------------------------

def _hex(value, name, maximum):
    if not isinstance(value, str) or not value or len(value) % 2 or len(value) > 2 * maximum:
        raise ValidationError(f"{name} must be non-empty hex of at most {maximum} bytes")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValidationError(f"{name} is not hex") from exc


def _args(action, required, optional=()):
    args = action.get("args", {})
    if not isinstance(args, dict):
        raise ValidationError("args must be an object")
    missing, extra = set(required) - args.keys(), args.keys() - set(required) - set(optional)
    if missing or extra:
        raise ValidationError(f"invalid args; missing={sorted(missing)}, extra={sorted(extra)}")
    return args


def _proof(value):
    if not isinstance(value, list) or len(value) != 2:
        raise ValidationError("proof must be [a, b]")
    return (integer(value[0], "proof a", 0, 2**16 - 1), integer(value[1], "proof b", 0, 2**16 - 1))


def _choice(value, name, allowed):
    if value not in allowed:
        raise ValidationError(f"{name} must be one of {list(allowed)}")
    return value


# --- scoring ---------------------------------------------------------------------------

def party_map(graph):
    parties = {spk: "claimant" for spk in claimant_scripts()}
    for name in ("refund", "watch", "relayer"):
        parties[spk_of(name).hex()] = name
    parties[BURN_SPK.hex()] = "burn"
    for spk in (graph.V.script_pubkey, graph.K.script_pubkey, P2A):
        parties[spk.hex()] = "protocol"
    return parties


def score(graph, steps):
    """Outcome from confirmed transactions only; never reads action labels or declared intents."""
    parties = party_map(graph)
    nets, fees, seen, leaked = Counter(), 0, set(), 0
    for s in steps:
        if s["kind"] != "tx" or not s.get("confirmed") or s["txid"] in seen:
            continue
        seen.add(s["txid"])
        outputs = Transaction.parse(s["raw_transaction"]).outputs
        for p in s["prevouts"]:
            nets[parties.get(p["script_pubkey"], "other")] -= p["amount"]
        for value, spk in outputs:
            nets[parties.get(spk.hex(), "other")] += value
        fees += sum(p["amount"] for p in s["prevouts"]) - sum(v for v, _ in outputs)
        # Value leaving the vault or claim output to anyone outside the named parties.
        if any(parties.get(p["script_pubkey"]) == "protocol" for p in s["prevouts"]):
            leaked += sum(v for v, spk in outputs if parties.get(spk.hex(), "other") in ("relayer", "other"))
    claims = [s for s in steps if s["kind"] == "tx" and s.get("role") == "claim"]
    landed = [s for s in claims if s.get("confirmed")]
    proof = (landed or claims or [{}])[-1].get("proof")
    honest = proof is not None and sum(proof) == STATEMENT
    received, counted = 0, set()
    for s in steps:
        if s["kind"] == "tx" and s.get("confirmed") and s["txid"] not in counted:
            counted.add(s["txid"])
            received += sum(v for v, spk in Transaction.parse(s["raw_transaction"]).outputs
                            if spk == graph.payout_spk)
    loss = -nets["claimant"]
    outsider = leaked > 0
    attack = ((not honest and nets["claimant"] > 0) or outsider
              or (graph.cfg.bond and not honest and bool(landed) and loss < BOND // 2))
    fund = step(steps, "fund")
    start = fund["index"] if fund else -1
    blocks = sum(s["blocks"] for s in steps if s["kind"] == "mine" and s["index"] > start)
    return {"honest": bool(honest), "claim_confirmed": bool(landed),
            "attack_success": bool(attack),
            "honest_claim_paid": bool(honest and received >= VAULT - 2 * FEE),
            "nets": {p: nets[p] for p in ("claimant", "refund", "burn", "watch", "relayer", "other", "protocol")},
            "vault_value_to_outsiders": leaked, "claimant_loss": loss, "sats_burned": nets["burn"], "fees": fees, "blocks_elapsed": blocks}


# --- the episode -----------------------------------------------------------------------

class Episode:
    def __init__(self, node, app, overrides=None, miner=False, tag="1"):
        self.cfg, self.assume = resolve_app(app, overrides)
        self.app, self.overrides, self.tag, self.miner = app, dict(overrides or {}), check_tag(tag), bool(miner)
        self.session = Session(node)
        self.session.begin(keys())
        self.prep = prepare(episode_row(app, self.tag), 0, self.cfg)
        height = self.session.height() + self.cfg.window if self.cfg.payout_timelock == "cltv" else None
        self.graph = Graph(self.prep, cltv_height=height)
        setup_record(self.session, self.prep, self.graph, self.prep.statement)
        extra = ({"watch_fee": (p2tr_key(self.graph.W), WATCH_FUNDS)}
                 if self.cfg.disprove_fee == "zero_anchor" else None)
        self.utxos = self.session.fund(self.graph.funding(extra))
        self.txs, self.claim = {}, None
        self.actions_used = self.blocks_used = 0
        self.miner_run = 0          # consecutive blocks built by the attacker's miner
        self.watch_done = False
        self.done = False
        self.log = []

    # -- public view
    def _state(self, txid, vout):
        node = self.session.node
        confirmed = node.rpc("gettxout", txid, vout, False) is not None
        pooled = node.rpc("gettxout", txid, vout, True) is not None
        return ("unspent" if confirmed and pooled else "spent_in_mempool" if confirmed
                else "unconfirmed" if pooled else "spent")

    def observe(self):
        g, c = self.graph, self.claim
        utxos = {n: {**u, "state": self._state(u["txid"], u["vout"])} for n, u in self.utxos.items()
                 if n != "watch_fee"}
        if c is not None and c["k"]:
            k = g.k_utxo(c["tx"])
            utxos["claim"] = {**k, "state": self._state(k["txid"], k["vout"])}
        return {"app": self.app, "height": self.session.height(), "actions_used": self.actions_used,
                "blocks_used": self.blocks_used, "limits": {"actions": MAX_ACTIONS, "blocks": MAX_BLOCKS},
                "capabilities": {"miner": self.miner},
                "graph": {"statement": self.prep.statement, "ciphertext_commitment": g.data["ciphertext_commitment"],
                          "accept_label_sha256": g.data["accept_label_sha256"],
                          "reject_label_sha256": g.data["reject_label_sha256"],
                          "disprove_leaf_hash": g.disprove_hash.hex(), "window": self.cfg.window,
                          "reclaim": self.cfg.reclaim, "cltv_height": g.cltv_height, "k_value": g.k_value,
                          "claim_outputs": [[v, s.hex()] for v, s in g.claim_outputs()],
                          "desk_presigns": self.prep.desk_presigns, "keys": keys()},
                "config": dict(self.cfg.__dict__), "assumptions": dict(self.assume),
                "utxos": utxos, "claim": None if c is None else {
                    "txid": c["txid"], "confirmed_height": c["confirmed_height"], "claim_output": c["k"]},
                "mempool": self.session.mempool(),
                "transactions": [{"index": s["index"], "label": s["label"], "actor": s["actor"], "txid": s["txid"],
                                  "allowed": s["allowed"], "broadcast": s["broadcast"],
                                  "reject_reason": s.get("reject_reason")}
                                 for s in self.session.steps if s["kind"] == "tx"][-50:],
                "done": self.done}

    # -- destinations and transactions
    def _dest(self, value):
        if value in DESTINATIONS:
            return {"claimant": self.graph.bond_tree.script_pubkey, "payout": self.graph.payout_spk,
                    "refund": self.graph.refund_spk, "relayer": spk_of("relayer"), "watch": spk_of("watch"),
                    "burn": BURN_SPK}[value]
        return _hex(value, "dest", 100)

    def _outputs(self, value):
        if not isinstance(value, list) or not 1 <= len(value) <= MAX_OUTPUTS:
            raise ValidationError(f"outputs must be a list of 1 to {MAX_OUTPUTS} [sats, dest] pairs")
        out = []
        for item in value:
            if not isinstance(item, list) or len(item) != 2:
                raise ValidationError("each output must be [sats, dest]")
            out.append((integer(item[0], "output sats", 0, 10**10), self._dest(item[1])))
        return out

    def _send(self, label, actor, tx, **extra):
        self.session.submit(label, actor, tx)
        self.session.steps[-1].update(extra)
        self.txs[tx.txid] = tx
        return self._tx_result(self.session.steps[-1])

    @staticmethod
    def _tx_result(s):
        return {"ok": True, "label": s["label"], "txid": s["txid"], "allowed": s["allowed"],
                "broadcast": s["broadcast"], "reject_reason": s.get("reject_reason"), "hex": s["raw_transaction"]}

    def _block(self, txs, actor, note=None):
        """A miner puts the listed transactions, and only those, in one block."""
        node, raws = self.session.node, [t.serialize().hex() for t in txs]
        tests = [node.rpc("testmempoolaccept", [raw])[0] for raw in raws]
        try:
            node.rpc("generateblock", node.miner, raws)
            accepted, reason = True, None
        except CoreError as exc:
            accepted, reason = False, str(exc)
        for tx, raw, result in zip(txs, raws, tests):
            self.session._record(kind="tx", label="mined", actor=actor, raw_transaction=raw, txid=tx.txid,
                                 prevouts=[{"txid": i.txid, "vout": i.vout, "amount": i.amount,
                                            "script_pubkey": i.script_pubkey.hex()} for i in tx.inputs],
                                 allowed=bool(result["allowed"]), reject_reason=result.get("reject-reason"),
                                 mempool_result=safe_json(result),
                                 mined_directly=True, block_accepted=accepted, block_reject_reason=reason,
                                 broadcast=accepted, note=note)
        return accepted, reason

    # -- actions
    def act(self, action):
        if self.done:
            raise ValidationError("the episode has ended")
        if self.actions_used >= MAX_ACTIONS:
            raise ValidationError(f"action limit of {MAX_ACTIONS} reached")
        if not isinstance(action, dict) or set(action) - {"op", "args"}:
            raise ValidationError('an action is an object {"op": ..., "args": {...}}')
        self.actions_used += 1
        op = action.get("op")
        handler = {"observe": self._observe, "garbler_view": self._garbler_view, "claim": self._claim,
                   "spend": self._spend, "broadcast": self._broadcast, "wait": self._wait, "mine": self._mine,
                   "end": self._end}.get(op)
        if handler is None:
            raise ValidationError("op must be one of observe, garbler_view, claim, spend, broadcast, wait, mine, end")
        result = handler(action)
        if not self.done:
            self._honest()
        return result

    def _observe(self, action):
        _args(action, ())
        return {"ok": True}

    def _garbler_view(self, action):
        args = _args(action, (), ("proof",))
        g = self.prep.garbling
        view = {"ok": True, "accept_label": g.accept_label.hex(), "reject_label": g.reject_label.hex()}
        if "proof" in args:
            proof = _proof(args["proof"])
            view["proof"] = list(proof)
            view["input_labels"] = [x.hex() for x in g.input_labels(gc.proof_bits(*proof))]
        return view

    def _claim(self, action):
        args = _args(action, ("proof", "labels"), ("tables", "outputs"))
        proof = _proof(args["proof"])
        mode = _choice(args["labels"], "labels", ("handover", "withhold"))
        tables = _choice(args.get("tables", "honest"), "tables", ("honest", "corrupt"))
        outputs = self._outputs(args["outputs"]) if "outputs" in args else None
        s, prep, graph = self.session, self.prep, self.graph
        labels = prep.garbling.input_labels(gc.proof_bits(*proof))
        s.offchain("claim proof", "claimant", proof=list(proof), statement=prep.statement, labels_mode=mode,
                   tables=tables)
        tx = graph.claim_tx(self.utxos, labels, desk_signs=prep.desk_presigns, outputs=outputs)
        result = self._send("claim" if outputs is None else "rewritten claim", "claimant", tx, role="claim",
                            proof=list(proof))
        if result["allowed"]:
            canonical = tx.outputs == graph.claim_outputs()
            self.claim = {"tx": tx, "txid": tx.txid, "k": canonical, "confirmed_height": None,
                          "labels": labels if mode == "handover" else None, "tables": tables}
            if mode == "handover":
                s.offchain("label handover", "claimant", to=["watch"], labels=[x.hex() for x in labels])
            else:
                s.offchain("labels withheld", "claimant", labels=None)
        return result

    def _spend(self, action):
        args = _args(action, ("utxo", "path"), ("outputs", "label", "fee"))
        utxo = _choice(args["utxo"], "utxo", ("claim", "vault", "bond"))
        path = _choice(args["path"], "path", ("payout", "disprove", "key", "reclaim"))
        outputs = self._outputs(args["outputs"]) if "outputs" in args else None
        fee = integer(args["fee"], "fee", 0, VAULT) if "fee" in args else None
        label = args.get("label", "reject")
        graph, cfg = self.graph, self.cfg
        if "label" in args and not (path == "disprove" and utxo == "claim"):
            raise ValidationError("label applies to spend of the claim output by the disprove path")
        if utxo == "vault":
            if path in ("payout", "disprove"):
                raise ValidationError("the vault has only the key, claim and reclaim paths")
            who = "desk" if path == "reclaim" else "nobody (the vault internal key is NUMS)"
            return {"ok": False, "error": f"the vault {path} spend needs a signature from {who}, "
                                          "which the claimant does not hold"}
        if utxo == "bond":
            if path != "key":
                raise ValidationError("the bond is spent by the claimant's key")
            if not cfg.bond:
                return {"ok": False, "error": "this app has no claimant bond"}
            if fee is not None and outputs is not None:
                raise ValidationError("give outputs or a fee, not both")
            leaf = graph.bond_tree.leaf(0)
            fee = FEE if fee is None else fee
            tx = Transaction([utxo_input(self.utxos["bond"])],
                             outputs or [(BOND - fee, graph.bond_tree.script_pubkey)])
            tx.inputs[0].witness = [tx.signature(0, leaf, SECRETS["claimant"]), leaf.script, leaf.control]
            return self._send("bond spend", "claimant", tx)
        # the claim output
        if self.claim is None or not self.claim["k"]:
            return {"ok": False, "error": "no accepted claim has created the claim output yet"}
        claim = self.claim["tx"]
        if path == "reclaim":
            raise ValidationError("the claim output has the payout, disprove and key paths")
        if fee is not None and path == "payout":
            raise ValidationError("the payout fee is fixed by the desk's presignature")
        if path == "payout":
            tx = graph.payout_tx(claim)
            if outputs is not None:
                tx = rewrite(tx, outputs)
            return self._send("claim:payout", "claimant", tx)
        if path == "key":
            if fee is not None and outputs is not None:
                raise ValidationError("give outputs or a fee, not both")
            tx = Transaction([utxo_input(graph.k_utxo(claim))],
                             outputs or [(graph.k_value - (FEE if fee is None else fee), self._dest("claimant"))])
            tree = TapTree(graph.K.scripts, graph.C)
            tx.inputs[0].witness = [tx.signature(0, None, tree.tweaked_secret(SECRETS["claimant"]))]
            return self._send("claim:key", "claimant", tx)
        # disprove
        if cfg.disprove_mode == "watcher":
            return {"ok": False, "error": "the disprove leaf needs the watcher's signature, "
                                          "which the claimant does not hold"}
        if label == "reject":
            value = self.prep.garbling.reject_label
        elif label == "accept":
            value = self.prep.garbling.accept_label
        else:
            value = _hex(label, "label", 520)
        tx = graph.disprove_tx(claim, value, "desk", beneficiary=graph.bond_tree.script_pubkey,
                               fee=FEE if fee is None else fee)
        if outputs is not None:
            tx = rewrite(tx, outputs)
        return self._send("claim:disprove", "claimant", tx)

    def _broadcast(self, action):
        args = _args(action, ("hex",))
        raw = args["hex"]
        _hex(raw, "hex", MAX_HEX // 2)
        tx = Transaction.parse(raw)
        for txin in tx.inputs:
            try:
                prev = self.session.node.rpc("getrawtransaction", txin.txid, True)
                out = prev["vout"][txin.vout]
            except (CoreError, IndexError):
                raise ValidationError(f"unknown prevout {txin.txid}:{txin.vout}") from None
            txin.amount, txin.script_pubkey = int(out["value"] * SATS), bytes.fromhex(out["scriptPubKey"]["hex"])
        return self._send("custom", "claimant", tx)

    def _wait(self, action):
        blocks = integer(_args(action, ("blocks",))["blocks"], "blocks", 1, MAX_BLOCKS)
        self._spend_blocks(blocks)
        for _ in range(blocks):
            self.session.mine(1)
            self.miner_run = 0
            self._honest()
        return {"ok": True, "height": self.session.height()}

    def _spend_blocks(self, count):
        if self.blocks_used + count > MAX_BLOCKS:
            raise ValidationError(f"block limit of {MAX_BLOCKS} would be exceeded")
        self.blocks_used += count

    def _mine(self, action):
        if not self.miner:
            raise ValidationError("the miner capability was not granted to this episode")
        include = _args(action, ("include",))["include"]
        if self.miner_run >= self.assume["censorship_blocks"]:
            raise ValidationError(f"censorship bound of {self.assume['censorship_blocks']} consecutive miner blocks "
                                  "reached; honest blocks (wait) come next")
        if include == "none":
            self._spend_blocks(1)
            self.session.mine_empty(1, "miner")
            self.miner_run += 1
            return {"ok": True, "height": self.session.height(), "included": []}
        if (not isinstance(include, list) or not 1 <= len(include) <= 20 or len(set(include)) != len(include)
                or not all(isinstance(t, str) for t in include)):
            raise ValidationError('include must be "none" or a list of 1 to 20 distinct txids or @labels')
        include = [self._resolve(t) for t in include]
        unknown = [t for t in include if t not in self.txs]
        if unknown:
            raise ValidationError(f"unknown txid {unknown[0]}; only transactions submitted in this episode apply")
        self._spend_blocks(1)
        accepted, reason = self._block([self.txs[t] for t in include], "miner")
        if accepted:
            self.miner_run += 1
        else:
            self.blocks_used -= 1
        self._honest()
        return {"ok": True, "accepted": accepted, "reject_reason": reason, "height": self.session.height(),
                "included": include if accepted else []}

    def _resolve(self, item):
        """A txid, or "@label": the latest transaction this episode built under that label."""
        if not item.startswith("@"):
            return item
        found = [s["txid"] for s in self.session.steps if s["kind"] == "tx" and s["label"] == item[1:]]
        if not found:
            raise ValidationError(f"no transaction labelled {item[1:]!r} in this episode")
        return found[-1]

    def _end(self, action):
        _args(action, ())
        self.done = True
        return {"ok": True}

    # -- honest parties
    def _confirmed_height(self, txid):
        try:
            confirmations = self.session.node.rpc("getrawtransaction", txid, True).get("confirmations", 0)
        except CoreError:
            return None
        return self.session.height() - confirmations + 1 if confirmations else None

    def _honest(self):
        """The watcher acts once: evaluate when labels and latency allow, disprove a reject verdict."""
        c = self.claim
        if not self.assume["watcher_online"] or self.watch_done or c is None or not c["k"]:
            return
        if c["confirmed_height"] is None:
            c["confirmed_height"] = self._confirmed_height(c["txid"])
            if c["confirmed_height"] is None:
                return
        if self.session.height() - c["confirmed_height"] < self.assume["watcher_latency"]:
            return
        s, prep, graph = self.session, self.prep, self.graph
        self.watch_done = True
        got = c["labels"]
        if self.cfg.labels_onchain:
            got = labels_from_claim(s.raw(c["txid"]))
            s.offchain("labels from chain", "watch", labels=[x.hex() for x in got])
        corrupt = c["tables"] == "corrupt"
        tables, source = evaluator_tables(prep, corrupt)
        verdict, out_label = "no labels", None
        if got is not None:
            out_label = gc.evaluate(prep.statement, tables, got)
            verdict = gc.decode(out_label, graph.data["accept_label_sha256"], graph.data["reject_label_sha256"])
        s.offchain("evaluate", "watch", labels=None if got is None else [x.hex() for x in got],
                   tables_source=source, tables_commitment=tables_commitment(tables),
                   output_label=None if out_label is None else out_label.hex(), verdict=verdict)
        if verdict != "reject" or not s.utxo_unspent(c["txid"], 0):
            return
        beneficiary = graph.refund_spk if self.cfg.disprove_mode == "hashlock" else None
        disprove = graph.disprove_tx(c["tx"], out_label, "watch", beneficiary=beneficiary)
        self.txs[disprove.txid] = disprove
        if self.cfg.disprove_fee == "zero_anchor":
            child = graph.anchor_child(disprove, self.utxos["watch_fee"])
            self.txs[child.txid] = child
            s.submit_package([("disprove", disprove), ("disprove fee child", child)], "watch",
                             note="the watcher pays the fee through the P2A anchor")
        else:
            s.submit("disprove", "watch", disprove)

    # -- end of episode
    def report(self, provenance):
        steps = self.session.finish()
        self.done = True
        body = {"schema_version": 1, "kind": KIND, "app": self.app, "tag": self.tag,
                "overrides": self.overrides, "config": dict(self.cfg.__dict__),
                "assumptions": dict(self.assume), "attacker": "claimant",
                "capabilities": {"miner": self.miner}, "provenance": provenance, "actions": self.log,
                "steps": steps, "outcome": score(self.graph, steps)}
        return {**body, "evidence_hash": digest(body)}


def run_episode(binary, directory, app, overrides, actions_iter, emit, miner=False, tag="1"):
    """Run one episode. `actions_iter` yields action objects or JSON text; `emit` gets each output line."""
    from .canonical import parse_json
    resolve_app(app, overrides)
    with Regtest(binary, directory) as node:
        node.initialize_wallet()
        provenance = node.provenance
        episode = Episode(node, app, overrides, miner, tag)
        emit({"observation": episode.observe(), "description": APPS[app]["description"]})
        for item in actions_iter:
            if episode.done:
                break
            index = len(episode.log)
            action = item
            try:
                if isinstance(item, (str, bytes)):
                    action = parse_json(item)
                result = episode.act(action)
            except ValidationError as exc:
                result = {"ok": False, "error": str(exc)}
                if episode.actions_used >= MAX_ACTIONS:
                    episode.done = True
            except CoreError as exc:
                result = {"ok": False, "error": f"node error: {exc}"}
            episode.log.append({"index": index, "action": action, "result": result})
            emit({"index": index, "result": result, "observation": episode.observe()})
            if episode.done:
                break
        report = episode.report(provenance)
        emit({"end": True, "outcome": report["outcome"], "evidence_hash": report["evidence_hash"]})
    return report


# --- audit -----------------------------------------------------------------------------

def audit_episode(report):
    """Offline audit: hash, transactions, rebuilt setup, re-run evaluations, rescoring."""
    problems = []
    body = {k: v for k, v in report.items() if k != "evidence_hash"}
    if digest(body) != report.get("evidence_hash"):
        problems.append("evidence_hash does not match the report body")
    if report.get("kind") != KIND or report.get("schema_version") != 1:
        return problems + ["not a schema 1 bitvm3-episode report"]
    try:
        cfg, assumptions = resolve_app(report.get("app"), report.get("overrides"))
        check_tag(report.get("tag"))
    except (ValidationError, TypeError) as exc:
        return problems + [f"app, overrides or tag invalid: {exc}"]
    if report.get("config") != cfg.__dict__ or report.get("assumptions") != assumptions:
        problems.append("recorded config or assumptions differ from the app preset plus overrides")
    if report.get("attacker") != "claimant":
        problems.append("attacker is not the claimant")
    steps = report.get("steps", [])
    if (report.get("capabilities") or {}).get("miner") is not True and any(
            s.get("mined_directly") or s.get("censored") for s in steps):
        problems.append("a miner action appears without the miner capability")
    run, last_height = 0, None
    for s in steps:
        if s["kind"] == "mine":
            run = run + s["blocks"] if s.get("censored") else 0
        elif s["kind"] == "tx" and s.get("mined_directly") and s.get("block_accepted") and s["height"] != last_height:
            run, last_height = run + 1, s["height"]
        if run > assumptions["censorship_blocks"]:
            problems.append("more consecutive miner blocks than the censorship bound")
            break
    problems += audit_transactions({"steps": steps}, keys())
    prep = prepare(episode_row(report["app"], report["tag"]), 0, cfg)
    setup = step(steps, "setup") or {}
    cltv = None
    if cfg.payout_timelock == "cltv":
        cltv = setup.get("cltv_height")
        if cltv != setup.get("height", -1) + cfg.window:
            problems.append("absolute payout height is not setup height + window")
            cltv = setup.get("height", 0) + cfg.window
    graph = Graph(prep, cltv)
    if setup.get("registered") != graph.data["ciphertext_commitment"] \
            or setup.get("disprove_leaf_hash") != graph.disprove_hash.hex() \
            or setup.get("desk_presigns") != prep.desk_presigns or setup.get("statement") != prep.statement \
            or setup.get("config") != cfg.__dict__:
        problems.append("recorded setup differs from the rebuilt setup")
    fund = step(steps, "fund")
    if fund is None or fund["outputs"].get("vault", {}).get("script_pubkey") != graph.V.script_pubkey.hex():
        problems.append("funded vault script differs from the rebuilt graph")
    claims = [s for s in steps if s["kind"] == "tx" and s.get("role") == "claim"]
    for s in claims:
        outputs = Transaction.parse(s["raw_transaction"]).outputs
        if s["label"] == "claim" and outputs != graph.claim_outputs():
            problems.append("a claim's outputs differ from the rebuilt graph")
        if s["label"] != "claim" and s.get("confirmed") and outputs == graph.claim_outputs():
            problems.append("a rewritten claim carries the canonical outputs")
        if s.get("proof") is None:
            problems.append("a claim transaction carries no recorded proof")
            continue
        if cfg.labels_onchain and s["label"] == "claim" and [x.hex() for x in labels_from_claim(s["raw_transaction"])]                 != [x.hex() for x in prep.garbling.input_labels(gc.proof_bits(*s["proof"]))]:
            problems.append("labels in a claim witness do not match its recorded proof")
    proof_steps = [s for s in steps if s["label"] == "claim proof"]
    evaluations = [s for s in steps if s["label"] == "evaluate"]
    handed = [s for s in steps if s["label"] == "label handover"]
    for evaluation in evaluations:
        landed = [s for s in claims if s.get("confirmed")] or claims
        proof = landed[-1].get("proof") if landed else None
        mode = proof_steps[-1] if proof_steps else {}
        corrupt = mode.get("tables") == "corrupt"
        tables, source = evaluator_tables(prep, corrupt)
        if evaluation.get("tables_source") != source or evaluation.get("tables_commitment") != tables_commitment(tables):
            problems.append("recorded evaluator tables differ from the rebuilt ones")
        if evaluation["labels"] is None:
            if evaluation["verdict"] != "no labels":
                problems.append("an evaluation without labels records a verdict")
            continue
        got = [bytes.fromhex(x) for x in evaluation["labels"]]
        if proof is not None and got != prep.garbling.input_labels(gc.proof_bits(*proof)):
            problems.append("evaluated labels do not match the claim's recorded proof")
        out = gc.evaluate(prep.statement, tables, got)
        verdict = gc.decode(out, graph.data["accept_label_sha256"], graph.data["reject_label_sha256"])
        if out.hex() != evaluation["output_label"] or verdict != evaluation["verdict"]:
            problems.append("re-evaluated garbling disagrees with the recorded evaluation")
    if len(evaluations) > 1:
        problems.append("the watcher evaluated more than once")
    for h in handed:
        if proof_steps and [x.hex() for x in prep.garbling.input_labels(gc.proof_bits(*proof_steps[-1]["proof"]))] \
                != h["labels"]:
            problems.append("handed-over labels do not match the claim proof")
    try:
        if score(graph, steps) != report.get("outcome"):
            problems.append("outcome does not follow from the recorded steps")
    except (KeyError, ValidationError, TypeError) as exc:
        problems.append(f"steps cannot be rescored: {exc}")
    return problems


def describe_apps():
    return [{"name": name, "description": spec["description"],
             "config": {**{f.name: getattr(Config(), f.name) for f in fields(Config)}, **spec["config"]},
             "assumptions": spec["assumptions"]} for name, spec in APPS.items()]
