"""Shared machinery for multi-step native trajectories on an owned regtest node.

A trajectory is a deterministic script of actions by named actors. Transaction steps
go through Core's testmempoolaccept and, when allowed and intended, sendrawtransaction.
Off-chain steps (garbling, label handover, evaluation, cut-and-choose) are recorded
with their inputs so an offline auditor can recompute them. Outcomes are scored from
what Core confirmed; declared expectations come from the catalog, never from Core.
"""

from __future__ import annotations

from decimal import Decimal
from types import SimpleNamespace

from .bitcoin import Transaction, TxInput, check_signature, leaf_hash, verify_commitment
from .canonical import ValidationError, digest
from .core import CoreError, safe_json

SATS = Decimal(100_000_000)


class Session:
    """Runs one case at a time on a shared node and records every step."""

    def __init__(self, node):
        self.node = node
        self.steps = []
        self.keys = {}

    def begin(self, keys):
        self.steps, self.keys = [], dict(keys)

    def height(self):
        return self.node.rpc("getblockcount")

    def _record(self, **step):
        step["index"] = len(self.steps)
        step["height"] = self.height()
        self.steps.append(step)
        return step

    def fund(self, outputs, label="fund"):
        """outputs: {name: (TapTree-like with output_key/script_pubkey, sats)} -> {name: utxo}."""
        payments, wanted = {}, {}
        for name, (tree, sats) in outputs.items():
            address = self.node.address(tree.output_key)
            if address in payments:
                raise ValidationError("duplicate funding address in one case")
            payments[address] = format(Decimal(sats) / SATS, "f")
            wanted[name] = (tree.script_pubkey, sats)
        txid = self.node.rpc("sendmany", "", payments, wallet=True)
        self.node.mine()
        funding = self.node.rpc("getrawtransaction", txid, True)
        utxos = {}
        for name, (spk, sats) in wanted.items():
            output = next(v for v in funding["vout"] if v["scriptPubKey"]["hex"] == spk.hex())
            utxos[name] = {"txid": txid, "vout": output["n"], "amount": sats, "script_pubkey": spk.hex()}
        self._record(kind="fund", label=label, actor="evaluator", txid=txid,
                     raw_transaction=funding["hex"], outputs=utxos)
        return utxos

    def submit(self, label, actor, tx, *, broadcast=True, note=None, via=None, via_name=None):
        """Mempool test then broadcast. `via` submits through another owned node of a cluster."""
        node = via or self.node
        raw = tx.serialize().hex()
        result = node.rpc("testmempoolaccept", [raw])[0]
        allowed = bool(result["allowed"])
        sent = False
        if allowed and broadcast:
            if node.rpc("sendrawtransaction", raw) != tx.txid:
                raise CoreError("Core txid disagrees with local serialization")
            sent = True
        extra = {"submitted_to": via_name} if via_name else {}
        self._record(kind="tx", label=label, actor=actor, raw_transaction=raw, txid=tx.txid,
                     prevouts=[{"txid": i.txid, "vout": i.vout, "amount": i.amount,
                                "script_pubkey": i.script_pubkey.hex()} for i in tx.inputs],
                     allowed=allowed, reject_reason=result.get("reject-reason"),
                     mempool_result=safe_json(result), broadcast=sent, note=note, **extra)
        return allowed

    def submit_package(self, entries, actor, *, note=None):
        """Relay a parent+child package with `submitpackage` (CPFP through an anchor).

        entries: [(label, tx), ...] in topological order. Each transaction is first tried
        alone with testmempoolaccept (recorded), then the package is submitted; a step is
        allowed when Core's package result for it carries no error.
        """
        raws = [tx.serialize().hex() for _, tx in entries]
        alone = [self.node.rpc("testmempoolaccept", [raw])[0] for raw in raws]
        try:
            result = self.node.rpc("submitpackage", raws)
            message = result.get("package_msg")
            by_txid = {r.get("txid"): r for r in result.get("tx-results", {}).values()}
        except CoreError as exc:
            message, by_txid = str(exc), {}
        allowed_all = True
        for (label, tx), raw, solo in zip(entries, raws, alone):
            entry = by_txid.get(tx.txid)
            allowed = entry is not None and not entry.get("error")
            allowed_all &= allowed
            self._record(kind="tx", label=label, actor=actor, raw_transaction=raw, txid=tx.txid,
                         prevouts=[{"txid": i.txid, "vout": i.vout, "amount": i.amount,
                                    "script_pubkey": i.script_pubkey.hex()} for i in tx.inputs],
                         allowed=allowed, reject_reason=(entry or {}).get("error") or
                         (None if allowed else message),
                         mempool_result=safe_json(entry or {}), alone_result=safe_json(solo),
                         package_msg=message, broadcast=allowed, note=note)
        return allowed_all

    def submit_in_block(self, label, actor, tx, *, note=None):
        """A miner puts `tx` in a block of its own (`generateblock`), bypassing the mempool.

        Mempool policy is still recorded (testmempoolaccept); the block itself is judged by
        Core's consensus checks. Only the listed transaction is included, so anything else
        waiting in the mempool is censored from that block.
        """
        raw = tx.serialize().hex()
        result = self.node.rpc("testmempoolaccept", [raw])[0]
        try:
            self.node.rpc("generateblock", self.node.miner, [raw])
            accepted, reason = True, None
        except CoreError as exc:
            accepted, reason = False, str(exc)
        self._record(kind="tx", label=label, actor=actor, raw_transaction=raw, txid=tx.txid,
                     prevouts=[{"txid": i.txid, "vout": i.vout, "amount": i.amount,
                                "script_pubkey": i.script_pubkey.hex()} for i in tx.inputs],
                     allowed=bool(result["allowed"]), reject_reason=result.get("reject-reason"),
                     mempool_result=safe_json(result), mined_directly=True, block_accepted=accepted,
                     block_reject_reason=reason, broadcast=accepted, note=note)
        return accepted

    def mine(self, count, note=None):
        start = self.height()
        self.node.mine(count)
        self._record(kind="mine", label=f"mine {count}", actor="environment", blocks=count,
                     from_height=start, note=note)

    def mine_congested(self, count, floor_sat_vb, note=None):
        """Blocks from a congested fee market: each includes only the mempool transactions whose
        ancestor package pays at least `floor_sat_vb`, as if higher-paying traffic filled the rest."""
        start, included = self.height(), []
        for _ in range(count):
            pool = self.node.rpc("getrawmempool", True)
            chosen = set()
            for txid, entry in pool.items():
                rate = Decimal(entry["fees"]["ancestor"]) * SATS / entry["ancestorsize"]
                if rate >= floor_sat_vb:
                    chosen.add(txid)
                    chosen.update(self.node.rpc("getmempoolancestors", txid))
            ordered = sorted(chosen, key=lambda t: pool[t]["ancestorcount"])
            self.node.rpc("generateblock", self.node.miner, ordered)
            included.append(ordered)
        self._record(kind="mine", label=f"mine {count} congested", actor="environment", blocks=count,
                     from_height=start, fee_floor_sat_vb=str(floor_sat_vb), included=included, note=note)

    def mine_empty(self, count, actor, note=None):
        """A censoring miner produces `count` blocks that include no mempool transaction."""
        start = self.height()
        for _ in range(count):
            self.node.rpc("generateblock", self.node.miner, [])
        self._record(kind="mine", label=f"mine {count} empty", actor=actor, blocks=count,
                     from_height=start, censored=True, note=note)

    def mempool(self):
        return self.node.rpc("getrawmempool")

    def offchain(self, label, actor, **data):
        self._record(kind="offchain", label=label, actor=actor, **data)

    def utxo_unspent(self, txid, vout):
        return self.node.rpc("gettxout", txid, vout) is not None

    def raw(self, txid):
        return self.node.rpc("getrawtransaction", txid)

    def _displaced(self, step):
        """True when a broadcast transaction lost its inputs to a confirmed conflict."""
        try:
            self.node.rpc("getrawtransaction", step["txid"], True)
            return False
        except CoreError:
            pass
        return any(self.node.rpc("gettxout", p["txid"], p["vout"]) is None for p in step["prevouts"])

    def finish(self):
        """Mine a block and attach confirmation evidence to every broadcast transaction.

        A broadcast transaction that was replaced (RBF) or evicted by a conflicting block
        is recorded as displaced; any other unconfirmed broadcast is an error.
        """
        self.node.mine()
        for step in self.steps:
            if step["kind"] == "tx":
                step["confirmed"] = False
                if step["broadcast"]:
                    if self._displaced(step):
                        step["displaced"] = True
                        continue
                    info = self.node.rpc("getrawtransaction", step["txid"], True)
                    confirmations = info.get("confirmations", 0)
                    if confirmations < 1:
                        raise CoreError(f"broadcast step {step['label']} was not confirmed")
                    outputs = [[int(v["value"] * SATS), v["scriptPubKey"]["hex"]] for v in info["vout"]]
                    parsed = Transaction.parse(step["raw_transaction"])
                    if outputs != [[value, spk.hex()] for value, spk in parsed.outputs]:
                        raise CoreError("confirmed outputs disagree with the submitted transaction")
                    step.update(confirmed=True, blockhash=info["blockhash"])
        return self.steps


def confirmed(steps, label):
    return any(s["kind"] == "tx" and s["label"] == label and s.get("confirmed") for s in steps)


def step(steps, label):
    return next((s for s in steps if s["label"] == label), None)


def finalize_report(track, provenance, rows, cases):
    report = {"schema_version": 1, "track": track, "evidence_level": "bitcoin-core-regtest-transactions",
              "provenance": provenance, "catalog_hash": digest(rows), "cases": cases,
              "summary": {"cases": len(cases),
                          "confirmed_transactions": sum(1 for c in cases for s in c["steps"]
                                                        if s["kind"] == "tx" and s.get("confirmed")),
                          "rejected_transactions": sum(1 for c in cases for s in c["steps"]
                                                       if s["kind"] == "tx" and not s["allowed"]
                                                       and not s.get("block_accepted")),
                          "expectation_failures": [c["id"] for c in cases if not c["expectation_met"]]}}
    report["evidence_hash"] = digest(report)
    return report


def script_keys(script):
    """32-byte keys pushed immediately before CHECKSIG/CHECKSIGVERIFY, in script order."""
    found, offset = [], 0
    while offset < len(script):
        opcode = script[offset]
        offset += 1
        data = None
        if 1 <= opcode <= 75:
            data, offset = script[offset:offset + opcode], offset + opcode
        elif opcode == 0x4c:
            size = script[offset]
            data, offset = script[offset + 1:offset + 1 + size], offset + 1 + size
        elif opcode == 0x4d:
            size = int.from_bytes(script[offset:offset + 2], "little")
            data, offset = script[offset + 2:offset + 2 + size], offset + 2 + size
        if data is not None and len(data) == 32 and offset < len(script) and script[offset] in (0xac, 0xad):
            found.append(data)
    return found


def audit_transactions(case, keys=None):
    """Local re-checks of every transaction step; returns a list of problems.

    Signatures are matched to the keys their CHECKSIG opcodes name: witness signatures
    (bottom to top) are consumed by those opcodes in reverse script order.
    """
    problems = []
    spent = {}
    for s in case["steps"]:
        if s["kind"] == "tx" and s.get("confirmed"):
            if s.get("displaced"):
                problems.append(f"{s['label']}: recorded as both displaced and confirmed")
            for p in s["prevouts"]:
                outpoint = (p["txid"], p["vout"])
                if outpoint in spent and spent[outpoint] != s["txid"]:
                    problems.append(f"{s['label']}: confirmed double spend of an outpoint "
                                    f"already spent by {spent[outpoint][:16]}")
                spent[outpoint] = s["txid"]
    for s in case["steps"]:
        if s["kind"] != "tx":
            continue
        try:
            tx = Transaction.parse(s["raw_transaction"])
        except ValidationError as exc:
            problems.append(f"{s['label']}: unparsable ({exc})")
            continue
        if tx.txid != s["txid"]:
            problems.append(f"{s['label']}: txid mismatch")
        if len(tx.inputs) != len(s["prevouts"]):
            problems.append(f"{s['label']}: prevout count mismatch")
            continue
        for txin, prev in zip(tx.inputs, s["prevouts"]):
            if (txin.txid, txin.vout) != (prev["txid"], prev["vout"]):
                problems.append(f"{s['label']}: input does not spend the recorded prevout")
            txin.amount, txin.script_pubkey = prev["amount"], bytes.fromhex(prev["script_pubkey"])
        signature_failure = commitment_failure = False
        for index, txin in enumerate(tx.inputs):
            if len(txin.witness) == 1 and len(txin.witness[0]) in (64, 65) \
                    and txin.script_pubkey[:2] == b"\x51\x20":
                # Taproot key path: the signature must verify against the output key.
                if not check_signature(tx, index, None, txin.script_pubkey[2:], txin.witness[0]):
                    signature_failure = True
                continue
            if len(txin.witness) < 2:
                continue
            script, control = txin.witness[-2], txin.witness[-1]
            if not verify_commitment(txin.script_pubkey, script, control):
                commitment_failure = True
                continue
            leaf = SimpleNamespace(leaf_hash=leaf_hash(script, control[0] & 0xfe))
            signatures = [item for item in txin.witness[:-2] if len(item) in (64, 65)]
            expected = list(reversed(script_keys(script)))
            if len(signatures) != len(expected):
                signature_failure = True
                continue
            for signature, key in zip(signatures, expected):
                if not check_signature(tx, index, leaf, key, signature):
                    signature_failure = True
        reason = s.get("reject_reason") or ""
        s_label = s["label"]
        if (s["allowed"] or s.get("block_accepted")) and (signature_failure or commitment_failure):
            problems.append(f"{s_label}: Core accepted but a local signature/commitment check failed")
        if not s["allowed"] and "Invalid Schnorr signature" in reason and not signature_failure:
            problems.append(f"{s_label}: Core reported a bad signature that verifies locally")
        if not s["allowed"] and "Witness program hash mismatch" in reason and not commitment_failure:
            problems.append(f"{s_label}: Core reported a commitment mismatch that verifies locally")
    return problems


def check_report_envelope(report, track, rows):
    problems = []
    body = {k: v for k, v in report.items() if k != "evidence_hash"}
    if digest(body) != report.get("evidence_hash"):
        problems.append("evidence_hash does not match the report body")
    if report.get("track") != track:
        problems.append("wrong track")
    if report.get("catalog_hash") != digest(rows):
        problems.append("catalog_hash does not match this library's catalog")
    by_id = {r["id"]: r for r in rows}
    seen = set()
    for case in report.get("cases", []):
        row = by_id.get(case.get("id"))
        if row is None:
            problems.append(f"{case.get('id')}: not in catalog")
            continue
        seen.add(row["id"])
        for key, value in row.items():
            if case.get(key) != value:
                problems.append(f"{row['id']}: field {key} differs from the catalog")
        if case.get("expectation_met") != (case.get("outcome") == row["expected"]):
            problems.append(f"{row['id']}: expectation_met is inconsistent")
    if seen != set(by_id):
        problems.append("report does not cover the whole catalog")
    summary = report.get("summary", {})
    if summary.get("expectation_failures") != [c["id"] for c in report.get("cases", []) if not c.get("expectation_met")]:
        problems.append("summary expectation_failures inconsistent")
    return problems


def utxo_input(utxo, sequence=0xfffffffd):
    return TxInput(utxo["txid"], utxo["vout"], utxo["amount"], bytes.fromhex(utxo["script_pubkey"]), sequence)
