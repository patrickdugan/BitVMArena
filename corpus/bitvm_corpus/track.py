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

    def fund(self, outputs):
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
        self._record(kind="fund", label="fund", actor="evaluator", txid=txid,
                     raw_transaction=funding["hex"], outputs=utxos)
        return utxos

    def submit(self, label, actor, tx, *, broadcast=True, note=None):
        raw = tx.serialize().hex()
        result = self.node.rpc("testmempoolaccept", [raw])[0]
        allowed = bool(result["allowed"])
        sent = False
        if allowed and broadcast:
            if self.node.rpc("sendrawtransaction", raw) != tx.txid:
                raise CoreError("Core txid disagrees with local serialization")
            sent = True
        self._record(kind="tx", label=label, actor=actor, raw_transaction=raw, txid=tx.txid,
                     prevouts=[{"txid": i.txid, "vout": i.vout, "amount": i.amount,
                                "script_pubkey": i.script_pubkey.hex()} for i in tx.inputs],
                     allowed=allowed, reject_reason=result.get("reject-reason"),
                     mempool_result=safe_json(result), broadcast=sent, note=note)
        return allowed

    def mine(self, count, note=None):
        start = self.height()
        self.node.mine(count)
        self._record(kind="mine", label=f"mine {count}", actor="environment", blocks=count,
                     from_height=start, note=note)

    def offchain(self, label, actor, **data):
        self._record(kind="offchain", label=label, actor=actor, **data)

    def utxo_unspent(self, txid, vout):
        return self.node.rpc("gettxout", txid, vout) is not None

    def raw(self, txid):
        return self.node.rpc("getrawtransaction", txid)

    def finish(self):
        """Mine a block and attach confirmation evidence to every broadcast transaction."""
        self.node.mine()
        for step in self.steps:
            if step["kind"] == "tx":
                step["confirmed"] = False
                if step["broadcast"]:
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
                                                       if s["kind"] == "tx" and not s["allowed"]),
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
        if s["allowed"] and (signature_failure or commitment_failure):
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
