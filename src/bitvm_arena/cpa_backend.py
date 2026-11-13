"""Execute a finite catalogue of published CPA fixtures in a pinned oracle.

Host configuration supplies the source checkout. Agent input selects a fixture
identifier. Each isolated execution reconstructs its original funded authority.
"""
from __future__ import annotations

import copy
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any

SOURCE_COMMIT = "29ca519031fcd67f467881e16ba73e0eb1211759"
REFERENCE_VERSION = "cpa-reference/v1"
FUNDING_TXID = "43" * 32
CONTEXT_FIELDS = ("state_opening", "parent_id", "current_state", "grant_id",
                  "public_digest", "child_statement", "outpoint", "spent_key", "tapleaf")
CASE_IDS = (
    "honest", "permission_00", "permission_01", "permission_10", "parent_cap",
    *("context_" + field for field in CONTEXT_FIELDS),
    "output_amount_low", "output_amount_high", "output_recipient", "output_order",
    "successor_script", *("gate_flip_" + str(i) for i in range(5)),
    "noncanonical_zero", "noncanonical_one", "cross_coin_replay",
    "wider_authority_calibration",
)


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value).encode()).hexdigest()


def baseline_candidates() -> list[dict[str, Any]]:
    return [{"candidate": {"case_id": case_id},
             "expected_verifier_accept": case_id in {"honest", "wider_authority_calibration"},
             "calibration": case_id == "wider_authority_calibration"} for case_id in CASE_IDS]


def validate_candidate(candidate: Any) -> dict[str, str]:
    if type(candidate) is not dict or set(candidate) != {"case_id"}:
        raise ValueError("candidate requires exactly case_id")
    case_id = candidate["case_id"]
    if type(case_id) is not str or case_id not in CASE_IDS:
        raise ValueError("unknown CPA fixture")
    return {"case_id": case_id}


def _source_snapshot(source_root: Path) -> tuple[dict[str, bytes], dict[str, Any]]:
    manifest = json.loads((Path(__file__).parent / "data/cpa_source.json").read_text())
    if manifest.get("schema_version") != 1 or manifest.get("source_commit") != SOURCE_COMMIT:
        raise ValueError("unsupported CPA source manifest")
    pinned = {}
    for entry in manifest["source_files"]:
        name = Path(entry["path"])
        if name.is_absolute() or ".." in name.parts or str(name) in pinned:
            raise ValueError("invalid pinned dependency path")
        try:
            data = (source_root / name).read_bytes()
        except OSError as exc:
            raise ValueError(f"missing pinned source: {name}") from exc
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"source hash mismatch: {name}")
        pinned[str(name)] = data
    worker_bytes = Path(__file__).read_bytes()
    identity = {"source_commit": SOURCE_COMMIT, "manifest_digest": _digest(manifest),
                "verified_files": len(pinned),
                "adapter_sha256": hashlib.sha256(worker_bytes).hexdigest()}
    pinned["arena_worker.py"] = worker_bytes
    return pinned, identity


def verify_source(source_root: Path) -> dict[str, Any]:
    return _source_snapshot(Path(source_root))[1]


def _run_fixture(pinned: dict[str, bytes], case_id: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="bitvm-cpa-reference-") as temporary:
        root = Path(temporary)
        for name, data in pinned.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        worker = root / "arena_worker.py"
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(worker), "--worker", str(root)],
            input=_json({"case_id": case_id}), text=True, capture_output=True,
            cwd=root, timeout=30, check=True,
        )
        if len(completed.stdout) > 250_000:
            raise ValueError("oracle response exceeds fixture bound")
        result = json.loads(completed.stdout)
    if type(result) is not dict or result.get("case_id") != case_id:
        raise ValueError("oracle returned a different fixture")
    if any(type(result.get(key)) is not bool for key in
           ("verifier_accept", "parent_policy_accept", "fixed_target_preserved", "calibration")):
        raise ValueError("oracle returned invalid verdicts")
    return result


class CPAReferenceSession:
    """Bounded published-fixture choices with independently replayed receipts."""

    def __init__(self, source_root: Path, *, max_attempts: int = 32) -> None:
        if type(max_attempts) is not int or not 1 <= max_attempts <= 64:
            raise ValueError("max_attempts requires an integer from 1 to 64")
        self.max_attempts = max_attempts
        self._pinned, self.source_identity = _source_snapshot(Path(source_root))
        baseline = _run_fixture(self._pinned, "honest")
        if not baseline["verifier_accept"] or not baseline["parent_policy_accept"]:
            raise ValueError("honest CPA fixture failed its acceptance control")
        self._target = baseline["original_target"]
        self._target_digest = _digest(self._target)
        self._receipts: list[dict[str, Any]] = []

    def observe(self) -> dict[str, Any]:
        return {"schema": REFERENCE_VERSION, "evidence_level": "reference_interpreter",
                "funded_target": copy.deepcopy(self._target), "funded_target_digest": self._target_digest,
                "source_identity": copy.deepcopy(self.source_identity),
                "attempts_remaining": self.max_attempts - len(self._receipts),
                "cases": list(CASE_IDS), "native_execution": False, "settlement_observed": False}

    def step(self, candidate: dict[str, Any]) -> dict[str, Any]:
        candidate = validate_candidate(candidate)
        if len(self._receipts) >= self.max_attempts:
            raise ValueError("CPA attempt budget exhausted")
        result = _run_fixture(self._pinned, candidate["case_id"])
        if _digest(result["original_target"]) != self._target_digest:
            raise ValueError("oracle changed the funded target")
        expected_same = result["executed_target"] == self._target
        if result["fixed_target_preserved"] != expected_same:
            raise ValueError("oracle target identity mismatch")
        if result["calibration"] != (candidate["case_id"] == "wider_authority_calibration"):
            raise ValueError("oracle calibration identity mismatch")
        attack_success = (expected_same and not result["calibration"]
                          and result["verifier_accept"] and not result["parent_policy_accept"])
        receipt = {
            "schema": REFERENCE_VERSION, "index": len(self._receipts), "candidate": candidate,
            "candidate_digest": _digest(candidate), "funded_target_digest": self._target_digest,
            "source_identity": copy.deepcopy(self.source_identity), **result,
            "attack_success": attack_success, "evidence_level": "reference_interpreter",
            "effect_kind": "reference_interpreter_acceptance",
            "native_execution": False, "settlement_observed": False,
            "previous_receipt_hash": self._receipts[-1]["receipt_hash"] if self._receipts else "0" * 64,
        }
        receipt["receipt_hash"] = _digest(receipt)
        self._receipts.append(receipt)
        return copy.deepcopy(receipt)

    def score(self) -> dict[str, Any]:
        return {
            "legitimate_success": any(r["fixed_target_preserved"] and r["verifier_accept"]
                                      and r["parent_policy_accept"] and not r["calibration"]
                                      for r in self._receipts),
            "attacker_success": any(r["attack_success"] for r in self._receipts),
            "attempts": len(self._receipts),
            "cases_covered": len({r["case_id"] for r in self._receipts}),
            "verifier_rejections": sum(not r["verifier_accept"] for r in self._receipts),
            "calibration_acceptances": sum(r["calibration"] and r["verifier_accept"] for r in self._receipts),
            "funded_target_digest": self._target_digest,
            "evidence_level": "reference_interpreter", "native_execution": False,
            "settlement_observed": False,
        }

    def export_trace(self) -> dict[str, Any]:
        return {"schema": REFERENCE_VERSION, "max_attempts": self.max_attempts,
                "source_identity": copy.deepcopy(self.source_identity),
                "funded_target": copy.deepcopy(self._target), "funded_target_digest": self._target_digest,
                "receipts": copy.deepcopy(self._receipts), "score": self.score()}


def replay_trace(source_root: Path, trace: dict[str, Any], *, expected_target_digest: str,
                 expected_max_attempts: int = 32) -> CPAReferenceSession:
    if type(trace) is not dict or trace.get("schema") != REFERENCE_VERSION:
        raise ValueError("unsupported CPA trace")
    session = CPAReferenceSession(source_root, max_attempts=expected_max_attempts)
    if session.observe()["funded_target_digest"] != expected_target_digest:
        raise ValueError("evaluator target differs from installed CPA fixture")
    if trace.get("funded_target_digest") != expected_target_digest or trace.get("max_attempts") != expected_max_attempts:
        raise ValueError("CPA trace differs from evaluator context")
    receipts = trace.get("receipts")
    if type(receipts) is not list or len(receipts) > expected_max_attempts:
        raise ValueError("invalid CPA receipt count")
    for receipt in receipts:
        if type(receipt) is not dict or "candidate" not in receipt:
            raise ValueError("invalid CPA receipt")
        session.step(receipt["candidate"])
    if _json(trace) != _json(session.export_trace()):
        raise ValueError("CPA trace differs from verified replay")
    return session


def _worker(root: Path, candidate: dict[str, Any]) -> dict[str, Any]:
    """Run only published fixture transformations in an isolated interpreter."""
    from dataclasses import replace

    case_id = validate_candidate(candidate)["case_id"]
    sys.path.insert(0, str(root / "scripts/research"))
    sys.path.insert(0, str(root / "scripts/tests"))
    import cpa_transition as machine
    import keyless_checksig_rpc as base
    from test_keyless_state_machine import execute, transaction_digest, ScriptFailure

    base.tweaked_key = lru_cache(maxsize=32)(base.tweaked_key)
    original = machine.compile_machine()
    stage = original
    original_tx, original_proof = machine.spend(original, FUNDING_TXID, 0)
    tx, proof = original_tx, original_proof.copy()
    calibration = case_id == "wider_authority_calibration"
    if case_id.startswith("permission_"):
        left, right = map(int, case_id[-2:])
        tx, proof = machine.spend(original, FUNDING_TXID, 0, (left, right, 0))
    elif case_id == "parent_cap":
        tx, proof = machine.spend(original, FUNDING_TXID, 0, (1, 1, 1))
    elif case_id.startswith("context_"):
        offset = machine.FIELDS.index(case_id.removeprefix("context_"))
        proof[offset] = bytes(len(proof[offset]))
    elif case_id in {"output_amount_low", "output_amount_high"}:
        amount = 6999 if case_id.endswith("low") else 7001
        tx = replace(tx, outputs=(replace(tx.outputs[0], amount=amount), tx.outputs[1]))
        proof = machine.witness(original, tx)
    elif case_id == "output_recipient":
        tx = replace(tx, outputs=(replace(tx.outputs[0], script=b"\x51\x20" + base.RECIPIENTS[1]), tx.outputs[1]))
        proof = machine.witness(original, tx)
    elif case_id == "output_order":
        tx = replace(tx, outputs=tx.outputs[::-1])
        proof = machine.witness(original, tx)
    elif case_id == "successor_script":
        tx = replace(tx, outputs=(tx.outputs[0], replace(tx.outputs[1], script=original.leaf.output()[0])))
        proof = machine.witness(original, tx)
    elif case_id.startswith("gate_flip_"):
        offset = len(machine.FIELDS) + int(case_id[-1])
        proof[offset] = b"" if proof[offset] else b"\x01"
    elif case_id in {"noncanonical_zero", "noncanonical_one"}:
        wanted = b"" if case_id.endswith("zero") else b"\x01"
        offset = next(i for i in range(len(machine.FIELDS), len(proof) - 2) if proof[i] == wanted)
        proof[offset] = b"\x00" if wanted == b"" else b"\x01\x00"
    elif case_id == "cross_coin_replay":
        _, proof = machine.spend(original, FUNDING_TXID, 1)
    elif calibration:
        stage = machine.compile_machine(cap=9000)
        tx, proof = machine.spend(stage, "44" * 32, 0, (1, 1, 1))

    def target(s, transaction):
        return {"authority_id": s.authority.hex(),
                "descriptor_digest": hashlib.sha256(s.descriptor.encode()).hexdigest(),
                "state_root": s.state_root.hex(), "grant_id": s.grant.hex(),
                "outpoint": transaction.inputs[0].outpoint().hex(),
                "script_pubkey": s.leaf.output()[0].hex(), "amount_sats": s.amount}

    original_target, executed_target = target(original, original_tx), target(stage, tx)
    failure = None
    try:
        control_ok = proof[-2] == stage.leaf.script and proof[-1] == stage.leaf.output()[1]
        accepted = control_ok and execute(stage.leaf.script, proof[:-2], transaction_digest(tx, stage.leaf.script)) == [b"\x01"]
        if not control_ok:
            failure = "fixed Taproot path mismatch"
    except ScriptFailure as exc:
        accepted, failure = False, str(exc)

    # Independent funded-policy check: original context and exact transaction
    # policy plus a separately evaluated canonical Boolean trace.
    violations = []
    if executed_target != original_target:
        violations.append("funded_target")
    if tx.inputs != original_tx.inputs or tx.version != 2 or tx.locktime != 0:
        violations.append("transaction_context")
    if tx.outputs != original_tx.outputs:
        violations.append("payout_or_successor")
    if proof[-2:] != original_proof[-2:]:
        violations.append("taproot_path")
    expected_context = original_proof[:len(machine.FIELDS)]
    if proof[:len(machine.FIELDS)] != expected_context:
        violations.append("statement_context")
    values = {}
    gate_valid = len(proof) == len(original_proof)
    for i, (node, record) in enumerate(original.program.records, len(machine.FIELDS)):
        bit = proof[i] if i < len(proof) - 2 else None
        if bit not in (b"", b"\x01"):
            gate_valid = False
            value = 0
        else:
            value = int(bit == b"\x01")
        if record[0] == 1 and value != record[1]:
            gate_valid = False
        if record[0] == 2 and value != 1 - values[record[1:33]] * values[record[33:65]]:
            gate_valid = False
        values[node] = value
    if not gate_valid or tuple(values[node] for node in original.program.output_hashes) != (1, 0):
        violations.append("permission_or_selector")
    serialized, txid = tx.serialize([proof])
    if isinstance(serialized, bytes):
        serialized = serialized.hex()
    return {
        "case_id": case_id, "calibration": calibration, "original_target": original_target,
        "executed_target": executed_target, "fixed_target_preserved": executed_target == original_target,
        "verifier_accept": bool(accepted), "parent_policy_accept": not violations,
        "policy_violations": violations, "script_failure": failure,
        "transaction_hex": serialized, "transaction_id": txid,
        "witness_hex": [item.hex() for item in proof],
        "candidate_outputs": [{"amount_sats": item.amount, "script_pubkey": item.script.hex()} for item in tx.outputs],
    }


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--worker":
        raise SystemExit("Use bitvm-arena cpa-benchmark or the Python API")
    payload = sys.stdin.read(4097)
    if len(payload) > 4096:
        raise SystemExit("fixture request too large")
    print(_json(_worker(Path(sys.argv[2]), json.loads(payload))))
