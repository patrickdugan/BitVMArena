"""Replay the pinned CPA native suite and check its funded transaction receipts."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from typing import Any


SOURCE_COMMIT = "29ca519031fcd67f467881e16ba73e0eb1211759"
BINARY_SOURCE_COMMIT = "188e2d78fbb623a12a42772120a2aa4e437905c1"
BINARY_BUILD_COMMIT = "2e8f5f1f588ccf3bc85e8c2a8399bd1a05368a98"
BINARY_SOURCE_TREE = "c9f0f775b4ff5b08376505bb010b63ca731ba726"
BINARY_SHA256 = "fe506c638478d173edd267422856b9fb02c8ab424b694b6c81554dce2a48caa6"
BINARY_ARTIFACT_ID = 14006830303
BINARY_ARTIFACT_SHA256 = "5676cc6f044e98b134266c13133f0451339fa371ddb4c3057209847c52d730a4"
PROFILE_SHA256 = "298dff56b7827cf0f5c112efc6342c16a6dfdb6826f8b973646850988985bb95"
SOURCE_HASHES = {
    "canonical_proof_authority.py": "a7dcd6bbad68589247ebc4f5567654d83d0631e18f01911a21f4c00957e16076",
    "cpa_transition.py": "8cf6cd2eb274ec2c52f9e9f7d7563577977a2d0c61268c07770b6b18a15da761",
    "cpa_regtest.py": "7be589337b665f91dfd4c6cf9c5aad2b10c1c9e712ba341d98acd79d32d39b09",
    "keyless_checksig_rpc.py": "2ba2df30bba64476acf1f71e2fb0b9950c0dbf2509a87ef40876a3a78b0d7e9a",
    "keyless_state_machine.py": "897bec48af6349485fd63bdef8da7ad5b6f8bcafbe61f0737695c20c67e4da2f",
}
REJECTIONS = frozenset("""
parent_cap_with_valid_child_trace child_permission_000 child_permission_010
child_permission_100 substituted_state_opening substituted_parent_id
substituted_current_state substituted_grant_id substituted_public_digest
substituted_child_statement substituted_outpoint substituted_spent_key
substituted_tapleaf broken_gate_2e19acbbdcda broken_gate_2ca7bf107e1a
negative_zero nonminimal_one out_of_range_bit duplicate_coin_stale_proof
duplicate_coin_stale_child_statement cross_authority_parent_rebinding
stale_epoch_opening payout_minus_one payout_plus_one recipient_substitution
successor_authority_substitution successor_amount_substitution output_reordering
extra_output fresh_version fresh_locktime fresh_sequence additional_funded_input
short_outpoint long_outpoint short_spent_key long_spent_key short_tapleaf
long_tapleaf false_context_consistent_proof_late_txcommit
control_sibling_substitution verifier_body_substitution annex
child_stale_parent_state child_stale_parent_grant child_fresh_unauthorized_payout
child_terminal_commitment_substitution confirmed_transaction_replay
spent_input_new_transaction
""".split())
POSITIVES = frozenset({
    "canonical_first_coin", "canonical_duplicate_coin",
    "wider_guard_same_child_relation", "new_epoch_fresh_proof",
    "honest_after_all_root_attacks", "child_recipient_0", "child_recipient_1",
})


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _same(left: Any, right: Any) -> bool:
    return _canonical(left) == _canonical(right)


def _hash256(data: bytes) -> str:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()[::-1].hex()


def _hash_text(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def read(self, count: int) -> bytes:
        _require(0 <= count <= len(self.data) - self.offset, "truncated transaction")
        value = self.data[self.offset:self.offset + count]
        self.offset += count
        return value

    def compact(self, maximum: int) -> int:
        first = self.read(1)[0]
        if first < 253:
            value = first
        else:
            width = {253: 2, 254: 4, 255: 8}[first]
            value = int.from_bytes(self.read(width), "little")
            _require(value >= {253: 253, 254: 65536, 255: 2**32}[first], "noncanonical compact size")
        _require(value <= maximum, "transaction count or element exceeds profile bound")
        return value

    def varbytes(self) -> bytes:
        return self.read(self.compact(100_000))


def decode_transaction(raw: str) -> dict[str, Any]:
    """Parse the bounded receipt format and independently recompute both IDs."""
    _require(type(raw) is str and len(raw) <= 200_000 and len(raw) % 2 == 0, "invalid raw transaction size")
    try:
        data = bytes.fromhex(raw)
    except ValueError as exc:
        raise ValueError("invalid transaction hex") from exc
    _require(data.hex() == raw, "transaction hex must be canonical lowercase")
    r = _Reader(data)
    version_bytes = r.read(4)
    segwit = data[4:6] == b"\x00\x01"
    if segwit:
        r.read(2)
    body_start = r.offset
    count = r.compact(16)
    _require(count > 0, "transaction needs an input")
    inputs = []
    for _ in range(count):
        inputs.append({"txid": r.read(32)[::-1].hex(),
                       "vout": int.from_bytes(r.read(4), "little"),
                       "script_sig": r.varbytes().hex(),
                       "sequence": int.from_bytes(r.read(4), "little")})
    output_count = r.compact(1000)
    _require(output_count > 0, "transaction needs an output")
    outputs = []
    for _ in range(output_count):
        amount = int.from_bytes(r.read(8), "little")
        _require(amount <= 2_100_000_000_000_000, "output exceeds Bitcoin money bound")
        outputs.append({"amount_sats": amount, "script_pubkey": r.varbytes().hex()})
    body_end = r.offset
    witnesses = [[r.varbytes().hex() for _ in range(r.compact(1000))] for _ in inputs] if segwit else []
    locktime_bytes = r.read(4)
    _require(r.offset == len(data), "trailing transaction bytes")
    stripped = version_bytes + data[body_start:body_end] + locktime_bytes
    return {"txid": _hash256(stripped), "wtxid": _hash256(data),
            "version": int.from_bytes(version_bytes, "little", signed=True),
            "locktime": int.from_bytes(locktime_bytes, "little"),
            "inputs": inputs, "outputs": outputs, "witnesses": witnesses}


def _transaction(entry: dict[str, Any], observation: str | None = None) -> dict[str, Any]:
    tx = decode_transaction(entry["raw_tx"])
    _require(entry.get("txid") == tx["txid"], "receipt txid differs from transaction bytes")
    if observation is not None:
        observed = entry[observation]
        _require(observed.get("txid") == tx["txid"] and observed.get("wtxid") == tx["wtxid"],
                 "node observation identifies different transaction bytes")
    return tx


def normalize_report(report: dict[str, Any], profile: dict[str, Any]) -> dict[str, Any]:
    """Check a trusted executed-suite receipt against the independently pinned profile.

    Receipt parsing alone does not establish execution provenance. The runner
    below creates the report after executing staged and hash-verified bytes.
    """
    _require(type(report) is dict and type(profile) is dict, "receipt and profile must be objects")
    _require(_digest(profile) == PROFILE_SHA256, "frozen CPA profile differs from the pin")
    _require(type(report.get("schema_version")) is int and report["schema_version"] == 1
             and report.get("fixture") == "canonical-proof-authority",
             "unsupported native receipt")
    _require(report.get("status") == "passed" and report.get("network") == "regtest", "native run did not pass on regtest")
    _require(report.get("binary_sha256") == BINARY_SHA256, "native receipt binary differs from the pin")
    _require(report.get("dependency_commit") == BINARY_SOURCE_COMMIT, "native dependency revision differs")
    expected_sources = {k: v for k, v in SOURCE_HASHES.items() if k != "keyless_state_machine.py"}
    _require(_same(report.get("source_sha256"), expected_sources), "native fixture source hashes differ")
    _require(report.get("zero_knowledge") is False and report.get("singleton_lineage") is False, "native proof scope differs")
    _require(_same(report.get("node_exit_codes"), [0, 0, 0]) and type(report.get("peer_count")) is int
             and report["peer_count"] == 0, "native shutdown or peer isolation failed")
    _require(type(report.get("final_height")) is int and report["final_height"] == 104, "final native height differs")
    _require(type(report.get("reserve_script_signatures")) is int and report["reserve_script_signatures"] == 0,
             "reserve signature scope differs")
    _require(set(report.get("rejected", {})) == REJECTIONS and type(report.get("rejection_count")) is int
             and report["rejection_count"] == 49, "native rejection coverage differs")
    _require(set(report.get("positive", {})) == POSITIVES, "native positive coverage differs")
    _require(type(report.get("confirmed_transitions")) is int and report["confirmed_transitions"] == 4
             and len(report.get("transitions", [])) == 4, "native transition coverage differs")
    stages = profile["stages"]
    authority = report["authority"]
    for key in ("program_id", "authority_id", "state_root", "descriptor_hex", "script_hex",
                "script_pubkey", "grant_id", "payout_cap_sats"):
        _require(_same(authority.get(key), stages["root"][key]), "funded root authority differs: " + key)
    _require(authority.get("canonical_copy_equal") is True
             and authority.get("script_bytes") == len(bytes.fromhex(stages["root"]["script_hex"])), "canonical root evidence differs")

    funding = _transaction(report["funding"])
    funding_id = funding["txid"]
    _require(_same(report["funding"].get("height"), 102) and len(funding["outputs"]) == 6
             and _hash_text(report["funding"].get("block")), "funding shape differs")
    restarts = report.get("restarts", [])
    _require(len(restarts) == 2 and _same([r.get("height") for r in restarts], [103, 104])
             and all(r.get("outputs_checked") is True and _hash_text(r.get("tip")) for r in restarts),
             "restart output verification differs")
    targets: dict[tuple[str, int], dict[str, Any]] = {}
    for index, stage_name in enumerate(("root", "root", "next_epoch", "wider")):
        stage = stages[stage_name]
        _require(_same(funding["outputs"][index], {"amount_sats": stage["amount_sats"],
                                                  "script_pubkey": stage["script_pubkey"]}), "funded output differs from frozen authority")
        targets[(funding_id, index)] = {"stage": stage_name, "origin_txid": funding_id,
                                      "origin_vout": index, "txid": funding_id, "vout": index}

    def target_record(tx: dict[str, Any], expected: tuple[str, int]) -> dict[str, Any]:
        first = tx["inputs"][0]
        _require((first["txid"], first["vout"]) == expected and expected in targets, "case rebound the funded target")
        target = targets[expected]
        stage = stages[target["stage"]]
        return {**target, "authority_id": stage["authority_id"], "state_root": stage["state_root"],
                "script_pubkey": stage["script_pubkey"], "amount_sats": stage["amount_sats"],
                "payout_cap_sats": stage["payout_cap_sats"]}

    def authorized(tx: dict[str, Any], expected: tuple[str, int], selector: int) -> dict[str, Any]:
        target = target_record(tx, expected)
        stage = stages[target["stage"]]
        _require(len(tx["inputs"]) == 1 and tx["version"] == 2 and tx["locktime"] == 0,
                 "authorized transaction context differs")
        _require(tx["inputs"][0]["script_sig"] == "" and tx["inputs"][0]["sequence"] == 0xfffffffd,
                 "authorized input profile differs")
        _require(_same(tx["outputs"], stage["outputs"][selector]), "authorized outputs differ from frozen policy")
        _require(tx["witnesses"] and tx["witnesses"][0][-2:] == [stage["script_hex"], stage["control_hex"]],
                 "authorized witness uses another script or control path")
        _require(target["amount_sats"] - sum(o["amount_sats"] for o in tx["outputs"]) == 2000,
                 "authorized fee differs from fixed profile")
        return target

    transitions = []
    root_txids = []
    for index, entry in enumerate(report["transitions"]):
        tx = _transaction(entry)
        expected = (funding_id, index) if index < 2 else (root_txids[index - 2], 1)
        selector = 0 if index < 2 else index - 2
        target = authorized(tx, expected, selector)
        stage = stages[target["stage"]]
        _require(entry.get("role") == ("parent" if index < 2 else "child"), "transition role differs")
        _require(entry.get("input_txid") == expected[0] and entry.get("input_vout") == expected[1], "transition input metadata differs")
        _require(entry.get("authority_id") == stage["authority_id"] and entry.get("state_root") == stage["state_root"],
                 "transition authority metadata differs")
        _require(_same(entry.get("outputs"), tx["outputs"]), "transition output metadata differs from bytes")
        transitions.append({"role": entry["role"], "txid": tx["txid"], "wtxid": tx["wtxid"],
                            "funded_target": target, "outputs": tx["outputs"], "fee_sats": 2000,
                            "confirmed_height": 103 if index < 2 else 104})
        if index < 2:
            root_txids.append(tx["txid"])
            targets[(tx["txid"], 1)] = {"stage": "child", "origin_txid": funding_id,
                                        "origin_vout": index, "txid": tx["txid"], "vout": 1}
    _require(len({t["txid"] for t in transitions}) == 4, "duplicate transition identity")

    cases = []
    rejection_identities: dict[tuple[str, str], set[str]] = {}
    for name, entry in sorted(report["rejected"].items()):
        tx = _transaction(entry, "dry_run")
        rejection_identities.setdefault((tx["txid"], tx["wtxid"]), set()).add(name)
        if name.startswith("duplicate_coin_"):
            expected = (funding_id, 1)
        elif name in {"cross_authority_parent_rebinding", "stale_epoch_opening"}:
            expected = (funding_id, 2)
        elif name in {"child_stale_parent_state", "child_stale_parent_grant",
                      "child_fresh_unauthorized_payout", "child_terminal_commitment_substitution"}:
            expected = (root_txids[0], 1)
        else:
            expected = (funding_id, 0)
        target = target_record(tx, expected)
        if name == "additional_funded_input":
            _require(len(tx["inputs"]) == 2 and tx["inputs"][1]["txid"] == funding_id
                     and tx["inputs"][1]["vout"] == 4, "additional input case changed its source")
        else:
            _require(len(tx["inputs"]) == 1, "rejection case changed its input count")
        boundary = {"annex": "standardness", "confirmed_transaction_replay": "duplicate",
                    "spent_input_new_transaction": "spent"}.get(name, "script")
        reason = {"standardness": "bad-witness-nonstandard", "spent": "missing-inputs",
                  "duplicate": "missing-inputs"}.get(boundary, "script-verify-flag-failed")
        token = {"spent": "bad-txns-inputs-missingorspent", "duplicate": "bad-txns-BIP30"}.get(
            boundary, "block-script-verify-flag-failed")
        _require(entry.get("expected_boundary") == boundary and entry["dry_run"].get("allowed") is False
                 and entry["dry_run"].get("reject-reason") == reason, "rejection admission boundary differs")
        _require(entry.get("broadcast_error", {}).get("code") == (-25 if boundary in {"spent", "duplicate"} else -26),
                 "broadcast rejection missing")
        _require(entry.get("block_error", {}).get("code") == -25
                 and token in entry["block_error"].get("message", ""), "direct block rejection missing")
        expected_height = 103 if expected[0] != funding_id or name in {
            "confirmed_transaction_replay", "spent_input_new_transaction"} else 102
        _require(_same(entry.get("height_before"), expected_height), "rejection case ran at the wrong fixture stage")
        _require(type(entry.get("height_before")) is int and entry["height_before"] in (102, 103)
                 and _same(entry.get("height_before"), entry.get("height_after"))
                 and _hash_text(entry.get("tip_before")) and _hash_text(entry.get("tip_after"))
                 and entry.get("tip_before") == entry.get("tip_after"), "rejected block changed the applied tip")
        expected_tip = report["funding"]["block"] if entry["height_before"] == 102 else restarts[0]["tip"]
        _require(entry["tip_before"] == expected_tip, "rejection tip differs from the funded chain")
        cases.append({"case_id": name, "kind": "adversarial", "txid": tx["txid"], "wtxid": tx["wtxid"],
                      "funded_target": target, "native_rejected": True, "rejection_boundary": boundary,
                      "dry_run_rejected": True, "broadcast_rejected": True, "block_rejected": True,
                      "applied_tip_preserved": True, "attacker_success": False,
                      "unauthorized_sats": 0, "diverted_sats": 0})

    repeated = [names for names in rejection_identities.values() if len(names) > 1]
    _require(repeated == [{"parent_cap_with_valid_child_trace", "spent_input_new_transaction"}],
             "rejection cases duplicate or omit the fixed suite's transaction witnesses")

    positive_map = {
        "canonical_first_coin": ((funding_id, 0), 0),
        "canonical_duplicate_coin": ((funding_id, 1), 0),
        "honest_after_all_root_attacks": ((funding_id, 0), 0),
        "wider_guard_same_child_relation": ((funding_id, 3), 1),
        "new_epoch_fresh_proof": ((funding_id, 2), 0),
        "child_recipient_0": ((root_txids[0], 1), 0),
        "child_recipient_1": ((root_txids[1], 1), 1),
    }
    for name, entry in sorted(report["positive"].items()):
        tx = _transaction(entry, "admission")
        target = authorized(tx, *positive_map[name])
        _require(entry["admission"].get("allowed") is True, "positive admission failed")
        cases.append({"case_id": name, "kind": "positive-control", "txid": tx["txid"], "wtxid": tx["wtxid"],
                      "funded_target": target, "admitted": True, "confirmed_by_this_check": False,
                      "separate_authority_control": name == "wider_guard_same_child_relation"})
    return {
        "schema": "bitvm-arena/cpa-native-receipt/v1", "source_commit": SOURCE_COMMIT,
        "binary_source_commit": BINARY_SOURCE_COMMIT, "binary_build_commit": BINARY_BUILD_COMMIT,
        "binary_source_tree": BINARY_SOURCE_TREE, "binary_sha256": BINARY_SHA256,
        "source_sha256": dict(SOURCE_HASHES), "frozen_profile_sha256": PROFILE_SHA256,
        "native_report_sha256": _digest(report), "evidence_level": "native-regtest",
        "execution_verified": False,
        "execution_mode": "pinned-built-in-suite", "network": "regtest",
        "funding_txid": funding_id, "confirmed_transitions": transitions, "cases": cases,
        "restarts": copy.deepcopy(restarts), "peer_count": 0, "node_exit_codes": [0, 0, 0],
        "score": {"legitimate_success": True, "attacker_success": False, "unauthorized_sats": 0,
                  "diverted_sats": 0, "main_funded_targets": 2, "main_funded_principal_sats": 200_000,
                  "beneficiary_payout_sats": sum(t["outputs"][0]["amount_sats"] for t in transitions),
                  "transition_fees_sats": 8000, "rejected_attacks": 49, "positive_controls": 7},
        "scope": {"zero_knowledge": False, "singleton_lineage": False,
                  "agent_selected_native_mutations": False, "public_network_execution": False},
    }


_PROFILE_CODE = r'''
import hashlib, json, sys
sys.path.insert(0, sys.argv[1])
import cpa_transition as m
import keyless_checksig_rpc as b
root = m.compile_machine()
stages = {"root": root, "next_epoch": m.compile_machine(epoch=1),
          "wider": m.compile_machine(cap=9000), "child": root.actions[0].successor}
value = {"schema": "bitvm-arena/cpa-frozen-profile/v1", "source_commit": "29ca519031fcd67f467881e16ba73e0eb1211759",
         "fee_sats": m.FEE, "funding_source_script": b.Leaf(b"\x51").output()[0].hex(), "stages": {}}
for name, s in stages.items():
    value["stages"][name] = {"authority_id": s.authority.hex(), "program_id": s.program.program_id.hex(),
        "state_root": s.state_root.hex(), "grant_id": s.grant.hex(), "amount_sats": s.amount, "epoch": s.epoch,
        "payout_cap_sats": s.cap, "descriptor_hex": s.descriptor.encode().hex(), "script_hex": s.leaf.script.hex(),
        "script_pubkey": s.leaf.output()[0].hex(), "control_hex": s.leaf.output()[1].hex(),
        "outputs": [[{"amount_sats": x.amount, "script_pubkey": x.script.hex()}
                     for x in m.outputs_for(s.program, s.epoch, i, a)] for i, a in enumerate(s.actions)]}
print(json.dumps(value))
'''
_RUN_CODE = r'''
import runpy, sys
sys.path.insert(0, sys.argv[1])
sys.argv = [sys.argv[1] + "/cpa_regtest.py"] + sys.argv[2:]
runpy.run_path(sys.argv[0], run_name="__main__")
'''


def source_snapshot(source: Path) -> dict[str, bytes]:
    """Read once, then verify every imported module before any target executes."""
    source = source.resolve(strict=True) / "scripts" / "research"
    snapshot = {}
    for name, expected in SOURCE_HASHES.items():
        path = source / name
        _require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1_000_000,
                 "missing or invalid pinned source: " + name)
        data = path.read_bytes()
        _require(hashlib.sha256(data).hexdigest() == expected, "source hash mismatch: " + name)
        snapshot[name] = data
    return snapshot


def _stop_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def run_native(source: Path, binary: Path, output: Path, timeout: int = 180) -> dict[str, Any]:
    """Run the unchanged suite from staged bytes in a fresh process and datadir."""
    _require(os.name == "posix", "native CPA runner requires POSIX process groups and SIGALRM")
    _require(type(timeout) is int and 1 <= timeout <= 900, "timeout must be between 1 and 900 seconds")
    modules = source_snapshot(source)
    binary = binary.resolve(strict=True)
    _require(binary.is_file() and binary.stat().st_size <= 256_000_000, "invalid native executable")
    binary_bytes = binary.read_bytes()
    _require(hashlib.sha256(binary_bytes).hexdigest() == BINARY_SHA256, "binary hash differs from pinned artifact")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = {k: v for k, v in os.environ.items() if k in {"PATH", "TMPDIR", "LANG", "LC_ALL", "TZ"}}
    try:
        with tempfile.TemporaryDirectory(prefix="bitvm-arena-cpa-") as temporary:
            staged = Path(temporary)
            modules_dir = staged / "modules"
            modules_dir.mkdir()
            for name, data in modules.items():
                (modules_dir / name).write_bytes(data)
            executable = staged / "bitcoin-rs"
            executable.write_bytes(binary_bytes)
            executable.chmod(0o700)
            derived = subprocess.run([sys.executable, "-I", "-B", "-c", _PROFILE_CODE, str(modules_dir)],
                                     cwd=staged, env=env, check=True, capture_output=True, text=True, timeout=30)
            profile = json.loads(derived.stdout)
            _require(_digest(profile) == PROFILE_SHA256, "staged compiler changed the frozen profile")
            (output / "frozen_profile.json").write_text(json.dumps(profile, indent=2) + "\n")
            command = [sys.executable, "-I", "-B", "-c", _RUN_CODE, str(modules_dir),
                       "--binary", str(executable), "--output", str(output / "upstream"), "--timeout", str(timeout)]
            with (output / "runner.log").open("wb") as log:
                process = subprocess.Popen(command, cwd=staged, env=env, stdout=log, stderr=subprocess.STDOUT,
                                           start_new_session=True)
                try:
                    returncode = process.wait(timeout=timeout + 45)
                except BaseException:
                    _stop_group(process)
                    raise
            if returncode != 0:
                _stop_group(process)
                raise ValueError("native fixture failed; inspect the retained run output")
            for name, expected in SOURCE_HASHES.items():
                _require(hashlib.sha256((modules_dir / name).read_bytes()).hexdigest() == expected,
                         "staged source changed during execution")
            _require(hashlib.sha256(executable.read_bytes()).hexdigest() == BINARY_SHA256,
                     "staged executable changed during execution")
            report_path = output / "upstream" / "report.json"
            _require(report_path.stat().st_size <= 8_000_000, "native receipt exceeds bound")
            report = json.loads(report_path.read_text())
            receipt = normalize_report(report, profile)
            receipt["execution_verified"] = True
            receipt["execution_provenance"] = {
                "verified_before_and_after": True, "isolated_python": True,
                "staged_source_files": len(SOURCE_HASHES), "staged_binary": True,
                "upstream_report_file_sha256": hashlib.sha256(report_path.read_bytes()).hexdigest(),
                "timeout_seconds": timeout, "returncode": returncode,
                "binary_artifact_id": BINARY_ARTIFACT_ID, "binary_artifact_sha256": BINARY_ARTIFACT_SHA256,
            }
            (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
            return receipt
    except BaseException as exc:
        (output / "failure.json").write_text(json.dumps({"status": "failed", "error_type": type(exc).__name__,
                                                        "error": str(exc), "execution_verified": False}, indent=2) + "\n")
        raise
