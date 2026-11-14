"""Per-case isolated-regtest execution and receipt verification for CPA campaigns.

Individual campaign cases connect to native regtest execution only when their
scenario has native_supported=True and no unmet evidence gates (ZK delegation,
HF CHECKSIG, P2MR, or singleton lineage). Script-oracle, synthetic-simulator,
and native-execution outcomes remain in distinct fields on every step and score.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from typing import Any

from .cpa_campaign import (
    DEFAULT_EVIDENCE_GATES,
    EVIDENCE_GATE_KEYS,
    SOURCE_COMMIT,
    _canonical,
    _digest,
    _invoke_worker,
    _require,
    _source_snapshot,
    evaluate_parent_policy,
    get_campaign_scenario,
    load_campaign_scenarios,
    score_candidate_outcome,
    validate_candidate_proposal,
)
from .cpa_native import SOURCE_HASHES, _stop_group, decode_transaction, source_snapshot

NATIVE_REPORT_SCHEMA = "bitvm-arena/cpa-campaign-native-report/v1"
NATIVE_RECEIPT_SCHEMA = "bitvm-arena/cpa-campaign-native-receipt/v1"
PROVENANCE_SCHEMA = "bitvm-arena/cpa-campaign-provenance/v1"


def _hash_text(value: Any) -> bool:
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def load_provenance_manifest() -> dict[str, Any]:
    manifest = json.loads(
        (Path(__file__).parent / "data/cpa_campaign_provenance.json").read_text(encoding="utf-8")
    )
    _require(
        manifest.get("schema") == PROVENANCE_SCHEMA
        and manifest.get("source_commit") == SOURCE_COMMIT
        and manifest.get("source_sha256") == SOURCE_HASHES,
        "unsupported CPA campaign provenance manifest",
    )
    return manifest


def verify_binary_provenance(binary_sha256: str) -> dict[str, Any]:
    _require(_hash_text(binary_sha256), "binary_sha256 must be 64 lowercase hex characters")
    manifest = load_provenance_manifest()
    for entry in manifest["approved_binaries"]:
        if entry["binary_sha256"] == binary_sha256:
            return copy.deepcopy(entry)
    raise ValueError(f"unpinned CPA native binary SHA256: {binary_sha256}")


def check_native_eligibility(scenario_id: str) -> Any:
    scenario = get_campaign_scenario(scenario_id)
    if not scenario.native_supported or scenario.required_evidence_gates:
        gates = ", ".join(scenario.required_evidence_gates) or "native_unsupported"
        raise ValueError(
            f"scenario {scenario_id} cannot connect to native regtest; unmet evidence gates: {gates}"
        )
    return scenario


def default_native_campaign_specs(split: str = "all") -> list[dict[str, Any]]:
    """Build deterministic per-case native specs for all eligible scenarios in split."""
    specs: list[dict[str, Any]] = []
    for scenario in load_campaign_scenarios(split):
        if not scenario.native_supported:
            continue
        check_native_eligibility(scenario.scenario_id)
        if scenario.adversarial_proposals:
            proposals = [copy.deepcopy(item["proposal"]) for item in scenario.adversarial_proposals]
            has_honest_parent = any(
                item["expected_script_accept"]
                and not item["expected_calibration"]
                and item["proposal"].get("stage_role", "parent") == "parent"
                for item in scenario.adversarial_proposals
            )
            has_honest_child = any(
                item["expected_script_accept"]
                and not item["expected_calibration"]
                and item["proposal"].get("stage_role") == "child"
                for item in scenario.adversarial_proposals
            )
            if not has_honest_parent:
                proposals.extend(copy.deepcopy(p) for p in scenario.honest_proposals)
            elif scenario.requires_child_completion and not has_honest_child:
                proposals.extend(
                    copy.deepcopy(p)
                    for p in scenario.honest_proposals
                    if p.get("stage_role") == "child"
                )
            mode = "adversarial_and_honest"
        else:
            proposals = [copy.deepcopy(p) for p in scenario.honest_proposals]
            mode = "honest_control"
        specs.append({
            "case_id": f"{scenario.scenario_id}:{mode}",
            "scenario_id": scenario.scenario_id,
            "proposals": proposals,
        })
    return specs


def _expected_rejection_rules(boundary: str) -> tuple[str, int, str]:
    table = {
        "script": ("script-verify-flag-failed", -26, "block-script-verify-flag-failed"),
        "standardness": ("bad-witness-nonstandard", -26, "block-script-verify-flag-failed"),
        "duplicate": ("missing-inputs", -25, "bad-txns-BIP30"),
        "spent": ("missing-inputs", -25, "bad-txns-inputs-missingorspent"),
        "nonfinal": ("non-final", -26, "bad-txns-nonfinal"),
    }
    _require(boundary in table, f"unsupported native rejection boundary: {boundary}")
    return table[boundary]


def verify_native_campaign_receipt(report: dict[str, Any], source_root: Path) -> dict[str, Any]:
    """Verify an external native campaign report against source bytes and provenance pins.

    Parsing and verifying a report returns execution_verified=False. Only live
    execution through run_native_campaign_cases sets execution_verified=True.
    """
    _require(type(report) is dict, "native campaign report must be an object")
    _require(report.get("execution_verified") is not True,
             "unexecuted report input cannot pre-assert execution_verified=True")
    _require(
        report.get("schema") == NATIVE_REPORT_SCHEMA
        and report.get("status") == "passed"
        and report.get("network") == "regtest"
        and report.get("source_commit") == SOURCE_COMMIT,
        "unsupported or failed native campaign report",
    )
    provenance = verify_binary_provenance(report.get("binary_sha256", ""))
    _require(report.get("binary_provenance") == provenance,
             "native report binary_provenance metadata differs from pinned manifest")
    _require(report.get("source_sha256") == SOURCE_HASHES,
             "native report source_sha256 differs from pinned CPA modules")
    _require(report.get("evidence_gates") == DEFAULT_EVIDENCE_GATES,
             "native report cannot claim unverified evidence gates")

    pinned_worker, source_identity = _source_snapshot(Path(source_root))
    source_snapshot(Path(source_root))

    cases = report.get("cases")
    _require(type(cases) is list and len(cases) >= 1, "native report requires at least one case")
    seen_case_ids: set[str] = set()
    seen_funding_txids: set[str] = set()
    seen_step_evidence: set[tuple[str, str, str]] = set()
    normalized_cases: list[dict[str, Any]] = []

    for case in cases:
        _require(type(case) is dict, "case entry must be an object")
        case_id = case.get("case_id")
        scenario_id = case.get("scenario_id")
        _require(type(case_id) is str and case_id and case_id not in seen_case_ids,
                 f"duplicate or invalid native case_id: {case_id}")
        seen_case_ids.add(case_id)
        scenario = check_native_eligibility(scenario_id)
        _require(
            case.get("split") == scenario.split
            and case.get("family") == scenario.family
            and case.get("calibration_scenario") == scenario.calibration,
            f"case metadata mismatch for {case_id}",
        )

        funding = case.get("funding")
        _require(type(funding) is dict and funding.get("height") == 102 and _hash_text(funding.get("block")),
                 f"invalid funding height or block hash in {case_id}")
        decoded_funding = decode_transaction(funding.get("raw_tx", ""))
        funding_txid = decoded_funding["txid"]
        _require(funding.get("txid") == funding_txid and funding_txid not in seen_funding_txids,
                 f"duplicate or mismatched funding_txid in {case_id}")
        seen_funding_txids.add(funding_txid)
        expected_tag = "6a20" + hashlib.sha256(case_id.encode("utf-8")).hexdigest()
        _require(
            len(decoded_funding["outputs"]) == 7
            and decoded_funding["outputs"][5] == {"amount_sats": 0, "script_pubkey": expected_tag},
            f"funding transaction case-binding tag mismatch in {case_id} (swapped or copied funding)",
        )

        bootstrap = _invoke_worker(pinned_worker, {
            "mode": "bootstrap",
            "scenario_id": scenario.scenario_id,
            "funding_txid_override": funding_txid,
        })
        expected_target = bootstrap["funded_target"]
        expected_target_digest = _digest(expected_target)
        expected_cal_target = bootstrap["calibration_target"]
        _require(
            case.get("funded_target") == expected_target
            and case.get("funded_target_digest") == expected_target_digest,
            f"swapped or mismatched target identity in {case_id}",
        )
        _require(
            decoded_funding["outputs"][0] == {
                "amount_sats": expected_target["amount_sats"],
                "script_pubkey": expected_target["context"]["script_pubkey"],
            }
            and decoded_funding["outputs"][3] == {
                "amount_sats": expected_cal_target["amount_sats"],
                "script_pubkey": expected_cal_target["script_pubkey"],
            },
            f"funded outputs differ from compiled CPA stage in {case_id}",
        )

        steps = case.get("steps")
        _require(type(steps) is list and 1 <= len(steps) <= 32, f"invalid steps list in {case_id}")

        current_height = 102
        current_tip = funding["block"]
        parent_confirmed = False
        parent_confirmed_proposal: dict[str, Any] | None = None
        authenticated_parent_txid: str | None = None
        child_completed = False
        calibration_confirmed = False
        prev_hash = "0" * 64
        seen_case_proposals: set[tuple[str, int]] = set()
        normalized_steps: list[dict[str, Any]] = []

        for idx, step in enumerate(steps):
            _require(type(step) is dict and step.get("index") == idx, f"invalid step index in {case_id}")
            raw_proposal, canonical_proposal = validate_candidate_proposal(step.get("raw_proposal"))
            _require(step.get("canonical_proposal") == canonical_proposal,
                     f"canonical_proposal mismatch in {case_id} step {idx}")
            if canonical_proposal["target_coin"] == "calibration_wider_parent":
                _require(scenario.calibration, f"unexpected calibration coin in non-calibration case {case_id}")

            stage_role = canonical_proposal["stage_role"]
            is_calibration = canonical_proposal["target_coin"] == "calibration_wider_parent"
            if stage_role == "child":
                _require(authenticated_parent_txid is not None,
                         f"child step without confirmed parent in {case_id}")
            if canonical_proposal["post_confirm_mode"] != "none":
                _require(parent_confirmed and parent_confirmed_proposal is not None,
                         f"post_confirm_mode without confirmed parent in {case_id}")

            reconstructed = _invoke_worker(pinned_worker, {
                "mode": "reconstruct",
                "scenario_id": scenario.scenario_id,
                "funding_txid_override": funding_txid,
                "proposal": canonical_proposal,
                "authenticated_parent_txid": authenticated_parent_txid,
                "confirmed_parent_proposal": parent_confirmed_proposal,
            })
            decoded_tx = decode_transaction(step.get("raw_tx", ""))
            _require(
                step.get("raw_tx") == reconstructed["transaction_hex"]
                and decoded_tx["txid"] == step.get("txid") == reconstructed["txid"]
                and decoded_tx["wtxid"] == step.get("wtxid") == reconstructed["wtxid"]
                and step.get("witness_hex") == reconstructed["witness_hex"],
                f"copied or altered transaction/witness bytes in {case_id} step {idx}",
            )

            prop_sig = (_canonical(canonical_proposal), current_height)
            _require(prop_sig not in seen_case_proposals,
                     f"duplicate copied step proposal at same height in {case_id}")
            seen_case_proposals.add(prop_sig)

            global_ev_key = (funding_txid, decoded_tx["txid"], decoded_tx["wtxid"])
            if canonical_proposal["post_confirm_mode"] == "none":
                _require(global_ev_key not in seen_step_evidence,
                         f"copied transaction evidence across steps/cases in {case_id}")
                seen_step_evidence.add(global_ev_key)

            expected_origin = {
                "origin_txid": funding_txid,
                "origin_vout": 3 if is_calibration else 0,
                "spent_txid": authenticated_parent_txid if stage_role == "child" else funding_txid,
                "spent_vout": 1 if stage_role == "child" else (3 if is_calibration else 0),
                "stage_role": stage_role,
            }
            _require(step.get("funded_origin") == expected_origin,
                     f"funded_origin lineage mismatch in {case_id} step {idx}")

            if is_calibration:
                utxo_available = not calibration_confirmed
            elif stage_role == "parent":
                utxo_available = not parent_confirmed
            else:
                utxo_available = parent_confirmed and not child_completed

            annex_absent = canonical_proposal["annex_hex"] is None
            all_seq_final = all(inp["sequence"] == 0xFFFFFFFF for inp in decoded_tx["inputs"])
            locktime_final = (
                decoded_tx["locktime"] == 0
                or all_seq_final
                or decoded_tx["locktime"] <= current_height
            )
            script_valid = bool(reconstructed["script_valid"])
            expected_accepted = bool(script_valid and utxo_available and locktime_final and annex_absent)

            script_oracle = step.get("script_oracle")
            _require(
                type(script_oracle) is dict
                and script_oracle.get("executed") is True
                and script_oracle.get("accepted") == expected_accepted
                and script_oracle.get("script_valid") == script_valid
                and script_oracle.get("utxo_available") == utxo_available
                and script_oracle.get("locktime_final") == locktime_final
                and script_oracle.get("annex_absent") == annex_absent
                and script_oracle.get("op_count") == reconstructed["op_count"],
                f"script_oracle field mismatch in {case_id} step {idx}",
            )
            _require(step.get("synthetic_simulator") == {"executed": False, "accepted": None},
                     f"synthetic_simulator field contaminated in {case_id} step {idx}")
            _require(step.get("evidence_gates") == DEFAULT_EVIDENCE_GATES,
                     f"unverified evidence gate claimed in {case_id} step {idx}")

            native = step.get("native_execution")
            _require(
                type(native) is dict
                and native.get("executed") is True
                and native.get("execution_verified") is False
                and native.get("binary_sha256") == report["binary_sha256"],
                f"forged or invalid native_execution header in {case_id} step {idx}",
            )
            _require(
                native.get("height_before") == current_height
                and native.get("tip_before") == current_tip,
                f"wrong chain height or tip before {case_id} step {idx}",
            )
            dry_run = native.get("dry_run")
            _require(
                type(dry_run) is dict
                and dry_run.get("txid") == decoded_tx["txid"]
                and dry_run.get("wtxid") == decoded_tx["wtxid"],
                f"native dry_run observation does not match transaction bytes in {case_id} step {idx}",
            )

            if expected_accepted:
                _require(
                    native.get("accepted") is True
                    and dry_run.get("allowed") is True
                    and native.get("settlement_observed") is True
                    and native.get("confirmed_height") == current_height + 1
                    and native.get("height_after") == current_height + 1
                    and _hash_text(native.get("confirmed_block"))
                    and native["confirmed_block"] != current_tip
                    and native.get("tip_after") == native["confirmed_block"]
                    and native.get("rejection_boundary") is None
                    and native.get("spent_input_verified_absent") is True,
                    f"confirmed native transition missing valid block/height/settlement proof in {case_id} step {idx}",
                )
                expected_live = [
                    out for out in decoded_tx["outputs"] if not out["script_pubkey"].startswith("6a")
                ]
                _require(native.get("live_outputs_verified") == expected_live,
                         f"confirmed live outputs mismatch in {case_id} step {idx}")
                current_height = native["height_after"]
                current_tip = native["confirmed_block"]
                if is_calibration:
                    calibration_confirmed = True
                elif stage_role == "parent":
                    parent_confirmed = True
                    parent_confirmed_proposal = copy.deepcopy(canonical_proposal)
                    succ = expected_target["intended_successor"]
                    if (
                        len(decoded_tx["outputs"]) >= 2
                        and decoded_tx["outputs"][1]["amount_sats"] == succ["amount_sats"]
                        and decoded_tx["outputs"][1]["script_pubkey"] == succ["script_pubkey"]
                    ):
                        authenticated_parent_txid = decoded_tx["txid"]
                else:
                    child_completed = True
            else:
                if not utxo_available:
                    expected_boundary = (
                        "duplicate"
                        if canonical_proposal["post_confirm_mode"] == "replay_confirmed_tx"
                        else "spent"
                    )
                elif not locktime_final:
                    expected_boundary = "nonfinal"
                elif not annex_absent:
                    expected_boundary = "standardness"
                else:
                    expected_boundary = "script"
                reason, bcast_code, block_token = _expected_rejection_rules(expected_boundary)
                _require(
                    native.get("accepted") is False
                    and native.get("settlement_observed") is False
                    and native.get("confirmed_height") is None
                    and native.get("confirmed_block") is None
                    and native.get("rejection_boundary") == expected_boundary
                    and dry_run.get("allowed") is False
                    and dry_run.get("reject-reason") == reason
                    and native.get("broadcast_error", {}).get("code") == bcast_code
                    and native.get("block_error", {}).get("code") == -25
                    and block_token in native.get("block_error", {}).get("message", "")
                    and native.get("height_after") == current_height
                    and native.get("tip_after") == current_tip,
                    f"native rejection boundary/tip/height verification failed in {case_id} step {idx}",
                )

            honest_decoded = decode_transaction(reconstructed["expected_honest_tx_hex"])
            circuit_out_raw = reconstructed["circuit_outputs"]
            circuit_out = tuple(circuit_out_raw) if circuit_out_raw is not None else None
            expected_policy = evaluate_parent_policy(
                funded_target=expected_target,
                stage_role=stage_role,
                calibration=is_calibration,
                executed_target=reconstructed["executed_target"],
                expected_stage_target=reconstructed["expected_stage_target"],
                decoded_tx=decoded_tx,
                expected_Honest_tx=honest_decoded,
                witness_hex=reconstructed["witness_hex"],
                expected_honest_witness_hex=reconstructed["expected_honest_witness_hex"],
                gate_trace_valid=bool(reconstructed["gate_trace_valid"]),
                circuit_outputs=circuit_out,
                expected_selector=int(reconstructed["expected_selector"]),
                utxo_available=utxo_available,
                locktime_final=locktime_final,
                annex_absent=annex_absent,
            )
            _require(step.get("policy_decision") == expected_policy,
                     f"policy_decision mismatch in {case_id} step {idx}")

            intended_rec = (
                expected_target["intended_recipient"]
                if stage_role == "parent"
                else expected_target["intended_successor"]["intended_child_recipient"]
            )
            expected_step_score = score_candidate_outcome(
                accepted=bool(native["accepted"]),
                parent_policy_accept=expected_policy["parent_policy_accept"],
                fixed_target_preserved=expected_policy["fixed_target_preserved"],
                calibration=is_calibration,
                candidate_outputs=decoded_tx["outputs"],
                intended_recipient=intended_rec,
                committed_return_outputs=[honest_decoded["outputs"][1]],
            )
            _require(step.get("step_score") == expected_step_score,
                     f"step_score mismatch in {case_id} step {idx}")

            _require(step.get("previous_event_hash") == prev_hash,
                     f"broken event hash chain in {case_id} step {idx}")
            step_without_hash = {k: v for k, v in step.items() if k != "event_hash"}
            _require(step.get("event_hash") == _digest(step_without_hash),
                     f"tampered event_hash in {case_id} step {idx}")
            prev_hash = step["event_hash"]
            normalized_steps.append(copy.deepcopy(step))

        _require(
            case.get("final_height") == current_height
            and case.get("final_tip") == current_tip
            and case.get("peer_count") == 0
            and case.get("node_exit_codes") == [0],
            f"final height, tip, peer isolation, or exit code check failed in {case_id}",
        )

        parent_legit = any(
            s["policy_decision"]["stage_role"] == "parent" and s["step_score"]["legitimate_step"]
            for s in normalized_steps
        )
        child_legit = any(
            s["policy_decision"]["stage_role"] == "child" and s["step_score"]["legitimate_step"]
            for s in normalized_steps
        )
        expected_legit = (parent_legit and child_legit) if scenario.requires_child_completion else parent_legit
        expected_case_score = {
            "legitimate_completion": expected_legit,
            "legitimate_success": expected_legit,
            "attacker_success": any(s["step_score"]["attack_success"] for s in normalized_steps),
            "unauthorized_sats": sum(s["step_score"]["unauthorized_sats"] for s in normalized_steps),
            "diverted_sats": sum(s["step_score"]["diverted_sats"] for s in normalized_steps),
            "calibration_acceptances": sum(
                1 for s in normalized_steps if s["step_score"]["calibration_acceptance"]
            ),
            "calibration_released_sats": sum(
                s["step_score"]["calibration_released_sats"] for s in normalized_steps
            ),
            "confirmed_transitions": sum(
                1 for s in normalized_steps
                if s["native_execution"]["settlement_observed"] and not s["policy_decision"]["calibration"]
            ),
            "rejected_candidates": sum(
                1 for s in normalized_steps if not s["native_execution"]["accepted"]
            ),
        }
        _require(case.get("score") == expected_case_score, f"case score mismatch in {case_id}")
        normalized_cases.append({
            "case_id": case_id,
            "scenario_id": scenario.scenario_id,
            "split": scenario.split,
            "family": scenario.family,
            "calibration_scenario": scenario.calibration,
            "funding_txid": funding_txid,
            "funding_height": 102,
            "final_height": current_height,
            "funded_target_digest": expected_target_digest,
            "steps": normalized_steps,
            "score": expected_case_score,
        })

    aggregate_score = {
        "cases_verified": len(normalized_cases),
        "dev_cases": sum(1 for c in normalized_cases if c["split"] == "dev"),
        "held_out_cases": sum(1 for c in normalized_cases if c["split"] == "held_out"),
        "legitimate_completions": sum(1 for c in normalized_cases if c["score"]["legitimate_completion"]),
        "attacker_success": any(c["score"]["attacker_success"] for c in normalized_cases),
        "unauthorized_sats": sum(c["score"]["unauthorized_sats"] for c in normalized_cases),
        "diverted_sats": sum(c["score"]["diverted_sats"] for c in normalized_cases),
        "calibration_acceptances": sum(c["score"]["calibration_acceptances"] for c in normalized_cases),
        "confirmed_transitions": sum(c["score"]["confirmed_transitions"] for c in normalized_cases),
        "rejected_candidates": sum(c["score"]["rejected_candidates"] for c in normalized_cases),
    }
    return {
        "schema": NATIVE_RECEIPT_SCHEMA,
        "source_commit": SOURCE_COMMIT,
        "source_identity": source_identity,
        "source_sha256": dict(SOURCE_HASHES),
        "binary_sha256": report["binary_sha256"],
        "binary_provenance": provenance,
        "raw_report_sha256": _digest(report),
        "network": "regtest",
        "execution_verified": False,
        "evidence_gates": copy.deepcopy(DEFAULT_EVIDENCE_GATES),
        "score": aggregate_score,
        "cases": normalized_cases,
    }


_NATIVE_SUBPROCESS_DRIVER = r'''
import copy, hashlib, json, os, signal, struct, sys, tempfile
from pathlib import Path

staged = Path(sys.argv[1])
binary = Path(sys.argv[2])
output_path = Path(sys.argv[3])
timeout = int(sys.argv[4])
specs = json.loads(Path(sys.argv[5]).read_text(encoding="utf-8"))
provenance = json.loads(Path(sys.argv[6]).read_text(encoding="utf-8"))

sys.path.insert(0, str(staged / "scripts/research"))
sys.path.insert(0, str(staged / "scripts/tests"))
sys.path.insert(0, str(staged / "bitvm_arena_worker"))

import keyless_checksig_rpc as base
import cpa_campaign as camp
from cpa_native import SOURCE_HASHES, decode_transaction


def on_timeout(signum, frame):
    raise TimeoutError("CPA native campaign runner exceeded timeout")


signal.signal(signal.SIGALRM, on_timeout)
signal.alarm(timeout)

binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
source_hashes = {
    name: hashlib.sha256((staged / "scripts/research" / name).read_bytes()).hexdigest()
    for name in SOURCE_HASHES
}

cases_out = []
try:
    for spec in specs:
        case_id = spec["case_id"]
        scenario_id = spec["scenario_id"]
        scenario = camp.get_campaign_scenario(scenario_id)
        with tempfile.TemporaryDirectory(prefix="cpa-case-", dir=str(staged)) as case_tmp:
            case_dir = Path(case_tmp)
            node = base.Node(binary, case_dir)
            rpc = node.rpc
            try:
                base.require(node.start()["blocks"] == 0, "fresh regtest chain required")
                coinbase_leaf = base.Leaf(b"\x51")
                coinbase_spk, coinbase_control = coinbase_leaf.output()
                mining_address = base.address(coinbase_spk[2:])
                blocks = rpc("generatetoaddress", [101, mining_address])
                coinbase = rpc("getblock", [blocks[0], 2])["tx"][0]
                src_out = next(
                    item for item in coinbase["vout"] if item["scriptPubKey"]["hex"] == coinbase_spk.hex()
                )
                src_amount = base.satoshis(src_out["value"])

                circuit = scenario.circuit
                nodes = {k: tuple(v) for k, v in circuit["nodes"].items()}
                outputs = tuple(circuit["outputs"])
                import cpa_transition as machine
                from functools import lru_cache
                base.tweaked_key = lru_cache(maxsize=128)(base.tweaked_key)
                root_stage = machine.compile_machine(nodes, outputs, n_inputs=circuit["n_inputs"])
                next_epoch = machine.compile_machine(nodes, outputs, n_inputs=circuit["n_inputs"], epoch=1)
                wider = machine.compile_machine(nodes, outputs, n_inputs=circuit["n_inputs"], cap=9000)

                tag_script = b"\x6a\x20" + hashlib.sha256(case_id.encode("utf-8")).digest()
                funding_tx = base.Tx(
                    (base.Input(bytes.fromhex(coinbase["txid"])[::-1], src_out["n"], src_amount, coinbase_spk),),
                    (
                        base.Output(100_000, root_stage.leaf.output()[0]),
                        base.Output(100_000, root_stage.leaf.output()[0]),
                        base.Output(100_000, next_epoch.leaf.output()[0]),
                        base.Output(100_000, wider.leaf.output()[0]),
                        base.Output(100_000, coinbase_spk),
                        base.Output(0, tag_script),
                        base.Output(src_amount - 500_000 - 2_000, coinbase_spk),
                    ),
                )
                funding_raw, funding_id = funding_tx.serialize([[coinbase_leaf.script, coinbase_control]])
                base.require(rpc("sendrawtransaction", [funding_raw]) == funding_id, "funding txid mismatch")
                funding_block = rpc("generatetoaddress", [1, mining_address])[0]
                base.require(funding_id in rpc("getblock", [funding_block])["tx"], "funding unconfirmed")
                base.require(rpc("getblockcount") == 102, "unexpected funding height")

                boot = camp._worker_main(staged, {
                    "mode": "bootstrap",
                    "scenario_id": scenario_id,
                    "funding_txid_override": funding_id,
                })
                funded_target = boot["funded_target"]
                funded_target_digest = camp._digest(funded_target)

                parent_confirmed = False
                parent_confirmed_proposal = None
                authenticated_parent_txid = None
                child_completed = False
                calibration_confirmed = False
                prev_hash = "0" * 64
                steps_out = []

                for idx, raw_prop in enumerate(spec["proposals"]):
                    raw_clean, canonical_prop = camp.validate_candidate_proposal(raw_prop)
                    stage_role = canonical_prop["stage_role"]
                    is_cal = canonical_prop["target_coin"] == "calibration_wider_parent"

                    rec = camp._worker_main(staged, {
                        "mode": "reconstruct",
                        "scenario_id": scenario_id,
                        "funding_txid_override": funding_id,
                        "proposal": canonical_prop,
                        "authenticated_parent_txid": authenticated_parent_txid,
                        "confirmed_parent_proposal": parent_confirmed_proposal,
                    })
                    raw_tx = rec["transaction_hex"]
                    decoded_tx = decode_transaction(raw_tx)

                    if is_cal:
                        utxo_avail = not calibration_confirmed
                    elif stage_role == "parent":
                        utxo_avail = not parent_confirmed
                    else:
                        utxo_avail = parent_confirmed and not child_completed

                    annex_absent = canonical_prop["annex_hex"] is None
                    all_seq_final = all(i["sequence"] == 0xFFFFFFFF for i in decoded_tx["inputs"])
                    current_h = rpc("getblockcount")
                    locktime_final = (
                        decoded_tx["locktime"] == 0
                        or all_seq_final
                        or decoded_tx["locktime"] <= current_h
                    )
                    script_valid = bool(rec["script_valid"])
                    oracle_accepted = bool(script_valid and utxo_avail and locktime_final and annex_absent)
                    oracle_failure = rec["script_failure"]
                    if oracle_failure is None and not oracle_accepted:
                        oracle_failure = (
                            "duplicate_confirmed_transaction"
                            if canonical_prop["post_confirm_mode"] == "replay_confirmed_tx"
                            else "spent_input" if not utxo_avail
                            else "non_final_locktime" if not locktime_final
                            else "annex_rejected"
                        )
                    script_oracle = {
                        "executed": True,
                        "accepted": oracle_accepted,
                        "script_valid": script_valid,
                        "utxo_available": utxo_avail,
                        "locktime_final": locktime_final,
                        "annex_absent": annex_absent,
                        "script_failure": oracle_failure,
                        "op_count": int(rec["op_count"]),
                    }

                    height_before = rpc("getblockcount")
                    tip_before = rpc("getbestblockhash")
                    dry_run = rpc("testmempoolaccept", [[raw_tx]])[0]

                    spent_txid = authenticated_parent_txid if stage_role == "child" else funding_id
                    spent_vout = 1 if stage_role == "child" else (3 if is_cal else 0)

                    if dry_run["allowed"] is True:
                        sent_id = rpc("sendrawtransaction", [raw_tx])
                        base.require(sent_id == decoded_tx["txid"], "broadcast txid mismatch")
                        conf_block = rpc("generatetoaddress", [1, mining_address])[0]
                        base.require(sent_id in rpc("getblock", [conf_block])["tx"], "tx absent from mined block")
                        height_after = rpc("getblockcount")
                        tip_after = rpc("getbestblockhash")
                        base.require(rpc("gettxout", [spent_txid, spent_vout]) is None, "spent input still live")
                        live_verified = []
                        for out_i, out_spec in enumerate(decoded_tx["outputs"]):
                            if out_spec["script_pubkey"].startswith("6a"):
                                continue
                            live = rpc("gettxout", [sent_id, out_i])
                            base.require(
                                live is not None
                                and base.satoshis(live["value"]) == out_spec["amount_sats"]
                                and live["scriptPubKey"]["hex"] == out_spec["script_pubkey"],
                                "confirmed output UTXO mismatch",
                            )
                            live_verified.append(out_spec)
                        native_exec = {
                            "executed": True,
                            "execution_verified": False,
                            "accepted": True,
                            "settlement_observed": True,
                            "dry_run": dry_run,
                            "confirmed_height": height_after,
                            "confirmed_block": conf_block,
                            "rejection_boundary": None,
                            "broadcast_error": None,
                            "block_error": None,
                            "height_before": height_before,
                            "height_after": height_after,
                            "tip_before": tip_before,
                            "tip_after": tip_after,
                            "spent_input_verified_absent": True,
                            "live_outputs_verified": live_verified,
                            "binary_sha256": binary_sha,
                        }
                        if is_cal:
                            calibration_confirmed = True
                        elif stage_role == "parent":
                            parent_confirmed = True
                            parent_confirmed_proposal = copy.deepcopy(canonical_prop)
                            succ = funded_target["intended_successor"]
                            if (
                                len(decoded_tx["outputs"]) >= 2
                                and decoded_tx["outputs"][1]["amount_sats"] == succ["amount_sats"]
                                and decoded_tx["outputs"][1]["script_pubkey"] == succ["script_pubkey"]
                            ):
                                authenticated_parent_txid = sent_id
                        else:
                            child_completed = True
                    else:
                        if not utxo_avail:
                            boundary = (
                                "duplicate"
                                if canonical_prop["post_confirm_mode"] == "replay_confirmed_tx"
                                else "spent"
                            )
                        elif not locktime_final:
                            boundary = "nonfinal"
                        elif not annex_absent:
                            boundary = "standardness"
                        else:
                            boundary = "script"
                        try:
                            rpc("sendrawtransaction", [raw_tx])
                        except base.RpcError as err:
                            bcast_err = err.error
                        else:
                            raise ValueError("rejected tx entered mempool")
                        try:
                            rpc("generateblock", [mining_address, [raw_tx]])
                        except base.RpcError as err:
                            blk_err = err.error
                        else:
                            raise ValueError("rejected tx entered block")
                        height_after = rpc("getblockcount")
                        tip_after = rpc("getbestblockhash")
                        base.require(
                            (height_after, tip_after) == (height_before, tip_before),
                            "rejected block changed chain tip",
                        )
                        native_exec = {
                            "executed": True,
                            "execution_verified": False,
                            "accepted": False,
                            "settlement_observed": False,
                            "dry_run": dry_run,
                            "confirmed_height": None,
                            "confirmed_block": None,
                            "rejection_boundary": boundary,
                            "broadcast_error": bcast_err,
                            "block_error": blk_err,
                            "height_before": height_before,
                            "height_after": height_after,
                            "tip_before": tip_before,
                            "tip_after": tip_after,
                            "spent_input_verified_absent": False,
                            "live_outputs_verified": [],
                            "binary_sha256": binary_sha,
                        }

                    honest_decoded = decode_transaction(rec["expected_honest_tx_hex"])
                    c_out = tuple(rec["circuit_outputs"]) if rec["circuit_outputs"] is not None else None
                    policy_dec = camp.evaluate_parent_policy(
                        funded_target=funded_target,
                        stage_role=stage_role,
                        calibration=is_cal,
                        executed_target=rec["executed_target"],
                        expected_stage_target=rec["expected_stage_target"],
                        decoded_tx=decoded_tx,
                        expected_Honest_tx=honest_decoded,
                        witness_hex=rec["witness_hex"],
                        expected_honest_witness_hex=rec["expected_honest_witness_hex"],
                        gate_trace_valid=bool(rec["gate_trace_valid"]),
                        circuit_outputs=c_out,
                        expected_selector=int(rec["expected_selector"]),
                        utxo_available=utxo_avail,
                        locktime_final=locktime_final,
                        annex_absent=annex_absent,
                    )
                    intended_rec = (
                        funded_target["intended_recipient"]
                        if stage_role == "parent"
                        else funded_target["intended_successor"]["intended_child_recipient"]
                    )
                    step_score = camp.score_candidate_outcome(
                        accepted=bool(native_exec["accepted"]),
                        parent_policy_accept=policy_dec["parent_policy_accept"],
                        fixed_target_preserved=policy_dec["fixed_target_preserved"],
                        calibration=is_cal,
                        candidate_outputs=decoded_tx["outputs"],
                        intended_recipient=intended_rec,
                        committed_return_outputs=[honest_decoded["outputs"][1]],
                    )
                    step_entry = {
                        "index": idx,
                        "raw_proposal": raw_clean,
                        "canonical_proposal": canonical_prop,
                        "funded_origin": {
                            "origin_txid": funding_id,
                            "origin_vout": 3 if is_cal else 0,
                            "spent_txid": spent_txid,
                            "spent_vout": spent_vout,
                            "stage_role": stage_role,
                        },
                        "txid": decoded_tx["txid"],
                        "wtxid": decoded_tx["wtxid"],
                        "raw_tx": raw_tx,
                        "witness_hex": rec["witness_hex"],
                        "candidate_outputs": decoded_tx["outputs"],
                        "script_oracle": script_oracle,
                        "synthetic_simulator": {"executed": False, "accepted": None},
                        "native_execution": native_exec,
                        "policy_decision": policy_dec,
                        "step_score": step_score,
                        "evidence_gates": copy.deepcopy(camp.DEFAULT_EVIDENCE_GATES),
                        "previous_event_hash": prev_hash,
                    }
                    step_entry["event_hash"] = camp._digest(step_entry)
                    prev_hash = step_entry["event_hash"]
                    steps_out.append(step_entry)

                peer_count = rpc("getconnectioncount")
                final_height = rpc("getblockcount")
                final_tip = rpc("getbestblockhash")
            finally:
                node.stop()
                node.log.close()

            parent_legit = any(
                s["policy_decision"]["stage_role"] == "parent" and s["step_score"]["legitimate_step"]
                for s in steps_out
            )
            child_legit = any(
                s["policy_decision"]["stage_role"] == "child" and s["step_score"]["legitimate_step"]
                for s in steps_out
            )
            legit = (parent_legit and child_legit) if scenario.requires_child_completion else parent_legit
            case_score = {
                "legitimate_completion": legit,
                "legitimate_success": legit,
                "attacker_success": any(s["step_score"]["attack_success"] for s in steps_out),
                "unauthorized_sats": sum(s["step_score"]["unauthorized_sats"] for s in steps_out),
                "diverted_sats": sum(s["step_score"]["diverted_sats"] for s in steps_out),
                "calibration_acceptances": sum(
                    1 for s in steps_out if s["step_score"]["calibration_acceptance"]
                ),
                "calibration_released_sats": sum(
                    s["step_score"]["calibration_released_sats"] for s in steps_out
                ),
                "confirmed_transitions": sum(
                    1 for s in steps_out
                    if s["native_execution"]["settlement_observed"] and not s["policy_decision"]["calibration"]
                ),
                "rejected_candidates": sum(
                    1 for s in steps_out if not s["native_execution"]["accepted"]
                ),
            }
            cases_out.append({
                "case_id": case_id,
                "scenario_id": scenario.scenario_id,
                "split": scenario.split,
                "family": scenario.family,
                "calibration_scenario": scenario.calibration,
                "funding": {
                    "txid": funding_id,
                    "raw_tx": funding_raw,
                    "block": funding_block,
                    "height": 102,
                },
                "funded_target": funded_target,
                "funded_target_digest": funded_target_digest,
                "steps": steps_out,
                "final_height": final_height,
                "final_tip": final_tip,
                "peer_count": peer_count,
                "node_exit_codes": node.exit_codes,
                "score": case_score,
            })

    report = {
        "schema": "bitvm-arena/cpa-campaign-native-report/v1",
        "status": "passed",
        "network": "regtest",
        "source_commit": camp.SOURCE_COMMIT,
        "source_sha256": source_hashes,
        "binary_sha256": binary_sha,
        "binary_provenance": provenance,
        "evidence_gates": copy.deepcopy(camp.DEFAULT_EVIDENCE_GATES),
        "cases": cases_out,
    }
    output_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
finally:
    signal.alarm(0)
'''


def run_native_campaign_cases(
    source: Path,
    binary: Path,
    output: Path,
    *,
    case_specs: list[dict[str, Any]] | None = None,
    split: str = "all",
    timeout: int = 300,
) -> dict[str, Any]:
    """Execute individual eligible CPA campaign cases on fresh isolated regtest nodes."""
    _require(os.name == "posix", "native CPA campaign runner requires POSIX process groups and SIGALRM")
    _require(type(timeout) is int and 5 <= timeout <= 900, "timeout must be an integer in [5, 900]")

    specs = default_native_campaign_specs(split) if case_specs is None else copy.deepcopy(case_specs)
    _require(type(specs) is list and len(specs) >= 1, "at least one native campaign case is required")
    for spec in specs:
        check_native_eligibility(spec["scenario_id"])
        for prop in spec["proposals"]:
            validate_candidate_proposal(prop)

    pinned_worker, _ = _source_snapshot(source)
    research_modules = source_snapshot(source)

    binary = binary.resolve(strict=True)
    _require(binary.is_file() and binary.stat().st_size <= 256_000_000, "invalid native executable")
    binary_bytes = binary.read_bytes()
    binary_sha256 = hashlib.sha256(binary_bytes).hexdigest()
    provenance = verify_binary_provenance(binary_sha256)

    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = {k: v for k, v in os.environ.items() if k in {"PATH", "TMPDIR", "LANG", "LC_ALL", "TZ"}}

    try:
        with tempfile.TemporaryDirectory(prefix="bitvm-cpa-campaign-native-") as temporary:
            staged = Path(temporary)
            for rel, data in pinned_worker.items():
                dest = staged / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
            for name, data in research_modules.items():
                dest = staged / "scripts/research" / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)

            executable = staged / "bitcoin-rs"
            executable.write_bytes(binary_bytes)
            executable.chmod(0o700)

            specs_file = staged / "specs.json"
            specs_file.write_text(json.dumps(specs), encoding="utf-8")
            prov_file = staged / "provenance.json"
            prov_file.write_text(json.dumps(provenance), encoding="utf-8")
            raw_report_path = output / "raw_report.json"

            cmd = [
                sys.executable,
                "-I",
                "-B",
                "-c",
                _NATIVE_SUBPROCESS_DRIVER,
                str(staged),
                str(executable),
                str(raw_report_path),
                str(timeout),
                str(specs_file),
                str(prov_file),
            ]
            with (output / "runner.log").open("wb") as log_handle:
                process = subprocess.Popen(
                    cmd,
                    cwd=staged,
                    env=env,
                    stdout=log_handle,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                try:
                    returncode = process.wait(timeout=timeout + 45)
                except BaseException:
                    _stop_group(process)
                    raise
            if returncode != 0:
                _stop_group(process)
                raise ValueError("native CPA campaign run failed; inspect runner.log")

            for name, expected in SOURCE_HASHES.items():
                actual = hashlib.sha256((staged / "scripts/research" / name).read_bytes()).hexdigest()
                _require(actual == expected, "staged CPA source module changed during native run")
            _require(
                hashlib.sha256(executable.read_bytes()).hexdigest() == binary_sha256,
                "staged native executable changed during native run",
            )

            _require(raw_report_path.stat().st_size <= 16_000_000, "native campaign report exceeds bound")
            raw_report = json.loads(raw_report_path.read_text(encoding="utf-8"))
            receipt = verify_native_campaign_receipt(raw_report, source)
            receipt["execution_verified"] = True
            for case in receipt["cases"]:
                for step in case["steps"]:
                    step["native_execution"]["execution_verified"] = True
            receipt["execution_provenance"] = {
                "verified_before_and_after": True,
                "isolated_python": True,
                "per_case_isolated_regtest": True,
                "staged_binary": True,
                "timeout_seconds": timeout,
                "returncode": returncode,
                "raw_report_file_sha256": hashlib.sha256(raw_report_path.read_bytes()).hexdigest(),
            }
            (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
            return receipt
    except BaseException as exc:
        (output / "failure.json").write_text(
            json.dumps(
                {
                    "status": "failed",
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                    "execution_verified": False,
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        raise
