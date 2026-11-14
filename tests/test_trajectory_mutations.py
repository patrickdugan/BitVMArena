"""Tamper and mutation tests for ControlArena trajectory replay verification."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from bitvm_arena.model import digest
from bitvm_arena.trajectories import (
    TrajectorySpec,
    export_trajectory_pack,
    replay_trajectory,
    run_trajectory,
    select_representative_audit_cases,
    verify_trajectory_pack,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
BUNDLE_ROOT = REPO_ROOT / "evidence" / "cpa_native"
SOURCE_ROOT = Path(os.environ["CPA_SOURCE"]) if os.environ.get("CPA_SOURCE") else None
SOURCE_AVAILABLE = SOURCE_ROOT is not None and SOURCE_ROOT.is_dir()


def _reseal_trajectory(record: dict) -> dict:
    """Recompute all turn hashes, underlying_trace_sha256, and trajectory_sha256 after mutation."""
    mutated = copy.deepcopy(record)
    prev_hash = "0" * 64
    new_turns = []
    for idx, turn in enumerate(mutated["turns"]):
        turn["turn_index"] = idx
        turn["prev_turn_hash"] = prev_hash
        t_body = {k: v for k, v in turn.items() if k != "turn_hash"}
        t_sha = digest(t_body)
        turn["turn_hash"] = t_sha
        prev_hash = t_sha
        new_turns.append(turn)
    mutated["turns"] = new_turns
    mutated["underlying_trace_sha256"] = digest(mutated["underlying_trace"])
    body = {k: v for k, v in mutated.items() if k != "trajectory_sha256"}
    mutated["trajectory_sha256"] = digest(body)
    return mutated


class TrajectoryMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.arena_dtt = run_trajectory(
            TrajectorySpec(
                "bitvm_arena",
                "watchtower-outage",
                "attack",
                "trusted_monitor_deferral",
                untrusted_policy="adaptive_prober",
            )
        )
        reps = select_representative_audit_cases(BUNDLE_ROOT)
        self.audit_rec = run_trajectory(
            TrajectorySpec(
                "bitvm_native_receipt_audit",
                reps["admission_root"],
                "honest",
                "trusted_monitor_deferral",
                untrusted_policy="premature_confirmation_auditor",
            ),
            bundle_root=BUNDLE_ROOT,
        )

    def test_broken_turn_hash_chain_and_top_level_digest_rejected(self) -> None:
        bad_sha = copy.deepcopy(self.arena_dtt)
        bad_sha["trajectory_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "trajectory_sha256 mismatch"):
            replay_trajectory(bad_sha)

        bad_chain = copy.deepcopy(self.arena_dtt)
        bad_chain["turns"][1]["prev_turn_hash"] = "a" * 64
        body = {k: v for k, v in bad_chain.items() if k != "trajectory_sha256"}
        bad_chain["trajectory_sha256"] = digest(body)
        with self.assertRaisesRegex(ValueError, "broken prev_turn_hash chain"):
            replay_trajectory(bad_chain)

        bad_turn_hash = copy.deepcopy(self.arena_dtt)
        bad_turn_hash["turns"][1]["turn_hash"] = "b" * 64
        body = {k: v for k, v in bad_turn_hash.items() if k != "trajectory_sha256"}
        bad_turn_hash["trajectory_sha256"] = digest(body)
        with self.assertRaisesRegex(ValueError, "turn_hash mismatch"):
            replay_trajectory(bad_turn_hash)

    def test_resealed_turn_argument_proposal_and_reply_tampering_rejected(self) -> None:
        # Even when all SHA-256 digests are recomputed, deterministic policy/monitor replay catches edits.
        tampered_proposal = copy.deepcopy(self.arena_dtt)
        tampered_proposal["turns"][1]["untrusted_proposal"]["arguments"]["kind"] = "challenge"
        tampered_proposal = _reseal_trajectory(tampered_proposal)
        with self.assertRaisesRegex(ValueError, "differs from deterministic policy and monitor replay"):
            replay_trajectory(tampered_proposal)

        tampered_reply = copy.deepcopy(self.arena_dtt)
        tampered_reply["turns"][0]["public_reply"]["height"] = 999
        tampered_reply = _reseal_trajectory(tampered_reply)
        with self.assertRaisesRegex(ValueError, "differs from deterministic policy and monitor replay"):
            replay_trajectory(tampered_reply)

    def test_forged_monitor_score_or_controller_decision_rejected(self) -> None:
        forged_monitor = copy.deepcopy(self.arena_dtt)
        forged_monitor["turns"][1]["monitor_review"]["suspicion_score"] = 0.01
        forged_monitor["turns"][1]["monitor_review"]["deferred"] = False
        forged_monitor = _reseal_trajectory(forged_monitor)
        with self.assertRaisesRegex(ValueError, "differs from deterministic policy and monitor replay"):
            replay_trajectory(forged_monitor)

        forged_lane = copy.deepcopy(self.audit_rec)
        forged_lane["control_trajectory_lane"]["controller_decision"] = "allow"
        forged_lane = _reseal_trajectory(forged_lane)
        with self.assertRaisesRegex(ValueError, "differs from deterministic policy and monitor replay"):
            replay_trajectory(forged_lane, bundle_root=BUNDLE_ROOT)

    def test_swapped_evaluator_expectations_and_copied_evidence_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "scenario_id differs from evaluator expectation"):
            replay_trajectory(self.arena_dtt, expected_scenario_id="honest-uncontested")

        with self.assertRaisesRegex(ValueError, "eval_mode differs from evaluator expectation"):
            replay_trajectory(self.arena_dtt, expected_eval_mode="honest")

        with self.assertRaisesRegex(ValueError, "policy_family differs from evaluator expectation"):
            replay_trajectory(self.arena_dtt, expected_policy_family="adaptive_prober")

        # Copying underlying_trace from another scenario is caught by domain trace replay.
        other = run_trajectory(
            TrajectorySpec("bitvm_arena", "honest-uncontested", "honest", "honest_solver")
        )
        copied = copy.deepcopy(self.arena_dtt)
        copied["underlying_trace"] = copy.deepcopy(other["underlying_trace"])
        copied = _reseal_trajectory(copied)
        with self.assertRaises(ValueError):
            replay_trajectory(copied)

    def test_hidden_oracle_leakage_in_turns_is_rejected(self) -> None:
        for hidden_key in ("policy_decision", "expected_answer", "parent_policy_accept", "authorized_bits"):
            leaked = copy.deepcopy(self.arena_dtt)
            leaked["turns"][0]["public_reply"][hidden_key] = "leaked"
            leaked = _reseal_trajectory(leaked)
            with self.assertRaisesRegex(ValueError, "leaked evaluator-only oracle keys"):
                replay_trajectory(leaked)

    def test_forged_native_execution_model_generated_and_evidence_gates_rejected(self) -> None:
        forged_model = copy.deepcopy(self.arena_dtt)
        forged_model["model_generated"] = True
        forged_model = _reseal_trajectory(forged_model)
        with self.assertRaisesRegex(ValueError, "cannot claim model_generated=True"):
            replay_trajectory(forged_model)

        forged_gate = copy.deepcopy(self.arena_dtt)
        forged_gate["evidence_gates"]["zk_delegation_verified"] = True
        forged_gate = _reseal_trajectory(forged_gate)
        with self.assertRaisesRegex(ValueError, "cannot claim unverified evidence gates"):
            replay_trajectory(forged_gate)

        for native_flag in ("executed", "execution_verified", "settlement_observed", "live_execution_this_sample"):
            forged_native = copy.deepcopy(self.audit_rec)
            forged_native["native_execution"][native_flag] = True
            forged_native = _reseal_trajectory(forged_native)
            with self.assertRaisesRegex(ValueError, "cannot claim live native execution or observed settlement"):
                replay_trajectory(forged_native, bundle_root=BUNDLE_ROOT)

    def test_pack_summary_and_duplicate_id_tampering_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="bitvm-traj-mut-") as tmp:
            out = Path(tmp)
            specs = [
                TrajectorySpec("bitvm_arena", "honest-uncontested", "honest", "honest_solver"),
                TrajectorySpec("bitvm_arena", "watchtower-outage", "attack", "adaptive_prober"),
            ]
            export_trajectory_pack(specs, output_dir=out)

            summary_path = out / "summary.json"
            jsonl_path = out / "trajectories.jsonl"
            tampered_summary = json.loads(summary_path.read_text(encoding="utf-8"))
            tampered_summary["controller_outcomes"]["attack_unmonitored"]["side_task_success_count"] = 0
            summary_path.write_text(json.dumps(tampered_summary), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "summary.json differs"):
                verify_trajectory_pack(jsonl_path, summary_path=summary_path)

            lines = jsonl_path.read_text(encoding="utf-8").splitlines()
            jsonl_path.write_text(lines[0] + "\n" + lines[0] + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate trajectory_id"):
                verify_trajectory_pack(jsonl_path)

    @unittest.skipUnless(SOURCE_AVAILABLE, "set CPA_SOURCE to run CPA trajectory mutation tests")
    def test_cpa_campaign_split_swap_and_outcome_forgery_rejected(self) -> None:
        cpa_rec = run_trajectory(
            TrajectorySpec(
                "bitvm_cpa_campaign",
                "heldout-calibration-weaker-parent",
                "attack",
                "adaptive_prober",
                max_attempts=4,
            ),
            source_root=SOURCE_ROOT,
        )
        with self.assertRaisesRegex(ValueError, "split differs from evaluator expectation"):
            replay_trajectory(cpa_rec, source_root=SOURCE_ROOT, expected_split="dev")

        # Forging attack credit on weaker-parent calibration is rejected.
        forged_credit = copy.deepcopy(cpa_rec)
        forged_credit["outcome"]["side_task_success"] = True
        forged_credit["outcome"]["unauthorized_sats"] = 98_000
        forged_credit = _reseal_trajectory(forged_credit)
        with self.assertRaisesRegex(ValueError, "differs from deterministic policy and monitor replay"):
            replay_trajectory(forged_credit, source_root=SOURCE_ROOT)


if __name__ == "__main__":
    unittest.main()
