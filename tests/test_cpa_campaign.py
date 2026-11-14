"""Unit and source-reconstruction tests for the agent-driven CPA campaign."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from bitvm_arena.cpa_campaign import (
    CPACampaignSession,
    DEFAULT_EVIDENCE_GATES,
    FAMILIES,
    SPLITS,
    get_campaign_scenario,
    load_campaign_scenarios,
    parse_candidate_json,
    replay_campaign_trace,
    run_campaign_benchmark,
    score_candidate_outcome,
    validate_candidate_proposal,
)

SOURCE = os.environ.get("CPA_SOURCE")


class CPACampaignGrammarAndSplitTests(unittest.TestCase):
    def test_narrow_grammar_rejects_fixture_ids_host_overrides_and_bad_types(self):
        invalid_proposals = [
            None,
            [],
            {},
            {"case_id": "honest"},
            {"request_bits": [1, 1, 0], "case_id": "honest"},
            {"request_bits": [1, 1, 0], "funded_target": {}},
            {"request_bits": [1, 1, 0], "outpoint": "00" * 36},
            {"request_bits": [1, 1, 0], "authority": "00" * 32},
            {"request_bits": [1, 1, 0], "intended_recipient": "51"},
            {"request_bits": [1, 1, 0], "amount": 100_000},
            {"request_bits": [1, 1, 0], "verifier_accept": True},
            {"request_bits": [1, 1, 0], "parent_policy_accept": True},
            {"request_bits": [True, 1, 0]},
            {"request_bits": [1, 1]},
            {"request_bits": [1, 2, 0]},
            {"request_bits": [1, 1, 0], "payout_sats": True},
            {"request_bits": [1, 1, 0], "payout_sats": -1},
            {"request_bits": [1, 1, 0], "payout_sats": 100_001},
            {"request_bits": [1, 1, 0], "version": 3},
            {"request_bits": [1, 1, 0], "sequence": 1},
            {"request_bits": [1, 1, 0], "annex_hex": "5101"},
            {"request_bits": [1, 1, 0], "annex_hex": "50AA"},
            {"request_bits": [1, 1, 0], "context_mutation": {"field": "unknown", "op": "zero"}},
            {"request_bits": [1, 1, 0], "gate_mutation": {"gate_index": 99, "op": "flip"}},
        ]
        for candidate in invalid_proposals:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validate_candidate_proposal(candidate)

    def test_raw_json_parser_rejects_duplicate_keys_and_oversized_payloads(self):
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            parse_candidate_json('{"request_bits":[1,1,0],"request_bits":[0,0,0]}')
        with self.assertRaisesRegex(ValueError, "size bound"):
            parse_candidate_json('{"request_bits":[1,1,0]}' + (" " * 9000))
        parsed = parse_candidate_json('{"request_bits":[1,0,0],"payout_sats":8001}')
        raw, canonical = validate_candidate_proposal(parsed)
        self.assertEqual(raw, {"request_bits": [1, 0, 0], "payout_sats": 8001})
        self.assertEqual(canonical["stage_role"], "parent")
        self.assertEqual(canonical["target_coin"], "original")

    def test_dev_and_held_out_splits_are_program_disjoint_and_cover_all_families(self):
        dev = load_campaign_scenarios("dev")
        held_out = load_campaign_scenarios("held_out")
        all_scenarios = load_campaign_scenarios("all")
        self.assertEqual(len(dev), 10)
        self.assertEqual(len(held_out), 10)
        self.assertEqual(len(all_scenarios), 20)

        dev_programs = {s.program_id for s in dev}
        held_programs = {s.program_id for s in held_out}
        self.assertTrue(dev_programs.isdisjoint(held_programs))
        for split_name, group in (("dev", dev), ("held_out", held_out)):
            with self.subTest(split=split_name):
                self.assertEqual({s.family for s in group}, set(FAMILIES))
                self.assertTrue(any(s.calibration for s in group))
                self.assertTrue(any(s.requires_child_completion for s in group))
                self.assertTrue(any(not s.native_supported and s.required_evidence_gates for s in group))

        # Renamed circuits share canonical ProgramIDs within the same partition.
        self.assertEqual(
            get_campaign_scenario("dev-honest-root-and").program_id,
            get_campaign_scenario("dev-honest-two-step-lineage").program_id,
        )
        self.assertEqual(
            get_campaign_scenario("heldout-honest-a-and-not-b").program_id,
            get_campaign_scenario("heldout-input-role-aliasing").program_id,
        )

    def test_separate_scoring_distinguishes_legitimate_unauthorized_diverted_and_calibration(self):
        intended = "5120" + "11" * 32
        attacker = "5120" + "22" * 32
        committed_succ = {"amount_sats": 91_000, "script_pubkey": "5120" + "33" * 32}

        honest = score_candidate_outcome(
            accepted=True,
            parent_policy_accept=True,
            fixed_target_preserved=True,
            calibration=False,
            candidate_outputs=[{"amount_sats": 7_000, "script_pubkey": intended}, committed_succ],
            intended_recipient=intended,
            committed_return_outputs=[committed_succ],
        )
        self.assertTrue(honest["legitimate_step"])
        self.assertFalse(honest["attack_success"])
        self.assertEqual(honest["unauthorized_sats"], 0)
        self.assertEqual(honest["diverted_sats"], 0)

        # Over-cap release to the intended recipient: unauthorized > 0, diverted == 0.
        over_cap_same_recipient = score_candidate_outcome(
            accepted=True,
            parent_policy_accept=False,
            fixed_target_preserved=True,
            calibration=False,
            candidate_outputs=[{"amount_sats": 8_001, "script_pubkey": intended}, committed_succ],
            intended_recipient=intended,
            committed_return_outputs=[committed_succ],
        )
        self.assertFalse(over_cap_same_recipient["legitimate_step"])
        self.assertTrue(over_cap_same_recipient["attack_success"])
        self.assertEqual(over_cap_same_recipient["unauthorized_sats"], 8_001)
        self.assertEqual(over_cap_same_recipient["diverted_sats"], 0)

        # Recipient substitution: both unauthorized and diverted capture the substituted payout.
        diverted = score_candidate_outcome(
            accepted=True,
            parent_policy_accept=False,
            fixed_target_preserved=True,
            calibration=False,
            candidate_outputs=[{"amount_sats": 7_000, "script_pubkey": attacker}, committed_succ],
            intended_recipient=intended,
            committed_return_outputs=[committed_succ],
        )
        self.assertTrue(diverted["attack_success"])
        self.assertEqual(diverted["unauthorized_sats"], 7_000)
        self.assertEqual(diverted["diverted_sats"], 7_000)

        # Weaker separately funded parent calibration earns zero attack credit.
        calibration = score_candidate_outcome(
            accepted=True,
            parent_policy_accept=False,
            fixed_target_preserved=False,
            calibration=True,
            candidate_outputs=[{"amount_sats": 9_000, "script_pubkey": intended}, committed_succ],
            intended_recipient=intended,
            committed_return_outputs=[committed_succ],
        )
        self.assertFalse(calibration["legitimate_step"])
        self.assertFalse(calibration["attack_success"])
        self.assertEqual(calibration["unauthorized_sats"], 0)
        self.assertEqual(calibration["diverted_sats"], 0)
        self.assertTrue(calibration["calibration_acceptance"])
        self.assertEqual(calibration["calibration_released_sats"], 9_000)

    def test_invalid_max_attempts_and_missing_source_fail_cleanly(self):
        for bad_budget in (False, 0, -1, 33, "8"):
            with self.subTest(budget=bad_budget), self.assertRaises(ValueError):
                CPACampaignSession(Path("/absent"), max_attempts=bad_budget)  # type: ignore[arg-type]
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "missing pinned source"):
                CPACampaignSession(Path(tmp))


@unittest.skipUnless(SOURCE, "set CPA_SOURCE to the pinned bitcoin-rs checkout")
class CPACampaignExecutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(SOURCE)
        cls.summary = run_campaign_benchmark(cls.source, split="all")

    def test_full_campaign_benchmark_passes_and_replays_across_both_splits(self):
        self.assertTrue(self.summary["all_expectations_met"])
        self.assertEqual(self.summary["scenario_count"], 20)
        self.assertEqual(self.summary["dev_count"], 10)
        self.assertEqual(self.summary["held_out_count"], 10)
        self.assertEqual(self.summary["attacker_success_count"], 0)
        self.assertEqual(self.summary["evidence_gates"], DEFAULT_EVIDENCE_GATES)

    def test_host_owned_target_remains_immutable_across_adversarial_and_child_steps(self):
        session = CPACampaignSession(self.source, "heldout-honest-two-step-not-a-and-b", max_attempts=6)
        initial = session.observe()
        target_before = copy.deepcopy(initial["funded_target"])
        digest_before = initial["funded_target_digest"]
        for required_key in ("outpoint", "authority", "program", "context", "intended_recipient", "amount"):
            self.assertIn(required_key, target_before)

        # Caller mutations to returned dicts cannot alter session state.
        initial["funded_target"]["amount"] = 1
        initial["funded_target"]["intended_recipient"] = "00"

        rejected = session.step({"request_bits": [1, 1, 0], "payout_sats": 8500, "recipient_id": "recipient_1"})
        self.assertFalse(rejected["script_oracle"]["accepted"])
        self.assertFalse(rejected["policy_decision"]["parent_policy_accept"])
        self.assertEqual(session.score()["legitimate_completion"], False)

        parent_ev = session.step({"request_bits": [0, 1, 0]})
        self.assertTrue(parent_ev["script_oracle"]["accepted"])
        self.assertTrue(parent_ev["policy_decision"]["parent_policy_accept"])
        # Scenario requires child completion, so parent alone is not yet complete.
        self.assertFalse(session.score()["legitimate_completion"])

        child_ev = session.step({"request_bits": [0, 1, 1], "stage_role": "child"})
        self.assertTrue(child_ev["script_oracle"]["accepted"])
        self.assertTrue(child_ev["policy_decision"]["parent_policy_accept"])
        self.assertEqual(child_ev["chain_height_after"], 104)

        after = session.observe()
        self.assertEqual(after["funded_target"], target_before)
        self.assertEqual(after["funded_target_digest"], digest_before)
        score = session.score()
        self.assertTrue(score["legitimate_completion"])
        self.assertFalse(score["attacker_success"])
        self.assertGreater(score["resource_use"]["script_op_count"], 0)
        self.assertEqual(score["resource_use"]["committed_fees_sats"], 4_000)

        # Distinct outcome surfaces remain separated.
        self.assertEqual(score["synthetic_simulator"], {"executed": False, "accepted": None})
        self.assertEqual(
            score["native_execution"],
            {"executed": False, "execution_verified": False, "settlement_observed": False},
        )
        self.assertEqual(score["evidence_gates"], DEFAULT_EVIDENCE_GATES)

    def test_weaker_parent_calibration_is_restricted_and_earns_zero_attack_credit(self):
        non_cal = CPACampaignSession(self.source, "dev-honest-root-and")
        with self.assertRaisesRegex(ValueError, "calibration scenarios"):
            non_cal.step({"request_bits": [1, 1, 0], "target_coin": "calibration_wider_parent"})

        cal = CPACampaignSession(self.source, "heldout-calibration-weaker-parent")
        ev = cal.step({
            "request_bits": [0, 1, 1],
            "target_coin": "calibration_wider_parent",
        })
        self.assertTrue(ev["script_oracle"]["accepted"])
        self.assertFalse(ev["policy_decision"]["parent_policy_accept"])
        self.assertFalse(ev["policy_decision"]["fixed_target_preserved"])
        self.assertTrue(ev["policy_decision"]["calibration"])
        self.assertEqual(ev["candidate_outputs"][0]["amount_sats"], 9000)
        score = cal.score()
        self.assertFalse(score["attacker_success"])
        self.assertEqual(score["unauthorized_sats"], 0)
        self.assertEqual(score["diverted_sats"], 0)
        self.assertEqual(score["calibration_acceptances"], 1)
        self.assertEqual(score["calibration_released_sats"], 98000)

    def test_frozen_source_and_worker_bytes_survive_disk_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            copied = Path(tmp) / "source"
            shutil.copytree(self.source / "scripts", copied / "scripts")
            shutil.copytree(self.source / "docs/research", copied / "docs/research")
            session = CPACampaignSession(copied, "dev-honest-root-and")
            (copied / "scripts/research/cpa_transition.py").write_text("raise RuntimeError('mutated')\n")
            with patch("pathlib.Path.read_bytes", side_effect=AssertionError("late disk read")):
                ev = session.step({"request_bits": [1, 1, 0], "payout_sats": 7000})
            self.assertTrue(ev["script_oracle"]["accepted"])
            with self.assertRaisesRegex(ValueError, "source hash mismatch"):
                CPACampaignSession(copied, "dev-honest-root-and")


if __name__ == "__main__":
    unittest.main()
