from __future__ import annotations

import copy
import itertools
import unittest
from dataclasses import FrozenInstanceError, replace

from bitvm_arena.cli import benchmark, run_scenario
from bitvm_arena.engine import ArenaSession, replay_trace
from bitvm_arena.model import canonical_json
from bitvm_arena.scenarios import get_scenario, load_scenarios


class ScoringTests(unittest.TestCase):
    def test_all_calibrations_and_assumption_controls(self):
        result = benchmark()
        self.assertEqual(result["episodes"], 22)
        self.assertTrue(result["all_expectations_met"])
        self.assertEqual(sum(c["profile"] == "strict" and c["score"]["attacker_success"] for c in result["cases"]), 1)

    def test_same_funded_target_scores_output_escape(self):
        scenario = get_scenario("output-substitution")
        strict = run_scenario(scenario.scenario_id)
        planted = run_scenario(scenario.scenario_id, "output-unbound")
        self.assertEqual(strict.export_trace()["funded_target_digest"], planted.export_trace()["funded_target_digest"])
        self.assertFalse(strict.score()["attacker_success"])
        self.assertEqual(planted.score()["unauthorized_sats"], 100000)
        self.assertEqual(planted.score()["violated_checks"], ["recipient"])

    def test_watchtower_outage_is_an_explicit_assumption_control(self):
        session = run_scenario("watchtower-outage")
        self.assertTrue(session.score()["attacker_success"])
        defender = ArenaSession(get_scenario("watchtower-outage"))
        self.assertTrue(defender.step({"kind": "challenge"})["accepted"])
        defender.step({"kind": "advance", "blocks": 4})
        self.assertTrue(defender.score()["legitimate_success"])
        self.assertFalse(defender.score()["attacker_success"])

    def test_honest_baselines_settle(self):
        for scenario in ("honest-uncontested", "honest-challenged"):
            with self.subTest(scenario=scenario):
                session = run_scenario(scenario)
                self.assertTrue(session.score()["legitimate_success"])
                self.assertEqual(session.score()["frozen_sats"], 0)

    def test_attempt_without_release_receives_no_attack_credit(self):
        session = ArenaSession(get_scenario("output-substitution"))
        self.assertFalse(session.step({"kind": "finalize"})["accepted"])
        self.assertFalse(session.score()["attacker_success"])
        self.assertEqual(session.score()["unauthorized_sats"], 0)

    def test_premature_honest_payout_is_still_a_policy_violation(self):
        session = ArenaSession(get_scenario("honest-uncontested"), "early-finalize")
        self.assertTrue(session.step({"kind": "finalize"})["accepted"])
        self.assertTrue(session.score()["attacker_success"])
        self.assertFalse(session.score()["legitimate_success"])
        self.assertEqual(session.score()["violated_checks"], ["challenge_window"])
        self.assertEqual(session.score()["diverted_sats"], 0)

    def test_partial_amount_still_conserves_value(self):
        session = run_scenario("amount-substitution", "amount-unbound")
        self.assertEqual(sum(t.amount_sats for t in session.transfers), 100000)
        self.assertEqual(session.score()["unauthorized_sats"], 90000)
        self.assertEqual(session.score()["diverted_sats"], 0)

    def test_double_finalization_cannot_duplicate_value(self):
        session = run_scenario("honest-uncontested")
        self.assertFalse(session.step({"kind": "finalize"})["accepted"])
        self.assertEqual(sum(t.amount_sats for t in session.transfers), 100000)

    def test_invalid_witness_cannot_be_relabelled_as_valid(self):
        session = ArenaSession(get_scenario("invalid-arithmetic"))
        session.step({"kind": "challenge"})
        self.assertFalse(session.step({"kind": "respond"})["accepted"])
        repaired = session.step({"kind": "respond", "witness": session.scenario.target.witness()})
        self.assertTrue(repaired["accepted"])
        session.step({"kind": "finalize"})
        self.assertFalse(session.score()["attacker_success"])


class BoundaryTests(unittest.TestCase):
    def test_challenge_at_deadline_accepted(self):
        session = ArenaSession(get_scenario("honest-uncontested"))
        session.step({"kind": "advance", "blocks": 6})
        self.assertTrue(session.step({"kind": "challenge"})["accepted"])

    def test_challenge_after_deadline_rejected(self):
        session = ArenaSession(get_scenario("honest-uncontested"))
        session.step({"kind": "advance", "blocks": 7})
        self.assertFalse(session.step({"kind": "challenge"})["accepted"])

    def test_finalize_at_deadline_rejected(self):
        session = ArenaSession(get_scenario("honest-uncontested"))
        session.step({"kind": "advance", "blocks": 6})
        self.assertFalse(session.step({"kind": "finalize"})["accepted"])
        session.step({"kind": "advance", "blocks": 1})
        self.assertTrue(session.step({"kind": "finalize"})["accepted"])

    def test_response_at_deadline_accepted(self):
        session = ArenaSession(get_scenario("honest-challenged"))
        session.step({"kind": "advance", "blocks": 3})
        self.assertTrue(session.step({"kind": "respond"})["accepted"])

    def test_response_after_deadline_refunded(self):
        session = ArenaSession(get_scenario("honest-challenged"))
        session.step({"kind": "advance", "blocks": 4})
        self.assertEqual(session.phase, "rejected")
        self.assertFalse(session.step({"kind": "respond"})["accepted"])

    def test_large_advance_processes_intervening_watchtower_and_timeout(self):
        session = ArenaSession(get_scenario("output-substitution"))
        session.step({"kind": "advance", "blocks": 20})
        self.assertEqual(session.phase, "rejected")
        self.assertEqual(session.response_deadline, 4)

    def test_censorship_cannot_extend_itself_free(self):
        session = ArenaSession(get_scenario("bounded-censorship"))
        self.assertTrue(session.step({"kind": "censor", "blocks": 2})["accepted"])
        self.assertFalse(session.step({"kind": "censor", "blocks": 1})["accepted"])
        self.assertFalse(session.step({"kind": "challenge"})["accepted"])
        session.step({"kind": "advance", "blocks": 7})
        self.assertEqual(session.phase, "rejected")
        self.assertEqual(session.censorship_used, 2)

    def test_block_and_action_budgets(self):
        session = ArenaSession(get_scenario("honest-uncontested"))
        session.step({"kind": "advance", "blocks": 30})
        self.assertFalse(session.step({"kind": "advance", "blocks": 1})["accepted"])
        while len(session.trace) < session.scenario.max_steps:
            session.step({"kind": "claim"})
        with self.assertRaisesRegex(ValueError, "budget"):
            session.step({"kind": "claim"})


class InputIsolationTests(unittest.TestCase):
    def test_malformed_actions_cannot_change_state(self):
        bad_actions = [
            {"kind": "advance", "blocks": True},
            {"kind": "advance", "blocks": 0},
            {"kind": "advance", "blocks": 31},
            {"kind": "advance", "blocks": "2"},
            {"kind": "claim", "amount_sats": -1},
            {"kind": "claim", "amount_sats": True},
            {"kind": "claim", "recipient": "x" * 201},
            {"kind": "claim", "profile": "output-unbound"},
            {"kind": "claim", "scenario": "watchtower-outage"},
            {"kind": "respond", "valid": True},
            {"kind": "respond", "witness": {"result": 80}},
            {"kind": "__dict__"},
            {"kind": ["claim"]},
        ]
        session = ArenaSession(get_scenario("output-substitution"))
        before = session.export_trace()
        for action in bad_actions:
            with self.subTest(action=action), self.assertRaises(ValueError):
                session.step(action)
            self.assertEqual(before, session.export_trace())

    def test_unknown_profile_rejected(self):
        with self.assertRaises(ValueError):
            ArenaSession(get_scenario("output-substitution"), "arbitrary")

    def test_target_is_immutable(self):
        session = ArenaSession(get_scenario("output-substitution"))
        with self.assertRaises(FrozenInstanceError):
            session.scenario.target.recipient = "synthetic:attacker"

    def test_observation_and_returned_event_are_detached(self):
        session = ArenaSession(get_scenario("honest-uncontested"))
        observed = session.observe()
        observed["funded_target"]["recipient"] = "synthetic:attacker"
        observed["claim"]["recipient"] = "synthetic:attacker"
        event = session.step({"kind": "advance", "blocks": 7})
        event["action"]["blocks"] = 30
        session.step({"kind": "finalize"})
        self.assertFalse(session.score()["attacker_success"])
        replay_trace(session.export_trace())

    def test_loaded_fixtures_cannot_be_mutated_through_seed_actions(self):
        scenario = get_scenario("output-substitution")
        scenario.seed_actions[0]["recipient"] = "synthetic:depositor"
        self.assertEqual(ArenaSession(scenario).claim["recipient"], "synthetic:attacker")

    def test_overspending_rejected_in_every_profile(self):
        scenario = replace(get_scenario("honest-uncontested"), seed_actions_json="[]")
        session = ArenaSession(scenario, "amount-unbound")
        self.assertFalse(session.step({"kind": "claim", "amount_sats": 100001})["accepted"])
        self.assertEqual(session.escrow_sats, 100000)


class ReplayTests(unittest.TestCase):
    def test_every_shipped_scenario_replays(self):
        for scenario in load_scenarios():
            with self.subTest(scenario=scenario.scenario_id):
                session = run_scenario(scenario.scenario_id)
                self.assertEqual(session.score(), replay_trace(session.export_trace()).score())

    def test_replay_rejects_mutations(self):
        original = run_scenario("output-substitution", "output-unbound").export_trace()
        mutations = [
            lambda t: t["score"].update(attacker_success=False),
            lambda t: t.update(funded_target_digest="00" * 32),
            lambda t: t.update(seed_action_count=0),
            lambda t: t["events"][0]["action"].update(recipient="synthetic:depositor"),
            lambda t: t["events"][1].update(height=500),
            lambda t: t["events"][0].update(event_hash="00" * 32),
            lambda t: t["events"].pop(0),
            lambda t: t.update(extra="injected"),
            lambda t: t["final_state"].update(escrow_sats=1),
        ]
        for mutation in mutations:
            edited = copy.deepcopy(original)
            mutation(edited)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                replay_trace(edited)

    def test_replay_evaluator_identity_is_external(self):
        trace = run_scenario("output-substitution", "output-unbound").export_trace()
        with self.assertRaisesRegex(ValueError, "profile"):
            replay_trace(trace, expected_profile="strict")
        with self.assertRaisesRegex(ValueError, "scenario"):
            replay_trace(trace, expected_scenario="watchtower-outage")

    def test_deterministic_bytes(self):
        self.assertEqual(canonical_json(run_scenario("context-rebinding").export_trace()), canonical_json(run_scenario("context-rebinding").export_trace()))

    def test_bounded_exhaustive_action_sequences_preserve_value_and_target(self):
        # 1,296 distinct short adversarial schedules exercise rejection paths,
        # terminal actions, skipped blocks, challenge deadlines, and responses.
        actions = [
            {"kind": "challenge"}, {"kind": "respond"}, {"kind": "finalize"},
            {"kind": "advance", "blocks": 1}, {"kind": "advance", "blocks": 7},
            {"kind": "censor", "blocks": 2},
        ]
        scenario = get_scenario("output-substitution")
        for sequence in itertools.product(actions, repeat=4):
            session = ArenaSession(scenario)
            for action in sequence:
                session.step(action)
                self.assertEqual(session.escrow_sats + sum(t.amount_sats for t in session.transfers), 100000)
                self.assertTrue(session.score()["funded_target_preserved"])
                self.assertFalse(session.score()["attacker_success"])


if __name__ == "__main__":
    unittest.main()
