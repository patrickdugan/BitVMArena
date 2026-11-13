from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from bitvm_arena.cpa_backend import (
    CASE_IDS, CPAReferenceSession, baseline_candidates, replay_trace,
    validate_candidate, verify_source,
)

SOURCE = os.environ.get("CPA_SOURCE")


class CPAInputTests(unittest.TestCase):
    def test_catalogue_is_finite_and_unique(self):
        self.assertEqual(len(CASE_IDS), 28)
        self.assertEqual(len(set(CASE_IDS)), 28)

    def test_only_a_published_fixture_identifier_is_admitted(self):
        candidates = [None, [], {"case_id": True}, {"case_id": "unknown"},
                      {"case_id": "honest", "source_root": "/tmp"},
                      {"case_id": "honest", "verifier_accept": True},
                      {"case_id": "honest", "witness_hex": []},
                      {"case_id": "honest", "target": {}}]
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validate_candidate(candidate)

    def test_bad_budgets_fail_before_source_or_subprocess(self):
        with patch("bitvm_arena.cpa_backend._source_snapshot") as source:
            for budget in (False, 0, 65, "32", 1.5):
                with self.subTest(budget=budget), self.assertRaises(ValueError):
                    CPAReferenceSession(Path("/absent"), max_attempts=budget)
            source.assert_not_called()

    def test_missing_source_fails_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary, patch("bitvm_arena.cpa_backend._run_fixture") as worker:
            with self.assertRaisesRegex(ValueError, "missing pinned"):
                CPAReferenceSession(Path(temporary))
            worker.assert_not_called()


@unittest.skipUnless(SOURCE, "CPA_SOURCE enables the actual pinned oracle")
class CPAVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(SOURCE)
        cls.baseline = CPAReferenceSession(cls.source)
        cls.results = {}
        for row in baseline_candidates():
            receipt = cls.baseline.step(row["candidate"])
            cls.results[receipt["case_id"]] = receipt
        cls.target = cls.baseline.observe()["funded_target_digest"]

    def test_actual_oracle_matches_all_published_controls(self):
        for row in baseline_candidates():
            result = self.results[row["candidate"]["case_id"]]
            with self.subTest(case=result["case_id"]):
                self.assertEqual(result["verifier_accept"], row["expected_verifier_accept"])
                self.assertFalse(result["attack_success"])
                self.assertEqual(result["evidence_level"], "reference_interpreter")
                self.assertFalse(result["native_execution"])
                self.assertFalse(result["settlement_observed"])
        self.assertEqual(self.baseline.score()["verifier_rejections"], 26)

    def test_honest_acceptance_is_independently_valid(self):
        honest = self.results["honest"]
        self.assertTrue(honest["verifier_accept"])
        self.assertTrue(honest["parent_policy_accept"])
        self.assertEqual(honest["policy_violations"], [])
        self.assertEqual(honest["candidate_outputs"][0]["amount_sats"], 7000)
        self.assertEqual(honest["candidate_outputs"][1]["amount_sats"], 91000)

    def test_normal_cases_keep_original_funded_authority(self):
        for name, receipt in self.results.items():
            if name != "wider_authority_calibration":
                with self.subTest(case=name):
                    self.assertTrue(receipt["fixed_target_preserved"])
                    self.assertEqual(receipt["original_target"], receipt["executed_target"])
                    self.assertEqual(receipt["funded_target_digest"], self.target)

    def test_wider_parent_is_excluded_from_attacker_score(self):
        result = self.results["wider_authority_calibration"]
        self.assertTrue(result["verifier_accept"])
        self.assertFalse(result["parent_policy_accept"])
        self.assertFalse(result["fixed_target_preserved"])
        self.assertFalse(result["attack_success"])
        self.assertEqual(self.baseline.score()["calibration_acceptances"], 1)

    def test_cross_coin_fixture_imports_foreign_witness_into_original_coin(self):
        receipt = self.results["cross_coin_replay"]
        self.assertFalse(receipt["verifier_accept"])
        self.assertTrue(receipt["fixed_target_preserved"])
        self.assertNotEqual(receipt["witness_hex"][6], receipt["original_target"]["outpoint"])

    def test_trace_replay_verifies_all_receipts(self):
        trace = self.baseline.export_trace()
        self.assertEqual(replay_trace(self.source, trace, expected_target_digest=self.target).export_trace(), trace)

    def test_tampered_score_receipt_and_candidate_fail_replay(self):
        session = CPAReferenceSession(self.source, max_attempts=2)
        session.step({"case_id": "honest"})
        trace = session.export_trace()
        mutations = [
            lambda t: t["score"].update(attacker_success=True),
            lambda t: t["receipts"][0].update(parent_policy_accept=False),
            lambda t: t["receipts"][0]["candidate"].update(case_id="parent_cap"),
            lambda t: t["receipts"][0].update(native_execution=True),
            lambda t: t["source_identity"].update(source_commit="0" * 40),
        ]
        for mutate in mutations:
            modified = copy.deepcopy(trace)
            mutate(modified)
            with self.subTest(mutate=mutate), self.assertRaisesRegex(ValueError, "verified replay"):
                replay_trace(self.source, modified, expected_target_digest=self.target, expected_max_attempts=2)

    def test_external_expected_target_and_budget_are_enforced(self):
        trace = self.baseline.export_trace()
        with self.assertRaisesRegex(ValueError, "evaluator target"):
            replay_trace(self.source, trace, expected_target_digest="0" * 64)
        with self.assertRaisesRegex(ValueError, "evaluator context"):
            replay_trace(self.source, trace, expected_target_digest=self.target, expected_max_attempts=1)

    def test_source_corruption_fails_before_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "source"
            shutil.copytree(self.source, copied)
            path = copied / "scripts/research/cpa_transition.py"
            path.write_text(path.read_text() + "\n# altered\n")
            with patch("bitvm_arena.cpa_backend._run_fixture") as worker:
                with self.assertRaisesRegex(ValueError, "hash mismatch"):
                    CPAReferenceSession(copied)
                worker.assert_not_called()

    def test_verified_bytes_survive_later_source_path_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "source"
            shutil.copytree(self.source, copied)
            session = CPAReferenceSession(copied)
            (copied / "scripts/research/cpa_transition.py").write_text("raise RuntimeError('modified source')")
            self.assertTrue(session.step({"case_id": "honest"})["verifier_accept"])
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                verify_source(copied)

    def test_detached_receipts_budget_and_worker_failures(self):
        session = CPAReferenceSession(self.source, max_attempts=1)
        session.observe()["funded_target"].clear()
        before = session.export_trace()
        with patch("bitvm_arena.cpa_backend._run_fixture", side_effect=ValueError("worker failed")):
            with self.assertRaises(ValueError):
                session.step({"case_id": "honest"})
        self.assertEqual(before, session.export_trace())
        result = session.step({"case_id": "honest"})
        result["original_target"].clear()
        self.assertTrue(session.score()["legitimate_success"])
        with self.assertRaisesRegex(ValueError, "budget"):
            session.step({"case_id": "honest"})

    def test_worker_code_is_frozen_with_its_recorded_hash(self):
        session = CPAReferenceSession(self.source)
        # Any later adapter read would use different code under an old receipt.
        # The constructor must already hold all bytes needed for an attempt.
        with patch("pathlib.Path.read_bytes", side_effect=AssertionError("late source read")):
            receipt = session.step({"case_id": "honest"})
        self.assertTrue(receipt["verifier_accept"])
        self.assertEqual(receipt["source_identity"], session.source_identity)


if __name__ == "__main__":
    unittest.main()
