from collections import Counter
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY))

from research.authority_enumeration.catalogue import (
    DATA, ROOT, EvidenceLevel, FixedTarget, assess_fixed_target,
    load_catalogue, verify_recovered_files,
)
from research.authority_enumeration.replay import replay, verified_source_bytes


class AuthorityStudyTests(unittest.TestCase):
    def setUp(self):
        self.target = FixedTarget("11" * 32, "22" * 32, "33" * 32, "44" * 32, 0)

    def assessment(self, executed=None, **changes):
        values = dict(
            validator_accept=True, parent_policy_accept=False,
            unauthorized_effect_observed=True,
            evidence_level=EvidenceLevel.CPA_PYTHON,
        )
        values.update(changes)
        return assess_fixed_target(self.target, executed or self.target, **values)

    def test_eight_recovered_blobs_match_upstream(self):
        self.assertEqual(len(verify_recovered_files()), 8)

    def test_catalogue_retains_evidence_levels(self):
        catalogue = load_catalogue()
        self.assertEqual(len(catalogue), 10)
        self.assertEqual(Counter(x.evidence_level for x in catalogue), {
            EvidenceLevel.PLANTED_MODEL: 5,
            EvidenceLevel.CPA_PYTHON: 3,
            EvidenceLevel.PROPOSED_HF: 2,
        })
        self.assertTrue(all(x.fixed_target_required for x in catalogue))
        self.assertFalse(any(x.native_arena_adapter_verified for x in catalogue))

    def test_scenario_cannot_relax_fixed_target_or_raise_evidence(self):
        original = json.loads((DATA / "arena_scenarios.jsonl").read_text().splitlines()[0])
        for field, value in (
            ("fixed_target_required", False),
            ("native_arena_adapter_verified", True),
            ("network_access", True),
            ("evidence_level", "native_consensus"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "scenario.jsonl"
                path.write_text(json.dumps({**original, field: value}) + "\n")
                with self.assertRaises(ValueError):
                    load_catalogue(path)

    def test_replaced_descriptor_state_authority_or_outpoint_gets_no_credit(self):
        for field in ("authority_id", "descriptor_digest", "state_commitment", "txid", "vout"):
            with self.subTest(field=field):
                changed = replace(self.target, **{field: 1 if field == "vout" else "55" * 32})
                result = self.assessment(changed)
                self.assertFalse(result["fixed_target_preserved"])
                self.assertFalse(result["attack_success"])

    def test_attack_requires_acceptance_policy_violation_and_effect(self):
        self.assertTrue(self.assessment()["attack_success"])
        for key, value in (
            ("validator_accept", False),
            ("parent_policy_accept", True),
            ("unauthorized_effect_observed", False),
        ):
            with self.subTest(key=key):
                self.assertFalse(self.assessment(**{key: value})["attack_success"])

    def test_hypothesis_cannot_be_counted_as_executed_attack(self):
        result = self.assessment(evidence_level=EvidenceLevel.PROPOSED_HF)
        self.assertFalse(result["attack_success"])

    def test_planted_success_retains_its_scope(self):
        result = self.assessment(evidence_level=EvidenceLevel.PLANTED_MODEL)
        self.assertTrue(result["attack_success"])
        self.assertEqual(result["evidence_level"], "planted_model")
        self.assertFalse(result["native_consensus_evidence"])

    def test_verifier_booleans_are_strict(self):
        for value in ("false", 0, 1, None):
            with self.subTest(value=value), self.assertRaises(TypeError):
                self.assessment(validator_accept=value)

    def test_frozen_target_has_canonical_identity(self):
        for changes in ({"vout": True}, {"vout": -1}, {"vout": 2**32}, {"authority_id": "11"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                replace(self.target, **changes)

    def test_replay_refuses_missing_source_before_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("subprocess.run") as execute, self.assertRaises(ValueError):
                replay(Path(directory), Path(directory) / "out")
            execute.assert_not_called()

    def test_replay_refuses_tampered_dependency(self):
        entry = json.loads((DATA / "provenance.json").read_text())["source_files"][0]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / entry["path"]
            path.parent.mkdir(parents=True)
            path.write_text("raise RuntimeError('must not execute')\n")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                verified_source_bytes(Path(directory))

    def test_copied_fixture_tampering_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "study"
            shutil.copytree(ROOT, destination)
            source = destination / "upstream/scripts/research/bitvm_authority_enumeration.py"
            source.write_bytes(source.read_bytes() + b"\n# modified\n")
            with self.assertRaisesRegex(ValueError, "recovered source changed"):
                verify_recovered_files(destination)

    def test_original_enumerator_exposes_wiring_counterexample(self):
        path = ROOT / "upstream/scripts/research/bitvm_authority_enumeration.py"
        spec = importlib.util.spec_from_file_location("preserved_authority_study", path)
        study = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(study)
        left, right = ((0, 1), (0, 2)), ((0, 0), (1, 2))
        self.assertEqual(study.truth_table(left), "1101")
        self.assertEqual(study.truth_table(right), "1011")
        self.assertEqual(
            Counter(node[0] for node in study.graph(left)[0].values()),
            Counter(node[0] for node in study.graph(right)[0].values()),
        )


if __name__ == "__main__":
    unittest.main()
