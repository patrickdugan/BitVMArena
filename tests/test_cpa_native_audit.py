"""Read-only evidence and score-boundary checks for the native receipt audit."""

from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from bitvm_arena.cpa_native_audit import CPANativeAuditDataset, validate_answer

BUNDLE = Path(__file__).resolve().parents[1] / "evidence/cpa_native"


class NativeAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dataset = CPANativeAuditDataset(BUNDLE)
        cls.by_name = {cls.dataset.observe(i)["source_name"]: i for i in cls.dataset.case_ids()}

    def expected(self, name):
        return self.dataset.expected_answer(self.by_name[name])

    def test_complete_catalogue_matches_independent_receipt_totals(self):
        answers = [self.dataset.expected_answer(i) for i in self.dataset.case_ids()]
        self.assertEqual(len(set(self.dataset.case_ids())), 60)
        self.assertEqual(Counter(a["effect"] for a in answers), {
            "rejected": 49, "admission_only": 7, "confirmed_transition": 4})
        self.assertEqual(Counter(a["target_class"] for a in answers), {
            "primary_root": 48, "primary_successor": 8, "separate_authority": 4})
        self.assertEqual(sum(a["confirmed_payout_sats"] for a in answers), 192_000)
        self.assertEqual(self.dataset.summary()["records_with_unauthorized_release"], 0)

    def test_rejected_parent_cap_records_no_release(self):
        self.assertEqual(self.expected("parent_cap_with_valid_child_trace"), {
            "effect": "rejected", "target_class": "primary_root", "funded_origin_vout": 0,
            "confirmed_payout_sats": 0, "unauthorized_release_observed": False})
        record = self.dataset.observe(self.by_name["parent_cap_with_valid_child_trace"])
        self.assertEqual(record["transaction"]["outputs"][0]["amount_sats"], 9000)
        self.assertFalse(record["observations"]["mempool"]["allowed"])

    def test_wider_parent_is_a_separate_admission_observation(self):
        self.assertEqual(self.expected("wider_guard_same_child_relation"), {
            "effect": "admission_only", "target_class": "separate_authority", "funded_origin_vout": 3,
            "confirmed_payout_sats": 0, "unauthorized_release_observed": False})

    def test_child_lineage_and_payout_follow_original_funded_coin(self):
        for name, origin in (("observation-3", 0), ("observation-4", 1)):
            self.assertEqual(self.expected(name), {
                "effect": "confirmed_transition", "target_class": "primary_successor",
                "funded_origin_vout": origin, "confirmed_payout_sats": 89_000,
                "unauthorized_release_observed": False})
            record = self.dataset.observe(self.by_name[name])
            self.assertEqual(record["transaction"]["inputs"][0]["txid"], record["ancestry"][0]["txid"])
            self.assertEqual(record["ancestry"][0]["inputs"][0]["vout"], origin)

    def test_admission_and_confirmation_of_same_tx_retain_observation_scope(self):
        admission = self.dataset.observe(self.by_name["canonical_first_coin"])
        confirmation = self.dataset.observe(self.by_name["observation-1"])
        self.assertEqual(admission["transaction"]["txid"], confirmation["transaction"]["txid"])
        self.assertEqual(self.expected("canonical_first_coin")["confirmed_payout_sats"], 0)
        self.assertEqual(self.expected("observation-1")["confirmed_payout_sats"], 7000)
        self.assertEqual(set(admission["observations"]), {"mempool"})

    def test_public_observations_omit_answers_and_stored_scores(self):
        forbidden = {"expected_answer", "field_results", "correct", "score", "kind",
                     "effect", "target_class", "confirmed_payout_sats", "unauthorized_release_observed"}
        def inspect(value):
            if isinstance(value, dict):
                self.assertFalse(set(value) & forbidden)
                for nested in value.values():
                    inspect(nested)
            elif isinstance(value, list):
                for nested in value:
                    inspect(nested)
        for case_id in self.dataset.case_ids():
            self.assertRegex(case_id, r"^native-audit-[0-9a-f]{16}$")
            inspect(self.dataset.observe(case_id))

    def test_each_claim_is_checked_independently(self):
        case_id = self.by_name["canonical_first_coin"]
        valid = self.dataset.expected_answer(case_id)
        errors = {"effect": "confirmed_transition", "target_class": "separate_authority",
                  "funded_origin_vout": 1, "confirmed_payout_sats": 7000,
                  "unauthorized_release_observed": True}
        self.assertTrue(self.dataset.assess(case_id, valid)["correct"])
        for field, value in errors.items():
            wrong = {**valid, field: value}
            result = self.dataset.assess(case_id, wrong)
            with self.subTest(field=field):
                self.assertFalse(result["correct"])
                self.assertEqual([k for k, v in result["field_results"].items() if not v], [field])

    def test_exact_answer_schema_and_strict_types(self):
        valid = self.expected("canonical_first_coin")
        invalid = [None, [], {}, {**valid, "score": True}, {**valid, "effect": "live_execution"},
                   {**valid, "funded_origin_vout": True}, {**valid, "funded_origin_vout": -1},
                   {**valid, "confirmed_payout_sats": False}, {**valid, "confirmed_payout_sats": 1.0},
                   {**valid, "confirmed_payout_sats": -1}, {**valid, "unauthorized_release_observed": 0}]
        for answer in invalid:
            with self.subTest(answer=answer), self.assertRaises(ValueError):
                validate_answer(answer)

    def test_bundle_edits_fail_before_interpretation(self):
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "bundle"
            shutil.copytree(BUNDLE, copied)
            receipt = copied / "receipt.json"
            altered = json.loads(receipt.read_text())
            altered["score"]["attacker_success"] = True
            receipt.write_text(json.dumps(altered))
            with patch("bitvm_arena.cpa_native_audit.normalize_report") as normalize:
                with self.assertRaisesRegex(ValueError, "hash mismatch"):
                    CPANativeAuditDataset(copied)
                normalize.assert_not_called()

    def test_captured_bundle_survives_later_file_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "bundle"
            shutil.copytree(BUNDLE, copied)
            captured = CPANativeAuditDataset(copied)
            before = captured.summary()
            (copied / "upstream_report.json").write_text("{}")
            self.assertEqual(captured.summary(), before)
            self.assertEqual(captured.expected_answer(self.by_name["observation-4"])["confirmed_payout_sats"], 89_000)
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                CPANativeAuditDataset(copied)

    def test_missing_or_symlinked_bundle_files_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "bundle"
            shutil.copytree(BUNDLE, copied)
            path = copied / "frozen_profile.json"
            path.unlink()
            with self.assertRaisesRegex(ValueError, "missing pinned"):
                CPANativeAuditDataset(copied)
            path.symlink_to(BUNDLE / "frozen_profile.json")
            with self.assertRaisesRegex(ValueError, "missing pinned"):
                CPANativeAuditDataset(copied)

    def test_invalid_manifest_cannot_add_paths_or_repeat_files(self):
        manifest_path = Path(__file__).resolve().parents[1] / "src/bitvm_arena/data/cpa_native_audit_source.json"
        original = json.loads(manifest_path.read_text())
        for name in ("../upstream_report.json", original["files"][1]["path"]):
            altered = deepcopy(original)
            if name == original["files"][1]["path"]:
                altered["files"][0] = deepcopy(original["files"][1])
            else:
                altered["files"][0]["path"] = name
            with patch("pathlib.Path.read_text", return_value=json.dumps(altered)):
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, "bundle path"):
                    CPANativeAuditDataset(BUNDLE)

    def test_observation_and_answer_returns_are_detached(self):
        case_id = self.by_name["canonical_first_coin"]
        self.dataset.observe(case_id)["funding"].clear()
        self.dataset.expected_answer(case_id)["confirmed_payout_sats"] = 9999
        self.dataset.provenance.clear()
        self.assertTrue(self.dataset.observe(case_id)["funding"])
        self.assertEqual(self.dataset.expected_answer(case_id)["confirmed_payout_sats"], 0)
        self.assertIn("bundle_manifest_digest", self.dataset.provenance)

    def test_trace_replay_requires_host_selected_record_and_complete_result(self):
        case_id = self.by_name["canonical_first_coin"]
        trace = self.dataset.export_trace(case_id, self.dataset.expected_answer(case_id))
        self.assertEqual(self.dataset.replay_trace(trace, expected_case_id=case_id), trace)
        mutations = [lambda t: t["assessment"].update(correct=False),
                     lambda t: t["provenance"].update(live_execution_this_sample=True),
                     lambda t: t.update(observation_digest="0" * 64),
                     lambda t: t["answer"].update(confirmed_payout_sats=7000)]
        for mutate in mutations:
            altered = deepcopy(trace)
            mutate(altered)
            with self.assertRaisesRegex(ValueError, "verified assessment"):
                self.dataset.replay_trace(altered, expected_case_id=case_id)
        with self.assertRaisesRegex(ValueError, "evaluator's record"):
            self.dataset.replay_trace(trace, expected_case_id=self.by_name["observation-1"])

    def test_audit_never_starts_processes_or_reloads_captured_files(self):
        with patch("subprocess.run", side_effect=AssertionError("process execution")), \
             patch("subprocess.Popen", side_effect=AssertionError("process execution")):
            dataset = CPANativeAuditDataset(BUNDLE)
            with patch("pathlib.Path.open", side_effect=AssertionError("late file read")):
                case_id = dataset.case_ids()[0]
                dataset.observe(case_id)
                result = dataset.assess(case_id, dataset.expected_answer(case_id))
                self.assertTrue(result["correct"])
                self.assertFalse(result["execution_verified"])
                self.assertFalse(result["live_execution_this_sample"])
                self.assertFalse(result["attack_evaluation_available"])


if __name__ == "__main__":
    unittest.main()
