"""Retained receipt and live isolated-regtest tests for CPA campaign cases."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from bitvm_arena.cpa_campaign import DEFAULT_EVIDENCE_GATES
from bitvm_arena.cpa_campaign_native import (
    check_native_eligibility,
    default_native_campaign_specs,
    load_provenance_manifest,
    run_native_campaign_cases,
    verify_binary_provenance,
    verify_native_campaign_receipt,
)

SOURCE = os.environ.get("CPA_SOURCE")
BINARY = os.environ.get("CPA_CAMPAIGN_BINARY") or os.environ.get("CPA_BINARY")
EVIDENCE_DIR = Path(__file__).resolve().parents[1] / "evidence" / "cpa_campaign_native"
RAW_REPORT = EVIDENCE_DIR / "raw_report.json"


class CampaignProvenanceAndEligibilityTests(unittest.TestCase):
    def test_provenance_manifest_and_binary_pin_checks(self):
        manifest = load_provenance_manifest()
        self.assertGreaterEqual(len(manifest["approved_binaries"]), 1)
        for entry in manifest["approved_binaries"]:
            self.assertEqual(verify_binary_provenance(entry["binary_sha256"]), entry)
        with self.assertRaisesRegex(ValueError, "unpinned CPA native binary"):
            verify_binary_provenance(hashlib.sha256(b"forged").hexdigest())

    def test_default_specs_include_only_eligible_scenarios_and_exclude_gated_ones(self):
        all_specs = default_native_campaign_specs("all")
        dev_specs = default_native_campaign_specs("dev")
        held_specs = default_native_campaign_specs("held_out")
        self.assertEqual(len(all_specs), 18)
        self.assertEqual(len(dev_specs), 9)
        self.assertEqual(len(held_specs), 9)
        for gated in ("dev-gated-zk-p2mr-hypothesis", "heldout-gated-hf-checksig-hypothesis"):
            with self.assertRaisesRegex(ValueError, "unmet evidence gates"):
                check_native_eligibility(gated)


@unittest.skipUnless(
    SOURCE and RAW_REPORT.is_file(),
    "set CPA_SOURCE and ensure evidence/cpa_campaign_native/raw_report.json exists",
)
class RetainedNativeCampaignReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(SOURCE)
        cls.raw_report = json.loads(RAW_REPORT.read_text(encoding="utf-8"))
        cls.verified = verify_native_campaign_receipt(cls.raw_report, cls.source)

    def test_retained_native_report_verifies_from_source_bytes_without_execution_flag(self):
        # Parsing an existing JSON report never asserts live execution_verified=True.
        self.assertFalse(self.verified["execution_verified"])
        self.assertEqual(self.verified["evidence_gates"], DEFAULT_EVIDENCE_GATES)
        score = self.verified["score"]
        self.assertEqual(score["cases_verified"], 18)
        self.assertEqual(score["dev_cases"], 9)
        self.assertEqual(score["held_out_cases"], 9)
        self.assertEqual(score["legitimate_completions"], 18)
        self.assertFalse(score["attacker_success"])
        self.assertEqual(score["unauthorized_sats"], 0)
        self.assertEqual(score["diverted_sats"], 0)
        self.assertEqual(score["calibration_acceptances"], 2)
        self.assertEqual(score["confirmed_transitions"], 21)
        self.assertGreaterEqual(score["rejected_candidates"], 40)

    def test_distinct_oracle_synthetic_and_native_fields_and_all_rejection_boundaries(self):
        observed_boundaries: set[str] = set()
        for case in self.verified["cases"]:
            for step in case["steps"]:
                self.assertTrue(step["script_oracle"]["executed"])
                self.assertEqual(step["synthetic_simulator"], {"executed": False, "accepted": None})
                self.assertTrue(step["native_execution"]["executed"])
                self.assertFalse(step["native_execution"]["execution_verified"])
                self.assertEqual(
                    step["script_oracle"]["accepted"],
                    step["native_execution"]["accepted"],
                )
                if step["native_execution"]["accepted"]:
                    self.assertTrue(step["native_execution"]["settlement_observed"])
                    self.assertIsNotNone(step["native_execution"]["confirmed_block"])
                else:
                    self.assertFalse(step["native_execution"]["settlement_observed"])
                    observed_boundaries.add(step["native_execution"]["rejection_boundary"])
        self.assertTrue({"script", "standardness", "duplicate", "spent"}.issubset(observed_boundaries))


@unittest.skipUnless(
    os.name == "posix" and SOURCE and BINARY and Path(BINARY).is_file(),
    "POSIX, CPA_SOURCE, and CPA_CAMPAIGN_BINARY/CPA_BINARY required for live regtest execution",
)
class LiveNativeCampaignExecutionTests(unittest.TestCase):
    def test_live_per_case_isolated_regtest_and_gated_refusal(self):
        source = Path(SOURCE)
        binary = Path(BINARY)
        with tempfile.TemporaryDirectory(prefix="cpa-camp-live-test-") as tmp:
            with self.assertRaisesRegex(ValueError, "unmet evidence gates"):
                run_native_campaign_cases(
                    source,
                    binary,
                    Path(tmp) / "gated",
                    case_specs=[
                        {
                            "case_id": "gated",
                            "scenario_id": "dev-gated-zk-p2mr-hypothesis",
                            "proposals": [{"request_bits": [1, 1, 0]}],
                        }
                    ],
                )

            selected = [
                spec
                for spec in default_native_campaign_specs("all")
                if spec["scenario_id"]
                in {
                    "dev-calibration-weaker-parent",
                    "heldout-honest-two-step-not-a-and-b",
                    "dev-timing-boundaries",
                }
            ]
            receipt = run_native_campaign_cases(
                source,
                binary,
                Path(tmp) / "live",
                case_specs=selected,
                timeout=180,
            )
            self.assertTrue(receipt["execution_verified"])
            self.assertEqual(receipt["score"]["cases_verified"], 3)
            self.assertEqual(receipt["score"]["legitimate_completions"], 3)
            self.assertFalse(receipt["score"]["attacker_success"])
            self.assertEqual(receipt["score"]["calibration_acceptances"], 1)


if __name__ == "__main__":
    unittest.main()
