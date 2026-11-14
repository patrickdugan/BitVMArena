"""Mutation tests for swapped target IDs, copied evidence, wrong heights,
forged native status, reference-as-settlement, and unmet evidence gates.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import unittest

from bitvm_arena.cpa_campaign import (
    CPACampaignSession,
    EVIDENCE_GATE_KEYS,
    _digest,
    replay_campaign_trace,
)
from bitvm_arena.cpa_campaign_native import (
    check_native_eligibility,
    verify_native_campaign_receipt,
)

SOURCE = os.environ.get("CPA_SOURCE")
NATIVE_REPORT_PATH = (
    Path(__file__).resolve().parents[1] / "evidence" / "cpa_campaign_native" / "raw_report.json"
)


def _rehash_campaign_events(trace: dict) -> None:
    prev = "0" * 64
    for event in trace["events"]:
        event["previous_event_hash"] = prev
        without_hash = {k: v for k, v in event.items() if k != "event_hash"}
        event["event_hash"] = _digest(without_hash)
        prev = event["event_hash"]


def _rehash_native_case_steps(case: dict) -> None:
    prev = "0" * 64
    for step in case["steps"]:
        step["previous_event_hash"] = prev
        without_hash = {k: v for k, v in step.items() if k != "event_hash"}
        step["event_hash"] = _digest(without_hash)
        prev = step["event_hash"]


@unittest.skipUnless(SOURCE, "set CPA_SOURCE to the pinned bitcoin-rs checkout")
class ReferenceCampaignMutationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(SOURCE)
        dev_sess = CPACampaignSession(cls.source, "dev-honest-two-step-lineage", max_attempts=4)
        dev_sess.step({"request_bits": [1, 1, 0]})
        dev_sess.step({"request_bits": [1, 1, 0], "stage_role": "child"})
        cls.dev_trace = dev_sess.export_trace()
        cls.dev_digest = dev_sess.observe()["funded_target_digest"]

        held_sess = CPACampaignSession(cls.source, "heldout-honest-a-and-not-b", max_attempts=4)
        held_sess.step({"request_bits": [1, 0, 0]})
        cls.held_trace = held_sess.export_trace()
        cls.held_digest = held_sess.observe()["funded_target_digest"]

        cal_sess = CPACampaignSession(cls.source, "dev-calibration-weaker-parent", max_attempts=4)
        cal_sess.step({
            "request_bits": [1, 1, 1],
            "target_coin": "calibration_wider_parent",
        })
        cls.cal_trace = cal_sess.export_trace()

    def test_swapped_target_ids_are_rejected(self):
        # 1. Submitting a held-out trace under the dev scenario expectation.
        with self.assertRaisesRegex(ValueError, "scenario_id differs"):
            replay_campaign_trace(
                self.source,
                copy.deepcopy(self.held_trace),
                expected_scenario_id="dev-honest-two-step-lineage",
                expected_target_digest=self.dev_digest,
            )

        # 2. Rewriting scenario_id while keeping foreign funded_target.
        swapped_id = copy.deepcopy(self.held_trace)
        swapped_id["scenario_id"] = "dev-honest-two-step-lineage"
        with self.assertRaisesRegex(ValueError, "target digest differs"):
            replay_campaign_trace(
                self.source,
                swapped_id,
                expected_scenario_id="dev-honest-two-step-lineage",
                expected_target_digest=self.dev_digest,
            )

        # 3. Replacing executed_target with calibration wider-authority target.
        swapped_exec = copy.deepcopy(self.dev_trace)
        swapped_exec["events"][0]["executed_target"] = copy.deepcopy(
            self.cal_trace["events"][0]["executed_target"]
        )
        _rehash_campaign_events(swapped_exec)
        with self.assertRaisesRegex(ValueError, "differs from deterministic source replay"):
            replay_campaign_trace(
                self.source,
                swapped_exec,
                expected_scenario_id="dev-honest-two-step-lineage",
                expected_target_digest=self.dev_digest,
            )

    def test_copied_evidence_across_steps_or_scenarios_is_rejected(self):
        # Copy transaction/witness bytes from held_out step into dev step.
        copied_tx = copy.deepcopy(self.dev_trace)
        donor = self.held_trace["events"][0]
        for field in ("transaction_hex", "txid", "wtxid", "witness_hex", "candidate_outputs"):
            copied_tx["events"][0][field] = copy.deepcopy(donor[field])
        _rehash_campaign_events(copied_tx)
        with self.assertRaisesRegex(ValueError, "differs from deterministic source replay"):
            replay_campaign_trace(
                self.source,
                copied_tx,
                expected_scenario_id="dev-honest-two-step-lineage",
                expected_target_digest=self.dev_digest,
            )

        # Copy parent event into child slot (even after rehashing event chain).
        copied_step = copy.deepcopy(self.dev_trace)
        copied_step["events"][1] = copy.deepcopy(copied_step["events"][0])
        copied_step["events"][1]["index"] = 1
        _rehash_campaign_events(copied_step)
        with self.assertRaisesRegex(ValueError, "spent_input|differs from deterministic source replay"):
            replay_campaign_trace(
                self.source,
                copied_step,
                expected_scenario_id="dev-honest-two-step-lineage",
                expected_target_digest=self.dev_digest,
            )

    def test_wrong_heights_are_rejected(self):
        for mutator in (
            lambda t: t["events"][0].update(chain_height_before=101),
            lambda t: t["events"][0].update(chain_height_after=102),
            lambda t: t["events"][1].update(chain_height_before=102),
            lambda t: t["events"][1].update(chain_height_after=103),
            lambda t: t["funded_target"]["context"].update(funding_height=101),
        ):
            mutated = copy.deepcopy(self.dev_trace)
            mutator(mutated)
            _rehash_campaign_events(mutated)
            with self.subTest(mutator=mutator), self.assertRaises(ValueError):
                replay_campaign_trace(
                    self.source,
                    mutated,
                    expected_scenario_id="dev-honest-two-step-lineage",
                    expected_target_digest=self.dev_digest,
                )

    def test_forged_native_status_is_rejected(self):
        for mutator in (
            lambda t: t["events"][0]["native_execution"].update(executed=True),
            lambda t: t["events"][0]["native_execution"].update(execution_verified=True),
            lambda t: t["score"]["native_execution"].update(executed=True),
            lambda t: t["score"]["native_execution"].update(execution_verified=True),
        ):
            mutated = copy.deepcopy(self.held_trace)
            mutator(mutated)
            _rehash_campaign_events(mutated)
            with self.subTest(mutator=mutator), self.assertRaisesRegex(
                ValueError, "cannot claim native execution"
            ):
                replay_campaign_trace(
                    self.source,
                    mutated,
                    expected_scenario_id="heldout-honest-a-and-not-b",
                    expected_target_digest=self.held_digest,
                )

    def test_accepted_reference_result_presented_as_observed_settlement_is_rejected(self):
        # Genuine Script-oracle + parent-policy accepted reference trace:
        self.assertTrue(self.held_trace["events"][0]["script_oracle"]["accepted"])
        self.assertTrue(self.held_trace["events"][0]["policy_decision"]["parent_policy_accept"])

        for mutator in (
            lambda t: t["events"][0]["native_execution"].update(settlement_observed=True),
            lambda t: t["score"]["native_execution"].update(settlement_observed=True),
        ):
            forged_settlement = copy.deepcopy(self.held_trace)
            mutator(forged_settlement)
            _rehash_campaign_events(forged_settlement)
            with self.subTest(mutator=mutator), self.assertRaisesRegex(
                ValueError, "observed settlement"
            ):
                replay_campaign_trace(
                    self.source,
                    forged_settlement,
                    expected_scenario_id="heldout-honest-a-and-not-b",
                    expected_target_digest=self.held_digest,
                )

    def test_unverified_evidence_gates_are_rejected(self):
        for gate in EVIDENCE_GATE_KEYS:
            for on_score in (False, True):
                mutated = copy.deepcopy(self.held_trace)
                if on_score:
                    mutated["score"]["evidence_gates"][gate] = True
                else:
                    mutated["events"][0]["evidence_gates"][gate] = True
                _rehash_campaign_events(mutated)
                with self.subTest(gate=gate, on_score=on_score), self.assertRaisesRegex(
                    ValueError, "unverified evidence gates"
                ):
                    replay_campaign_trace(
                        self.source,
                        mutated,
                        expected_scenario_id="heldout-honest-a-and-not-b",
                        expected_target_digest=self.held_digest,
                    )


@unittest.skipUnless(
    SOURCE and NATIVE_REPORT_PATH.is_file(),
    "set CPA_SOURCE and ensure evidence/cpa_campaign_native/raw_report.json exists",
)
class NativeCampaignMutationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = Path(SOURCE)
        cls.report = json.loads(NATIVE_REPORT_PATH.read_text(encoding="utf-8"))

    def _find_case(self, scenario_id: str) -> tuple[int, dict]:
        for idx, item in enumerate(self.report["cases"]):
            if item["scenario_id"] == scenario_id:
                return idx, item
        raise AssertionError(f"missing scenario {scenario_id} in retained native report")

    def test_native_swapped_target_ids_and_funding_tags_are_rejected(self):
        idx_a, _ = self._find_case("dev-honest-root-and")
        idx_b, _ = self._find_case("heldout-honest-a-and-not-b")

        # 1. Swap funded_target + digest between two cases.
        mutated = copy.deepcopy(self.report)
        mutated["cases"][idx_a]["funded_target"] = copy.deepcopy(mutated["cases"][idx_b]["funded_target"])
        mutated["cases"][idx_a]["funded_target_digest"] = mutated["cases"][idx_b]["funded_target_digest"]
        with self.assertRaisesRegex(ValueError, "swapped or mismatched target identity"):
            verify_native_campaign_receipt(mutated, self.source)

        # 2. Swap entire case body under another case_id -> caught by OP_RETURN sha256(case_id) tag.
        mutated_tag = copy.deepcopy(self.report)
        saved_case_id = mutated_tag["cases"][idx_a]["case_id"]
        mutated_tag["cases"][idx_a] = copy.deepcopy(mutated_tag["cases"][idx_b])
        mutated_tag["cases"][idx_a]["case_id"] = saved_case_id
        with self.assertRaisesRegex(ValueError, "duplicate or mismatched funding_txid|case-binding tag"):
            verify_native_campaign_receipt(mutated_tag, self.source)

        # 3. Relabel calibration coin step (origin_vout=3) as original target (origin_vout=0).
        idx_cal, _ = self._find_case("dev-calibration-weaker-parent")
        mutated_cal = copy.deepcopy(self.report)
        mutated_cal["cases"][idx_cal]["steps"][0]["funded_origin"]["origin_vout"] = 0
        mutated_cal["cases"][idx_cal]["steps"][0]["funded_origin"]["spent_vout"] = 0
        _rehash_native_case_steps(mutated_cal["cases"][idx_cal])
        with self.assertRaisesRegex(ValueError, "funded_origin lineage mismatch"):
            verify_native_campaign_receipt(mutated_cal, self.source)

    def test_native_copied_evidence_is_rejected(self):
        idx_out, _ = self._find_case("dev-output-substitution")
        mutated = copy.deepcopy(self.report)
        # Copy rejection step 0 onto rejection step 1.
        donor = copy.deepcopy(mutated["cases"][idx_out]["steps"][0])
        donor["index"] = 1
        mutated["cases"][idx_out]["steps"][1] = donor
        _rehash_native_case_steps(mutated["cases"][idx_out])
        with self.assertRaisesRegex(ValueError, "duplicate copied step|copied or altered"):
            verify_native_campaign_receipt(mutated, self.source)

        # Flip 1 witness bit without updating source reconstruction -> wtxid mismatch.
        mutated_wit = copy.deepcopy(self.report)
        step = mutated_wit["cases"][idx_out]["steps"][0]
        raw_bytes = bytearray.fromhex(step["raw_tx"])
        raw_bytes[-5] ^= 1
        step["raw_tx"] = raw_bytes.hex()
        _rehash_native_case_steps(mutated_wit["cases"][idx_out])
        with self.assertRaisesRegex(ValueError, "copied or altered transaction/witness bytes"):
            verify_native_campaign_receipt(mutated_wit, self.source)

    def test_native_wrong_heights_are_rejected(self):
        idx_lin, _ = self._find_case("heldout-honest-two-step-not-a-and-b")
        idx_tim, _ = self._find_case("dev-timing-boundaries")

        # 1. Wrong funding height (101 instead of 102).
        m1 = copy.deepcopy(self.report)
        m1["cases"][idx_lin]["funding"]["height"] = 101
        with self.assertRaisesRegex(ValueError, "funding height"):
            verify_native_campaign_receipt(m1, self.source)

        # 2. Wrong parent confirmation height (104 instead of 103).
        m2 = copy.deepcopy(self.report)
        m2["cases"][idx_lin]["steps"][0]["native_execution"]["confirmed_height"] = 104
        m2["cases"][idx_lin]["steps"][0]["native_execution"]["height_after"] = 104
        _rehash_native_case_steps(m2["cases"][idx_lin])
        with self.assertRaisesRegex(ValueError, "confirmed native transition"):
            verify_native_campaign_receipt(m2, self.source)

        # 3. Wrong post-confirmation replay height_before (102 instead of 103).
        m3 = copy.deepcopy(self.report)
        replay_step = next(
            s for s in m3["cases"][idx_tim]["steps"]
            if s["canonical_proposal"]["post_confirm_mode"] == "replay_confirmed_tx"
        )
        replay_step["native_execution"]["height_before"] = 102
        _rehash_native_case_steps(m3["cases"][idx_tim])
        with self.assertRaisesRegex(ValueError, "wrong chain height or tip"):
            verify_native_campaign_receipt(m3, self.source)

    def test_native_forged_status_unpinned_binary_and_gated_scenarios_are_rejected(self):
        # 1. External JSON pre-asserting execution_verified=True.
        forged_top = copy.deepcopy(self.report)
        forged_top["execution_verified"] = True
        with self.assertRaisesRegex(ValueError, "execution_verified=True"):
            verify_native_campaign_receipt(forged_top, self.source)

        # 2. Step-level forged execution_verified=True on parsed report.
        forged_step = copy.deepcopy(self.report)
        forged_step["cases"][0]["steps"][0]["native_execution"]["execution_verified"] = True
        _rehash_native_case_steps(forged_step["cases"][0])
        with self.assertRaisesRegex(ValueError, "forged or invalid native_execution"):
            verify_native_campaign_receipt(forged_step, self.source)

        # 3. Unpinned binary SHA256.
        unpinned = copy.deepcopy(self.report)
        unpinned["binary_sha256"] = hashlib.sha256(b"unpinned-binary").hexdigest()
        with self.assertRaisesRegex(ValueError, "unpinned CPA native binary"):
            verify_native_campaign_receipt(unpinned, self.source)

        # 4. Gated scenarios cannot connect to native execution.
        for gated_id in ("dev-gated-zk-p2mr-hypothesis", "heldout-gated-hf-checksig-hypothesis"):
            with self.subTest(gated_id=gated_id), self.assertRaisesRegex(
                ValueError, "unmet evidence gates"
            ):
                check_native_eligibility(gated_id)

    def test_native_unconfirmed_or_reference_result_cannot_claim_observed_settlement(self):
        idx_hon, _ = self._find_case("dev-honest-root-and")
        idx_out, _ = self._find_case("dev-output-substitution")

        # 1. Accepted dry-run / reference step stripped of block confirmation proof.
        unconfirmed = copy.deepcopy(self.report)
        step = unconfirmed["cases"][idx_hon]["steps"][0]
        step["native_execution"]["confirmed_block"] = None
        step["native_execution"]["confirmed_height"] = None
        step["native_execution"]["settlement_observed"] = True
        _rehash_native_case_steps(unconfirmed["cases"][idx_hon])
        with self.assertRaisesRegex(ValueError, "missing valid block/height/settlement proof"):
            verify_native_campaign_receipt(unconfirmed, self.source)

        # 2. Rejected candidate claiming settlement_observed=True.
        rejected_claim = copy.deepcopy(self.report)
        rstep = rejected_claim["cases"][idx_out]["steps"][0]
        rstep["native_execution"]["settlement_observed"] = True
        _rehash_native_case_steps(rejected_claim["cases"][idx_out])
        with self.assertRaisesRegex(ValueError, "rejection boundary/tip/height"):
            verify_native_campaign_receipt(rejected_claim, self.source)

    def test_native_unverified_evidence_gates_are_rejected(self):
        for gate in EVIDENCE_GATE_KEYS:
            mutated = copy.deepcopy(self.report)
            mutated["evidence_gates"][gate] = True
            with self.subTest(gate=gate), self.assertRaisesRegex(
                ValueError, "unverified evidence gates"
            ):
                verify_native_campaign_receipt(mutated, self.source)


if __name__ == "__main__":
    unittest.main()
