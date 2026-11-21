"""Regression gates for the synthetic correlated setup threat campaign."""

from __future__ import annotations

import copy
import itertools
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from bitvm_arena.model import digest
from bitvm_arena.setup_compromise import (
    AMOUNT_SATS, ARMS, DOMAIN, HOST_COUNT, SIGNING_THRESHOLD, Trial,
    benchmark, get_trial, replay_receipt, run_trial,
)


class CorrelatedSetupTests(unittest.TestCase):
    def test_all_paired_expectations(self):
        result = benchmark()
        self.assertEqual(result["episodes"], 27)
        self.assertEqual(result["cases"], 9)
        self.assertTrue(result["all_expectations_met"])
        self.assertEqual(sum(r["score"]["attacker_success"] for r in result["results"]), 5)

    def test_every_coalition_at_declared_threshold(self):
        for n in range(HOST_COUNT + 1):
            for hosts in itertools.combinations(range(HOST_COUNT), n):
                trial = Trial("enumeration", "retained_setup_key", hosts, "covert" if hosts else "none")
                vanilla = run_trial(trial, "presigned-bitvm")
                keyless = run_trial(trial, "keyless-txcommit")
                self.assertEqual(vanilla["score"]["attacker_success"], n >= SIGNING_THRESHOLD)
                self.assertFalse(keyless["score"]["attacker_success"])
                self.assertEqual(vanilla["funded_target"]["logical_policy_id"],
                                 keyless["funded_target"]["logical_policy_id"])
                self.assertNotEqual(vanilla["funded_target"]["outpoint"],
                                    keyless["funded_target"]["outpoint"])

    def test_covert_and_visible_have_same_consensus_result_without_detector(self):
        covert = run_trial(get_trial("quorum-covert"), "presigned-bitvm")
        visible = run_trial(get_trial("quorum-visible"), "presigned-bitvm")
        self.assertEqual(covert["score"], visible["score"])
        self.assertNotEqual(covert["evidence_hash"], visible["evidence_hash"])
        self.assertIsNone(covert["events"][1]["payload"]["covert_channel_observed"])

    def test_setup_presign_poisoning_and_subthreshold(self):
        self.assertTrue(run_trial(get_trial("poisoned-presigns"), "presigned-bitvm")["score"]["attacker_success"])
        self.assertFalse(run_trial(get_trial("subthreshold-covert"), "presigned-bitvm")["score"]["attacker_success"])
        self.assertFalse(run_trial(get_trial("poisoned-presigns"), "keyless-txcommit")["score"]["attacker_success"])

    def test_watcher_outage_separate_from_setup_compromise(self):
        case = get_trial("watcher-outage")
        self.assertTrue(run_trial(case, "presigned-bitvm")["score"]["attacker_success"])
        self.assertFalse(run_trial(replace(case, watcher_online=True), "presigned-bitvm")["score"]["attacker_success"])
        self.assertFalse(run_trial(case, "keyless-txcommit")["score"]["attacker_success"])

    def test_txcommit_activation_is_a_separate_consensus_gate(self):
        case = get_trial("wrong-actual-tx")
        self.assertTrue(run_trial(case, "keyless-txcommit-disabled")["score"]["attacker_success"])
        self.assertFalse(run_trial(case, "keyless-txcommit")["score"]["attacker_success"])
        self.assertFalse(run_trial(case, "presigned-bitvm")["score"]["attacker_success"])
        self.assertFalse(run_trial(get_trial("wrong-old-state"), "keyless-txcommit-disabled")["score"]["attacker_success"])

    def test_proof_availability_is_a_liveness_result(self):
        for arm in ARMS:
            score = run_trial(get_trial("proof-withheld"), arm)["score"]
            self.assertTrue(score["liveness_blocked"])
            self.assertFalse(score["attacker_success"])
            self.assertEqual(score["unauthorized_sats"], 0)
            self.assertEqual(score["escrow_sats"], AMOUNT_SATS)

    def test_value_conserved_in_every_issued_case(self):
        for arm in ARMS:
            for case in ("honest", "quorum-covert", "watcher-outage", "wrong-actual-tx", "proof-withheld"):
                score = run_trial(get_trial(case), arm)["score"]
                self.assertEqual(
                    score["authorized_sats"] + score["unauthorized_sats"] + score["escrow_sats"], AMOUNT_SATS
                )
                self.assertEqual(score["attacker_success"], score["unauthorized_sats"] > 0)

    def test_replay_rejects_changed_score_even_after_forged_hash(self):
        original = run_trial(get_trial("quorum-covert"), "presigned-bitvm")
        replay_receipt(original, expected_arm="presigned-bitvm", expected_case="quorum-covert")
        tampered = copy.deepcopy(original)
        tampered["score"]["attacker_success"] = False
        body = {k: v for k, v in tampered.items() if k != "evidence_hash"}
        tampered["evidence_hash"] = digest({"domain": DOMAIN + "/receipt", "body": body})
        with self.assertRaisesRegex(ValueError, "differs"):
            replay_receipt(tampered, expected_arm="presigned-bitvm", expected_case="quorum-covert")
        with self.assertRaisesRegex(ValueError, "evaluator-selected"):
            replay_receipt(original, expected_arm="keyless-txcommit", expected_case="quorum-covert")

    def test_invalid_input_capabilities_fail_closed(self):
        bad = [
            Trial("bad", "retained_setup_key", (1, 1), "covert"),
            Trial("bad", "retained_setup_key", (-1,), "covert"),
            Trial("bad", "retained_setup_key", (HOST_COUNT,), "covert"),
            Trial("bad", "retained_setup_key", (True,), "covert"),
            Trial("bad", "retained_setup_key", (1, 0), "covert"),
            Trial("bad", "retained_setup_key", [0, 1], "covert"),
            Trial("bad", "retained_setup_key", (), "covert"),
            Trial("bad", "retained_setup_key", (), "none", watcher_online=1),
            Trial("../bad", "honest"),
            Trial("bad", "unknown_action"),
        ]
        for trial in bad:
            with self.subTest(trial=str(trial)), self.assertRaises(ValueError):
                run_trial(trial, "presigned-bitvm")
        with self.assertRaises(ValueError):
            run_trial(get_trial("honest"), "unknown-arm")

    def test_write_and_replay_saved_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "fresh"
            result = benchmark(out)
            self.assertTrue(result["all_expectations_met"])
            receipt = out / "receipts" / "quorum-covert.presigned-bitvm.json"
            import json
            replay_receipt(json.loads(receipt.read_text()), expected_arm="presigned-bitvm",
                           expected_case="quorum-covert")
            self.assertTrue((out / "summary.json").is_file())
            from bitvm_arena.setup_compromise import main
            with self.assertRaises(SystemExit) as error:
                main(["benchmark", "--output", str(out)])
            self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
