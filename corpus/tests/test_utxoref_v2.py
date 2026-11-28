from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from bitvm_corpus import utxoref_v2
from bitvm_corpus.bitcoin import Transaction
from bitvm_corpus.canonical import ValidationError, digest

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "examples" / "native" / "utxoref-v2-core31.1.json"
SUBSET_ONLY = {"catalog_hash does not match this library's catalog", "report does not cover the whole catalog"}


def load():
    return json.loads(REPORT.read_text(encoding="utf-8"))


def case_of(report, recipe):
    return next(c for c in report["cases"] if c["recipe"] == recipe)


def step_of(case, label):
    return next(s for s in case["steps"] if s["label"] == label)


def resealed(report):
    report.pop("evidence_hash")
    report["evidence_hash"] = digest(report)
    return report


class UtxoRefV2CatalogTests(unittest.TestCase):
    def test_catalog_has_one_as_built_row_per_recipe(self):
        rows = utxoref_v2.catalog()
        self.assertEqual(len(rows), len(utxoref_v2.RECIPES))
        self.assertEqual(len({r["id"] for r in rows}), len(rows))
        self.assertEqual({r["recipe"] for r in rows}, set(utxoref_v2.RUNNERS))
        self.assertEqual([r["recipe"] for r in rows if r["variant"] == "benign"], ["honest_settlement"])
        for row in rows:
            self.assertEqual(row["id"], f"utxoref-v2.{row['recipe']}.as_built.{row['variant']}")
            self.assertEqual((row["track"], row["profile"]), ("utxoref-v2", "as_built"))
            self.assertEqual(row["evidence_level"], "target_code_regtest")
            self.assertEqual(row["target"]["commit"], utxoref_v2.TARGET_COMMIT)
            self.assertEqual(set(row["expected"]), {"legitimate_completion", "attacker_success", "diverted_sats",
                                                    "defense_layer", "verdicts"})
            self.assertIn(row["expected"]["defense_layer"], ("n/a", "none", "bitcoin_script", "target_verifier"))
            # Every attack step has a predicted verdict.
            for label in utxoref_v2.RECIPES[row["recipe"]]["attack_steps"]:
                self.assertIn(label, row["expected"]["verdicts"])

    def test_verifier_rows_have_no_completion_and_no_diverted_script(self):
        for row in utxoref_v2.catalog():
            meta = utxoref_v2.RECIPES[row["recipe"]]
            if meta["layer"] == "verifier":
                self.assertIsNone(row["expected"]["legitimate_completion"])
                self.assertIsNone(meta["attacker_script"])
                self.assertEqual(row["expected"]["diverted_sats"], 0)

    def test_missing_tools_fail_with_a_clear_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"BVA_NODE": str(Path(tmp) / "no-node.exe")}):
                with self.assertRaisesRegex(ValidationError, "BVA_NODE"):
                    utxoref_v2.tool_paths()
            node = Path(tmp) / "node.exe"
            node.write_bytes(b"")
            with mock.patch.dict(os.environ, {"BVA_NODE": str(node), "BVA_UTXOREF": str(Path(tmp) / "none")}):
                with self.assertRaisesRegex(ValidationError, "BVA_UTXOREF"):
                    utxoref_v2.tool_paths()

    def test_fixed_keys_are_valid_and_distinct(self):
        values = list(utxoref_v2.keys().values()) + list(utxoref_v2.scripts().values())
        self.assertEqual(len(set(values)), len(values))


class UtxoRefV2SavedEvidenceTests(unittest.TestCase):
    def test_saved_report_audits_clean(self):
        report = load()
        self.assertEqual(utxoref_v2.audit(report), [])
        self.assertEqual(report["evidence_level"], "target_code_regtest")
        self.assertEqual(report["provenance"]["target"]["commit_observed"], utxoref_v2.TARGET_COMMIT)
        self.assertEqual(report["provenance"]["subversion"], "/Satoshi:31.1.0/")
        self.assertEqual(report["summary"]["cases"], len(utxoref_v2.RECIPES))
        self.assertEqual(report["summary"]["expectation_failures"], [])

    def test_saved_outcomes(self):
        report = load()
        vault = utxoref_v2.VAULT
        diverted = {c["recipe"]: c["diverted_sats"] for c in report["cases"] if c["diverted_sats"]}
        self.assertEqual(diverted, {
            "disprove_fraud_to_challenger": vault - utxoref_v2.DISPROVE_FEE,
            "recovery_after_stalled_settlement": vault - utxoref_v2.RECOVERY_FEE,
            "recovery_resigned_to_other_script": vault - utxoref_v2.RESIGNED_RECOVERY_FEE,
            "collusion_opposite_preimage_sweep": vault - utxoref_v2.DISPROVE_FEE,
            "cosigned_settlement_to_other_outputs": vault - utxoref_v2.FEE})
        for case in report["cases"]:
            self.assertEqual(case["attacker_success"], case["defense_layer"] == "none", case["id"])
            # A diverting attack and payment of the payees exclude each other.
            self.assertFalse(case["diverted_sats"] and case["legitimate_completion"], case["id"])
        resigned = step_of(case_of(report, "recovery_resigned_to_other_script"), "resign recovery")["result"]
        self.assertTrue(resigned["challengerSignatureReused"] and resigned["settlementTxUnchanged"])
        self.assertFalse(resigned["challengerSecretUsed"])
        self.assertTrue(resigned["verify"]["ok"])

    def test_diverted_sats_are_read_from_confirmed_raw_transactions(self):
        case = case_of(load(), "recovery_resigned_to_other_script")
        confirmed = step_of(case, "resigned recovery")
        outputs = Transaction.parse(confirmed["raw_transaction"]).outputs
        self.assertEqual([(value, spk.hex()) for value, spk in outputs],
                         [(case["diverted_sats"], utxoref_v2.scripts()["operator_other"])])
        self.assertEqual(utxoref_v2.paid_to(case["steps"], utxoref_v2.scripts()["operator_wallet"]), 0)

    def test_audit_detects_tampering(self):
        report = load()

        flipped = deepcopy(report)
        case_of(flipped, "disprove_valid_trace")["outcome"]["attacker_success"] = True
        self.assertTrue(any("outcome does not follow" in p for p in utxoref_v2.audit(resealed(flipped))))

        inflated = deepcopy(report)
        case = case_of(inflated, "disprove_fraud_to_challenger")
        case["diverted_sats"] = case["outcome"]["diverted_sats"] = 1
        self.assertTrue(any("disprove_fraud_to_challenger" in p for p in utxoref_v2.audit(resealed(inflated))))

        # A Core refusal rewritten as a confirmation, with Core's recorded result rewritten to match
        # and the case rescored: the local re-execution of the leaf still disagrees.
        accepted = deepcopy(report)
        case = case_of(accepted, "disprove_valid_trace")
        forged = step_of(case, "forged disprove on gate leaf")
        forged.update(allowed=True, broadcast=True, confirmed=True, reject_reason=None, blockhash="00" * 32,
                      mempool_result={"allowed": True})
        row = next(r for r in utxoref_v2.catalog() if r["id"] == case["id"])
        case["outcome"] = utxoref_v2.score(row, case["steps"])
        for field in ("legitimate_completion", "attacker_success", "diverted_sats", "defense_layer"):
            case[field] = case["outcome"][field]
        case["expectation_met"] = case["outcome"] == case["expected"]
        accepted["summary"]["expectation_failures"] = [c["id"] for c in accepted["cases"] if not c["expectation_met"]]
        accepted["summary"]["attacks_confirmed"] = [c["id"] for c in accepted["cases"] if c["attacker_success"]]
        accepted["summary"]["diverted_sats"] = sum(c["diverted_sats"] for c in accepted["cases"])
        self.assertTrue(any("the recorded steps give hashlock_mismatch" in p
                            for p in utxoref_v2.audit(resealed(accepted))))

        # A transaction that is not the one the target built.
        swapped = deepcopy(report)
        case = case_of(swapped, "honest_settlement")
        step_of(case, "graph vault")["result"]["settlementWitnessTxHex"] = \
            step_of(case, "graph vault")["result"]["recoveryWitnessTxHex"]
        self.assertTrue(any("differs from the transaction the target built" in p
                            for p in utxoref_v2.audit(resealed(swapped))))

        # A leaf that does not rebuild from the recorded keys.
        releafed = deepcopy(report)
        setup = step_of(case_of(releafed, "honest_settlement"), "setup vault")["result"]
        setup["operatorXonly"] = setup["challengerXonly"]
        self.assertTrue(any("leaf scripts do not rebuild" in p for p in utxoref_v2.audit(resealed(releafed))))

        # A verifier verdict detached from the object it is about.
        detached = deepcopy(report)
        probe = step_of(case_of(detached, "settlement_keys_from_own_commitment"),
                        "settlement verifier on forged settlement")
        probe["params"]["settlement"] = step_of(case_of(detached, "settlement_keys_from_own_commitment"),
                                                "graph vault")["result"]["settlement"]
        self.assertTrue(any("not a check of the forged object" in p for p in utxoref_v2.audit(resealed(detached))))

        repinned = deepcopy(report)
        repinned["provenance"]["target"]["commit_observed"] = "00" * 20
        self.assertTrue(any("pinned target commit" in p for p in utxoref_v2.audit(resealed(repinned))))


class LiveUtxoRefV2CoreTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("BITVM_ARENA_BITCOIND"), "set BITVM_ARENA_BITCOIND to run against Core")
    def test_live_subset_against_the_pinned_target(self):
        try:
            utxoref_v2.tool_paths()
        except ValidationError as exc:
            self.skipTest(str(exc))
        wanted = ("honest_settlement", "disprove_fraud_to_challenger", "recovery_resigned_to_other_script",
                  "settlement_keys_from_own_commitment")
        rows = [r for r in utxoref_v2.catalog() if r["recipe"] in wanted]
        with tempfile.TemporaryDirectory() as tmp:
            report = utxoref_v2.execute(os.environ["BITVM_ARENA_BITCOIND"], Path(tmp) / "regtest", rows)
        self.assertEqual(report["summary"]["expectation_failures"], [])
        self.assertEqual(set(utxoref_v2.audit(report)), SUBSET_ONLY)


if __name__ == "__main__":
    unittest.main()
