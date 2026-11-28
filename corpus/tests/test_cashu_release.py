from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from bitvm_corpus import cashu_release, cashu_replay, gc
from bitvm_corpus.canonical import ValidationError, digest
from bitvm_corpus.cli import main

ROOT = Path(__file__).resolve().parents[1]
REPLAY_REPORT = ROOT / "examples" / "native" / "cashu-release-replay-core31.1.json"
RELEASE_REPORT = ROOT / "examples" / "native" / "cashu-release-core31.1.json"


class CashuReplayTests(unittest.TestCase):
    def test_catalog_covers_payout_fallback_six_controls_and_reorg(self):
        rows = cashu_replay.catalog()
        recipes = {r["recipe"] for r in rows}
        self.assertEqual(len(rows), 10)
        self.assertIn("honest_payout", recipes)
        self.assertIn("holder_fallback_before_release", recipes)
        self.assertIn("holder_fallback_after_release", recipes)
        self.assertIn("substituted_beneficiary", recipes)
        self.assertIn("reorg_and_timeout_fork", recipes)
        for name in cashu_replay.WITNESS_CONTROLS:
            self.assertIn(name, recipes)

    def test_committed_replay_receipt_audits_clean(self):
        report = json.loads(REPLAY_REPORT.read_text(encoding="utf-8"))
        self.assertEqual(cashu_replay.audit(report), [])
        self.assertEqual(report["evidence_level"], "arena_replayed_regtest")
        self.assertEqual(report["provenance"]["wallets_loaded"], 0)
        self.assertEqual(report["summary"]["substitution_controls_rejected"], 6)
        self.assertTrue(report["summary"]["honest_payout_confirmed"])
        self.assertEqual(report["summary"]["expectation_failures"], [])
        for case in report["cases"]:
            for req in cashu_replay.REQUIRED_RECEIPT_FIELDS:
                self.assertIn(req, case)

    def test_replay_audit_detects_tampering(self):
        report = json.loads(REPLAY_REPORT.read_text(encoding="utf-8"))
        # Tamper wallets_loaded -> audit fails.
        bad = deepcopy(report)
        bad["provenance"]["wallets_loaded"] = 1
        bad.pop("evidence_hash")
        bad["evidence_hash"] = digest(bad)
        self.assertTrue(any("walletless" in p for p in cashu_replay.audit(bad)))

        # Tamper funded_target reserve_outpoint -> audit fails.
        bad2 = deepcopy(report)
        bad2["cases"][0]["funded_target"]["reserve_outpoint"] = "00" * 32 + ":0"
        bad2.pop("evidence_hash")
        bad2["evidence_hash"] = digest(bad2)
        self.assertTrue(any("funded_target" in p for p in cashu_replay.audit(bad2)))

    def test_verify_archive_rejects_wrong_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "fake.zip"
            fake.write_bytes(b"not the pinned spiral archive")
            with self.assertRaisesRegex(ValidationError, "archive sha256 mismatch"):
                cashu_replay.verify_and_load_archive(fake)

    def test_cli_native_audit_on_replay_receipt(self):
        self.assertEqual(main(["native", "audit", str(REPLAY_REPORT)]), 0)


class CashuReleaseCeremonyAndAttackTests(unittest.TestCase):
    def test_catalog_covers_all_10_families_x_4_trajectories(self):
        rows = cashu_release.catalog()
        self.assertEqual(len(rows), 40)
        families = {r["family"] for r in rows}
        self.assertEqual(len(families), 10)
        for family in (
            "wrong_circuit_under_pin",
            "leaked_accept_label",
            "selective_failure",
            "tape_equivocation",
            "seed_delta_reuse",
            "decoding_polarity_flip",
            "withholding",
            "garbler_challenger_collusion",
            "proof_replay",
            "statement_substitution",
        ):
            self.assertIn(family, families)

    def test_k4_cut_and_choose_always_catches_cheating_on_every_instance(self):
        recipe = "wrong_circuit_under_pin"
        cfg = cashu_release.config_for(recipe, "hardened")
        self.assertEqual((cfg.cut_and_choose_k, cfg.challenge_mode), (4, "joint"))
        for n in range(20):
            cid = f"test.{recipe}.{n}"
            cer = cashu_release.run_ceremony(cid, cfg, cashu_release._statement_for(cid, cfg), recipe=recipe, attack=True)
            self.assertFalse(cer["checks"]["openings_verified"])
            self.assertFalse(cer["ceremony_ok"])
            self.assertFalse(cer["challenge"]["escaped"])
            self.assertEqual(cer["opened_count"], 3)

    def test_single_bad_instance_escapes_exactly_when_kept(self):
        # One honest draw per ceremony: a 1-of-4 cheat escapes iff its instance is kept (~1/4).
        recipe = "decoding_polarity_flip"
        cfg = cashu_release.config_for(recipe, "hardened")
        escapes = 0
        trials = 200
        for n in range(trials):
            cid = f"test.{recipe}.{n}"
            cer = cashu_release.run_ceremony(cid, cfg, cashu_release._statement_for(cid, cfg), recipe=recipe, attack=True)
            kept_bad = cer["kept"] in cer["bad_indices"]
            self.assertEqual(cer["challenge"]["escaped"], kept_bad)
            self.assertEqual(cer["ceremony_ok"], kept_bad)
            self.assertNotIn("extra_nonce", cer["challenge"])
            escapes += kept_bad
        self.assertTrue(0.15 < escapes / trials < 0.35, escapes)

    def test_challenge_reveals_are_keyed_by_role_secrets(self):
        cfg = cashu_release.config_for("decoding_polarity_flip", "hardened")
        cid = "test.reveal"
        cer = cashu_release.run_ceremony(cid, cfg, cashu_release._statement_for(cid, cfg),
                                         recipe="decoding_polarity_flip", attack=True)
        public_only = cashu_release.cashu_hash("reveal-holder", cid, "0").hex()
        self.assertNotEqual(cer["challenge"]["reveal_holder"], public_only)
        self.assertNotIn("kept_seed", cer)

    def test_statement_substitution_statement_differs_and_binding_decides(self):
        for profile, same_int in (("hardened", False), ("mutant", True)):
            cfg = cashu_release.config_for("statement_substitution", profile)
            pinned = cashu_release._statement_for("test.sub", cfg)
            attacker = cashu_release._statement_for("test.sub", cfg, holder_role="attacker")
            self.assertNotEqual(pinned, attacker)
            ints = [cashu_release.statement_int_from(cashu_release.verifier_view(s, cfg)) for s in (pinned, attacker)]
            self.assertEqual(ints[0] == ints[1], same_int)

    def test_selective_failure_leak_needs_a_bad_kept_instance(self):
        recipe = "selective_failure"
        for profile, leaked in (("mutant", True), ("hardened", False)):
            cfg = cashu_release.config_for(recipe, profile)
            cid = f"test.{recipe}.{profile}"
            cer = cashu_release.run_ceremony(cid, cfg, cashu_release._statement_for(cid, cfg), recipe=recipe,
                                             attack=(profile == "mutant"))
            probe = cashu_release.selective_failure_probe(
                cer, cfg, cashu_release.proof_for(cer["statement_int"], honest=True))
            self.assertEqual(probe["secret_bit_leaked"], leaked)
            if leaked:
                self.assertEqual(probe["actual"]["verdict"], "invalid")
                self.assertNotEqual(probe["counterfactual"]["verdict"], "invalid")

    def test_always_accept_circuit_matches_gate_count_and_accepts_false_proof(self):
        stmt = 48_400
        honest_c = gc.statement_circuit(stmt)
        bad_c = cashu_release.always_accept_circuit()
        self.assertEqual(bad_c.and_count, honest_c.and_count)
        g = cashu_release.garble_circuit(bad_c, stmt, b"0" * 16)
        false_bits = gc.proof_bits(*cashu_release.proof_for(stmt, honest=False))
        out = cashu_release.evaluate_circuit(bad_c, g.tables, g.input_labels(false_bits))
        self.assertEqual(out, g.accept_label)

    def test_equivocated_tables_change_commitment_and_accept_false_proof(self):
        stmt = 48_400
        c = gc.statement_circuit(stmt)
        g = gc.garble(stmt, b"1" * 16)
        false_bits = gc.proof_bits(*cashu_release.proof_for(stmt, honest=False))
        eq_tables = cashu_release._build_equivocated_tables_for_proof(c, g, false_bits)
        self.assertNotEqual(
            cashu_release.cashu_tables_commitment(eq_tables),
            cashu_release.cashu_tables_commitment(g.tables),
        )
        out = cashu_release.evaluate_circuit(c, eq_tables, g.input_labels(false_bits))
        self.assertEqual(out, g.accept_label)

    def test_committed_cashu_release_report_audits_clean(self):
        report = json.loads(RELEASE_REPORT.read_text(encoding="utf-8"))
        self.assertEqual(cashu_release.audit(report), [])
        self.assertEqual(report["evidence_level"], "arena_reconstruction_regtest")
        self.assertEqual(report["summary"]["cases"], 40)
        self.assertEqual(report["summary"]["expectation_failures"], [])
        self.assertEqual(main(["native", "audit", str(RELEASE_REPORT)]), 0)
        # Verify separate scoring dimensions on every case.
        for case in report["cases"]:
            for req in cashu_replay.REQUIRED_RECEIPT_FIELDS:
                self.assertIn(req, case)
            self.assertIn("legitimate_completion", case)
            self.assertIn("unauthorized_release", case)
            self.assertIn("diverted_principal_sats", case)

    def test_cashu_release_audit_detects_tampering(self):
        report = json.loads(RELEASE_REPORT.read_text(encoding="utf-8"))
        bad = deepcopy(report)
        bad["cases"][0]["outcome"]["attacker_success"] = True
        bad.pop("evidence_hash")
        bad["evidence_hash"] = digest(bad)
        self.assertTrue(cashu_release.audit(bad))

        bad2 = deepcopy(report)
        cer = next(s for s in bad2["cases"][0]["steps"] if s["label"] == "ceremony")
        cer["transcript_view"] = "00" * 32
        bad2.pop("evidence_hash")
        bad2["evidence_hash"] = digest(bad2)
        self.assertTrue(any("transcript_view" in p for p in cashu_release.audit(bad2)))

        # Flip a Core-rejected attack to confirmed and rescore consistently: the step check catches it.
        bad3 = deepcopy(report)
        case = next(c for c in bad3["cases"] if c["id"] == "cashu-release.proof_replay.hardened.attack")
        s = next(s for s in case["steps"] if s["label"] == "replayed release 2")
        s.update(allowed=True, broadcast=True, confirmed=True, reject_reason=None, blockhash="00" * 32)
        case["outcome"] = cashu_release.score(next(r for r in cashu_release.catalog() if r["id"] == case["id"]),
                                              case["steps"], case["observed_final_state"])
        bad3.pop("evidence_hash")
        bad3["evidence_hash"] = digest(bad3)
        self.assertTrue(any("mempool result" in p for p in cashu_release.audit(bad3)))

        # Claim a leaked bit where the offline recomputation finds none.
        bad4 = deepcopy(report)
        case = next(c for c in bad4["cases"] if c["id"] == "cashu-release.selective_failure.hardened.attack")
        case["observed_final_state"]["secret_bit_leaked"] = True
        bad4.pop("evidence_hash")
        bad4["evidence_hash"] = digest(bad4)
        self.assertTrue(any("secret_bit_leaked" in p for p in cashu_release.audit(bad4)))

    def test_diverted_sats_come_from_confirmed_outputs(self):
        report = json.loads(RELEASE_REPORT.read_text(encoding="utf-8"))
        by_id = {c["id"]: c for c in report["cases"]}
        self.assertEqual(cashu_release.paid_to_attacker(by_id["cashu-release.garbler_challenger_collusion.mutant.attack"]["steps"]), 24_750)
        self.assertEqual(cashu_release.paid_to_attacker(by_id["cashu-release.proof_replay.mutant.attack"]["steps"]), 0)
        self.assertTrue(by_id["cashu-release.proof_replay.mutant.attack"]["unauthorized_release"])


class LiveCashuReleaseCoreTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("BITVM_ARENA_BITCOIND"), "set BITVM_ARENA_BITCOIND to run against Core")
    def test_live_subset_withholding_and_wrong_circuit(self):
        rows = [
            r
            for r in cashu_release.catalog()
            if r["recipe"] in ("wrong_circuit_under_pin", "withholding")
        ]
        with tempfile.TemporaryDirectory() as tmp:
            report = cashu_release.execute(os.environ["BITVM_ARENA_BITCOIND"], Path(tmp) / "regtest", rows)
        self.assertEqual(report["summary"]["expectation_failures"], [])


if __name__ == "__main__":
    unittest.main()
