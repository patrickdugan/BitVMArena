from copy import deepcopy
import json
from pathlib import Path
import unittest

from bitvm_corpus import cashu_release, cashu_testnet4 as ct4
from bitvm_corpus.canonical import digest

ROOT = Path(__file__).resolve().parents[1]
REHEARSAL = ROOT / "examples" / "cashu-testnet4" / "rehearsal.json"


class CashuStageTests(unittest.TestCase):
    def test_fixture_stage_is_the_corpus(self):
        fixture = cashu_release.FIXTURE
        self.assertEqual(fixture.secrets, cashu_release.SECRETS)
        self.assertEqual((fixture.reserve, fixture.collateral, fixture.payout, fixture.refund),
                         (25_000, 25_250, 24_750, 24_750))
        self.assertEqual(fixture.salt, b"")

    def test_stage_keeps_pinned_fee_deltas_above_dust(self):
        a = ct4.AMOUNTS
        self.assertEqual(a["reserve"] + a["collateral"] - a["payout"] - a["refund"], 750)
        self.assertEqual(a["reserve"] - a["payout"], 250)
        self.assertTrue(min(a["payout"], a["refund"]) > 330)

    def test_stage_record_round_trip_and_public_only(self):
        stage = ct4.new_stage()
        private = ct4.stage_record(stage, private=True)
        again = ct4.stage_from_record(private)
        self.assertEqual(again.keys, stage.keys)
        self.assertEqual(again.secrets, stage.secrets)
        public = ct4.stage_from_record(ct4.stage_record(stage))
        self.assertIsNone(public.secrets)
        with self.assertRaises(Exception):
            public.secret("holder")

    def test_fresh_stage_changes_keys_seeds_and_draws(self):
        a, b = ct4.new_stage(), ct4.new_stage()
        self.assertNotEqual(a.keys["holder"], b.keys["holder"])
        self.assertNotEqual(a.salt, b.salt)
        rows = ct4.catalog(a)
        self.assertEqual(len(rows), 40)
        self.assertTrue(all(r["id"].startswith(ct4.TRACK + ".") for r in rows))
        for r in rows:
            self.assertEqual(r["expected"], cashu_release.expected_for(
                r["recipe"], r["profile"], r["variant"], r["cut_and_choose_escaped"], a.payout))

    def test_wave_rows_exist(self):
        stage = ct4.new_stage()
        for wave in ct4.WAVES:
            self.assertEqual([r["id"] for r in ct4.select(stage, wave=wave)], ct4.WAVES[wave])


@unittest.skipUnless(REHEARSAL.exists(), "no committed cashu rehearsal report")
class CashuRehearsalReportTests(unittest.TestCase):
    def test_committed_rehearsal_audits_clean(self):
        report = json.loads(REHEARSAL.read_text(encoding="utf-8"))
        self.assertEqual(ct4.audit(report), [])
        self.assertEqual(report["network"], "regtest")
        self.assertEqual(report["summary"]["expectation_failures"], [])

    def test_audit_catches_a_tampered_draw_and_outcome(self):
        report = json.loads(REHEARSAL.read_text(encoding="utf-8"))
        bad = deepcopy(report)
        case = next(c for c in bad["cases"] if c["profile"] == "hardened" and c["variant"] == "attack")
        cer = next(s for s in case["steps"] if s["label"] == "ceremony")
        cer["challenge"]["escaped"] = not cer["challenge"]["escaped"]
        bad.pop("evidence_hash")
        bad["evidence_hash"] = digest(bad)
        self.assertTrue(any("joint draw" in p for p in ct4.audit(bad)))

        bad2 = deepcopy(report)
        bad2["stage"]["keys"]["holder"] = bad2["stage"]["keys"]["guardian"]
        bad2.pop("evidence_hash")
        bad2["evidence_hash"] = digest(bad2)
        self.assertTrue(ct4.audit(bad2))


if __name__ == "__main__":
    unittest.main()
