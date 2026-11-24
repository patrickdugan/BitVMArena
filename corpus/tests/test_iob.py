import unittest
from pathlib import Path

from bitvm_corpus import bitvm3, iob
from bitvm_corpus.canonical import load_json

EVIDENCE = Path(__file__).resolve().parents[1] / "examples" / "native" / "bitvm3-iob-core31.1.json"


class IobTrackTests(unittest.TestCase):
    def test_catalog_is_every_recipe_but_pinning_under_one_design(self):
        rows = iob.catalog()
        recipes = [r for r in bitvm3.RECIPES if r not in bitvm3.IOB_EXCLUDED]
        self.assertEqual(len(rows), 2 * len(recipes))
        hardened = {r["id"].replace(".hardened.", f".{bitvm3.IOB_PROFILE}.").replace("bitvm3.", "bitvm3-iob.", 1): r
                    for r in bitvm3.catalog() if r["profile"] == "hardened"}
        for row in rows:
            self.assertEqual(row["track"], iob.TRACK)
            self.assertEqual(row["profile"], bitvm3.IOB_PROFILE)
            self.assertEqual(row["expected"], hardened[row["id"]]["expected"])
            self.assertFalse(row["expected"]["attack_success"])
            self.assertEqual(bitvm3.config(row["recipe"], row["profile"]), bitvm3.iob_config())

    def test_the_static_check_flags_nothing(self):
        self.assertEqual(bitvm3.assess(bitvm3.iob_config())["findings"], [])

    def test_the_design_takes_every_hardened_choice(self):
        cfg = bitvm3.iob_config()
        for recipe in bitvm3.RECIPES:
            if recipe in ("disprove_unbumpable", "disprove_anchor_pinned"):
                continue    # their hardened fix is an anchor on a zero-fee disprove; this one pays its fee
            hardened, mutant = bitvm3.config(recipe, "hardened"), bitvm3.config(recipe, "mutant")
            for name, value in vars(hardened).items():
                if getattr(mutant, name) != value:
                    self.assertEqual(getattr(cfg, name), value, f"{recipe}: {name}")

    @unittest.skipUnless(EVIDENCE.exists(), "no committed bitvm3-iob evidence")
    def test_committed_evidence_audits(self):
        report = load_json(EVIDENCE)
        self.assertEqual(iob.audit(report), [])
        self.assertEqual(report["summary"]["expectation_failures"], [])


if __name__ == "__main__":
    unittest.main()
