import copy
import json
import os
import unittest
import uuid
from pathlib import Path

from bitvm_corpus import m14
from bitvm_corpus.canonical import digest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "examples" / "native" / "bitvm3-m14-core31.1.json"
HAVE_RUNS = all((m14.ARTIFACTS / f"{name}.json").exists() for name in m14.RUNS.values())


class CatalogTests(unittest.TestCase):
    def test_catalog_shape(self):
        rows = m14.catalog()
        self.assertEqual(len(rows), 4 * len(m14.RECIPES))
        for recipe in m14.RECIPES:
            combos = {(r["profile"], r["variant"]) for r in rows if r["recipe"] == recipe}
            self.assertEqual(combos, {(p, v) for p in ("hardened", "mutant") for v in ("benign", "attack")})
        binding = [r for r in rows if r["recipe"] == "m14_statement_binding" and r["variant"] == "attack"]
        self.assertEqual({tuple(r["m14_runs"]) for r in binding},
                         {("eval-honest", "eval-wrong-statement"), ("eval-honest", "eval-shared-statement")})


@unittest.skipUnless(HAVE_RUNS, "the recorded M14 runs are not present")
class RecordedRunTests(unittest.TestCase):
    def setUp(self):
        self.runs = m14.load_runs()

    def test_runs_are_consistent_and_full_scale(self):
        self.assertEqual(m14.check_runs(self.runs), [])
        meta = json.loads((m14.ARTIFACTS / "runs.json").read_text(encoding="utf-8"))
        self.assertEqual(meta["commit"], m14.UPSTREAM["commit"])
        self.assertEqual(meta["commit"], "25c6c23")
        for name in m14.RUNS.values():
            self.assertEqual(meta["runs"][name]["exit_status"], 0)

    def test_disprove_leaf_is_bound_to_the_real_reject_label(self):
        for row in m14.catalog():
            for index, role in enumerate(m14.vaults(row["recipe"], row["profile"], row["variant"])):
                graph = m14.M14Graph(row, self.runs[role], index)
                self.assertEqual(graph.disprove_hash.hex(), self.runs[role]["reject_label_sha256"])
        tampered = self.runs["tampered"]
        self.assertEqual(tampered["verdict"], "reject")
        self.assertEqual(tampered["output_label_sha256"], tampered["reject_label_sha256"])

    def test_check_runs_catches_a_forged_label(self):
        forged = copy.deepcopy(self.runs)
        label = bytearray.fromhex(forged["tampered"]["output_label"])
        label[0] ^= 1
        forged["tampered"]["output_label"] = label.hex()
        self.assertTrue(m14.check_runs(forged))
        swapped = copy.deepcopy(self.runs)
        swapped["shared"]["seed_sha256"] = swapped["honest"]["seed_sha256"]
        self.assertTrue(any("seed" in p for p in m14.check_runs(swapped)))

    @unittest.skipUnless(EVIDENCE.exists(), "no committed M14 report")
    def test_committed_report_audits_clean_and_detects_tampering(self):
        report = json.loads(EVIDENCE.read_text(encoding="utf-8"))
        self.assertEqual(m14.audit(report), [])
        self.assertEqual(report["summary"]["expectation_failures"], [])
        forged = copy.deepcopy(report)
        case = next(c for c in forged["cases"] if c["id"] == f"{m14.TRACK}.m14_false_claim.mutant.attack")
        for s in case["steps"]:
            if s["label"] == "payout":
                s["confirmed"] = False
        forged["evidence_hash"] = digest({k: v for k, v in forged.items() if k != "evidence_hash"})
        self.assertTrue(m14.audit(forged))


@unittest.skipUnless(HAVE_RUNS and os.environ.get("BITVM_ARENA_BITCOIND"), "needs the M14 runs and Core")
class LiveTests(unittest.TestCase):
    def test_live_false_claim(self):
        rows = [r for r in m14.catalog() if r["recipe"] == "m14_false_claim"]
        report = m14.execute(Path(os.environ["BITVM_ARENA_BITCOIND"]), ROOT / "work" / "regtest" / uuid.uuid4().hex, rows)
        self.assertEqual(report["summary"]["expectation_failures"], [])
        problems = [p for p in m14.audit(report) if "whole catalog" not in p and "catalog_hash" not in p]
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
