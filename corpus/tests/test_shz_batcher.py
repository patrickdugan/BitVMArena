import hashlib
import os
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from bitvm_corpus import shz_batcher as sb
from bitvm_corpus.canonical import digest, load_json

EVIDENCE = Path(__file__).resolve().parents[1] / "examples" / "native" / "shz-batcher-core31.1.json"
BITCOIND = os.environ.get("BITVM_ARENA_BITCOIND")


class ShzBatcherTrackTests(unittest.TestCase):
    def test_catalog_has_one_as_built_row_per_recipe(self):
        rows = sb.catalog()
        self.assertEqual([r["recipe"] for r in rows], list(sb.RECIPES))
        self.assertEqual(len({r["id"] for r in rows}), len(rows))
        for row in rows:
            self.assertEqual(row["profile"], "as_built")
            self.assertEqual(row["track"], sb.TRACK)
            self.assertEqual(set(row["expected"]), {"legitimate_completion", "attacker_success", "diverted_sats",
                                                    "defense_layer"})
            if row["variant"] == "benign":
                self.assertFalse(row["expected"]["attacker_success"])

    def test_the_rebuilt_graph_is_the_targets_recorded_graph(self):
        built = sb.check_against_target()
        self.assertEqual(built["vault_spk"], sb.RECORDED["vault_spk"])
        self.assertEqual(built["honest"], sb.RECORDED["honest"])
        self.assertEqual(built["wrong"], sb.RECORDED["wrong"])

    def test_a_changed_key_is_noticed(self):
        saved = sb.SECRETS["watch"]
        try:
            sb.SECRETS["watch"] = saved + 1
            with self.assertRaises(sb.ValidationError):
                sb.check_against_target()
        finally:
            sb.SECRETS["watch"] = saved

    def test_the_seed_gives_the_other_output_label_of_both_recorded_instances(self):
        # Each instance records the label its evaluation produced and the hashes of both labels.
        for name, other in (("honest", "reject_label_sha256"), ("wrong", "accept_label_sha256")):
            instance = sb.INSTANCES[name]
            label = sb.opposite_label(instance)
            self.assertEqual(hashlib.sha256(label).hexdigest(), instance[other])
            self.assertNotEqual(label.hex(), instance["evaluated_label_hex"])

    def test_another_seed_does_not_open_the_leaf(self):
        instance = dict(sb.INSTANCES["honest"], garbling_seed=102)
        self.assertNotEqual(hashlib.sha256(sb.opposite_label(instance)).hexdigest(),
                            sb.INSTANCES["honest"]["reject_label_sha256"])

    @unittest.skipUnless(EVIDENCE.exists(), "no committed shz-batcher evidence")
    def test_committed_evidence_audits(self):
        report = load_json(EVIDENCE)
        self.assertEqual(sb.audit(report), [])
        self.assertEqual(report["summary"]["expectation_failures"], [])
        self.assertEqual(report["provenance"]["upstream"], sb.UPSTREAM)

    @unittest.skipUnless(EVIDENCE.exists(), "no committed shz-batcher evidence")
    def test_the_audit_notices_edits(self):
        report = load_json(EVIDENCE)

        def edited(change):
            copy = deepcopy(report)
            change(copy)
            body = {k: v for k, v in copy.items() if k != "evidence_hash"}
            copy["evidence_hash"] = digest(body)
            return sb.audit(copy)

        def case(copy, recipe):
            return next(c for c in copy["cases"] if c["recipe"] == recipe)

        def flip_outcome(copy):
            target = case(copy, "seed_reject_label_theft")
            target["outcome"]["diverted_sats"] = 0
            target["expectation_met"] = False
            copy["summary"]["expectation_failures"] = [target["id"]]

        def other_label(copy):
            target = next(s for s in case(copy, "seed_reject_label_grief")["steps"]
                          if s["label"] == "derive reject label")
            target["derived_label"] = "00" * 16

        self.assertTrue(any("outcome does not follow" in p for p in edited(flip_outcome)))
        self.assertTrue(any("derived label" in p for p in edited(other_label)))

    @unittest.skipUnless(BITCOIND, "set BITVM_ARENA_BITCOIND to run against Bitcoin Core")
    def test_live_run_meets_the_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            report = sb.execute(BITCOIND, Path(directory) / "node")
        self.assertEqual(report["summary"]["expectation_failures"], [])
        self.assertEqual(sb.audit(report), [])


if __name__ == "__main__":
    unittest.main()
