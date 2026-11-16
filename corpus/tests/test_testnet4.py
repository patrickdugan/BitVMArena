import copy
import io
import json
import os
import unittest
import uuid
from contextlib import redirect_stderr
from pathlib import Path

from bitvm_corpus import bitvm3, gc, testnet4
from bitvm_corpus.bitcoin import P2A, Transaction
from bitvm_corpus.canonical import digest
from bitvm_corpus.cli import main

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "examples" / "testnet4"
DUST = 330


def reports():
    return sorted(EVIDENCE.glob("*.json")) if EVIDENCE.exists() else []


class CatalogTests(unittest.TestCase):
    def test_catalog_is_bitvm3_without_miner_or_topology_recipes(self):
        rows = testnet4.catalog()
        regtest = {r["id"].split(".", 1)[1]: r for r in bitvm3.catalog()}
        self.assertEqual(len(rows), 4 * (len(bitvm3.RECIPES) - len(testnet4.EXCLUDED)))
        for row in rows:
            self.assertTrue(row["id"].startswith(testnet4.TRACK + "."))
            self.assertNotIn(row["recipe"], testnet4.EXCLUDED)
            base = regtest[row["id"].split(".", 1)[1]]
            self.assertEqual(row["expected"], base["expected"])
            self.assertEqual(row["evidence_level"], testnet4.EVIDENCE_LEVEL)

    def test_waves_name_catalog_rows(self):
        ids = {r["id"] for r in testnet4.catalog()}
        for wave, members in testnet4.WAVES.items():
            self.assertTrue(set(members) <= ids, wave)
            self.assertEqual(len(members), len(set(members)), wave)


class StageTests(unittest.TestCase):
    def test_fixture_stage_keeps_the_regtest_seeds_and_keys(self):
        self.assertEqual(bitvm3.FIXTURE.seed("x", "garbling"), bitvm3.sha(b"x:garbling")[:16])
        self.assertEqual(bitvm3.keys(), {n: bitvm3.public(s).hex() for n, s in bitvm3.SECRETS.items()})
        row = bitvm3.catalog()[0]
        graph = bitvm3.Graph(bitvm3.prepare(row))
        self.assertEqual(graph.claim_fee, bitvm3.FEE)
        self.assertEqual(graph.k_value, bitvm3.VAULT - bitvm3.FEE)

    def test_record_round_trip_and_public_rebuild(self):
        stage = testnet4.new_stage()
        private = testnet4.stage_record(stage, private=True)
        self.assertEqual(testnet4.stage_from_record(private).secrets, stage.secrets)
        public = testnet4.stage_from_record(json.loads(json.dumps(testnet4.stage_record(stage))))
        self.assertIsNone(public.secrets)
        for row in testnet4.select(wave="wave1"):
            signing = bitvm3.Graph(bitvm3.prepare(row, stage=stage))
            rebuilt = bitvm3.Graph(bitvm3.prepare(row, stage=public))
            self.assertEqual((signing.V.script_pubkey, signing.K.script_pubkey, signing.claim_outputs()),
                             (rebuilt.V.script_pubkey, rebuilt.K.script_pubkey, rebuilt.claim_outputs()))
        with self.assertRaises(Exception):
            public.secret("desk")

    def test_salt_changes_every_garbling(self):
        row = testnet4.catalog()[0]
        a, b = testnet4.new_stage(), testnet4.new_stage()
        self.assertNotEqual(bitvm3.prepare(row, stage=a).public["reject_label_sha256"],
                            bitvm3.prepare(row, stage=b).public["reject_label_sha256"])

    def test_claim_fee_matches_the_signed_claim(self):
        stage = testnet4.new_stage()
        dummy = {"txid": "11" * 32, "vout": 0, "amount": 0, "script_pubkey": ""}
        for row in testnet4.catalog():
            prep = bitvm3.prepare(row, stage=stage)
            graph = bitvm3.Graph(prep, cltv_height=500 if prep.cfg.payout_timelock == "cltv" else None)
            utxos = {"vault": dict(dummy, script_pubkey=graph.V.script_pubkey.hex(), amount=stage.vault),
                     "bond": dict(dummy, vout=1, script_pubkey=graph.bond_tree.script_pubkey.hex(), amount=stage.bond)}
            labels = prep.garbling.input_labels(gc.proof_bits(*bitvm3.HONEST_PROOF))
            claim = graph.claim_tx(utxos, labels, desk_signs=prep.desk_presigns)
            self.assertEqual(graph.claim_fee, -(-claim.vsize * stage.claim_feerate // 1000), row["id"])

    def test_testnet4_amounts_stay_above_dust(self):
        stage = testnet4.new_stage()
        for row in testnet4.catalog():
            prep = bitvm3.prepare(row, stage=stage)
            graph = bitvm3.Graph(prep, cltv_height=500 if prep.cfg.payout_timelock == "cltv" else None)
            fake = Transaction([], graph.claim_outputs())
            label = prep.garbling.reject_label
            outputs = [o for o in graph.claim_outputs()[:1]]
            outputs += graph.payout_tx(fake).outputs + graph.disprove_tx(fake, label, "watch").outputs
            outputs += graph.desk_payout_tx(fake, graph.refund_spk).outputs + graph.sweep_tx(fake, graph.payout_spk).outputs
            for value, spk in outputs:
                if spk != P2A:
                    self.assertGreaterEqual(value, DUST, row["id"])

    def test_wif_encoding(self):
        self.assertEqual(testnet4.wif(1, testnet=False), "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")


class CliSafetyTests(unittest.TestCase):
    def run_cli(self, *argv):
        with redirect_stderr(io.StringIO()) as err:
            code = main(list(argv))
        return code, err.getvalue()

    def test_run_needs_broadcast_and_an_outside_state_directory(self):
        code, err = self.run_cli("testnet4", "run", "--wave", "wave1")
        self.assertEqual(code, 2)
        self.assertIn("--broadcast", err)
        code, err = self.run_cli("testnet4", "run", "--wave", "wave1", "--broadcast", "--state", str(ROOT / "work" / "x"),
                                 "--rpc-port", "1", "--cookie", "c", "--wallet", "w")
        self.assertEqual(code, 2)
        self.assertIn("outside the repository", err)

    def test_staging_node_refuses_other_chains(self):
        with self.assertRaises(Exception):
            testnet4.StagingNode(1, "cookie", "w", chain="main")


@unittest.skipUnless(reports(), "no committed testnet4 report")
class EvidenceTests(unittest.TestCase):
    def test_committed_reports_audit_clean_and_detect_tampering(self):
        for path in reports():
            report = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(report["network"], "testnet4", path.name)
            self.assertEqual(testnet4.audit(report), [], path.name)
            forged = copy.deepcopy(report)
            case = next(c for c in forged["cases"] if any(s["kind"] == "tx" and s.get("confirmed") for s in c["steps"]))
            payout = next(s for s in case["steps"] if s["kind"] == "tx" and s.get("confirmed"))
            payout["raw_transaction"] = payout["raw_transaction"][:-8] + "01000000"
            forged["evidence_hash"] = digest({k: v for k, v in forged.items() if k != "evidence_hash"})
            self.assertTrue(testnet4.audit(forged), path.name)
            leaked = copy.deepcopy(report)
            leaked["stage"]["secrets"] = {n: "01" * 32 for n in testnet4.ROLES}
            self.assertTrue(testnet4.audit(leaked))


@unittest.skipUnless(os.environ.get("BITVM_ARENA_BITCOIND"), "needs BITVM_ARENA_BITCOIND")
class RehearsalTests(unittest.TestCase):
    def test_rehearsal_of_relay_and_timing_cases(self):
        rows = testnet4.select(["disprove_unbumpable.hardened.attack", "window_below_latency.mutant.attack",
                                "proof_replay_across_vaults.hardened.attack", "bond_self_slash.mutant.attack"])
        report = testnet4.rehearse(Path(os.environ["BITVM_ARENA_BITCOIND"]),
                                   ROOT / "work" / "staging" / uuid.uuid4().hex, rows, interval=1.0)
        self.assertEqual(report["summary"]["errors"], [])
        self.assertEqual(report["summary"]["expectation_failures"], [])
        problems = [p for p in testnet4.audit(report) if "catalog" not in p]
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
