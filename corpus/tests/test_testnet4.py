import copy
import io
import json
import os
import unittest
import uuid
from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal
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

    def test_iob_catalog_is_the_iob_track_without_miner_or_topology_recipes(self):
        rows = testnet4.catalog(testnet4.IOB_TRACK)
        regtest = {r["id"].split(".", 1)[1]: r for r in bitvm3.iob_catalog()}
        self.assertEqual(len(rows), 2 * (len(bitvm3.RECIPES) - len(testnet4.EXCLUDED)))
        for row in rows:
            self.assertTrue(row["id"].startswith(testnet4.IOB_TRACK + "."))
            self.assertEqual(row["profile"], bitvm3.IOB_PROFILE)
            self.assertEqual(row["expected"], regtest[row["id"].split(".", 1)[1]]["expected"])
            self.assertFalse(row["expected"]["attack_success"])
        with self.assertRaises(Exception):
            testnet4.catalog("bitvm3")

    def test_a_selection_stays_within_one_track(self):
        self.assertEqual({r["track"] for r in testnet4.select(["bitvm3-testnet4"])}, {testnet4.TRACK})
        self.assertEqual({r["track"] for r in testnet4.select(["bitvm3-iob-testnet4"])}, {testnet4.IOB_TRACK})
        with self.assertRaises(Exception):
            testnet4.select(["labels_offchain_withheld"])

    def test_waves_name_catalog_rows(self):
        ids = {r["id"] for track in testnet4.TRACKS for r in testnet4.catalog(track)}
        for wave, members in testnet4.WAVES.items():
            self.assertTrue(set(members) <= ids, wave)
            self.assertEqual(len({m.split(".", 1)[0] for m in members}), 1, wave)
            self.assertEqual(len(members), len(set(members)), wave)
            with redirect_stdout(io.StringIO()) as out:
                self.assertEqual(main(["testnet4", "list", "--wave", wave]), 0)
            self.assertEqual([r["id"] for r in json.loads(out.getvalue())], members)


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
        for row in testnet4.catalog() + testnet4.catalog(testnet4.IOB_TRACK):
            prep = bitvm3.prepare(row, stage=stage)
            graph = bitvm3.Graph(prep, cltv_height=500 if prep.cfg.payout_timelock == "cltv" else None)
            utxos = {"vault": dict(dummy, script_pubkey=graph.V.script_pubkey.hex(), amount=stage.vault),
                     "bond": dict(dummy, vout=1, script_pubkey=graph.bond_tree.script_pubkey.hex(), amount=stage.bond)}
            labels = prep.garbling.input_labels(gc.proof_bits(*bitvm3.HONEST_PROOF))
            claim = graph.claim_tx(utxos, labels, desk_signs=prep.desk_presigns)
            self.assertEqual(graph.claim_fee, -(-claim.vsize * stage.claim_feerate // 1000), row["id"])

    def test_testnet4_amounts_stay_above_dust(self):
        stage = testnet4.new_stage()
        for row in testnet4.catalog() + testnet4.catalog(testnet4.IOB_TRACK):
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

    def test_rehearsal_refuses_a_reorg_every_block_or_two(self):
        # With 1 or 2 every transaction-bearing block is reorganized away; refused before a node starts.
        for every in ("1", "2", "-3"):
            code, err = self.run_cli("testnet4", "rehearse", "--wave", "wave1", "--bitcoind", "missing.exe",
                                     "--reorg-every", every)
            self.assertEqual(code, 2)
            self.assertIn("at least 3", err)

    def test_staging_node_refuses_other_chains(self):
        with self.assertRaises(Exception):
            testnet4.StagingNode(1, "cookie", "w", chain="main")


class ScriptedNetwork:
    """A best chain plus a mempool, advanced one scripted event per tip-change wait."""

    def __init__(self, height, events):
        self.blocks = [(f"G{h}", []) for h in range(height + 1)]
        self.mempool, self.events, self.version = set(), list(events), 0
        self.resendable = set()     # txids the node would accept again (inputs still unspent)

    # the node side
    def rpc(self, method, *params, **_):
        tip = len(self.blocks) - 1
        if method == "getblockcount":
            return tip
        if method == "getrawtransaction":
            for height, (block, txids) in enumerate(self.blocks):
                if params[0] in txids:
                    return {"hex": "aa", "blockhash": block, "confirmations": tip - height + 1}
            if params[0] in self.mempool:
                return {"hex": "aa"}
            raise testnet4.CoreError("No such mempool or blockchain transaction")
        if method == "getmempoolentry":
            if params[0] not in self.mempool:
                raise testnet4.CoreError("Transaction not in mempool")
            return {}
        if method == "getblockheader":
            return {"height": next(h for h, (b, _) in enumerate(self.blocks) if b == params[0]), "time": 0}
        if method == "sendrawtransaction":
            txid = next((t for t in self.resendable), None)
            if txid is None:
                raise testnet4.CoreError("bad-txns-inputs-missingorspent")
            self.resendable.discard(txid)
            self.mempool.add(txid)
            return txid
        raise AssertionError(method)

    # the chain-poller side
    def wait_change(self, seen, timeout=60):
        event = self.events.pop(0) if self.events else ("block", [])
        if event[0] == "block":
            txids = [t for t in event[1] if t in self.mempool]
            self.mempool -= set(txids)
            self.blocks.append((f"B{len(self.blocks)}", txids))
        else:                       # ("reorg", depth, replacement block count)
            for _, txids in self.blocks[-event[1]:]:
                self.mempool |= set(txids)
            del self.blocks[-event[1]:]
            self.blocks += [(f"R{len(self.blocks) + i}", []) for i in range(event[2])]
        self.version += 1
        return self.version


class ReorgTests(unittest.TestCase):
    class Quiet:
        def write(self, **_):
            pass

    def session(self, network):
        session = testnet4.StagingSession(network, network, None, self.Quiet(), "case", patience=18)
        session._record(kind="tx", label="claim", actor="claimant", txid="claim", raw_transaction="aa",
                        prevouts=[], allowed=True, broadcast=True)
        network.mempool.add("claim")
        return session

    def test_owed_confirmations_follow_regtest(self):
        network = ScriptedNetwork(100, [])
        session = self.session(network)
        session._record(kind="blocks", label="2 network blocks", blocks=2)
        session._record(kind="tx", label="payout", txid="payout", broadcast=True)
        session._record(kind="tx", label="refused", txid="refused", broadcast=False)
        self.assertEqual(session._owed(3), {"payout": 3, "claim": 5})

    def test_a_reorg_after_the_claim_confirms_extends_the_csv_wait(self):
        # Wave 1: the claim confirmed in block 161,710, a reorg replaced that block, and the
        # claim confirmed again at 161,712. The 5-block wait for a 6-block CSV must count
        # from the block the claim ends up in.
        network = ScriptedNetwork(100, [("block", ["claim"]), ("reorg", 1, 2), ("block", ["claim"])])
        session = self.session(network)
        session.mine(1)
        self.assertEqual(network.rpc("getblockcount"), 101)     # confirmed in A101, as on testnet4
        session.mine(5)
        self.assertEqual(session._confirmations("claim"), 6)
        self.assertEqual(network.rpc("getblockcount"), 108)     # claim at 103, so 103 + 5
        steps = session.finish()
        claim = steps[0]
        self.assertEqual((claim["confirmed"], claim["block_height"]), (True, 103))
        self.assertEqual(claim["reorged_out_of"], ["B101"])
        self.assertEqual(steps[-1]["stalled"], [])

    def test_a_displaced_transaction_does_not_hold_the_wait(self):
        network = ScriptedNetwork(100, [])
        session = self.session(network)
        network.mempool.clear()                  # replaced by a conflict that never shows here
        session.mine(2)
        self.assertEqual(network.rpc("getblockcount"), 102)
        claim = session.finish()[0]
        self.assertFalse(claim["confirmed"])
        self.assertTrue(claim.get("displaced") or claim.get("dropped"))
        self.assertNotIn("rebroadcasts", claim)

    def test_a_dropped_transaction_is_sent_again_and_waited_for(self):
        network = ScriptedNetwork(100, [("block", []), ("block", ["claim"])])
        session = self.session(network)
        network.mempool.clear()                  # evicted, inputs still unspent
        network.resendable.add("claim")
        session.mine(1)
        self.assertEqual(session._confirmations("claim"), 1)
        self.assertEqual(network.rpc("getblockcount"), 102)
        self.assertEqual(session.finish()[0]["rebroadcasts"], 1)


class SplitTests(unittest.TestCase):
    class Node:
        def __init__(self):
            self.mempool, self.confirmed, self.sent, self.addresses = set(), False, 0, 0

        def rpc_named(self, method, wallet=False, **_):
            self.mempool.add("split")
            return {"txid": "split"}

        def rpc(self, method, *args, wallet=False):
            if method == "getnewaddress":
                self.addresses += 1
                return f"addr{self.addresses}"
            if method == "gettransaction":
                return {"hex": "raw"}
            if method == "getmempoolentry":
                if args[0] not in self.mempool:
                    raise testnet4.CoreError("Transaction not in mempool")
                return {}
            if method == "sendrawtransaction":
                self.sent += 1
                self.mempool.add("split")
                return "split"
            if method == "getrawtransaction":
                if not self.confirmed:
                    raise testnet4.CoreError("No such mempool or blockchain transaction")
                vout = [{"n": n, "value": Decimal("0.00002300"), "scriptPubKey": {"address": f"addr{n + 1}"}}
                        for n in range(self.addresses)]
                return {"confirmations": 1, "hex": "raw", "blockhash": "B", "vout": vout}
            raise AssertionError(method)

    class Chain:
        def __init__(self, node):
            self.node = node

        def wait_until(self, predicate, timeout):
            self.node.mempool.clear()            # the reorg right after the split evicts it
            if predicate():
                return True
            if "split" in self.node.mempool:     # the next block mines whatever is in the mempool
                self.node.mempool.clear()
                self.node.confirmed = True
            return predicate()

    class Journal:
        def __init__(self):
            self.entries = []

        def write(self, **entry):
            self.entries.append(entry)

    def test_an_evicted_split_is_sent_again(self):
        # Wave 5's rehearsal: a reorg two seconds after the split lowered the tip, the split
        # (nLockTime = the old tip) left the mempool, and the wave waited six hours for it.
        node, journal = self.Node(), self.Journal()
        pool, record = testnet4.CoinPool.split(node, self.Chain(node), [2300, 2300], journal)
        self.assertEqual(node.sent, 1)
        self.assertIn("coin split resent", [e["kind"] for e in journal.entries])
        self.assertEqual(record["sizes"], [2300, 2300])
        self.assertEqual(len(pool.coins), 2)


class ChainCheckTests(unittest.TestCase):
    class Chain:
        def __init__(self, txs):
            self.txs = txs

        def rpc(self, method, txid, verbose):
            if txid not in self.txs:
                raise testnet4.CoreError("No such mempool or blockchain transaction")
            return self.txs[txid]

    def test_the_split_and_vault_fundings_are_rechecked(self):
        # Waves 3 and 4: the split was recorded in a block a reorg replaced. The re-check
        # covered only the steps, so the move went unnoted.
        report = {
            "funding": {"txid": "split", "blockhash": "A", "raw_transaction": "00"},
            "cases": [{"id": "row", "steps": [
                {"kind": "fund", "label": "fund", "txid": "fund", "blockhash": "A", "raw_transaction": "11"},
                {"kind": "tx", "label": "claim", "txid": "claim", "blockhash": "C", "raw_transaction": "22",
                 "broadcast": True, "confirmed": True},
            ]}],
        }
        chain = self.Chain({"split": {"confirmations": 9, "hex": "00", "blockhash": "B"},
                            "claim": {"confirmations": 3, "hex": "22", "blockhash": "C"}})
        problems, notes = testnet4.verify_chain(report, chain)
        self.assertEqual(notes, ["funding: split was reorganized into block B"])
        self.assertEqual(problems, ["row: fund fund is not in the best chain"])


class RecoverTests(unittest.TestCase):
    """Wave 1 left a claim output unpaid and burned a bond; wave 5 left a vault unclaimed."""

    class Node:
        def __init__(self, tip, txs, unspent, mine=()):
            self.tip, self.txs, self.unspent, self.mine, self.sent = tip, txs, unspent, set(mine), []

        def rpc(self, method, *args, wallet=False):
            if method == "getblockcount":
                return self.tip
            if method == "getrawtransaction":
                return {"vout": self.txs[args[0]]}
            if method == "gettxout":
                confirmations = self.unspent.get(f"{args[0]}:{args[1]}")
                return None if confirmations is None else {"confirmations": confirmations}
            if method == "getaddressinfo":
                return {"ismine": args[0] in self.mine}
            if method == "testmempoolaccept":
                return [{"allowed": True}]
            if method == "sendrawtransaction":
                self.sent.append(args[0])
                return Transaction.parse(bytes.fromhex(args[0])).txid
            raise AssertionError(method)

    @staticmethod
    def out(n, sats, spk, address=None):
        script = {"hex": spk.hex() if isinstance(spk, bytes) else spk}
        if address:
            script["address"] = address
        return {"n": n, "value": Decimal(sats) / Decimal(100_000_000), "scriptPubKey": script}

    def setUp(self):
        self.stage = testnet4.new_stage()
        self.row = testnet4.select(["cut_and_choose_grindable.hardened.attack"])[0]
        self.graph = testnet4._graphs(self.row, self.stage, {})[0]

    def report(self, steps):
        return {"wave": "w", "stage": testnet4.stage_record(self.stage),
                "cases": [{"id": self.row["id"], "steps": steps}]}

    def test_reclaims_pays_out_and_leaves_burned_and_owned_outputs(self):
        g, stage = self.graph, self.stage
        steps = [
            {"kind": "fund", "label": "fund", "txid": "aa" * 32},
            {"kind": "tx", "label": "claim", "txid": "bb" * 32, "confirmed": True},
            {"kind": "tx", "label": "disprove", "txid": "cc" * 32, "confirmed": True},
        ]
        node = self.Node(1_000, {
            "aa" * 32: [self.out(0, stage.vault, g.V.script_pubkey)],
            "bb" * 32: [self.out(0, g.k_value, g.K.script_pubkey), self.out(1, 0, "6a")],
            "cc" * 32: [self.out(0, 1_438, stage.spk("refund"), "refund-address"),
                        self.out(1, stage.bond, bitvm3.BURN_SPK), self.out(2, 700, "51200000")],
        }, {f"{'aa' * 32}:0": 10, f"{'bb' * 32}:0": 30, f"{'cc' * 32}:0": 5, f"{'cc' * 32}:1": 5,
            f"{'cc' * 32}:2": 5}, mine={"refund-address"})
        found = testnet4.recover(self.report(steps), stage, node, send=True)["outputs"]
        by_kind = {f["kind"]: f for f in found}
        self.assertEqual(sorted(by_kind), ["burned", "payout", "reclaim", "unknown"])
        reclaim = by_kind["reclaim"]   # funded at 991: the 144-block reclaim opens at 1,135
        self.assertEqual((reclaim["opens_at_height"], reclaim["returns"]), (991 + g.cfg.reclaim, stage.vault - stage.fee))
        self.assertNotIn("sent", reclaim)
        payout = by_kind["payout"]
        self.assertEqual(payout["opens_at_height"], 971 + g.cfg.window)
        self.assertTrue(payout["allowed"] and payout["sent"])
        self.assertEqual(payout["txid"], g.payout_tx(testnet4._Spent("bb" * 32)).txid)
        self.assertEqual(len(node.sent), 1)

    def test_refuses_another_waves_keys(self):
        other = self.report([])
        other["stage"] = testnet4.stage_record(testnet4.new_stage())
        with self.assertRaises(testnet4.ValidationError):
            testnet4.recover(other, self.stage, self.Node(1, {}, {}))


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

    def test_rehearsal_through_reorgs(self):
        rows = testnet4.select(["reclaim_preempts_claim.hardened.attack", "seed_reuse_across_claims.hardened.benign",
                                "payout_csv_removed.hardened.attack", "disprove_unbumpable.hardened.attack"])
        report = testnet4.rehearse(Path(os.environ["BITVM_ARENA_BITCOIND"]),
                                   ROOT / "work" / "staging" / uuid.uuid4().hex, rows, interval=1.0, reorg_every=3)
        self.assertEqual(report["summary"]["errors"], [])
        self.assertEqual(report["summary"]["expectation_failures"], [])
        self.assertGreater(report["provenance"]["rehearsal_network"]["reorgs"], 0)
        self.assertEqual(testnet4.audit(report), [])


if __name__ == "__main__":
    unittest.main()
