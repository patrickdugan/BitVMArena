import copy
import io
import json
import os
import random
import unittest
import uuid
from contextlib import redirect_stdout
from pathlib import Path

from bitvm_arena import bitcoin, bitvm3, gc, native
from bitvm_arena.cli import main, track_module
from bitvm_arena.canonical import digest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "examples" / "native"
TRACKS = ("primitive", "bitvm2", "bitvm3")


def load(track):
    path = EVIDENCE / f"{track}-core31.1.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


class BitcoinPrimitiveTests(unittest.TestCase):
    def test_bip340_vectors(self):
        # BIP340 test vectors 0 and 1.
        sig0 = bitcoin.sign(bytes(32), 3, bytes(32))
        self.assertEqual(bitcoin.public(3).hex().upper(),
                         "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
        self.assertEqual(sig0.hex().upper(),
                         "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
                         "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
        secret = 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
        message = bytes.fromhex("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
        sig1 = bitcoin.sign(message, secret, bytes(31) + b"\x01")
        self.assertEqual(sig1.hex().upper(),
                         "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
                         "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A")
        self.assertTrue(bitcoin.verify_signature(message, bitcoin.public(secret), sig1))
        self.assertFalse(bitcoin.verify_signature(message[::-1], bitcoin.public(secret), sig1))

    def test_ripemd160_fallback_vectors(self):
        self.assertEqual(bitcoin.ripemd160_py(b"").hex(), "9c1185a5c5e9fc54612808977ee8f548b2258d31")
        self.assertEqual(bitcoin.ripemd160_py(b"abc").hex(), "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
        self.assertEqual(bitcoin.ripemd160_py(b"a" * 1_000).hex(),
                         bitcoin.ripemd160_py(b"a" * 999 + b"a").hex())

    def test_scriptnum_minimal_encoding(self):
        cases = {0: b"", 1: b"\x01", 127: b"\x7f", 128: b"\x80\x00", 255: b"\xff\x00", 256: b"\x00\x01",
                 -1: b"\x81", -128: b"\x80\x80"}
        for value, encoded in cases.items():
            self.assertEqual(bitcoin.scriptnum(value), encoded, value)

    def test_taptree_commitments(self):
        for count in range(1, 6):
            tree = bitcoin.TapTree(tuple(bytes([0x51 + i]) for i in range(count)))
            for i in range(count):
                self.assertTrue(bitcoin.verify_commitment(tree.script_pubkey, tree.scripts[i], tree.control(i)))
            self.assertFalse(bitcoin.verify_commitment(tree.script_pubkey, b"\x60", tree.control(0)))
            flipped = bytes([tree.control(0)[0] ^ 1]) + tree.control(0)[1:]
            self.assertFalse(bitcoin.verify_commitment(tree.script_pubkey, tree.scripts[0], flipped))

    def test_transaction_round_trip_and_key_path_tweak(self):
        tree = bitcoin.TapTree((b"\x51",), bitcoin.public(5))
        tx = bitcoin.Transaction([bitcoin.TxInput("ab" * 32, 3, 5_000, tree.script_pubkey, 7)],
                                 [(4_000, tree.script_pubkey), (0, bitcoin.op_return(b"arena"))], 9)
        signature = tx.signature(0, None, tree.tweaked_secret(5), bitcoin.SIGHASH_ALL)
        tx.inputs[0].witness = [signature]
        parsed = bitcoin.Transaction.parse(tx.serialize().hex())
        self.assertEqual(parsed.serialize(), tx.serialize())
        self.assertEqual(parsed.txid, tx.txid)
        parsed.inputs[0].amount, parsed.inputs[0].script_pubkey = 5_000, tree.script_pubkey
        message = parsed.sighash(0, None, bitcoin.SIGHASH_ALL)
        self.assertTrue(bitcoin.verify_signature(message, tree.output_key, signature[:64]))

    def test_sighash_single_commits_only_its_output(self):
        tree = bitcoin.TapTree((b"\x51",))
        leaf = tree.leaf(0)
        tx = bitcoin.Transaction([bitcoin.TxInput("cd" * 32, 0, 9_000, tree.script_pubkey)],
                                 [(1_000, b"\x51\x20" + bytes(32)), (2_000, b"\x51\x20" + bytes(31) + b"\x01")])
        single = tx.sighash(0, leaf, bitcoin.SIGHASH_SINGLE)
        changed = copy.deepcopy(tx)
        changed.outputs[1] = (3_000, changed.outputs[1][1])
        self.assertEqual(single, changed.sighash(0, leaf, bitcoin.SIGHASH_SINGLE))
        changed.outputs[0] = (999, changed.outputs[0][1])
        self.assertNotEqual(single, changed.sighash(0, leaf, bitcoin.SIGHASH_SINGLE))


class GarblingTests(unittest.TestCase):
    def test_garbled_evaluation_matches_plain_circuit(self):
        rng = random.Random(7)
        statement = 48_400
        garbling = gc.garble(statement, b"test-seed")
        public = garbling.public()
        circuit = gc.statement_circuit(statement)
        for trial in range(100):
            a = rng.randrange(2**16)
            b = (statement - a) % 2**16 if trial % 2 else rng.randrange(2**16)
            bits = gc.proof_bits(a, b)
            expected = circuit.evaluate(bits)[0]
            self.assertEqual(expected, int(a + b == statement))
            label = gc.evaluate(statement, garbling.tables, garbling.input_labels(bits))
            self.assertEqual(gc.decode(label, public["accept_label_sha256"], public["reject_label_sha256"]),
                             "accept" if expected else "reject")

    def test_free_xor_offset_links_output_labels(self):
        garbling = gc.garble(1_000, b"seed")
        self.assertEqual(gc.xor(garbling.accept_label, garbling.delta), garbling.reject_label)
        self.assertEqual(garbling.delta[-1] & 1, 1)

    def test_cut_and_choose_opening_detects_swapped_decoding(self):
        garbling = gc.garble(bitvm3.STATEMENT, b"seed")
        honest = bitvm3.published(garbling)
        swapped = bitvm3.published(garbling, swapped=True)
        self.assertTrue(gc.check_opening(bitvm3.STATEMENT, b"seed", honest))
        self.assertFalse(gc.check_opening(bitvm3.STATEMENT, b"seed", swapped))

    def test_seed_reuse_leaks_delta_through_two_label_sets(self):
        first = gc.garble(bitvm3.PRIOR_STATEMENT, b"shared")
        second = gc.garble(bitvm3.STATEMENT, b"shared")
        a = first.input_labels(gc.proof_bits(*bitvm3.PRIOR_PROOF))
        b = second.input_labels(gc.proof_bits(*bitvm3.HONEST_PROOF))
        leaked = {gc.xor(x, y) for x, y in zip(a, b)} - {bytes(gc.LABEL)}
        self.assertEqual(leaked, {second.delta})
        fresh = gc.garble(bitvm3.STATEMENT, b"fresh")
        c = fresh.input_labels(gc.proof_bits(*bitvm3.HONEST_PROOF))
        self.assertNotIn(fresh.delta, {gc.xor(x, y) for x, y in zip(a, c)})


class CatalogTests(unittest.TestCase):
    def test_catalog_shape(self):
        for name in TRACKS:
            try:
                module = track_module(name)
            except ImportError:
                continue
            rows = module.catalog()
            ids = [r["id"] for r in rows]
            self.assertEqual(len(ids), len(set(ids)), name)
            recipes = {r["recipe"] for r in rows}
            for recipe in recipes:
                combos = {(r["profile"], r["variant"]) for r in rows if r["recipe"] == recipe}
                self.assertEqual(combos, {(p, v) for p in ("hardened", "mutant") for v in ("benign", "attack")})
            for row in rows:
                self.assertFalse(row["upstream_exploit_claim"])
                self.assertEqual(row["evidence_level"], "bitcoin-core-regtest-transactions")

    def test_bitvm3_setup_is_deterministic_and_bound(self):
        for row in bitvm3.catalog():
            a, b = bitvm3.prepare(row), bitvm3.prepare(row)
            self.assertEqual(a.public, b.public)
            self.assertEqual(bitvm3.Graph(a).V.script_pubkey, bitvm3.Graph(b).V.script_pubkey)
        grind = next(r for r in bitvm3.catalog() if r["id"] == "bitvm3.cut_and_choose_grindable.mutant.attack")
        log = bitvm3.prepare(grind).setup_log
        self.assertGreater(log["grind_attempts"], 0)
        self.assertIn(log["kept"], log["malicious"])


class EvidenceTests(unittest.TestCase):
    def test_committed_reports_audit_clean(self):
        found = 0
        for name in TRACKS:
            report = load(name)
            if report is None:
                continue
            found += 1
            with self.subTest(track=name):
                self.assertEqual(track_module(name).audit(report), [])
                self.assertEqual(report["summary"]["expectation_failures"], [])
                self.assertEqual(report["provenance"]["chain"], "regtest")
                self.assertFalse(report["provenance"]["p2p_network_active"])
                self.assertEqual(report["provenance"]["subversion"], "/Satoshi:31.1.0/")
        self.assertGreaterEqual(found, 2)

    def test_audit_detects_tampering(self):
        report = load("bitvm3")
        if report is None:
            self.skipTest("no committed BitVM3 report")
        tx_case = next(c for c in report["cases"] if c["id"] == "bitvm3.labels_offchain_withheld.mutant.attack")
        index = report["cases"].index(tx_case)

        def tampered(mutate):
            copy_ = copy.deepcopy(report)
            mutate(copy_)
            body = {k: v for k, v in copy_.items() if k != "evidence_hash"}
            copy_["evidence_hash"] = digest(body)   # an attacker can always rehash
            return bitvm3.audit(copy_)

        def flip_payout(r):
            payout = next(s for s in r["cases"][index]["steps"] if s["label"] == "payout")
            raw = bytearray.fromhex(payout["raw_transaction"])
            raw[-60] ^= 1
            payout["raw_transaction"] = raw.hex()

        def claim_success_never_happened(r):
            for s in r["cases"][index]["steps"]:
                if s["label"] == "payout":
                    s["confirmed"] = False

        def relabel(r):
            r["cases"][index]["expected"]["attack_success"] = False

        def drop_case(r):
            del r["cases"][index]

        for mutate in (flip_payout, claim_success_never_happened, relabel, drop_case):
            with self.subTest(mutation=mutate.__name__):
                self.assertTrue(tampered(mutate))
        unhashed = copy.deepcopy(report)
        unhashed["summary"]["cases"] += 1
        self.assertIn("evidence_hash does not match the report body", bitvm3.audit(unhashed))

    def test_cli_native_list_and_audit(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(["native", "list", "--track", "bitvm3"]), 0)
        self.assertEqual(len(json.loads(out.getvalue())), len(bitvm3.catalog()))
        path = EVIDENCE / "primitive-core31.1.json"
        if path.exists():
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(main(["native", "audit", str(path)]), 0)
            self.assertTrue(json.loads(out.getvalue())["valid"])


@unittest.skipUnless(os.environ.get("BITVM_ARENA_BITCOIND"), "set BITVM_ARENA_BITCOIND to run against Core")
class LiveCoreTests(unittest.TestCase):
    def test_live_subset(self):
        binary = Path(os.environ["BITVM_ARENA_BITCOIND"])
        for module, match in ((native, "selector_unbound"), (bitvm3, "seed_reuse_across_claims")):
            rows = [r for r in module.catalog() if match in r["id"]]
            report = module.execute(binary, ROOT / "work" / "regtest" / uuid.uuid4().hex, rows)
            self.assertEqual(report["summary"]["expectation_failures"], [])
            problems = [p for p in module.audit(report) if "whole catalog" not in p and "catalog_hash" not in p]
            self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
