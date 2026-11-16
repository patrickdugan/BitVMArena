import copy
import io
import json
import os
import random
import unittest
import uuid
from contextlib import redirect_stdout
from pathlib import Path

from bitvm_corpus import bitcoin, bitvm3, gc, native
from bitvm_corpus.cli import main, track_module
from bitvm_corpus.canonical import ValidationError, digest

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


class WinternitzTests(unittest.TestCase):
    def test_sign_verify_and_hash_forward_forgery(self):
        from bitvm_corpus import wots
        master, n0 = b"\x01" * 20, 3
        keys = wots.public_keys(master, n0)
        pairs = wots.sign(master, 150, n0)
        self.assertEqual(wots.n1_digits(2), 2)
        self.assertEqual(wots.n1_digits(3), 2)
        self.assertTrue(wots.check_pairs(keys, pairs, n0))
        self.assertEqual(wots.value_of(pairs, n0), 150)
        forged = list(pairs)
        forged[n0 - 1] = wots.forward(forged[n0 - 1])
        self.assertEqual(wots.value_of(forged, n0), 151)
        # The chains still verify; only the checksum catches the forgery.
        self.assertTrue(wots.check_pairs(keys, forged, n0, checksum=False))
        self.assertFalse(wots.check_pairs(keys, forged, n0))


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
            cltv = 200 if a.cfg.payout_timelock == "cltv" else None
            self.assertEqual(bitvm3.Graph(a, cltv).V.script_pubkey, bitvm3.Graph(b, cltv).V.script_pubkey)
            self.assertEqual(bitvm3.Graph(a, cltv).K.script_pubkey, bitvm3.Graph(b, cltv).K.script_pubkey)
        grind = next(r for r in bitvm3.catalog() if r["id"] == "bitvm3.cut_and_choose_grindable.mutant.attack")
        log = bitvm3.prepare(grind).setup_log
        self.assertGreater(log["grind_attempts"], 0)
        self.assertIn(log["kept"], log["malicious"])

    def test_bitvm3_layers_cover_every_recipe(self):
        rows = bitvm3.catalog()
        self.assertEqual(len(rows), 4 * len(bitvm3.RECIPES))
        self.assertEqual({r["layer"] for r in rows}, set(bitvm3.LAYERS))
        for row in rows:
            honest_attack = row["recipe"] in bitvm3.HONEST_ATTACKS
            self.assertEqual(bitvm3.proof_for(row) == bitvm3.HONEST_PROOF,
                             row["variant"] == "benign" or honest_attack, row["id"])

    def test_bitvm3_assess_flags_exactly_the_mutant_designs(self):
        offline_desk = {"desk_online_at_dispute": False}
        for recipe in bitvm3.RECIPES:
            with self.subTest(recipe=recipe):
                mutant = bitvm3.assess(bitvm3.config(recipe, "mutant"), offline_desk)
                hardened = bitvm3.assess(bitvm3.config(recipe, "hardened"), offline_desk)
                self.assertIn(recipe, {f["recipe"] for f in mutant["findings"]})
                self.assertNotIn(recipe, {f["recipe"] for f in hardened["findings"]})
        as_built = {f["recipe"] for f in bitvm3.assess(bitvm3.Config())["findings"]}
        self.assertEqual(as_built, {"labels_offchain_withheld", "garbling_unchecked", "disprove_censored_by_miner",
                                    "single_watcher_disprove", "window_below_latency", "claimant_unbonded",
                                    "disprove_watcher_redirect", "desk_key_retained"})
        with self.assertRaises(ValidationError):
            bitvm3.assess(bitvm3.Config(), {"no_such_assumption": 1})

    def test_bitvm3_profiles_differ_in_one_decision(self):
        """Hardened and mutant configs differ only in the fields their recipe is about."""
        for recipe in bitvm3.RECIPES:
            hardened = bitvm3.config(recipe, "hardened").check().__dict__
            mutant = bitvm3.config(recipe, "mutant").check().__dict__
            changed = {k for k in hardened if hardened[k] != mutant[k]}
            if recipe == "seed_reuse_across_claims":
                self.assertEqual(changed, {"seed_reuse"})
            elif recipe in ("garbling_unchecked", "tables_delivered_late", "proof_replay_across_vaults"):
                self.assertTrue(changed, recipe)
            self.assertLessEqual(len(changed), 2, (recipe, changed))

    def test_bitvm3_config_rejects_incoherent_designs(self):
        for bad in ({"disprove_mode": "nobody"}, {"disprove_fee": "zero_anchor"},
                    {"disprove_fee": "zero_anchor", "disprove_mode": "presigned", "bond": True},
                    {"claim_hash_type": 7}, {"window": 0}):
            with self.subTest(bad=bad), self.assertRaises(ValidationError):
                bitvm3.Config(**bad).check()

    def _graph(self, recipe, profile, variant="attack", index=0):
        row = next(r for r in bitvm3.catalog() if r["id"] == f"bitvm3.{recipe}.{profile}.{variant}")
        prep = bitvm3.prepare(row, index=index)
        return row, prep, bitvm3.Graph(prep, 200 if prep.cfg.payout_timelock == "cltv" else None)

    @staticmethod
    def _claim(graph):
        return bitcoin.Transaction([bitcoin.TxInput("11" * 32, 0, 0, b"")], graph.claim_outputs())

    def test_bitvm3_key_path_and_presignature_scope(self):
        for profile, works in (("hardened", False), ("mutant", True)):
            _, _, graph = self._graph("claim_internal_key_spendable", profile)
            sweep = graph.sweep_tx(self._claim(graph), graph.payout_spk)
            self.assertEqual(bitcoin.check_signature(sweep, 0, None, graph.K.output_key, sweep.inputs[0].witness[0]),
                             works, profile)
            _, prep, graph = self._graph("claim_sighash_none", profile)
            vault = {"txid": "22" * 32, "vout": 0, "amount": bitvm3.VAULT, "script_pubkey": graph.V.script_pubkey.hex()}
            rewritten = graph.claim_tx({"vault": vault}, [], outputs=[(graph.k_value, graph.payout_spk)])
            desk_sig = rewritten.inputs[0].witness[1]
            self.assertEqual(bitcoin.check_signature(rewritten, 0, graph.V.leaf(0), graph.D, desk_sig), works, profile)

    def test_bitvm3_trust_and_pinning_shapes(self):
        claim = None
        for profile, cosigned in (("hardened", True), ("mutant", False)):
            _, _, graph = self._graph("desk_key_retained", profile)
            claim = self._claim(graph)
            self.assertEqual(graph.K.scripts[0].count(bytes([0xad])), 1 if cosigned else 0)
            steal = graph.desk_payout_tx(claim, graph.refund_spk)
            sig = steal.inputs[0].witness[-3]
            self.assertTrue(bitcoin.check_signature(steal, 0, graph.K.leaf(0), graph.D, sig))
            if cosigned:   # the desk can only put its own signature in the claimant's slot
                self.assertFalse(bitcoin.check_signature(steal, 0, graph.K.leaf(0), graph.C, steal.inputs[0].witness[0]))
        for profile, version in (("hardened", 3), ("mutant", 2)):
            _, prep, graph = self._graph("disprove_anchor_pinned", profile)
            claim = self._claim(graph)
            parent = graph.disprove_tx(claim, prep.garbling.reject_label, "claimant")
            self.assertEqual((parent.version, parent.outputs[1]), (version, (0, bitcoin.P2A)))
            coin = {"txid": "44" * 32, "vout": 0, "amount": bitvm3.PIN_COIN,
                    "script_pubkey": bitcoin.p2tr_key(graph.C).script_pubkey.hex()}
            pin = graph.pin_child(parent, coin, bitvm3.PIN_OUTPUTS, bitvm3.PIN_FEE)
            self.assertGreater(pin.vsize, 40_000)                      # far above TRUC's 1,000 vB child limit
            self.assertLess(bitvm3.PIN_FEE / (pin.vsize + parent.vsize), bitvm3.PIN_FLOOR)
            self.assertGreater(bitvm3.PIN_FEE, bitvm3.WATCH_FUNDS)      # outbidding it costs more than the watcher holds
        _, _, graph = self._graph("disprove_watcher_redirect", "mutant")
        claim = self._claim(graph)
        steal = graph.disprove_tx(claim, bytes(16), "watch", outputs=[(graph.k_value - bitvm3.FEE, bitvm3.spk_of("watch"))])
        self.assertTrue(bitcoin.check_signature(steal, 0, graph.K.leaf(1), graph.W, steal.inputs[0].witness[0]))

    def test_bitvm3_anchor_and_burn_shapes(self):
        _, _, graph = self._graph("disprove_unbumpable", "hardened")
        claim = self._claim(graph)
        parent = graph.disprove_tx(claim, b"\x00" * 16, "watch")
        self.assertEqual(parent.version, 3)
        self.assertEqual(sum(v for v, _ in parent.outputs), graph.k_value)       # zero fee
        self.assertEqual(parent.outputs[1], (0, bitcoin.P2A))
        child = graph.anchor_child(parent, {"txid": "33" * 32, "vout": 0, "amount": bitvm3.WATCH_FUNDS,
                                            "script_pubkey": bitvm3.spk_of("watch").hex()})
        self.assertEqual((child.version, child.inputs[0].txid, child.inputs[0].vout), (3, parent.txid, 1))
        _, _, graph = self._graph("disprove_unbumpable", "mutant")
        self.assertEqual(graph.disprove_tx(claim, b"\x00" * 16, "watch").outputs, [(graph.k_value, graph.refund_spk)])
        _, _, burned = self._graph("bond_self_slash", "hardened")
        self.assertEqual(burned.disprove_outputs(bitvm3.spk_of("watch"))[1], (bitvm3.BOND, bitvm3.BURN_SPK))

    def test_bitvm3_statement_binding_and_table_corruption(self):
        for profile, second in (("hardened", "reject"), ("mutant", "accept")):
            _, prep, graph = self._graph("proof_replay_across_vaults", profile, index=1)
            out = gc.evaluate(prep.statement, prep.garbling.tables,
                              prep.garbling.input_labels(gc.proof_bits(*bitvm3.HONEST_PROOF)))
            self.assertEqual(gc.decode(out, graph.data["accept_label_sha256"], graph.data["reject_label_sha256"]),
                             second, profile)
        for row in bitvm3.catalog():
            prep = bitvm3.prepare(row)
            out = gc.evaluate(prep.statement, bitvm3.corrupt_tables(prep.garbling.tables),
                              prep.garbling.input_labels(gc.proof_bits(*bitvm3.FALSE_PROOF)))
            self.assertEqual(gc.decode(out, prep.public["accept_label_sha256"], prep.public["reject_label_sha256"]),
                             "invalid", row["id"])


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

        slash = next(c for c in report["cases"] if c["id"] == "bitvm3.bond_self_slash.mutant.attack")
        slash_index = report["cases"].index(slash)

        def revive_displaced_disprove(r):
            # Claim the watcher's replaced disprove confirmed too: a double spend.
            for s in r["cases"][slash_index]["steps"]:
                if s.get("displaced"):
                    s["confirmed"] = True
                    del s["displaced"]

        for mutate in (flip_payout, claim_success_never_happened, relabel, drop_case, revive_displaced_disprove):
            with self.subTest(mutation=mutate.__name__):
                self.assertTrue(tampered(mutate))
        unhashed = copy.deepcopy(report)
        unhashed["summary"]["cases"] += 1
        self.assertIn("evidence_hash does not match the report body", bitvm3.audit(unhashed))

    def test_cli_native_assess(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(["native", "assess", "--app", "iob-payout-desk"]), 0)
        self.assertIn("labels_offchain_withheld", {f["recipe"] for f in json.loads(out.getvalue())["findings"]})
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(["native", "assess", "--config", '{"claim_internal": "claimant"}',
                                   "--assume", '{"watchers": 2}']), 0)
        findings = {f["recipe"] for f in json.loads(out.getvalue())["findings"]}
        self.assertIn("claim_internal_key_spendable", findings)
        self.assertNotIn("single_watcher_disprove", findings)
        self.assertEqual(main(["native", "assess", "--config", '{"window": "6"}']), 2)

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
        for module, match in ((native, "selector_unbound"), (bitvm3, "seed_reuse_across_claims"),
                              (bitvm3, "disprove_unbumpable"), (bitvm3, "disprove_censored_by_miner"),
                              (bitvm3, "disprove_anchor_pinned"), (bitvm3, "disprove_partitioned")):
            rows = [r for r in module.catalog() if match in r["id"]]
            report = module.execute(binary, ROOT / "work" / "regtest" / uuid.uuid4().hex, rows)
            self.assertEqual(report["summary"]["expectation_failures"], [])
            problems = [p for p in module.audit(report) if "whole catalog" not in p and "catalog_hash" not in p]
            self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
