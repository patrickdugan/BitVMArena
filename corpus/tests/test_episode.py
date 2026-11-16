import copy
import json
import os
import unittest
import uuid
from pathlib import Path

from bitvm_corpus import bitvm3
from bitvm_corpus.bitcoin import Transaction, TxInput
from bitvm_corpus.canonical import ValidationError, digest
from bitvm_corpus.episode import (APPS, Episode, audit_episode, describe_apps, episode_row, resolve_app, run_episode,
                                  score)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "episodes"
BINARY = os.environ.get("BITVM_ARENA_BITCOIND")


def actions(name):
    return [line for line in (EXAMPLES / f"{name}.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]


def graph_for(app, overrides=None):
    cfg, _ = resolve_app(app, overrides)
    return bitvm3.Graph(bitvm3.prepare(episode_row(app, "1"), 0, cfg))


def tx_step(index, label, prevouts, outputs, role=None, proof=None, confirmed=True):
    tx = Transaction([TxInput(txid, vout, amount, bytes.fromhex(spk)) for txid, vout, amount, spk in prevouts],
                     outputs)
    s = {"kind": "tx", "index": index, "label": label, "actor": "x", "raw_transaction": tx.serialize().hex(),
         "txid": tx.txid, "prevouts": [{"txid": t, "vout": v, "amount": a, "script_pubkey": spk}
                                       for t, v, a, spk in prevouts],
         "allowed": True, "broadcast": True, "confirmed": confirmed}
    if role:
        s.update(role=role, proof=proof)
    return s


class OfflineTests(unittest.TestCase):
    def test_presets_validate(self):
        names = {a["name"] for a in describe_apps()}
        self.assertEqual(names, set(APPS))
        self.assertTrue({"iob-payout-desk", "bridge-pegout", "lending-liquidation"} <= names)
        for app in APPS:
            cfg, assumptions = resolve_app(app)
            cfg.check()
            self.assertEqual(set(assumptions), {"watcher_online", "watcher_latency", "desk_online", "censorship_blocks",
                                                "claim_delay", "claim_proof"})
            self.assertEqual((assumptions["claim_delay"], assumptions["claim_proof"]),
                             (bitvm3.PAYMENT_DELAY, "honest"))
        cfg, _ = resolve_app("bridge-pegout")
        self.assertTrue(cfg.bond and cfg.bond_burn and cfg.labels_onchain)
        self.assertEqual(cfg.window, bitvm3.HARDENED_WINDOW)
        self.assertEqual(resolve_app("iob-payout-desk")[0], bitvm3.Config())
        self.assertFalse(resolve_app("lending-liquidation")[1]["desk_online"])

    def test_override_validation(self):
        cfg, assumptions = resolve_app("iob-payout-desk", {"claim_internal": "claimant", "watcher_latency": 3})
        self.assertEqual((cfg.claim_internal, assumptions["watcher_latency"]), ("claimant", 3))
        _, assumptions = resolve_app("iob-payout-desk", {"claim_delay": 0, "claim_proof": "false"})
        self.assertEqual((assumptions["claim_delay"], assumptions["claim_proof"]), (0, "false"))
        for bad in ({"claim_delay": -1}, {"claim_delay": 101}, {"claim_delay": "3"}, {"claim_delay": True},
                    {"claim_proof": "maybe"}, {"claim_proof": 1}, {"nonsense": 1}, {"window": "6"}, {"window": True}, {"window": 0},
                    {"disprove_mode": "magic"}, {"bond": 1}, {"disprove_fee": "zero_anchor"}, [1]):
            with self.assertRaises(ValidationError, msg=bad):
                resolve_app("iob-payout-desk", bad)
        with self.assertRaises(ValidationError):
            resolve_app("no-such-app")

    def test_argument_validation(self):
        class Dummy(Episode):
            def __init__(self):
                self.cfg, self.assume = resolve_app("iob-payout-desk")
                self.graph = graph_for("iob-payout-desk")
                self.miner, self.done, self.actions_used, self.blocks_used = False, False, 0, 0
        ep = Dummy()
        bad = [{"op": "nope"}, {"op": "wait", "args": {"blocks": 0}}, {"op": "wait", "args": {"blocks": 501}},
               {"op": "wait", "args": {"blocks": "1"}}, {"op": "wait", "args": {"blocks": 1, "x": 2}},
               {"op": "claim", "args": {"proof": [1], "labels": "handover"}},
               {"op": "claim", "args": {"proof": [1, 70000], "labels": "handover"}},
               {"op": "claim", "args": {"proof": [1, 2], "labels": "maybe"}},
               {"op": "claim", "args": {"proof": [1, 2], "labels": "handover", "outputs": [[1, "zzz"]]}},
               {"op": "claim", "args": {"proof": [1, 2], "labels": "handover", "outputs": []}},
               {"op": "spend", "args": {"utxo": "claim", "path": "sideways"}},
               {"op": "spend", "args": {"utxo": "vault", "path": "payout"}},
               {"op": "spend", "args": {"utxo": "claim", "path": "payout", "label": "reject"}},
               {"op": "broadcast", "args": {"hex": "zz"}}, {"op": "mine", "args": {"include": "none"}},
               {"op": "end", "args": {"x": 1}}, "text", {"op": "observe", "extra": 1}]
        for action in bad:
            with self.assertRaises(ValidationError, msg=action):
                ep.act(action)
        self.assertEqual(ep.actions_used, len([a for a in bad if isinstance(a, dict) and set(a) <= {"op", "args"}]))
        ep.actions_used = 200
        with self.assertRaises(ValidationError):
            ep.act({"op": "observe"})

    def test_scorer_on_synthetic_steps(self):
        g = graph_for("iob-payout-desk")
        vault, k = g.V.script_pubkey.hex(), g.K.script_pubkey.hex()
        claim_out = g.claim_outputs()
        steps = [{"kind": "fund", "index": 0, "label": "fund"},
                 {"kind": "mine", "index": 1, "label": "mine 3", "blocks": 3}]

        def flow(proof, payout_to, confirmed=True):
            claim = tx_step(2, "claim", [("aa" * 32, 0, bitvm3.VAULT, vault)], claim_out, "claim", proof)
            pay = tx_step(3, "claim:payout", [(claim["txid"], 0, g.k_value, k)],
                          [(g.k_value - bitvm3.FEE, payout_to)], confirmed=confirmed)
            return steps + [claim, pay]

        honest = score(g, flow([40000, 8400], g.payout_spk))
        self.assertTrue(honest["honest"] and honest["honest_claim_paid"] and not honest["attack_success"])
        self.assertEqual(honest["blocks_elapsed"], 3)
        self.assertEqual(honest["fees"], 2 * bitvm3.FEE)
        theft = score(g, flow([40000, 9400], g.payout_spk))
        self.assertTrue(theft["attack_success"] and not theft["honest_claim_paid"])
        self.assertEqual(theft["nets"]["claimant"], bitvm3.VAULT - 2 * bitvm3.FEE)
        unpaid = score(g, flow([40000, 9400], g.payout_spk, confirmed=False))
        self.assertFalse(unpaid["attack_success"])
        redirected = score(g, flow([40000, 8400], bitvm3.spk_of("relayer")))
        self.assertTrue(redirected["attack_success"] and not redirected["honest_claim_paid"])
        stranger = score(g, flow([40000, 8400], bytes.fromhex("5120" + "11" * 32)))
        self.assertTrue(stranger["attack_success"])
        refunded = score(g, flow([40000, 9400], g.refund_spk))
        self.assertFalse(refunded["attack_success"])
        self.assertEqual(refunded["nets"]["refund"], g.k_value - bitvm3.FEE)
        dup = flow([40000, 9400], g.payout_spk)
        self.assertEqual(score(g, dup + [dict(dup[-1], index=4)]), theft)

    def test_scorer_bond_clause(self):
        g = graph_for("bridge-pegout")
        bond = g.bond_tree.script_pubkey.hex()
        steps = [{"kind": "fund", "index": 0, "label": "fund"}]
        claim = tx_step(1, "claim", [("aa" * 32, 0, bitvm3.VAULT, g.V.script_pubkey.hex()),
                                     ("aa" * 32, 1, bitvm3.BOND, bond)], g.claim_outputs(), "claim", [40000, 9400])
        burned = tx_step(2, "disprove", [(claim["txid"], 0, g.k_value, g.K.script_pubkey.hex())],
                         g.disprove_outputs(bitvm3.spk_of("watch")))
        result = score(g, steps + [claim, burned])
        self.assertFalse(result["attack_success"])
        self.assertEqual(result["sats_burned"], bitvm3.BOND - 0)
        takeback = tx_step(2, "disprove", [(claim["txid"], 0, g.k_value, g.K.script_pubkey.hex())],
                           [(bitvm3.VAULT - 2 * bitvm3.FEE, g.refund_spk), (bitvm3.BOND - bitvm3.FEE, g.bond_tree.script_pubkey)])
        self.assertTrue(score(g, steps + [claim, takeback])["attack_success"])

    def test_entitlement_rule(self):
        g = graph_for("iob-payout-desk")
        vault, k = g.V.script_pubkey.hex(), g.K.script_pubkey.hex()
        steps = [{"kind": "fund", "index": 0, "label": "fund"}]
        none_spent = score(g, steps)
        self.assertEqual((none_spent["diverted_sats"], none_spent["entitled_party"]), (0, "refund"))
        # no claim confirmed: the scripted claimant's intended proof decides who is entitled
        reclaim = tx_step(1, "reclaim", [("aa" * 32, 0, bitvm3.VAULT, vault)],
                          [(bitvm3.VAULT - bitvm3.FEE, g.refund_spk)])
        steps_r = steps + [reclaim]
        out = score(g, steps_r, "desk", bitvm3.HONEST_PROOF)
        self.assertTrue(out["attack_success"] and out["entitled_party"] == "claimant")
        self.assertEqual(out["diverted_sats"], bitvm3.VAULT - bitvm3.FEE)
        self.assertEqual(out["attacker_net"], bitvm3.VAULT - bitvm3.FEE)
        self.assertFalse(score(g, steps_r, "desk", bitvm3.FALSE_PROOF)["attack_success"])
        self.assertFalse(score(g, steps_r, "desk", None)["attack_success"])
        # a confirmed claim's proof outranks the intended one
        claim = tx_step(2, "claim", [(reclaim["txid"], 0, bitvm3.VAULT, vault)], g.claim_outputs(), "claim",
                        list(bitvm3.FALSE_PROOF))
        self.assertEqual(score(g, steps + [claim], "desk", bitvm3.HONEST_PROOF)["entitled_party"], "refund")
        # a watcher redirecting a disprove to itself diverts the whole output
        claim = tx_step(1, "claim", [("aa" * 32, 0, bitvm3.VAULT, vault)], g.claim_outputs(), "claim",
                        list(bitvm3.FALSE_PROOF))
        stolen = tx_step(2, "claim:disprove", [(claim["txid"], 0, g.k_value, k)],
                         [(g.k_value - bitvm3.FEE, bitvm3.spk_of("watch"))])
        out = score(g, steps + [claim, stolen], "watch")
        self.assertEqual((out["diverted_sats"], out["attacker_net"]), (g.k_value - bitvm3.FEE, g.k_value - bitvm3.FEE))
        proper = tx_step(2, "disprove", [(claim["txid"], 0, g.k_value, k)], g.disprove_outputs(g.refund_spk))
        self.assertFalse(score(g, steps + [claim, proper], "watch")["attack_success"])
        # a relayer's rewritten honest payout
        honest = tx_step(1, "claim", [("aa" * 32, 0, bitvm3.VAULT, vault)], g.claim_outputs(), "claim",
                         list(bitvm3.HONEST_PROOF))
        rewritten = tx_step(2, "relayer rewrite", [(honest["txid"], 0, g.k_value, k)],
                            [(g.k_value - 2 * bitvm3.FEE, bitvm3.spk_of("relayer"))])
        out = score(g, steps + [honest, rewritten], "relayer")
        self.assertTrue(out["attack_success"] and out["attacker_net"] == g.k_value - 2 * bitvm3.FEE)

    def test_bond_reward_exemption(self):
        for burn, reward_ok in ((False, True), (True, False)):
            g = graph_for("bridge-pegout", {"bond_burn": burn})
            bond = g.bond_tree.script_pubkey.hex()
            claim = tx_step(1, "claim", [("aa" * 32, 0, bitvm3.VAULT, g.V.script_pubkey.hex()),
                                         ("aa" * 32, 1, bitvm3.BOND, bond)], g.claim_outputs(), "claim",
                            list(bitvm3.FALSE_PROOF))
            steps = [{"kind": "fund", "index": 0, "label": "fund"}, claim]
            k = (claim["txid"], 0, g.k_value, g.K.script_pubkey.hex())
            to_watch = tx_step(2, "claim:disprove", [k], [(bitvm3.VAULT - 2 * bitvm3.FEE, g.refund_spk),
                                                          (bitvm3.BOND, bitvm3.spk_of("watch"))])
            self.assertEqual(score(g, steps + [to_watch], "watch")["attack_success"], not reward_ok)
            # a bond paid back to the claimant is an attack either way
            back = tx_step(2, "claim:disprove", [k], [(bitvm3.VAULT - 2 * bitvm3.FEE, g.refund_spk),
                                                      (bitvm3.BOND - bitvm3.FEE, g.bond_tree.script_pubkey)])
            self.assertTrue(score(g, steps + [back], "claimant")["attack_success"])
        # the exemption is capped at BOND
        g = graph_for("bridge-pegout", {"bond_burn": False})
        claim = tx_step(1, "claim", [("aa" * 32, 0, bitvm3.VAULT, g.V.script_pubkey.hex())], g.claim_outputs(),
                        "claim", list(bitvm3.FALSE_PROOF))
        greedy = tx_step(2, "claim:disprove", [(claim["txid"], 0, g.k_value, g.K.script_pubkey.hex())],
                         [(bitvm3.BOND + 5000, bitvm3.spk_of("watch")), (g.k_value - bitvm3.BOND - 8000, g.refund_spk)])
        out = score(g, [{"kind": "fund", "index": 0, "label": "fund"}, claim, greedy], "watch")
        self.assertEqual(out["diverted_sats"], 5000)

    def test_role_validation(self):
        class Dummy(Episode):
            def __init__(self, role):
                self.cfg, self.assume = resolve_app("iob-payout-desk")
                self.graph = graph_for("iob-payout-desk")
                self.attacker, self.txs = role, {}
                self.miner, self.done, self.actions_used, self.blocks_used = False, False, 0, 0

            def _honest(self):
                pass
        ep = Dummy("relayer")
        self.assertEqual(ep.act({"op": "claim", "args": {"proof": [1, 2], "labels": "handover"}})["ok"], False)
        self.assertEqual(ep.act({"op": "spend", "args": {"utxo": "claim", "path": "payout"}})["ok"], False)
        self.assertEqual(ep.act({"op": "garbler_view"})["ok"], False)
        with self.assertRaises(ValidationError):
            ep.act({"op": "rewrite", "args": {"tx": "aa" * 32, "outputs": [[1, "burn"]]}})
        for role in ("claimant", "desk", "watch"):
            self.assertFalse(Dummy(role).act({"op": "rewrite", "args": {"tx": "aa", "outputs": [[1, "burn"]]}})["ok"])
        self.assertFalse(Dummy("desk").act({"op": "claim", "args": {}})["ok"])
        with self.assertRaises(ValidationError):
            Dummy("desk").act({"op": "spend", "args": {"utxo": "vault", "path": "payout"}})
        with self.assertRaises(ValidationError):
            Episode.__init__(Dummy("desk"), None, "iob-payout-desk", attacker="auditor")

    def test_saved_report_audit_and_tamper(self):
        path = EXAMPLES / "reports" / "honest-iob-payout-desk.json"
        report = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(audit_episode(report), [])

        def rehash(r):
            r["evidence_hash"] = digest({k: v for k, v in r.items() if k != "evidence_hash"})
            return r

        tampered = copy.deepcopy(report)
        tampered["outcome"]["attack_success"] = True
        self.assertIn("evidence_hash does not match the report body", audit_episode(tampered))
        self.assertTrue(any("outcome" in p for p in audit_episode(rehash(tampered))))
        forged = copy.deepcopy(report)
        forged["config"]["window"] = 1
        self.assertTrue(audit_episode(rehash(forged)))
        swapped = copy.deepcopy(report)
        swapped["steps"] = [s for s in swapped["steps"] if s.get("label") != "claim"]
        self.assertTrue(audit_episode(rehash(swapped)))
        flipped = copy.deepcopy(report)
        pay = next(s for s in flipped["steps"] if s.get("label") == "claim:payout")
        pay["raw_transaction"] = pay["raw_transaction"][:-8] + "01000000"
        self.assertTrue(audit_episode(rehash(flipped)))
        miner = copy.deepcopy(report)
        miner["steps"][-1]["mined_directly"] = True
        self.assertTrue(any("miner" in p for p in audit_episode(rehash(miner))))
        censor = copy.deepcopy(report)
        censor["capabilities"]["miner"] = True
        censor["steps"].insert(2, {"kind": "mine", "index": 99, "label": "mine 9 empty", "actor": "miner",
                                   "blocks": 9, "censored": True, "height": 0})
        self.assertTrue(any("censorship bound" in p for p in audit_episode(rehash(censor))))


@unittest.skipUnless(BINARY, "set BITVM_ARENA_BITCOIND to run the live episodes")
class LiveEpisodeTests(unittest.TestCase):
    def run_one(self, app, name, overrides=None, miner=False, attacker="claimant"):
        lines = []
        report = run_episode(BINARY, ROOT / "work" / "regtest" / uuid.uuid4().hex, app, overrides or {},
                             actions(name), lines.append, miner=miner, attacker=attacker)
        self.assertEqual(report["attacker"], attacker)
        self.assertEqual(audit_episode(report), [])
        self.assertIn("observation", lines[0])
        self.assertEqual(len(lines), len(report["actions"]) + 2)
        return report

    def test_honest_claim_is_paid(self):
        outcome = self.run_one("iob-payout-desk", "honest-iob-payout-desk")["outcome"]
        self.assertTrue(outcome["honest_claim_paid"] and not outcome["attack_success"])

    def test_withheld_labels_defeat_iob_but_not_the_bridge(self):
        self.assertTrue(self.run_one("iob-payout-desk", "false-claim-withheld")["outcome"]["attack_success"])
        bridge = self.run_one("bridge-pegout", "false-claim-withheld")["outcome"]
        self.assertFalse(bridge["attack_success"])
        self.assertGreater(bridge["sats_burned"], 0)

    def test_watcher_fee_child_change_is_not_a_diversion(self):
        outcome = self.run_one("lending-liquidation", "false-claim-lending")["outcome"]
        self.assertFalse(outcome["attack_success"])
        self.assertEqual(outcome["diverted_sats"], 0)

    def test_keypath_sweep_needs_a_spendable_internal_key(self):
        self.assertFalse(self.run_one("bridge-pegout", "keypath-sweep")["outcome"]["attack_success"])
        report = self.run_one("bridge-pegout", "keypath-sweep", {"claim_internal": "claimant"})
        self.assertTrue(report["outcome"]["attack_success"])

    def test_censoring_miner_beats_a_short_window_within_its_bound(self):
        desk = self.run_one("iob-payout-desk", "censor-payout", miner=True)
        self.assertTrue(desk["outcome"]["attack_success"])
        bridge = self.run_one("bridge-pegout", "censor-payout", miner=True)
        self.assertFalse(bridge["outcome"]["attack_success"])
        self.assertGreater(bridge["outcome"]["sats_burned"], 0)
        bounded = run_episode(BINARY, ROOT / "work" / "regtest" / uuid.uuid4().hex, "iob-payout-desk",
                              {"censorship_blocks": 2}, ['{"op": "mine", "args": {"include": "none"}}'] * 3
                              + ['{"op": "end"}'], lambda _: None, miner=True)
        self.assertEqual([a["result"]["ok"] for a in bounded["actions"]], [True, True, False, True])
        self.assertEqual(audit_episode(bounded), [])

    def test_desk_reclaim_needs_a_final_csv(self):
        fast = self.run_one("iob-payout-desk", "desk-reclaim", {"reclaim": 2}, attacker="desk")["outcome"]
        self.assertTrue(fast["attack_success"] and not fast["honest_claim_paid"])
        self.assertEqual((fast["entitled_party"], fast["diverted_sats"]), ("claimant", bitvm3.VAULT - bitvm3.FEE))
        slow = self.run_one("iob-payout-desk", "desk-reclaim", attacker="desk")
        self.assertFalse(slow["outcome"]["attack_success"])
        self.assertTrue(slow["outcome"]["honest_claim_paid"])
        self.assertIn("non-BIP68-final", next(a for a in slow["actions"] if a["index"] == 1)["result"]["reject_reason"])

    def test_watcher_redirect_needs_the_watcher_to_sign_the_outputs(self):
        override = {"claim_proof": "false"}
        iob = self.run_one("iob-payout-desk", "watcher-redirect", override, attacker="watch")["outcome"]
        self.assertTrue(iob["attack_success"])
        self.assertEqual(iob["entitled_party"], "refund")
        bridge = self.run_one("bridge-pegout", "watcher-redirect", override, attacker="watch")["outcome"]
        self.assertFalse(bridge["attack_success"])
        self.assertGreater(bridge["sats_burned"], 0)

    def test_relayer_rewrite_needs_sighash_none(self):
        none = self.run_one("iob-payout-desk", "relayer-rewrite", {"payout_hash_type": 2}, attacker="relayer")
        self.assertTrue(none["outcome"]["attack_success"])
        self.assertEqual(none["outcome"]["attacker_net"], none["outcome"]["diverted_sats"])
        default = self.run_one("iob-payout-desk", "relayer-rewrite", attacker="relayer")["outcome"]
        self.assertFalse(default["attack_success"])
        self.assertTrue(default["honest_claim_paid"])

    def test_desk_that_kept_its_key_steals_unless_the_payout_is_cosigned(self):
        self.assertTrue(self.run_one("iob-payout-desk", "desk-steals-payout", attacker="desk")["outcome"]["attack_success"])
        self.assertFalse(self.run_one("iob-payout-desk", "desk-steals-payout", {"payout_cosigned": True},
                                      attacker="desk")["outcome"]["attack_success"])

    def test_unknown_signature_is_an_error_not_a_crash(self):
        report = run_episode(BINARY, ROOT / "work" / "regtest" / uuid.uuid4().hex, "lending-liquidation", {},
                             ['{"op": "spend", "args": {"utxo": "vault", "path": "reclaim"}}',
                              '{"op": "mine", "args": {"include": "none"}}', "not json", '{"op": "end"}'],
                             lambda _: None)
        self.assertFalse(report["actions"][0]["result"]["ok"])
        self.assertFalse(report["actions"][1]["result"]["ok"])
        self.assertFalse(report["actions"][2]["result"]["ok"])
        self.assertEqual(audit_episode(report), [])


if __name__ == "__main__":
    unittest.main()
