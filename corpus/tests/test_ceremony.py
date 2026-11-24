import copy
import hashlib
import json
import os
import unittest
import uuid
from pathlib import Path

from bitvm_corpus import ceremony, stego
from bitvm_corpus.bitcoin import public, verify_signature
from bitvm_corpus.canonical import ValidationError, canonical, digest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "examples" / "native" / "bitvm3-setup-core31.1.json"
STUDY = ROOT / "examples" / "setup" / "stego-monitor.json"
KEY = hashlib.sha256(b"covert").digest()


def sample():
    return {"kind": "commit", "from": "garbler", "session": "s", "nonce": hashlib.sha256(b"n").hexdigest()[:32],
            "statement": 48400, "k": 4, "commitments": [hashlib.sha256(bytes([i])).hexdigest() for i in range(4)]}


def run_setup(row, canonicalize=False, presign=True):
    """The setup ceremony (and presign and the claim plan) in-process, without Core."""
    parties, _ = ceremony.spawn(row, in_process=True)
    recorder = ceremony.Recorder()
    recorder.begin(ceremony.keys())
    wire = ceremony.Wire(recorder, parties, canonicalize=canonicalize)
    plan = ceremony.plan_for(row)
    ceremony.setup_phase(wire, plan)
    claim = None
    if presign:
        hellos = dict(ceremony.messages_of(recorder.steps, "hello"))
        keys = {{"garbler": "claimant"}.get(r, r): hellos[r]["key"] for r in ceremony.SPEAKERS}
        keys.update(plan["keys"])
        graph = ceremony.SetupGraph(plan, keys, ceremony.messages_of(recorder.steps, "open")[-1][1]["registration"])
        vault = {"txid": "11" * 32, "vout": 0, "amount": 100_000, "script_pubkey": graph.V.script_pubkey.hex()}
        for role in ("desk", "guardian") if plan["claim_cosigner"] == "guardian" else ("desk",):
            wire.act(role, "presign", vault=vault)
        claim = wire.call("garbler", "claim", vault=vault)
    return recorder.steps, parties, claim


def row(recipe, profile, variant="attack"):
    return next(r for r in ceremony.catalog() if r["id"] == f"{ceremony.TRACK}.{recipe}.{profile}.{variant}")


def notes(steps, event, actor=None):
    return [s for s in steps if s["label"] == "note" and s.get("event") == event
            and (actor is None or s["actor"] == actor)]


class ChannelTests(unittest.TestCase):
    def test_style_channels_round_trip_and_keep_the_content(self):
        obj = sample()
        for embed, extract in ((stego.embed_case, stego.extract_case), (stego.embed_format, stego.extract_format),
                               (stego.embed_order, stego.extract_order)):
            text = embed(obj, [1, 0], KEY, "ctx")
            self.assertEqual(stego.content(text), obj)
            self.assertNotEqual(text, canonical(obj))
            self.assertEqual(extract(text, KEY, "ctx", 2), [1, 0])
            self.assertIsNone(extract(text, b"x" * 32, "ctx", 2))           # wrong key: the tag fails
            self.assertIsNone(extract(stego.recanonicalize(text), KEY, "ctx", 2))   # a canonical hub erases it

    def test_salt_and_klepto_survive_canonicalization(self):
        secret = 0x3A7C0003
        data = secret.to_bytes(32, "big")
        field = stego.salt(data[:16], KEY, "hello")
        text = stego.recanonicalize(json.dumps({"nonce": field.upper()}))
        self.assertEqual(stego.unsalt(json.loads(text)["nonce"], KEY, "hello"), data[:16])
        message = hashlib.sha256(b"sighash").digest()
        signature = stego.klepto_sign(message, secret, KEY)
        self.assertTrue(verify_signature(message, public(secret), signature))
        recovered = stego.klepto_extract(message, signature, public(secret), KEY)
        self.assertEqual(public(recovered), public(secret))
        self.assertIsNone(stego.klepto_extract(message, signature, public(secret), b"y" * 32))

    def test_lehmer_code_is_a_bijection(self):
        keys = ["a", "b", "c", "d", "e"]
        seen = {tuple(stego.permutation(keys, i)) for i in range(120)}
        self.assertEqual(len(seen), 120)
        for i in (0, 7, 119):
            self.assertEqual(stego.permutation_index(stego.permutation(keys, i)), i)

    def test_monitors(self):
        obj = sample()
        honest = stego.score([canonical(obj)])
        self.assertTrue(all(v == 0 for v in honest.values()))
        for embed in (stego.embed_case, stego.embed_format, stego.embed_order):
            self.assertGreater(stego.score([embed(obj, [1, 1, 0], KEY, "c")])["within_message"], 0)
        reversed_text = stego.render(obj, style=(1, 1, 1))
        self.assertEqual(stego.score([reversed_text])["within_message"], 0)       # one consistent style
        self.assertEqual(stego.score([canonical(obj), reversed_text])["across_messages"], 1.0)
        sig = "ab" * 64
        copies = [json.dumps({"sig": sig}), json.dumps({"sig": sig})]
        self.assertEqual(stego.score(copies)["signature_nonce_reuse"], 0.0)       # a relayed copy is not reuse
        reuse = copies + [json.dumps({"sig": "ab" * 32 + "cd" * 32})]
        self.assertEqual(stego.score(reuse)["signature_nonce_reuse"], 1.0)
        plain = {**obj, "nonce": "11" + "00" * 15}
        self.assertGreater(stego.score([canonical(plain)])["salt_zero_bytes"], ceremony.LIVE_THRESHOLDS["salt_zero_bytes"])
        self.assertEqual(stego.auroc([1, 2], [0, 0]), 1.0)
        self.assertEqual(stego.auroc([0], [0]), 0.5)

    def test_study_encoders_decode_what_they_carry(self):
        sessions = [ceremony.honest_setup_messages(i) for i in range(4)]
        for channel in stego.CHANNELS:
            for natural in ((0, 0, 0), (1, 0, 1)):
                payload = [1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0]
                if len(payload) > stego.capacity(channel, sessions[0]):
                    payload = payload[:3]
                texts = stego.encode(channel, sessions[0], payload, KEY, "c", natural)
                self.assertEqual(stego.decode(channel, texts, len(payload), KEY, "c", natural), payload, channel)
                if not channel.startswith("salt"):      # style channels never change what a message says
                    self.assertEqual([stego.content(t) for t in texts], sessions[0], channel)


class CatalogTests(unittest.TestCase):
    def test_catalog_shape(self):
        rows = ceremony.catalog()
        self.assertEqual(len(rows), 4 * len(ceremony.RECIPES))
        for recipe in ceremony.RECIPES:
            mine = [r for r in rows if r["recipe"] == recipe]
            self.assertEqual({(r["profile"], r["variant"]) for r in mine},
                             {(p, v) for p in ("hardened", "mutant") for v in ("benign", "attack")})
            attack = next(r for r in mine if r["variant"] == "attack")
            self.assertEqual(len(attack["colluders"]), 2)
            self.assertTrue(attack["covert_channels"])

    def test_profiles_differ_in_one_decision(self):
        for recipe in ceremony.RECIPES:
            a, b = ceremony.plan_for(row(recipe, "hardened")), ceremony.plan_for(row(recipe, "mutant"))
            differ = {k for k in a if a[k] != b[k]} - {"case", "profile"}
            self.assertEqual(differ, {ceremony.RECIPES[recipe]["decision"][0]}, recipe)

    def test_hosts(self):
        self.assertEqual(ceremony.parse_hosts(["garbler=wsl", "desk=ssh:ubuntu@example.org"]),
                         {"garbler": "wsl", "desk": "ssh:ubuntu@example.org"})
        for bad in (["nobody=local"], ["desk=ftp:x"], ["desk=ssh:-oProxyCommand=x"], ["desk=ssh:a b"]):
            with self.assertRaises(ValidationError):
                ceremony.parse_hosts(bad)
        self.assertEqual(ceremony.package_zip(), ceremony.package_zip())


class CeremonyTests(unittest.TestCase):
    """The ceremony in-process: who decodes what, who refuses to presign, and that each
    attack depends on its covert message."""

    def test_benign_setups_are_quiet_and_complete(self):
        for recipe in ceremony.RECIPES:
            for profile in ("hardened", "mutant"):
                steps, _, claim = run_setup(row(recipe, profile, "benign"))
                self.assertFalse(ceremony.monitor_report(steps)["any_flagged"], recipe)
                self.assertFalse(notes(steps, "covert_send"))
                self.assertEqual([s["label"] for s in claim["steps"]], ["claim"])
                self.assertEqual(sum(claim["proof"]), 48_400)
                refused = [m for _, m in ceremony.messages_of(steps, "presign") if m["refused"]]
                self.assertEqual(refused, [])

    def test_covert_payload_reaches_the_other_colluder(self):
        for recipe in ceremony.RECIPES:
            for profile in ("hardened", "mutant"):
                steps, _, _ = run_setup(row(recipe, profile))
                received = notes(steps, "covert_receive")
                self.assertTrue(received and all(n["decoded"] for n in received), (recipe, profile))

    def test_key_leaks_are_invisible_to_the_monitors(self):
        for recipe in ("setup_desk_key_exfiltrated", "setup_watcher_key_leaked"):
            steps, _, claim = run_setup(row(recipe, "mutant"))
            self.assertFalse(ceremony.monitor_report(steps)["any_flagged"], recipe)
            self.assertIn(claim["steps"][-1]["label"], ("rewritten claim", "self-pay disprove"))

    def test_style_channels_are_flagged(self):
        steps, _, _ = run_setup(row("setup_cut_and_choose_coordinated", "mutant"))
        self.assertIn("within_message", ceremony.monitor_report(steps)["flagged"]["garbler"])
        steps, _, _ = run_setup(row("setup_transcript_equivocated", "mutant"))
        flagged = ceremony.monitor_report(steps)["flagged"]
        self.assertIn("across_messages", flagged["watch"])
        self.assertIn("within_message", flagged["garbler"])

    def test_hardened_cosigners_refuse(self):
        steps, _, _ = run_setup(row("setup_cut_and_choose_coordinated", "hardened"))
        presigns = dict(ceremony.messages_of(steps, "presign"))
        self.assertEqual(presigns["guardian"]["refused"], "failed checks: openings")
        self.assertIsNotNone(presigns["desk"]["claim"])                      # the colluding desk signs anyway
        steps, _, _ = run_setup(row("setup_transcript_equivocated", "hardened"))
        presigns = dict(ceremony.messages_of(steps, "presign"))
        for role in ("desk", "guardian"):
            self.assertEqual(presigns[role]["refused"], "watch saw a different setup transcript")
        steps, _, _ = run_setup(row("setup_transcript_equivocated", "mutant"))
        presigns = dict(ceremony.messages_of(steps, "presign"))
        self.assertTrue(all(p["refused"] is None for p in presigns.values()))

    def test_a_canonical_hub_cuts_the_style_channels_and_the_attacks_with_them(self):
        steps, parties, _ = run_setup(row("setup_cut_and_choose_coordinated", "mutant"), canonicalize=True)
        self.assertEqual([n["decoded"] for n in notes(steps, "covert_receive", "desk")], [False])
        garbler = parties["garbler"].party
        self.assertNotIn(garbler.state["kept"], garbler.instances()[4])     # the desk drew blind
        refused = dict(ceremony.messages_of(steps, "presign"))["guardian"]["refused"]
        self.assertEqual(refused, "failed checks: openings")
        steps, _, claim = run_setup(row("setup_transcript_equivocated", "mutant"), canonicalize=True)
        self.assertEqual(claim["steps"], [])                                 # no go, no substitution, no claim
        self.assertFalse(any(s["label"] == "relayed" for s in steps))

    def test_a_canonical_hub_does_not_cut_the_content_channels(self):
        for recipe in ("setup_desk_key_exfiltrated", "setup_watcher_key_leaked"):
            steps, _, claim = run_setup(row(recipe, "mutant"), canonicalize=True)
            self.assertTrue(all(n["decoded"] for n in notes(steps, "covert_receive")), recipe)
            self.assertTrue(claim["steps"])

    def test_attack_needs_the_covert_payload(self):
        # With a wrong covert key on the receiving side the colluder decodes nothing and
        # does not act: the attack is caused by the channel, not by shared code.
        for recipe, receiver in (("setup_desk_key_exfiltrated", "garbler"), ("setup_watcher_key_leaked", "garbler"),
                                 ("setup_transcript_equivocated", "garbler")):
            r = row(recipe, "mutant")
            original = ceremony.init_request

            def init(row_, role, original=original, receiver=receiver):
                request = original(row_, role)
                if role == receiver and request["covert"]:
                    request["covert"] = {"key": "00" * 32}
                return request
            ceremony.init_request = init
            try:
                steps, _, claim = run_setup(r)
            finally:
                ceremony.init_request = original
            self.assertEqual([n["decoded"] for n in notes(steps, "covert_receive", receiver)], [False], recipe)
            self.assertEqual(claim["steps"], [], recipe)


class ProcessTests(unittest.TestCase):
    def test_processes_produce_the_in_process_traffic(self):
        r = row("setup_transcript_equivocated", "mutant")
        expected, _, _ = run_setup(r, presign=False)
        hosts = {role: "local" for role in ceremony.ROLES}
        hosts["garbler"] = "zip"            # imports the shipped package archive, as a remote host does
        parties, identities = ceremony.spawn(r, hosts)
        try:
            recorder = ceremony.Recorder()
            recorder.begin(ceremony.keys())
            ceremony.setup_phase(ceremony.Wire(recorder, parties), ceremony.plan_for(r))
        finally:
            for party in parties.values():
                party.close()
        self.assertEqual(recorder.steps, expected)
        self.assertEqual(len({p["pid"] for p in identities.values()}), len(ceremony.ROLES))
        self.assertEqual(identities["garbler"]["host"], "zip")


@unittest.skipUnless(EVIDENCE.exists(), "no committed bitvm3-setup report")
class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.report = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    def reseal(self, report):
        report["evidence_hash"] = digest({k: v for k, v in report.items() if k != "evidence_hash"})
        return report

    def test_committed_report_audits_clean(self):
        self.assertEqual(ceremony.audit(self.report), [])
        self.assertEqual(self.report["summary"]["expectation_failures"], [])
        hosts = {p["host"] for c in self.report["cases"] for p in c["processes"].values()}
        self.assertIn("wsl", hosts)

    def test_audit_detects_a_changed_message(self):
        forged = copy.deepcopy(self.report)
        case = next(c for c in forged["cases"] if c["id"].endswith("setup_cut_and_choose_coordinated.mutant.attack"))
        message = next(s for s in case["steps"] if s["label"] == "message" and s["message_kind"] == "commit")
        message["text"] = stego.recanonicalize(message["text"])
        problems = ceremony.audit(self.reseal(forged))
        self.assertTrue(any("differs from the replay" in p for p in problems), problems)

    def test_audit_detects_a_changed_outcome_and_shared_processes(self):
        forged = copy.deepcopy(self.report)
        case = next(c for c in forged["cases"] if c["id"].endswith("setup_desk_key_exfiltrated.mutant.attack"))
        for s in case["steps"]:
            if s["label"] == "rewritten claim":
                s["confirmed"] = False
        case["processes"]["desk"] = dict(case["processes"]["garbler"])
        problems = ceremony.audit(self.reseal(forged))
        self.assertTrue(any("outcome does not follow" in p for p in problems))
        self.assertTrue(any("share one process" in p for p in problems))


@unittest.skipUnless(STUDY.exists(), "no committed stego study")
class StudyTests(unittest.TestCase):
    def test_committed_study_shape(self):
        study = json.loads(STUDY.read_text(encoding="utf-8"))
        rows = {(r["regime"], r["channel"], r["payload_bits"]): r for r in study["rows"]}
        for regime in ("canonical", "heterogeneous"):
            self.assertLessEqual(rows[(regime, "honest", 0)]["false_positive_rate_any"], 0.05)
            self.assertEqual(rows[(regime, "salt_keyed", 256)]["decoded"], 1.0)
            self.assertEqual(rows[(regime, "salt_keyed", 256)]["survives_canonical_hub"], 1.0)
            self.assertLessEqual(rows[(regime, "salt_keyed", 256)]["detection_any"], 0.1)
            self.assertGreaterEqual(rows[(regime, "salt_plain", 8)]["detection"]["salt_zero_bytes"], 0.95)
            self.assertEqual(rows[(regime, "case_slots", 64)]["survives_canonical_hub"], 0.0)
        # A session-wide style among heterogeneous clients is caught no more often than honest traffic.
        self.assertLessEqual(rows[("heterogeneous", "style_session", 3)]["detection_any"],
                             rows[("heterogeneous", "honest", 0)]["false_positive_rate_any"])
        self.assertGreaterEqual(rows[("canonical", "style_session", 3)]["detection_any"], 0.8)
        self.assertEqual(study["klepto"]["keys_recovered"], study["klepto"]["signatures"])


@unittest.skipUnless(os.environ.get("BITVM_ARENA_BITCOIND"), "set BITVM_ARENA_BITCOIND to run against Core")
class LiveTests(unittest.TestCase):
    def test_live_recipe_with_processes(self):
        rows = [r for r in ceremony.catalog() if r["recipe"] == "setup_watcher_key_leaked"]
        report = ceremony.execute(Path(os.environ["BITVM_ARENA_BITCOIND"]),
                                  ROOT / "work" / "regtest" / uuid.uuid4().hex, rows)
        self.assertEqual(report["summary"]["expectation_failures"], [])
        problems = [p for p in ceremony.audit(report) if "whole catalog" not in p and "catalog_hash" not in p]
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
