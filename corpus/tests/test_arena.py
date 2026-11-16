import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path

from bitvm_corpus import corpus, schema, spec, sut
from bitvm_corpus.canonical import ValidationError, digest, load_json
from bitvm_corpus.engine import Arena
from bitvm_corpus.fixtures import asset_totals, fixtures, quote, request
from bitvm_corpus.runner import replay, verify_transcript


class CorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = corpus.generate()

    def test_every_attack_kills_its_mutant_and_hardened_preserves_safety(self):
        for row in self.rows:
            for profile in ("hardened", "mutant"):
                with self.subTest(case=row["id"], profile=profile):
                    result = replay(row, profile)
                    self.assertEqual(result["outcome"], row["expect"][profile])
                    self.assertTrue(verify_transcript(row, result))
                    if result["outcome"]["attack_success"]:
                        self.assertIsNotNone(result["first_failure_step"])
                        self.assertTrue(result["violations"])

    def test_corpus_regeneration_and_family_splits(self):
        self.assertEqual(corpus.load(), self.rows)
        self.assertEqual(len(self.rows), 168)
        self.assertEqual({r["defect"] for r in self.rows}, set(sut.DEFECTS))
        for family in corpus.GROUPS:
            self.assertEqual(len({r["split"] for r in self.rows if r["family"] == family}), 1)
        for defect in sut.DEFECTS:
            self.assertEqual({r["variant"] for r in self.rows if r["defect"] == defect}, {"benign", "attack"})

    def test_stop_at_first_harm_and_harmless_prefix(self):
        for row in self.rows:
            if row["variant"] != "attack":
                continue
            result = replay(row, "mutant")
            first = result["first_failure_step"]
            self.assertEqual(len(result["events"]), first + 1)
            short = deepcopy(row)
            short["steps"] = short["steps"][:first]
            if short["steps"]:
                self.assertFalse(replay(short, "mutant")["outcome"]["attack_success"])

    def test_repeatability_and_asset_conservation(self):
        for row in self.rows:
            first = replay(row, "hardened")
            self.assertEqual(first, replay(row, "hardened"))
            self.assertEqual(asset_totals(row["fixture"]["state"]), asset_totals(first["final_observation"]["state"]))


class ProtocolTests(unittest.TestCase):
    def test_boundary_arithmetic_and_independent_verifiers(self):
        for kind in ("withdraw", "swap", "borrow", "liquidate"):
            for amount in (0, 1, 999, 100_000, 100_001, 2**31, 2**32 + 1):
                f = fixtures()
                f["requests"]["request-1"] = request(kind, amount)
                if kind == "liquidate":
                    f["quote"] = quote(price=1)
                arena = Arena(f)
                arena.act(corpus.step("propose", request="request-1", claim="c"))
                claim = arena.claims["c"]["claim"]
                reference = spec.violations(f["state"], f["requests"]["request-1"], f["quote"], 100, f["anchor"], claim)
                candidate = sut.verify(f["state"], f["requests"]["request-1"], f["quote"], f["anchor"], claim)
                self.assertEqual(bool(reference), bool(candidate), (kind, amount, reference, candidate))

    def test_timelock_boundary_and_no_stale_concurrent_settlement(self):
        f = fixtures()
        f["requests"]["request-2"] = request(nonce=2)
        arena = Arena(f)
        for n in (1, 2):
            arena.act(corpus.step("propose", request=f"request-{n}", claim=f"c{n}"))
        arena.act(corpus.step("mine", "environment", blocks=5))
        self.assertFalse(arena.act(corpus.step("settle", claim="c1"))["accepted"])
        arena.act(corpus.step("mine", "environment", blocks=1))
        self.assertEqual(arena.act(corpus.step("settle", claim="c1"))["status"], "settled")
        self.assertEqual(arena.act(corpus.step("settle", claim="c2"))["status"], "rejected")

    def test_response_and_timeout_boundary(self):
        arena = Arena(fixtures())
        arena.act(corpus.step("propose", request="request-1", claim="c"))
        arena.act(corpus.step("challenge", "outsider", claim="c"))
        arena.act(corpus.step("mine", "environment", blocks=3))
        self.assertFalse(arena.act(corpus.step("timeout", "watcher", claim="c"))["accepted"])
        self.assertTrue(arena.act(corpus.step("respond", claim="c"))["accepted"])

    def test_reorg_after_claim_is_rechecked(self):
        arena = Arena(fixtures())
        arena.act(corpus.step("propose", request="request-1", claim="c"))
        arena.act(corpus.step("reorg", "environment", anchor="new-canonical-chain"))
        arena.act(corpus.step("mine", "environment", blocks=6))
        self.assertEqual(arena.act(corpus.step("settle", claim="c"))["status"], "rejected")

    def test_fee_reserve_is_finite(self):
        arena = Arena(fixtures())
        arena.act(corpus.step("fee_market", "environment", fee=10_101))
        arena.act(corpus.step("propose", request="request-1", claim="c"))
        self.assertEqual(arena.act(corpus.step("audit", "watcher", claim="c"))["audit"], "unfunded")
        self.assertEqual(arena.fee_reserve, 10_000)

    def test_rejected_action_is_atomic(self):
        arena = Arena(fixtures())
        before = arena.observe()
        result = arena.act(corpus.step("propose", request="request-1", claim="c", override={"effect": []}))
        self.assertFalse(result["accepted"])
        self.assertEqual(arena.observe(), before)
        with self.assertRaises(ValidationError):
            schema.action(corpus.step("settle", "environment", claim="c"))

    def test_schema_rejects_boolean_integers_and_unknown_fields(self):
        for field, value in (("blocks", True), ("blocks", -1), ("blocks", 100_001)):
            with self.assertRaises(ValidationError):
                schema.action(corpus.step("mine", "environment", **{field: value}))
        f = fixtures()
        f["quote"]["payload"]["price"] = 0
        with self.assertRaises(ValidationError):
            schema.fixture(f)
        row = corpus.build_case("and_as_or")
        row["untrusted_extra"] = True
        with self.assertRaises(ValidationError):
            schema.trajectory(row)

    def test_json_duplicate_keys_and_nonfinite_numbers_rejected(self):
        scratch = Path(__file__).resolve().parents[1] / "work"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as folder:
            path = Path(folder) / "bad.json"
            for data in ('{"a":1,"a":2}', '{"x":NaN}'):
                path.write_text(data, encoding="utf-8")
                with self.assertRaises(ValidationError):
                    load_json(path)

    def test_transcript_tampering_and_fixture_substitution(self):
        row = corpus.build_case("and_as_or")
        report = replay(row, "mutant")
        report["events"][0]["result"]["accepted"] = False
        self.assertFalse(verify_transcript(row, report))
        report = replay(row, "mutant")
        report["outcome"]["attack_success"] = False
        self.assertFalse(verify_transcript(row, report))
        other = deepcopy(row)
        other["fixture"]["height"] += 1
        self.assertFalse(verify_transcript(other, replay(row, "mutant")))

    def test_recomputed_prefix_cannot_hide_later_harm(self):
        row = corpus.build_case("recipient_redirect")
        short = deepcopy(row)
        short["steps"] = short["steps"][:1]
        report = replay(short, "mutant")
        report["trajectory_hash"] = digest(row)
        self.assertFalse(verify_transcript(row, report))
        self.assertFalse(verify_transcript(row, {}))
