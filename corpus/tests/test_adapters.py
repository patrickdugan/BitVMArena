import sys
import unittest

from bitvm_corpus import corpus
from bitvm_corpus.adapters import AdapterError, JsonProcess, audit_transition, checked_observation, external_replay
from bitvm_corpus.engine import Arena
from bitvm_corpus.fixtures import fixtures


class AdapterTests(unittest.TestCase):
    def test_hardened_external_process_uses_independent_scoring(self):
        row = corpus.build_case("recipient_redirect")
        report = external_replay(row, [sys.executable, "-m", "bitvm_corpus", "serve"])
        self.assertFalse(report["attack_success"])

    def test_mutant_external_process_exposes_settlement_corruption(self):
        row = corpus.build_case("recipient_redirect")
        report = external_replay(row, [sys.executable, "-m", "bitvm_corpus", "serve", "--defect", "recipient_redirect"])
        self.assertTrue(report["attack_success"])
        self.assertIn("effect.recipient", report["violations"])

    def test_protocol_error_and_output_bounds(self):
        commands = ["print('not json', flush=True)", "print('x'*2048, flush=True)"]
        for code in commands:
            with self.subTest(code=code), JsonProcess([sys.executable, "-c", code], max_bytes=1024) as backend:
                with self.assertRaises((AdapterError, ValueError)):
                    backend.exchange({"protocol": 1, "op": "reset", "fixture": {}})

    def test_hung_adapter_times_out_and_is_reaped(self):
        with JsonProcess([sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.2) as backend:
            with self.assertRaises(AdapterError):
                backend.exchange({"protocol": 1, "op": "reset"})
            self.assertIsNotNone(backend.process.poll())

    def test_argv_is_not_a_shell_string(self):
        with self.assertRaises(AdapterError):
            JsonProcess("python -m bitvm_corpus serve")

    def test_independent_observation_auditor_covers_every_corruption(self):
        for row in corpus.generate(seeds=(0,)):
            for profile in ("hardened", "mutant"):
                arena = Arena(row["fixture"], [row["defect"]] if profile == "mutant" else [])
                errors = []
                for action in row["steps"]:
                    before = arena.observe()
                    result = arena.act(action)
                    after = arena.observe()
                    checked_observation(after, row["fixture"])
                    errors.extend(audit_transition(before, action, result, after))
                    if errors:
                        break
                with self.subTest(case=row["id"], profile=profile):
                    self.assertEqual(bool(errors), row["expect"][profile]["attack_success"])

    def test_substituted_adapter_evidence_is_not_scored_as_safe(self):
        f = fixtures()
        observation = Arena(f).observe()
        observation["requests"]["request-1"]["payload"]["recipient"] = "mallory"
        with self.assertRaises(AdapterError):
            checked_observation(observation, f)
