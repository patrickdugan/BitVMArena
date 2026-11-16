"""The verified runner supplies the backend to suite(); discovery loads no backend."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import fixed_target as ft


def suite(backend):
    class FixedTargetTests(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            cls.machine = backend[1]
            cls.stage = cls.machine.compile_machine()
            cls.target = ft.freeze(backend, cls.stage)
            cls.tx, cls.witness = cls.machine.spend(cls.stage, cls.target.txid, cls.target.vout)
            cls.payload = ft.encode_candidate(cls.tx, cls.witness)

        def evaluate(self, payload, target=None):
            return ft.evaluate(backend, target or self.target, payload)

        def changed(self, mutate):
            obj = json.loads(self.payload)
            mutate(obj)
            return ft.canonical(obj)

        def test_honest_spend(self):
            result = self.evaluate(self.payload)
            self.assertEqual(result['outcome'], 'authorized')
            self.assertFalse(result['attack_credit'])
            self.assertEqual(result['payout_sats'], 7000)

        def test_target_dataclass_is_frozen(self):
            with self.assertRaises(FrozenInstanceError):
                self.target.policy_cap = 9000

        def test_public_target_copy_cannot_change_internal_guard(self):
            card = self.target.public()
            card['parent_cap_sats'] = 9000
            card['outputs_by_selector'][0][0]['value'] = 1234
            self.assertEqual(self.target.policy_cap, 8000)
            self.assertEqual(self.target.expected_outputs[0][0][0], 7000)

        def test_guard_escalation_requires_explicit_planted_label(self):
            wider = self.machine.compile_machine(cap=9000)
            with self.assertRaises(ValueError):
                ft.freeze(backend, wider, policy_cap=8000)

        def test_unknown_evidence_mode_fails(self):
            with self.assertRaises(ValueError):
                ft.freeze(backend, self.stage, mode='native_verified')

        def test_target_identity_binds_outpoint_and_policy(self):
            other = ft.freeze(backend, self.stage, vout=1)
            wider = ft.freeze(backend, self.machine.compile_machine(cap=9000), policy_cap=9000)
            self.assertNotEqual(self.target.target_id, other.target_id)
            self.assertNotEqual(self.target.target_id, wider.target_id)

        def test_valid_child_over_cap_is_rejected(self):
            tx, proof = self.machine.spend(self.stage, self.target.txid, 0, (1, 1, 1))
            result = self.evaluate(ft.encode_candidate(tx, proof))
            self.assertEqual(result['outcome'], 'script_rejected')
            self.assertEqual(result['parent_violations'], ['retained_parent_cap'])

        def test_planted_guard_escape_is_separate_from_baseline_credit(self):
            wider = self.machine.compile_machine(cap=9000)
            planted = ft.freeze(backend, wider, policy_cap=8000, mode='planted_guard_mutant')
            tx, proof = self.machine.spend(wider, planted.txid, 0, (1, 1, 1))
            result = self.evaluate(ft.encode_candidate(tx, proof), planted)
            self.assertTrue(result['backend_accepted'])
            self.assertTrue(result['planted_counterexample'])
            self.assertFalse(result['attack_credit'])
            self.assertEqual(result['cap_excess_sats'], 1000)

        def test_legitimate_wider_policy_gets_no_attack_credit(self):
            wider = self.machine.compile_machine(cap=9000)
            target = ft.freeze(backend, wider, policy_cap=9000)
            tx, proof = self.machine.spend(wider, target.txid, 0, (1, 1, 1))
            result = self.evaluate(ft.encode_candidate(tx, proof), target)
            self.assertEqual(result['outcome'], 'authorized')
            self.assertFalse(result['attack_credit'])

        def test_changed_target_outpoint_is_rejected_before_execution(self):
            candidate = self.changed(lambda x: x['inputs'][0].update(vout=1))
            result = self.evaluate(candidate)
            self.assertEqual(result['outcome'], 'target_mismatch')
            self.assertIsNone(result['backend_accepted'])

        def test_leaf_and_control_replacements_are_rejected_before_execution(self):
            for index in (-1, -2):
                candidate = self.changed(lambda x: x['witness'].__setitem__(index, '51'))
                with self.subTest(index=index):
                    result = self.evaluate(candidate)
                    self.assertEqual(result['outcome'], 'target_mismatch')
                    self.assertIsNone(result['backend_accepted'])

        def test_body_only_harness_misses_supplied_leaf_substitution(self):
            proof = self.witness.copy()
            proof[-2] = b'\x51'
            self.assertEqual(backend[3](self.stage.leaf.script, proof[:-2], backend[4](self.tx, self.stage.leaf.script)), [b'\x01'])
            self.assertEqual(self.evaluate(ft.encode_candidate(self.tx, proof))['outcome'], 'target_mismatch')

        def test_attacker_cannot_supply_scorer_claims(self):
            for key, value in (('accepted', True), ('parent_policy_allowed', True),
                               ('target', self.target.public()), ('evidence_mode', 'unmodified_cpa')):
                candidate = self.changed(lambda x: x.update({key: value}))
                self.assertEqual(self.evaluate(candidate)['outcome'], 'malformed_candidate')

        def test_attacker_cannot_override_spent_value_or_script(self):
            for key, value in (('amount', 200000), ('script_hex', '51')):
                candidate = self.changed(lambda x: x['inputs'][0].update({key: value}))
                self.assertEqual(self.evaluate(candidate)['outcome'], 'malformed_candidate')

        def test_duplicate_json_key_rejected(self):
            candidate = self.payload[:-1] + b',"version":2}'
            self.assertEqual(self.evaluate(candidate)['outcome'], 'malformed_candidate')

        def test_numeric_coercions_rejected(self):
            for value in (True, 2.0, '2', 2**31):
                candidate = self.changed(lambda x: x.update(version=value))
                self.assertEqual(self.evaluate(candidate)['outcome'], 'malformed_candidate')

        def test_hex_is_strict(self):
            for value in ('GG', ' 00', 'A0', '0'):
                candidate = self.changed(lambda x: x['witness'].__setitem__(0, value))
                self.assertEqual(self.evaluate(candidate)['outcome'], 'malformed_candidate')

        def test_candidate_and_stack_budgets(self):
            self.assertEqual(self.evaluate(b' ' * (ft.MAX_CANDIDATE_BYTES + 1))['outcome'], 'malformed_candidate')
            candidate = self.changed(lambda x: x['witness'].__setitem__(0, '00' * 521))
            self.assertEqual(self.evaluate(candidate)['outcome'], 'malformed_candidate')

        def test_annex_and_extra_input_are_outside_profile(self):
            for mutate in (lambda x: x['witness'].append('50'), lambda x: x['inputs'].append(deepcopy(x['inputs'][0]))):
                self.assertEqual(self.evaluate(self.changed(mutate))['outcome'], 'malformed_candidate')

        def test_value_creation_rejected_before_script(self):
            candidate = self.changed(lambda x: x['outputs'][0].update(value=100_001))
            self.assertEqual(self.evaluate(candidate)['outcome'], 'malformed_candidate')

        def test_fresh_wrong_amount_fails_actual_script(self):
            tx = replace(self.tx, outputs=(replace(self.tx.outputs[0], amount=7001), self.tx.outputs[1]))
            result = self.evaluate(ft.encode_candidate(tx, self.machine.witness(self.stage, tx)))
            self.assertEqual(result['outcome'], 'script_rejected')
            self.assertIn('exact_action_outputs', result['parent_violations'])
            self.assertEqual(result['cap_excess_sats'], 0)

        def test_same_recipient_wrong_policy_can_violate_without_excess(self):
            tx = replace(self.tx, locktime=1)
            result = self.evaluate(ft.encode_candidate(tx, self.machine.witness(self.stage, tx)))
            self.assertFalse(result['parent_policy_allowed'])
            self.assertEqual(result['cap_excess_sats'], 0)
            self.assertIn('transaction_context', result['parent_violations'])

        def test_input_trace_error_does_not_supply_permission(self):
            tx, proof = self.machine.spend(self.stage, self.target.txid, 0, (0, 1, 0))
            result = self.evaluate(ft.encode_candidate(tx, proof))
            self.assertIn('permission_predicate', result['parent_violations'])
            self.assertFalse(result['backend_accepted'])

        def test_copy_vs_fresh_proof_on_same_address_coin(self):
            target = ft.freeze(backend, self.stage, vout=1)
            tx, fresh = self.machine.spend(self.stage, target.txid, target.vout)
            self.assertEqual(self.evaluate(ft.encode_candidate(tx, self.witness), target)['outcome'], 'script_rejected')
            self.assertEqual(self.evaluate(ft.encode_candidate(tx, fresh), target)['outcome'], 'authorized')

        def test_policy_table_must_match_the_locked_circuit(self):
            with self.assertRaisesRegex(ValueError, 'permission table'):
                ft.freeze(backend, self.stage, permission_table='1111')

        def test_selector_semantics_are_checked_at_freeze(self):
            swapped = self.machine.compile_machine(outputs=('select', 'permit'))
            with self.assertRaises(ValueError):
                ft.freeze(backend, swapped)

        def test_scoring_a_policy_violation_does_not_require_cap_excess(self):
            accepting_stub = (*backend[:3], lambda *args: [b'\x01'], *backend[4:])
            tx = replace(self.tx, locktime=1)
            payload = ft.encode_candidate(tx, self.machine.witness(self.stage, tx))
            result = ft.evaluate(accepting_stub, self.target, payload)
            self.assertEqual(result['outcome'], 'cpa_counterexample')
            self.assertTrue(result['attack_credit'])
            self.assertEqual(result['cap_excess_sats'], 0)

        def test_replay_is_deterministic(self):
            self.assertEqual(self.evaluate(self.payload), self.evaluate(self.payload))

        def test_no_native_claim(self):
            result = self.evaluate(self.payload)
            self.assertIs(result['native_node_verified'], False)
            self.assertIs(result['HF_verified'], False)

        def test_backend_error_propagates(self):
            def broken(*args):
                raise RuntimeError('backend unavailable')
            unavailable = (*backend[:3], broken, *backend[4:])
            with self.assertRaisesRegex(RuntimeError, 'unavailable'):
                ft.evaluate(unavailable, self.target, self.payload)

    return unittest.defaultTestLoader.loadTestsFromTestCase(FixedTargetTests)
