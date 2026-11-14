"""Native receipt boundaries with synthetic RPC responses; no daemon starts here."""
from copy import deepcopy
from decimal import Decimal
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import native_candidates as native
import fixed_target as ft
import run_native

TXID = 'aa' * 32
RAW = '010203'
COIN = {'confirmations': 1, 'value': '0.00100000', 'scriptPubKey': {'hex': '5120'}}


class RpcError(RuntimeError):
    def __init__(self, error):
        self.error = error


class Rpc:
    def __init__(self, allowed=True):
        self.allowed, self.spent, self.height = allowed, False, 102
        self.calls = []
        self.confirmed_hex = RAW
        self.block_error = {'code': -25, 'message': 'block-script-verify-flag-failed'}

    def __call__(self, method, params=None):
        self.calls.append(method)
        if method == 'getconnectioncount':
            return 0
        if method == 'getblockcount':
            return self.height
        if method == 'getbestblockhash':
            return str(self.height)
        if method == 'gettxout':
            return None if self.spent else deepcopy(COIN)
        if method == 'testmempoolaccept':
            return [{'txid': TXID, 'allowed': self.allowed,
                     **({} if self.allowed else {'reject-reason': 'script-verify-flag-failed'})}]
        if method == 'sendrawtransaction':
            if not self.allowed:
                raise RpcError({'code': -26, 'message': 'script-verify-flag-failed'})
            return TXID
        if method == 'generateblock':
            raise RpcError(self.block_error)
        if method == 'generatetoaddress':
            self.spent = True
            self.height += 1
            return ['block']
        if method == 'getblock':
            return {'tx': [{'txid': TXID, 'hex': self.confirmed_hex}]}
        raise AssertionError(method)


class NativeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        self.base = SimpleNamespace(satoshis=lambda x: int(Decimal(str(x)) * 100_000_000), RpcError=RpcError)
        self.target = SimpleNamespace(target_id='host-target', txid='43' * 32, vout=0,
                                      stage=SimpleNamespace(amount=100000), script_pubkey=b'\x51\x20')
        self.rpc = Rpc()
        self.backend = (None, None, self.base, None, None, None)
        self.reference = {'target_bound': True, 'backend_accepted': True, 'parent_policy_allowed': True}
        self.tx = SimpleNamespace(serialize=lambda witnesses: (RAW, TXID),
                                  outputs=(SimpleNamespace(amount=7000), SimpleNamespace(amount=91000)))
        self.patches = [patch.object(native.search, 'reconstruct', return_value=b'candidate'),
                        patch.object(native.ft, 'evaluate', side_effect=lambda *args: deepcopy(self.reference)),
                        patch.object(native.ft, 'decode', return_value=(self.tx, []))]
        self.mocks = [p.start() for p in self.patches]
        for p in self.patches:
            self.addCleanup(p.stop)
        self.evaluator = native.NativeTarget(self.backend, self.target, SimpleNamespace(rpc=self.rpc), 'local', self.path)

    def test_admission_requires_exactly_one_matching_transaction(self):
        for value in ([], {}, [{'txid': 'wrong', 'allowed': True}],
                      [{'txid': TXID, 'allowed': True}] * 2):
            with self.subTest(value=value), self.assertRaises(native.EvidenceError):
                native.admission_result(value, TXID)

    def test_admission_verdict_preserves_boolean_type(self):
        for value in (1, 0, 1.0, 'true', None):
            with self.subTest(value=value), self.assertRaises(native.EvidenceError):
                native.admission_result([{'txid': TXID, 'allowed': value}], TXID)

    def test_rejection_requires_a_reason(self):
        for value in (None, '', False):
            with self.assertRaises(native.EvidenceError):
                native.admission_result([{'txid': TXID, 'allowed': False, 'reject-reason': value}], TXID)

    def test_typed_admission_controls(self):
        self.assertTrue(native.admission_result([{'txid': TXID, 'allowed': True}], TXID))
        self.assertFalse(native.admission_result([{'txid': TXID, 'allowed': False, 'reject-reason': 'reason'}], TXID))

    def test_funded_coin_matches_amount_script_and_confirmations(self):
        native.check_coin(self.base, self.target, deepcopy(COIN))
        variants = [None, {**COIN, 'value': '0.00100001'},
                    {**COIN, 'scriptPubKey': {'hex': '51'}},
                    {**COIN, 'confirmations': 0}, {**COIN, 'confirmations': True}]
        for coin in variants:
            with self.subTest(coin=coin), self.assertRaises(native.EvidenceError):
                native.check_coin(self.base, self.target, coin)

    def test_outer_limits_reject_before_candidate_reconstruction(self):
        for payload, finalize in (('text', False), (b'x' * 16385, False), (b'{}', 1)):
            with self.assertRaises(ft.CandidateError):
                self.evaluator.step(payload, finalize=finalize)
        self.mocks[0].assert_not_called()
        self.assertEqual(self.evaluator.events, [])

    def test_invalid_proposal_consumes_budget_without_native_admission(self):
        self.mocks[0].side_effect = ft.CandidateError('malformed')
        event = self.evaluator.step(b'{')
        self.assertEqual(event['outcome'], 'invalid_proposal')
        self.assertEqual(len(self.evaluator.events), 1)
        self.assertNotIn('testmempoolaccept', self.rpc.calls)
        self.assertFalse(event['native_admission_checked'])

    def test_target_replacement_has_no_native_acceptance_claim(self):
        self.reference['target_bound'] = False
        event = self.evaluator.step(b'{}')
        self.assertEqual(event['outcome'], 'host_rejected')
        self.assertFalse(event['native_admission_checked'])
        self.assertNotIn('testmempoolaccept', self.rpc.calls)

    def test_admitted_probe_has_zero_confirmed_value(self):
        event = self.evaluator.step(b'{}')
        self.assertEqual(event['outcome'], 'admission_only')
        self.assertFalse(event['confirmed_this_event'])
        self.assertEqual(event['confirmed_beneficiary_sats'], 0)
        self.assertFalse(self.evaluator.consumed)
        self.assertNotIn('sendrawtransaction', self.rpc.calls)

    def test_rejected_candidate_reaches_broadcast_and_block_checks(self):
        self.rpc.allowed = self.reference['backend_accepted'] = False
        event = self.evaluator.step(b'{}')
        self.assertEqual(event['outcome'], 'native_script_rejected')
        self.assertTrue(event['native_block_checked'])
        self.assertEqual(event['before'], event['after'])
        self.assertIn('sendrawtransaction', self.rpc.calls)
        self.assertIn('generateblock', self.rpc.calls)

    def test_unrelated_block_error_is_not_a_script_rejection(self):
        self.rpc.allowed = self.reference['backend_accepted'] = False
        self.rpc.block_error = {'code': -25, 'message': 'missing input'}
        with self.assertRaisesRegex(native.EvidenceError, 'Script validation'):
            self.evaluator.step(b'{}')
        event = json.loads((self.path / 'event-000.json').read_bytes())
        self.assertFalse(event['native_block_checked'])
        self.assertIn('error', event)

    def test_reference_disagreement_is_retained_and_propagated(self):
        self.reference['backend_accepted'] = False
        with self.assertRaisesRegex(native.EvidenceError, 'mismatch'):
            self.evaluator.step(b'{}')
        event = json.loads((self.path / 'event-000.json').read_bytes())
        self.assertTrue(event['native_allowed'])
        self.assertFalse(event['reference']['backend_accepted'])

    def test_confirmation_requires_exact_transaction_bytes(self):
        self.rpc.confirmed_hex = 'ff'
        with self.assertRaises(native.EvidenceError):
            self.evaluator.step(b'{}', finalize=True)
        event = json.loads((self.path / 'event-000.json').read_bytes())
        self.assertFalse(event['confirmed_this_event'])
        self.assertEqual(event['confirmed_beneficiary_sats'], 0)
        self.assertIn('error', event)

    def test_successful_confirmation_counts_only_beneficiary_payment(self):
        event = self.evaluator.step(b'{}', finalize=True)
        self.assertTrue(event['confirmed_this_event'])
        self.assertEqual(event['confirmed_beneficiary_sats'], 7000)
        self.assertEqual(event['unauthorized_release_sats'], 0)
        self.assertTrue(self.evaluator.consumed)
        self.assertEqual(event['after']['height'], 103)

    def test_policy_violation_retains_distinct_release_and_diversion(self):
        self.reference['parent_policy_allowed'] = False
        self.tx.outputs[0].script = b'wrong'
        self.tx.outputs[1].script = b'successor'
        self.target.expected_outputs = (((7000, b'right'), (91000, b'successor')), )
        event = self.evaluator.step(b'{}', finalize=True)
        self.assertEqual(event['outcome'], 'native_policy_counterexample')
        self.assertEqual(event['unauthorized_release_sats'], 98000)
        self.assertEqual(event['diverted_sats'], 7000)
        self.assertEqual(event['confirmed_beneficiary_sats'], 0)

    def test_finalization_is_terminal_without_more_rpc_calls(self):
        self.evaluator.step(b'{}', finalize=True)
        previous = len(self.rpc.calls)
        with self.assertRaisesRegex(native.EvidenceError, 'consumed'):
            self.evaluator.step(b'{}')
        self.assertEqual(len(self.rpc.calls), previous)

    def test_returned_receipts_do_not_alias_internal_records(self):
        event = self.evaluator.step(b'{}')
        event['native_allowed'] = False
        events = self.evaluator.events
        events[0]['after']['height'] = 500
        self.assertTrue(self.evaluator.events[0]['native_allowed'])
        self.assertEqual(self.evaluator.events[0]['after']['height'], 102)

    def test_attempt_limit_prevents_more_reconstruction(self):
        with patch.object(native, 'MAX_PROPOSALS', 1):
            self.evaluator.step(b'{}')
            with self.assertRaisesRegex(native.EvidenceError, 'budget'):
                self.evaluator.step(b'{}')
        self.assertEqual(self.mocks[0].call_count, 1)

    def test_wrong_binary_is_rejected_before_launch_or_output_creation(self):
        binary = self.path / 'unreviewed-node'
        binary.write_bytes(b'unreviewed executable')
        with patch.object(run_native, 'read_sources', return_value={}), \
                patch.object(run_native.subprocess, 'Popen') as launch:
            with self.assertRaisesRegex(ValueError, 'binary differs'):
                run_native.run(self.path, binary, self.path / 'out')
            launch.assert_not_called()
        self.assertFalse((self.path / 'out').exists())

    def test_timeout_bound_is_strict(self):
        for timeout in (True, 0, -1, 901, 1.5):
            with self.assertRaises(ValueError):
                run_native.run(self.path, self.path / 'missing', self.path / 'out', timeout)


if __name__ == '__main__':
    unittest.main()
