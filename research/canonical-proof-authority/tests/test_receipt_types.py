"""Receipt comparison preserves JSON scalar types; the replayed result owns the verdict."""
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import session


class ReceiptTypeTests(unittest.TestCase):
    def setUp(self):
        self.expected = {'schema': 'BA-CPA-03/trace-v1', 'context_id': 'test-context',
                         'config': {}, 'target': {}, 'actions': [], 'events': [],
                         'score': {'target_consumed': False, 'main_task_success': True, 'calls': 1}}
        replayed = SimpleNamespace(export_trace=lambda: deepcopy(self.expected),
                                   score=lambda: deepcopy(self.expected['score']))
        self.replay = patch.object(session, 'replay', return_value=replayed)
        self.replay.start()
        self.addCleanup(self.replay.stop)

    def verify(self, trace):
        return session.verify_trace((), session.SessionConfig(), trace)

    def test_false_cannot_be_replaced_by_zero(self):
        trace = deepcopy(self.expected)
        trace['score']['target_consumed'] = 0
        with self.assertRaises(ValueError):
            self.verify(trace)

    def test_true_cannot_be_replaced_by_one(self):
        trace = deepcopy(self.expected)
        trace['score']['main_task_success'] = 1
        with self.assertRaises(ValueError):
            self.verify(trace)

    def test_integer_counter_cannot_be_replaced_by_boolean(self):
        trace = deepcopy(self.expected)
        trace['score']['calls'] = True
        with self.assertRaises(ValueError):
            self.verify(trace)

    def test_integer_counter_cannot_be_replaced_by_float(self):
        trace = deepcopy(self.expected)
        trace['score']['calls'] = 1.0
        with self.assertRaises(ValueError):
            self.verify(trace)

    def test_unchanged_typed_receipt_passes(self):
        self.assertEqual(self.verify(deepcopy(self.expected)), self.expected['score'])

    def test_object_key_order_does_not_change_receipt(self):
        trace = dict(reversed(list(deepcopy(self.expected).items())))
        trace['score'] = dict(reversed(list(trace['score'].items())))
        self.assertEqual(self.verify(trace), self.expected['score'])


if __name__ == '__main__':
    unittest.main()
