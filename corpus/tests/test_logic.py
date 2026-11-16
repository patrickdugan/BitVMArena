import itertools
import unittest

from bitvm_corpus.canonical import ValidationError
from bitvm_corpus.logic import Rule, closure, script


class BooleanTests(unittest.TestCase):
    def test_exhaustive_binary_gates(self):
        for a, b in itertools.product((False, True), repeat=2):
            witness = ["01" if x else "" for x in (a, b)]
            self.assertEqual(script(["OP_BOOLAND"], witness), a and b)
            self.assertEqual(script(["OP_BOOLOR"], witness), a or b)
            self.assertEqual(script(["OP_BOOLAND", "OP_NOT"], witness), not (a and b))

    def test_exhaustive_conditional(self):
        for selector, a, b in itertools.product((False, True), repeat=3):
            program = ["OP_IF", "OP_1" if a else "OP_0", "OP_ELSE", "OP_1" if b else "OP_0", "OP_ENDIF"]
            self.assertEqual(script(program, ["01" if selector else ""]), a if selector else b)

    def test_nested_inactive_branches_do_not_pop(self):
        program = ["OP_0", "OP_IF", "OP_IF", "OP_DROP", "OP_ELSE", "OP_DROP", "OP_ENDIF", "OP_ELSE", "OP_1", "OP_ENDIF"]
        self.assertTrue(script(program, []))

    def test_minimalif_and_negative_zero(self):
        program = ["OP_IF", "OP_1", "OP_ELSE", "OP_0", "OP_ENDIF"]
        for value in ("02", "80", "0000", "0100"):
            with self.assertRaises(ValidationError):
                script(program, [value])
        self.assertTrue(script(program, ["02"], minimal_if=False))
        self.assertFalse(script(program, ["80"], minimal_if=False))

    def test_fail_closed_and_limits(self):
        for program, witness in [(["OP_CAT"], []), (["OP_BOOLAND"], ["01"]),
                                 (["OP_ELSE"], []), (["OP_IF"], ["01"]),
                                 (["OP_1"], [False]), (["OP_1"], ["00" * 521]),
                                 (["PUSH:xyz"], []), (["OP_1"] * 1001, [])]:
            with self.subTest(program=program[:2], witness=witness[:1]):
                with self.assertRaises(ValidationError):
                    script(program, witness)
        self.assertFalse(script(["OP_1", "OP_1"], []))
        self.assertFalse(script(["OP_0", "OP_VERIFY", "OP_1"], []))


class RuleTests(unittest.TestCase):
    def test_synchronous_closure_and_order_independence(self):
        rules = [Rule(("a", "b"), "c"), Rule(("c",), "d"), Rule(("d",), "c")]
        known, trace = closure({"a", "b"}, rules)
        self.assertEqual(known, {"a", "b", "c", "d"})
        self.assertEqual(trace, [["c"], ["d"]])
        self.assertEqual(closure({"a", "b"}, list(reversed(rules))), (known, trace))

    def test_bound_exhaustion_is_not_partial_success(self):
        with self.assertRaises(ValidationError):
            closure({"a"}, [Rule(("a",), "b"), Rule(("b",), "c")], max_rounds=1)
        self.assertEqual(closure({"a"}, [Rule(("a",), "b")], max_rounds=1)[0], {"a", "b"})

    def test_no_implicit_negation_or_empty_antecedents(self):
        for data in ({"premises": ["!cancelled"], "conclusion": "pay"},
                     {"premises": [], "conclusion": "pay"}):
            with self.assertRaises(ValidationError):
                Rule.from_dict(data)
        with self.assertRaises(ValidationError):
            closure({"!cancelled"}, [])
