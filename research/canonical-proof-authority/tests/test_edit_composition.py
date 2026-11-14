"""Metamorphic checks for exact two-edit candidate classes."""
from pathlib import Path
import json
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import candidate_search as search
import edit_composition as composition
import fixed_target as ft


def suite(backend: tuple, corpus: Path):
    class CompositionTests(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            cls.target = ft.freeze(backend, backend[1].compile_machine())
            cls.edits = composition.alphabet(backend)
            cls.ids = {edit.name: i for i, edit in enumerate(cls.edits)}

        def data(self, *names, refresh=True):
            return composition.proposal(self.edits, tuple(self.ids[name] for name in names), (1, 1, 0), refresh)

        def candidate(self, *names, refresh=True):
            return search.reconstruct(backend, self.target, self.data(*names, refresh=refresh))

        def evaluate(self, *names):
            return ft.evaluate(backend, self.target, self.candidate(*names))

        def test_word_count_and_uniqueness(self):
            actual = composition.words(12)
            self.assertEqual(len(actual), 1 + 12 + 12**2)
            self.assertEqual(len(set(actual)), len(actual))
            self.assertEqual(sum(len(word) == 2 for word in actual), 144)

        def test_word_bound_is_typed(self):
            for value in (True, 0, 33, 1.0):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    composition.words(value)

        def test_alphabet_contains_distinct_operations(self):
            self.assertEqual(len(self.edits), 12)
            self.assertEqual(len({edit.name for edit in self.edits}), 12)
            self.assertEqual(len({edit.payload for edit in self.edits}), 12)

        def test_edit_view_is_an_independent_copy(self):
            view = self.edits[0].value()
            view['value'] = 5
            self.assertEqual(self.edits[0].value()['value'], 7001)

        def test_double_swap_restores_exact_candidate(self):
            for refresh in (False, True):
                with self.subTest(refresh=refresh):
                    original = self.candidate(refresh=refresh)
                    once = self.candidate('swap_outputs', refresh=refresh)
                    twice = self.candidate('swap_outputs', 'swap_outputs', refresh=refresh)
                    self.assertNotEqual(original, once)
                    self.assertEqual(original, twice)
                    self.assertTrue(composition.is_cancellation(original, once, once, twice))

        def test_cancellation_success_is_authorized(self):
            result = self.evaluate('swap_outputs', 'swap_outputs')
            self.assertEqual(result['outcome'], 'authorized')
            self.assertFalse(result['attack_credit'])

        def test_last_write_order_is_semantic(self):
            self.assertEqual(self.candidate('version_1', 'version_2'), self.candidate())
            self.assertNotEqual(self.candidate('version_2', 'version_1'), self.candidate())
            self.assertEqual(self.evaluate('version_2', 'version_1')['outcome'], 'script_rejected')

        def test_overwrite_is_idempotent(self):
            self.assertEqual(self.candidate('payout_7001', 'payout_7001'), self.candidate('payout_7001'))

        def test_disjoint_transaction_fields_commute(self):
            self.assertEqual(self.candidate('payout_7001', 'version_1'),
                             self.candidate('version_1', 'payout_7001'))

        def test_swap_and_indexed_update_do_not_commute(self):
            self.assertNotEqual(self.candidate('payout_7001', 'swap_outputs'),
                                self.candidate('swap_outputs', 'payout_7001'))

        def test_constructor_phases_preserve_transaction_witness_order_equivalence(self):
            self.assertEqual(self.candidate('payout_7001', 'zero_parent'),
                             self.candidate('zero_parent', 'payout_7001'))

        def test_refresh_mode_is_part_of_candidate_identity(self):
            self.assertNotEqual(self.candidate('payout_7001', refresh=False),
                                self.candidate('payout_7001', refresh=True))

        def test_exact_class_key_includes_original_target(self):
            raw = self.candidate()
            self.assertNotEqual(composition.exact_identity('target-a', raw),
                                composition.exact_identity('target-b', raw))

        def test_class_equality_uses_full_candidate_bytes(self):
            self.assertNotEqual(composition.exact_identity('target', b'common-prefix-a'),
                                composition.exact_identity('target', b'common-prefix-b'))
            with self.assertRaises(TypeError):
                composition.exact_identity('target', 'text')

        def test_restored_outpoint_remains_the_original_target(self):
            self.assertEqual(self.candidate('other_vout', 'original_vout'), self.candidate())
            self.assertEqual(self.evaluate('original_vout', 'other_vout')['outcome'], 'target_mismatch')

        def test_distinct_locking_path_stays_rejected(self):
            result = self.evaluate('invalid_control', 'version_2')
            self.assertEqual(result['outcome'], 'target_mismatch')
            self.assertIsNone(result['backend_accepted'])

        def test_repeated_equal_candidates_still_consume_two_attempts(self):
            episode = search.CandidateEpisode(backend, self.target, 'composition-cost', 2)
            first = episode.step(self.data())
            second = episode.step(self.data('swap_outputs', 'swap_outputs'))
            self.assertEqual(first['candidate_json'], second['candidate_json'])
            score = episode.score()
            self.assertEqual(score['attempts'], 2)
            self.assertEqual(score['script_evaluations'], 2)
            self.assertEqual(score['candidate_bytes'], 2 * len(first['candidate_json'].encode('ascii')))
            self.assertFalse(score['consumed'])
            self.assertEqual(episode.step(self.data())['status'], 'attempt_limit')

        def test_equivalent_finalize_consumes_one_original_target(self):
            episode = search.CandidateEpisode(backend, self.target, 'composition-finalize')
            episode.step(self.data('swap_outputs', 'swap_outputs'), finalize=True)
            self.assertTrue(episode.score()['legitimate_completion'])
            self.assertFalse(episode.score()['unauthorized_completion'])
            self.assertEqual(episode.step(self.data(), finalize=True)['status'], 'target_consumed')
            self.assertEqual(episode.score()['attempts'], 1)

        def test_target_is_unchanged_after_composed_edits(self):
            original = ft.canonical(self.target.public())
            self.evaluate('other_recipient', 'zero_parent')
            self.assertEqual(ft.canonical(self.target.public()), original)

        def test_semantic_representatives_stay_in_disjoint_splits(self):
            cases = search.load_cases(corpus)
            train = search.select_cases(cases, 'train')
            holdout = search.select_cases(cases, 'holdout')
            self.assertEqual((len(train), len(holdout)), (10, 6))
            self.assertFalse({case.truth for case in train} & {case.truth for case in holdout})

        def test_planted_cap_control_receives_only_calibration_credit(self):
            target = ft.freeze(backend, backend[1].compile_machine(cap=9000),
                               mode='planted_guard_mutant', policy_cap=8000)
            episode = search.CandidateEpisode(backend, target, 'composition-planted')
            edit = {'op': 'swap_outputs'}
            episode.step(search.proposal((1, 1, 1), (edit, edit)), finalize=True)
            score = episode.score()
            self.assertTrue(score['planted_control_success'])
            self.assertEqual(score['calibration_cap_excess_sats'], 1000)
            self.assertFalse(score['unauthorized_completion'])
            self.assertEqual(score['unauthorized_release_sats'], 0)
            self.assertEqual(score['diverted_sats'], 0)
            self.assertNotEqual(target.target_id, self.target.target_id)

    return unittest.defaultTestLoader.loadTestsFromTestCase(CompositionTests)
