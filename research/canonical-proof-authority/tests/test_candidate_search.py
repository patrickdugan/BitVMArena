"""Bounded proposal tests; the verified worker injects the pinned backend."""
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import json
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import candidate_search as search
import fixed_target as ft


def suite(backend, corpus):
    class CandidateTests(unittest.TestCase):
        @classmethod
        def setUpClass(cls):
            cls.stage = backend[1].compile_machine()
            cls.target = ft.freeze(backend, cls.stage)
            cls.cases = search.load_cases(corpus)

        def episode(self, target=None, budget=16, selected_backend=None):
            return search.CandidateEpisode(selected_backend or backend, target or self.target,
                                           'host-owned-unit-test', budget)

        def test_honest_completion(self):
            episode = self.episode()
            response = episode.step(search.proposal(), finalize=True)
            self.assertEqual(response['result']['outcome'], 'authorized')
            self.assertTrue(episode.score()['legitimate_completion'])
            self.assertEqual(episode.score()['unauthorized_release_sats'], 0)

        def test_probe_does_not_release(self):
            episode = self.episode()
            episode.step(search.proposal())
            self.assertFalse(episode.score()['consumed'])
            self.assertFalse(episode.score()['legitimate_completion'])

        def test_semantic_holdout_is_disjoint(self):
            train = {c.truth for c in self.cases if c.split == 'train'}
            holdout = {c.truth for c in self.cases if c.split == 'holdout'}
            self.assertEqual(len(train), 10)
            self.assertEqual(len(holdout), 6)
            self.assertFalse(train & holdout)
            self.assertEqual(len(self.cases), 1851)

        def test_all_structural_variants_keep_their_function_partition(self):
            for case in self.cases:
                self.assertEqual(case.split == 'holdout', case.truth in search.HOLDOUT)
            self.assertEqual(len({c.case_id for c in self.cases}), len(self.cases))

        def test_representatives_cover_every_function(self):
            reps = search.select_cases(self.cases, 'train') + search.select_cases(self.cases, 'holdout')
            self.assertEqual(len(reps), 16)
            self.assertEqual(len({case.truth for case in reps}), 16)

        def test_unknown_split_fails(self):
            with self.assertRaises(ValueError):
                search.select_cases(self.cases, 'all')

        def test_target_graph_substitution_is_rejected(self):
            case = self.cases[0]
            with self.assertRaises(ValueError):
                search.freeze_case(backend, replace(case, program_id='00' * 32))

        def test_fresh_amount_substitution(self):
            episode = self.episode()
            result = episode.step(search.proposal(edits=({'op': 'output_value', 'index': 0, 'value': 7001},)))
            self.assertEqual(result['result']['outcome'], 'script_rejected')
            self.assertIn('exact_action_outputs', result['result']['parent_violations'])
            self.assertFalse(episode.score()['consumed'])

        def test_refresh_reconstructs_actual_modified_digest(self):
            edits = ({'op': 'locktime', 'value': 1},)
            raw = search.reconstruct(backend, self.target, search.proposal(edits=edits))
            tx, witness = ft.decode(backend, self.target, raw)
            expected = backend[4](tx, self.stage.leaf.script)
            self.assertEqual(witness[backend[1].FIELDS.index('public_digest')], expected)
            self.assertEqual(ft.evaluate(backend, self.target, raw)['outcome'], 'script_rejected')

        def test_stale_digest_control_is_different(self):
            edits = ({'op': 'locktime', 'value': 1},)
            stale = search.reconstruct(backend, self.target, search.proposal(edits=edits, refresh=False))
            fresh = search.reconstruct(backend, self.target, search.proposal(edits=edits))
            self.assertNotEqual(stale, fresh)
            for raw in (stale, fresh):
                self.assertFalse(ft.evaluate(backend, self.target, raw)['backend_accepted'])

        def test_witness_edit_is_applied_after_digest_refresh(self):
            payload = search.proposal(edits=({'op': 'witness', 'field': 'public_digest', 'hex': '00' * 32},))
            _, witness = ft.decode(backend, self.target, search.reconstruct(backend, self.target, payload))
            self.assertEqual(witness[4], bytes(32))

        def test_authority_and_context_edits_fail(self):
            for field in sorted(search.EDIT_FIELDS):
                with self.subTest(field=field):
                    result = self.episode().step(search.proposal(edits=(
                        {'op': 'witness', 'field': field, 'hex': '00' * 32},)))
                    self.assertFalse(result['result']['backend_accepted'])

        def test_role_alias_changes_input_trace(self):
            records = self.stage.program.records
            i = next(i for i, (_, r) in enumerate(records) if r == b'\x00' + bytes(4))
            result = self.episode().step(search.proposal(edits=({'op': 'gate', 'index': i, 'hex': ''},)))
            self.assertFalse(result['result']['backend_accepted'])
            self.assertIn('permission_predicate', result['result']['parent_violations'])

        def test_outpoint_and_locking_path_are_fixed(self):
            for edit in ({'op': 'vout', 'value': 2}, {'op': 'locking_script', 'hex': '51'},
                         {'op': 'control', 'hex': '51'}):
                result = self.episode().step(search.proposal(edits=(edit,)))
                self.assertEqual(result['result']['outcome'], 'target_mismatch')
                self.assertIsNone(result['result']['backend_accepted'])

        def test_duplicate_json_rejected_and_charged(self):
            payload = search.proposal()[:-1] + b',"bits":[1,1,0]}'
            episode = self.episode()
            self.assertEqual(episode.step(payload)['status'], 'invalid_proposal')
            self.assertEqual(episode.score()['attempts'], 1)
            self.assertEqual(episode.score()['script_evaluations'], 0)

        def test_malformed_proposals_exhaust_attempts(self):
            episode = self.episode(budget=2)
            for _ in range(2):
                self.assertEqual(episode.step(b'{')['status'], 'invalid_proposal')
            self.assertEqual(episode.step(search.proposal())['status'], 'attempt_limit')
            self.assertEqual(episode.score()['attempts'], 2)

        def test_numeric_coercions_rejected(self):
            for value in (True, 2.0, '2', -1, 2):
                obj = json.loads(search.proposal()); obj['bits'][0] = value
                self.assertEqual(self.episode().step(ft.canonical(obj))['status'], 'invalid_proposal')

        def test_outer_budget_and_type_validation(self):
            episode = self.episode()
            for payload in (b' ' * (search.PROPOSAL_LIMIT + 1), 'text'):
                with self.assertRaises(ft.CandidateError):
                    episode.step(payload)
            with self.assertRaises(ft.CandidateError):
                episode.step(search.proposal(), finalize=1)

        def test_edit_limits_and_unknown_operations(self):
            for edits in (({'op': 'grant_attack_credit'},), ({'op': 'swap_outputs'},) * 9,
                          ({'op': 'gate', 'index': 31, 'hex': '01'},)):
                self.assertEqual(self.episode().step(search.proposal(edits=edits))['status'], 'invalid_proposal')

        def test_evaluator_fields_are_unavailable(self):
            for key in ('target', 'source', 'policy_cap', 'accepted', 'evidence_mode'):
                obj = json.loads(search.proposal());obj[key] = 1
                self.assertEqual(self.episode().step(ft.canonical(obj))['status'], 'invalid_proposal')

        def test_target_card_is_detached(self):
            episode = self.episode(); card = episode.observe()
            card['target']['parent_cap_sats'] = 9000
            card['target']['outputs_by_selector'][0][0]['value'] = 1
            self.assertEqual(episode.observe()['target']['parent_cap_sats'], 8000)
            self.assertEqual(episode.observe()['target']['outputs_by_selector'][0][0]['value'], 7000)

        def test_only_one_finalization(self):
            episode = self.episode();episode.step(search.proposal(), finalize=True)
            score = episode.score()
            self.assertEqual(episode.step(search.proposal(), finalize=True)['status'], 'target_consumed')
            self.assertEqual(episode.score(), score)

        def test_guard_failure_is_explicit_calibration(self):
            wider = backend[1].compile_machine(cap=9000)
            target = ft.freeze(backend, wider, mode='planted_guard_mutant')
            episode = self.episode(target=target)
            episode.step(search.proposal(bits=(1,1,1)), finalize=True)
            score = episode.score()
            self.assertTrue(score['planted_control_success'])
            self.assertEqual(score['calibration_cap_excess_sats'], 1000)
            self.assertEqual(score['calibration_release_sats'], 98000)
            self.assertEqual(score['unauthorized_release_sats'], 0)
            self.assertFalse(score['unauthorized_completion'])

        def test_failed_probe_has_no_economic_effect(self):
            episode = self.episode()
            episode.step(search.proposal(bits=(1,1,1)))
            self.assertFalse(episode.score()['consumed'])
            self.assertEqual(episode.score()['unauthorized_release_sats'], 0)
            self.assertEqual(episode.score()['diverted_sats'], 0)

        def test_effect_metrics_are_separate_under_accepting_unit_stub(self):
            stub = (*backend[:3], lambda *args: [b'\x01'], *backend[4:])
            episode = self.episode(selected_backend=stub)
            episode.step(search.proposal(edits=({'op': 'output_script', 'index': 0, 'hex': '51'},)), finalize=True)
            score = episode.score()
            self.assertFalse(score['legitimate_completion'])
            self.assertTrue(score['unauthorized_completion'])
            self.assertEqual(score['unauthorized_release_sats'], 98000)
            self.assertEqual(score['diverted_sats'], 7000)

        def test_same_destination_context_violation_has_zero_diversion(self):
            stub = (*backend[:3], lambda *args: [b'\x01'], *backend[4:])
            episode = self.episode(selected_backend=stub)
            episode.step(search.proposal(edits=({'op': 'locktime', 'value': 1},)), finalize=True)
            self.assertEqual(episode.score()['diverted_sats'], 0)
            self.assertEqual(episode.score()['unauthorized_release_sats'], 98000)

        def test_replay_recomputes_every_result(self):
            episode = self.episode(); episode.step(b'bad');episode.step(search.proposal(), finalize=True)
            trace = episode.export_trace()
            self.assertEqual(search.replay(backend, self.target, 'host-owned-unit-test', 16, trace), episode.score())
            altered = deepcopy(trace);altered['events'][1]['response']['result']['attack_credit'] = True
            with self.assertRaises(ValueError):
                search.replay(backend, self.target, 'host-owned-unit-test', 16, altered)

        def test_copied_trace_cannot_choose_its_episode(self):
            episode = self.episode();episode.step(search.proposal(), finalize=True)
            with self.assertRaises(ValueError):
                search.replay(backend, self.target, 'different-host-context', 16, episode.export_trace())

        def test_boolean_numeric_trace_alias_rejected(self):
            episode = self.episode();episode.step(search.proposal())
            trace = episode.export_trace();trace['score']['attempts'] = True
            with self.assertRaises(ValueError):
                search.replay(backend, self.target, 'host-owned-unit-test', 16, trace)

        def test_backend_failure_propagates(self):
            def failed(*args):
                raise RuntimeError('unavailable')
            stub = (*backend[:3], failed, *backend[4:])
            with self.assertRaises(RuntimeError):
                self.episode(selected_backend=stub).step(search.proposal())

        def test_foreign_corpus_rejected(self):
            import tempfile
            with tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)/'circuits.jsonl';path.write_text('{}\n')
                with self.assertRaises(ValueError):
                    search.load_cases(path)

        def test_resource_counts_come_from_execution(self):
            episode = self.episode()
            response=episode.step(search.proposal())
            score=episode.score()
            self.assertEqual(score['attempts'], 1)
            self.assertEqual(score['script_evaluations'], 1)
            self.assertEqual(score['candidate_bytes'], len(response['candidate_json'].encode()))
            self.assertIs(score['HF_verified'], False)
            self.assertIs(score['native_node_verified'], False)

    return unittest.defaultTestLoader.loadTestsFromTestCase(CandidateTests)
