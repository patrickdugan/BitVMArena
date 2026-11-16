"""BA-CPA-05: exact candidate classes for a finite two-edit experiment."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import itertools
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import candidate_search as search
import fixed_target as ft


@dataclass(frozen=True)
class Edit:
    name: str
    payload: bytes

    def value(self) -> dict:
        return json.loads(self.payload)


def alphabet(backend: tuple) -> tuple[Edit, ...]:
    base = backend[2]
    rows = (
        ('payout_7001', {'op': 'output_value', 'index': 0, 'value': 7001}),
        ('payout_7000', {'op': 'output_value', 'index': 0, 'value': 7000}),
        ('version_1', {'op': 'version', 'value': 1}),
        ('version_2', {'op': 'version', 'value': 2}),
        ('other_vout', {'op': 'vout', 'value': 1}),
        ('original_vout', {'op': 'vout', 'value': 0}),
        ('swap_outputs', {'op': 'swap_outputs'}),
        ('other_recipient', {'op': 'output_script', 'index': 0,
                             'hex': (b'\x51\x20' + base.RECIPIENTS[1]).hex()}),
        ('original_recipient', {'op': 'output_script', 'index': 0,
                                'hex': (b'\x51\x20' + base.RECIPIENTS[0]).hex()}),
        ('zero_parent', {'op': 'witness', 'field': 'parent_id', 'hex': '00' * 32}),
        ('invalid_control', {'op': 'control', 'hex': '51'}),
        ('nonminimal_gate', {'op': 'gate', 'index': 0, 'hex': '0100'}),
    )
    return tuple(Edit(name, ft.canonical(value)) for name, value in rows)


def words(size: int) -> tuple[tuple[int, ...], ...]:
    ft.integer(size, 1, 32)
    return ((),) + tuple((i,) for i in range(size)) + tuple(itertools.product(range(size), repeat=2))


def proposal(edits: tuple[Edit, ...], word: tuple[int, ...], bits: tuple[int, ...], refresh: bool) -> bytes:
    return search.proposal(bits, tuple(edits[i].value() for i in word), refresh)


def exact_identity(target_id: str, candidate: bytes) -> tuple[str, bytes]:
    """Full bytes and host target determine classes; hash prefixes never determine equality."""
    if type(target_id) is not str or type(candidate) is not bytes:
        raise TypeError('target string and candidate bytes required')
    return target_id, candidate


def is_cancellation(baseline: bytes, first: bytes, second: bytes, composed: bytes) -> bool:
    return first != baseline and second != baseline and composed == baseline


def signature(result: dict) -> dict:
    names = ('outcome', 'target_bound', 'backend_accepted', 'parent_policy_allowed',
             'parent_violations', 'attack_credit', 'planted_counterexample')
    return {name: result[name] for name in names}


def run(backend: tuple, corpus: Path, output: Path) -> dict:
    cases = search.load_cases(corpus)
    selected = search.select_cases(cases, 'train') + search.select_cases(cases, 'holdout')
    edits = alphabet(backend)
    edit_words = words(len(edits))
    assignment_order = tuple(itertools.product((0, 1), repeat=3))
    refresh_order = (False, True)
    output.mkdir(parents=True, exist_ok=False)
    spec = {'schema': 'BA-CPA-05/grammar-v1', 'alphabet': [
        {'name': edit.name, 'edit': edit.value()} for edit in edits],
        'words': [list(word) for word in edit_words],
        'assignments': [list(bits) for bits in assignment_order],
        'refresh_values': list(refresh_order),
        'member_index': '((assignment_index * 2 + refresh_index) * len(words)) + word_index',
        'corpus_sha256': search.CORPUS_SHA256}
    (output / 'grammar.json').write_bytes(ft.canonical(spec) + b'\n')
    targets, calibrations = {}, []
    totals, raw_outcomes, class_outcomes = Counter(), Counter(), Counter()
    by_split = {'train': Counter(), 'holdout': Counter()}
    with (output / 'classes.jsonl').open('wb') as stream:
        for case in selected:
            target = search.freeze_case(backend, case)
            frozen_card = ft.canonical(target.public())
            targets[target.target_id] = json.loads(frozen_card)
            groups: dict[tuple[str, bytes], dict] = {}
            case_stats = Counter(targets=1)
            for assignment_index, bits in enumerate(assignment_order):
                for refresh_index, refresh in enumerate(refresh_order):
                    realized = {}
                    for word_index, word in enumerate(edit_words):
                        data = proposal(edits, word, bits, refresh)
                        candidate = search.reconstruct(backend, target, data)
                        realized[word] = candidate
                        key = exact_identity(target.target_id, candidate)
                        group = groups.setdefault(key, {'representative': json.loads(data), 'members': []})
                        member = (assignment_index * 2 + refresh_index) * len(edit_words) + word_index
                        group['members'].append(member)
                        case_stats['constructions'] += 1
                        case_stats['proposal_bytes'] += len(data)
                    baseline = realized[()]
                    case_stats['baseline_equivalent_constructions'] += sum(
                        value == baseline for value in realized.values())
                    for left, right in itertools.product(range(len(edits)), repeat=2):
                        if is_cancellation(baseline, realized[(left,)], realized[(right,)],
                                           realized[(left, right)]):
                            case_stats['nontrivial_cancellations'] += 1
                    for left, right in itertools.combinations(range(len(edits)), 2):
                        equivalent = realized[(left, right)] == realized[(right, left)]
                        case_stats['commuting_pairs' if equivalent else 'order_dependent_pairs'] += 1
            for (target_id, candidate), group in sorted(groups.items(), key=lambda item: item[0][1]):
                result = ft.evaluate(backend, target, candidate)
                repeated = search.reconstruct(backend, target, ft.canonical(group['representative']))
                if repeated != candidate:
                    raise AssertionError('representative did not reconstruct exact candidate bytes')
                replayed = ft.evaluate(backend, target, repeated)
                if ft.canonical(result) != ft.canonical(replayed):
                    raise AssertionError('candidate class replay changed its result')
                count = len(group['members'])
                case_stats['classes'] += 1
                case_stats['replayed_classes'] += 1
                case_stats['non_singleton_classes'] += count > 1
                case_stats['logical_script_checks'] += result['target_bound'] is True
                case_stats['unauthorized_classes'] += result['attack_credit'] is True
                case_stats['authorized_classes'] += result['outcome'] == 'authorized'
                case_stats['authorized_constructions'] += count * (result['outcome'] == 'authorized')
                raw_outcomes[result['outcome']] += count
                class_outcomes[result['outcome']] += 1
                row = {'schema': 'BA-CPA-05/class-v1', 'program_id': case.program_id,
                       'permission_table': case.truth, 'split': case.split, 'target_id': target_id,
                       'candidate_sha256': sha256(candidate).hexdigest(), 'candidate_bytes': len(candidate),
                       'representative': group['representative'], 'members': group['members'],
                       'result': signature(result)}
                stream.write(ft.canonical(row) + b'\n')
            if ft.canonical(target.public()) != frozen_card:
                raise AssertionError('target changed during enumeration')
            totals.update(case_stats)
            by_split[case.split].update(case_stats)
            if '1' in case.truth:
                index = case.truth.index('1')
                bits = (index // 2, index % 2, 1)
                wider = search.freeze_case(backend, case, calibration=True)
                episode = search.CandidateEpisode(backend, wider, 'BA-CPA-05/calibration/' + case.case_id)
                episode.step(search.proposal(bits), finalize=True)
                score = episode.score()
                replayed = search.replay(backend, wider, 'BA-CPA-05/calibration/' + case.case_id, 16,
                                         episode.export_trace())
                if ft.canonical(replayed) != ft.canonical(score) or not score['planted_control_success']:
                    raise AssertionError('separately funded calibration failed replay')
                if score['unauthorized_completion'] or score['unauthorized_release_sats'] or score['diverted_sats']:
                    raise AssertionError('calibration received original-target credit')
                if wider.target_id == target.target_id:
                    raise AssertionError('calibration target aliases baseline target')
                calibrations.append({'baseline_target_id': target.target_id, 'trace': episode.export_trace()})
    (output / 'targets.json').write_bytes(ft.canonical(targets) + b'\n')
    with (output / 'calibrations.jsonl').open('wb') as stream:
        for row in calibrations:
            stream.write(ft.canonical(row) + b'\n')
    summary = {'schema': 'BA-CPA-05/summary-v1', 'source_pin': '24a5593350f42efc8a96047aa9e7e114fa22cb08',
               'research_base': 'c296a683b5b6b3091200b106864880081be0d971',
               'alphabet_size': len(edits), 'edit_words_per_assignment': len(edit_words),
               'coverage': dict(sorted(totals.items())),
               'by_split': {name: dict(sorted(values.items())) for name, values in by_split.items()},
               'raw_outcomes': dict(sorted(raw_outcomes.items())),
               'class_outcomes': dict(sorted(class_outcomes.items())),
               'saved_duplicate_constructions': totals['constructions'] - totals['classes'],
               'strict_script_checks_including_replays': 2 * totals['logical_script_checks'],
               'calibration_script_checks_including_replays': 2 * len(calibrations),
               'calibrations': len(calibrations), 'calibration_original_target_credit': 0,
               'execution_layer': 'pinned CPA Python Script oracle', 'native_node_run': False,
               'HF_verifier_run': False, 'model_generated_run': False}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bitcoin-rs', type=Path, required=True)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--tests', action='store_true')
    parser.add_argument('--regressions', action='store_true')
    args = parser.parse_args()
    if not __debug__:
        parser.error('optimized Python is unsupported')
    sys.path.insert(0, str(args.bitcoin_rs / 'scripts/research'))
    import bitvm_authority_enumeration as study
    backend = study.load_backend(args.bitcoin_rs)
    if args.regressions:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests'))
        import test_candidate_search, test_session, test_receipt_types
        tests = unittest.TestSuite((test_candidate_search.suite(backend, args.corpus),
                                    test_session.suite(backend),
                                    unittest.defaultTestLoader.loadTestsFromModule(test_receipt_types)))
        result = unittest.TextTestRunner(verbosity=2).run(tests)
        raise SystemExit(not result.wasSuccessful())
    if args.tests:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests'))
        import test_edit_composition
        result = unittest.TextTestRunner(verbosity=2).run(test_edit_composition.suite(backend, args.corpus))
        raise SystemExit(not result.wasSuccessful())
    if args.out is None:
        parser.error('--out is required')
    print(json.dumps(run(backend, args.corpus, args.out), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
