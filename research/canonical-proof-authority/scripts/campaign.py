"""BA-CPA-02 exhaustive finite-policy scoring, executed by the verified runner."""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import replace
import hashlib
import itertools
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixed_target as ft


def matrix(backend):
    machine, base = backend[1:3]
    stage = machine.compile_machine()
    target = ft.freeze(backend, stage)
    second_target = ft.freeze(backend, stage, vout=1)
    wider = machine.compile_machine(cap=9000)
    wide_target = ft.freeze(backend, wider, policy_cap=9000, vout=2)
    planted = ft.freeze(backend, wider, policy_cap=8000, mode='planted_guard_mutant', vout=3)
    locked_targets = {x.target_id: x for x in (target, second_target, wide_target, planted)}
    targets = {key: value.public() for key, value in locked_targets.items()}
    rows = []

    def add(name, locked, tx, proof, expected):
        payload = ft.encode_candidate(tx, proof)
        result = ft.evaluate(backend, locked, payload)
        if result['outcome'] != expected:
            raise AssertionError(f'{name}: expected {expected}, observed {result}')
        rows.append({'schema': 'BA-CPA-02/episode-v1', 'case_id': name, 'target_id': locked.target_id,
                     'candidate': json.loads(payload), 'expected_outcome': expected, 'result': result})

    for bits in itertools.product((0, 1), repeat=3):
        tx, proof = machine.spend(stage, target.txid, target.vout, bits)
        add('base_bits_' + ''.join(map(str, bits)), target, tx, proof,
            'authorized' if bits == (1, 1, 0) else 'script_rejected')
    tx, proof = machine.spend(stage, target.txid, target.vout)
    for offset, name in enumerate(machine.FIELDS):
        changed = proof.copy()
        changed[offset] = bytes(len(changed[offset]))
        add('context_' + name, target, tx, changed, 'script_rejected')
    for offset, (key, record) in enumerate(stage.program.records, len(machine.FIELDS)):
        if record[0] == 2:
            changed = proof.copy()
            changed[offset] = b'' if changed[offset] else b'\x01'
            add('gate_' + key.hex(), target, tx, changed, 'script_rejected')
    for name, outputs in (
        ('amount_6999', (replace(tx.outputs[0], amount=6999), tx.outputs[1])),
        ('amount_7001', (replace(tx.outputs[0], amount=7001), tx.outputs[1])),
        ('recipient', (replace(tx.outputs[0], script=b'\x51\x20' + base.RECIPIENTS[1]), tx.outputs[1])),
        ('successor', (tx.outputs[0], replace(tx.outputs[1], script=target.script_pubkey))),
        ('reorder', tx.outputs[::-1]),
        ('extra_output', tx.outputs + (base.Output(0, b'\x6a'),)),
        ('missing_successor', (tx.outputs[0],)),
    ):
        altered = replace(tx, outputs=outputs)
        add(name, target, altered, machine.witness(stage, altered), 'script_rejected')
    for name, altered in (
        ('version', replace(tx, version=1)), ('locktime', replace(tx, locktime=1)),
        ('sequence', replace(tx, inputs=(replace(tx.inputs[0], sequence=0xfffffffe),))),
    ):
        add(name, target, altered, machine.witness(stage, altered), 'script_rejected')
    for index, name in ((-2, 'leaf'), (-1, 'control')):
        changed = proof.copy()
        changed[index] = b'\x51'
        add('substituted_' + name, target, tx, changed, 'target_mismatch')
    other_tx, other_proof = machine.spend(stage, second_target.txid, second_target.vout)
    add('replace_outpoint', target, other_tx, other_proof, 'target_mismatch')
    add('identical_address_stale_proof', second_target, other_tx, proof, 'script_rejected')
    add('identical_address_fresh_proof', second_target, other_tx, other_proof, 'authorized')
    wide_tx, wide_proof = machine.spend(wider, wide_target.txid, wide_target.vout, (1, 1, 1))
    add('legitimate_wider_authority', wide_target, wide_tx, wide_proof, 'authorized')
    replacement, replacement_proof = machine.spend(wider, target.txid, target.vout, (1, 1, 1))
    add('replace_authority_same_outpoint', target, replacement, replacement_proof, 'target_mismatch')
    for bits in itertools.product((0, 1), repeat=3):
        mutant_tx, mutant_proof = machine.spend(wider, planted.txid, planted.vout, bits)
        expected = ('planted_counterexample' if bits == (1, 1, 1) else
                    'authorized' if bits == (1, 1, 0) else 'script_rejected')
        add('planted_bits_' + ''.join(map(str, bits)), planted, mutant_tx, mutant_proof, expected)
    for row in rows:
        repeated = ft.evaluate(backend, locked_targets[row['target_id']], ft.canonical(row['candidate']))
        if repeated != row['result']:
            raise AssertionError('episode replay changed its observed result')
    return targets, rows


def lattice():
    # Each policy is a four-bit subset of the fixed input universe.
    safe = widening = triangle_checks = triangle_failures = 0
    for parent, child in itertools.product(range(16), repeat=2):
        excess = child & (~parent & 15)
        safe += excess == 0
        widening += excess != 0
        if (parent & child) & (~parent & 15):
            raise AssertionError('retained intersection escaped parent')
        for final in range(16):
            direct = (final & (~parent & 15)).bit_count()
            through = excess.bit_count() + (final & (~child & 15)).bit_count()
            triangle_checks += 1
            triangle_failures += direct > through
    if (safe, widening, triangle_checks, triangle_failures) != (81, 175, 4096, 0):
        raise AssertionError('finite lattice invariant failed')
    return {'policies': 16, 'ordered_pairs': 256, 'safe_refinements': safe,
            'strict_widenings_or_incomparable_pairs': widening,
            'directed_triangle_checks': triangle_checks, 'directed_triangle_failures': triangle_failures}


def run(backend, corpus_path: Path, output: Path):
    cpa, machine = backend[:2]
    corpus_bytes = corpus_path.read_bytes()
    expected = '35ccc2601e705bb5a8de0bc383e571d3ca5bc6eac51848f841ef38f26b0b4614'
    if hashlib.sha256(corpus_bytes).hexdigest() != expected:
        raise ValueError('enumeration corpus is not the pinned BA-CPA-01 corpus')
    corpus = [json.loads(line) for line in corpus_bytes.splitlines()]
    output.mkdir(parents=True, exist_ok=False)
    totals = Counter()
    by_function = {}
    authority_ids, output_keys = set(), set()
    with (output / 'coverage.jsonl').open('w') as stream:
        for row in corpus:
            nodes = {name: tuple(value) for name, value in row['nodes'].items()}
            stage = machine.compile_machine(nodes, tuple(row['outputs']))
            if stage.program.program_id.hex() != row['program_id']:
                raise ValueError('program identity changed')
            target = ft.freeze(backend, stage, permission_table=row['truth'])
            expected_mask, observed_mask = 0, 0
            for index, bits in enumerate(itertools.product((0, 1), repeat=3)):
                tx, proof = machine.spend(stage, target.txid, target.vout, bits)
                result = ft.evaluate(backend, target, ft.encode_candidate(tx, proof))
                expected_accept = row['truth'][2 * bits[0] + bits[1]] == '1' and bits[2] == 0
                actual = result['backend_accepted']
                if (result['target_bound'] is not True or actual is None
                        or actual != expected_accept or result['parent_policy_allowed'] != expected_accept):
                    (output / 'counterexample.json').write_bytes(ft.canonical({
                        'program': row, 'bits': bits, 'target': target.public(), 'result': result,
                        'candidate': json.loads(ft.encode_candidate(tx, proof))}))
                    raise AssertionError('exhaustive policy/oracle mismatch; see counterexample.json')
                expected_mask |= int(expected_accept) << index
                observed_mask |= int(actual) << index
                totals['cases'] += 1
                totals['accepted'] += actual
                totals['rejected'] += not actual
            totals['programs'] += 1
            authority_ids.add(stage.authority.hex())
            output_keys.add(target.script_pubkey[2:].hex())
            by_function.setdefault(row['truth'], {'programs': 0, 'cases': 0, 'accepted': 0})
            by_function[row['truth']]['programs'] += 1
            by_function[row['truth']]['cases'] += 8
            by_function[row['truth']]['accepted'] += observed_mask.bit_count()
            stream.write(json.dumps({'program_id': row['program_id'], 'target_id': target.target_id,
                                     'authority_id': stage.authority.hex(), 'output_key': target.script_pubkey[2:].hex(),
                                     'script_sha256': hashlib.sha256(stage.leaf.script).hexdigest(),
                                     'permission_table': row['truth'],
                                     'expected_mask': expected_mask, 'observed_mask': observed_mask,
                                     'script_bytes': len(stage.leaf.script)}, sort_keys=True) + '\n')
    if len(authority_ids) != len(corpus) or len(output_keys) != len(corpus):
        raise AssertionError('distinct canonical programs unexpectedly alias an authority or output key')
    targets, episodes = matrix(backend)
    (output / 'targets.json').write_text(json.dumps(targets, indent=2, sort_keys=True) + '\n')
    with (output / 'episodes.jsonl').open('w') as stream:
        for row in episodes:
            stream.write(json.dumps(row, sort_keys=True) + '\n')
    for row in episodes:
        if row['result']['attack_credit']:
            raise AssertionError('unexpected unmodified CPA counterexample')
    result = {'schema': 'BA-CPA-02/campaign-v1', 'scope': 'single-input root CPA Python Script oracle',
              'coverage': dict(totals), 'acceptance_mismatches': 0,
              'distinct_authority_ids': len(authority_ids), 'distinct_output_keys': len(output_keys),
              'by_permission_function': dict(sorted(by_function.items())),
              'targets': len(targets), 'episodes': len(episodes), 'episode_replays': len(episodes),
              'episode_outcomes': dict(sorted(Counter(row['result']['outcome'] for row in episodes).items())),
              'unmodified_counterexamples': sum(row['result']['attack_credit'] for row in episodes),
              'planted_counterexamples': sum(row['result']['planted_counterexample'] for row in episodes),
              'lattice': lattice(), 'native_node_run': False, 'HF_verifier_run': False,
              'interactive_core_adapter_run': False, 'upstream_corpus_sha256': expected}
    (output / 'summary.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bitcoin-rs', type=Path, required=True)
    parser.add_argument('--corpus', type=Path)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--tests', action='store_true')
    args = parser.parse_args()
    if not __debug__:
        parser.error('optimized Python is unsupported')
    sys.path.insert(0, str(args.bitcoin_rs / 'scripts/research'))
    import bitvm_authority_enumeration as upstream
    backend = upstream.load_backend(args.bitcoin_rs)
    if args.tests:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests'))
        import test_fixed_target
        result = unittest.TextTestRunner(verbosity=2).run(test_fixed_target.suite(backend))
        raise SystemExit(0 if result.wasSuccessful() else 1)
    if args.corpus is None or args.out is None:
        parser.error('--corpus and --out are required for a campaign')
    print(json.dumps(run(backend, args.corpus, args.out), indent=2))


if __name__ == '__main__':
    main()
