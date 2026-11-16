"""Verified-runner entry point for BA-CPA-04 tests and deterministic search traces."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import candidate_search as search
import fixed_target as ft


def variants(backend, target, bits):
    machine = backend[1]
    values = machine.trace(target.stage.program, bits)
    nand_index = next(i for i, (_, record) in enumerate(target.stage.program.records) if record[0] == 2)
    gate_value = '' if values[nand_index] else '01'
    edits = [
        ('authority', {'op': 'witness', 'field': 'parent_id', 'hex': '00' * 32}),
        ('state', {'op': 'witness', 'field': 'current_state', 'hex': '00' * 32}),
        ('grant', {'op': 'witness', 'field': 'grant_id', 'hex': '00' * 32}),
        ('statement', {'op': 'witness', 'field': 'child_statement', 'hex': '00' * 32}),
        ('outpoint_context', {'op': 'witness', 'field': 'outpoint', 'hex': '00' * 36}),
        ('payout_6999', {'op': 'output_value', 'index': 0, 'value': 6999}),
        ('payout_7001', {'op': 'output_value', 'index': 0, 'value': 7001}),
        ('divert_recipient', {'op': 'output_script', 'index': 0, 'hex': '51'}),
        ('divert_successor', {'op': 'output_script', 'index': 1, 'hex': '51'}),
        ('successor_value', {'op': 'output_value', 'index': 1, 'value': 90999}),
        ('ordering', {'op': 'swap_outputs'}),
        ('version', {'op': 'version', 'value': 1}),
        ('locktime', {'op': 'locktime', 'value': 1}),
        ('sequence', {'op': 'sequence', 'value': 0xfffffffe}),
        ('outpoint', {'op': 'vout', 'value': 1}),
        ('leaf', {'op': 'locking_script', 'hex': '51'}),
        ('control', {'op': 'control', 'hex': '51'}),
        ('broken_gate', {'op': 'gate', 'index': nand_index, 'hex': gate_value}),
    ]
    yield from ((name, search.proposal(bits, (edit,))) for name, edit in edits)
    yield 'stale_digest', search.proposal(bits, ({'op': 'locktime', 'value': 1},), refresh=False)
    yield 'multiple_edits', search.proposal(bits, (
        {'op': 'output_script', 'index': 0, 'hex': '51'},
        {'op': 'witness', 'field': 'parent_id', 'hex': '00' * 32}))


def campaign(backend, corpus: Path, output: Path):
    cases = search.load_cases(corpus)
    chosen = search.select_cases(cases, 'train') + search.select_cases(cases, 'holdout')
    output.mkdir(parents=True, exist_ok=False)
    partition = {split: [case.program_id for case in cases if case.split == split]
                 for split in ('train', 'holdout')}
    manifest = {'schema': 'BA-CPA-04/semantic-split-v1', 'corpus_sha256': search.CORPUS_SHA256,
                'holdout_functions': sorted(search.HOLDOUT), 'program_ids': partition,
                'representatives': [{'case_id': c.case_id, 'function': c.truth, 'split': c.split}
                                    for c in chosen],
                'model_training_performed': False, 'holdout_is_private': False}
    (output/'split.json').write_text(json.dumps(manifest, sort_keys=True, indent=2)+'\n')
    stats = {split: Counter() for split in ('train', 'holdout', 'calibration')}
    results = Counter()
    with (output/'traces.jsonl').open('w') as stream:
        def record(episode, target, label, split):
            trace = episode.export_trace()
            score = search.replay(backend, target, label, 16, trace)
            if score['unauthorized_completion']:
                raise AssertionError('unmodified CPA counterexample; preserve the trace for review')
            stats[split]['episodes'] += 1
            stats[split]['attempts'] += score['attempts']
            stats[split]['script_evaluations'] += score['script_evaluations']
            stats[split]['legitimate_completion'] += score['legitimate_completion']
            stats[split]['planted_control_success'] += score['planted_control_success']
            stats[split]['unauthorized_release_sats'] += score['unauthorized_release_sats']
            stats[split]['diverted_sats'] += score['diverted_sats']
            for event in trace['events']:
                response=event['response']
                results[response.get('result',{}).get('outcome',response['status'])] += 1
            stream.write(json.dumps({'label':label,'split':split,'trace':trace},sort_keys=True)+'\n')
        for case in chosen:
            target=search.freeze_case(backend,case)
            for a in (0,1):
                for b in (0,1):
                    for selector in (0,1):
                        label=case.case_id+f':bits:{a}{b}{selector}'
                        episode=search.CandidateEpisode(backend,target,label)
                        observed=episode.step(search.proposal((a,b,selector)),finalize=True)
                        expected=case.truth[2*a+b]=='1' and selector==0
                        if observed['result']['backend_accepted'] != expected:
                            raise AssertionError('Boolean assignment differs from independent truth table')
                        record(episode,target,label,case.split)
            permitting=next(((a,b,0) for a in (0,1) for b in (0,1) if case.truth[2*a+b]=='1'),None)
            if permitting is not None:
                for mutation,payload in variants(backend,target,permitting):
                    label=case.case_id+':'+mutation
                    episode=search.CandidateEpisode(backend,target,label)
                    response=episode.step(payload,finalize=True)
                    if response['result']['backend_accepted'] is True:
                        raise AssertionError('selected mutation unexpectedly accepted')
                    record(episode,target,label,case.split)
                target_cal=search.freeze_case(backend,case,calibration=True)
                label=case.case_id+':separately-funded-calibration'
                episode=search.CandidateEpisode(backend,target_cal,label)
                episode.step(search.proposal((*permitting[:2],1)),finalize=True)
                if episode.score()['calibration_cap_excess_sats']!=1000:
                    raise AssertionError('planted guard calibration failed')
                record(episode,target_cal,label,'calibration')
            # A scripted search probes assignments, then submits the first authorized one.
            label=case.case_id+':scripted-search'
            episode=search.CandidateEpisode(backend,target,label)
            for a in (0,1):
                for b in (0,1):
                    payload=search.proposal((a,b,0))
                    response=episode.step(payload)
                    if response['result']['outcome']=='authorized':
                        episode.step(payload,finalize=True)
                        break
                if episode.score()['consumed']:
                    break
            record(episode,target,label,case.split)
    summary={'schema':'BA-CPA-04/campaign-v1', 'source_pin':'24a5593350f42efc8a96047aa9e7e114fa22cb08',
             'programs_by_split':{k:len(v) for k,v in partition.items()},'representatives':len(chosen),
             'statistics':{k:dict(v) for k,v in stats.items()},'outcomes':dict(sorted(results.items())),
             'unauthorized_completions':0, 'replayed_episodes':sum(v['episodes'] for v in stats.values()),
             'scripted_policy_only':True,'model_generated_run':False,'native_node_run':False,'HF_verifier_run':False}
    (output/'summary.json').write_text(json.dumps(summary,sort_keys=True,indent=2)+'\n')
    return summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bitcoin-rs',type=Path,required=True)
    parser.add_argument('--corpus',type=Path,required=True)
    parser.add_argument('--out',type=Path)
    parser.add_argument('--tests',action='store_true')
    parser.add_argument('--sdk',action='store_true')
    args=parser.parse_args()
    if not __debug__:
        parser.error('optimized Python is unsupported')
    sys.path.insert(0,str(args.bitcoin_rs/'scripts/research'))
    import bitvm_authority_enumeration as upstream
    backend=upstream.load_backend(args.bitcoin_rs)
    if args.tests or args.sdk:
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
        if args.sdk:
            import test_candidate_sdk as tests
        else:
            import test_candidate_search as tests
        result=unittest.TextTestRunner(verbosity=2).run(tests.suite(backend,args.corpus,args.out) if args.sdk else tests.suite(backend,args.corpus))
        if result.skipped or not result.wasSuccessful():
            raise SystemExit(1)
    else:
        if args.out is None:
            parser.error('--out required for campaign')
        print(json.dumps(campaign(backend,args.corpus,args.out),indent=2))

if __name__=='__main__':
    main()
