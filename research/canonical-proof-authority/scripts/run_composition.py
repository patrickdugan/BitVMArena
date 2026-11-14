"""Capture checked sources and reproduce the finite two-edit campaign offline."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

MODULE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MODULE / 'scripts'))
from run import read_sources, checked_path

PINS = {
    'scripts/fixed_target.py': 'da1275823155260e8573eb0236cdac9d7bc94b57bf2bcf9c43f03193ab5aabc3',
    'scripts/candidate_search.py': '283ad37a50b81fe7e4692b5e4bd7048ce8c97610bbf664273d3b1dae20818055',
}
FILES = tuple(PINS) + ('scripts/edit_composition.py', 'scripts/session.py',
                      'tests/test_edit_composition.py', 'tests/test_candidate_search.py',
                      'tests/test_session.py', 'tests/test_receipt_types.py')


def run(source: Path, corpus: Path, output: Path) -> dict:
    if not __debug__:
        raise ValueError('optimized Python is unsupported')
    lock = json.loads((MODULE / 'fixtures/source-lock.json').read_bytes())
    if lock.get('commit') != '24a5593350f42efc8a96047aa9e7e114fa22cb08':
        raise ValueError('review upstream pin before changing it')
    # The enumeration-only test file is not imported by this campaign.
    hashes = {name: digest for name, digest in lock['files'].items()
              if name != 'scripts/tests/test_bitvm_authority_enumeration.py'}
    upstream = read_sources(source.resolve(strict=True), hashes)
    owned = {name: checked_path(MODULE, name).read_bytes() for name in FILES}
    for name, expected in PINS.items():
        if sha256(owned[name]).hexdigest() != expected:
            raise ValueError(f'review pinned evaluator source before changing {name}')
    corpus_bytes = corpus.read_bytes()
    expected_corpus = lock['outputs']['circuits.jsonl']
    if sha256(corpus_bytes).hexdigest() != expected_corpus:
        raise ValueError('corpus hash mismatch')
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    receipt = {'schema': 'BA-CPA-05/run-v1', 'status': 'running',
               'upstream_commit': lock['commit'], 'upstream_sha256': hashes,
               'research_sha256': {name: sha256(data).hexdigest() for name, data in owned.items()},
               'runner_sha256': sha256(Path(__file__).read_bytes()).hexdigest(),
               'corpus_sha256': expected_corpus, 'native_node_run': False,
               'HF_verifier_run': False, 'model_generated_run': False}
    try:
        with tempfile.TemporaryDirectory(prefix='cpa-composition-') as temporary:
            root = Path(temporary)
            for name, data in list(upstream.items()) + [('arena_cpa/' + n, b) for n, b in owned.items()]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            (root / 'corpus.jsonl').write_bytes(corpus_bytes)
            environment = {k: v for k, v in os.environ.items()
                           if k in ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'LANG', 'LC_ALL')}

            def stage(label, args, count=None):
                with (output / (label + '.log')).open('wb') as log:
                    result = subprocess.run([sys.executable, '-I', '-S', '-B', *args],
                                            cwd=root, env=environment, stdout=log,
                                            stderr=subprocess.STDOUT, timeout=240, check=False)
                if result.returncode:
                    raise RuntimeError(f'{label} failed; inspect {label}.log')
                if count is not None:
                    text = (output / (label + '.log')).read_text()
                    if re.search(rf'Ran {count} tests? in ', text) is None or 'skipped=' in text:
                        raise RuntimeError(f'{label} did not run all expected tests')

            worker = str(root / 'arena_cpa/scripts/edit_composition.py')
            args = [worker, '--bitcoin-rs', str(root), '--corpus', str(root / 'corpus.jsonl')]
            stage('composition-tests', args + ['--tests'], 21)
            stage('existing-reference-tests', args + ['--regressions'], 64)
            stage('upstream-cpa-tests', ['-m', 'unittest', 'discover', '-s', str(root / 'scripts/tests'),
                                        '-p', 'test_cpa*.py', '-v'], 42)
            stage('composition-campaign', args + ['--out', str(output / 'campaign')])
        expected = json.loads((MODULE / 'fixtures/composition-lock.json').read_bytes())
        receipt['output_sha256'] = {path.name: sha256(path.read_bytes()).hexdigest()
                                   for path in sorted((output / 'campaign').iterdir()) if path.is_file()}
        receipt['summary'] = json.loads((output / 'campaign/summary.json').read_bytes())
        if receipt['output_sha256'] != expected['outputs'] or receipt['summary'] != expected['summary']:
            raise ValueError('campaign differs from reviewed evidence')
        receipt.update(status='passed', composition_tests=21, existing_reference_tests=64,
                       upstream_cpa_tests=42, tests_passed=127)
    except Exception as error:
        receipt.update(status='failed', error=f'{type(error).__name__}: {error}')
        raise
    finally:
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bitcoin-rs', type=Path, required=True)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.bitcoin_rs, args.corpus, args.out), indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
