"""Capture pinned local source and executable, then check fresh regtest candidates."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

MODULE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MODULE / 'scripts'))
from run import checked_path, read_sources

BINARY_SHA256 = 'fe506c638478d173edd267422856b9fb02c8ab424b694b6c81554dce2a48caa6'
DEPENDENCY_COMMIT = '188e2d78fbb623a12a42772120a2aa4e437905c1'
RUNTIME_FILES = ('scripts/research/bitvm_authority_enumeration.py',
                 'scripts/research/canonical_proof_authority.py',
                 'scripts/research/cpa_transition.py',
                 'scripts/research/keyless_checksig_rpc.py',
                 'scripts/research/keyless_state_machine.py',
                 'scripts/tests/test_keyless_state_machine.py')
OWNED_FILES = ('scripts/fixed_target.py', 'scripts/candidate_search.py', 'scripts/native_candidates.py')


def run(source: Path, binary: Path, output: Path, timeout: int = 240) -> dict:
    if not __debug__ or type(timeout) is not int or not 1 <= timeout <= 900:
        raise ValueError('unoptimized Python and a 1..900 second bound are required')
    if os.name != 'posix':
        raise ValueError('this reviewed executable profile requires POSIX')
    source_lock = json.loads((MODULE / 'fixtures/source-lock.json').read_bytes())
    source = source.resolve(strict=True)
    sources = read_sources(source, {name: source_lock['files'][name] for name in RUNTIME_FILES})
    owned = {name: checked_path(MODULE, name).read_bytes() for name in OWNED_FILES}
    binary_bytes = binary.read_bytes()
    if sha256(binary_bytes).hexdigest() != BINARY_SHA256:
        raise ValueError('binary differs from reviewed Keyless artifact 14006830303')
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    receipt = {'schema': 'BA-CPA-05/run-v1', 'status': 'running',
               'source_commit_pin': source_lock['commit'], 'native_dependency_commit': DEPENDENCY_COMMIT,
               'source_sha256': {name: sha256(data).hexdigest() for name, data in sources.items()},
               'research_sha256': {name: sha256(data).hexdigest() for name, data in owned.items()},
               'binary_sha256': BINARY_SHA256, 'binary_artifact_id': 14006830303,
               'runner_sha256': sha256(Path(__file__).read_bytes()).hexdigest(),
               'fresh_binary_build': False, 'native_node_run': False,
               'HF_verifier_run': False, 'model_generated_run': False}
    try:
        with tempfile.TemporaryDirectory(prefix='cpa-native-captured-') as tmp:
            root = Path(tmp)
            for name, data in sources.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            for name, data in owned.items():
                path = root / 'arena_cpa' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            executable = root / 'bitcoin-rs'
            executable.write_bytes(binary_bytes)
            executable.chmod(0o500)
            command = [sys.executable, '-I', '-S', '-B', str(root / 'arena_cpa/scripts/native_candidates.py'),
                       '--bitcoin-rs', str(root), '--binary', str(executable), '--out', str(output / 'native')]
            env = {k: v for k, v in os.environ.items() if k in
                   ('PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'LANG', 'LC_ALL')}
            # The dedicated process group contains the worker and its node child.
            with (output / 'worker.log').open('wb') as log:
                process = subprocess.Popen(command, cwd=root, env=env, stdout=log,
                                           stderr=subprocess.STDOUT, start_new_session=True)
                try:
                    code = process.wait(timeout=timeout)
                except BaseException:
                    import signal
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        pass
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=10)
                    raise
            if code:
                raise RuntimeError(f'native worker exited {code}; retained logs and partial records')
            report = json.loads((output / 'native/report.json').read_bytes())
            if (report.get('status') != 'passed' or report.get('binary_sha256') != BINARY_SHA256
                    or report.get('node_exit_codes') != [0, 0]
                    or any(type(code) is not int for code in report.get('node_exit_codes', []))):
                raise ValueError('native run lacks successful source/binary/lifecycle evidence')
            receipt.update(status='passed', native_node_run=True, summary=report)
    except Exception as error:
        receipt.update(status='failed', error=f'{type(error).__name__}: {error}')
        raise
    finally:
        receipt['output_sha256'] = {str(p.relative_to(output)): sha256(p.read_bytes()).hexdigest()
                                   for p in sorted(output.rglob('*')) if p.is_file() and p.name != 'receipt.json'}
        (output / 'receipt.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    return receipt


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bitcoin-rs', type=Path, required=True)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--timeout', type=int, default=240)
    a = p.parse_args()
    print(json.dumps(run(a.bitcoin_rs, a.binary, a.out, a.timeout), indent=2))


if __name__ == '__main__':
    main()
