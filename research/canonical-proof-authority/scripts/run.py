"""Run the pinned offline CPA study without loading the Arena rebuild."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile

MODULE = Path(__file__).resolve().parents[1]
LOCK = MODULE / 'fixtures/source-lock.json'
SCENARIOS = MODULE / 'scenarios/arena_scenarios.jsonl'
CAMPAIGN_LOCK = MODULE / 'fixtures/campaign-lock.json'
CAMPAIGN_FILES = ('scripts/fixed_target.py', 'scripts/campaign.py', 'tests/test_fixed_target.py')


class VerificationError(ValueError):
    pass


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_path(root: Path, name: str) -> Path:
    parts = PurePosixPath(name)
    if not name or parts.is_absolute() or '..' in parts.parts or '\\' in name:
        raise VerificationError(f'Unsafe relative path: {name}')
    path = root
    for part in parts.parts:
        path = path / part
        if path.is_symlink():
            raise VerificationError(f'Symlink in pinned path: {name}')
    if not path.is_file():
        raise VerificationError(f'Missing pinned file: {name}')
    return path


def read_sources(root: Path, hashes: dict[str, str]) -> dict[str, bytes]:
    result = {}
    for name, expected in hashes.items():
        if re.fullmatch('[0-9a-f]{64}', expected) is None:
            raise VerificationError(f'Invalid SHA256 for {name}')
        data = checked_path(root, name).read_bytes()
        if digest(data) != expected:
            raise VerificationError(f'Source SHA256 mismatch: {name}')
        result[name] = data
    if not result:
        raise VerificationError('Empty source lock')
    return result


def validate_scenarios(path: Path) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    identifiers = set()
    levels = {'planted_model', 'measured_CPA_python', 'proposed_HF_Arena'}
    for row in rows:
        if (row.get('schema') != 'BA-CPA-01/scenario-v1'
                or row.get('fixed_target_required') is not True
                or row.get('network_access') is not False
                or row.get('native_arena_adapter_verified') is not False
                or row.get('evidence_level') not in levels):
            raise VerificationError('Scenario scope or schema mismatch')
        identifier = row.get('id')
        if not isinstance(identifier, str) or not identifier or identifier in identifiers:
            raise VerificationError('Missing or duplicate scenario ID')
        identifiers.add(identifier)
    if len(rows) != 10:
        raise VerificationError('Expected ten scenario families')
    return rows


def verify_outputs(root: Path, hashes: dict[str, str], expected: dict) -> dict:
    for name, sha in hashes.items():
        if digest(checked_path(root, name).read_bytes()) != sha:
            raise VerificationError(f'Evidence SHA256 mismatch: {name}')
    result = json.loads((root / 'results.json').read_text())
    measured = {key: result['enumeration'][key] for key in ('unique_programs', 'semantic_functions')}
    measured.update({key: result['compiler'][key] for key in ('programs_tested', 'input_cases', 'accepted', 'mismatches')})
    measured['mutation_cases'] = len(result['mutations'])
    if measured != expected or not all(row['matches_expectation'] for row in result['mutations']):
        raise VerificationError('Measured results differ from the fixed study')
    return measured


def verify_campaign(root: Path) -> dict:
    lock = json.loads(CAMPAIGN_LOCK.read_text())
    if lock.get('schema') != 'BA-CPA-02/evidence-lock-v1':
        raise VerificationError('Unknown campaign lock')
    for name, expected in lock['outputs'].items():
        if digest(checked_path(root, name).read_bytes()) != expected:
            raise VerificationError(f'Campaign evidence SHA256 mismatch: {name}')
    summary = json.loads((root / 'summary.json').read_text())
    if summary != lock['expected_summary']:
        raise VerificationError('Campaign summary differs from the fixed experiment')
    return summary


def run_stage(snapshot: Path, output: Path, label: str, arguments: list[str], timeout: int) -> None:
    environment = {key: value for key, value in os.environ.items()
                   if key in {'PATH', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'LANG', 'LC_ALL'}}
    with (output / f'{label}.log').open('wb') as log:
        completed = subprocess.run([sys.executable, '-I', '-S', '-B', *arguments],
                                   cwd=snapshot, env=environment, stdout=log,
                                   stderr=subprocess.STDOUT, timeout=timeout, check=False)
    if completed.returncode:
        raise VerificationError(f'{label} failed with exit {completed.returncode}; see {label}.log')


def run(source: Path, output: Path, timeout: int = 120, campaign: bool = False) -> dict:
    if timeout <= 0 or sys.flags.optimize:
        raise VerificationError('Use a positive timeout and run Python without -O')
    lock = json.loads(LOCK.read_text())
    if lock.get('schema') != 'BA-CPA-01/source-lock-v1':
        raise VerificationError('Unknown source-lock schema')
    source = source.resolve(strict=True)
    sources = read_sources(source, lock['files'])
    scenarios = validate_scenarios(SCENARIOS)
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    receipt = {'schema': 'BA-CPA-01/arena-run-v1', 'status': 'running',
               'source_repository': lock['repository'], 'source_commit_pin': lock['commit'],
               'source_verification': 'SHA256 of every copied input; Git metadata is not required',
               'source_sha256': lock['files'], 'runner_sha256': digest(Path(__file__).read_bytes()),
               'lock_sha256': digest(LOCK.read_bytes()), 'scenario_sha256': digest(SCENARIOS.read_bytes()),
               'scenario_families': len(scenarios), 'python_version': sys.version.split()[0],
               'native_node_run': False, 'HF_verifier_run': False,
               'native_arena_adapter_run': False}
    try:
        with tempfile.TemporaryDirectory(prefix='arena-cpa-locked-') as temporary:
            snapshot = Path(temporary)
            for name, data in sources.items():
                destination = snapshot / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
            tests = str(snapshot / 'scripts/tests')
            run_stage(snapshot, output, 'study-tests',
                      ['-m', 'unittest', 'discover', '-s', tests,
                       '-p', 'test_bitvm_authority_enumeration.py', '-v'], timeout)
            run_stage(snapshot, output, 'cpa-tests',
                      ['-m', 'unittest', 'discover', '-s', tests, '-p', 'test_cpa*.py', '-v'], timeout)
            run_stage(snapshot, output, 'enumeration',
                      [str(snapshot / 'scripts/research/bitvm_authority_enumeration.py'),
                       '--bitcoin-rs', str(snapshot), '--out', str(output / 'generated'),
                       '--max-gates', '5', '--sample-limit', '32'], timeout)
            if campaign:
                verify_outputs(output / 'generated', lock['outputs'], lock['expected'])
                campaign_hashes = {}
                for name in CAMPAIGN_FILES:
                    data = checked_path(MODULE, name).read_bytes()
                    destination = snapshot / 'arena_cpa' / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(data)
                    campaign_hashes[name] = digest(data)
                receipt['campaign_source_sha256'] = campaign_hashes
                worker = str(snapshot / 'arena_cpa/scripts/campaign.py')
                run_stage(snapshot, output, 'fixed-target-tests',
                          [worker, '--bitcoin-rs', str(snapshot), '--tests'], timeout)
                run_stage(snapshot, output, 'fixed-target-campaign',
                          [worker, '--bitcoin-rs', str(snapshot),
                           '--corpus', str(output / 'generated/circuits.jsonl'),
                           '--out', str(output / 'campaign')], timeout)
                receipt['campaign'] = verify_campaign(output / 'campaign')
                receipt['campaign_lock_sha256'] = digest(CAMPAIGN_LOCK.read_bytes())
                receipt['campaign_output_sha256'] = json.loads(CAMPAIGN_LOCK.read_text())['outputs']
                text = (output / 'fixed-target-tests.log').read_text()
                if re.search(r'Ran 30 tests? in ', text) is None:
                    raise VerificationError('Unexpected fixed-target test count')
                receipt['fixed_target_tests'] = 30
        receipt['measured'] = verify_outputs(output / 'generated', lock['outputs'], lock['expected'])
        receipt['output_sha256'] = lock['outputs']
        for label, count in (('study-tests', 14), ('cpa-tests', 42)):
            text = (output / f'{label}.log').read_text()
            if re.search(rf'Ran {count} tests? in ', text) is None:
                raise VerificationError(f'Unexpected test count in {label}')
        receipt.update(status='passed', study_tests=14, cpa_tests=42)
    except Exception as error:
        receipt.update(status='failed', error=f'{type(error).__name__}: {error}')
        raise
    finally:
        (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bitcoin-rs', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True, help='New output directory; never overwritten')
    parser.add_argument('--timeout', type=int, default=120, help='Seconds per subprocess')
    parser.add_argument('--campaign', action='store_true', help='Run BA-CPA-02 fixed-target tests and exhaustive corpus')
    args = parser.parse_args()
    try:
        receipt = run(args.bitcoin_rs, args.out, args.timeout, args.campaign)
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f'{error}\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
