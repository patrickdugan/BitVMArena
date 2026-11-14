from pathlib import Path
import json
import sys
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(MODULE / 'scripts'))
import run as runner


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data = b'print("fixture")\n'
        (self.root / 'input.py').write_bytes(self.data)
        self.hashes = {'input.py': runner.digest(self.data)}

    def test_valid_source_bytes(self):
        self.assertEqual(runner.read_sources(self.root, self.hashes), {'input.py': self.data})

    def test_changed_source_rejected(self):
        (self.root / 'input.py').write_bytes(b'changed')
        with self.assertRaises(runner.VerificationError):
            runner.read_sources(self.root, self.hashes)

    def test_missing_source_rejected(self):
        (self.root / 'input.py').unlink()
        with self.assertRaises(runner.VerificationError):
            runner.read_sources(self.root, self.hashes)

    def test_empty_lock_rejected(self):
        with self.assertRaises(runner.VerificationError):
            runner.read_sources(self.root, {})

    def test_bad_hash_rejected(self):
        with self.assertRaises(runner.VerificationError):
            runner.read_sources(self.root, {'input.py': 'wrong'})

    def test_path_traversal_rejected(self):
        for name in ('../input.py', '/input.py', 'sub/../../input.py', 'sub\\input.py'):
            with self.subTest(name=name), self.assertRaises(runner.VerificationError):
                runner.checked_path(self.root, name)

    def test_file_symlink_rejected(self):
        (self.root / 'alias.py').symlink_to(self.root / 'input.py')
        with self.assertRaises(runner.VerificationError):
            runner.checked_path(self.root, 'alias.py')

    def test_parent_symlink_rejected(self):
        (self.root / 'nested').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(runner.VerificationError):
            runner.checked_path(self.root, 'nested/input.py')

    def test_catalogue_is_explicitly_offline(self):
        rows = runner.validate_scenarios(runner.SCENARIOS)
        self.assertEqual(len({row['id'] for row in rows}), 10)

    def test_scenario_scope_changes_rejected(self):
        original = [json.loads(line) for line in runner.SCENARIOS.read_text().splitlines()]
        for field, value in (('network_access', True), ('fixed_target_required', False),
                             ('native_arena_adapter_verified', True), ('evidence_level', 'native_verified')):
            rows = [dict(row) for row in original]
            rows[0][field] = value
            path = self.root / 'scenarios.jsonl'
            path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
            with self.subTest(field=field), self.assertRaises(runner.VerificationError):
                runner.validate_scenarios(path)

    def test_duplicate_scenario_rejected(self):
        rows = [json.loads(line) for line in runner.SCENARIOS.read_text().splitlines()]
        rows[-1]['id'] = rows[0]['id']
        path = self.root / 'scenarios.jsonl'
        path.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        with self.assertRaises(runner.VerificationError):
            runner.validate_scenarios(path)

    def test_changed_evidence_rejected(self):
        (self.root / 'results.json').write_bytes(b'changed')
        with self.assertRaises(runner.VerificationError):
            runner.verify_outputs(self.root, {'results.json': runner.digest(b'expected')}, {})

    def test_subprocess_cannot_use_cpa_source_override(self):
        import os
        from unittest.mock import patch
        script = self.root / 'check.py'
        script.write_text('import os,sys\nassert "CPA_SOURCE" not in os.environ\n'
                          'assert sys.flags.isolated and sys.flags.no_site\nassert __debug__\n')
        with patch.dict(os.environ, {'CPA_SOURCE': 'untrusted'}):
            runner.run_stage(self.root, self.root, 'isolation', [str(script)], 10)

    def test_sdk_subprocess_retains_site_but_removes_overrides(self):
        import os
        from unittest.mock import patch
        script = self.root / 'sdk-check.py'
        script.write_text('import os,sys\nassert "CPA_SOURCE" not in os.environ\n'
                          'assert "PYTHONPATH" not in os.environ\n'
                          'assert sys.flags.isolated and not sys.flags.no_site\nassert __debug__\n')
        with patch.dict(os.environ, {'CPA_SOURCE': 'untrusted', 'PYTHONPATH': 'untrusted'}):
            runner.run_stage(self.root, self.root, 'sdk-isolation', [str(script)], 10, sdk=True)

    def test_changed_session_evidence_is_rejected(self):
        (self.root / 'summary.json').write_text('{}')
        with self.assertRaises(runner.VerificationError):
            runner.verify_session(self.root)

    def test_nonzero_subprocess_rejected(self):
        with self.assertRaises(runner.VerificationError):
            runner.run_stage(self.root, self.root, 'failure', ['-c', 'raise SystemExit(7)'], 10)


if __name__ == '__main__':
    unittest.main()
