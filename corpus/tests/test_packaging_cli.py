import base64
import csv
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import build_backend
from bitvm_corpus import __version__, corpus
from bitvm_corpus.cli import main

ROOT = Path(__file__).resolve().parents[1]


class PackagingCliTests(unittest.TestCase):
    def test_cli_filter_and_invalid_id(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(["list", "--family", "rule_execution"]), 0)
        self.assertEqual(len(json.loads(out.getvalue())), 4)
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["replay", "missing"]), 2)

    def test_agent_export_does_not_include_evaluator_fields(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(main(["export", "--family", "rule_execution"]), 0)
        rows = json.loads(out.getvalue())
        for row in rows:
            self.assertEqual(set(row), {"sample", "main_task", "observation"})
            for forbidden in ("defect", "expect", "variant", "side_task", "steps"):
                self.assertNotIn(forbidden, row["observation"])

    def test_reproducible_installable_wheel_and_shipped_data(self):
        scratch = ROOT / "work"
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as folder:
            wheel = Path(folder) / build_backend.build_wheel(folder)
            original = wheel.read_bytes()
            self.assertEqual(build_backend.VERSION, __version__)
            build_backend.build_wheel(folder)
            self.assertEqual(original, wheel.read_bytes())
            with zipfile.ZipFile(wheel) as archive:
                record = archive.read(f"{build_backend.DIST}/RECORD").decode()
                for name, checksum, size in csv.reader(io.StringIO(record)):
                    if checksum:
                        data = archive.read(name)
                        expected = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
                        self.assertEqual(checksum, "sha256=" + expected)
                        self.assertEqual(int(size), len(data))
                archive.extractall(Path(folder) / "installed")
            code = ("import sys; sys.path.insert(0, sys.argv[1]); "
                    "from bitvm_corpus.corpus import load; "
                    "assert len(load()) == 168; print('installed-corpus-ok')")
            result = subprocess.run([sys.executable, "-I", "-c", code, str(Path(folder) / "installed")],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("installed-corpus-ok", result.stdout)

    def test_manifest_matches_corpus(self):
        manifest = json.loads((ROOT / "corpus/manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest, corpus.manifest(corpus.load()))
