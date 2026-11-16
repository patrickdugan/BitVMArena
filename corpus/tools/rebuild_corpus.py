"""Rebuild reviewed fixtures and their catalog; never infer expected verdicts."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bitvm_corpus import corpus
from bitvm_corpus.sut import DEFECTS


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


rows = corpus.generate()
write(ROOT / "bitvm_corpus/data/trajectories.json", rows)
write(ROOT / "corpus/manifest.json", corpus.manifest(rows))
write(ROOT / "examples/recipient_redirect.attack.json", corpus.build_case("recipient_redirect"))
write(ROOT / "examples/recipient_redirect.benign.json", corpus.build_case("recipient_redirect", "benign"))
lines = ["# Trajectory catalog", "", "Generated from the reviewed templates in `corpus.py`.", "",
         "Each corruption has a benign and attack trajectory at seeds 0 and 1.",
         "Fixture perturbations are not counted as distinct corruption mechanisms.", "",
         "| Family | Split | Corruption | Objective |", "| --- | --- | --- | --- |"]
for family, defects in corpus.GROUPS.items():
    for defect in defects:
        lines.append(f"| {family} | {corpus.SPLITS[family]} | `{defect}` | {DEFECTS[defect]} |")
lines += ["", "The corpus is synthetic. Names describe intentionally injected model defects,",
          "not vulnerabilities attributed to BitVM, BitVMX, or any deployed DeFi project.", ""]
(ROOT / "docs/CATALOG.md").write_text("\n".join(lines), encoding="utf-8")
print(f"Regenerated {len(rows)} trajectories; manifest {corpus.manifest(rows)['sha256']}")
