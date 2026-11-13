#!/usr/bin/env python3
"""Reproduce BA-CPA-01 using a verified local CPA source checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
UPSTREAM = ROOT / "upstream"
DATA = UPSTREAM / "scripts/tests/data/bitvm-authority-enumeration"


def verified_source_bytes(source: Path) -> dict[str, bytes]:
    """Read and hash the complete pinned dependency list before any execution."""
    provenance = json.loads((DATA / "provenance.json").read_text(encoding="utf-8"))
    result = {}
    for entry in provenance["source_files"]:
        path = Path(entry["path"])
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("dependency path escapes source checkout")
        try:
            data = (source / path).read_bytes()
        except OSError as exc:
            raise ValueError(f"required pinned source is unavailable: {path}") from exc
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"source hash mismatch: {path}")
        result[entry["path"]] = data
    return result


def verify_generated_evidence(output: Path) -> dict[str, str]:
    checked = {}
    for line in (DATA / "evidence.sha256").read_text(encoding="utf-8").splitlines():
        expected, name = line.split()
        data = (output / name).read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise ValueError(f"generated evidence differs from frozen study: {name}")
        checked[name] = actual
    return checked


def replay(source: Path, output: Path, *, timeout_seconds: int = 180) -> dict[str, object]:
    # Import via an explicit package path when invoked as a direct script.
    sys.path.insert(0, str(ROOT.parent.parent))
    from research.authority_enumeration.catalogue import verify_recovered_files

    verify_recovered_files()
    pinned = verified_source_bytes(source.resolve())
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("replay output directory must be empty")
    # Only pinned bytes enter the execution path. Extra checkout modules and
    # stale bytecode cannot shadow the verified source files in this snapshot.
    with tempfile.TemporaryDirectory(prefix="bitvm-arena-cpa-") as temporary:
        snapshot = Path(temporary)
        for name, data in pinned.items():
            destination = snapshot / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        command = [
            sys.executable, "-I", "-S", "-B",
            str(UPSTREAM / "scripts/research/bitvm_authority_enumeration.py"),
            "--bitcoin-rs", str(snapshot), "--out", str(output),
            "--max-gates", "5", "--sample-limit", "32",
        ]
        completed = subprocess.run(
            command, check=True, capture_output=True, text=True,
            timeout=timeout_seconds, cwd=snapshot,
        )
    hashes = verify_generated_evidence(output)
    results = json.loads((output / "results.json").read_text(encoding="utf-8"))
    receipt = {
        "schema": "bitvm-arena/authority-replay/v1",
        "evidence_level": "measured_CPA_python",
        "source_commit": "29ca519031fcd67f467881e16ba73e0eb1211759",
        "study_commit": "24a5593350f42efc8a96047aa9e7e114fa22cb08",
        "verified_dependency_files": len(pinned),
        "generated_evidence_sha256": hashes,
        "compiler": results["compiler"],
        "mutations": len(results["mutations"]),
        "native_consensus_run": False,
        "live_funds": False,
    }
    (output / "replay_receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    (output / "enumeration.log").write_text(completed.stdout + completed.stderr, encoding="utf-8")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoin-rs", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        receipt = replay(args.bitcoin_rs, args.out)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        parser.exit(1, f"authority replay failed: {exc}\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
