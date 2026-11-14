#!/usr/bin/env python3
"""Run the pinned CPA native campaign with Arena receipt checks."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from bitvm_arena.cpa_native import run_native


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="bitcoin-rs CPA checkout or pinned source snapshot")
    parser.add_argument("--binary", type=Path, required=True, help="the pinned Keyless Actions executable")
    parser.add_argument("--output", type=Path, required=True, help="a new output directory")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()
    try:
        receipt = run_native(args.source, args.binary, args.output, args.timeout)
    except (ValueError, OSError) as exc:
        parser.exit(1, f"CPA native run failed: {exc}\n")
    print(json.dumps({"execution_verified": receipt["execution_verified"],
                      "evidence_level": receipt["evidence_level"],
                      "confirmed_transitions": len(receipt["confirmed_transitions"]),
                      "score": receipt["score"]}, indent=2))


if __name__ == "__main__":
    main()
