#!/usr/bin/env python3
"""Run per-case isolated-regtest execution for eligible CPA campaign scenarios."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from bitvm_arena.cpa_campaign_native import run_native_campaign_cases


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True, help="pinned bitcoin-rs CPA checkout")
    parser.add_argument("--binary", type=Path, required=True, help="pinned bitcoin-rs executable")
    parser.add_argument("--output", type=Path, required=True, help="fresh output directory for report and receipt")
    parser.add_argument("--split", choices=("dev", "held_out", "all"), default="all")
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    try:
        receipt = run_native_campaign_cases(
            args.source,
            args.binary,
            args.output,
            split=args.split,
            timeout=args.timeout,
        )
    except (ValueError, OSError) as exc:
        parser.exit(1, f"CPA campaign native run failed: {exc}\n")
    print(
        json.dumps(
            {
                "execution_verified": receipt["execution_verified"],
                "binary_sha256": receipt["binary_sha256"],
                "provenance_id": receipt["binary_provenance"]["provenance_id"],
                "score": receipt["score"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
