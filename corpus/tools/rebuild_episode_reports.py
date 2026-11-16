"""Re-run every saved example episode on a regtest node and rewrite its report.

Usage: python tools/rebuild_episode_reports.py --bitcoind /path/to/bitcoind
Each row: (report name, attacker script, app, overrides, miner capability).
"""

import argparse
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bitvm_corpus.episode import audit_episode, run_episode  # noqa: E402

EPISODES = [
    ("honest-iob-payout-desk", "honest-iob-payout-desk", "iob-payout-desk", {}, False),
    ("honest-bridge-pegout", "honest-bridge-pegout", "bridge-pegout", {}, False),
    ("honest-lending-liquidation", "honest-lending-liquidation", "lending-liquidation", {}, False),
    ("false-claim-withheld-iob-payout-desk", "false-claim-withheld", "iob-payout-desk", {}, False),
    ("false-claim-withheld-bridge-pegout", "false-claim-withheld", "bridge-pegout", {}, False),
    ("false-claim-lending-liquidation", "false-claim-lending", "lending-liquidation", {}, False),
    ("keypath-sweep-bridge-pegout", "keypath-sweep", "bridge-pegout", {}, False),
    ("keypath-sweep-bridge-pegout-claimant-internal", "keypath-sweep", "bridge-pegout",
     {"claim_internal": "claimant"}, False),
    ("self-disprove-hashlock-iob-payout-desk", "self-disprove-hashlock", "iob-payout-desk",
     {"disprove_mode": "hashlock"}, False),
    ("censor-payout-iob-payout-desk", "censor-payout", "iob-payout-desk", {}, True),
    ("censor-payout-bridge-pegout", "censor-payout", "bridge-pegout", {}, True),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind", type=Path, required=True)
    parser.add_argument("--match", default="")
    args = parser.parse_args()
    examples = ROOT / "examples" / "episodes"
    for name, script, app, overrides, miner in EPISODES:
        if args.match not in name:
            continue
        lines = [line for line in (examples / f"{script}.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        report = run_episode(args.bitcoind, ROOT / "work" / "regtest" / uuid.uuid4().hex, app, overrides, lines,
                             lambda _: None, miner=miner)
        problems = audit_episode(report)
        (examples / "reports" / f"{name}.json").write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n",
                                                          encoding="utf-8", newline="\n")
        outcome = report["outcome"]
        print(f"{name}: attack_success={outcome['attack_success']} honest_claim_paid={outcome['honest_claim_paid']} "
              f"problems={len(problems)}")
        if problems:
            print("  " + "\n  ".join(problems))
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
