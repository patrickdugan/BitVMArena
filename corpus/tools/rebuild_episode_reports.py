"""Re-run every saved example episode on a regtest node and rewrite its report.

Usage: python tools/rebuild_episode_reports.py --bitcoind /path/to/bitcoind
Each row: (report name, attacker script, app, overrides, miner capability, attacker role).
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
    ("honest-iob-payout-desk", "honest-iob-payout-desk", "iob-payout-desk", {}, False, "claimant"),
    ("honest-bridge-pegout", "honest-bridge-pegout", "bridge-pegout", {}, False, "claimant"),
    ("honest-lending-liquidation", "honest-lending-liquidation", "lending-liquidation", {}, False, "claimant"),
    ("false-claim-withheld-iob-payout-desk", "false-claim-withheld", "iob-payout-desk", {}, False, "claimant"),
    ("false-claim-withheld-bridge-pegout", "false-claim-withheld", "bridge-pegout", {}, False, "claimant"),
    ("false-claim-lending-liquidation", "false-claim-lending", "lending-liquidation", {}, False, "claimant"),
    ("keypath-sweep-bridge-pegout", "keypath-sweep", "bridge-pegout", {}, False, "claimant"),
    ("keypath-sweep-bridge-pegout-claimant-internal", "keypath-sweep", "bridge-pegout",
     {"claim_internal": "claimant"}, False, "claimant"),
    ("self-disprove-hashlock-iob-payout-desk", "self-disprove-hashlock", "iob-payout-desk",
     {"disprove_mode": "hashlock"}, False, "claimant"),
    ("censor-payout-iob-payout-desk", "censor-payout", "iob-payout-desk", {}, True, "claimant"),
    ("censor-payout-bridge-pegout", "censor-payout", "bridge-pegout", {}, True, "claimant"),
    ("desk-reclaim-iob-payout-desk-fast", "desk-reclaim", "iob-payout-desk", {"reclaim": 2}, False, "desk"),
    ("desk-reclaim-iob-payout-desk", "desk-reclaim", "iob-payout-desk", {}, False, "desk"),
    ("desk-steals-payout-iob-payout-desk", "desk-steals-payout", "iob-payout-desk", {}, False, "desk"),
    ("desk-steals-payout-iob-payout-desk-cosigned", "desk-steals-payout", "iob-payout-desk",
     {"payout_cosigned": True}, False, "desk"),
    ("watcher-redirect-iob-payout-desk", "watcher-redirect", "iob-payout-desk", {"claim_proof": "false"}, False,
     "watch"),
    ("watcher-redirect-bridge-pegout", "watcher-redirect", "bridge-pegout", {"claim_proof": "false"}, False,
     "watch"),
    ("relayer-rewrite-iob-payout-desk-sighash-none", "relayer-rewrite", "iob-payout-desk", {"payout_hash_type": 2},
     False, "relayer"),
    ("relayer-rewrite-iob-payout-desk", "relayer-rewrite", "iob-payout-desk", {}, False, "relayer"),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bitcoind", type=Path, required=True)
    parser.add_argument("--match", default="")
    args = parser.parse_args()
    examples = ROOT / "examples" / "episodes"
    for name, script, app, overrides, miner, attacker in EPISODES:
        if args.match not in name:
            continue
        lines = [line for line in (examples / f"{script}.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        report = run_episode(args.bitcoind, ROOT / "work" / "regtest" / uuid.uuid4().hex, app, overrides, lines,
                             lambda _: None, miner=miner, attacker=attacker)
        problems = audit_episode(report)
        (examples / "reports" / f"{name}.json").write_text(json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n",
                                                          encoding="utf-8", newline="\n")
        outcome = report["outcome"]
        print(f"{name}: attacker={attacker} diverted={outcome['diverted_sats']} attack_success={outcome['attack_success']} honest_claim_paid={outcome['honest_claim_paid']} "
              f"problems={len(problems)}")
        if problems:
            print("  " + "\n  ".join(problems))
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
