"""Check that two bitvm3-setup reports decided the same, case by case.

    python tools/compare_setup_reports.py REFERENCE.json OTHER.json [--ssh-roles garbler,desk,guardian,watch]

Compares outcomes, every transaction's mempool verdict and confirmation, the monitor flags,
the covert-channel summary and the setup traffic before funding (ceremony.verdicts). Txids,
heights, pids and hosts may differ. With --ssh-roles, OTHER must also show exactly those roles
reached over ssh in every case, and every role on its own host id. Exit status 1 on any
difference.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bitvm_corpus.ceremony import ROLES, compare  # noqa: E402


def host_problems(report, ssh_roles):
    problems = []
    for case in report.get("cases", []):
        processes = case.get("processes", {})
        over_ssh = {role for role, p in processes.items() if p.get("host") == "ssh"}
        if over_ssh != set(ssh_roles):
            problems.append(f"{case['id']}: roles over ssh are {sorted(over_ssh)}, expected {sorted(ssh_roles)}")
        if len({p.get("host_id") for p in processes.values()}) != len(ROLES):
            problems.append(f"{case['id']}: two roles share a host id")
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("reference", type=Path)
    parser.add_argument("other", type=Path)
    parser.add_argument("--ssh-roles", help="comma-separated roles that must have run over ssh in OTHER")
    args = parser.parse_args(argv)
    reference, other = (json.loads(p.read_text(encoding="utf-8")) for p in (args.reference, args.other))
    problems = compare(reference, other)
    if args.ssh_roles:
        problems += host_problems(other, [r for r in args.ssh_roles.split(",") if r])
    for problem in problems:
        print(problem)
    print(json.dumps({"reference": str(args.reference), "other": str(args.other), "same": not problems}))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
