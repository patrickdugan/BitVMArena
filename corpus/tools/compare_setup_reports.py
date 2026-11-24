"""Check that two bitvm3-setup reports decided the same, case by case.

    python tools/compare_setup_reports.py REFERENCE.json OTHER.json

Compares outcomes, every transaction's mempool verdict and confirmation, the monitor flags,
the covert-channel summary and the setup traffic before funding (ceremony.verdicts). Txids,
heights, pids and hosts may differ. Exit status 1 on any difference.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bitvm_corpus.ceremony import compare  # noqa: E402


def main(reference, other):
    problems = compare(*(json.loads(Path(p).read_text(encoding="utf-8")) for p in (reference, other)))
    for problem in problems:
        print(problem)
    print(json.dumps({"reference": reference, "other": other, "same": not problems}))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
