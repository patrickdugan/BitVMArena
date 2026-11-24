"""The `bitvm3-iob` track: the BitVM3 claim graph as IOB would deploy it with every fix.

The `bitvm3` track's hardened profile closes one recipe's flaw per row and leaves the rest of
the graph as built. Here the graph carries every hardened fix at once (`bitvm3.iob_config`),
and each recipe's benign and attack trajectories run against that one design, unchanged. A
row passes when the fixes hold together: no attack succeeds, and an honest claim is paid
wherever the hardened row pays it.
"""

from __future__ import annotations

from copy import deepcopy

from .bitvm3 import IOB_TRACK as TRACK
from .bitvm3 import audit_cases, iob_catalog, keys, run_case, score
from .bitvm3 import FIXTURE
from .core import Regtest
from .track import Session, check_report_envelope, finalize_report


def catalog():
    return iob_catalog()


def execute(binary, directory, rows=None):
    rows = deepcopy(rows or catalog())
    cases = []
    with Regtest(binary, directory) as node:
        node.initialize_wallet()
        provenance = node.provenance
        session = Session(node)
        for row in rows:
            _, steps = run_case(session, row)
            outcome = score(row, steps)
            cases.append({**row, "keys": keys(), "steps": steps, "outcome": outcome,
                          "expectation_met": outcome == row["expected"]})
    return finalize_report(TRACK, provenance, rows, cases)


def audit(report):
    """Offline audit, as for the bitvm3 track, against this track's catalog."""
    rows = catalog()
    problems = check_report_envelope(report, TRACK, rows)
    for case in report.get("cases", []):
        if case.get("id") in {r["id"] for r in rows} and case.get("keys") != keys():
            problems.append(f"{case['id']}: party keys differ from the fixture keys")
    return problems + audit_cases(report.get("cases", []), rows, FIXTURE)
