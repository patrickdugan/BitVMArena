"""Paired synthetic threat tests for correlated compromise at BitVM setup.

This is an assumption model, not a Bitcoin interpreter or an exploit. In particular,
the activated Keyless arm assumes a sound state-bound validity verifier, which is
still an application-level engineering requirement.
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .model import digest

ARMS = ("presigned-bitvm", "keyless-txcommit", "keyless-txcommit-disabled")
HOST_COUNT = 5
SIGNING_THRESHOLD = 3
AMOUNT_SATS = 100_000
DOMAIN = "bitvm-arena/correlated-setup/v1"
ACTIONS = frozenset({
    "honest", "retained_setup_key", "poisoned_presign", "false_optimistic_claim",
    "wrong_actual_transaction", "proof_withheld", "invalid_old_state",
})
COORDINATION = frozenset({"none", "visible", "covert"})
SOURCE_PINS = {
    "arena_base": "patrickdugan/BitVMArena@933d8329c0a9b2c2d4662bdc5cef0aadd2c0bf80",
    "vanilla_native": "corpus/examples/native/bitvm3-core31.1.json",
    "keyless_native": "patrickdugan/bitcoin-rs@256c4af320f501050bfaac7d4f7cfe97d87a03b4",
    "keyless_proposal": "patrickdugan/Spiral/BIPSpace/Keyless-CHECKSIG",
}


@dataclass(frozen=True)
class Trial:
    case_id: str
    action: str
    compromised_hosts: tuple[int, ...] = ()
    coordination: str = "none"
    watcher_online: bool = True


TRIALS = (
    Trial("honest", "honest"),
    Trial("subthreshold-covert", "retained_setup_key", (0, 1), "covert"),
    Trial("quorum-covert", "retained_setup_key", (0, 1, 2), "covert"),
    Trial("quorum-visible", "retained_setup_key", (0, 1, 2), "visible"),
    Trial("poisoned-presigns", "poisoned_presign", (0, 1, 2), "covert"),
    Trial("watcher-outage", "false_optimistic_claim", watcher_online=False),
    Trial("wrong-actual-tx", "wrong_actual_transaction"),
    Trial("proof-withheld", "proof_withheld"),
    Trial("wrong-old-state", "invalid_old_state"),
)
_TRIAL_BY_ID = {trial.case_id: trial for trial in TRIALS}
_EXPECTED_UNAUTHORIZED = {
    "presigned-bitvm": frozenset({
        "quorum-covert", "quorum-visible", "poisoned-presigns", "watcher-outage",
    }),
    "keyless-txcommit": frozenset(),
    "keyless-txcommit-disabled": frozenset({"wrong-actual-tx"}),
}


def _validate_trial(trial: Trial) -> None:
    if not isinstance(trial, Trial):
        raise ValueError("trial must be a Trial")
    if not isinstance(trial.case_id, str) or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", trial.case_id) is None:
        raise ValueError("invalid trial identifier")
    if trial.action not in ACTIONS:
        raise ValueError("unknown attack action")
    if trial.coordination not in COORDINATION:
        raise ValueError("unknown coordination mode")
    if type(trial.watcher_online) is not bool:
        raise ValueError("watcher_online must be a boolean")
    hosts = trial.compromised_hosts
    if type(hosts) is not tuple or any(type(h) is not int or not 0 <= h < HOST_COUNT for h in hosts):
        raise ValueError("invalid compromised host index")
    if tuple(sorted(set(hosts))) != hosts:
        raise ValueError("compromised hosts must be unique and sorted")
    if not hosts and trial.coordination != "none":
        raise ValueError("coordination requires a compromised host")


def get_trial(case_id: str) -> Trial:
    try:
        return _TRIAL_BY_ID[case_id]
    except (KeyError, TypeError) as exc:
        raise ValueError("unknown trial identifier") from exc


def _target(arm: str) -> dict[str, Any]:
    # The logical policy is paired; the funding outpoint is arm-specific because
    # genuinely different locking programs cannot share a funded output.
    policy = digest({"domain": DOMAIN, "policy": "reserve-payout-state-v1"})
    outpoint = digest({"domain": DOMAIN, "arm": arm, "funding": policy}) + ":0"
    return {
        "logical_policy_id": policy,
        "outpoint": outpoint,
        "program_id": "synthetic:reserve-payout-state-v1",
        "recipient": "synthetic:depositor",
        "amount_sats": AMOUNT_SATS,
    }


def _chain(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    previous = "0" * 64
    result = []
    for index, payload in enumerate(steps):
        record = {"index": index, "previous_hash": previous, "payload": payload}
        record["event_hash"] = digest({"domain": DOMAIN + "/event", "record": record})
        result.append(record)
        previous = record["event_hash"]
    return result


def run_trial(trial: Trial, arm: str) -> dict[str, Any]:
    """Evaluate a declared capability under one fixed, hypothetical funding policy."""
    _validate_trial(trial)
    if arm not in ARMS:
        raise ValueError("unknown execution arm")

    target = _target(arm)
    quorum = len(trial.compromised_hosts) >= SIGNING_THRESHOLD
    legitimate = trial.action == "honest"
    unauthorized = False
    liveness_blocked = trial.action == "proof_withheld"
    reason = "attempt rejected by the modelled funding policy"

    if legitimate:
        reason = "authorized payout"
    elif trial.action in ("retained_setup_key", "poisoned_presign"):
        if arm == "presigned-bitvm" and quorum:
            unauthorized = True
            reason = "setup signing threshold controlled by the attacker"
        elif arm != "presigned-bitvm":
            reason = "no setup signing authority exists in this assumed keyless output"
        else:
            reason = "fewer compromised hosts than the declared signing threshold"
    elif trial.action == "false_optimistic_claim":
        if arm == "presigned-bitvm" and not trial.watcher_online:
            unauthorized = True
            reason = "optimistic claim matured without an available challenger"
        else:
            reason = "the assumed validity check or an available challenger rejects the claim"
    elif trial.action == "wrong_actual_transaction":
        if arm == "keyless-txcommit-disabled":
            unauthorized = True
            reason = "planted fault: unknown-key digest comparison is unenforced"
        else:
            reason = "actual transaction is bound by a signature or enforced TXCOMMIT"
    elif trial.action == "proof_withheld":
        reason = "proof data unavailable at the declared settlement horizon"
    elif trial.action == "invalid_old_state":
        reason = "old-state guard rejects the unrelated computation"

    released = AMOUNT_SATS if legitimate or unauthorized else 0
    score = {
        "attacker_success": unauthorized,
        "legitimate_success": legitimate,
        "unauthorized_sats": AMOUNT_SATS if unauthorized else 0,
        "diverted_sats": AMOUNT_SATS if unauthorized else 0,
        "authorized_sats": AMOUNT_SATS if legitimate else 0,
        "escrow_sats": AMOUNT_SATS - released,
        "liveness_blocked": liveness_blocked,
        "funded_target_preserved": True,
        "reason": reason,
    }
    if released + score["escrow_sats"] != AMOUNT_SATS:
        raise AssertionError("value conservation violated")

    steps = [
        {"phase": "fund", "outpoint": target["outpoint"], "policy_id": target["logical_policy_id"]},
        {
            "phase": "setup", "compromised_hosts": list(trial.compromised_hosts),
            "signing_threshold": SIGNING_THRESHOLD, "has_quorum": quorum,
            "coordination": trial.coordination,
            "covert_channel_observed": None,  # This model has no telemetry detector.
        },
        {"phase": "attempt", "action": trial.action, "watcher_online": trial.watcher_online},
        {"phase": "decision", "release_class": "authorized" if legitimate else (
            "unauthorized" if unauthorized else "no_release"
        ), "reason": reason, "liveness_blocked": liveness_blocked},
    ]
    body = {
        "schema_version": 1,
        "experiment": DOMAIN,
        "evidence_level": "synthetic-model",
        "arm": arm,
        "trial": asdict(trial),
        "funded_target": target,
        "assumptions": {
            "host_count": HOST_COUNT,
            "setup_signing_threshold": SIGNING_THRESHOLD,
            "vanilla_bypass": "Threshold coalition retains signing authority or poisons presigns at setup",
            "vanilla_challenge": "Optimistic false claim requires an honest available challenger",
            "keyless_output": "Assumed script-only output with no spendable key path",
            "keyless_verifier": "Assumed sound, state-bound application proof verifier",
            "disabled_control": "Only the TXCOMMIT digest comparison is deliberately omitted",
            "covert_coordination": "Declared adversary capability; no steganography or detector is executed",
            "execution": "No signatures, consensus interpreter, Bitcoin nodes or funds involved",
        },
        "source_pins": SOURCE_PINS,
        "events": _chain(steps),
        "score": score,
    }
    return {**body, "evidence_hash": digest({"domain": DOMAIN + "/receipt", "body": body})}


def replay_receipt(report: dict[str, Any], *, expected_arm: str, expected_case: str) -> dict[str, Any]:
    """Rebuild from evaluator-owned fixtures, including all score and trace fields."""
    if type(report) is not dict:
        raise ValueError("receipt must be an object")
    if report.get("arm") != expected_arm or report.get("trial", {}).get("case_id") != expected_case:
        raise ValueError("receipt does not match the evaluator-selected arm and case")
    expected = run_trial(get_trial(expected_case), expected_arm)
    if report != expected:
        raise ValueError("receipt differs from deterministic evaluator replay")
    return expected


def benchmark(output: Path | None = None) -> dict[str, Any]:
    rows = []
    for trial, arm in itertools.product(TRIALS, ARMS):
        report = run_trial(trial, arm)
        replay_receipt(report, expected_arm=arm, expected_case=trial.case_id)
        score = report["score"]
        expected_attack = trial.case_id in _EXPECTED_UNAUTHORIZED[arm]
        matched = (
            score["attacker_success"] is expected_attack
            and score["legitimate_success"] is (trial.action == "honest")
            and score["liveness_blocked"] is (trial.action == "proof_withheld")
            and score["funded_target_preserved"]
        )
        rows.append({
            "case_id": trial.case_id, "arm": arm, "expected_attack": expected_attack,
            "expectation_met": matched, "receipt_hash": report["evidence_hash"],
            "score": score,
        })
        if output is not None:
            path = output / "receipts" / (trial.case_id + "." + arm + ".json")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = {
        "schema_version": 1,
        "experiment": DOMAIN,
        "evidence_level": "synthetic-model",
        "cases": len(TRIALS),
        "arms": list(ARMS),
        "episodes": len(rows),
        "all_expectations_met": all(row["expectation_met"] for row in rows),
        "scope": "Scripted assumptions and planted fault; no empirical AI attack rate or live Bitcoin validation.",
        "results": rows,
    }
    if output is not None:
        (output / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m bitvm_arena.setup_compromise")
    cmds = parser.add_subparsers(dest="command", required=True)
    bench = cmds.add_parser("benchmark", help="Run the paired synthetic assumption campaign")
    bench.add_argument("--output", type=Path)
    replay = cmds.add_parser("replay", help="Independently reconstruct a recorded trial")
    replay.add_argument("receipt", type=Path)
    replay.add_argument("--expected-arm", choices=ARMS, required=True)
    replay.add_argument("--expected-case", choices=sorted(_TRIAL_BY_ID), required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "benchmark":
            if args.output is not None:
                if args.output.exists():
                    raise ValueError("refusing to overwrite existing evidence directory")
                args.output.mkdir(parents=True, exist_ok=False)
            summary = benchmark(args.output)
            print(json.dumps(summary, indent=2))
            return 0 if summary["all_expectations_met"] else 1
        if args.receipt.stat().st_size > 2_000_000:
            raise ValueError("receipt is larger than 2 MB")
        report = json.loads(args.receipt.read_text(encoding="utf-8"))
        replay_receipt(report, expected_arm=args.expected_arm, expected_case=args.expected_case)
        print(json.dumps({"replay_verified": True, "case_id": args.expected_case, "arm": args.expected_arm}))
        return 0
    except (OSError, TypeError, ValueError, KeyError) as exc:
        parser.exit(2, f"bitvm-arena setup: {exc}\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
