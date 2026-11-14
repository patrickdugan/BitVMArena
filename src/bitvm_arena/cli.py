"""Run the shipped offline benchmark and replay its complete evidence."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

from .engine import ArenaSession, replay_trace
from .model import POLICIES
from .scenarios import get_scenario, load_scenarios


def run_scenario(scenario_id: str, profile: str = "strict") -> ArenaSession:
    scenario = get_scenario(scenario_id)
    session = ArenaSession(scenario, profile)
    for action in scenario.benchmark_actions:
        if session.score()["terminal"]:
            break
        session.step(action)
    return session


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def benchmark(output: Path | None = None) -> dict[str, Any]:
    cases = []
    for scenario in load_scenarios():
        profiles = [("strict", scenario.expected_strict_attack)]
        if scenario.calibration_profile != "strict":
            profiles.append((scenario.calibration_profile, scenario.expected_calibration_attack))
        for profile, expected in profiles:
            session = run_scenario(scenario.scenario_id, profile)
            trace = session.export_trace()
            replay_trace(trace, expected_profile=profile, expected_scenario=scenario.scenario_id)
            score = session.score()
            matched = score["attacker_success"] == expected and score["terminal"] and score["funded_target_preserved"]
            case = {"scenario_id": scenario.scenario_id, "category": scenario.category, "profile": profile,
                    "expected_attacker_success": expected, "expectation_met": matched, "replay_verified": True, "score": score}
            cases.append(case)
            if output is not None:
                write_json(output / (scenario.scenario_id + "." + profile + ".json"), trace)
    summary = {
        "schema_version": 1,
        "engine_version": "0.1.0",
        "evidence_level": "synthetic-model",
        "episodes": len(cases),
        "all_expectations_met": all(case["expectation_met"] for case in cases),
        "scope": "Scripted calibration and assumption controls; no empirical model or Bitcoin security rate.",
        "cases": cases,
    }
    if output is not None:
        write_json(output / "summary.json", summary)
    return summary


def cpa_benchmark(source: Path, output: Path | None = None) -> dict[str, Any]:
    from .cpa_backend import CPAReferenceSession, baseline_candidates, replay_trace as replay_cpa

    session = CPAReferenceSession(source)
    checks = []
    for fixture in baseline_candidates():
        receipt = session.step(fixture["candidate"])
        checks.append({"case_id": receipt["case_id"], "verifier_accept": receipt["verifier_accept"],
                       "expected_verifier_accept": fixture["expected_verifier_accept"],
                       "calibration": receipt["calibration"],
                       "expectation_met": receipt["verifier_accept"] == fixture["expected_verifier_accept"]})
    trace = session.export_trace()
    replay_cpa(source, trace, expected_target_digest=session.observe()["funded_target_digest"])
    summary = {"schema": "cpa-reference-benchmark/v1", "source_identity": trace["source_identity"],
               "score": session.score(), "cases": checks, "replay_verified": True,
               "all_expectations_met": all(row["expectation_met"] for row in checks)}
    if output is not None:
        write_json(output / "trace.json", trace)
        write_json(output / "summary.json", summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bitvm-arena")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="List the installed synthetic scenarios")
    run = commands.add_parser("run", help="Execute the scripted baseline for one scenario")
    run.add_argument("scenario")
    run.add_argument("--profile", choices=sorted(POLICIES), default="strict")
    run.add_argument("--output", type=Path)
    bench = commands.add_parser("benchmark", help="Run strict and planted calibration cases")
    bench.add_argument("--output", type=Path)
    replay = commands.add_parser("replay", help="Check a trace by re-executing every action")
    replay.add_argument("trace", type=Path)
    replay.add_argument("--expected-profile", choices=sorted(POLICIES))
    replay.add_argument("--expected-scenario")
    cpa_run = commands.add_parser("cpa-run", help="Execute a published CPA fixture in the pinned reference oracle")
    cpa_run.add_argument("case_id")
    cpa_run.add_argument("--source", type=Path, required=True)
    cpa_run.add_argument("--output", type=Path)
    cpa_bench = commands.add_parser("cpa-benchmark", help="Verify and replay the complete finite CPA fixture catalogue")
    cpa_bench.add_argument("--source", type=Path, required=True)
    cpa_bench.add_argument("--output", type=Path)
    cpa_replay = commands.add_parser("cpa-replay", help="Re-execute CPA evidence against the installed funded fixture")
    cpa_replay.add_argument("trace", type=Path)
    cpa_replay.add_argument("--source", type=Path, required=True)
    cpa_replay.add_argument("--max-attempts", type=int, default=32)
    audit_list = commands.add_parser("cpa-audit-list", help="List records in the pinned native receipt audit")
    audit_list.add_argument("--bundle", type=Path, required=True)
    audit_observe = commands.add_parser("cpa-audit-observe", help="Read one native audit observation")
    audit_observe.add_argument("case_id")
    audit_observe.add_argument("--bundle", type=Path, required=True)
    audit_assess = commands.add_parser("cpa-audit-assess", help="Check a classification against recorded native evidence")
    audit_assess.add_argument("case_id")
    audit_assess.add_argument("--bundle", type=Path, required=True)
    audit_assess.add_argument("--answer", type=Path, required=True)
    audit_assess.add_argument("--output", type=Path)
    audit_replay = commands.add_parser("cpa-audit-replay", help="Recheck an audit trace against a host-selected record")
    audit_replay.add_argument("trace", type=Path)
    audit_replay.add_argument("--bundle", type=Path, required=True)
    audit_replay.add_argument("--expected-case", required=True)
    camp_list = commands.add_parser("cpa-campaign-list", help="List bounded CPA campaign scenarios by split")
    camp_list.add_argument("--split", choices=("dev", "held_out", "all"), default="all")
    camp_bench = commands.add_parser("cpa-campaign-benchmark", help="Run and replay the bounded CPA campaign benchmark")
    camp_bench.add_argument("--source", type=Path, required=True)
    camp_bench.add_argument("--split", choices=("dev", "held_out", "all"), default="all")
    camp_bench.add_argument("--output", type=Path)
    camp_replay = commands.add_parser("cpa-campaign-replay", help="Reconstruct and replay a CPA campaign trace from source bytes")
    camp_replay.add_argument("trace", type=Path)
    camp_replay.add_argument("--source", type=Path, required=True)
    camp_replay.add_argument("--expected-scenario")
    camp_replay.add_argument("--expected-split", choices=("dev", "held_out"))
    camp_replay.add_argument("--max-attempts", type=int)
    args = parser.parse_args(argv)
    try:
        if args.command == "list":
            print(json.dumps([{"id": s.scenario_id, "category": s.category, "title": s.title} for s in load_scenarios()], indent=2))
        elif args.command == "run":
            session = run_scenario(args.scenario, args.profile)
            if args.output:
                write_json(args.output, session.export_trace())
            print(json.dumps(session.score(), indent=2))
        elif args.command == "benchmark":
            summary = benchmark(args.output)
            print(json.dumps(summary, indent=2))
            return 0 if summary["all_expectations_met"] else 1
        elif args.command == "replay":
            if args.trace.stat().st_size > 2_000_000:
                raise ValueError("trace exceeds 2 MB limit")
            session = replay_trace(json.loads(args.trace.read_text()), expected_profile=args.expected_profile, expected_scenario=args.expected_scenario)
            print(json.dumps({"replay_verified": True, "score": session.score()}, indent=2))
        elif args.command == "cpa-benchmark":
            summary = cpa_benchmark(args.source, args.output)
            print(json.dumps(summary, indent=2))
            return 0 if summary["all_expectations_met"] else 1
        elif args.command.startswith("cpa-audit-"):
            from .cpa_native_audit import CPANativeAuditDataset
            dataset = CPANativeAuditDataset(args.bundle)
            if args.command == "cpa-audit-list":
                print(json.dumps({**dataset.summary(), "catalogue": [
                    {"case_id": case_id, "source_name": dataset.observe(case_id)["source_name"]}
                    for case_id in dataset.case_ids()]}, indent=2))
            elif args.command == "cpa-audit-observe":
                print(json.dumps(dataset.observe(args.case_id), indent=2))
            elif args.command == "cpa-audit-assess":
                if args.answer.stat().st_size > 4096:
                    raise ValueError("audit answer exceeds 4 KB limit")
                trace = dataset.export_trace(args.case_id, json.loads(args.answer.read_text()))
                if args.output:
                    write_json(args.output, trace)
                print(json.dumps(trace["assessment"], indent=2))
                return 0 if trace["assessment"]["correct"] else 1
            else:
                if args.trace.stat().st_size > 32_000:
                    raise ValueError("audit trace exceeds 32 KB limit")
                trace = dataset.replay_trace(json.loads(args.trace.read_text()), expected_case_id=args.expected_case)
                print(json.dumps({"replay_verified": True, "assessment": trace["assessment"]}, indent=2))
        elif args.command in ("cpa-campaign-list", "cpa-campaign-benchmark", "cpa-campaign-replay"):
            from .cpa_campaign import (
                CPACampaignSession,
                load_campaign_scenarios,
                replay_campaign_trace,
                run_campaign_benchmark,
            )

            if args.command == "cpa-campaign-list":
                rows = [
                    {
                        "scenario_id": s.scenario_id,
                        "split": s.split,
                        "family": s.family,
                        "program_id": s.program_id,
                        "calibration": s.calibration,
                        "requires_child_completion": s.requires_child_completion,
                        "native_supported": s.native_supported,
                        "required_evidence_gates": list(s.required_evidence_gates),
                        "title": s.title,
                    }
                    for s in load_campaign_scenarios(args.split)
                ]
                print(json.dumps(rows, indent=2))
            elif args.command == "cpa-campaign-benchmark":
                summary = run_campaign_benchmark(args.source, split=args.split, output=args.output)
                print(json.dumps(summary, indent=2))
                return 0 if summary["all_expectations_met"] else 1
            else:
                if args.trace.stat().st_size > 2_000_000:
                    raise ValueError("CPA campaign trace exceeds 2 MB limit")
                loaded = json.loads(args.trace.read_text(encoding="utf-8"))
                scenario_id = args.expected_scenario or loaded.get("scenario_id")
                if not isinstance(scenario_id, str):
                    raise ValueError("CPA campaign trace missing scenario_id")
                max_attempts = args.max_attempts if args.max_attempts is not None else loaded.get("max_attempts", 8)
                expected = CPACampaignSession(args.source, scenario_id, max_attempts=max_attempts)
                session = replay_campaign_trace(
                    args.source,
                    loaded,
                    expected_scenario_id=scenario_id,
                    expected_split=args.expected_split,
                    expected_target_digest=expected.observe()["funded_target_digest"],
                    expected_max_attempts=max_attempts,
                )
                print(json.dumps({"replay_verified": True, "score": session.score()}, indent=2))
        else:
            from .cpa_backend import CPAReferenceSession, replay_trace as replay_cpa
            if args.command == "cpa-run":
                session = CPAReferenceSession(args.source)
                receipt = session.step({"case_id": args.case_id})
                if args.output:
                    write_json(args.output, session.export_trace())
                print(json.dumps(receipt, indent=2))
            else:
                if args.trace.stat().st_size > 2_000_000:
                    raise ValueError("CPA trace exceeds 2 MB limit")
                # Derive the evaluator's expected target from verified source,
                # independent of the submitted trace's claimed target.
                expected = CPAReferenceSession(args.source, max_attempts=args.max_attempts)
                session = replay_cpa(args.source, json.loads(args.trace.read_text()),
                                     expected_target_digest=expected.observe()["funded_target_digest"],
                                     expected_max_attempts=args.max_attempts)
                print(json.dumps({"replay_verified": True, "score": session.score()}, indent=2))
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        parser.exit(2, f"bitvm-arena: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
