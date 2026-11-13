"""Run the shipped offline benchmark and replay its complete evidence."""

from __future__ import annotations

import argparse
import json
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
        else:
            if args.trace.stat().st_size > 2_000_000:
                raise ValueError("trace exceeds 2 MB limit")
            session = replay_trace(json.loads(args.trace.read_text()), expected_profile=args.expected_profile, expected_scenario=args.expected_scenario)
            print(json.dumps({"replay_verified": True, "score": session.score()}, indent=2))
    except (ValueError, OSError, KeyError, TypeError) as exc:
        parser.exit(2, f"bitvm-arena: {exc}\n")
    return 0
