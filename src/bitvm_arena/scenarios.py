"""Load the versioned benchmark fixtures shipped in the package."""

from __future__ import annotations

import json
from importlib.resources import files

from .model import FundedTarget, Scenario, canonical_json, digest, get_policy


def load_scenarios() -> list[Scenario]:
    raw = json.loads(files("bitvm_arena").joinpath("data/scenarios.json").read_text())
    if raw["schema_version"] != 1:
        raise ValueError("unsupported scenario schema")
    scenarios = []
    seen = set()
    for row in raw["scenarios"]:
        data = dict(row)
        scenario_id = data["scenario_id"]
        if scenario_id in seen:
            raise ValueError(f"duplicate scenario id: {scenario_id}")
        seen.add(scenario_id)
        get_policy(data["calibration_profile"])
        data["target"] = FundedTarget(
            outpoint=digest({"funding": scenario_id}) + ":0",
            authority_id=digest({"authority": scenario_id, "program": "toy-muladd-v1"}),
            context=digest({"domain": "bitvm-arena/synthetic/v1", "scenario": scenario_id}),
            program_id="toy-muladd-v1",
            recipient="synthetic:depositor",
            amount_sats=100_000,
        )
        data["seed_actions_json"] = canonical_json(data.pop("seed_actions", []))
        data["benchmark_actions_json"] = canonical_json(data.pop("benchmark_actions", []))
        scenarios.append(Scenario(**data))
    return scenarios


def get_scenario(scenario_id: str) -> Scenario:
    for scenario in load_scenarios():
        if scenario.scenario_id == scenario_id:
            return scenario
    raise ValueError(f"unknown scenario: {scenario_id}")
