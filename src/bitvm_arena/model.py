"""Immutable scenario inputs and deliberately limited calibration policies."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def bounded_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


@dataclass(frozen=True)
class FundedTarget:
    outpoint: str
    authority_id: str
    context: str
    program_id: str
    recipient: str
    amount_sats: int
    a: int = 7
    b: int = 11
    c: int = 3
    modulus: int = 97
    result: int = 80

    def to_dict(self) -> dict[str, Any]:
        return {
            "outpoint": self.outpoint,
            "authority_id": self.authority_id,
            "context": self.context,
            "program_id": self.program_id,
            "recipient": self.recipient,
            "amount_sats": self.amount_sats,
            "witness": self.witness(),
        }

    def witness(self) -> dict[str, int]:
        return {key: getattr(self, key) for key in ("a", "b", "c", "modulus", "result")}


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    title: str
    description: str
    legitimate_task: str
    attacker_goal: str
    category: str
    objective: str
    target: FundedTarget
    seed_actions_json: str
    benchmark_actions_json: str
    calibration_profile: str
    expected_strict_attack: bool = False
    expected_calibration_attack: bool = False
    watchtower_enabled: bool = True
    watchtower_delay: int = 1
    challenge_window: int = 6
    response_window: int = 3
    censorship_budget: int = 2
    max_steps: int = 40
    max_blocks: int = 30

    @property
    def seed_actions(self) -> tuple[dict[str, Any], ...]:
        return tuple(json.loads(self.seed_actions_json))

    @property
    def benchmark_actions(self) -> tuple[dict[str, Any], ...]:
        return tuple(json.loads(self.benchmark_actions_json))

    def to_dict(self) -> dict[str, Any]:
        value = dict(self.__dict__)
        value["target"] = self.target.to_dict()
        value["seed_actions"] = list(self.seed_actions)
        value["benchmark_actions"] = list(self.benchmark_actions)
        del value["seed_actions_json"]
        del value["benchmark_actions_json"]
        return value


@dataclass(frozen=True)
class Policy:
    name: str
    omitted_checks: frozenset[str] = frozenset()
    early_finalize: bool = False


POLICIES = {"strict": Policy("strict")}
for _field in ("recipient", "amount_sats", "outpoint", "authority_id", "context", "program_id", "witness"):
    _name = {
        "recipient": "output-unbound",
        "amount_sats": "amount-unbound",
        "authority_id": "authority-unbound",
        "witness": "proof-unchecked",
    }.get(_field, _field.replace("_id", "") + "-unbound")
    POLICIES[_name] = Policy(_name, frozenset({_field}))
POLICIES["early-finalize"] = Policy("early-finalize", early_finalize=True)


def get_policy(name: str) -> Policy:
    try:
        return POLICIES[name]
    except KeyError as exc:
        raise ValueError(f"unknown policy profile: {name}") from exc
