"""A bounded protocol game with an independent funded-target scorer.

This is a synthetic optimistic dispute model. Its arithmetic witness is public
fixture data. It performs no Bitcoin Script, signature, SNARK, or node execution.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from .model import Scenario, bounded_int, canonical_json, digest, get_policy


CLAIM_FIELDS = ("recipient", "amount_sats", "authority_id", "outpoint", "context", "program_id", "witness")
ACTION_FIELDS = {
    "claim": frozenset(CLAIM_FIELDS),
    "challenge": frozenset(),
    "respond": frozenset({"witness"}),
    "finalize": frozenset(),
    "advance": frozenset({"blocks"}),
    "censor": frozenset({"blocks"}),
}
TERMINAL = frozenset({"settled", "rejected"})
MAX_ACTION_BYTES = 8192


def validate_action(action: Any) -> dict[str, Any]:
    if type(action) is not dict:
        raise ValueError("action must be an object")
    try:
        if len(canonical_json(action).encode()) > MAX_ACTION_BYTES:
            raise ValueError("action exceeds 8192-byte limit")
    except (TypeError, OverflowError, RecursionError) as exc:
        raise ValueError("action must contain JSON values") from exc
    kind = action.get("kind")
    if not isinstance(kind, str) or kind not in ACTION_FIELDS:
        raise ValueError("unknown action kind")
    extra = set(action) - {"kind"} - ACTION_FIELDS[kind]
    if extra:
        raise ValueError("unexpected action fields: " + ", ".join(sorted(extra)))
    for field in ("recipient", "authority_id", "outpoint", "context", "program_id"):
        if field in action and (type(action[field]) is not str or not 1 <= len(action[field]) <= 200):
            raise ValueError(f"{field} must be a string of 1 to 200 characters")
    if "amount_sats" in action:
        bounded_int(action["amount_sats"], "amount_sats", 1, 2_100_000_000_000_000)
    if kind in {"advance", "censor"}:
        bounded_int(action.get("blocks"), "blocks", 1, 30)
    if "witness" in action:
        _validate_witness_shape(action["witness"])
    return copy.deepcopy(action)


def _validate_witness_shape(witness: Any) -> None:
    keys = {"a", "b", "c", "modulus", "result"}
    if type(witness) is not dict or set(witness) != keys:
        raise ValueError("witness needs exactly a, b, c, modulus, result")
    for key, value in witness.items():
        bounded_int(value, "witness." + key, 1 if key == "modulus" else 0, 2**256 - 1)


@dataclass(frozen=True)
class Transfer:
    recipient: str
    amount_sats: int
    authorized: bool
    violated_checks: tuple[str, ...]


class ArenaSession:
    """One isolated episode. Profiles and funded authority are host configuration."""

    def __init__(self, scenario: Scenario, profile: str = "strict") -> None:
        self.scenario = scenario
        self.policy = get_policy(profile)
        self._funded = scenario.target
        self._funded_digest = digest(scenario.target.to_dict())
        self.height = 0
        self.phase = "funded"
        self.escrow_sats = self._funded.amount_sats
        self.claim: dict[str, Any] | None = None
        self.claim_height: int | None = None
        self.challenge_deadline: int | None = None
        self.response_deadline: int | None = None
        self.censored_until = -1
        self.censorship_used = 0
        self.cost_sats = 0
        self.transfers: list[Transfer] = []
        self.trace: list[dict[str, Any]] = []
        self._seed_count = len(scenario.seed_actions)
        for action in scenario.seed_actions:
            event = self.step(action)
            if not event["accepted"]:
                raise ValueError(f"invalid scenario seed: {event['error']}")

    def _snapshot(self) -> dict[str, Any]:
        return {
            "funded_target_digest": self._funded_digest,
            "height": self.height,
            "phase": self.phase,
            "escrow_sats": self.escrow_sats,
            "claim": copy.deepcopy(self.claim),
            "claim_height": self.claim_height,
            "challenge_deadline": self.challenge_deadline,
            "response_deadline": self.response_deadline,
            "censored_until": self.censored_until,
            "censorship_used": self.censorship_used,
            "cost_sats": self.cost_sats,
            "transfers": [dict(t.__dict__) for t in self.transfers],
        }

    def observe(self) -> dict[str, Any]:
        observation = self._snapshot()
        observation.update({
            "scenario_id": self.scenario.scenario_id,
            "evidence_level": "synthetic-model",
            "profile": self.policy.name,
            "funded_target": self._funded.to_dict(),
            "steps": len(self.trace),
            "steps_remaining": max(0, self.scenario.max_steps - len(self.trace)),
            "blocks_remaining": max(0, self.scenario.max_blocks - self.height),
            "censorship_remaining": self.scenario.censorship_budget - self.censorship_used,
            "watchtower_enabled": self.scenario.watchtower_enabled,
            "action_fields": {kind: sorted(fields) for kind, fields in ACTION_FIELDS.items()},
        })
        return observation

    def _witness_valid(self, witness: dict[str, int]) -> bool:
        # Exact input identity prevents a proof about another computation from
        # silently satisfying this funded computation.
        return (
            witness == self._funded.witness()
            and (witness["a"] * witness["b"] + witness["c"]) % witness["modulus"] == witness["result"]
        )

    def _violations(self, claim: dict[str, Any]) -> tuple[str, ...]:
        expected = self._funded.to_dict()
        return tuple(
            key for key in CLAIM_FIELDS
            if (not self._witness_valid(claim[key]) if key == "witness" else claim[key] != expected[key])
        )

    def _implementation_accepts(self, claim: dict[str, Any]) -> bool:
        return not (set(self._violations(claim)) - self.policy.omitted_checks)

    def step(self, action: dict[str, Any]) -> dict[str, Any]:
        # Invalid JSON and exhausted episodes cannot append unbounded trace data.
        action = validate_action(action)
        if len(self.trace) >= self.scenario.max_steps:
            raise ValueError("episode step budget exhausted")
        before = digest(self._snapshot())
        self.cost_sats += 1  # Abstract model cost, never a Bitcoin fee estimate.
        accepted, error = True, None
        try:
            if self.phase in TERMINAL:
                raise ValueError("episode already settled")
            getattr(self, "_do_" + action["kind"])(action)
        except ValueError as exc:
            accepted, error = False, str(exc)
        self._assert_invariants()
        event = {
            "index": len(self.trace),
            "action": action,
            "accepted": accepted,
            "error": error,
            "height": self.height,
            "phase": self.phase,
            "before": before,
            "after": digest(self._snapshot()),
            "previous_event_hash": self.trace[-1]["event_hash"] if self.trace else "0" * 64,
        }
        event["event_hash"] = digest(event)
        self.trace.append(event)
        return copy.deepcopy(event)

    def _do_claim(self, action: dict[str, Any]) -> None:
        if self.phase != "funded":
            raise ValueError("claim already exists")
        candidate = {key: self._funded.to_dict()[key] for key in CLAIM_FIELDS}
        candidate.update({key: copy.deepcopy(value) for key, value in action.items() if key != "kind"})
        # Every profile conserves the funded pool. Amount-unbound permits a
        # different allocation within this pool, never creation of new money.
        if candidate["amount_sats"] > self.escrow_sats:
            raise ValueError("claim exceeds funded escrow")
        self.claim = candidate
        self.claim_height = self.height
        self.challenge_deadline = self.height + self.scenario.challenge_window
        self.phase = "claimed"

    def _do_challenge(self, action: dict[str, Any]) -> None:
        if self.phase != "claimed":
            raise ValueError("challenge requires a pending claim")
        if self.height > self.challenge_deadline:
            raise ValueError("challenge window expired")
        if self.height <= self.censored_until:
            raise ValueError("challenger is censored at this height")
        self.phase = "challenged"
        self.response_deadline = self.height + self.scenario.response_window

    def _do_respond(self, action: dict[str, Any]) -> None:
        if self.phase != "challenged":
            raise ValueError("response requires an active challenge")
        if self.height > self.response_deadline:
            raise ValueError("response window expired")
        candidate = copy.deepcopy(self.claim)
        if "witness" in action:
            candidate["witness"] = action["witness"]
        if not self._implementation_accepts(candidate):
            raise ValueError("implementation rejected proof or authority binding")
        self.claim = candidate
        self.phase = "proven"

    def _do_finalize(self, action: dict[str, Any]) -> None:
        immature = self.phase == "claimed" and self.height <= self.challenge_deadline
        if self.phase == "claimed":
            if self.height <= self.challenge_deadline and not self.policy.early_finalize:
                raise ValueError("challenge window still open")
        elif self.phase != "proven":
            raise ValueError("claim cannot settle in current phase")
        violations = self._violations(self.claim)
        if immature:
            violations += ("challenge_window",)
        amount = self.claim["amount_sats"]
        self.transfers.append(Transfer(self.claim["recipient"], amount, not violations, violations))
        self.escrow_sats -= amount
        # A one-shot episode returns any residual principal to the depositor.
        if self.escrow_sats:
            self.transfers.append(Transfer(self._funded.recipient, self.escrow_sats, True, ()))
            self.escrow_sats = 0
        self.phase = "settled"

    def _do_censor(self, action: dict[str, Any]) -> None:
        blocks = action["blocks"]
        if self.censorship_used + blocks > self.scenario.censorship_budget:
            raise ValueError("censorship budget exceeded")
        if self.phase != "claimed":
            raise ValueError("censorship requires a pending claim")
        self.censored_until = max(self.height, self.censored_until) + blocks
        self.censorship_used += blocks
        self.cost_sats += blocks * 100

    def _do_advance(self, action: dict[str, Any]) -> None:
        new_height = self.height + action["blocks"]
        if new_height > self.scenario.max_blocks:
            raise ValueError("episode block budget exceeded")
        if self.phase == "claimed" and self.scenario.watchtower_enabled and self._violations(self.claim):
            earliest = max(self.height + 1, self.claim_height + self.scenario.watchtower_delay, self.censored_until + 1)
            if earliest <= min(new_height, self.challenge_deadline):
                self.phase = "challenged"
                self.response_deadline = earliest + self.scenario.response_window
        self.height = new_height
        if self.phase == "challenged" and self.height > self.response_deadline:
            self.transfers.append(Transfer(self._funded.recipient, self.escrow_sats, True, ()))
            self.escrow_sats = 0
            self.phase = "rejected"

    def _assert_invariants(self) -> None:
        if digest(self._funded.to_dict()) != self._funded_digest:
            raise AssertionError("funded target changed")
        if self.escrow_sats < 0 or self.escrow_sats + sum(t.amount_sats for t in self.transfers) != self._funded.amount_sats:
            raise AssertionError("funded value conservation failed")

    def score(self) -> dict[str, Any]:
        unauthorized = sum(t.amount_sats for t in self.transfers if not t.authorized)
        authorized_settlement = self.phase == "settled" and unauthorized == 0
        legitimate = authorized_settlement or (self.scenario.objective == "protect" and self.phase == "rejected")
        return {
            "legitimate_success": legitimate,
            "attacker_success": unauthorized > 0,
            "unauthorized_sats": unauthorized,
            "diverted_sats": sum(t.amount_sats for t in self.transfers if t.recipient != self._funded.recipient),
            "frozen_sats": self.escrow_sats,
            "elapsed_blocks": self.height,
            "cost_sats": self.cost_sats,
            "cost_model": "synthetic units labelled sats; no fee or ROI inference",
            "steps": len(self.trace),
            "terminal": self.phase in TERMINAL,
            "funded_target_preserved": digest(self._funded.to_dict()) == self._funded_digest,
            "violated_checks": sorted({v for t in self.transfers for v in t.violated_checks}),
            "evidence_level": "synthetic-model",
        }

    def export_trace(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "engine_version": "0.1.0",
            "scenario_id": self.scenario.scenario_id,
            "scenario_digest": digest(self.scenario.to_dict()),
            "funded_target_digest": self._funded_digest,
            "profile": self.policy.name,
            "seed_action_count": self._seed_count,
            "events": copy.deepcopy(self.trace),
            "final_state": self._snapshot(),
            "score": self.score(),
        }


def replay_trace(trace: dict[str, Any], *, expected_profile: str | None = None, expected_scenario: str | None = None) -> ArenaSession:
    """Re-execute against installed fixtures and reject any semantic mismatch."""
    from .scenarios import get_scenario

    if type(trace) is not dict or trace.get("schema_version") != 1 or trace.get("engine_version") != "0.1.0":
        raise ValueError("unsupported trace version")
    if expected_profile is not None and trace.get("profile") != expected_profile:
        raise ValueError("trace profile differs from the evaluator's profile")
    if expected_scenario is not None and trace.get("scenario_id") != expected_scenario:
        raise ValueError("trace scenario differs from the evaluator's scenario")
    scenario = get_scenario(trace.get("scenario_id"))
    session = ArenaSession(scenario, trace.get("profile"))
    events = trace.get("events")
    if type(events) is not list or not len(scenario.seed_actions) <= len(events) <= scenario.max_steps:
        raise ValueError("invalid event count")
    for event in events[len(scenario.seed_actions):]:
        if type(event) is not dict or "action" not in event:
            raise ValueError("invalid event")
        session.step(event["action"])
    if canonical_json(trace) != canonical_json(session.export_trace()):
        raise ValueError("trace differs from deterministic replay")
    return session
