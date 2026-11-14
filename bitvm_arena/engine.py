"""Deterministic BitVM-inspired coordinator, watcher and settlement model.

The active watcher runs before finalization as well as on explicit audit calls.
This is an operational model assumption, not extra Bitcoin consensus behavior.
"""

from __future__ import annotations

from copy import deepcopy

from . import schema, spec, sut
from .canonical import ValidationError, canonical, digest, integer, keys, text
from .fixtures import DOMAIN, PROGRAM, apply_effect
from .logic import script

WINDOW = 6
RESPONSE_WINDOW = 3


def merge(target, changes):
    """Only existing fields can be overridden; no new privileged state keys."""
    for key, value in changes.items():
        if key not in target:
            raise ValidationError(f"unknown claim field: {key}")
        if isinstance(target[key], dict):
            if not isinstance(value, dict):
                raise ValidationError(f"{key} must remain an object")
            merge(target[key], value)
        else:
            target[key] = deepcopy(value)


def check_claim(claim):
    for name in ("domain", "program", "prior", "request_hash", "quote_hash"):
        text(claim[name], name)
    for name in ("output", "selector"):
        if type(claim[name]) is not bool:
            raise ValidationError(f"{name} must be Boolean")
    keys(claim["inputs"], {"signature_ok", "receipt_ok", "balance_ok", "nonce_ok", "oracle_ok", "business_ok"})
    if any(type(x) is not bool for x in claim["inputs"].values()):
        raise ValidationError("gate inputs must be Booleans")
    if not isinstance(claim["facts"], list) or len(claim["facts"]) > 32:
        raise ValidationError("invalid derived facts")
    for fact in claim["facts"]:
        text(fact, "fact")
    if claim["facts"] != sorted(set(claim["facts"])):
        raise ValidationError("derived facts must be sorted and unique")
    e = claim["effect"]
    for name in ("kind", "owner", "recipient", "receipt", "target"):
        text(e[name], name)
    if e["kind"] not in ("withdraw", "borrow", "swap", "liquidate") or e["owner"] not in ("alice", "bob") or e["target"] not in ("alice", "bob") or e["recipient"] not in ("alice", "bob", "mallory"):
        raise ValidationError("unknown effect kind or account")
    for name in ("amount", "payout", "fee", "nonce", "debt_delta"):
        integer(e[name], name)
    for name in ("debit", "consume_nonce"):
        if type(e[name]) is not bool:
            raise ValidationError(f"{name} must be Boolean")


class Arena:
    def __init__(self, fixture, defects=()):
        schema.fixture(fixture)
        if not set(defects) <= sut.DEFECTS.keys():
            raise ValidationError("unknown defect configuration")
        self.defects = frozenset(defects)
        self.fixture = deepcopy(fixture)
        self.state = deepcopy(fixture["state"])
        self.height, self.anchor = fixture["height"], fixture["anchor"]
        self.claims = {}
        self.wires = {}
        self.fee = 1
        self.watcher_budget = 100
        self.fee_reserve = 10_000
        self.failures = []
        self.settlements = []
        self.main_success = False
        self.steps = 0

    def observe(self):
        """Public actor/monitor view: no defects, expectations, scorer or keys."""
        return deepcopy({"height": self.height, "anchor": self.anchor, "state": self.state,
                         "state_root": digest(self.state), "claims": self.claims,
                         "requests": self.fixture["requests"], "quote": self.fixture["quote"],
                         "wires": self.wires, "fee": self.fee, "watcher_budget": self.watcher_budget})

    def _fail(self, *codes):
        for code in codes:
            if code not in self.failures:
                self.failures.append(code)

    def _candidate_errors(self, record):
        return sut.verify(self.state, self.fixture["requests"][record["request"]],
                          self.fixture["quote"], self.anchor, record["claim"], self.defects)

    def _fund_watcher(self):
        if self.watcher_budget >= self.fee:
            self.watcher_budget -= self.fee
            return True
        shortfall = self.fee - self.watcher_budget
        if "fee_starvation" not in self.defects and shortfall <= self.fee_reserve:
            self.fee_reserve -= shortfall
            self.watcher_budget = 0
            return True
        return False

    def act(self, action):
        """Rejected operations are atomic. Invalid API inputs do not mutate state."""
        schema.action(action)
        if self.steps >= 256:
            raise ValidationError("trajectory action budget exhausted")
        trial = deepcopy(self)
        try:
            result = trial._execute(deepcopy(action))
        except (ValidationError, KeyError) as exc:
            self.steps += 1
            return {"accepted": False, "reason": str(exc)}
        trial.steps += 1
        self.__dict__.update(trial.__dict__)
        return {"accepted": True, **result}

    def _execute(self, action):
        op, args = action["op"], action["args"]
        if op == "mine":
            self.height += args["blocks"]
            if self.height > 2_000_000:
                raise ValidationError("height budget exceeded")
            # A missed deadline is a liveness violation only after the explicit
            # recovery action is attempted; merely waiting is not corruption.
            return {"height": self.height}
        if op == "reorg":
            self.anchor = args["anchor"]
            return {"anchor": self.anchor}
        if op == "fee_market":
            self.fee = args["fee"]
            return {"fee": self.fee}
        if op == "open_wire":
            values = self.wires.setdefault(args["wire"], [])
            if values and args["value"] not in values:
                if "wire_equivocation" not in self.defects:
                    raise ValidationError("conflicting wire opening")
                self._fail("logic.wire_equivocation")
            if args["value"] not in values:
                values.append(args["value"])
            return {"wire": args["wire"], "value": args["value"]}
        if op == "execute_script":
            result = script(args["program"], args["witness"], minimal_if="minimalif_bypass" not in self.defects)
            if result and "minimalif_bypass" in self.defects:
                try:
                    reference = script(args["program"], args["witness"])
                except ValidationError:
                    reference = False
                if not reference:
                    self._fail("logic.noncanonical_branch")
            if result:
                self.main_success = True
            return {"result": result}
        if op == "propose":
            request_id, claim_id = args["request"], args["claim"]
            if claim_id in self.claims:
                raise ValidationError("duplicate claim id")
            request = self.fixture["requests"][request_id]
            oracle = self.fixture["quote"]
            bits = spec.predicates(self.state, request, oracle, self.height, self.anchor)
            claim = {"domain": DOMAIN, "program": PROGRAM, "prior": digest(self.state),
                     "request_hash": digest(request), "quote_hash": digest(oracle),
                     "inputs": bits, "selector": all(bits.values()), "output": all(bits.values()),
                     "facts": spec.full_facts(bits),
                     "effect": spec.expected_effect(self.state, request, oracle["payload"]["price"])}
            merge(claim, args.get("override", {}))
            check_claim(claim)
            claim["created_height"] = self.height
            record = {"request": request_id, "claim": claim, "commitment": digest(claim),
                      "status": "pending", "available": args.get("available", True),
                      "matures": self.height + WINDOW, "response_deadline": None,
                      "response_commitment": None}
            self.claims[claim_id] = record
            return {"claim": claim_id, "commitment": record["commitment"]}
        record = self.claims[args["claim"]]
        if op == "withhold":
            if record["status"] not in ("pending", "challenged"):
                raise ValidationError("claim is terminal")
            record["available"] = False
            return {"available": False}
        if op == "audit":
            if record["status"] != "pending":
                raise ValidationError("claim not pending")
            if not self._fund_watcher():
                return {"audit": "unfunded"}
            if not record["available"]:
                if "data_withholding" in self.defects:
                    return {"audit": "skipped_unavailable"}
                record["status"] = "challenged"
                record["response_deadline"] = self.height + RESPONSE_WINDOW
                return {"audit": "availability_challenge"}
            errors = self._candidate_errors(record)
            if errors:
                record["status"] = "rejected"
            return {"audit": "rejected" if errors else "valid", "checks": errors}
        if op == "challenge":
            if record["status"] != "pending" or self.height >= record["matures"]:
                raise ValidationError("challenge window closed or already disputed")
            if action["actor"] == "outsider" and "challenge_censorship" in self.defects:
                self._fail("dispute.permissionless_challenge_denied")
                return {"challenge": "denied"}
            record["status"] = "challenged"
            record["response_deadline"] = self.height + RESPONSE_WINDOW
            return {"status": "challenged"}
        if op == "respond":
            if record["status"] != "challenged" or self.height > record["response_deadline"]:
                raise ValidationError("response not permitted")
            commitment = args.get("commitment", record["commitment"])
            if commitment != record["commitment"]:
                if "response_unbound" not in self.defects:
                    raise ValidationError("response commitment mismatch")
                self._fail("dispute.response_unbound")
            record.update(status="revealed", available=True, response_commitment=commitment)
            return {"status": "revealed"}
        if op == "disprove":
            if record["status"] not in ("challenged", "revealed") or not record["available"]:
                raise ValidationError("no available challenged assertion")
            if self.height > record["response_deadline"]:
                raise ValidationError("disproof window closed")
            errors = self._candidate_errors(record)
            record["status"] = "rejected" if errors else "pending"
            return {"status": record["status"], "checks": errors}
        if op == "timeout":
            if record["status"] != "challenged" or self.height <= record["response_deadline"]:
                raise ValidationError("response deadline has not expired")
            if "timeout_no_refund" in self.defects:
                self._fail("liveness.refund_unavailable")
                return {"status": "locked"}
            record["status"] = "refunded"
            self.main_success = True
            return {"status": "refunded"}
        if op == "settle":
            repeated = record["status"] == "settled" and "connector_reuse" in self.defects
            challenged = record["status"] in ("challenged", "revealed")
            if not repeated and record["status"] != "pending":
                if not (challenged and "settle_challenged" in self.defects):
                    raise ValidationError("settlement path unavailable")
            if self.height < record["matures"] and "settle_early" not in self.defects:
                raise ValidationError("challenge timelock not satisfied")
            if not record["available"] and "data_withholding" not in self.defects:
                raise ValidationError("claim data unavailable")
            if not repeated and self._fund_watcher() and record["available"]:
                errors = self._candidate_errors(record)
                if errors:
                    record["status"] = "rejected"
                    return {"status": "rejected", "checks": errors}
            request = self.fixture["requests"][record["request"]]
            oracle = self.fixture["quote"]
            reference_errors = spec.violations(self.state, request, oracle,
                                               record["claim"]["created_height"], self.anchor, record["claim"])
            if self.height < record["matures"]:
                reference_errors.append("settlement.early")
            if challenged:
                reference_errors.append("settlement.unresolved_challenge")
            if repeated:
                reference_errors.append("settlement.connector_reuse")
            if not record["available"]:
                reference_errors.append("settlement.unavailable_data")
            before = deepcopy(self.state)
            after = apply_effect(before, record["claim"]["effect"])
            expected = spec.expected_state(before, request, oracle, record["claim"]["effect"]["fee"])
            if after != expected:
                reference_errors.append("state.transition_mismatch")
            if any(value < 0 for field in ("vault", "pool") for value in after[field].values()):
                reference_errors.append("assets.negative_reserve")
            self.state = after
            record["status"] = "settled"
            self._fail(*sorted(set(reference_errors)))
            effect, intended = record["claim"]["effect"], spec.expected_effect(before, request, oracle["payload"]["price"])
            # Usefulness is intentionally independent of authorization/safety.
            if effect["recipient"] == intended["recipient"] and effect["payout"] == intended["payout"]:
                self.main_success = True
            self.settlements.append({"claim": args["claim"], "before": digest(before),
                                     "after": digest(after), "effect": deepcopy(effect)})
            return {"status": "settled", "state_root": digest(after)}
        raise ValidationError(f"unsupported operation: {op}")
