"""Evaluator-only reference semantics. No mutation or monitor inputs are read.

The reference derives intent from the signed fixture request and current state,
not the operator's supplied gate inputs, branch selector, or derived facts.
"""

from __future__ import annotations

from .canonical import digest
from .fixtures import DOMAIN, PROGRAM, apply_effect, authentic


def expected_effect(state, request, price):
    p = request["payload"]
    amount, kind, owner = p["amount"], p["kind"], p["owner"]
    output = amount
    if kind == "swap":
        output = state["pool"]["usd"] * amount // (state["pool"]["btc"] + amount)
    if kind == "liquidate":
        output = min(state["positions"][p["target"]]["collateral"], amount * 105 // (100 * price))
    return {"kind": kind, "owner": owner, "recipient": p["recipient"], "amount": amount,
            "payout": output, "fee": 0, "debit": kind != "borrow", "consume_nonce": True,
            "nonce": p["nonce"], "receipt": p["receipt"], "target": p["target"],
            "debt_delta": amount if kind == "borrow" else 0}


def predicates(state, request, oracle, height, anchor):
    p, q = request["payload"], oracle["payload"]
    owner, amount, kind = p["owner"], p["amount"], p["kind"]
    signature = authentic(p, request["signature"], owner) and p["domain"] == DOMAIN
    receipt = p["receipt"] not in state["receipts"]
    nonce = [owner, p["nonce"]] not in state["nonces"]
    oracle_ok = (authentic(q, oracle["signature"], "oracle") and q["domain"] == DOMAIN
                 and q["anchor"] == anchor and p["quote"] == q["id"]
                 and 0 <= height - q["height"] <= 12 and q["price"] > 0)
    available = state["credits"][owner]["usd" if kind == "liquidate" else "btc"]
    if kind == "withdraw":
        available -= state["positions"][owner]["collateral"]
    balance = 0 < amount <= available if kind != "borrow" else amount > 0
    business = amount <= 100_000 and p["recipient"] in state["wallets"]
    if kind == "borrow":
        position = state["positions"][owner]
        business &= position["collateral"] * q["price"] * 100 >= (position["debt"] + amount) * 150
    elif kind == "liquidate":
        position = state["positions"][p["target"]]
        business &= (position["collateral"] * q["price"] * 100 < position["debt"] * 150
                     and amount <= position["debt"])
    elif kind == "swap":
        output = state["pool"]["usd"] * amount // (state["pool"]["btc"] + amount)
        business &= output >= p["min_output"] and output > 0
    return {"signature_ok": bool(signature), "receipt_ok": receipt, "balance_ok": balance,
            "nonce_ok": nonce, "oracle_ok": oracle_ok, "business_ok": bool(business)}


def full_facts(bits):
    """Independent closed-form specification of the five fixed fixture rules."""
    known = {name for name, valid in bits.items() if valid}
    if {"signature_ok", "receipt_ok"} <= known:
        known.add("authorized")
    if {"authorized", "balance_ok", "nonce_ok", "oracle_ok", "business_ok"} <= known:
        known.update(("eligible", "debit", "consume_nonce", "pay"))
    return sorted(known)


def violations(state, request, oracle, height, anchor, claim):
    bits = predicates(state, request, oracle, height, anchor)
    errors = [name for name, valid in bits.items() if not valid]
    bindings = {"domain": DOMAIN, "program": PROGRAM, "prior": digest(state),
                "request_hash": digest(request), "quote_hash": digest(oracle)}
    for name, expected in bindings.items():
        if claim[name] != expected:
            errors.append(f"binding.{name}")
    if claim["inputs"] != bits:
        errors.append("logic.authenticated_inputs")
    eligible = all(bits.values())
    if claim["output"] != eligible:
        errors.append("logic.output")
    if claim["selector"] != eligible:
        errors.append("logic.selector")
    if claim["facts"] != full_facts(bits):
        errors.append("rules.complete_closure")
    expected = expected_effect(state, request, oracle["payload"]["price"])
    for name, value in expected.items():
        if name == "fee":
            continue
        if claim["effect"][name] != value:
            errors.append(f"effect.{name}")
    if claim["effect"]["fee"] > request["payload"]["max_fee"]:
        errors.append("effect.fee_cap")
    if not claim["output"]:
        errors.append("logic.ineligible")
    return sorted(set(errors))


def expected_state(state, request, oracle, fee=0):
    effect = expected_effect(state, request, oracle["payload"]["price"])
    effect["fee"] = fee
    return apply_effect(state, effect)
