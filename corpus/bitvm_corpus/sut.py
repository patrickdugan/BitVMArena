"""Candidate coordinator verification with explicit, switchable corruption sites.

This implementation intentionally does not import the evaluator reference spec.
Defects are research fixtures, not claims about any upstream BitVM project.
"""

from __future__ import annotations

from .canonical import digest
from .fixtures import DOMAIN, PROGRAM, RULES, authentic
from .logic import Rule, closure, script

DEFECTS = {
    "signature_bypass": "Accept an unauthenticated request",
    "domain_unbound": "Accept a request from a different contract instance",
    "program_unbound": "Accept a substituted program commitment",
    "prior_unbound": "Accept a transition from a stale state",
    "request_unbound": "Ignore the signed request commitment",
    "quote_unbound": "Ignore the oracle commitment",
    "input_push_unbound": "Trust operator-supplied Boolean inputs",
    "and_as_or": "Replace conjunction with disjunction",
    "selector_unbound": "Trust a branch selector independently of the predicate",
    "implication_gate": "Use implication instead of exact output equivalence",
    "closure_incomplete": "Accept a partial rule closure",
    "nonce_replay": "Omit nonce uniqueness",
    "receipt_replay": "Omit receipt uniqueness",
    "amount_wrap32": "Truncate amount before balance and limit checks",
    "collateral_unlock": "Include locked collateral in spendable balance",
    "borrow_ratio": "Omit the post-borrow collateral ratio check",
    "liquidation_health": "Permit liquidation of a healthy position",
    "liquidation_overrepay": "Repay more than the outstanding debt",
    "swap_round_up": "Round AMM output upward",
    "swap_slippage": "Ignore the signed minimum output",
    "oracle_stale": "Omit oracle maximum age",
    "oracle_future": "Accept future-dated oracle data",
    "oracle_anchor": "Accept an orphaned oracle anchor",
    "oracle_signature": "Accept a forged oracle signature",
    "oracle_domain": "Accept a quote from another instance",
    "recipient_redirect": "Do not bind recipient to the signed request",
    "amount_substitution": "Do not bind amount to the signed request",
    "debit_omission": "Accept payout without debiting user credit",
    "nonce_omission": "Accept payout without consuming the event",
    "debt_omission": "Accept borrowing without recording debt",
    "fee_unbounded": "Permit operator fee above the signed cap",
    "payout_inflation": "Do not bind payout to execution output",
    "settle_early": "Ignore the challenge window",
    "settle_challenged": "Finalize while a challenge is unresolved",
    "connector_reuse": "Reuse a finalized settlement authorization",
    "response_unbound": "Accept a response for a different claim",
    "data_withholding": "Finalize without available execution data",
    "challenge_censorship": "Restrict permissionless challenges to a fixed identity",
    "timeout_no_refund": "Keep funds locked after a missed response deadline",
    "fee_starvation": "Do not provision a challenger fee reserve",
    "wire_equivocation": "Accept both values for the same committed wire",
    "minimalif_bypass": "Accept noncanonical branch selectors",
}


def verify(state, request, oracle, anchor, claim, defects=frozenset()):
    p, q, e = request["payload"], oracle["payload"], claim["effect"]
    bad = []

    def need(condition, code):
        if not condition:
            bad.append(code)

    checks = {"domain": (DOMAIN, "domain_unbound"), "program": (PROGRAM, "program_unbound"),
              "prior": (digest(state), "prior_unbound"),
              "request_hash": (digest(request), "request_unbound"),
              "quote_hash": (digest(oracle), "quote_unbound")}
    for key, (expected, defect) in checks.items():
        if defect not in defects:
            need(claim[key] == expected, f"binding.{key}")
    owner, kind, amount = p["owner"], p["kind"], p["amount"]
    checked_amount = amount % 2**32 if "amount_wrap32" in defects else amount
    credit = state["credits"][owner]["usd" if kind == "liquidate" else "btc"]
    if kind == "withdraw" and "collateral_unlock" not in defects:
        credit -= state["positions"][owner]["collateral"]
    age = claim["created_height"] - q["height"]
    oracle_checks = [
        "oracle_signature" in defects or authentic(q, oracle["signature"], "oracle"),
        "oracle_domain" in defects or q["domain"] == DOMAIN,
        "oracle_anchor" in defects or q["anchor"] == anchor,
        "oracle_stale" in defects or age <= 12,
        "oracle_future" in defects or age >= 0,
        p["quote"] == q["id"],
    ]
    business = (checked_amount <= 100_000 and p["recipient"] in state["wallets"])
    if kind == "borrow" and "borrow_ratio" not in defects:
        pos = state["positions"][owner]
        business &= pos["collateral"] * q["price"] * 100 >= (pos["debt"] + amount) * 150
    if kind == "liquidate":
        pos = state["positions"][p["target"]]
        if "liquidation_health" not in defects:
            business &= pos["collateral"] * q["price"] * 100 < pos["debt"] * 150
        if "liquidation_overrepay" not in defects:
            business &= amount <= pos["debt"]
    payout = amount
    if kind == "swap":
        numerator = state["pool"]["usd"] * amount
        denominator = state["pool"]["btc"] + amount
        payout = (numerator + denominator - 1) // denominator if "swap_round_up" in defects else numerator // denominator
        if "swap_slippage" not in defects:
            business &= payout >= p["min_output"] and payout > 0
    if kind == "liquidate":
        payout = min(state["positions"][p["target"]]["collateral"], amount * 105 // (100 * q["price"]))
    bits = {
        "signature_ok": ("signature_bypass" in defects or authentic(p, request["signature"], owner))
                         and ("domain_unbound" in defects or p["domain"] == DOMAIN),
        "receipt_ok": "receipt_replay" in defects or p["receipt"] not in state["receipts"],
        "nonce_ok": "nonce_replay" in defects or [owner, p["nonce"]] not in state["nonces"],
        "balance_ok": checked_amount > 0 and (kind == "borrow" or checked_amount <= credit),
        "oracle_ok": all(oracle_checks), "business_ok": bool(business),
    }
    # Changes in a corrupted predicate also affect its authenticated input and
    # rule closure; an attacker must supply a coherent forged execution trace.
    if "input_push_unbound" in defects:
        bits = claim["inputs"]
    else:
        need(claim["inputs"] == bits, "logic.inputs")
    known, _ = closure({key for key, value in bits.items() if value}, [Rule.from_dict(r) for r in RULES])
    eligible = "eligible" in known
    if "and_as_or" in defects:
        encoded = ["01" if value else "" for value in bits.values()]
        eligible = script(["OP_BOOLOR"] * (len(encoded) - 1), encoded)
    if "selector_unbound" in defects:
        eligible = claim["selector"]
    else:
        need(claim["selector"] == eligible, "logic.selector")
    if "implication_gate" in defects:
        need(not eligible or claim["output"], "logic.implication")
    else:
        need(claim["output"] == eligible, "logic.output")
    need(claim["output"], "logic.ineligible")
    if "closure_incomplete" not in defects:
        need(claim["facts"] == sorted(known), "rules.closure")
    else:
        need(set(claim["facts"]) <= known, "rules.unsound_fact")
    fixed = {"kind": kind, "owner": owner, "nonce": p["nonce"], "receipt": p["receipt"], "target": p["target"]}
    for key, value in fixed.items():
        need(e[key] == value, f"effect.{key}")
    optional = {
        "recipient": (p["recipient"], "recipient_redirect"),
        "amount": (amount, "amount_substitution"), "payout": (payout, "payout_inflation"),
        "debit": (kind != "borrow", "debit_omission"), "consume_nonce": (True, "nonce_omission"),
        "debt_delta": (amount if kind == "borrow" else 0, "debt_omission"),
    }
    for key, (value, defect) in optional.items():
        if defect not in defects:
            need(e[key] == value, f"effect.{key}")
    if "closure_incomplete" in defects:
        # Vulnerable interpreters apply only emitted effects; omitted rules make
        # omission of a debit/nonce update appear locally consistent.
        bad = [x for x in bad if x not in ("effect.debit", "effect.consume_nonce")]
        need(e["debit"] == ("debit" in claim["facts"] and kind != "borrow"), "rules.debit")
        need(e["consume_nonce"] == ("consume_nonce" in claim["facts"]), "rules.nonce")
    # A fee is an additional modeled payment, not an excuse to inflate payout.
    need(e["fee"] <= p["max_fee"] if "fee_unbounded" not in defects else True, "effect.fee_cap")
    return sorted(set(bad))
