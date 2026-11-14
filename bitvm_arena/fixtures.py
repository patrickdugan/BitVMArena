"""Synthetic keys, signed requests, and conserved model assets (not Bitcoin)."""

from __future__ import annotations

import hmac
from copy import deepcopy
from hashlib import sha256

from .canonical import canonical, digest

KEYS = {name: sha256(f"arena-test-key:{name}".encode()).digest()
        for name in ("alice", "bob", "oracle")}
PROGRAM = digest({"language": "arena-rules-v1", "policy": "defi-v1"})
DOMAIN = "arena:regtest:instance-1"
RULES = [
    {"premises": ["signature_ok", "receipt_ok"], "conclusion": "authorized"},
    {"premises": ["authorized", "balance_ok", "nonce_ok", "oracle_ok", "business_ok"],
     "conclusion": "eligible"},
    {"premises": ["eligible"], "conclusion": "debit"},
    {"premises": ["eligible"], "conclusion": "consume_nonce"},
    {"premises": ["eligible"], "conclusion": "pay"},
]


def sign(payload, signer):
    return hmac.new(KEYS[signer], canonical(payload).encode(), sha256).hexdigest()


def authentic(payload, signature, signer):
    return signer in KEYS and isinstance(signature, str) and hmac.compare_digest(sign(payload, signer), signature)


def initial_state():
    return {
        "revision": 0,
        "credits": {name: {"btc": 500_000, "usd": 200_000} for name in ("alice", "bob")},
        "positions": {name: {"collateral": 100_000, "debt": 100_000} for name in ("alice", "bob")},
        "vault": {"btc": 2**40, "usd": 2**40},
        "pool": {"btc": 1_000_000, "usd": 2_000_000},
        "wallets": {name: {"btc": 0, "usd": 0} for name in ("alice", "bob", "mallory")},
        "nonces": [], "receipts": [],
    }


def quote(height=100, price=2, **changes):
    payload = {"id": "quote-1", "height": height, "price": price,
               "domain": DOMAIN, "anchor": "canonical-100"}
    payload.update(changes)
    return {"payload": payload, "signature": sign(payload, "oracle")}


def request(kind="withdraw", amount=1000, nonce=1, owner="alice", **changes):
    payload = {"domain": DOMAIN, "kind": kind, "owner": owner, "recipient": owner,
               "amount": amount, "nonce": nonce, "receipt": f"receipt-{owner}-{nonce}",
               "quote": "quote-1", "min_output": 1, "target": "alice", "max_fee": 100}
    payload.update(changes)
    return {"payload": payload, "signature": sign(payload, owner)}


def fixtures():
    return {"state": initial_state(), "requests": {"request-1": request()}, "quote": quote(),
            "height": 100, "anchor": "canonical-100"}


def asset_totals(state):
    return {asset: state["vault"][asset] + state["pool"][asset]
            + sum(wallet[asset] for wallet in state["wallets"].values()) for asset in ("btc", "usd")}


def apply_effect(state, effect):
    """Apply a candidate transition. Validation belongs to the DUT or oracle.

    Both debit and nonce consumption are explicit so omissions remain observable.
    Vault, AMM and recipient movements are independently scored after execution.
    """
    result = deepcopy(state)
    owner, recipient, kind = effect["owner"], effect["recipient"], effect["kind"]
    amount, payout, fee = effect["amount"], effect["payout"], effect["fee"]
    input_asset = "usd" if kind == "liquidate" else "btc"
    output_asset = "usd" if kind in ("swap", "borrow") else "btc"
    if effect["debit"]:
        result["credits"][owner][input_asset] -= amount
    if kind == "swap":
        result["vault"]["btc"] -= amount
        result["pool"]["btc"] += amount
        result["pool"]["usd"] -= payout + fee
    elif kind == "liquidate":
        result["positions"][effect["target"]]["debt"] -= amount
        result["positions"][effect["target"]]["collateral"] -= payout + fee
        result["vault"]["btc"] -= payout + fee
    else:
        result["vault"][output_asset] -= payout + fee
        if kind == "borrow":
            result["positions"][owner]["debt"] += effect["debt_delta"]
    result["wallets"][recipient][output_asset] += payout
    result["wallets"]["bob"][output_asset] += fee  # synthetic operator fee account
    if effect["consume_nonce"]:
        result["nonces"].append([owner, effect["nonce"]])
        result["receipts"].append(effect["receipt"])
    result["revision"] += 1
    return result
