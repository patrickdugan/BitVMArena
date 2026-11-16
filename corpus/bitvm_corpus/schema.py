"""Strict, bounded schemas at every replay/API boundary."""

from __future__ import annotations

from .canonical import ValidationError, canonical, integer, keys, text
from .fixtures import initial_state
from .sut import DEFECTS

OPS = {
    "propose": ({"request", "claim"}, {"override", "available"}),
    "audit": ({"claim"}, set()), "challenge": ({"claim"}, set()),
    "respond": ({"claim"}, {"commitment"}), "disprove": ({"claim"}, set()),
    "settle": ({"claim"}, set()), "timeout": ({"claim"}, set()),
    "mine": ({"blocks"}, set()), "reorg": ({"anchor"}, set()),
    "fee_market": ({"fee"}, set()), "withhold": ({"claim"}, set()),
    "open_wire": ({"wire", "value"}, set()),
    "execute_script": ({"program", "witness"}, set()),
}
ROLES = {
    "operator": {"propose", "respond", "settle", "withhold", "open_wire", "execute_script"},
    "watcher": {"audit", "challenge", "disprove", "timeout"},
    "outsider": {"challenge", "disprove", "timeout"},
    "environment": {"mine", "reorg", "fee_market"},
}


def action(data):
    keys(data, {"actor", "op", "args"})
    actor, op = data["actor"], data["op"]
    if not isinstance(actor, str) or not isinstance(op, str) or actor not in ROLES or op not in ROLES[actor]:
        raise ValidationError("actor cannot perform this operation")
    args = keys(data["args"], *OPS[op])
    for name in ("request", "claim", "wire", "anchor", "commitment"):
        if name in args:
            text(args[name], name)
    for name in ("blocks", "fee"):
        if name in args:
            integer(args[name], name, 1, 100_000)
    if "available" in args and type(args["available"]) is not bool:
        raise ValidationError("available must be Boolean")
    if op == "open_wire":
        integer(args["value"], "wire value", 0, 1)
    if "override" in args and not isinstance(args["override"], dict):
        raise ValidationError("override must be an object")
    if len(canonical(data)) > 64_000:
        raise ValidationError("action exceeds 64 KB")
    return data


def fixture(data):
    keys(data, {"state", "requests", "quote", "height", "anchor"})
    integer(data["height"], "height", 0, 1_000_000)
    text(data["anchor"], "anchor")
    state = data["state"]
    baseline = initial_state()
    keys(state, set(baseline))
    integer(state["revision"], "revision")
    for field in ("credits", "positions", "vault", "pool", "wallets"):
        keys(state[field], set(baseline[field]))
        if field in ("vault", "pool"):
            for name, value in state[field].items():
                integer(value, name, 1)
        else:
            for name, record in state[field].items():
                keys(record, set(baseline[field][name]))
                for key, value in record.items():
                    integer(value, key)
    for field in ("nonces", "receipts"):
        if not isinstance(state[field], list) or len(state[field]) > 4096:
            raise ValidationError(f"invalid {field}")
    for pair in state["nonces"]:
        if not isinstance(pair, list) or len(pair) != 2 or pair[0] not in state["credits"]:
            raise ValidationError("invalid used nonce")
        integer(pair[1], "nonce")
    for receipt in state["receipts"]:
        text(receipt, "receipt")
    if not isinstance(data["requests"], dict) or not 1 <= len(data["requests"]) <= 128:
        raise ValidationError("expected 1..128 requests")
    required = {"domain", "kind", "owner", "recipient", "amount", "nonce", "receipt", "quote", "min_output", "target", "max_fee"}
    for name, request in data["requests"].items():
        text(name, "request id")
        keys(request, {"payload", "signature"})
        p = keys(request["payload"], required)
        text(request["signature"], "signature")
        for field in ("amount", "nonce", "min_output", "max_fee"):
            integer(p[field], field)
        for field in required - {"amount", "nonce", "min_output", "max_fee"}:
            text(p[field], field)
        if p["kind"] not in ("withdraw", "swap", "borrow", "liquidate"):
            raise ValidationError("unsupported DeFi operation")
        if p["owner"] not in state["credits"] or p["target"] not in state["positions"] or p["recipient"] not in state["wallets"]:
            raise ValidationError("unknown fixture account")
    q = keys(data["quote"], {"payload", "signature"})
    p = keys(q["payload"], {"id", "height", "price", "domain", "anchor"})
    integer(p["height"], "quote height", 0, 1_000_000)
    integer(p["price"], "price", 1, 1_000_000)
    for name in ("id", "domain", "anchor"):
        text(p[name], name)
    text(q["signature"], "oracle signature")
    return data


def trajectory(data):
    keys(data, {"schema_version", "id", "family", "split", "variant", "main_task", "side_task",
                "defect", "fixture", "steps", "expect", "sources"})
    if data["schema_version"] != 1 or type(data["schema_version"]) is not int:
        raise ValidationError("unsupported trajectory schema")
    for name in ("id", "family", "main_task", "side_task"):
        text(data[name], name, 2048)
    if data["split"] not in ("train", "validation", "test") or data["variant"] not in ("benign", "attack"):
        raise ValidationError("invalid split or variant")
    if data["defect"] not in DEFECTS:
        raise ValidationError("unknown defect")
    fixture(data["fixture"])
    if not isinstance(data["steps"], list) or not 1 <= len(data["steps"]) <= 256:
        raise ValidationError("expected 1..256 trajectory steps")
    for step in data["steps"]:
        action(step)
    keys(data["expect"], {"hardened", "mutant"})
    for profile in data["expect"].values():
        keys(profile, {"attack_success", "main_success"})
        if any(type(value) is not bool for value in profile.values()):
            raise ValidationError("expectations must be Boolean")
    if not isinstance(data["sources"], list) or not data["sources"]:
        raise ValidationError("source identifiers required")
    for source in data["sources"]:
        text(source, "source id")
    return data
