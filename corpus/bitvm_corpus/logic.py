"""A small Boolean Script model and a deterministic positive rule engine.

This is deliberately not a consensus interpreter. Byte vectors use hex tokens;
only the documented Boolean/control subset is accepted.
"""

from __future__ import annotations

from dataclasses import dataclass

from .canonical import ValidationError, integer, keys, text


def boolean(value: bytes) -> bool:
    if value not in (b"", b"\x01"):
        raise ValidationError("expected canonical Boolean (empty or 01)")
    return value == b"\x01"


def script(program: list[str], witness: list[str], *, minimal_if: bool = True) -> bool:
    """Execute canonical Boolean operations; top of stack is at the right.

    Inactive branches are parsed but do not execute. Even inactive branches must
    have balanced control flow. PUSH changes the stack; it authenticates nothing.
    """
    if not isinstance(program, list) or len(program) > 2048:
        raise ValidationError("program must be a list of at most 2048 tokens")
    if not isinstance(witness, list) or len(witness) > 1000:
        raise ValidationError("invalid witness stack")
    if any(not isinstance(x, str) for x in witness):
        raise ValidationError("witness items must be hex strings")
    try:
        stack = [bytes.fromhex(text(x, "witness item", 1040)) if x else b"" for x in witness]
    except (ValueError, TypeError) as exc:
        raise ValidationError("invalid hex witness") from exc
    if any(len(x) > 520 for x in stack):
        raise ValidationError("oversize stack element")
    branches: list[tuple[bool, bool, bool]] = []

    def pop():
        if not stack:
            raise ValidationError("stack underflow")
        return stack.pop()

    def truth(value):
        # Bitcoin's negative-zero convention matters to nonminimal selectors.
        return any(byte != 0 and not (i == len(value) - 1 and byte == 0x80)
                   for i, byte in enumerate(value))

    for token in program:
        text(token, "opcode", 1100)
        active = all(parent and chosen for parent, chosen, _ in branches)
        if token in ("OP_IF", "OP_NOTIF"):
            chosen = False
            if active:
                value = pop()
                chosen = boolean(value) if minimal_if else truth(value)
                if token == "OP_NOTIF":
                    chosen = not chosen
            branches.append((active, chosen, False))
            continue
        if token == "OP_ELSE":
            if not branches or branches[-1][2]:
                raise ValidationError("unbalanced or repeated ELSE")
            parent, chosen, _ = branches.pop()
            branches.append((parent, not chosen, True))
            continue
        if token == "OP_ENDIF":
            if not branches:
                raise ValidationError("unbalanced ENDIF")
            branches.pop()
            continue
        if token not in {"OP_0", "OP_1", "OP_DUP", "OP_DROP", "OP_SWAP", "OP_BOOLAND",
                         "OP_BOOLOR", "OP_NOT", "OP_EQUAL", "OP_VERIFY"} and not token.startswith("PUSH:"):
            raise ValidationError(f"unsupported opcode: {token}")
        pushed = None
        if token.startswith("PUSH:"):
            try:
                pushed = bytes.fromhex(token[5:])
            except ValueError as exc:
                raise ValidationError("invalid PUSH hex") from exc
            if len(pushed) > 520:
                raise ValidationError("oversize PUSH")
        if not active:
            continue
        if pushed is not None:
            stack.append(pushed)
        elif token in ("OP_0", "OP_1"):
            stack.append(b"\x01" if token == "OP_1" else b"")
        elif token == "OP_DUP":
            value = pop()
            stack.extend((value, value))
        elif token == "OP_DROP":
            pop()
        elif token == "OP_SWAP":
            right, left = pop(), pop()
            stack.extend((right, left))
        elif token in ("OP_BOOLAND", "OP_BOOLOR"):
            right, left = boolean(pop()), boolean(pop())
            result = left and right if token == "OP_BOOLAND" else left or right
            stack.append(b"\x01" if result else b"")
        elif token == "OP_NOT":
            stack.append(b"" if boolean(pop()) else b"\x01")
        elif token == "OP_EQUAL":
            stack.append(b"\x01" if pop() == pop() else b"")
        elif token == "OP_VERIFY":
            if not truth(pop()):
                return False
        if len(stack) > 1000:
            raise ValidationError("stack limit exceeded")
    if branches:
        raise ValidationError("unclosed IF")
    return len(stack) == 1 and truth(stack[0])


@dataclass(frozen=True)
class Rule:
    premises: tuple[str, ...]
    conclusion: str

    @classmethod
    def from_dict(cls, data):
        keys(data, {"premises", "conclusion"})
        if not isinstance(data["premises"], list) or not 1 <= len(data["premises"]) <= 32:
            raise ValidationError("rules require 1..32 positive premises")
        values = [text(x, "fact") for x in data["premises"]] + [text(data["conclusion"], "fact")]
        if any(x.startswith("!") for x in values):
            raise ValidationError("absence and negation require an explicit epoch model")
        return cls(tuple(values[:-1]), values[-1])


def closure(facts: set[str], rules: list[Rule], max_rounds: int = 128) -> tuple[set[str], list[list[str]]]:
    """Synchronous least fixed point: rules only read the previous round.

    A round bound exhaustion is an error, never a successful partial result.
    """
    integer(max_rounds, "max_rounds", 1, 1024)
    if len(facts) > 4096 or len(rules) > 4096:
        raise ValidationError("rule engine resource limit")
    for fact in facts:
        text(fact, "fact")
        if fact.startswith("!"):
            raise ValidationError("negative facts require an explicit epoch model")
    known, trace = set(facts), []
    for _ in range(max_rounds):
        additions = {r.conclusion for r in rules if set(r.premises) <= known} - known
        if not additions:
            return known, trace
        trace.append(sorted(additions))
        known.update(additions)
    if any(set(r.premises) <= known and r.conclusion not in known for r in rules):
        raise ValidationError("rule evaluation incomplete at round bound")
    return known, trace
