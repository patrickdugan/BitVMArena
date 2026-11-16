"""Winternitz one-time signatures in the shape used by the BitVM2 bridge.

Mirrors bitvm/src/signatures/winternitz.rs at BitVM/BitVM c620dbfa: a HASH160 chain,
base 16 (4-bit digits), sig_i = H^digit(sk_i), pk_i = H^15(sk_i). A message of n0
digits carries a checksum of 15*n0 - sum(digits) written in n1 base-16 digits (the
number needed for 15*n0). The witness pushes (sig_i, digit_i) pairs, message digits
first (most significant first), then checksum digits, so the last checksum digit is on
top of the stack. Per-digit secrets here are hash160(master || index) from public test
masters; these keys are fixtures, never real signing keys.
"""

from __future__ import annotations

from .bitcoin import hash160, number, ops, push, scriptnum
from .canonical import ValidationError

BASE, TOP = 16, 15


def n1_digits(n0):
    count, limit = 1, TOP * n0
    while BASE ** count <= limit:
        count += 1
    return count


def to_digits(value, count):
    if not 0 <= value < BASE ** count:
        raise ValidationError("value does not fit the Winternitz digit count")
    return [(value >> (4 * (count - 1 - i))) & 15 for i in range(count)]


def checksum_digits(message):
    return to_digits(TOP * len(message) - sum(message), n1_digits(len(message)))


def all_digits(value, n0):
    message = to_digits(value, n0)
    return message + checksum_digits(message)


def secret(master, index):
    return hash160(master + index.to_bytes(4, "big"))


def chain(start, steps):
    for _ in range(steps):
        start = hash160(start)
    return start


def public_keys(master, n0):
    return [chain(secret(master, i), TOP) for i in range(n0 + n1_digits(n0))]


def sign(master, value, n0):
    """[(sig, digit)] for the message digits then the checksum digits."""
    return [(chain(secret(master, i), d), d) for i, d in enumerate(all_digits(value, n0))]


def forward(pair):
    """Hash-forward one signature: the classic Winternitz forgery of digit d -> d + 1."""
    sig, digit = pair
    if digit >= TOP:
        raise ValidationError("digit 15 cannot be hash-forwarded")
    return hash160(sig), digit + 1


def witness_items(pairs):
    """Witness stack items, bottom to top, for the given pairs."""
    items = []
    for sig, digit in pairs:
        items += [sig, scriptnum(digit)]
    return items


def parse_items(items, count):
    if len(items) != 2 * count:
        raise ValidationError("wrong number of Winternitz witness items")
    return [(items[2 * i], int.from_bytes(items[2 * i + 1], "little")) for i in range(count)]


def check_pairs(keys, pairs, n0, checksum=True):
    """Python mirror of the script: chain checks, then the checksum equality."""
    if len(pairs) != len(keys):
        return False
    for pk, (sig, digit) in zip(keys, pairs):
        if not 0 <= digit < BASE or len(sig) != 20 or chain(sig, TOP - digit) != pk:
            return False
    digits = [d for _, d in pairs]
    return not checksum or digits[:n0] + checksum_digits(digits[:n0]) == digits


def value_of(pairs, n0):
    out = 0
    for _, digit in pairs[:n0]:
        out = out * BASE + digit
    return out


# --- script generation ------------------------------------------------------------------

def chain_script(pk):
    """Stack [.. sig, digit] -> [..]; the digit moves to the alt stack."""
    return (ops("DUP") + number(0) + number(BASE) + ops("WITHIN", "VERIFY")      # 0 <= digit < 16
            + ops("DUP", "TOALT", "SWAP", "SIZE") + number(20) + ops("EQUALVERIFY")
            + ops("DUP", "HASH160") * TOP                                         # s0 .. s15
            + number(BASE) + ops("ROLL", "PICK")                                  # s_(15 - digit)
            + push(pk) + ops("EQUALVERIFY") + ops("2DROP") * 8)


def doublings(times):
    return ops("DUP", "ADD") * times


def value_script(keys, n0, checksum=True):
    """Digits come back from the alt stack; leaves the value (checksum checked)."""
    n1 = len(keys) - n0
    n = n0 + n1
    script = ops("FROMALT") * n
    if checksum:
        script += number(n - 1) + ops("PICK")
        for i in range(1, n0):
            script += number(n - i) + ops("PICK", "ADD")
        for j in range(n1):
            script += number(n1 - j) + ops("PICK") + doublings(4 * (n1 - 1 - j)) + ops("ADD")
        script += number(TOP * n0) + ops("NUMEQUALVERIFY")
    script += ops("2DROP") * (n1 // 2) + ops("DROP") * (n1 % 2)
    if n0 > 1:
        script += number(n0 - 1) + ops("ROLL")
        for k in range(1, n0):
            script += doublings(4) + number(n0 - k) + ops("ROLL", "ADD")
    return script


def verify_script(layout, checksum=True):
    """Verify several signed values in one script and leave their values [X, Y, Z...].

    `layout` is [(keys, n0)] in witness order. Chains are checked from the top of the
    stack (the last variable's last digit) downward; the alt stack then returns the
    digits in witness order.
    """
    script = b""
    for keys, _ in reversed(layout):
        for pk in reversed(keys):
            script += chain_script(pk)
    for keys, n0 in layout:
        script += value_script(keys, n0, checksum)
    return script
