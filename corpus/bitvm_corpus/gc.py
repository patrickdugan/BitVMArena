"""A small free-XOR + half-gates garbling engine for the BitVM3 track.

Same construction family as the garbled-snark-verifier engine behind M14 (one global
offset Delta per garbling, half-gates AND tables, point-and-permute), at toy scale and
with SHA-256 as the gate hash. It decides a real statement, so the evaluator's output
label is earned, not asserted. Not constant-time and not for production keys.

Circuit: accept(proof) == 1 iff a + b == statement over 16 bits with no carry out,
where proof = (a, b) is 32 input bits and the statement is a circuit constant (as M14
pins its statement). A "false claim" is a proof that does not satisfy the statement.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .canonical import ValidationError, integer

LABEL = 16
WIDTH = 16


def prf(seed: bytes, *parts) -> bytes:
    h = hashlib.sha256(b"bitvm-arena/gc/prf\x00" + seed)
    for part in parts:
        data = part if isinstance(part, bytes) else str(part).encode()
        h.update(len(data).to_bytes(4, "big") + data)
    return h.digest()[:LABEL]


def gate_hash(label: bytes, tweak: int) -> bytes:
    return hashlib.sha256(b"bitvm-arena/gc/H\x00" + label + tweak.to_bytes(8, "big")).digest()[:LABEL]


def xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def lsb(label: bytes) -> int:
    return label[-1] & 1


ZERO = bytes(LABEL)


@dataclass
class Circuit:
    """Boolean circuit over XOR / AND / NOT with constants folded at build time."""
    inputs: int
    gates: list = field(default_factory=list)   # (op, a, b, out)
    outputs: list = field(default_factory=list)
    wires: int = 0

    def __post_init__(self):
        self.wires = self.inputs

    def _new(self):
        self.wires += 1
        return self.wires - 1

    def xor(self, a, b):
        out = self._new()
        self.gates.append(("XOR", a, b, out))
        return out

    def and_(self, a, b):
        out = self._new()
        self.gates.append(("AND", a, b, out))
        return out

    def not_(self, a):
        out = self._new()
        self.gates.append(("NOT", a, None, out))
        return out

    def evaluate(self, bits):
        if len(bits) != self.inputs:
            raise ValidationError("wrong number of input bits")
        values = list(bits) + [None] * (self.wires - self.inputs)
        for op, a, b, out in self.gates:
            values[out] = (values[a] ^ values[b] if op == "XOR" else
                           values[a] & values[b] if op == "AND" else 1 - values[a])
        return [values[w] for w in self.outputs]

    @property
    def and_count(self):
        return sum(op == "AND" for op, *_ in self.gates)


def statement_circuit(statement: int, width: int = WIDTH) -> Circuit:
    """accept = (a + b == statement) with no carry out; statement folded as a constant."""
    integer(statement, "statement", 0, 2**width - 1)
    c = Circuit(2 * width)
    a, b = list(range(width)), list(range(width, 2 * width))
    terms, carry = [], None
    for i in range(width):
        if carry is None:
            total, carry = c.xor(a[i], b[i]), c.and_(a[i], b[i])
        else:
            axc, bxc = c.xor(a[i], carry), c.xor(b[i], carry)
            total = c.xor(axc, b[i])
            carry = c.xor(carry, c.and_(axc, bxc))
        terms.append(total if statement >> i & 1 else c.not_(total))
    terms.append(c.not_(carry))
    while len(terms) > 1:
        nxt = [c.and_(terms[i], terms[i + 1]) for i in range(0, len(terms) - 1, 2)]
        if len(terms) % 2:
            nxt.append(terms[-1])
        terms = nxt
    c.outputs = [terms[0]]
    return c


def proof_bits(a: int, b: int, width: int = WIDTH):
    integer(a, "proof a", 0, 2**width - 1)
    integer(b, "proof b", 0, 2**width - 1)
    return [a >> i & 1 for i in range(width)] + [b >> i & 1 for i in range(width)]


@dataclass
class Garbling:
    """Garbler's full view. Only `tables`, `commitment` and output-label hashes are public."""
    statement: int
    delta: bytes
    zero_labels: list          # label meaning 0, per wire
    tables: list               # (TG, TE) per AND gate, in gate order
    circuit: Circuit

    def input_label(self, wire, bit):
        return self.zero_labels[wire] if bit == 0 else xor(self.zero_labels[wire], self.delta)

    def input_labels(self, bits):
        return [self.input_label(i, bit) for i, bit in enumerate(bits)]

    def output_label(self, bit):
        return self.input_label(self.circuit.outputs[0], bit)

    @property
    def accept_label(self):
        return self.output_label(1)

    @property
    def reject_label(self):
        return self.output_label(0)

    def public(self):
        return {"statement": self.statement, "width": WIDTH, "and_gates": self.circuit.and_count,
                "tables": [[tg.hex(), te.hex()] for tg, te in self.tables],
                "accept_label_sha256": hashlib.sha256(self.accept_label).hexdigest(),
                "reject_label_sha256": hashlib.sha256(self.reject_label).hexdigest(),
                "ciphertext_commitment": self.commitment}

    @property
    def commitment(self):
        h = hashlib.sha256(b"bitvm-arena/gc/ciphertexts\x00")
        for tg, te in self.tables:
            h.update(tg + te)
        return h.hexdigest()


def derive_keys(seed: bytes, delta_seed: bytes | None = None):
    """Delta and input-label key from a garbling seed. `delta_seed` overrides Delta's source."""
    raw = bytearray(prf(delta_seed if delta_seed is not None else seed, "delta"))
    raw[-1] |= 1
    return bytes(raw), seed


def garble(statement: int, seed: bytes, *, delta_seed: bytes | None = None,
           label_seed: bytes | None = None) -> Garbling:
    circuit = statement_circuit(statement)
    delta, _ = derive_keys(seed, delta_seed)
    labels_from = label_seed if label_seed is not None else seed
    zero = [prf(labels_from, "input", i) for i in range(circuit.inputs)] + [None] * (circuit.wires - circuit.inputs)
    tables = []
    for index, (op, a, b, out) in enumerate(circuit.gates):
        if op == "XOR":
            zero[out] = xor(zero[a], zero[b])
        elif op == "NOT":
            zero[out] = xor(zero[a], delta)
        else:
            a0, b0 = zero[a], zero[b]
            a1, b1 = xor(a0, delta), xor(b0, delta)
            pa, pb = lsb(a0), lsb(b0)
            j, k = 2 * index, 2 * index + 1
            tg = xor(xor(gate_hash(a0, j), gate_hash(a1, j)), delta if pb else ZERO)
            wg0 = xor(gate_hash(a0, j), tg if pa else ZERO)
            te = xor(xor(gate_hash(b0, k), gate_hash(b1, k)), a0)
            we0 = xor(gate_hash(b0, k), xor(te, a0) if pb else ZERO)
            zero[out] = xor(wg0, we0)
            tables.append((tg, te))
    return Garbling(statement, delta, zero, tables, circuit)


def evaluate(statement: int, tables, input_labels):
    """Evaluator's view: public circuit + tables + one label per input wire -> output label."""
    circuit = statement_circuit(statement)
    if len(input_labels) != circuit.inputs or len(tables) != circuit.and_count:
        raise ValidationError("labels or tables do not fit the circuit")
    labels = list(input_labels) + [None] * (circuit.wires - circuit.inputs)
    table = iter(tables)
    for index, (op, a, b, out) in enumerate(circuit.gates):
        if op == "XOR":
            labels[out] = xor(labels[a], labels[b])
        elif op == "NOT":
            labels[out] = labels[a]
        else:
            tg, te = next(table)
            wa, wb = labels[a], labels[b]
            j, k = 2 * index, 2 * index + 1
            wg = xor(gate_hash(wa, j), tg if lsb(wa) else ZERO)
            we = xor(gate_hash(wb, k), xor(te, wa) if lsb(wb) else ZERO)
            labels[out] = xor(wg, we)
    return labels[circuit.outputs[0]]


def decode(label: bytes, accept_sha256: str, reject_sha256: str):
    digest = hashlib.sha256(label).hexdigest()
    return "accept" if digest == accept_sha256 else "reject" if digest == reject_sha256 else "invalid"


def check_opening(statement: int, seed: bytes, public: dict, **derivation) -> bool:
    """Cut-and-choose check: regarble from the revealed seed and compare commitments."""
    regarbled = garble(statement, seed, **derivation).public()
    return all(regarbled[key] == public[key] for key in
               ("ciphertext_commitment", "accept_label_sha256", "reject_label_sha256"))
