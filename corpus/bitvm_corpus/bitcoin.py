"""Native Bitcoin fixtures: serialization, Taproot and test-only BIP340 signing.

This module handles public deterministic test keys only. It is not a wallet or
constant-time cryptographic implementation. Bitcoin Core independently verifies
the generated transactions in the native tracks; the local checks here exist so
saved evidence can be audited offline.
"""

from __future__ import annotations

import functools
import hashlib
import struct
from dataclasses import dataclass, field

from .canonical import ValidationError, integer

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
# Bitcoin Core functional-test H_POINT; no known secret key.
NUMS = bytes.fromhex("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
P2A = bytes.fromhex("51024e73")     # pay-to-anchor: keyless, spent with an empty witness
LEAF_VERSION = 0xC0
OP = {"0": 0x00, "1NEGATE": 0x4f, "1": 0x51, "IF": 0x63, "NOTIF": 0x64, "ELSE": 0x67, "ENDIF": 0x68,
      "VERIFY": 0x69, "RETURN": 0x6a, "TOALT": 0x6b, "FROMALT": 0x6c, "2DROP": 0x6d, "2DUP": 0x6e,
      "DROP": 0x75, "DUP": 0x76, "NIP": 0x77, "OVER": 0x78, "PICK": 0x79, "ROLL": 0x7a,
      "ROT": 0x7b, "SWAP": 0x7c, "SIZE": 0x82, "EQUAL": 0x87, "EQUALVERIFY": 0x88,
      "1ADD": 0x8b, "NOT": 0x91, "0NOTEQUAL": 0x92, "ADD": 0x93, "SUB": 0x94,
      "BOOLAND": 0x9a, "BOOLOR": 0x9b, "NUMEQUAL": 0x9c, "NUMEQUALVERIFY": 0x9d,
      "NUMNOTEQUAL": 0x9e, "LESSTHAN": 0x9f, "GREATERTHAN": 0xa0, "GREATERTHANOREQUAL": 0xa2,
      "MIN": 0xa3, "MAX": 0xa4, "WITHIN": 0xa5, "SHA256": 0xa8, "HASH160": 0xa9,
      "CHECKSIG": 0xac, "CHECKSIGVERIFY": 0xad, "CLTV": 0xb1, "CSV": 0xb2}
SIGHASH_DEFAULT, SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, ANYONECANPAY = 0, 1, 2, 3, 0x80


def sha(data):
    return hashlib.sha256(data).digest()


def tagged(tag, data):
    prefix = sha(tag.encode("ascii"))
    return sha(prefix + prefix + data)


# --- RIPEMD-160 (fallback when the local OpenSSL omits it) -----------------------------

_RL = [list(range(16)),
       [7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8],
       [3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12],
       [1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2],
       [4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]]
_RR = [[5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12],
       [6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2],
       [15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13],
       [8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14],
       [12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]]
_SL = [[11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8],
       [7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12],
       [11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5],
       [11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12],
       [9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]]
_SR = [[8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6],
       [9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11],
       [9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5],
       [15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8],
       [8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]]
_KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
_KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
_M32 = 0xFFFFFFFF


def _f(j, x, y, z):
    if j == 0:
        return x ^ y ^ z
    if j == 1:
        return (x & y) | (~x & _M32 & z)
    if j == 2:
        return (x | (~y & _M32)) ^ z
    if j == 3:
        return (x & z) | (y & (~z & _M32))
    return x ^ (y | (~z & _M32))


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & _M32


def ripemd160_py(data):
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    message = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + struct.pack("<Q", 8 * len(data))
    for offset in range(0, len(message), 64):
        x = struct.unpack("<16I", message[offset:offset + 64])
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for rnd in range(5):
            for i in range(16):
                t = _rol((al + _f(rnd, bl, cl, dl) + x[_RL[rnd][i]] + _KL[rnd]) & _M32, _SL[rnd][i]) + el
                al, el, dl, cl, bl = el, dl, _rol(cl, 10), bl, t & _M32
                t = _rol((ar + _f(4 - rnd, br, cr, dr) + x[_RR[rnd][i]] + _KR[rnd]) & _M32, _SR[rnd][i]) + er
                ar, er, dr, cr, br = er, dr, _rol(cr, 10), br, t & _M32
        t = (h[1] + cl + dr) & _M32
        h[1] = (h[2] + dl + er) & _M32
        h[2] = (h[3] + el + ar) & _M32
        h[3] = (h[4] + al + br) & _M32
        h[4] = (h[0] + bl + cr) & _M32
        h[0] = t
    return struct.pack("<5I", *h)


def hash160(data):
    try:
        inner = hashlib.new("ripemd160", sha(data)).digest()
    except ValueError:
        inner = ripemd160_py(sha(data))
    return inner


# --- serialization ---------------------------------------------------------------------

def compact(value):
    integer(value, "CompactSize", 0, 2**64 - 1)
    if value < 253:
        return bytes([value])
    if value <= 0xffff:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xffffffff:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def vector(data):
    return compact(len(data)) + data


def push(data):
    if len(data) > 520:
        raise ValidationError("native push exceeds stack element limit")
    if not data:
        return b"\x00"
    if len(data) == 1 and 1 <= data[0] <= 16:
        return bytes([0x50 + data[0]])
    if len(data) <= 75:
        return bytes([len(data)]) + data
    if len(data) <= 255:
        return b"\x4c" + bytes([len(data)]) + data
    return b"\x4d" + struct.pack("<H", len(data)) + data


def scriptnum(value):
    """Minimal CScriptNum encoding (as a stack element, not a push)."""
    integer(value, "Script number", -(2**31 - 1), 2**31 - 1)
    negative, magnitude, result = value < 0, abs(value), bytearray()
    while magnitude:
        result.append(magnitude & 255)
        magnitude >>= 8
    if result and result[-1] & 128:
        result.append(128 if negative else 0)
    elif negative:
        result[-1] |= 128
    return bytes(result)


def number(value):
    return push(scriptnum(value))


def ops(*names):
    return bytes(OP[name] for name in names)


def op_return(data):
    if len(data) > 80:
        raise ValidationError("OP_RETURN payload exceeds the standard 80 bytes")
    return bytes([OP["RETURN"]]) + push(data)


# --- secp256k1 / BIP340 ----------------------------------------------------------------

def add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x, y = left
    u, v = right
    if x == u and (y != v or y == 0):
        return None
    slope = ((3 * x * x) * pow(2 * y, -1, P) if left == right
             else (v - y) * pow((u - x) % P, -1, P)) % P
    out_x = (slope * slope - x - u) % P
    return out_x, (slope * (x - out_x) - y) % P


def _jacobian_multiply(scalar, point):
    """Double-and-add in Jacobian coordinates; one inversion at the end."""
    def double(p):
        x, y, z = p
        if y == 0:
            return (0, 0, 0)
        s = 4 * x * y * y % P
        m = 3 * x * x % P
        nx = (m * m - 2 * s) % P
        return nx, (m * (s - nx) - 8 * pow(y, 4, P)) % P, 2 * y * z % P

    def plus(p, q):
        if p[2] == 0:
            return q
        if q[2] == 0:
            return p
        x1, y1, z1 = p
        x2, y2, z2 = q
        z1s, z2s = z1 * z1 % P, z2 * z2 % P
        u1, u2 = x1 * z2s % P, x2 * z1s % P
        s1, s2 = y1 * z2s * z2 % P, y2 * z1s * z1 % P
        if u1 == u2:
            return double(p) if s1 == s2 else (0, 0, 0)
        h, r = (u2 - u1) % P, (s2 - s1) % P
        h2 = h * h % P
        h3 = h2 * h % P
        nx = (r * r - h3 - 2 * u1 * h2) % P
        return nx, (r * (u1 * h2 - nx) - s1 * h3) % P, h * z1 * z2 % P

    result, addend = (0, 0, 0), (point[0], point[1], 1)
    while scalar:
        if scalar & 1:
            result = plus(result, addend)
        addend = double(addend)
        scalar >>= 1
    if result[2] == 0:
        return None
    zinv = pow(result[2], -1, P)
    return result[0] * zinv * zinv % P, result[1] * zinv * zinv * zinv % P


def multiply(scalar, point=G):
    scalar %= N
    if scalar == 0 or point is None:
        return None
    return _jacobian_multiply(scalar, point)


def lift(key):
    if len(key) != 32:
        raise ValidationError("x-only key must be 32 bytes")
    x = int.from_bytes(key, "big")
    if x >= P:
        raise ValidationError("invalid x coordinate")
    square = (pow(x, 3, P) + 7) % P
    y = pow(square, (P + 1) // 4, P)
    if y * y % P != square:
        raise ValidationError("key is not on secp256k1")
    return x, y if y % 2 == 0 else P - y


@functools.lru_cache(maxsize=4096)
def public(secret):
    integer(secret, "test secret", 1, N - 1)
    return multiply(secret)[0].to_bytes(32, "big")


def sign(message, secret, auxiliary=bytes(32)):
    """BIP340 fixture signature with deterministic public test entropy."""
    integer(secret, "test secret", 1, N - 1)
    if len(auxiliary) != 32:
        raise ValidationError("auxiliary randomness must be 32 bytes")
    key = multiply(secret)
    d = secret if key[1] % 2 == 0 else N - secret
    mask = tagged("BIP0340/aux", auxiliary)
    masked = bytes(a ^ b for a, b in zip(d.to_bytes(32, "big"), mask))
    pub = key[0].to_bytes(32, "big")
    k = int.from_bytes(tagged("BIP0340/nonce", masked + pub + message), "big") % N
    if k == 0:
        raise ValidationError("zero signing nonce")
    r = multiply(k)
    if r[1] % 2:
        k = N - k
    rx = r[0].to_bytes(32, "big")
    challenge = int.from_bytes(tagged("BIP0340/challenge", rx + pub + message), "big") % N
    return rx + ((k + challenge * d) % N).to_bytes(32, "big")


def verify_signature(message, key, signature):
    if len(signature) != 64:
        return False
    try:
        point = lift(key)
    except ValidationError:
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r >= P or s >= N:
        return False
    e = int.from_bytes(tagged("BIP0340/challenge", signature[:32] + key + message), "big") % N
    result = add(multiply(s), multiply((N - e) % N, point))
    return result is not None and result[1] % 2 == 0 and result[0] == r


# --- Taproot ---------------------------------------------------------------------------

def leaf_hash(script, version=LEAF_VERSION):
    return tagged("TapLeaf", bytes([version]) + vector(script))


def branch_hash(left, right):
    return tagged("TapBranch", min(left, right) + max(left, right))


def _merkle(hashes):
    """Balanced tree over leaf hashes; returns (root, per-leaf sibling paths)."""
    if len(hashes) == 1:
        return hashes[0], [[]]
    middle = (len(hashes) + 1) // 2
    left_root, left_paths = _merkle(hashes[:middle])
    right_root, right_paths = _merkle(hashes[middle:])
    return (branch_hash(left_root, right_root),
            [path + [right_root] for path in left_paths] + [path + [left_root] for path in right_paths])


@functools.lru_cache(maxsize=4096)
def _taproot(internal_key, scripts):
    if scripts:
        root, paths = _merkle([leaf_hash(script) for script in scripts])
    else:
        root, paths = b"", []
    tweak = int.from_bytes(tagged("TapTweak", internal_key + root), "big")
    if tweak >= N:
        raise ValidationError("invalid Taproot tweak")
    point = add(lift(internal_key), multiply(tweak))
    if point is None:
        raise ValidationError("infinite Taproot output")
    return root, tuple(tuple(path) for path in paths), point, tweak


@dataclass(frozen=True)
class Leaf:
    script: bytes
    control: bytes
    script_pubkey: bytes

    @property
    def leaf_hash(self):
        return leaf_hash(self.script)


@dataclass(frozen=True)
class TapTree:
    """A P2TR output: internal key plus an ordered tuple of tapscript leaves."""
    scripts: tuple
    internal_key: bytes = NUMS

    @property
    def _info(self):
        return _taproot(self.internal_key, tuple(self.scripts))

    @property
    def merkle_root(self):
        return self._info[0]

    @property
    def output_point(self):
        return self._info[2]

    @property
    def output_key(self):
        return self.output_point[0].to_bytes(32, "big")

    @property
    def script_pubkey(self):
        return b"\x51\x20" + self.output_key

    def control(self, index):
        parity = self.output_point[1] & 1
        return bytes([LEAF_VERSION | parity]) + self.internal_key + b"".join(self._info[1][index])

    def leaf(self, index):
        return Leaf(self.scripts[index], self.control(index), self.script_pubkey)

    def tweaked_secret(self, secret):
        """Key-path secret for an internal key whose secret is known (test keys only)."""
        point = multiply(secret)
        if point[0].to_bytes(32, "big") != self.internal_key:
            raise ValidationError("secret does not match the internal key")
        d = secret if point[1] % 2 == 0 else N - secret
        return (d + self._info[3]) % N


@dataclass(frozen=True)
class TapLeaf:
    """Single-leaf output, kept for the primitive track's API."""
    script: bytes
    internal_key: bytes = NUMS

    @property
    def _tree(self):
        return TapTree((self.script,), self.internal_key)

    @property
    def leaf_hash(self):
        return leaf_hash(self.script)

    @property
    def output_point(self):
        return self._tree.output_point

    @property
    def script_pubkey(self):
        return self._tree.script_pubkey

    @property
    def control(self):
        return self._tree.control(0)


def p2tr_key(key):
    """Key-path-only output for an x-only key (BIP86-style tweak with an empty root)."""
    return TapTree((), key)


def verify_commitment(script_pubkey, script, control):
    """BIP341 script-path commitment check, independent of Core."""
    if len(script_pubkey) != 34 or script_pubkey[:2] != b"\x51\x20":
        return False
    if len(control) < 33 or (len(control) - 33) % 32 or len(control) > 33 + 32 * 128:
        return False
    if control[0] & 0xfe != LEAF_VERSION:
        return False
    try:
        internal = lift(control[1:33])
    except ValidationError:
        return False
    node = leaf_hash(script, control[0] & 0xfe)
    for offset in range(33, len(control), 32):
        node = branch_hash(node, control[offset:offset + 32])
    tweak = int.from_bytes(tagged("TapTweak", control[1:33] + node), "big")
    if tweak >= N:
        return False
    point = add(internal, multiply(tweak))
    return (point is not None and point[0].to_bytes(32, "big") == script_pubkey[2:]
            and point[1] & 1 == control[0] & 1)


# --- transactions ----------------------------------------------------------------------

@dataclass
class TxInput:
    txid: str
    vout: int
    amount: int
    script_pubkey: bytes
    sequence: int = 0xfffffffd
    witness: list = field(default_factory=list)

    def outpoint(self):
        return bytes.fromhex(self.txid)[::-1] + struct.pack("<I", self.vout)

    def serialize(self):
        return self.outpoint() + b"\x00" + struct.pack("<I", self.sequence)


class _Reader:
    def __init__(self, data):
        self.data, self.offset = data, 0

    def take(self, size):
        if self.offset + size > len(self.data):
            raise ValidationError("truncated transaction")
        chunk = self.data[self.offset:self.offset + size]
        self.offset += size
        return chunk

    def compact(self):
        first = self.take(1)[0]
        if first < 253:
            return first
        return int.from_bytes(self.take({253: 2, 254: 4, 255: 8}[first]), "little")

    def vector(self):
        return self.take(self.compact())


@dataclass
class Transaction:
    inputs: list
    outputs: list
    locktime: int = 0
    version: int = 2

    def output_bytes(self):
        return b"".join(struct.pack("<q", value) + vector(script) for value, script in self.outputs)

    def serialize(self, witness=True):
        has_witness = witness and any(txin.witness for txin in self.inputs)
        return (struct.pack("<i", self.version) + (b"\x00\x01" if has_witness else b"")
                + compact(len(self.inputs)) + b"".join(txin.serialize() for txin in self.inputs)
                + compact(len(self.outputs)) + self.output_bytes()
                + (b"".join(compact(len(txin.witness)) + b"".join(vector(item) for item in txin.witness)
                            for txin in self.inputs) if has_witness else b"")
                + struct.pack("<I", self.locktime))

    @property
    def txid(self):
        return sha(sha(self.serialize(False)))[::-1].hex()

    @property
    def wtxid(self):
        return sha(sha(self.serialize()))[::-1].hex()

    @property
    def vsize(self):
        base, total = len(self.serialize(False)), len(self.serialize())
        return (3 * base + total + 3) // 4

    @classmethod
    def parse(cls, raw):
        """Parse a serialized transaction. Spent amounts/scripts are unknown (zero/empty)."""
        reader = _Reader(bytes.fromhex(raw) if isinstance(raw, str) else raw)
        version = struct.unpack("<i", reader.take(4))[0]
        segwit = reader.data[reader.offset:reader.offset + 2] == b"\x00\x01"
        if segwit:
            reader.take(2)
        inputs = []
        for _ in range(reader.compact()):
            outpoint = reader.take(36)
            if reader.vector():
                raise ValidationError("native fixtures never carry a scriptSig")
            sequence = struct.unpack("<I", reader.take(4))[0]
            inputs.append(TxInput(outpoint[:32][::-1].hex(), struct.unpack("<I", outpoint[32:])[0], 0, b"", sequence))
        outputs = []
        for _ in range(reader.compact()):
            value = struct.unpack("<q", reader.take(8))[0]
            outputs.append((value, reader.vector()))
        if segwit:
            for txin in inputs:
                txin.witness = [reader.vector() for _ in range(reader.compact())]
        locktime = struct.unpack("<I", reader.take(4))[0]
        if reader.offset != len(reader.data):
            raise ValidationError("trailing bytes after transaction")
        return cls(inputs, outputs, locktime, version)

    def sighash(self, input_index, leaf, hash_type=SIGHASH_DEFAULT):
        """BIP341/342 signature message (no annex, no code separator).

        `leaf` is a script-path leaf (anything with `leaf_hash`) or None for the key path.
        All six standard hash types are supported; each input must carry its spent
        amount and scriptPubKey.
        """
        if hash_type not in (0, 1, 2, 3, 0x81, 0x82, 0x83):
            raise ValidationError("unsupported sighash type")
        integer(input_index, "input index", 0, len(self.inputs) - 1)
        base = hash_type & 3
        msg = bytes([hash_type]) + struct.pack("<iI", self.version, self.locktime)
        if not hash_type & ANYONECANPAY:
            msg += sha(b"".join(i.outpoint() for i in self.inputs))
            msg += sha(b"".join(struct.pack("<q", i.amount) for i in self.inputs))
            msg += sha(b"".join(vector(i.script_pubkey) for i in self.inputs))
            msg += sha(b"".join(struct.pack("<I", i.sequence) for i in self.inputs))
        if base not in (SIGHASH_NONE, SIGHASH_SINGLE):
            msg += sha(self.output_bytes())
        msg += b"\x02" if leaf is not None else b"\x00"
        txin = self.inputs[input_index]
        if hash_type & ANYONECANPAY:
            msg += txin.outpoint() + struct.pack("<q", txin.amount)
            msg += vector(txin.script_pubkey) + struct.pack("<I", txin.sequence)
        else:
            msg += struct.pack("<I", input_index)
        if base == SIGHASH_SINGLE:
            if input_index >= len(self.outputs):
                raise ValidationError("SIGHASH_SINGLE without a matching output")
            value, script = self.outputs[input_index]
            msg += sha(struct.pack("<q", value) + vector(script))
        if leaf is not None:
            msg += leaf.leaf_hash + b"\x00" + b"\xff\xff\xff\xff"
        return tagged("TapSighash", b"\x00" + msg)

    def signature(self, input_index, leaf, secret, hash_type=SIGHASH_DEFAULT):
        sig = sign(self.sighash(input_index, leaf, hash_type), secret)
        return sig if hash_type == SIGHASH_DEFAULT else sig + bytes([hash_type])


def check_signature(tx, input_index, leaf, key, signature):
    """Local BIP340 check of a witness signature against a parsed+annotated transaction."""
    if len(signature) == 64:
        hash_type = SIGHASH_DEFAULT
    elif len(signature) == 65 and signature[64] != 0:
        hash_type = signature[64]
    else:
        return False
    try:
        message = tx.sighash(input_index, leaf, hash_type)
    except ValidationError:
        return False
    return verify_signature(message, key, signature[:64])


def opening(wire):
    """Hash-bound canonical bit opening, with no hypothetical opcodes."""
    zero, one = (sha(f"arena-native:{wire}:{value}".encode()) for value in (0, 1))
    return bit_opening(sha(zero), sha(one)), (zero, one)


def bit_opening(hash0, hash1):
    """Consume a preimage, leave 0/1 if it opens hash0/hash1, fail otherwise."""
    return (ops("SHA256", "DUP") + push(hash0) + ops("EQUAL", "IF", "DROP", "0", "ELSE")
            + push(hash1) + ops("EQUALVERIFY", "1", "ENDIF"))
