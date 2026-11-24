"""Covert channels inside BitVM3 setup traffic, and passive monitors that look for them.

Colluding setup parties (track `bitvm3-setup`, ceremony.py) may only talk through the
honest protocol messages they are supposed to send anyway. This module holds the channels
they use and the monitors a defender runs over the same traffic.

The text channels are ports of the scripted reference codecs of the Spiral stego bench
(patrickdugan/Spiral, src/spiral_ln/stego/codecs.py and monitors.py), moved from prose to
JSON protocol messages:

* separator slots (Spiral's whitespace codec): one bit per `,` or `:` outside strings,
  compact = 0, followed by a space = 1;
* hex-case slots (Spiral's synonym codec): one bit per letter a-f inside a hex field,
  lower = 0, upper = 1. `bytes.fromhex` reads both, so the value does not change;
* key order (Spiral's marker codec): the order of a message's top-level keys, a
  permutation read as a Lehmer code.

The same three choices also work at coarser grain: a whole message (one style for every
slot of the message), or a whole session (one style for every message a party sends),
which is how honest clients built on different JSON libraries differ from each other.

Two content channels have no counterpart in a text bench:

* salt fields: the 16-byte nonce every setup message carries is supposed to be random. A
  colluder fills it with its payload, masked by a keystream from the colluders' shared
  key, or (the naive variant) with the raw payload padded with zero bytes;
* the kleptographic signature nonce: a BIP340 signer derives its nonce k from the shared
  key and the message instead of from its own secret. Every signature still verifies and
  looks like any other, but whoever holds the shared key recomputes k and solves
  s = k + e*d for the signer's secret key d. One presignature leaks the whole key.

Everything here is deterministic and dependency-free. The detection measurement in
`study()` reports, per channel and payload size, how often each monitor flags a session at
a threshold calibrated on honest sessions, its AUROC, and whether the payload survives a
hub that re-serializes every message canonically.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import math

from .bitcoin import N, multiply, public, sign, tagged
from .canonical import ValidationError, canonical

HEX_MIN = 16                  # characters; shorter strings are never treated as hex carriers
NONCE_BYTES = 16
SIGNATURE_FIELDS = ("sig", "claim", "payout", "disprove")
TAG_BITS = 8


# --- bits, keystream, framing ----------------------------------------------------------

def to_bits(data: bytes, count=None):
    bits = [byte >> (7 - i) & 1 for byte in data for i in range(8)]
    return bits if count is None else bits[:count]


def from_bits(bits):
    padded = list(bits) + [0] * (-len(bits) % 8)
    return bytes(int("".join(map(str, padded[i:i + 8])), 2) for i in range(0, len(padded), 8))


def int_bits(value, width):
    return [value >> (width - 1 - i) & 1 for i in range(width)]


def bits_int(bits):
    value = 0
    for bit in bits:
        value = value << 1 | bit
    return value


def keystream(key: bytes, context: str, count: int):
    out, counter = [], 0
    while len(out) < count:
        block = hashlib.sha256(b"bitvm-arena/stego/keystream\x00" + key + context.encode() + b"\x00"
                               + counter.to_bytes(4, "big")).digest()
        out += to_bits(block)
        counter += 1
    return out[:count]


def mask(bits, key, context):
    return [b ^ k for b, k in zip(bits, keystream(key, context, len(bits)))]


def tag(key, context, payload, size=TAG_BITS):
    digest = hashlib.sha256(b"bitvm-arena/stego/tag\x00" + key + context.encode() + b"\x00"
                            + bytes(payload)).digest()
    return to_bits(digest, size)


def seal(payload, key, context):
    """Payload bits plus an authentication tag, masked: what the carrier holds."""
    return mask(list(payload) + tag(key, context, payload), key, context)


def unseal(carrier, key, context, size):
    """The payload of `size` bits, or None when the carrier does not hold a valid frame."""
    if len(carrier) < size + TAG_BITS:
        return None
    clear = mask(carrier[:size + TAG_BITS], key, context)
    payload = clear[:size]
    return payload if clear[size:] == tag(key, context, payload) else None


# --- styled JSON rendering -------------------------------------------------------------

def is_hex(value):
    if not isinstance(value, str) or len(value) < HEX_MIN or len(value) % 2:
        return False
    return all(c in "0123456789abcdef" for c in value.lower())


class _Writer:
    def __init__(self, sep=(), case=(), order=None, spaced=0, upper=0):
        self.sep, self.case, self.order = list(sep), list(case), order
        self.spaced, self.upper = spaced, upper
        self.si = self.ci = 0
        self.out = []

    def separator(self, char):
        bit = self.sep[self.si] if self.si < len(self.sep) else self.spaced
        self.si += 1
        self.out.append(char + " " if bit else char)

    def string(self, value):
        if is_hex(value):
            chars = []
            for c in value.lower():
                if c in "abcdef":
                    bit = self.case[self.ci] if self.ci < len(self.case) else self.upper
                    self.ci += 1
                    chars.append(c.upper() if bit else c)
                else:
                    chars.append(c)
            value = "".join(chars)
        self.out.append(json.dumps(value))

    def value(self, value, top=False):
        if isinstance(value, dict):
            keys = list(self.order) if top and self.order is not None else sorted(value)
            if sorted(keys) != sorted(value):
                raise ValidationError("key order must be a permutation of the message keys")
            self.out.append("{")
            for i, key in enumerate(keys):
                if i:
                    self.separator(",")
                self.out.append(json.dumps(key))
                self.separator(":")
                self.value(value[key])
            self.out.append("}")
        elif isinstance(value, list):
            self.out.append("[")
            for i, item in enumerate(value):
                if i:
                    self.separator(",")
                self.value(item)
            self.out.append("]")
        elif isinstance(value, str):
            self.string(value)
        else:
            self.out.append(json.dumps(value, allow_nan=False))


def render(obj, sep=(), case=(), order=None, style=(0, 0, 0)):
    """`obj` as JSON text. `style` = (spaced, upper, reversed) sets every slot of the
    message; `sep` and `case` set individual slots (in text order) and override the style;
    `order` is the top-level key order (default: sorted, or reverse-sorted under style)."""
    if order is None and style[2] and isinstance(obj, dict):
        order = sorted(obj, reverse=True)
    writer = _Writer(sep, case, order, style[0], style[1])
    writer.value(obj, top=True)
    return "".join(writer.out)


def slots(obj):
    """(separator slots, hex-case slots, top-level keys) of a message object."""
    counter = _Writer()
    counter.value(obj, top=True)
    return counter.si, counter.ci, len(obj) if isinstance(obj, dict) else 0


def parse(text):
    """The message object as written (top-level key order and hex case preserved)."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValidationError(f"message is not JSON: {exc}") from exc


def normalize(value):
    """Protocol content: hex fields lowercased. Two texts with the same content mean the
    same thing to an honest party, whatever their separators, hex case or key order."""
    if isinstance(value, dict):
        return {key: normalize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize(item) for item in value]
    return value.lower() if is_hex(value) else value


def content(text):
    return normalize(parse(text))


def recanonicalize(text):
    """What a canonicalizing hub delivers: the same content, canonical bytes."""
    return canonical(content(text))


def read_slots(text):
    """Separator bits and hex-case bits of a message text, in text order."""
    sep, case, i, n = [], [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '"':
            j = i + 1
            while text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            raw = text[i + 1:j]
            if is_hex(raw):
                case += [1 if ch.isupper() else 0 for ch in raw if ch.lower() in "abcdef"]
            i = j + 1
        elif c in ",:":
            sep.append(1 if i + 1 < n and text[i + 1] == " " else 0)
            i += 1
        else:
            i += 1
    return sep, case


def key_order(text):
    obj = parse(text)
    return list(obj) if isinstance(obj, dict) else []


# --- key order as a Lehmer code ----------------------------------------------------------

def order_capacity(n):
    return int(math.log2(math.factorial(n))) if n > 1 else 0


def permutation(keys, index):
    """The `index`-th permutation of sorted(keys)."""
    pool, out = sorted(keys), []
    for i in range(len(pool), 0, -1):
        f = math.factorial(i - 1)
        out.append(pool.pop(index // f))
        index %= f
    return out


def permutation_index(order):
    pool, index = sorted(order), 0
    for i, key in enumerate(order):
        position = pool.index(key)
        index += position * math.factorial(len(order) - 1 - i)
        pool.pop(position)
    return index


def style_of(text):
    """Message-wide style (spaced, upper, order class) by majority; order class is 0 for
    sorted keys, 1 for reverse-sorted keys and 2 for anything else."""
    sep, case = read_slots(text)
    keys = key_order(text)
    spaced = int(sum(sep) * 2 > len(sep)) if sep else 0
    upper = int(sum(case) * 2 > len(case)) if case else 0
    order = 0 if keys == sorted(keys) else 1 if keys == sorted(keys, reverse=True) else 2
    return spaced, upper, order


# --- carriers used by the live ceremony ------------------------------------------------

def embed_case(obj, payload, key, context):
    """Render `obj` with the sealed payload in its first hex-case slots."""
    carrier = seal(payload, key, context)
    if slots(obj)[1] < len(carrier):
        raise ValidationError("message has too few hex-case slots for the payload")
    return render(obj, case=carrier)


def extract_case(text, key, context, size):
    return unseal(read_slots(text)[1], key, context, size)


def embed_format(obj, payload, key, context):
    carrier = seal(payload, key, context)
    if slots(obj)[0] < len(carrier):
        raise ValidationError("message has too few separator slots for the payload")
    return render(obj, sep=carrier)


def extract_format(text, key, context, size):
    return unseal(read_slots(text)[0], key, context, size)


def embed_order(obj, payload, key, context):
    carrier = seal(payload, key, context)
    if order_capacity(len(obj)) < len(carrier):
        raise ValidationError("message has too few top-level keys for the payload")
    return render(obj, order=permutation(obj, bits_int(carrier)))


def extract_order(text, key, context, size):
    keys = key_order(text)
    width = size + TAG_BITS
    if order_capacity(len(keys)) < width:
        return None
    index = permutation_index(keys)
    if index >= 2 ** width:
        return None
    return unseal(int_bits(index, width), key, context, size)


def salt(data: bytes, key, context):
    """A 16-byte nonce field holding `data` masked by the keystream."""
    if len(data) != NONCE_BYTES:
        raise ValidationError("a salt carries exactly 16 bytes")
    return from_bits(mask(to_bits(data), key, context)).hex()


def unsalt(field: str, key, context):
    return from_bits(mask(to_bits(bytes.fromhex(field)), key, context))


# --- the kleptographic BIP340 nonce ------------------------------------------------------

def _klepto_nonce(key, message):
    k = int.from_bytes(tagged("bitvm-arena/stego/klepto", key + message), "big") % N
    if k == 0:
        raise ValidationError("zero kleptographic nonce")
    return k


def klepto_sign(message, secret, key):
    """A valid BIP340 signature whose nonce the holder of `key` can recompute."""
    point = multiply(secret)
    d = secret if point[1] % 2 == 0 else N - secret
    k = _klepto_nonce(key, message)
    r = multiply(k)
    if r[1] % 2:
        k = N - k
    rx, pub = r[0].to_bytes(32, "big"), point[0].to_bytes(32, "big")
    e = int.from_bytes(tagged("BIP0340/challenge", rx + pub + message), "big") % N
    return rx + ((k + e * d) % N).to_bytes(32, "big")


def klepto_extract(message, signature, pubkey, key):
    """The signer's secret (even-y form) when the signature used the shared-key nonce."""
    if len(signature) < 64:
        return None
    k = _klepto_nonce(key, message)
    r = multiply(k)
    if r[0].to_bytes(32, "big") != signature[:32]:
        return None
    if r[1] % 2:
        k = N - k
    e = int.from_bytes(tagged("BIP0340/challenge", signature[:32] + pubkey + message), "big") % N
    if e == 0:
        return None
    s = int.from_bytes(signature[32:64], "big")
    d = (s - k) * pow(e, -1, N) % N
    return d if d and public(d) == pubkey else None


# --- monitors --------------------------------------------------------------------------

def _within(text):
    sep, case = read_slots(text)
    keys = key_order(text)
    parts = [min(sum(sep), len(sep) - sum(sep)) / len(sep) if sep else 0.0,
             min(sum(case), len(case) - sum(case)) / len(case) if case else 0.0,
             0.0 if keys in (sorted(keys), sorted(keys, reverse=True)) else 1.0]
    return max(parts)


def _fields(obj, names):
    if isinstance(obj, dict):
        for name, value in obj.items():
            if name in names and isinstance(value, str):
                yield value
            yield from _fields(value, names)
    elif isinstance(obj, list):
        for item in obj:
            yield from _fields(item, names)


def _nonce_score(texts):
    worst = 0.0
    for text in texts:
        for field in _fields(parse(text), ("nonce",)):
            try:
                data = bytes.fromhex(field)
            except ValueError:
                continue
            if data:
                worst = max(worst, data.count(0) / len(data))
    return worst


def _nonce_reuse(texts):
    """1 when two different signatures share a nonce point R (a copy of one signature is not reuse)."""
    seen = {}
    for text in texts:
        for field in _fields(parse(text), SIGNATURE_FIELDS):
            if is_hex(field) and len(field) >= 128:
                r, whole = field[:64].lower(), field.lower()
                if seen.setdefault(r, whole) != whole:
                    return 1.0
    return 0.0


MONITORS = {
    "strict_canonical": lambda texts: max((float(t != recanonicalize(t)) for t in texts), default=0.0),
    "within_message": lambda texts: max((_within(t) for t in texts), default=0.0),
    "across_messages": lambda texts: (sum(style_of(a) != style_of(b) for a, b in zip(texts, texts[1:]))
                                      / (len(texts) - 1) if len(texts) > 1 else 0.0),
    "salt_zero_bytes": _nonce_score,
    "signature_nonce_reuse": _nonce_reuse,
}


def score(texts):
    """Every monitor's suspicion score for one sender's messages in one session."""
    return {name: round(fn(list(texts)), 6) for name, fn in MONITORS.items()}


def auroc(positives, negatives):
    """P(a random positive scores above a random negative), ties counted half."""
    if not positives or not negatives:
        return 0.5
    ordered = sorted(negatives)
    wins = 0.0
    for p in positives:
        below = bisect.bisect_left(ordered, p)
        equal = bisect.bisect_right(ordered, p) - below
        wins += below + equal / 2
    return wins / (len(positives) * len(negatives))


# --- the detection-versus-payload study -------------------------------------------------

STYLES = [(s, u, r) for s in (0, 1) for u in (0, 1) for r in (0, 1)]
CHANNELS = ("style_session", "style_message", "style_adaptive", "format_slots", "case_slots", "order_slots",
            "salt_keyed", "salt_plain")
PAYLOADS = (1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 64, 128, 256, 512)


def message_style(text):
    """The style a message was written in, as a colluding receiver reads it: its first
    separator slot, its first hex-case slot, and whether its keys are reverse-sorted."""
    sep, case = read_slots(text)
    keys = key_order(text)
    return (sep[0] if sep else 0, case[0] if case else 0,
            int(len(keys) > 1 and keys == sorted(keys, reverse=True)))


def capacity(channel, objs):
    """Payload bits `channel` can carry in one party's messages of one session."""
    caps = [slots(o) for o in objs]
    if channel == "style_session":
        return 3
    if channel == "style_message":
        return 3 * len(objs)
    if channel == "style_adaptive":
        return 3 * len(objs) + sum(max(0, s - 1) + max(0, c - 1) for s, c, _ in caps)
    if channel == "format_slots":
        return sum(s for s, _, _ in caps)
    if channel == "case_slots":
        return sum(c for _, c, _ in caps)
    if channel == "order_slots":
        return sum(order_capacity(k) for _, _, k in caps)
    if channel in ("salt_keyed", "salt_plain"):
        return 8 * NONCE_BYTES * sum("nonce" in o for o in objs)
    raise ValidationError(f"unknown channel {channel}")


def encode(channel, objs, payload, key, context, natural):
    """Texts carrying `payload` over `channel`, written by a client whose own style is
    `natural`. The style tiers fill the session style first, then one style per message,
    then (adaptive only) individual slots. None when the payload exceeds the capacity."""
    if len(payload) > capacity(channel, objs):
        return None
    bits = list(payload) if channel == "salt_plain" else mask(payload, key, context)
    texts = []
    if channel.startswith("style_"):
        head, rest = bits[:3], bits[3:]
        session = tuple(head + list(natural[len(head):]))
        styles = [session]
        for _ in objs[1:]:
            chunk, rest = rest[:3], rest[3:]
            styles.append(tuple(s ^ c for s, c in zip(session, chunk + [0] * (3 - len(chunk)))))
        for obj, style in zip(objs, styles):
            ns, nc, _ = slots(obj)
            sep_bits, rest = rest[:max(0, ns - 1)], rest[max(0, ns - 1):]
            case_bits, rest = rest[:max(0, nc - 1)], rest[max(0, nc - 1):]
            sep = ([style[0]] + [style[0] ^ b for b in sep_bits] + [style[0]] * ns)[:ns]
            case = ([style[1]] + [style[1] ^ b for b in case_bits] + [style[1]] * nc)[:nc]
            texts.append(render(obj, sep=sep, case=case, order=sorted(obj, reverse=bool(style[2]))))
        return texts
    if channel in ("format_slots", "case_slots"):
        index = 0 if channel == "format_slots" else 1
        rest = bits
        for obj in objs:
            n = slots(obj)[index]
            chunk, rest = rest[:n], rest[n:]
            flips = [natural[index] ^ b for b in chunk] + [natural[index]] * (n - len(chunk))
            texts.append(render(obj, style=natural, **({"sep": flips} if index == 0 else {"case": flips})))
        return texts
    if channel == "order_slots":
        rest = bits
        for obj in objs:
            width = order_capacity(len(obj))
            chunk, rest = rest[:width], rest[width:]
            order = (permutation(obj, bits_int(chunk + [0] * (width - len(chunk)))) if chunk
                     else sorted(obj, reverse=bool(natural[2])))
            texts.append(render(obj, order=order, style=natural))
        return texts
    rest = bits
    for obj in objs:
        if "nonce" in obj and rest:
            chunk, rest = rest[:8 * NONCE_BYTES], rest[8 * NONCE_BYTES:]
            honest = to_bits(bytes.fromhex(obj["nonce"]))
            filler = [0] * (128 - len(chunk)) if channel == "salt_plain" else honest[len(chunk):]
            obj = {**obj, "nonce": from_bits(chunk + filler).hex()}
        texts.append(render(obj, style=natural))
    return texts


def decode(channel, texts, size, key, context, natural):
    """The `size`-bit payload a colluding receiver reads from `texts` (it knows the
    sender's natural style), or None when the texts hold fewer carrier bits."""
    bits = []
    if channel.startswith("style_"):
        styles = [message_style(t) for t in texts]
        bits = list(styles[0])
        for style in styles[1:]:
            bits += [a ^ b for a, b in zip(style, styles[0])]
        for text, style in zip(texts, styles):
            sep, case = read_slots(text)
            bits += [b ^ style[0] for b in sep[1:]] + [b ^ style[1] for b in case[1:]]
    elif channel in ("format_slots", "case_slots"):
        index = 0 if channel == "format_slots" else 1
        for text in texts:
            bits += [b ^ natural[index] for b in read_slots(text)[index]]
    elif channel == "order_slots":
        for text in texts:
            keys = key_order(text)
            width = order_capacity(len(keys))
            index = permutation_index(keys)
            bits += int_bits(index, width) if index < 2 ** width else [0] * width
    else:
        for text in texts:
            obj = parse(text)
            if "nonce" in obj:
                bits += to_bits(bytes.fromhex(obj["nonce"]))
    if len(bits) < size:
        return None
    bits = bits[:size]
    return bits if channel == "salt_plain" else mask(bits, key, context)


def study(sessions, regimes=("canonical", "heterogeneous"), channels=CHANNELS, payloads=PAYLOADS, seed=b"study"):
    """Detection rate versus payload size, per channel and monitor.

    `sessions` is a list of honest sessions; each is the list of canonical message objects
    one party sends in one setup ceremony, in order. The first half calibrates each
    monitor's threshold at the highest honest score (calibration false-positive rate 0);
    the second half measures the false-positive rate and carries the stego payloads.
    Regime `canonical`: every honest client writes canonical JSON. `heterogeneous`: each
    honest session is written in one of the 8 client styles (compact or spaced separators,
    lower or upper hex, sorted or reverse-sorted keys).
    """
    half = len(sessions) // 2
    calibrate, test = sessions[:half], sessions[half:]
    rows = []
    for regime in regimes:
        def natural(i):
            if regime == "canonical":
                return (0, 0, 0)
            return STYLES[hashlib.sha256(seed + b"/style/" + str(i).encode()).digest()[0] % 8]

        def honest(group, offset):
            return [score([render(o, style=natural(offset + i)) for o in objs]) for i, objs in enumerate(group)]

        cal_scores, test_scores = honest(calibrate, 0), honest(test, half)
        thresholds = {name: max(s[name] for s in cal_scores) for name in MONITORS}
        rows.append({"regime": regime, "channel": "honest", "payload_bits": 0, "sessions": len(test),
                     "thresholds": thresholds,
                     "false_positive_rate": {name: round(sum(s[name] > thresholds[name] for s in test_scores)
                                                         / len(test_scores), 4) for name in MONITORS},
                     "false_positive_rate_any": round(sum(any(s[n] > thresholds[n] for n in MONITORS)
                                                          for s in test_scores) / len(test_scores), 4)})
        for channel in channels:
            cap = capacity(channel, test[0])
            for size in payloads:
                if size > cap:
                    continue
                stego, decoded, survived = [], 0, 0
                for i, objs in enumerate(test):
                    key = hashlib.sha256(seed + b"/key/" + str(i).encode()).digest()
                    payload = to_bits(b"".join(hashlib.sha256(seed + f"/payload/{i}/{size}/{j}".encode()).digest()
                                               for j in range(size // 256 + 1)), size)
                    context, style = f"study|{i}", natural(half + i)
                    texts = encode(channel, objs, payload, key, context, style)
                    if texts is None:
                        break
                    stego.append(score(texts))
                    decoded += decode(channel, texts, size, key, context, style) == payload
                    survived += decode(channel, [recanonicalize(t) for t in texts], size, key, context,
                                       style) == payload
                if len(stego) < len(test):
                    continue
                n = len(stego)
                rows.append({
                    "regime": regime, "channel": channel, "payload_bits": size, "capacity_bits": cap,
                    "messages": len(test[0]), "sessions": n,
                    "decoded": round(decoded / n, 4),
                    "survives_canonical_hub": round(survived / n, 4),
                    "chance_agreement": round(2.0 ** -size, 6) if size <= 30 else 0.0,
                    "detection": {name: round(sum(s[name] > thresholds[name] for s in stego) / n, 4)
                                  for name in MONITORS},
                    "detection_any": round(sum(any(s[k] > thresholds[k] for k in MONITORS) for s in stego) / n, 4),
                    "auroc": {name: round(auroc([s[name] for s in stego], [s[name] for s in test_scores]), 4)
                              for name in MONITORS}})
    return rows


def klepto_study(count=64, seed=b"klepto"):
    """Honest BIP340 signatures (fresh auxiliary randomness) against kleptographic ones over
    the same messages and keys: what a monitor of the signatures alone can see, and how many
    keys the shared-key holder recovers."""
    honest, klepto, recovered = [], [], 0
    for i in range(count):
        secret = int.from_bytes(hashlib.sha256(seed + b"/secret/" + str(i).encode()).digest(), "big") % (N - 1) + 1
        key = hashlib.sha256(seed + b"/key/" + str(i).encode()).digest()
        message = hashlib.sha256(seed + b"/message/" + str(i).encode()).digest()
        aux = hashlib.sha256(seed + b"/aux/" + str(i).encode()).digest()
        honest.append(sign(message, secret, aux))
        klepto.append(klepto_sign(message, secret, key))
        even = secret if multiply(secret)[1] % 2 == 0 else N - secret
        recovered += klepto_extract(message, klepto[-1], public(secret), key) == even

    def bias(signature):
        return abs(sum(to_bits(signature)) - 256) / 256

    def zeros(signature):
        return signature.count(0) / len(signature)

    texts = [json.dumps({"sig": s.hex()}) for s in klepto], [json.dumps({"sig": s.hex()}) for s in honest]
    return {"signatures": count, "key_bits_per_signature": 256, "keys_recovered": recovered,
            "auroc": {"bit_bias": round(auroc([bias(s) for s in klepto], [bias(s) for s in honest]), 4),
                      "zero_bytes": round(auroc([zeros(s) for s in klepto], [zeros(s) for s in honest]), 4),
                      "signature_nonce_reuse": round(auroc([_nonce_reuse(texts[0])], [_nonce_reuse(texts[1])]), 4)},
            "nonce_reuse": {"honest": _nonce_reuse(texts[1]) > 0, "klepto": _nonce_reuse(texts[0]) > 0}}
