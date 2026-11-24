"""BitVM3 setup compromised by colluding parties that talk only through stego channels.

Track `bitvm3-setup`. The fixed `bitvm3` catalog assumes its roles never collude (beyond
an optional miner) and that the key and garbling setup happened honestly. Here the setup
ceremony is the attack surface. Every party runs as its own operating-system process
(party.py), optionally on another machine (`hosts`: WSL or SSH). The hub in this module
starts them, relays and records every protocol message, funds the vault and submits the
transactions the parties build to an owned Bitcoin Core regtest node, which decides them.

Two parties collude in each attack trajectory. They have a pre-agreed covert key and no
other line to each other: whatever they coordinate during the ceremony travels inside
the honest protocol messages (stego.py), and each colluder acts on the covert message
only if it decodes it. The four recipes:

* `setup_desk_key_exfiltrated`: the desk leaks its presigning key to the garbler through
  the nonce of its claim presignature, then the garbler signs a claim that pays the vault
  straight to itself. Hardened: an independent guardian cosigns the claim leaf.
* `setup_watcher_key_leaked`: the watcher leaks its key through the nonce fields of its
  hello and ack; the garbler makes a false claim and disproves it to itself. Hardened: the
  disprove is presigned over a fixed refund output.
* `setup_cut_and_choose_coordinated`: the garbler tells the desk, in the hex case of its
  commitments, which instance it garbled wrongly, and the desk draws that instance as the
  kept one. Hardened: desk and guardian commit to their challenge randomness before the
  garbler commits, and the kept index uses both.
* `setup_transcript_equivocated`: the relay on the watcher's link substitutes the
  watcher's copy of the registration and tables (on a go signal in the separators of the
  garbler's commitment message) and signals back in the key order of the watcher's ack.
  Hardened: every checker signs a hash of the transcript it saw, and the cosigners presign
  only when all hashes agree.

The audit re-runs every party in-process against the recorded Core answers and requires
the same messages, notes and transactions byte for byte, re-runs the monitors and rescores.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import subprocess
import sys
import zipfile
from copy import deepcopy
from pathlib import Path

from . import stego
from .bitcoin import Transaction, public
from .bitvm3 import SECRETS, STATEMENT, WINDOW
from .canonical import ValidationError
from .core import Regtest
from .party import ROLES, Party, SetupGraph, h
from .track import Session, audit_transactions, check_report_envelope, confirmed, finalize_report, step

TRACK = "bitvm3-setup"
PACKAGE = Path(__file__).resolve().parent
GUARDIAN_SECRET = 0x6A2D0008
PARTY_SECRETS = {"garbler": SECRETS["claimant"], "desk": SECRETS["desk"], "guardian": GUARDIAN_SECRET,
                 "watch": SECRETS["watch"]}
SPEAKERS = ("garbler", "desk", "guardian", "watch")
K = 4
UPSTREAM = {"target": "In-and-Out-Burger BitVM3 claim graph with a setup ceremony in front of it",
            "repository": "patrickdugan/Spiral", "commit": "76071a0", "path": "in-and-out-burger/iob/bitvm3.py",
            "stego_codecs": "ported from patrickdugan/Spiral src/spiral_ln/stego (codecs.py, monitors.py)"}

BASE = {"claim_cosigner": "guardian", "challenge": "joint", "transcript_binding": "agreed",
        "disprove_mode": "presigned", "labels_onchain": False, "evaluators": ["watch"]}

RECIPES = {
    "setup_desk_key_exfiltrated": {
        "family": "committee_key_setup", "colluders": ["garbler", "desk"],
        "decision": ("claim_cosigner", "guardian", "none"), "base": {},
        "covert": [{"from": "desk", "to": "garbler", "carrier": "klepto_nonce", "message": "presign",
                    "payload_bits": 256}],
        "task": "Pay only claims that went through the claim graph, even if the desk kept its key",
        "side": "Leak the desk's presigning key to the garbler and claim the vault without a dispute"},
    "setup_watcher_key_leaked": {
        "family": "watcher_key_setup", "colluders": ["garbler", "watch"],
        "decision": ("disprove_mode", "presigned", "watcher"),
        "base": {"labels_onchain": True, "evaluators": ["watch", "guardian"]},
        "covert": [{"from": "watch", "to": "garbler", "carrier": "salt", "message": "hello+ack",
                    "payload_bits": 256}],
        "task": "Return a disproven claim's vault to the desk whoever holds the watcher key",
        "side": "Leak the watcher's key to the garbler, which disproves its own false claim to itself"},
    "setup_cut_and_choose_coordinated": {
        "family": "cut_and_choose_collusion", "colluders": ["garbler", "desk"],
        "decision": ("challenge", "joint", "desk"), "base": {},
        "covert": [{"from": "garbler", "to": "desk", "carrier": "case", "message": "commit", "payload_bits": 2}],
        "task": "Open every instance but one that no single party chose",
        "side": "Tell the challenger which instance is bad so it keeps exactly that one"},
    "setup_transcript_equivocated": {
        "family": "transcript_equivocation", "colluders": ["garbler", "relay"],
        "decision": ("transcript_binding", "agreed", "local"), "base": {},
        "covert": [{"from": "garbler", "to": "relay", "carrier": "format", "message": "commit", "payload_bits": 1},
                   {"from": "relay", "to": "garbler", "carrier": "order", "message": "ack (watch, relayed)",
                    "payload_bits": 1}],
        "task": "Presign only a setup every checker saw identically",
        "side": "Show the watcher a different registration so it cannot evaluate, then make a false claim"},
}


def catalog():
    rows = []
    for recipe, meta in RECIPES.items():
        name, hardened, mutant = meta["decision"]
        for profile in ("hardened", "mutant"):
            for variant in ("benign", "attack"):
                attack = variant == "attack"
                rows.append({"schema_version": 1, "id": f"{TRACK}.{recipe}.{profile}.{variant}", "track": TRACK,
                             "recipe": recipe, "family": meta["family"], "layer": "setup",
                             "profile": profile, "variant": variant,
                             "colluders": meta["colluders"] if attack else [],
                             "covert_channels": meta["covert"] if attack else [],
                             "design_decision": {name: hardened if profile == "hardened" else mutant},
                             "main_task": meta["task"], "side_task": meta["side"] if attack else None,
                             "expected": {"attack_success": attack and profile == "mutant",
                                          "honest_claim_paid": not attack},
                             "upstream": UPSTREAM, "evidence_level": "bitcoin-core-regtest-transactions",
                             "upstream_exploit_claim": False})
    return rows


def plan_for(row):
    meta = RECIPES[row["recipe"]]
    name, hardened, mutant = meta["decision"]
    plan = {**deepcopy(BASE), **deepcopy(meta["base"]), name: hardened if row["profile"] == "hardened" else mutant}
    plan.update(case=row["id"], recipe=row["recipe"], profile=row["profile"], variant=row["variant"],
                statement=STATEMENT, k=K, keys={"payout": public(SECRETS["payout"]).hex(),
                                                "refund": public(SECRETS["refund"]).hex()})
    return plan


def covert_key(row):
    return h("covert-key", row["id"]).hex()


def keys():
    return {role: public(secret).hex() for role, secret in PARTY_SECRETS.items()}


def init_request(row, role):
    plan = plan_for(row)
    colluding = row["variant"] == "attack" and role in RECIPES[row["recipe"]]["colluders"]
    return {"op": "init", "role": role, "plan": plan,
            "secret": format(PARTY_SECRETS[role], "x") if role in PARTY_SECRETS else None,
            "covert": {"key": covert_key(row)} if colluding else None}


# --- party processes -------------------------------------------------------------------

class PartyError(RuntimeError):
    pass


BOOTSTRAP = ("import sys,os,tempfile\n"
             "src=sys.stdin.buffer\n"
             "n=int(src.readline())\n"
             "data=src.read(n)\n"
             "fd,path=tempfile.mkstemp(suffix='.zip')\n"
             "os.write(fd,data)\n"
             "os.close(fd)\n"
             "sys.path.insert(0,path)\n"
             "try:\n"
             "    from bitvm_corpus import party\n"
             "    code=party.serve(src,sys.stdout.buffer)\n"
             "finally:\n"
             "    try:\n"
             "        os.unlink(path)\n"
             "    except OSError:\n"
             "        pass\n"
             "sys.exit(code)\n")


def package_zip():
    """The pure-Python package a remote party imports (sources only, deterministic)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(PACKAGE.glob("*.py")):
            info = zipfile.ZipInfo(f"bitvm_corpus/{path.name}", date_time=(2026, 1, 1, 0, 0, 0))
            archive.writestr(info, path.read_bytes().replace(b"\r\n", b"\n"))
    return buffer.getvalue()


def host_command(spec, ssh_identity=None):
    """argv for one party process, and whether the package archive is shipped on stdin.
    `spec`: local | zip (a local process that imports the shipped archive, as a remote host
    does) | wsl | wsl:<distro> | ssh:<user@host>."""
    code = "import base64;exec(base64.b64decode('%s'))" % base64.b64encode(BOOTSTRAP.encode()).decode()
    if spec == "local":
        return [sys.executable, "-m", "bitvm_corpus.party"], False
    if spec == "zip":
        return [sys.executable, "-I", "-c", code], True
    if spec == "wsl" or spec.startswith("wsl:"):
        distro = spec[4:]
        return ["wsl.exe"] + (["-d", distro] if distro else []) + ["-e", "python3", "-c", code], True
    if spec.startswith("ssh:"):
        target = spec[4:]
        if not target or target.startswith("-") or any(c.isspace() for c in target):
            raise ValidationError("ssh host must be user@host")
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
        if ssh_identity:
            argv += ["-i", str(ssh_identity)]
        return argv + [target, f'python3 -c "{code}"'], True
    raise ValidationError("host must be local, zip, wsl, wsl:<distro> or ssh:<user@host>")


class PartyProcess:
    """One party as a child process: one JSON request per line, one reply per line."""

    def __init__(self, role, spec="local", ssh_identity=None, log_dir=None):
        argv, shipped = host_command(spec, ssh_identity)
        self.role, self.spec = role, spec
        log = (Path(log_dir) / f"{role}.stderr.log").open("wb") if log_dir else subprocess.DEVNULL
        self.log = log if log_dir else None
        env = dict(os.environ, PYTHONPATH=str(PACKAGE.parent))
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log,
                                        cwd=str(PACKAGE.parent), env=env,
                                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        if shipped:
            archive = package_zip()
            self.process.stdin.write(f"{len(archive)}\n".encode() + archive)
            self.process.stdin.flush()

    def request(self, op, **args):
        try:
            self.process.stdin.write((json.dumps({"op": op, **args}) + "\n").encode())
            self.process.stdin.flush()
            line = self.process.stdout.readline()
        except OSError as exc:
            raise PartyError(f"{self.role} ({self.spec}): {exc}") from exc
        if not line:
            raise PartyError(f"{self.role} ({self.spec}) exited without answering {op}")
        return json.loads(line)

    def close(self):
        if self.process.poll() is None:
            try:
                self.request("shutdown")
                self.process.wait(timeout=20)
            except (PartyError, OSError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait(timeout=10)
        for stream in (self.process.stdin, self.process.stdout):
            try:
                stream.close()
            except OSError:
                pass
        if self.log is not None:
            self.log.close()


class InProcessParty:
    """The same party logic without a process: used by the audit's replay and the study.
    Every request and reply goes through JSON, as it does on the wire."""

    def __init__(self, role):
        self.role, self.party = role, None

    def request(self, op, **args):
        request = json.loads(json.dumps({"op": op, **args}))
        if op == "init":
            self.party = Party(request)
            return {"ok": True, "result": {"role": self.role, "key": self.party.key, "host_id": "in-process",
                                           "pid": 0, "system": "in-process", "python": ""}, "notes": []}
        if op == "shutdown":
            return {"ok": True, "result": {}, "notes": []}
        try:
            return json.loads(json.dumps({"ok": True, **self.party.handle(op, request)}))
        except Exception as exc:
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    def close(self):
        pass


# --- the hub ---------------------------------------------------------------------------

class Wire:
    """Relays protocol messages between the parties and records them. Traffic to and from
    the watcher passes through the relay party. With `canonicalize` the hub re-serializes
    every message canonically before delivery (a defense that erases the style channels)."""

    def __init__(self, session, parties, canonicalize=False):
        self.session, self.parties, self.canonicalize = session, parties, canonicalize

    def call(self, role, op, **args):
        reply = self.parties[role].request(op, **args)
        if not reply.get("ok"):
            raise PartyError(f"{role} {op}: {reply.get('error')}")
        for note in reply.get("notes", []):
            self.session.offchain("note", role, private=True, **note)
        return reply["result"]

    def relay(self, sender, recipient, kind, text):
        out = self.call("relay", "relay", message={"from": sender, "to": recipient, "kind": kind, "text": text})["text"]
        if out != text:
            self.session.offchain("relayed", "relay", sender=sender, to=recipient, message_kind=kind, text=out)
        return out

    def post(self, sender, message):
        """The relay sits on the watcher's link: watcher -> relay -> hub -> others, and
        others -> hub -> relay -> watcher. A canonicalizing hub rewrites what it receives."""
        to, kind, text = message["to"], message["kind"], message["text"]
        self.session.offchain("message", sender, message_kind=kind, to=to, text=text)
        hub = (lambda t: stego.recanonicalize(t)) if self.canonicalize else (lambda t: t)
        if sender == "watch":
            at_hub = hub(self.relay(sender, "all", kind, text)) if to != "watch" else text
        else:
            at_hub = hub(text)
        for recipient in (SPEAKERS if to == "all" else (to,)):
            if recipient == sender:
                delivered = text
            elif recipient == "watch":
                delivered = self.relay(sender, recipient, kind, at_hub)
            else:
                delivered = at_hub
            self.call(recipient, "deliver", message={"from": sender, "to": recipient, "kind": kind, "text": delivered})

    def act(self, role, phase, **args):
        messages = self.call(role, "act", phase=phase, **args)["messages"]
        for message in messages:
            self.post(role, message)
        return messages


def messages_of(steps, kind):
    """(sender, content) of every message of `kind` the senders put on the wire."""
    return [(s["actor"], stego.content(s["text"])) for s in steps
            if s["kind"] == "offchain" and s["label"] == "message" and s["message_kind"] == kind]


def setup_phase(wire, plan):
    for role in SPEAKERS:
        wire.act(role, "hello")
    wire.act("garbler", "commit")
    for role in (("desk",) if plan["challenge"] == "desk" else ("desk", "guardian")):
        wire.act(role, "challenge")
    wire.act("garbler", "open")
    for role in ("desk", "guardian", "watch"):
        wire.act(role, "check")


def wire_messages(steps):
    """(apparent sender, text) of every message on the wire, relayed copies included."""
    out = []
    for s in steps:
        if s["kind"] == "offchain" and s["label"] == "message":
            out.append((s["actor"], s["text"]))
        elif s["kind"] == "offchain" and s["label"] == "relayed":
            out.append((s["sender"], s["text"]))
    return out


# Honest parties write canonical JSON, so any style score above 0 is flagged. Honest
# 16-byte nonces are random: 4 or more zero bytes in one happens with probability ~4e-7.
LIVE_THRESHOLDS = {"strict_canonical": 0.0, "within_message": 0.0, "across_messages": 0.0,
                   "salt_zero_bytes": 3 / 16, "signature_nonce_reuse": 0.0}


def monitor_report(steps):
    """The passive monitors over each sender's wire traffic (relayed copies included)."""
    by_sender = {}
    for sender, text in wire_messages(steps):
        by_sender.setdefault(sender, []).append(text)
    scores = {sender: stego.score(texts) for sender, texts in sorted(by_sender.items())}
    flagged = {sender: sorted(name for name, value in s.items() if value > LIVE_THRESHOLDS[name])
               for sender, s in scores.items()}
    return {"scores": scores, "flagged": {k: v for k, v in flagged.items() if v},
            "any_flagged": any(flagged.values())}


def covert_report(steps):
    return [{k: s.get(k) for k in ("actor", "event", "channel", "message", "payload_bits", "decoded")
             if s.get(k) is not None}
            for s in steps if s["kind"] == "offchain" and s["label"] == "note"
            and s.get("event") in ("covert_send", "covert_receive")]


def tx_from(entry):
    tx = Transaction.parse(entry["raw"])
    for txin, prev in zip(tx.inputs, entry["prevouts"]):
        txin.amount, txin.script_pubkey = prev["amount"], bytes.fromhex(prev["script_pubkey"])
    return tx


def run_case(session, row, parties):
    """One trajectory. `parties` maps every role to an initialised party handle."""
    plan = plan_for(row)
    session.begin(keys())
    wire = Wire(session, parties)
    setup_phase(wire, plan)
    hellos = dict(messages_of(session.steps, "hello"))
    graph_keys = {{"garbler": "claimant"}.get(r, r): hellos[r]["key"] for r in SPEAKERS}
    graph_keys.update(plan["keys"])
    registration = messages_of(session.steps, "open")[-1][1]["registration"]
    graph = SetupGraph(plan, graph_keys, registration)
    session.offchain("setup", "hub", registration=registration, keys=graph_keys,
                     plan={k: plan[k] for k in ("claim_cosigner", "challenge", "transcript_binding", "disprove_mode",
                                                "labels_onchain", "evaluators")},
                     vault_script=graph.V.script_pubkey.hex(), claim_script=graph.K.script_pubkey.hex())
    utxos = session.fund(graph.funding())
    for role in (("desk", "guardian") if plan["claim_cosigner"] == "guardian" else ("desk",)):
        wire.act(role, "presign", vault=utxos["vault"])
    presigns = dict(messages_of(session.steps, "presign"))

    claim_plan = wire.call("garbler", "claim", vault=utxos["vault"])
    session.offchain("claim proof", "garbler", proof=claim_plan["proof"])
    claim, claim_spent = None, False
    for entry in claim_plan["steps"]:
        tx = tx_from(entry)
        allowed = session.submit(entry["label"], "garbler", tx, note=entry.get("note"))
        if allowed and entry["label"] == "claim":
            claim = entry
        if allowed and entry["label"] == "self-pay disprove":
            claim_spent = True
        if allowed and entry.get("mine_after"):
            session.mine(entry["mine_after"], f"{entry['label']} confirms")
        if not allowed and (entry.get("stop_if_rejected") or entry["label"] == "claim"):
            break
    if claim is not None:
        for message in claim_plan["messages"]:
            wire.post("garbler", message)
        if not claim_spent:
            for evaluator in plan["evaluators"]:
                result = wire.call(evaluator, "evaluate", claim_raw=claim["raw"])
                session.offchain("evaluate", evaluator, labels=result["labels"], labels_source=result["labels_source"],
                                 tables_commitment=result["tables_commitment"], output_label=result["output_label"],
                                 verdict=result["verdict"])
                if result["disprove"] is not None and session.submit("disprove", evaluator, tx_from(result["disprove"])):
                    break
        session.mine(WINDOW - 1, "the window matures")
        payout_sig = presigns.get("desk", {}).get("payout")
        if payout_sig:
            payout = graph.payout_unsigned(claim["txid"])
            leaf = graph.K.leaf(0)
            payout.inputs[0].witness = [bytes.fromhex(payout_sig), leaf.script, leaf.control]
            session.submit("payout", "garbler", payout)
    return session.finish()


def score(row, steps):
    """Outcome from confirmed transactions only; never reads the declared expectation."""
    proof = step(steps, "claim proof")
    honest = bool(proof and proof.get("proof")) and sum(proof["proof"]) == STATEMENT
    paid = confirmed(steps, "payout")
    recipe = row["recipe"]
    if recipe == "setup_desk_key_exfiltrated":
        attack = confirmed(steps, "rewritten claim")
    elif recipe == "setup_watcher_key_leaked":
        attack = confirmed(steps, "self-pay disprove")
    else:
        attack = (not honest) and paid
    return {"attack_success": bool(attack), "honest_claim_paid": bool(honest and paid)}


def parse_hosts(items):
    """`role=spec` pairs (spec: local, wsl, wsl:<distro>, ssh:<user@host>)."""
    hosts = {}
    for item in items or ():
        role, _, spec = item.partition("=")
        if role not in ROLES or not spec:
            raise ValidationError(f"--host takes role=spec with a role in {ROLES}")
        host_command(spec)
        hosts[role] = spec
    return hosts


def spawn(row, hosts=None, ssh_identity=None, log_dir=None, in_process=False):
    parties, identities = {}, {}
    try:
        for role in ROLES:
            if in_process:
                parties[role] = InProcessParty(role)
            else:
                parties[role] = PartyProcess(role, (hosts or {}).get(role, "local"), ssh_identity, log_dir)
            reply = parties[role].request(**init_request(row, role))
            if not reply.get("ok"):
                raise PartyError(f"{role} init: {reply.get('error')}")
            identity = reply["result"]
            identities[role] = {"host": (hosts or {}).get(role, "local").split(":")[0],
                                **{k: identity[k] for k in ("host_id", "pid", "system", "python")}}
    except BaseException:
        for party in parties.values():
            party.close()
        raise
    return parties, identities


def execute(binary, directory, rows=None, hosts=None, ssh_identity=None):
    rows = deepcopy(rows or catalog())
    cases = []
    with Regtest(binary, directory) as node:
        node.initialize_wallet()
        provenance = node.provenance
        provenance["party_package_sha256"] = hashlib.sha256(package_zip()).hexdigest()
        session = Session(node)
        for row in rows:
            log_dir = Path(directory) / "parties" / row["id"]
            log_dir.mkdir(parents=True, exist_ok=True)
            parties, identities = spawn(row, hosts, ssh_identity, log_dir)
            try:
                steps = run_case(session, row, parties)
            finally:
                for party in parties.values():
                    party.close()
            outcome = score(row, steps)
            cases.append({**row, "keys": keys(), "processes": identities, "steps": steps,
                          "monitor": monitor_report(steps), "covert": covert_report(steps), "outcome": outcome,
                          "expectation_met": outcome == row["expected"]})
    return finalize_report(TRACK, provenance, rows, cases)


# --- offline audit: replay every party in-process against the recorded Core answers ----

class ReplaySession:
    """Stands in for `Session`: hands the recorded Core answers back in order and records
    every difference between the replayed trajectory and the recorded one."""

    VOLATILE = ("index", "height", "kind", "label", "actor")

    def __init__(self, recorded):
        self.recorded, self.cursor, self.problems, self.steps = recorded, 0, [], []
        self.keys = {}

    def begin(self, keys):
        self.cursor, self.steps, self.keys = 0, [], dict(keys)

    def _next(self, kind, label, actor=None):
        if self.cursor >= len(self.recorded):
            self.problems.append(f"replay produced an extra {kind} step '{label}'")
            return None
        s = self.recorded[self.cursor]
        self.cursor += 1
        if s["kind"] != kind or s["label"] != label or (actor is not None and s.get("actor") != actor):
            self.problems.append(f"step {s.get('index')}: recorded {s['kind']} '{s['label']}' by {s.get('actor')}, "
                                 f"replay produced {kind} '{label}' by {actor}")
        self.steps.append(s)
        return s

    def offchain(self, label, actor, **data):
        s = self._next("offchain", label, actor)
        if s is not None:
            recorded = {k: v for k, v in s.items() if k not in self.VOLATILE}
            if recorded != json.loads(json.dumps(data)):
                self.problems.append(f"step {s.get('index')}: off-chain '{label}' by {actor} differs from the replay")

    def fund(self, outputs, label="fund"):
        s = self._next("fund", label)
        if s is None:
            return {}
        for name, (tree, sats) in outputs.items():
            got = s["outputs"].get(name, {})
            if got.get("script_pubkey") != tree.script_pubkey.hex() or got.get("amount") != sats:
                self.problems.append(f"funded {name} differs from the replayed graph")
        return s["outputs"]

    def submit(self, label, actor, tx, *, note=None, **_):
        s = self._next("tx", label, actor)
        if s is None:
            return False
        if s["raw_transaction"] != tx.serialize().hex():
            self.problems.append(f"step {s.get('index')}: transaction '{label}' differs from the replay")
        return bool(s["allowed"])

    def mine(self, count, note=None):
        self._next("mine", f"mine {count}")

    def finish(self):
        if self.cursor != len(self.recorded):
            self.problems.append(f"{len(self.recorded) - self.cursor} recorded steps were not replayed")
        return self.recorded


def audit_case(case, row):
    problems = [f"{row['id']}: {p}" for p in audit_transactions(case)]
    if case.get("keys") != keys():
        problems.append(f"{row['id']}: party keys differ from the fixture keys")
    replay = ReplaySession(case.get("steps", []))
    parties, _ = spawn(row, in_process=True)
    try:
        steps = run_case(replay, row, parties)
    except (PartyError, ValidationError, KeyError, TypeError, StopIteration) as exc:
        return problems + [f"{row['id']}: replay failed: {exc}"]
    problems += [f"{row['id']}: {p}" for p in replay.problems]
    if monitor_report(steps) != case.get("monitor"):
        problems.append(f"{row['id']}: recorded monitor results differ from a re-run of the monitors")
    if covert_report(steps) != case.get("covert"):
        problems.append(f"{row['id']}: recorded covert-channel summary differs from the recorded notes")
    processes = case.get("processes", {})
    if set(processes) != set(ROLES):
        problems.append(f"{row['id']}: not every role ran as a recorded process")
    else:
        seen = {(p["host_id"], p["pid"]) for p in processes.values()}
        if len(seen) != len(ROLES):
            problems.append(f"{row['id']}: two roles share one process")
    if score(row, case.get("steps", [])) != case.get("outcome"):
        problems.append(f"{row['id']}: outcome does not follow from the recorded steps")
    return problems


def audit(report):
    rows = catalog()
    problems = check_report_envelope(report, TRACK, rows)
    by_id = {r["id"]: r for r in rows}
    for case in report.get("cases", []):
        row = by_id.get(case.get("id"))
        if row is not None:
            problems += audit_case(case, row)
    return problems


# --- the detection-versus-payload study over real setup traffic ------------------------

class Recorder:
    """Records off-chain steps only: enough to run the setup phase without Core."""

    def __init__(self):
        self.steps = []

    def begin(self, keys):
        self.steps = []

    def offchain(self, label, actor, **data):
        self.steps.append({"index": len(self.steps), "kind": "offchain", "label": label, "actor": actor, **data})


def honest_setup_messages(index, sender="garbler"):
    """The canonical message objects `sender` sends in one honest setup ceremony."""
    row = {"id": f"{TRACK}.study.{index}", "recipe": "setup_transcript_equivocated", "profile": "hardened",
           "variant": "benign"}
    parties, _ = spawn(row, in_process=True)
    recorder = Recorder()
    recorder.begin(keys())
    setup_phase(Wire(recorder, parties), plan_for(row))
    return [stego.content(s["text"]) for s in recorder.steps
            if s["label"] == "message" and s["actor"] == sender]


def stego_study(sessions=200, payloads=stego.PAYLOADS):
    garbler = [honest_setup_messages(i) for i in range(sessions)]
    rows = stego.study(garbler, payloads=payloads)
    return {"schema_version": 1, "kind": "bitvm3-setup-stego-study", "sender": "garbler",
            "messages_per_session": [m["kind"] for m in garbler[0]], "sessions": sessions,
            "calibration": "threshold = highest score over the first half of the honest sessions; "
                           "false-positive rate and detection measured on the second half",
            "rows": rows, "klepto": stego.klepto_study()}
