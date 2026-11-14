"""Bounded JSONL bridge for local protocol harnesses, with independent scoring.

Adapters normalize their own protocol's state into the Arena observation schema.
An observation is evidence from that harness, not a Bitcoin consensus proof.
No trajectory field is ever interpreted as a shell command.
"""

from __future__ import annotations

import json
import queue
import subprocess
import threading
from copy import deepcopy

from . import schema, spec
from .canonical import ValidationError, canonical, digest, parse_json
from .logic import script
from .engine import check_claim


class AdapterError(RuntimeError):
    pass


class JsonProcess:
    """One reset and up to 256 actions over a persistent child process.

    argv is provided by the evaluator, never by a corpus row. shell=False is
    mandatory. Wall-time, line size, stderr and total message counts are bounded.
    This transport is not an OS sandbox for untrusted executables.
    """
    def __init__(self, argv, *, timeout=30, max_bytes=1_048_576):
        if not isinstance(argv, list) or not argv or any(not isinstance(x, str) or not x for x in argv):
            raise AdapterError("adapter command must be a nonempty argv list")
        if not 0 < timeout <= 60 or not 1024 <= max_bytes <= 4_194_304:
            raise AdapterError("invalid adapter resource bounds")
        self.timeout, self.max_bytes = timeout, max_bytes
        self.messages = queue.Queue(maxsize=258)
        self.stderr = bytearray()
        self.count = 0
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, shell=False)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.error_reader = threading.Thread(target=self._errors, daemon=True)
        self.reader.start()
        self.error_reader.start()

    def _read(self):
        try:
            while True:
                line = self.process.stdout.readline(self.max_bytes + 1)
                if not line:
                    self.messages.put_nowait(AdapterError("adapter closed stdout"))
                    return
                if len(line) > self.max_bytes or not line.endswith(b"\n"):
                    self.messages.put_nowait(AdapterError("adapter exceeded response size or framing limit"))
                    self.process.kill()
                    return
                self.messages.put_nowait(line)
        except queue.Full:
            self.process.kill()
        except (OSError, ValueError) as exc:
            try:
                self.messages.put_nowait(AdapterError(str(exc)))
            except queue.Full:
                pass

    def _errors(self):
        try:
            while data := self.process.stderr.read(1024):
                if len(self.stderr) + len(data) > 65_536:
                    self.process.kill()
                    return
                self.stderr.extend(data)
        except (OSError, ValueError):
            return

    def exchange(self, message):
        self.count += 1
        if self.count > 257:
            raise AdapterError("adapter message budget exhausted")
        encoded = (canonical(message) + "\n").encode()
        if len(encoded) > self.max_bytes:
            raise AdapterError("adapter request too large")
        # A bounded writer thread prevents a non-reading child from hanging the
        # evaluator when a request exceeds the OS pipe buffer.
        writes = queue.Queue(maxsize=1)

        def write():
            try:
                self.process.stdin.write(encoded)
                self.process.stdin.flush()
                writes.put(None)
            except (OSError, ValueError) as exc:
                writes.put(exc)

        writer = threading.Thread(target=write, daemon=True)
        writer.start()
        writer.join(self.timeout)
        if writer.is_alive():
            self.close()
            raise AdapterError("adapter request write timed out")
        failure = writes.get_nowait()
        if failure:
            raise AdapterError(f"adapter request failed: {failure}")
        try:
            response = self.messages.get(timeout=self.timeout)
        except queue.Empty as exc:
            self.close()
            raise AdapterError("adapter response timed out") from exc
        if isinstance(response, Exception):
            raise response
        try:
            result = parse_json(response)
        except (ValueError, UnicodeDecodeError) as exc:
            raise AdapterError("adapter returned invalid JSON") from exc
        if not isinstance(result, dict) or result.get("protocol") != 1:
            raise AdapterError("unsupported adapter protocol")
        if "error" in result:
            raise AdapterError(str(result["error"]))
        return result

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=5)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()
        self.reader.join(timeout=1)
        self.error_reader.join(timeout=1)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def audit_transition(before, action, result, after):
    """Score normalized evidence without accepting a backend's success labels."""
    errors = []
    op, args = action["op"], action["args"]
    if before["state"] != after["state"] and op != "settle":
        errors.append("state.changed_outside_settlement")
    if op == "settle" and result.get("status") == "settled":
        record = before["claims"][args["claim"]]
        claim = record["claim"]
        request = before["requests"][record["request"]]
        oracle = before["quote"]
        errors += spec.violations(before["state"], request, oracle, claim["created_height"], before["anchor"], claim)
        if after["state"] != spec.expected_state(before["state"], request, oracle, claim["effect"]["fee"]):
            errors.append("state.transition_mismatch")
        if before["height"] < record["matures"]:
            errors.append("settlement.early")
        if record["status"] in ("challenged", "revealed"):
            errors.append("settlement.unresolved_challenge")
        if record["status"] == "settled":
            errors.append("settlement.connector_reuse")
        if not record["available"]:
            errors.append("settlement.unavailable_data")
    if result.get("accepted"):
        if op == "open_wire" and len(after["wires"].get(args["wire"], [])) > 1:
            errors.append("logic.wire_equivocation")
        if op == "respond":
            record = before["claims"][args["claim"]]
            if args.get("commitment", record["commitment"]) != record["commitment"]:
                errors.append("dispute.response_unbound")
        if op == "execute_script" and result.get("result"):
            try:
                valid = script(args["program"], args["witness"])
            except ValidationError:
                valid = False
            if not valid:
                errors.append("logic.noncanonical_branch")
    if op in ("challenge", "timeout"):
        record = before["claims"].get(args["claim"])
        after_record = after["claims"].get(args["claim"])
        if record and after_record:
            if op == "challenge" and record["status"] == "pending" and before["height"] < record["matures"] and after_record["status"] == "pending":
                errors.append("dispute.permissionless_challenge_denied")
            if op == "timeout" and record["status"] == "challenged" and before["height"] > record["response_deadline"] and after_record["status"] != "refunded":
                errors.append("liveness.refund_unavailable")
    return sorted(set(errors))


def checked_observation(observation, fixture):
    """Missing or substituted evidence is an adapter error, never a safe result."""
    try:
        required = {"height", "anchor", "state", "state_root", "claims", "requests", "quote", "wires", "fee", "watcher_budget"}
        if not isinstance(observation, dict) or set(observation) != required:
            raise AdapterError("adapter observation fields do not match protocol v1")
        if observation["requests"] != fixture["requests"] or observation["quote"] != fixture["quote"]:
            raise AdapterError("adapter substituted immutable request/oracle evidence")
        if digest(observation["state"]) != observation["state_root"]:
            raise AdapterError("adapter state root mismatch")
        if type(observation["height"]) is not int or not 0 <= observation["height"] <= 2_000_000:
            raise AdapterError("invalid adapter height")
        if not isinstance(observation["claims"], dict) or len(observation["claims"]) > 256:
            raise AdapterError("invalid adapter claims")
        for record in observation["claims"].values():
            if record["request"] not in fixture["requests"] or record["status"] not in ("pending", "challenged", "revealed", "rejected", "settled", "refunded"):
                raise AdapterError("invalid adapter claim identity or phase")
            check_claim(record["claim"])
            if type(record["claim"]["created_height"]) is not int:
                raise AdapterError("invalid adapter claim time")
        for field in ("credits", "positions", "vault", "pool", "wallets", "nonces", "receipts", "revision"):
            if field not in observation["state"]:
                raise AdapterError("incomplete adapter ledger")
    except (KeyError, TypeError, ValidationError) as exc:
        raise AdapterError(f"malformed adapter observation: {exc}") from exc
    return observation


def external_replay(case, argv, *, timeout=30):
    """Exercise a local normalized harness. No mutation labels/expected outcomes
    are sent to it, and attack success is computed from observed transitions.
    """
    schema.trajectory(case)
    with JsonProcess(argv, timeout=timeout) as backend:
        response = backend.exchange({"protocol": 1, "op": "reset", "fixture": case["fixture"]})
        observation = checked_observation(response["observation"], case["fixture"])
        if (observation["state"] != case["fixture"]["state"] or observation["height"] != case["fixture"]["height"]
                or observation["anchor"] != case["fixture"]["anchor"] or observation["claims"]):
            raise AdapterError("adapter reset state does not match the fixture")
        events, failures = [], []
        for index, action in enumerate(case["steps"]):
            before = deepcopy(observation)
            response = backend.exchange({"protocol": 1, "op": "step", "action": action})
            observation, result = checked_observation(response["observation"], case["fixture"]), response["result"]
            errors = audit_transition(before, action, result, observation)
            events.append({"step": index, "action": action, "result": result,
                           "before": digest(before), "after": digest(observation), "violations": errors})
            failures.extend(errors)
            if errors:
                break
    return {"id": case["id"], "evidence_level": "normalized-local-harness-observations",
            "attack_success": bool(failures), "violations": sorted(set(failures)),
            "events": events, "final_observation": observation}
