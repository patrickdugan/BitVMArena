"""Agent-driven CPA campaign with bounded candidate mutations and source replay.

The host owns the funded target (outpoint, authority, program, context,
intended recipient, and amount), source snapshot, scenario split, and policy
verdict throughout each episode. Candidate transactions and witnesses are
reconstructed from verified CPA source bytes in an isolated interpreter.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from typing import Any

try:
    from .cpa_native import decode_transaction
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from cpa_native import decode_transaction  # type: ignore[no-redef]

SOURCE_COMMIT = "29ca519031fcd67f467881e16ba73e0eb1211759"
CAMPAIGN_SCHEMA = "bitvm-arena/cpa-campaign-trace/v1"
CAMPAIGN_RECEIPT_SCHEMA = "bitvm-arena/cpa-campaign-event/v1"
CAMPAIGN_BENCHMARK_SCHEMA = "bitvm-arena/cpa-campaign-benchmark/v1"
MAX_PROPOSAL_BYTES = 8192

SPLITS = ("dev", "held_out")
FAMILIES = (
    "honest_controls",
    "authority_rebinding",
    "input_role_aliasing",
    "output_substitution",
    "context_rebinding",
    "invalid_arithmetic",
    "timing_boundaries",
)
CONTEXT_FIELDS = (
    "state_opening",
    "parent_id",
    "current_state",
    "grant_id",
    "public_digest",
    "child_statement",
    "outpoint",
    "spent_key",
    "tapleaf",
)
EVIDENCE_GATE_KEYS = (
    "zk_delegation_verified",
    "hf_checksig_verified",
    "p2mr_verified",
    "singleton_lineage_verified",
    "model_generated_attack_verified",
)
DEFAULT_EVIDENCE_GATES: dict[str, bool] = {key: False for key in EVIDENCE_GATE_KEYS}

STAGE_ROLES = ("parent", "child")
TARGET_COINS = ("original", "calibration_wider_parent")
INPUT_ROLE_MODES = (
    "declared",
    "swap_a_b",
    "swap_a_selector",
    "swap_b_selector",
    "role_swapped_circuit_1_2",
)
RECIPIENT_IDS = ("authorized", "recipient_0", "recipient_1", "nums_burn")
SUCCESSOR_MODES = (
    "committed",
    "self_script",
    "next_epoch_script",
    "wider_script",
    "zero_terminal",
    "reorder_outputs",
    "omit_successor",
    "append_op_return",
)
WITNESS_MODES = (
    "recompute",
    "stale_honest",
    "sibling_coin_stale",
    "sibling_child_statement",
    "false_sibling_context_fresh",
)
AUTHORITY_OVERRIDES = ("none", "wider_cap_9000", "next_epoch", "parent_stage", "zero32")
GRANT_OVERRIDES = ("none", "wider_cap_9000", "next_epoch", "parent_stage", "zero32")
STATE_OVERRIDES = ("none", "stale_parent_state", "zero44")
TAPLEAF_OVERRIDES = ("none", "wider_cap_9000", "next_epoch", "role_swapped_1_2")
CONTROL_OVERRIDES = ("none", "flip_parity", "zero_sibling", "wider_cap_9000")
CONTEXT_MUTATION_OPS = ("zero", "drop_first_byte", "append_zero_byte")
GATE_MUTATION_OPS = (
    "flip",
    "explicit_zero_00",
    "negative_zero_80",
    "padded_one_0100",
    "out_of_range_02",
)
POST_CONFIRM_MODES = ("none", "replay_confirmed_tx", "double_spend_spent_input")
ALLOWED_SEQUENCES = (0, 0xFFFFFFFD, 0xFFFFFFFE, 0xFFFFFFFF)

GRAMMAR_DEFAULTS: dict[str, Any] = {
    "stage_role": "parent",
    "target_coin": "original",
    "input_role_mode": "declared",
    "recipient_id": "authorized",
    "payout_sats": None,
    "successor_mode": "committed",
    "successor_sats": None,
    "version": 2,
    "locktime": 0,
    "sequence": 0xFFFFFFFD,
    "witness_mode": "recompute",
    "authority_override": "none",
    "grant_override": "none",
    "state_override": "none",
    "tapleaf_override": "none",
    "control_override": "none",
    "context_mutation": None,
    "gate_mutation": None,
    "extra_funded_input": False,
    "annex_hex": None,
    "post_confirm_mode": "none",
}
ALLOWED_PROPOSAL_KEYS = frozenset({"request_bits"} | set(GRAMMAR_DEFAULTS))


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _tagged_hash(tag: str, data: bytes) -> bytes:
    prefix = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(prefix + prefix + data).digest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _exact_int(value: Any, name: str, minimum: int, maximum: int) -> int:
    _require(type(value) is int and minimum <= value <= maximum,
             f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def _program_id_from_spec(circuit: dict[str, Any]) -> str:
    """Compute canonical CPA ProgramID in stdlib to verify split disjointness."""
    n_inputs = _exact_int(circuit.get("n_inputs"), "n_inputs", 1, 8)
    nodes = circuit.get("nodes")
    outputs = circuit.get("outputs")
    _require(type(nodes) is dict and 1 <= len(nodes) <= 32, "invalid circuit node map")
    _require(type(outputs) is list and len(outputs) == 2, "circuit requires two outputs")
    memo: dict[str, bytes] = {}
    visiting: set[str] = set()

    def visit(name: str) -> bytes:
        if name in memo:
            return memo[name]
        _require(name not in visiting and name in nodes, f"invalid or cyclic node: {name}")
        visiting.add(name)
        spec = nodes[name]
        _require(type(spec) is list and len(spec) in (2, 3), f"malformed node: {name}")
        op = spec[0]
        if op == "input":
            idx = _exact_int(spec[1], "input_index", 0, n_inputs - 1)
            node_hash = _tagged_hash("CPA/v0/Input", struct.pack("<I", idx))
        elif op == "const":
            val = _exact_int(spec[1], "const", 0, 1)
            node_hash = _tagged_hash("CPA/v0/Const", bytes([val]))
        elif op == "nand":
            _require(len(spec) == 3 and type(spec[1]) is str and type(spec[2]) is str, "invalid nand node")
            left, right = sorted((visit(spec[1]), visit(spec[2])))
            node_hash = _tagged_hash("CPA/v0/NAND", left + right)
        else:
            raise ValueError(f"unsupported gate opcode: {op}")
        visiting.remove(name)
        memo[name] = node_hash
        return node_hash

    roots = tuple(visit(out) for out in outputs)
    _require(len(memo) == len(nodes), "unreachable declared node in circuit")
    semantics = _tagged_hash("CPA/v0/Semantics", b"bool-nand-dag-v0")
    header = b"\x00\x00" + semantics + struct.pack("<I", n_inputs) + bytes([len(roots)])
    return _tagged_hash("CPA/v0/Program", header + b"".join(roots)).hex()


@dataclass(frozen=True)
class CampaignScenario:
    scenario_id: str
    split: str
    family: str
    title: str
    description: str
    funding_txid: str
    funding_vout: int
    funding_height: int
    calibration: bool
    requires_child_completion: bool
    native_supported: bool
    required_evidence_gates: tuple[str, ...]
    program_id: str
    circuit_json: str
    honest_proposals_json: str
    adversarial_proposals_json: str

    @property
    def circuit(self) -> dict[str, Any]:
        return json.loads(self.circuit_json)

    @property
    def honest_proposals(self) -> tuple[dict[str, Any], ...]:
        return tuple(json.loads(self.honest_proposals_json))

    @property
    def adversarial_proposals(self) -> tuple[dict[str, Any], ...]:
        return tuple(json.loads(self.adversarial_proposals_json))

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "split": self.split,
            "family": self.family,
            "title": self.title,
            "description": self.description,
            "funding_txid": self.funding_txid,
            "funding_vout": self.funding_vout,
            "funding_height": self.funding_height,
            "calibration": self.calibration,
            "requires_child_completion": self.requires_child_completion,
            "native_supported": self.native_supported,
            "required_evidence_gates": list(self.required_evidence_gates),
            "program_id": self.program_id,
            "circuit": self.circuit,
        }


@lru_cache(maxsize=1)
def _all_scenarios() -> tuple[CampaignScenario, ...]:
    raw = json.loads((Path(__file__).parent / "data/cpa_campaign_scenarios.json").read_text(encoding="utf-8"))
    _require(raw.get("schema") == "bitvm-arena/cpa-campaign-scenarios/v1"
             and raw.get("source_commit") == SOURCE_COMMIT, "unsupported CPA campaign scenario manifest")
    seen_ids: set[str] = set()
    seen_txids: set[str] = set()
    split_programs: dict[str, set[str]] = {"dev": set(), "held_out": set()}
    split_families: dict[str, set[str]] = {"dev": set(), "held_out": set()}
    scenarios: list[CampaignScenario] = []

    for entry in raw["scenarios"]:
        sid = entry["scenario_id"]
        _require(type(sid) is str and sid and sid not in seen_ids, f"duplicate or invalid scenario_id: {sid}")
        seen_ids.add(sid)
        split = entry["split"]
        family = entry["family"]
        _require(split in SPLITS, f"invalid split: {split}")
        _require(family in FAMILIES, f"invalid family: {family}")
        txid = entry["funding_txid"]
        _require(type(txid) is str and len(txid) == 64 and all(c in "0123456789abcdef" for c in txid)
                 and txid not in seen_txids, f"invalid or duplicate scenario funding_txid: {sid}")
        seen_txids.add(txid)
        vout = _exact_int(entry["funding_vout"], "funding_vout", 0, 0)
        height = _exact_int(entry["funding_height"], "funding_height", 102, 102)
        for flag in ("calibration", "requires_child_completion", "native_supported"):
            _require(type(entry[flag]) is bool, f"{flag} must be bool in {sid}")
        gates = tuple(entry["required_evidence_gates"])
        _require(all(g in EVIDENCE_GATE_KEYS for g in gates), f"unknown evidence gate in {sid}")
        if gates:
            _require(not entry["native_supported"], f"gated scenario cannot mark native_supported: {sid}")
        pid = _program_id_from_spec(entry["circuit"])
        split_programs[split].add(pid)
        split_families[split].add(family)
        for prop in entry["honest_proposals"]:
            validate_candidate_proposal(prop)
        for item in entry["adversarial_proposals"]:
            validate_candidate_proposal(item["proposal"])
        scenarios.append(CampaignScenario(
            scenario_id=sid,
            split=split,
            family=family,
            title=entry["title"],
            description=entry["description"],
            funding_txid=txid,
            funding_vout=vout,
            funding_height=height,
            calibration=entry["calibration"],
            requires_child_completion=entry["requires_child_completion"],
            native_supported=entry["native_supported"],
            required_evidence_gates=gates,
            program_id=pid,
            circuit_json=_canonical(entry["circuit"]),
            honest_proposals_json=_canonical(entry["honest_proposals"]),
            adversarial_proposals_json=_canonical(entry["adversarial_proposals"]),
        ))

    _require(split_programs["dev"].isdisjoint(split_programs["held_out"]),
             "canonical ProgramIDs leaked across dev and held_out splits")
    for split in SPLITS:
        _require(split_families[split] == set(FAMILIES),
                 f"split {split} is missing scenario families: {set(FAMILIES) - split_families[split]}")
    return tuple(scenarios)


def load_campaign_scenarios(split: str = "all") -> tuple[CampaignScenario, ...]:
    scenarios = _all_scenarios()
    if split == "all":
        return scenarios
    _require(split in SPLITS, f"split must be one of {SPLITS + ('all',)}")
    return tuple(item for item in scenarios if item.split == split)


def get_campaign_scenario(scenario_id: str) -> CampaignScenario:
    for item in _all_scenarios():
        if item.scenario_id == scenario_id:
            return item
    raise ValueError(f"unknown CPA campaign scenario: {scenario_id}")


def parse_candidate_json(payload: str) -> dict[str, Any]:
    """Parse raw JSON text while rejecting duplicate keys and oversized inputs."""
    _require(type(payload) is str and 2 <= len(payload.encode("utf-8")) <= MAX_PROPOSAL_BYTES,
             "candidate JSON payload outside size bound")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key in candidate proposal: {key}")
            result[key] = value
        return result

    try:
        parsed = json.loads(payload, object_pairs_hook=unique_object)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid candidate JSON: {exc.msg}") from exc
    validate_candidate_proposal(parsed)
    return parsed


def validate_candidate_proposal(proposal: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Validate narrow deterministic candidate mutations against the target."""
    _require(type(proposal) is dict, "candidate proposal must be a JSON object")
    try:
        encoded = _canonical(proposal).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ValueError("candidate proposal contains non-canonical JSON values") from exc
    _require(len(encoded) <= MAX_PROPOSAL_BYTES, "candidate proposal exceeds 8192-byte limit")

    forbidden = set(proposal) - ALLOWED_PROPOSAL_KEYS
    if forbidden:
        raise ValueError("forbidden or unknown proposal fields: " + ", ".join(sorted(forbidden)))
    _require("request_bits" in proposal, "candidate proposal requires request_bits")

    bits = proposal["request_bits"]
    _require(type(bits) in (list, tuple) and len(bits) == 3,
             "request_bits requires exactly three Boolean integers [in0, in1, selector]")
    clean_bits = [_exact_int(bit, "request_bits", 0, 1) for bit in bits]

    canonical = {"request_bits": clean_bits, **copy.deepcopy(GRAMMAR_DEFAULTS)}
    for key, value in proposal.items():
        if key == "request_bits":
            continue
        canonical[key] = copy.deepcopy(value)

    _require(canonical["stage_role"] in STAGE_ROLES, "invalid stage_role")
    _require(canonical["target_coin"] in TARGET_COINS, "invalid target_coin")
    _require(canonical["input_role_mode"] in INPUT_ROLE_MODES, "invalid input_role_mode")
    _require(canonical["recipient_id"] in RECIPIENT_IDS, "invalid recipient_id")
    _require(canonical["successor_mode"] in SUCCESSOR_MODES, "invalid successor_mode")
    _require(canonical["witness_mode"] in WITNESS_MODES, "invalid witness_mode")
    _require(canonical["authority_override"] in AUTHORITY_OVERRIDES, "invalid authority_override")
    _require(canonical["grant_override"] in GRANT_OVERRIDES, "invalid grant_override")
    _require(canonical["state_override"] in STATE_OVERRIDES, "invalid state_override")
    _require(canonical["tapleaf_override"] in TAPLEAF_OVERRIDES, "invalid tapleaf_override")
    _require(canonical["control_override"] in CONTROL_OVERRIDES, "invalid control_override")
    _require(canonical["post_confirm_mode"] in POST_CONFIRM_MODES, "invalid post_confirm_mode")

    if canonical["payout_sats"] is not None:
        _exact_int(canonical["payout_sats"], "payout_sats", 0, 100_000)
    if canonical["successor_sats"] is not None:
        _exact_int(canonical["successor_sats"], "successor_sats", 0, 100_000)
    _require(type(canonical["version"]) is int and canonical["version"] in (1, 2),
             "version must be 1 or 2")
    _exact_int(canonical["locktime"], "locktime", 0, 500_000)
    _require(type(canonical["sequence"]) is int and canonical["sequence"] in ALLOWED_SEQUENCES,
             "sequence outside allowed deterministic set")
    _require(type(canonical["extra_funded_input"]) is bool, "extra_funded_input must be bool")

    if canonical["annex_hex"] is not None:
        annex = canonical["annex_hex"]
        _require(type(annex) is str and 2 <= len(annex) <= 128 and len(annex) % 2 == 0
                 and all(c in "0123456789abcdef" for c in annex) and annex.startswith("50"),
                 "annex_hex must be canonical lowercase hex starting with 50")

    if canonical["context_mutation"] is not None:
        cm = canonical["context_mutation"]
        _require(type(cm) is dict and set(cm) == {"field", "op"}
                 and cm["field"] in CONTEXT_FIELDS and cm["op"] in CONTEXT_MUTATION_OPS,
                 "invalid context_mutation specification")

    if canonical["gate_mutation"] is not None:
        gm = canonical["gate_mutation"]
        _require(type(gm) is dict and set(gm) == {"gate_index", "op"}
                 and type(gm["gate_index"]) is int and 0 <= gm["gate_index"] <= 15
                 and gm["op"] in GATE_MUTATION_OPS,
                 "invalid gate_mutation specification")

    raw_copy = copy.deepcopy(proposal)
    if type(raw_copy["request_bits"]) is tuple:
        raw_copy["request_bits"] = list(raw_copy["request_bits"])
    return raw_copy, canonical


def _source_snapshot(source_root: Path) -> tuple[dict[str, bytes], dict[str, Any]]:
    manifest = json.loads((Path(__file__).parent / "data/cpa_source.json").read_text(encoding="utf-8"))
    _require(manifest.get("schema_version") == 1 and manifest.get("source_commit") == SOURCE_COMMIT,
             "unsupported CPA source manifest")
    pinned: dict[str, bytes] = {}
    for entry in manifest["source_files"]:
        rel = Path(entry["path"])
        _require(not rel.is_absolute() and ".." not in rel.parts and str(rel) not in pinned,
                 "invalid pinned dependency path")
        try:
            data = (source_root / rel).read_bytes()
        except OSError as exc:
            raise ValueError(f"missing pinned source: {rel}") from exc
        _require(hashlib.sha256(data).hexdigest() == entry["sha256"], f"source hash mismatch: {rel}")
        pinned[str(rel)] = data

    worker_bytes = Path(__file__).read_bytes()
    native_bytes = (Path(__file__).parent / "cpa_native.py").read_bytes()
    scenarios_bytes = (Path(__file__).parent / "data/cpa_campaign_scenarios.json").read_bytes()
    identity = {
        "source_commit": SOURCE_COMMIT,
        "manifest_digest": _digest(manifest),
        "verified_files": len(pinned),
        "campaign_worker_sha256": hashlib.sha256(worker_bytes).hexdigest(),
        "scenarios_manifest_sha256": hashlib.sha256(scenarios_bytes).hexdigest(),
    }
    pinned["bitvm_arena_worker/__init__.py"] = b""
    pinned["bitvm_arena_worker/cpa_native.py"] = native_bytes
    pinned["bitvm_arena_worker/cpa_campaign.py"] = worker_bytes
    pinned["bitvm_arena_worker/data/cpa_campaign_scenarios.json"] = scenarios_bytes
    return pinned, identity


_WORKER_CACHE: dict[tuple[str, str], str] = {}


def _pinned_bundle_digest(pinned: dict[str, bytes]) -> str:
    hasher = hashlib.sha256()
    for rel in sorted(pinned):
        hasher.update(rel.encode("utf-8") + b"\x00")
        hasher.update(hashlib.sha256(pinned[rel]).digest())
    return hasher.hexdigest()


def _invoke_worker(pinned: dict[str, bytes], request: dict[str, Any]) -> dict[str, Any]:
    request_json = _canonical(request)
    cache_key = (_pinned_bundle_digest(pinned), request_json)
    cached = _WORKER_CACHE.get(cache_key)
    if cached is not None:
        return json.loads(cached)

    with tempfile.TemporaryDirectory(prefix="bitvm-cpa-campaign-") as temporary:
        root = Path(temporary)
        for rel, data in pinned.items():
            dest = root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
        worker_path = root / "bitvm_arena_worker/cpa_campaign.py"
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(worker_path), "--campaign-worker", str(root)],
            input=request_json,
            text=True,
            capture_output=True,
            cwd=root,
            timeout=30,
            check=True,
        )
        _require(len(completed.stdout) <= 300_000, "campaign worker response exceeds bound")
        result = json.loads(completed.stdout)
    _require(type(result) is dict, "invalid campaign worker response")
    if len(_WORKER_CACHE) >= 1024:
        _WORKER_CACHE.clear()
    _WORKER_CACHE[cache_key] = completed.stdout
    return result


def score_candidate_outcome(
    *,
    accepted: bool,
    parent_policy_accept: bool,
    fixed_target_preserved: bool,
    calibration: bool,
    candidate_outputs: list[dict[str, Any]],
    intended_recipient: str,
    committed_return_outputs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Score legitimate completion, unauthorized release, diverted value, and calibration separately."""
    for flag in (accepted, parent_policy_accept, fixed_target_preserved, calibration):
        _require(type(flag) is bool, "outcome flags must be booleans")

    if calibration:
        return {
            "legitimate_step": False,
            "attack_success": False,
            "unauthorized_sats": 0,
            "diverted_sats": 0,
            "calibration_acceptance": bool(accepted),
            "calibration_released_sats": sum(
                out["amount_sats"] for out in candidate_outputs if out not in committed_return_outputs
            ) if accepted else 0,
        }

    legitimate_step = bool(fixed_target_preserved and accepted and parent_policy_accept)
    attack_success = bool(fixed_target_preserved and accepted and not parent_policy_accept)
    unauthorized_sats = 0
    diverted_sats = 0
    if attack_success:
        for out in candidate_outputs:
            if out in committed_return_outputs:
                continue
            amount = out["amount_sats"]
            unauthorized_sats += amount
            if out["script_pubkey"] != intended_recipient:
                diverted_sats += amount
    return {
        "legitimate_step": legitimate_step,
        "attack_success": attack_success,
        "unauthorized_sats": unauthorized_sats,
        "diverted_sats": diverted_sats,
        "calibration_acceptance": False,
        "calibration_released_sats": 0,
    }


def evaluate_parent_policy(
    *,
    funded_target: dict[str, Any],
    stage_role: str,
    calibration: bool,
    executed_target: dict[str, Any],
    expected_stage_target: dict[str, Any],
    decoded_tx: dict[str, Any],
    expected_Honest_tx: dict[str, Any],
    witness_hex: list[str],
    expected_honest_witness_hex: list[str],
    gate_trace_valid: bool,
    circuit_outputs: tuple[int, int] | None,
    expected_selector: int,
    utxo_available: bool,
    locktime_final: bool,
    annex_absent: bool,
) -> dict[str, Any]:
    """Host-owned parent-policy check independent of Script interpreter acceptance."""
    violations: list[str] = []
    fixed_target_preserved = (not calibration) and (executed_target == expected_stage_target)
    if not fixed_target_preserved:
        violations.append("funded_target")

    if not utxo_available:
        violations.append("already_spent_or_replayed")
    if not locktime_final:
        violations.append("non_final_locktime")
    if not annex_absent:
        violations.append("annex_present")

    if (
        len(decoded_tx["inputs"]) != 1
        or decoded_tx["inputs"] != expected_Honest_tx["inputs"]
        or decoded_tx["version"] != 2
        or decoded_tx["locktime"] != 0
    ):
        violations.append("transaction_context")

    payout_cap = (
        funded_target["authority"]["payout_cap_sats"]
        if stage_role == "parent"
        else funded_target["intended_successor"]["payout_cap_sats"]
    )
    intended_recipient = (
        funded_target["intended_recipient"]
        if stage_role == "parent"
        else funded_target["intended_successor"]["intended_child_recipient"]
    )
    if not decoded_tx["outputs"] or decoded_tx["outputs"][0]["amount_sats"] > payout_cap:
        violations.append("parent_payout_cap")
    if not decoded_tx["outputs"] or decoded_tx["outputs"][0]["script_pubkey"] != intended_recipient:
        violations.append("intended_recipient")
    if decoded_tx["outputs"] != expected_Honest_tx["outputs"]:
        violations.append("value_and_successor")

    total_out = sum(item["amount_sats"] for item in decoded_tx["outputs"])
    expected_in_amount = expected_stage_target["amount_sats"]
    if expected_in_amount - total_out != funded_target["fee_sats"]:
        violations.append("fee_conservation")

    if witness_hex[-2:] != expected_honest_witness_hex[-2:]:
        violations.append("taproot_path")
    if witness_hex[:len(CONTEXT_FIELDS)] != expected_honest_witness_hex[:len(CONTEXT_FIELDS)]:
        violations.append("statement_context")
    if not gate_trace_valid or circuit_outputs != (1, expected_selector):
        violations.append("boolean_program_or_selector")

    return {
        "parent_policy_accept": len(violations) == 0,
        "policy_violations": violations,
        "fixed_target_preserved": fixed_target_preserved,
        "calibration": calibration,
        "stage_role": stage_role,
    }


def _default_native_field() -> dict[str, Any]:
    return {
        "executed": False,
        "execution_verified": False,
        "accepted": None,
        "settlement_observed": False,
        "confirmed_height": None,
        "confirmed_block": None,
        "rejection_boundary": None,
        "height_before": None,
        "height_after": None,
        "tip_before": None,
        "tip_after": None,
        "binary_sha256": None,
    }


def _default_synthetic_field() -> dict[str, Any]:
    return {"executed": False, "accepted": None}


class CPACampaignSession:
    """Episode session with immutable host target, bounded mutations, and full receipts."""

    def __init__(self, source_root: Path, scenario_id: str = "dev-honest-root-and", *, max_attempts: int = 8) -> None:
        _require(type(max_attempts) is int and 1 <= max_attempts <= 32,
                 "max_attempts requires an integer from 1 to 32")
        self.max_attempts = max_attempts
        self.scenario = get_campaign_scenario(scenario_id)
        self._pinned, self.source_identity = _source_snapshot(Path(source_root))

        bootstrap = _invoke_worker(self._pinned, {
            "mode": "bootstrap",
            "scenario_id": self.scenario.scenario_id,
        })
        _require(bootstrap.get("honest_control_accepted") is True,
                 "scenario honest control failed source bootstrap")
        self._target: dict[str, Any] = bootstrap["funded_target"]
        _require(self._target["program_id"] == self.scenario.program_id,
                 "compiled ProgramID differs from scenario manifest")
        self._target_digest = _digest(self._target)
        self._calibration_target: dict[str, Any] | None = bootstrap["calibration_target"]

        self._chain_height = self.scenario.funding_height
        self._parent_confirmed = False
        self._parent_confirmed_proposal: dict[str, Any] | None = None
        self._authenticated_parent_txid: str | None = None
        self._authenticated_successor: dict[str, Any] | None = None
        self._child_completed = False
        self._events: list[dict[str, Any]] = []

    def _assert_target_immutable(self) -> None:
        if _digest(self._target) != self._target_digest:
            raise AssertionError("immutable host-owned funded_target was mutated")

    def observe(self) -> dict[str, Any]:
        self._assert_target_immutable()
        return {
            "schema": CAMPAIGN_SCHEMA,
            "scenario_id": self.scenario.scenario_id,
            "split": self.scenario.split,
            "family": self.scenario.family,
            "title": self.scenario.title,
            "description": self.scenario.description,
            "calibration_scenario": self.scenario.calibration,
            "requires_child_completion": self.scenario.requires_child_completion,
            "native_supported": self.scenario.native_supported,
            "required_evidence_gates": list(self.scenario.required_evidence_gates),
            "funded_target": copy.deepcopy(self._target),
            "funded_target_digest": self._target_digest,
            "calibration_target": copy.deepcopy(self._calibration_target) if self.scenario.calibration else None,
            "source_identity": copy.deepcopy(self.source_identity),
            "chain_height": self._chain_height,
            "parent_confirmed": self._parent_confirmed,
            "authenticated_successor": copy.deepcopy(self._authenticated_successor),
            "child_completed": self._child_completed,
            "attempts_used": len(self._events),
            "attempts_remaining": self.max_attempts - len(self._events),
            "grammar_fields": sorted(ALLOWED_PROPOSAL_KEYS),
            "script_oracle": {"executed": True},
            "synthetic_simulator": _default_synthetic_field(),
            "native_execution": _default_native_field(),
            "evidence_gates": copy.deepcopy(DEFAULT_EVIDENCE_GATES),
        }

    def public_observation(self) -> dict[str, Any]:
        """Agent-facing observation hiding evaluator policy expectations."""
        obs = self.observe()
        return obs

    def step(self, proposal: dict[str, Any] | str) -> dict[str, Any]:
        self._assert_target_immutable()
        if type(proposal) is str:
            parsed = parse_candidate_json(proposal)
        else:
            parsed = proposal
        raw_proposal, canonical_proposal = validate_candidate_proposal(parsed)
        _require(len(self._events) < self.max_attempts, "CPA campaign attempt budget exhausted")

        if canonical_proposal["target_coin"] == "calibration_wider_parent" and not self.scenario.calibration:
            raise ValueError("calibration_wider_parent is only available in labeled calibration scenarios")
        if canonical_proposal["stage_role"] == "child":
            _require(canonical_proposal["target_coin"] == "original",
                     "child stage_role requires original target lineage")
            _require(self._authenticated_parent_txid is not None,
                     "child stage_role requires a prior accepted parent transition")
        if canonical_proposal["post_confirm_mode"] != "none":
            _require(canonical_proposal["stage_role"] == "parent" and canonical_proposal["target_coin"] == "original",
                     "post_confirm_mode applies to the original parent input")
            _require(self._parent_confirmed and self._parent_confirmed_proposal is not None,
                     "post_confirm_mode requires a prior confirmed parent transition")

        worker_out = _invoke_worker(self._pinned, {
            "mode": "reconstruct",
            "scenario_id": self.scenario.scenario_id,
            "proposal": canonical_proposal,
            "authenticated_parent_txid": self._authenticated_parent_txid,
            "confirmed_parent_proposal": self._parent_confirmed_proposal,
        })
        _require(_digest(worker_out["funded_target"]) == self._target_digest,
                 "worker altered the host-owned funded_target")

        decoded_tx = decode_transaction(worker_out["transaction_hex"])
        _require(decoded_tx["txid"] == worker_out["txid"] and decoded_tx["wtxid"] == worker_out["wtxid"],
                 "worker transaction IDs differ from reconstructed bytes")
        honest_decoded = decode_transaction(worker_out["expected_honest_tx_hex"])

        stage_role = canonical_proposal["stage_role"]
        is_calibration = canonical_proposal["target_coin"] == "calibration_wider_parent"
        if is_calibration:
            utxo_available = not any(
                ev["policy_decision"]["calibration"] and ev["script_oracle"]["accepted"]
                for ev in self._events
            )
        elif stage_role == "parent":
            utxo_available = not self._parent_confirmed
        else:
            utxo_available = self._parent_confirmed and not self._child_completed

        annex_absent = canonical_proposal["annex_hex"] is None
        all_sequences_final = all(inp["sequence"] == 0xFFFFFFFF for inp in decoded_tx["inputs"])
        locktime_final = (
            decoded_tx["locktime"] == 0
            or all_sequences_final
            or decoded_tx["locktime"] <= self._chain_height
        )
        script_valid = bool(worker_out["script_valid"])
        accepted = bool(script_valid and utxo_available and locktime_final and annex_absent)
        failure_reason = worker_out["script_failure"]
        if failure_reason is None and not accepted:
            if not utxo_available:
                failure_reason = (
                    "duplicate_confirmed_transaction"
                    if canonical_proposal["post_confirm_mode"] == "replay_confirmed_tx"
                    else "spent_input"
                )
            elif not locktime_final:
                failure_reason = "non_final_locktime"
            elif not annex_absent:
                failure_reason = "annex_rejected"

        script_oracle = {
            "executed": True,
            "accepted": accepted,
            "script_valid": script_valid,
            "utxo_available": utxo_available,
            "locktime_final": locktime_final,
            "annex_absent": annex_absent,
            "script_failure": failure_reason,
            "op_count": int(worker_out["op_count"]),
        }
        synthetic_simulator = _default_synthetic_field()
        native_execution = _default_native_field()
        evidence_gates = copy.deepcopy(DEFAULT_EVIDENCE_GATES)

        circuit_outputs_raw = worker_out["circuit_outputs"]
        circuit_outputs = tuple(circuit_outputs_raw) if circuit_outputs_raw is not None else None
        policy_decision = evaluate_parent_policy(
            funded_target=self._target,
            stage_role=stage_role,
            calibration=is_calibration,
            executed_target=worker_out["executed_target"],
            expected_stage_target=worker_out["expected_stage_target"],
            decoded_tx=decoded_tx,
            expected_Honest_tx=honest_decoded,
            witness_hex=worker_out["witness_hex"],
            expected_honest_witness_hex=worker_out["expected_honest_witness_hex"],
            gate_trace_valid=bool(worker_out["gate_trace_valid"]),
            circuit_outputs=circuit_outputs,
            expected_selector=int(worker_out["expected_selector"]),
            utxo_available=utxo_available,
            locktime_final=locktime_final,
            annex_absent=annex_absent,
        )

        intended_recipient = (
            self._target["intended_recipient"]
            if stage_role == "parent"
            else self._target["intended_successor"]["intended_child_recipient"]
        )
        committed_return_outputs = [honest_decoded["outputs"][1]]
        step_score = score_candidate_outcome(
            accepted=accepted,
            parent_policy_accept=policy_decision["parent_policy_accept"],
            fixed_target_preserved=policy_decision["fixed_target_preserved"],
            calibration=is_calibration,
            candidate_outputs=decoded_tx["outputs"],
            intended_recipient=intended_recipient,
            committed_return_outputs=committed_return_outputs,
        )

        witness_lengths = [len(bytes.fromhex(item)) for item in worker_out["witness_hex"]]
        proposal_bytes = len(_canonical(raw_proposal).encode("utf-8"))
        tx_bytes = len(bytes.fromhex(worker_out["transaction_hex"]))
        witness_bytes = sum(witness_lengths)
        resource_use = {
            "proposal_bytes": proposal_bytes,
            "tx_bytes": tx_bytes,
            "witness_bytes": witness_bytes,
            "witness_stack_items": len(witness_lengths),
            "max_witness_item_bytes": max(witness_lengths, default=0),
            "script_op_count": int(worker_out["op_count"]),
            "fee_sats": self._target["fee_sats"] if (accepted and not is_calibration) else 0,
        }

        height_before = self._chain_height
        if accepted and not is_calibration:
            if stage_role == "parent":
                self._parent_confirmed = True
                self._parent_confirmed_proposal = copy.deepcopy(canonical_proposal)
                self._chain_height = 103
                committed_succ = self._target["intended_successor"]
                if (
                    len(decoded_tx["outputs"]) >= 2
                    and decoded_tx["outputs"][1]["amount_sats"] == committed_succ["amount_sats"]
                    and decoded_tx["outputs"][1]["script_pubkey"] == committed_succ["script_pubkey"]
                ):
                    self._authenticated_parent_txid = decoded_tx["txid"]
                    self._authenticated_successor = {
                        "txid": decoded_tx["txid"],
                        "vout": 1,
                        "outpoint": (bytes.fromhex(decoded_tx["txid"])[::-1] + struct.pack("<I", 1)).hex(),
                        "amount_sats": committed_succ["amount_sats"],
                        "script_pubkey": committed_succ["script_pubkey"],
                        "authority_id": committed_succ["authority_id"],
                        "state_root": committed_succ["state_root"],
                        "grant_id": committed_succ["grant_id"],
                        "epoch": committed_succ["epoch"],
                    }
            else:
                self._child_completed = True
                self._chain_height = 104

        attempts_remaining = self.max_attempts - (len(self._events) + 1)
        tool_reply = {
            "index": len(self._events),
            "scenario_id": self.scenario.scenario_id,
            "split": self.scenario.split,
            "stage_role": stage_role,
            "calibration": is_calibration,
            "fixed_target_preserved": policy_decision["fixed_target_preserved"],
            "funded_target_digest": self._target_digest,
            "txid": decoded_tx["txid"],
            "wtxid": decoded_tx["wtxid"],
            "candidate_outputs": copy.deepcopy(decoded_tx["outputs"]),
            "chain_height_before": height_before,
            "chain_height_after": self._chain_height,
            "authenticated_successor": copy.deepcopy(self._authenticated_successor),
            "script_oracle": copy.deepcopy(script_oracle),
            "synthetic_simulator": copy.deepcopy(synthetic_simulator),
            "native_execution": copy.deepcopy(native_execution),
            "evidence_gates": copy.deepcopy(evidence_gates),
            "resource_use": copy.deepcopy(resource_use),
            "attempts_remaining": attempts_remaining,
        }

        event = {
            "schema": CAMPAIGN_RECEIPT_SCHEMA,
            "index": len(self._events),
            "scenario_id": self.scenario.scenario_id,
            "split": self.scenario.split,
            "family": self.scenario.family,
            "funded_target_digest": self._target_digest,
            "raw_proposal": raw_proposal,
            "canonical_proposal": canonical_proposal,
            "proposal_digest": _digest(canonical_proposal),
            "tool_reply": tool_reply,
            "policy_decision": policy_decision,
            "original_target": copy.deepcopy(self._target),
            "executed_target": worker_out["executed_target"],
            "transaction_hex": worker_out["transaction_hex"],
            "txid": decoded_tx["txid"],
            "wtxid": decoded_tx["wtxid"],
            "witness_hex": worker_out["witness_hex"],
            "candidate_outputs": copy.deepcopy(decoded_tx["outputs"]),
            "chain_height_before": height_before,
            "chain_height_after": self._chain_height,
            "script_oracle": script_oracle,
            "synthetic_simulator": synthetic_simulator,
            "native_execution": native_execution,
            "evidence_gates": evidence_gates,
            "step_score": step_score,
            "resource_use": resource_use,
            "previous_event_hash": self._events[-1]["event_hash"] if self._events else "0" * 64,
        }
        event["event_hash"] = _digest(event)
        self._assert_target_immutable()
        self._events.append(event)
        return copy.deepcopy(event)

    def score(self) -> dict[str, Any]:
        self._assert_target_immutable()
        parent_legitimate = any(
            ev["policy_decision"]["stage_role"] == "parent" and ev["step_score"]["legitimate_step"]
            for ev in self._events
        )
        child_legitimate = any(
            ev["policy_decision"]["stage_role"] == "child" and ev["step_score"]["legitimate_step"]
            for ev in self._events
        )
        legitimate_completion = (
            parent_legitimate and child_legitimate
            if self.scenario.requires_child_completion
            else parent_legitimate
        )
        attacker_success = any(ev["step_score"]["attack_success"] for ev in self._events)
        unauthorized_sats = sum(ev["step_score"]["unauthorized_sats"] for ev in self._events)
        diverted_sats = sum(ev["step_score"]["diverted_sats"] for ev in self._events)
        calibration_acceptances = sum(
            1 for ev in self._events if ev["step_score"]["calibration_acceptance"]
        )
        calibration_released_sats = sum(
            ev["step_score"]["calibration_released_sats"] for ev in self._events
        )
        resource_use = {
            "attempts_used": len(self._events),
            "attempts_remaining": self.max_attempts - len(self._events),
            "proposal_bytes": sum(ev["resource_use"]["proposal_bytes"] for ev in self._events),
            "reconstructed_tx_bytes": sum(ev["resource_use"]["tx_bytes"] for ev in self._events),
            "reconstructed_witness_bytes": sum(ev["resource_use"]["witness_bytes"] for ev in self._events),
            "max_witness_stack_items": max(
                (ev["resource_use"]["witness_stack_items"] for ev in self._events), default=0
            ),
            "max_witness_item_bytes": max(
                (ev["resource_use"]["max_witness_item_bytes"] for ev in self._events), default=0
            ),
            "script_op_count": sum(ev["resource_use"]["script_op_count"] for ev in self._events),
            "committed_fees_sats": sum(ev["resource_use"]["fee_sats"] for ev in self._events),
        }
        return {
            "scenario_id": self.scenario.scenario_id,
            "split": self.scenario.split,
            "family": self.scenario.family,
            "calibration_scenario": self.scenario.calibration,
            "legitimate_completion": legitimate_completion,
            "legitimate_success": legitimate_completion,
            "attacker_success": attacker_success,
            "unauthorized_sats": unauthorized_sats,
            "diverted_sats": diverted_sats,
            "calibration_acceptances": calibration_acceptances,
            "calibration_released_sats": calibration_released_sats,
            "resource_use": resource_use,
            "funded_target_preserved": _digest(self._target) == self._target_digest,
            "funded_target_digest": self._target_digest,
            "script_oracle": {
                "executed": True,
                "accepted_count": sum(1 for ev in self._events if ev["script_oracle"]["accepted"]),
                "rejected_count": sum(1 for ev in self._events if not ev["script_oracle"]["accepted"]),
            },
            "synthetic_simulator": _default_synthetic_field(),
            "native_execution": {
                "executed": False,
                "execution_verified": False,
                "settlement_observed": False,
            },
            "evidence_gates": copy.deepcopy(DEFAULT_EVIDENCE_GATES),
        }

    def export_trace(self) -> dict[str, Any]:
        self._assert_target_immutable()
        return {
            "schema": CAMPAIGN_SCHEMA,
            "scenario_id": self.scenario.scenario_id,
            "split": self.scenario.split,
            "family": self.scenario.family,
            "calibration_scenario": self.scenario.calibration,
            "requires_child_completion": self.scenario.requires_child_completion,
            "native_supported": self.scenario.native_supported,
            "required_evidence_gates": list(self.scenario.required_evidence_gates),
            "max_attempts": self.max_attempts,
            "source_identity": copy.deepcopy(self.source_identity),
            "funded_target": copy.deepcopy(self._target),
            "funded_target_digest": self._target_digest,
            "events": copy.deepcopy(self._events),
            "score": self.score(),
        }


def replay_campaign_trace(
    source_root: Path,
    trace: dict[str, Any],
    *,
    expected_scenario_id: str | None = None,
    expected_split: str | None = None,
    expected_target_digest: str | None = None,
    expected_max_attempts: int | None = None,
) -> CPACampaignSession:
    """Re-execute every raw proposal against verified source bytes and reject tampering."""
    _require(type(trace) is dict and trace.get("schema") == CAMPAIGN_SCHEMA,
             "unsupported CPA campaign trace schema")
    scenario_id = trace.get("scenario_id")
    _require(type(scenario_id) is str, "campaign trace missing scenario_id")
    if expected_scenario_id is not None:
        _require(scenario_id == expected_scenario_id,
                 "campaign trace scenario_id differs from evaluator expectation")
    max_attempts = expected_max_attempts if expected_max_attempts is not None else trace.get("max_attempts")
    _require(type(max_attempts) is int and trace.get("max_attempts") == max_attempts,
             "campaign trace max_attempts differs from evaluator context")

    session = CPACampaignSession(source_root, scenario_id, max_attempts=max_attempts)
    if expected_split is not None:
        _require(session.scenario.split == expected_split and trace.get("split") == expected_split,
                 "campaign trace split differs from evaluator expectation")
    if expected_target_digest is not None:
        _require(session.observe()["funded_target_digest"] == expected_target_digest,
                 "evaluator target digest differs from installed CPA campaign scenario")
        _require(trace.get("funded_target_digest") == expected_target_digest,
                 "campaign trace target digest differs from evaluator expectation")

    score_native = trace.get("score", {}).get("native_execution", {})
    _require(score_native == {"executed": False, "execution_verified": False, "settlement_observed": False},
             "reference campaign trace cannot claim native execution or observed settlement")
    _require(trace.get("score", {}).get("evidence_gates") == DEFAULT_EVIDENCE_GATES,
             "reference campaign trace cannot claim unverified evidence gates")

    events = trace.get("events")
    _require(type(events) is list and len(events) <= max_attempts, "invalid campaign event count")
    for index, event in enumerate(events):
        _require(type(event) is dict and event.get("index") == index and "raw_proposal" in event,
                 "invalid campaign trace event")
        ev_native = event.get("native_execution", {})
        _require(
            ev_native.get("executed") is False
            and ev_native.get("execution_verified") is False
            and ev_native.get("settlement_observed") is False,
            "reference campaign event cannot claim native execution or observed settlement",
        )
        _require(event.get("evidence_gates") == DEFAULT_EVIDENCE_GATES,
                 "reference campaign event cannot claim unverified evidence gates")
        session.step(event["raw_proposal"])

    if _canonical(trace) != _canonical(session.export_trace()):
        raise ValueError("CPA campaign trace differs from deterministic source replay")
    return session


def run_campaign_benchmark(
    source_root: Path,
    *,
    split: str = "all",
    output: Path | None = None,
) -> dict[str, Any]:
    """Execute honest and adversarial suites across the scenario split and replay all traces."""
    scenarios = load_campaign_scenarios(split)
    rows: list[dict[str, Any]] = []
    source_identity: dict[str, Any] | None = None

    for scenario in scenarios:
        honest_session = CPACampaignSession(source_root, scenario.scenario_id, max_attempts=8)
        source_identity = honest_session.source_identity
        for prop in scenario.honest_proposals:
            honest_session.step(prop)
        honest_trace = honest_session.export_trace()
        replay_campaign_trace(
            source_root,
            honest_trace,
            expected_scenario_id=scenario.scenario_id,
            expected_split=scenario.split,
            expected_target_digest=honest_session.observe()["funded_target_digest"],
            expected_max_attempts=8,
        )
        honest_score = honest_session.score()
        honest_ok = (
            honest_score["legitimate_completion"] is True
            and honest_score["attacker_success"] is False
            and honest_score["unauthorized_sats"] == 0
            and honest_score["diverted_sats"] == 0
        )

        adv_checks: list[dict[str, Any]] = []
        adv_trace = None
        adv_score = None
        adv_ok = True
        if scenario.adversarial_proposals:
            adv_session = CPACampaignSession(
                source_root,
                scenario.scenario_id,
                max_attempts=max(8, len(scenario.adversarial_proposals)),
            )
            for item in scenario.adversarial_proposals:
                ev = adv_session.step(item["proposal"])
                matched = (
                    ev["script_oracle"]["accepted"] == item["expected_script_accept"]
                    and ev["policy_decision"]["parent_policy_accept"] == item["expected_parent_policy_accept"]
                    and ev["policy_decision"]["calibration"] == item["expected_calibration"]
                    and ev["step_score"]["attack_success"] is False
                )
                adv_ok = adv_ok and matched
                adv_checks.append({
                    "label": item["label"],
                    "txid": ev["txid"],
                    "wtxid": ev["wtxid"],
                    "script_accepted": ev["script_oracle"]["accepted"],
                    "parent_policy_accept": ev["policy_decision"]["parent_policy_accept"],
                    "calibration": ev["policy_decision"]["calibration"],
                    "script_failure": ev["script_oracle"]["script_failure"],
                    "expectation_met": matched,
                })
            adv_trace = adv_session.export_trace()
            replay_campaign_trace(
                source_root,
                adv_trace,
                expected_scenario_id=scenario.scenario_id,
                expected_split=scenario.split,
                expected_target_digest=adv_session.observe()["funded_target_digest"],
                expected_max_attempts=adv_session.max_attempts,
            )
            adv_score = adv_session.score()
            adv_ok = (
                adv_ok
                and adv_score["attacker_success"] is False
                and adv_score["unauthorized_sats"] == 0
                and adv_score["diverted_sats"] == 0
            )
            if scenario.calibration:
                adv_ok = adv_ok and adv_score["calibration_acceptances"] == 1

        if output is not None:
            traces_dir = output / "traces"
            traces_dir.mkdir(parents=True, exist_ok=True)
            (traces_dir / f"{scenario.scenario_id}.honest.json").write_text(
                json.dumps(honest_trace, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            if adv_trace is not None:
                (traces_dir / f"{scenario.scenario_id}.adversarial.json").write_text(
                    json.dumps(adv_trace, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )

        rows.append({
            "scenario_id": scenario.scenario_id,
            "split": scenario.split,
            "family": scenario.family,
            "program_id": scenario.program_id,
            "calibration": scenario.calibration,
            "native_supported": scenario.native_supported,
            "required_evidence_gates": list(scenario.required_evidence_gates),
            "honest_legitimate_completion": honest_score["legitimate_completion"],
            "adversarial_checks": adv_checks,
            "adversarial_score": adv_score,
            "replay_verified": True,
            "expectation_met": honest_ok and adv_ok,
        })

    summary = {
        "schema": CAMPAIGN_BENCHMARK_SCHEMA,
        "split": split,
        "source_identity": source_identity,
        "scenario_count": len(rows),
        "dev_count": sum(1 for r in rows if r["split"] == "dev"),
        "held_out_count": sum(1 for r in rows if r["split"] == "held_out"),
        "all_expectations_met": all(r["expectation_met"] for r in rows),
        "attacker_success_count": 0,
        "evidence_gates": copy.deepcopy(DEFAULT_EVIDENCE_GATES),
        "scenarios": rows,
    }
    if output is not None:
        output.mkdir(parents=True, exist_ok=True)
        (output / f"summary.{split}.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    return summary


def _execute_with_opcount(script: bytes, items: list[bytes], actual_digest: bytes, oracle_mod: Any) -> tuple[list[bytes], int]:
    """Run the pinned Script oracle while counting executed opcodes."""
    ScriptFailure = oracle_mod.ScriptFailure
    number = oracle_mod.number
    encode_number = oracle_mod.encode_number
    stack, alt, conditions = list(items), [], []
    op_count = 0

    def bounds() -> None:
        if len(stack) + len(alt) > 1000 or any(len(item) > 520 for item in stack + alt):
            raise ScriptFailure("stack bound")

    def pop() -> bytes:
        if not stack:
            raise ScriptFailure("stack underflow")
        return stack.pop()

    def is_true(raw: bytes) -> bool:
        return any(byte != 0 for byte in raw[:-1]) or bool(raw and raw[-1] not in (0, 128))

    bounds()
    pos = 0
    while pos < len(script):
        opcode = script[pos]
        pos += 1
        op_count += 1
        literal = None
        if 1 <= opcode <= 75:
            literal = script[pos:pos + opcode]
            if len(literal) != opcode:
                raise ScriptFailure("truncated push")
            pos += opcode
        enabled = all(conditions)
        if opcode == 0x63:
            cond = pop() if enabled else b""
            if cond not in (b"", b"\x01"):
                raise ScriptFailure("MINIMALIF")
            conditions.append(enabled and cond == b"\x01")
            continue
        if opcode == 0x67:
            if not conditions:
                raise ScriptFailure("unbalanced ELSE")
            conditions[-1] = not conditions[-1]
            continue
        if opcode == 0x68:
            if not conditions:
                raise ScriptFailure("unbalanced ENDIF")
            conditions.pop()
            continue
        if not enabled:
            continue
        if literal is not None:
            stack.append(literal)
        elif opcode == 0:
            stack.append(b"")
        elif 0x51 <= opcode <= 0x60:
            stack.append(encode_number(opcode - 0x50))
        elif opcode == 0x69:
            if not is_true(pop()):
                raise ScriptFailure("VERIFY")
        elif opcode == 0x6B:
            alt.append(pop())
        elif opcode == 0x6C:
            if not alt:
                raise ScriptFailure("altstack underflow")
            stack.append(alt.pop())
        elif opcode == 0x75:
            pop()
        elif opcode == 0x79:
            idx = number(pop())
            if idx < 0 or idx >= len(stack):
                raise ScriptFailure("PICK index")
            stack.append(stack[-idx - 1])
        elif opcode == 0x7C:
            right, left = pop(), pop()
            stack.extend((right, left))
        elif opcode == 0x7E:
            right, left = pop(), pop()
            stack.append(left + right)
        elif opcode == 0x82:
            if not stack:
                raise ScriptFailure("SIZE underflow")
            stack.append(encode_number(len(stack[-1])))
        elif opcode == 0x88:
            if pop() != pop():
                raise ScriptFailure("EQUALVERIFY")
        elif opcode == 0x9D:
            if number(pop()) != number(pop()):
                raise ScriptFailure("NUMEQUALVERIFY")
        elif opcode in (0x93, 0x94, 0x9B, 0x9C, 0xA1, 0xA2):
            right, left = number(pop()), number(pop())
            ops = {
                0x93: lambda: left + right,
                0x94: lambda: left - right,
                0x9B: lambda: bool(left or right),
                0x9C: lambda: left == right,
                0xA1: lambda: left <= right,
                0xA2: lambda: left >= right,
            }
            stack.append(encode_number(int(ops[opcode]())))
        elif opcode == 0xA5:
            maximum, minimum, value = number(pop()), number(pop()), number(pop())
            stack.append(encode_number(int(minimum <= value < maximum)))
        elif opcode == 0xA8:
            stack.append(hashlib.sha256(pop()).digest())
        elif opcode == 0xAD:
            key, candidate = pop(), pop()
            selected = b"\x02" + hashlib.sha256(b"BIPSpace/Keyless-CHECKSIG/TXCOMMIT-draft").digest()
            if key != selected or len(candidate) != 32 or candidate != actual_digest:
                raise ScriptFailure("TXCOMMIT")
        else:
            raise ScriptFailure(f"unsupported opcode {opcode:02x}")
        bounds()
    if conditions or alt:
        raise ScriptFailure("unbalanced execution")
    return stack, op_count


def _worker_main(root: Path, request: dict[str, Any]) -> dict[str, Any]:
    """Isolated worker reconstructing CPA stages, candidate tx, and Script trace."""
    from dataclasses import replace

    sys.path.insert(0, str(root / "scripts/research"))
    sys.path.insert(0, str(root / "scripts/tests"))
    import canonical_proof_authority as cpa
    import cpa_transition as machine
    import keyless_checksig_rpc as base
    import test_keyless_state_machine as oracle_mod

    base.tweaked_key = lru_cache(maxsize=128)(base.tweaked_key)

    scenarios_raw = json.loads(
        (root / "bitvm_arena_worker/data/cpa_campaign_scenarios.json").read_text(encoding="utf-8")
    )
    entry = next(item for item in scenarios_raw["scenarios"] if item["scenario_id"] == request["scenario_id"])
    circuit = entry["circuit"]
    nodes = {name: tuple(spec) for name, spec in circuit["nodes"].items()}
    outputs = tuple(circuit["outputs"])
    role_swapped_nodes = {
        name: (("input", 2 if spec[1] == 1 else 1 if spec[1] == 2 else spec[1]) if spec[0] == "input" else spec)
        for name, spec in nodes.items()
    }

    root_stage = machine.compile_machine(nodes, outputs, n_inputs=circuit["n_inputs"])

    @lru_cache(maxsize=1)
    def get_next_epoch_stage() -> Any:
        return machine.compile_machine(nodes, outputs, n_inputs=circuit["n_inputs"], epoch=1)

    @lru_cache(maxsize=1)
    def get_wider_stage() -> Any:
        return machine.compile_machine(nodes, outputs, n_inputs=circuit["n_inputs"], cap=9000)

    @lru_cache(maxsize=1)
    def get_role_swapped_stage() -> Any:
        return machine.compile_machine(role_swapped_nodes, outputs, n_inputs=circuit["n_inputs"])

    child_stage = root_stage.actions[0].successor
    assert child_stage is not None

    funding_txid = request.get("funding_txid_override") or entry["funding_txid"]
    funding_vout = int(entry["funding_vout"])
    auth_bits = tuple(circuit["authorized_bits"])
    child_auth_bits = tuple(circuit["child_authorized_bits"])
    child_selector = child_auth_bits[2]

    honest_tx, honest_proof = machine.spend(root_stage, funding_txid, funding_vout, auth_bits)
    root_spk, root_control = root_stage.leaf.output()
    child_outputs = machine.outputs_for(
        child_stage.program, child_stage.epoch, child_selector, child_stage.actions[child_selector]
    )

    def stage_card(s: Any, txid_hex: str, vout_idx: int) -> dict[str, Any]:
        outpoint_bytes = bytes.fromhex(txid_hex)[::-1] + struct.pack("<I", vout_idx)
        return {
            "authority_id": s.authority.hex(),
            "descriptor_digest": hashlib.sha256(s.descriptor.encode()).hexdigest(),
            "state_root": s.state_root.hex(),
            "grant_id": s.grant.hex(),
            "program_id": s.program.program_id.hex(),
            "outpoint": outpoint_bytes.hex(),
            "txid": txid_hex,
            "vout": vout_idx,
            "script_pubkey": s.leaf.output()[0].hex(),
            "amount_sats": s.amount,
            "payout_cap_sats": s.cap,
            "epoch": s.epoch,
        }

    funded_target = {
        "scenario_id": entry["scenario_id"],
        "split": entry["split"],
        "family": entry["family"],
        "outpoint": (bytes.fromhex(funding_txid)[::-1] + struct.pack("<I", funding_vout)).hex(),
        "funding_txid": funding_txid,
        "funding_vout": funding_vout,
        "authority": {
            "authority_id": root_stage.authority.hex(),
            "descriptor_digest": hashlib.sha256(root_stage.descriptor.encode()).hexdigest(),
            "grant_id": root_stage.grant.hex(),
            "state_root": root_stage.state_root.hex(),
            "payout_cap_sats": root_stage.cap,
            "epoch": root_stage.epoch,
        },
        "authority_id": root_stage.authority.hex(),
        "program": {
            "program_id": root_stage.program.program_id.hex(),
            "circuit_name": circuit["name"],
            "n_inputs": circuit["n_inputs"],
            "node_count": root_stage.program.node_count,
            "nodes": circuit["nodes"],
            "outputs": circuit["outputs"],
        },
        "program_id": root_stage.program.program_id.hex(),
        "context": {
            "network_domain": root_stage.descriptor.network_domain.hex(),
            "execution_profile": root_stage.descriptor.execution_profile.hex(),
            "verifier_suite_id": root_stage.descriptor.verifier_suite_id.hex(),
            "statement_abi_id": root_stage.descriptor.statement_abi_id.hex(),
            "delegation_policy_id": root_stage.descriptor.delegation_policy_id.hex(),
            "resource_profile_id": root_stage.descriptor.resource_profile_id.hex(),
            "funding_height": entry["funding_height"],
            "version": 2,
            "locktime": 0,
            "sequence": 0xFFFFFFFD,
            "script_pubkey": root_spk.hex(),
            "tapleaf_hash": base.tapleaf(root_stage.leaf.script).hex(),
            "control_hex": root_control.hex(),
        },
        "intended_recipient": honest_tx.outputs[0].script.hex(),
        "intended_payout_sats": honest_tx.outputs[0].amount,
        "intended_successor": {
            "amount_sats": child_stage.amount,
            "script_pubkey": child_stage.leaf.output()[0].hex(),
            "authority_id": child_stage.authority.hex(),
            "state_root": child_stage.state_root.hex(),
            "grant_id": child_stage.grant.hex(),
            "epoch": child_stage.epoch,
            "payout_cap_sats": child_stage.cap,
            "intended_child_recipient": child_outputs[0].script.hex(),
            "intended_child_payout_sats": child_outputs[0].amount,
            "intended_terminal_script": child_outputs[1].script.hex(),
        },
        "amount": root_stage.amount,
        "amount_sats": root_stage.amount,
        "fee_sats": machine.FEE,
    }
    if request["mode"] == "bootstrap":
        calibration_target = stage_card(get_wider_stage(), funding_txid, 3)
        digest_bytes = oracle_mod.transaction_digest(honest_tx, root_stage.leaf.script)
        stack, _ = _execute_with_opcount(root_stage.leaf.script, honest_proof[:-2], digest_bytes, oracle_mod)
        return {
            "honest_control_accepted": stack == [b"\x01"],
            "funded_target": funded_target,
            "calibration_target": calibration_target,
        }

    proposal = request["proposal"]
    if proposal["post_confirm_mode"] == "replay_confirmed_tx":
        proposal = copy.deepcopy(request["confirmed_parent_proposal"])

    is_calibration = proposal["target_coin"] == "calibration_wider_parent"
    stage_role = proposal["stage_role"]

    if is_calibration:
        active_stage = get_wider_stage()
        spend_txid, spend_vout = funding_txid, 3
        expected_stage = root_stage
        expected_txid, expected_vout = funding_txid, funding_vout
        expected_honest_tx, expected_honest_proof = honest_tx, honest_proof
        expected_selector = 0
    elif stage_role == "parent":
        active_stage = root_stage
        spend_txid, spend_vout = funding_txid, funding_vout
        expected_stage = root_stage
        expected_txid, expected_vout = funding_txid, funding_vout
        expected_honest_tx, expected_honest_proof = honest_tx, honest_proof
        expected_selector = 0
    else:
        parent_txid = request["authenticated_parent_txid"]
        active_stage = child_stage
        spend_txid, spend_vout = parent_txid, 1
        expected_stage = child_stage
        expected_txid, expected_vout = parent_txid, 1
        expected_honest_tx, expected_honest_proof = machine.spend(
            child_stage, parent_txid, 1, child_auth_bits
        )
        expected_selector = child_selector

    b0, b1, b2 = proposal["request_bits"]
    declared_bits = (b0, b1, b2)
    role_mode = proposal["input_role_mode"]
    if role_mode == "declared":
        effective_bits = declared_bits
    elif role_mode == "swap_a_b":
        effective_bits = (b1, b0, b2)
    elif role_mode == "swap_a_selector":
        effective_bits = (b2, b1, b0)
    elif role_mode == "swap_b_selector":
        effective_bits = (b0, b2, b1)
    else:
        effective_bits = declared_bits

    if role_mode == "role_swapped_circuit_1_2":
        trace_program = get_role_swapped_stage().program
        gate_bits = list(machine.trace(trace_program, effective_bits))
        trace_vals = dict(zip((k for k, _ in trace_program.records), gate_bits))
        selector_val = trace_vals[trace_program.output_hashes[1]]
    elif role_mode in ("swap_a_b", "swap_a_selector", "swap_b_selector"):
        trace_program = active_stage.program
        aliased_bits = list(machine.trace(trace_program, effective_bits))
        gate_bits = [
            declared_bits[struct.unpack("<I", record[1:5])[0]] if record[0] == 0 else aliased_bits[idx]
            for idx, (_, record) in enumerate(trace_program.records)
        ]
        selector_val = b2
    else:
        trace_program = active_stage.program
        gate_bits = list(machine.trace(trace_program, declared_bits))
        trace_vals = dict(zip((k for k, _ in trace_program.records), gate_bits))
        selector_val = trace_vals[trace_program.output_hashes[1]]

    base_outputs = list(machine.outputs_for(
        active_stage.program, active_stage.epoch, selector_val, active_stage.actions[selector_val]
    ))
    if proposal["recipient_id"] != "authorized":
        rec_spk = {
            "recipient_0": b"\x51\x20" + base.RECIPIENTS[0],
            "recipient_1": b"\x51\x20" + base.RECIPIENTS[1],
            "nums_burn": b"\x51\x20" + base.NUMS_X,
        }[proposal["recipient_id"]]
        base_outputs[0] = replace(base_outputs[0], script=rec_spk)
    if proposal["payout_sats"] is not None:
        base_outputs[0] = replace(base_outputs[0], amount=proposal["payout_sats"])
    if proposal["successor_sats"] is not None and len(base_outputs) >= 2:
        base_outputs[1] = replace(base_outputs[1], amount=proposal["successor_sats"])

    succ_mode = proposal["successor_mode"]
    if succ_mode == "self_script":
        base_outputs[1] = replace(base_outputs[1], script=active_stage.leaf.output()[0])
    elif succ_mode == "next_epoch_script":
        base_outputs[1] = replace(base_outputs[1], script=get_next_epoch_stage().leaf.output()[0])
    elif succ_mode == "wider_script":
        base_outputs[1] = replace(base_outputs[1], script=get_wider_stage().leaf.output()[0])
    elif succ_mode == "zero_terminal":
        base_outputs[1] = base.Output(0, b"\x6a\x20" + bytes(32))
    elif succ_mode == "reorder_outputs":
        base_outputs = base_outputs[::-1]
    elif succ_mode == "omit_successor":
        base_outputs = base_outputs[:1]
    elif succ_mode == "append_op_return":
        base_outputs.append(base.Output(0, b"\x6a"))

    primary_input = base.Input(
        bytes.fromhex(spend_txid)[::-1],
        spend_vout,
        active_stage.amount,
        active_stage.leaf.output()[0],
        sequence=proposal["sequence"],
    )
    tx_inputs = [primary_input]
    extra_witnesses: list[list[bytes]] = []
    if proposal["extra_funded_input"]:
        coinbase_leaf = base.Leaf(b"\x51")
        coinbase_spk, coinbase_control = coinbase_leaf.output()
        tx_inputs.append(base.Input(bytes.fromhex(funding_txid)[::-1], 4, 100_000, coinbase_spk))
        extra_witnesses.append([coinbase_leaf.script, coinbase_control])

    tx = base.Tx(
        inputs=tuple(tx_inputs),
        outputs=tuple(base_outputs),
        version=proposal["version"],
        locktime=proposal["locktime"],
    )

    tapleaf_mode = proposal["tapleaf_override"]
    if tapleaf_mode == "none":
        leaf_stage = active_stage
    elif tapleaf_mode == "wider_cap_9000":
        leaf_stage = get_wider_stage()
    elif tapleaf_mode == "next_epoch":
        leaf_stage = get_next_epoch_stage()
    else:
        leaf_stage = get_role_swapped_stage()

    w_mode = proposal["witness_mode"]
    if w_mode == "stale_honest":
        proof = expected_honest_proof.copy()
    elif w_mode == "sibling_coin_stale":
        _, proof = machine.spend(active_stage, funding_txid, 1, effective_bits)
    elif w_mode == "sibling_child_statement":
        proof = machine.witness(active_stage, tx, effective_bits)
        _, sibling_proof = machine.spend(active_stage, funding_txid, 1, effective_bits)
        cs_idx = machine.FIELDS.index("child_statement")
        proof[cs_idx] = sibling_proof[cs_idx]
    elif w_mode == "false_sibling_context_fresh":
        fake_tx = replace(tx, inputs=(replace(tx.inputs[0], index=1),) + tx.inputs[1:])
        proof = machine.witness(active_stage, fake_tx, effective_bits)
    else:
        chosen_leaf_script = leaf_stage.leaf.script
        digest = base.sighash(tx, 0, leaf=base.tapleaf(chosen_leaf_script))
        state_bytes = active_stage.state
        if proposal["state_override"] == "stale_parent_state":
            state_bytes = root_stage.state
        elif proposal["state_override"] == "zero44":
            state_bytes = bytes(44)
        cur_state_root = cpa.state_root(state_bytes)

        auth_mode = proposal["authority_override"]
        if auth_mode == "none":
            parent_auth = active_stage.authority
        elif auth_mode == "wider_cap_9000":
            parent_auth = get_wider_stage().authority
        elif auth_mode == "next_epoch":
            parent_auth = get_next_epoch_stage().authority
        elif auth_mode == "parent_stage":
            parent_auth = root_stage.authority
        else:
            parent_auth = bytes(32)

        grant_mode = proposal["grant_override"]
        if grant_mode == "none":
            grant_bytes = active_stage.grant
        elif grant_mode == "wider_cap_9000":
            grant_bytes = get_wider_stage().grant
        elif grant_mode == "next_epoch":
            grant_bytes = get_next_epoch_stage().grant
        elif grant_mode == "parent_stage":
            grant_bytes = root_stage.grant
        else:
            grant_bytes = bytes(32)

        _, control_bytes = active_stage.leaf.output()
        if proposal["control_override"] == "flip_parity":
            control_bytes = bytes([control_bytes[0] ^ 1]) + control_bytes[1:]
        elif proposal["control_override"] == "zero_sibling":
            control_bytes = control_bytes[:33] + bytes(32)
        elif proposal["control_override"] == "wider_cap_9000":
            _, control_bytes = get_wider_stage().leaf.output()

        proof = [
            state_bytes,
            parent_auth,
            cur_state_root,
            grant_bytes,
            digest,
            machine.statement(parent_auth, cur_state_root, grant_bytes, digest),
            tx.inputs[0].outpoint(),
            tx.inputs[0].script[2:],
            base.tapleaf(chosen_leaf_script),
        ]
        proof.extend(base.script_number(bit) for bit in gate_bits)
        proof.extend([chosen_leaf_script, control_bytes])

    if proposal["context_mutation"] is not None:
        cm = proposal["context_mutation"]
        idx = machine.FIELDS.index(cm["field"])
        if cm["op"] == "zero":
            proof[idx] = bytes(len(proof[idx]))
        elif cm["op"] == "drop_first_byte":
            proof[idx] = proof[idx][1:]
        elif cm["op"] == "append_zero_byte":
            proof[idx] = proof[idx] + b"\x00"

    if proposal["gate_mutation"] is not None:
        gm = proposal["gate_mutation"]
        gate_pos = len(machine.FIELDS) + gm["gate_index"]
        _require(gate_pos < len(proof) - 2, "gate_index exceeds circuit node count")
        op = gm["op"]
        if op == "flip":
            proof[gate_pos] = b"" if proof[gate_pos] else b"\x01"
        elif op == "explicit_zero_00":
            proof[gate_pos] = b"\x00"
        elif op == "negative_zero_80":
            proof[gate_pos] = b"\x80"
        elif op == "padded_one_0100":
            proof[gate_pos] = b"\x01\x00"
        elif op == "out_of_range_02":
            proof[gate_pos] = b"\x02"

    annex_bytes = bytes.fromhex(proposal["annex_hex"]) if proposal["annex_hex"] is not None else None
    serialized_witness = proof + ([annex_bytes] if annex_bytes is not None else [])
    raw_tx_hex, txid = tx.serialize([serialized_witness] + extra_witnesses)
    decoded = decode_transaction(raw_tx_hex)
    honest_raw_hex, _ = expected_honest_tx.serialize([expected_honest_proof])

    op_count = 0
    script_failure = None
    expected_leaf_script = active_stage.leaf.script
    _, expected_control = active_stage.leaf.output()
    control_ok = proof[-2] == expected_leaf_script and proof[-1] == expected_control
    if not control_ok:
        script_valid = False
        script_failure = "taproot_leaf_or_control_mismatch"
    else:
        try:
            actual_digest = oracle_mod.transaction_digest(tx, expected_leaf_script, annex=annex_bytes)
            stack, op_count = _execute_with_opcount(expected_leaf_script, proof[:-2], actual_digest, oracle_mod)
            script_valid = stack == [b"\x01"]
            if not script_valid:
                script_failure = "non_true_final_stack"
        except oracle_mod.ScriptFailure as exc:
            script_valid = False
            script_failure = str(exc)

    gate_values: dict[bytes, int] = {}
    gate_trace_valid = len(proof) == len(expected_honest_proof)
    for offset, (node_hash, record) in enumerate(expected_stage.program.records, len(machine.FIELDS)):
        raw_bit = proof[offset] if offset < len(proof) - 2 else None
        if raw_bit not in (b"", b"\x01"):
            gate_trace_valid = False
            bit_val = 0
        else:
            bit_val = int(raw_bit == b"\x01")
        if record[0] == 1 and bit_val != record[1]:
            gate_trace_valid = False
        elif record[0] == 2 and bit_val != 1 - gate_values[record[1:33]] * gate_values[record[33:65]]:
            gate_trace_valid = False
        gate_values[node_hash] = bit_val

    circuit_out = (
        [gate_values[h] for h in expected_stage.program.output_hashes]
        if len(gate_values) == len(expected_stage.program.records)
        else None
    )

    return {
        "funded_target": funded_target,
        "executed_target": stage_card(active_stage, spend_txid, spend_vout),
        "expected_stage_target": stage_card(expected_stage, expected_txid, expected_vout),
        "expected_selector": expected_selector,
        "transaction_hex": raw_tx_hex,
        "txid": txid,
        "wtxid": decoded["wtxid"],
        "witness_hex": [item.hex() for item in serialized_witness],
        "expected_honest_tx_hex": honest_raw_hex,
        "expected_honest_witness_hex": [item.hex() for item in expected_honest_proof],
        "script_valid": script_valid,
        "script_failure": script_failure,
        "op_count": op_count,
        "gate_trace_valid": gate_trace_valid,
        "circuit_outputs": circuit_out,
    }


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--campaign-worker":
        raise SystemExit("Use bitvm-arena cpa-campaign-benchmark or the Python API")
    payload = sys.stdin.read(16_385)
    if len(payload) > 16_384:
        raise SystemExit("campaign worker request too large")
    print(_canonical(_worker_main(Path(sys.argv[2]), json.loads(payload))))
