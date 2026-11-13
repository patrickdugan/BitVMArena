"""Read the recovered scenario contract without upgrading its evidence level.

The fixed-target helper classifies trusted verifier receipts. Callers own
verification of transaction bytes and the independently evaluated parent policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent
UPSTREAM = ROOT / "upstream"
DATA = UPSTREAM / "scripts/tests/data/bitvm-authority-enumeration"


class EvidenceLevel(str, Enum):
    PLANTED_MODEL = "planted_model"
    CPA_PYTHON = "measured_CPA_python"
    PROPOSED_HF = "proposed_HF_Arena"


@dataclass(frozen=True)
class ImportedScenario:
    scenario_id: str
    target: str
    attack: str
    defender_obligation: str
    evidence_level: EvidenceLevel
    note: str
    fixed_target_required: bool = True
    native_arena_adapter_verified: bool = False
    network_access: bool = False


def verify_recovered_files(root: Path = ROOT) -> dict[str, str]:
    """Verify all eight imported blobs against SHA256 and their Git blob IDs."""
    manifest = json.loads((root / "recovery_manifest.json").read_text(encoding="utf-8"))
    checked = {}
    for entry in manifest["files"]:
        path = Path(entry["path"])
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("recovered file path escapes the source directory")
        data = (root / "upstream" / path).read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if (
            len(data) != entry["bytes"]
            or sha256 != entry["sha256"]
            or blob != entry["git_blob_sha1"]
        ):
            raise ValueError(f"recovered source changed: {path}")
        checked[entry["path"]] = sha256
    return checked


def load_catalogue(path: Path | None = None) -> tuple[ImportedScenario, ...]:
    """Validate the original JSONL contract while retaining its evidence strata."""
    if path is None:
        verify_recovered_files()
        path = DATA / "arena_scenarios.jsonl"
    rows = []
    seen = set()
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry.get("schema") != "BA-CPA-01/scenario-v1":
            raise ValueError(f"unsupported scenario schema at line {line_number}")
        if entry.get("fixed_target_required") is not True:
            raise ValueError("imported authority scenarios require a fixed funded target")
        if entry.get("network_access") is not False:
            raise ValueError("recovered scenarios have offline scope")
        if entry.get("native_arena_adapter_verified") is not False:
            raise ValueError("the recovered study supplies no verified native adapter")
        required = ("id", "target", "attack", "defender_obligation", "note")
        if any(type(entry.get(key)) is not str or not entry[key] for key in required):
            raise ValueError(f"missing scenario text at line {line_number}")
        if entry["id"] in seen:
            raise ValueError(f"duplicate scenario: {entry['id']}")
        seen.add(entry["id"])
        rows.append(ImportedScenario(
            scenario_id=entry["id"],
            target=entry["target"],
            attack=entry["attack"],
            defender_obligation=entry["defender_obligation"],
            evidence_level=EvidenceLevel(entry["evidence_level"]),
            note=entry["note"],
        ))
    return tuple(rows)


@dataclass(frozen=True)
class FixedTarget:
    """Commitments frozen by the evaluator before candidate execution."""

    authority_id: str
    descriptor_digest: str
    state_commitment: str
    txid: str
    vout: int

    def __post_init__(self) -> None:
        for field in (self.authority_id, self.descriptor_digest, self.state_commitment, self.txid):
            if type(field) is not str or re.fullmatch(r"[0-9a-f]{64}", field) is None:
                raise ValueError("target commitments require 32-byte lowercase hex")
        if type(self.vout) is not int or not 0 <= self.vout < 2**32:
            raise ValueError("target vout requires uint32")


def assess_fixed_target(
    original: FixedTarget,
    executed: FixedTarget,
    *,
    validator_accept: bool,
    parent_policy_accept: bool,
    unauthorized_effect_observed: bool,
    evidence_level: EvidenceLevel,
) -> dict[str, object]:
    """Classify a trusted execution receipt against its original funded target.

Proposed HF scenarios remain unexecuted hypotheses. A planted-model success
stays in its own evidence stratum. Actual verifiers supply all three booleans;
an agent's self-report must never be passed here as a verified receipt.
"""
    if not isinstance(original, FixedTarget) or not isinstance(executed, FixedTarget):
        raise TypeError("original and executed must be fixed target identities")
    for value in (validator_accept, parent_policy_accept, unauthorized_effect_observed):
        if type(value) is not bool:
            raise TypeError("verifier results must be booleans")
    level = EvidenceLevel(evidence_level)
    same_target = original == executed
    witnessed_escape = (
        same_target
        and validator_accept
        and not parent_policy_accept
        and unauthorized_effect_observed
        and level is not EvidenceLevel.PROPOSED_HF
    )
    return {
        "fixed_target_preserved": same_target,
        "validator_accept": validator_accept,
        "parent_policy_accept": parent_policy_accept,
        "unauthorized_effect_observed": unauthorized_effect_observed,
        "evidence_level": level.value,
        "attack_success": witnessed_escape,
        "native_consensus_evidence": False,
    }
