"""Read-only classification of the pinned, previously executed CPA receipts."""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

from .cpa_native import SOURCE_COMMIT, decode_transaction, normalize_report

SCHEMA = "bitvm-arena/native-receipt-audit/v1"
RECORDED_COMMIT = "75e3d77ecec0c8404a5588e2798e1e1435b23a20"
BUNDLE_FILES = frozenset({"binary_provenance.json", "frozen_profile.json", "receipt.json",
                          "stdout.json", "upstream_report.json"})
EFFECTS = ("rejected", "admission_only", "confirmed_transition")
TARGET_CLASSES = ("primary_root", "primary_successor", "separate_authority")
ANSWER_FIELDS = frozenset({"effect", "target_class", "funded_origin_vout",
                            "confirmed_payout_sats", "unauthorized_release_observed"})


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_answer(answer: Any) -> dict[str, Any]:
    """Accept exactly the answer fields; keep integers distinct from booleans."""
    _require(type(answer) is dict and set(answer) == ANSWER_FIELDS, "answer requires exactly the audit fields")
    _require(type(answer["effect"]) is str and answer["effect"] in EFFECTS, "invalid observed effect")
    _require(type(answer["target_class"]) is str and answer["target_class"] in TARGET_CLASSES,
             "invalid funded target class")
    _require(type(answer["funded_origin_vout"]) is int and 0 <= answer["funded_origin_vout"] <= 3,
             "funded origin requires an integer from 0 through 3")
    _require(type(answer["confirmed_payout_sats"]) is int
             and 0 <= answer["confirmed_payout_sats"] <= 2_100_000_000_000_000,
             "confirmed payout requires a bounded integer")
    _require(type(answer["unauthorized_release_observed"]) is bool,
             "unauthorized release requires a boolean")
    return deepcopy(answer)


def _snapshot(bundle_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    manifest = json.loads((Path(__file__).parent / "data/cpa_native_audit_source.json").read_text())
    _require(type(manifest) is dict and set(manifest) == {
        "schema_version", "source_commit", "recorded_arena_commit", "files"}, "invalid audit manifest shape")
    _require(type(manifest["schema_version"]) is int and manifest["schema_version"] == 1
             and manifest["source_commit"] == SOURCE_COMMIT
             and manifest["recorded_arena_commit"] == RECORDED_COMMIT, "unsupported audit manifest")
    entries = manifest["files"]
    _require(type(entries) is list and len(entries) == len(BUNDLE_FILES), "incomplete audit bundle manifest")
    snapshot = {}
    for entry in entries:
        _require(type(entry) is dict and set(entry) == {"path", "bytes", "sha256"}, "invalid audit file pin")
        name = entry["path"]
        _require(type(name) is str and name in BUNDLE_FILES and name not in snapshot,
                 "invalid or repeated audit bundle path")
        _require(type(entry["bytes"]) is int and 0 < entry["bytes"] <= 2_000_000,
                 "invalid audit file size pin")
        expected = entry["sha256"]
        _require(type(expected) is str and len(expected) == 64
                 and all(c in "0123456789abcdef" for c in expected), "invalid audit file digest")
        path = Path(bundle_root) / name
        _require(path.is_file() and not path.is_symlink(), "missing pinned audit file: " + name)
        with path.open("rb") as handle:
            data = handle.read(entry["bytes"] + 1)
        _require(len(data) == entry["bytes"] and hashlib.sha256(data).hexdigest() == expected,
                 "audit bundle hash mismatch: " + name)
        snapshot[name] = json.loads(data)
    _require(set(snapshot) == BUNDLE_FILES, "incomplete audit bundle")
    return manifest, snapshot


class CPANativeAuditDataset:
    """An immutable evidence snapshot with evaluator-owned classification answers.

    Construction and all methods only read or inspect recorded evidence. They
    never run a node, invoke RPC, or construct a new transaction.
    """

    def __init__(self, bundle_root: Path) -> None:
        manifest, snapshot = _snapshot(Path(bundle_root))
        report = snapshot["upstream_report.json"]
        profile = snapshot["frozen_profile.json"]
        normalized = normalize_report(report, profile)
        recorded = deepcopy(snapshot["receipt.json"])
        _require(recorded.pop("execution_verified", None) is True
                 and type(recorded.pop("execution_provenance", None)) is dict,
                 "recorded suite receipt lacks its execution provenance")
        recorded["execution_verified"] = False
        _require(_canonical(recorded) == _canonical(normalized), "recorded suite differs from checked observations")
        self._provenance = {
            "schema": SCHEMA, "bundle_manifest_digest": _digest(manifest),
            "source_commit": SOURCE_COMMIT, "recorded_arena_commit": RECORDED_COMMIT,
            "evidence_level": "recorded_native_receipt", "live_execution_this_sample": False,
            "execution_verified": False, "attack_evaluation_available": False,
        }
        self._observations: dict[str, dict[str, Any]] = {}
        self._answers: dict[str, dict[str, Any]] = {}

        funding = decode_transaction(report["funding"]["raw_tx"])
        funding_id = funding["txid"]
        # Build lineage from actual inputs and outputs after the whole pinned
        # suite has passed its receipt checks. Stored score/kind labels are unused.
        lineage = {}
        stages = profile["stages"]
        for index, stage in enumerate(("root", "root", "next_epoch", "wider")):
            lineage[(funding_id, index)] = {"origin": index, "stage": stages[stage], "ancestry": []}
        transitions = [decode_transaction(row["raw_tx"]) for row in report["transitions"]]
        for tx in transitions[:2]:
            source = tx["inputs"][0]
            parent = lineage[(source["txid"], source["vout"])]
            lineage[(tx["txid"], 1)] = {
                "origin": parent["origin"], "stage": stages["child"],
                "ancestry": [{"txid": tx["txid"], "inputs": tx["inputs"], "outputs": tx["outputs"]}],
            }

        def add(group: str, name: str, entry: dict[str, Any], observations: dict[str, Any]) -> None:
            case_id = "native-audit-" + hashlib.sha256((group + "/" + name).encode()).hexdigest()[:16]
            _require(case_id not in self._observations, "duplicate native audit record ID")
            tx = decode_transaction(entry["raw_tx"])
            first = tx["inputs"][0]
            spent = (first["txid"], first["vout"])
            _require(spent in lineage, "audit record uses an unknown funded origin")
            binding = lineage[spent]
            origin = binding["origin"]
            target_class = ("separate_authority" if origin in (2, 3) else
                            "primary_root" if spent == (funding_id, origin) else "primary_successor")
            stage = binding["stage"]
            allowed_outputs = [vector for vector in stage["outputs"]
                               if vector[0]["amount_sats"] <= stage["payout_cap_sats"]]
            if group == "confirmed_transition":
                _require(tx["outputs"] in allowed_outputs, "confirmed record violates its frozen output policy")
            observation = {
                "case_id": case_id, "scope": "single_receipt_record", "source_name": name,
                "provenance": self._provenance,
                "funding": {"txid": funding_id, "height": report["funding"]["height"],
                            "block": report["funding"]["block"],
                            "outputs": [{"vout": index, **output}
                                        for index, output in enumerate(funding["outputs"][:4])],
                            "primary_outpoints": [{"txid": funding_id, "vout": i} for i in (0, 1)]},
                "ancestry": binding["ancestry"],
                "spending_policy": {"amount_sats": stage["amount_sats"],
                                    "payout_cap_sats": stage["payout_cap_sats"],
                                    "authorized_output_vectors": allowed_outputs},
                "transaction": {key: value for key, value in tx.items() if key != "witnesses"},
                "raw_transaction": entry["raw_tx"],
                "observations": observations,
            }
            answer = {"effect": group, "target_class": target_class, "funded_origin_vout": origin,
                      "confirmed_payout_sats": tx["outputs"][0]["amount_sats"]
                      if group == "confirmed_transition" else 0,
                      "unauthorized_release_observed": False}
            # Rejections preserve the chain; admission observations carry no
            # settlement. Confirmed entries passed the original policy checks.
            self._observations[case_id] = deepcopy(observation)
            self._answers[case_id] = validate_answer(answer)

        for name, entry in sorted(report["rejected"].items()):
            add("rejected", name, entry, {
                "mempool": entry["dry_run"], "broadcast_error": entry["broadcast_error"],
                "block_error": entry["block_error"], "height_before": entry["height_before"],
                "height_after": entry["height_after"], "tip_before": entry["tip_before"],
                "tip_after": entry["tip_after"],
            })
        for name, entry in sorted(report["positive"].items()):
            add("admission_only", name, entry, {"mempool": entry["admission"]})
        for index, entry in enumerate(report["transitions"]):
            add("confirmed_transition", "observation-" + str(index + 1), entry, {
                "suite_confirmation_record": {"height": normalized["confirmed_transitions"][index]["confirmed_height"]},
                "suite_restart_observations": report["restarts"],
                "suite_node_exit_codes": report["node_exit_codes"],
            })
        _require(len(self._observations) == 60, "native audit catalogue differs from the pinned suite")

    @property
    def provenance(self) -> dict[str, Any]:
        return deepcopy(self._provenance)

    def case_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._observations))

    def _check_case(self, case_id: str) -> None:
        _require(type(case_id) is str and case_id in self._observations, "unknown native audit record")

    def observe(self, case_id: str) -> dict[str, Any]:
        self._check_case(case_id)
        return deepcopy(self._observations[case_id])

    def expected_answer(self, case_id: str) -> dict[str, Any]:
        self._check_case(case_id)
        return deepcopy(self._answers[case_id])

    def assess(self, case_id: str, answer: Any) -> dict[str, Any]:
        submitted = validate_answer(answer)
        expected = self.expected_answer(case_id)
        fields = {field: submitted[field] == expected[field] for field in sorted(ANSWER_FIELDS)}
        return {"case_id": case_id, "correct": all(fields.values()), "field_results": fields,
                "expected_answer": expected, "submitted_answer": submitted,
                "evidence_level": "recorded_native_receipt", "live_execution_this_sample": False,
                "execution_verified": False, "attack_evaluation_available": False}

    def export_trace(self, case_id: str, answer: Any) -> dict[str, Any]:
        assessment = self.assess(case_id, answer)
        return {"schema": SCHEMA, "case_id": case_id, "provenance": self.provenance,
                "observation_digest": _digest(self.observe(case_id)),
                "answer": assessment["submitted_answer"], "assessment": assessment}

    def replay_trace(self, trace: Any, *, expected_case_id: str) -> dict[str, Any]:
        self._check_case(expected_case_id)
        _require(type(trace) is dict and trace.get("case_id") == expected_case_id,
                 "audit trace differs from the evaluator's record")
        expected = self.export_trace(expected_case_id, trace.get("answer"))
        _require(_canonical(trace) == _canonical(expected), "audit trace differs from verified assessment")
        return expected

    def summary(self) -> dict[str, Any]:
        return {**self.provenance, "records": len(self._answers),
                "effects": dict(sorted(Counter(a["effect"] for a in self._answers.values()).items())),
                "target_classes": dict(sorted(Counter(a["target_class"] for a in self._answers.values()).items())),
                "recorded_confirmed_payout_sats": sum(a["confirmed_payout_sats"] for a in self._answers.values()),
                "records_with_unauthorized_release": sum(a["unauthorized_release_observed"] for a in self._answers.values())}
