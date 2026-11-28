"""Walletless Bitcoin Core regtest replay adapter for BVA-CASHU-RELEASE.

Replays the pinned Spiral proof-backed Cashu withdrawal archive
(patrickdugan/Spiral @ 9cf56a56d02e8b63de91e435b9fcd7823a66bb9d,
cashu-v4-raw-proof-backed-withdrawal-evidence-4.zip, sha256 5446141e...db556a9b)
inside an isolated, walletless Bitcoin Core regtest node owned by Arena.

What this adapter verifies directly on Bitcoin Core:
  1. Archive SHA-256 and every file hash listed in manifest.json.
  2. Consistency of the pinned M14 setup/evaluation/checked-accept metadata with the
     on-chain reserve and collateral P2WSH witness scripts and accept label preimage.
  3. Walletless block replay (0 loaded wallets) of blocks 1..211, confirming the fixed
     25,000-sat reserve UTXO and 25,250-sat collateral UTXO exist and are unspent.
  4. Honest joint-release payout (txid 32e9951d..., 24,750 sats to holder, 24,750 sats
     collateral refund, 750 sats fee) accepted by mempool and confirmed in block 212.
  5. Six negative controls on the exact same funded inputs, all rejected by Core script
     validation: substituted accept label, holder signature, issuance preimage,
     challenger approval, holder approval, and beneficiary.
  6. Holder-only CSV fallback (txid 084310bd...) valid before release and missing-inputs
     after block 212; reorging block 212 restores both inputs; competing 8-block timeout
     fork (txid 95dce011...) and holder CSV fallback settle consistently and mutually
     exclude the joint release.

Scope boundary: this adapter replays the pinned regtest evidence archive produced with
a trusted single-use garbler (`proof-grove/m14/cashu-joint-release/v2`). It moves the
replay evidence level from `upstream_recorded_regtest` to `arena_replayed_regtest`, and
does not claim malicious-garbler resistance for the upstream v2 run.
"""

from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys
import uuid
import zipfile

from .bitcoin import Transaction
from .canonical import ValidationError, digest
from .core import CoreError, Regtest, safe_json

TRACK = "cashu-release-replay"
CAMPAIGN_ID = "BVA-CASHU-RELEASE"
EVIDENCE_LEVEL = "arena_replayed_regtest"

SOURCE_REVISION = {
    "repository": "patrickdugan/Spiral",
    "ref": "cashu/proof-backed-release-evidence",
    "commit": "9cf56a56d02e8b63de91e435b9fcd7823a66bb9d",
    "path": "proof-grove/evidence/proof-backed-release",
}

ARCHIVE_SHA256 = "5446141e6c12c5ce4681f9c07a82ad7f1607a7accaadc51726492350db556a9b"
REGTEST_GENESIS = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"
COLLATERAL_HEIGHT = 211
COLLATERAL_BLOCK_HASH = "0d06fcf78d2e9bb8fb88f9ba74643b06af1f5b3fafed1af7b8bd35a4f862b726"
PAYOUT_HEIGHT = 212
PAYOUT_BLOCK_HASH = "60434f6b92d0d50ff7ccfb5693bac57eaa5f8ad8733f977c5f0d10971871e60f"

RESERVE_TXID = "a147db7c729fcaed10954a8163a81bc0bf40dd7560dbcba3cc1e2a82eb4367fb"
RESERVE_VOUT = 1
RESERVE_SATS = 25_000
RESERVE_SCRIPT_SHA256 = "8c2e45df63aef9126a618b2305b3afe25bc6915666e2ebdcaca8b060b1cc2b48"

COLLATERAL_TXID = "2ba400f438e2c1b68cb5b80fda34ba17f90052ecd05f85e01da725afda224f29"
COLLATERAL_VOUT = 1
COLLATERAL_SATS = 25_250
COLLATERAL_SCRIPT_SHA256 = "55586b9f3f4e18cd43600bff480b2c8f717fb6537105f5ba3a3fd7a555552805"

HOLDER_PAYOUT_SATS = 24_750
COLLATERAL_REFUND_SATS = 24_750
JOINT_FEE_SATS = 750
HOLDER_SCRIPT = "001446b4c5aecb7ab99fb1fee82c82cbca92eef1e79f"
REFUND_SCRIPT = "0014f9d71f9832b3d2200e8f43c89f1924fcbbda938f"
TIMEOUT_BLOCKS = 8
RESERVE_CSV_BLOCKS = 6

AUTHORIZATION_SCHEMA = "proof-grove/m14/cashu-joint-release/v2"
PAYOUT_TXID = "32e9951df57f6cf0687b4682427bcafa5b7f5cc11f4f71f618082cc71884f564"
PAYOUT_WTXID = "456fdc6d9c8527106986f07c26efe549dbbd959793c06bed5c15bd0dac996e01"
FALLBACK_TXID = "084310bdd55345f8eb0ac04f07e4cc6b4d7ce62ae6c99a2f3d0bb4f45c42c9e5"
FALLBACK_WTXID = "4e0b6794a3e0d05fd4bf2b960af4e558e2d7102b06c84ea8e21b6d58a74b0f9d"
TIMEOUT_TXID = "95dce0113ba61a12b43b36e4ea0b37fccd07f87ed43c1a76ea4978526c0afe25"
TIMEOUT_WTXID = "8c38122f9c759b643c6871fd141a732ef3bf31dd417e0f0cd0fe55326c261692"

STATEMENT_SHA256 = "8fd9bc7f9340d1e969d2d4d22b2fdc23a5ba7a7701d94894d88355fb8ef4e33f"
M14_SETUP_SHA256 = "dd041853e7755facb96c55044187f75c0264284b6af575aac74c3490104803f4"
ACCEPT_LABEL_SHA256 = "9be3b02b3f0dea66e37e32dccb3f665d0e07481777b62c642da9d6dae2da9c18"
REJECT_LABEL_SHA256 = "dced7c6b11d301e7eae29e6d83e758ab24436b2e3cb90ad48e83b3b315c07b1b"
ISSUANCE_PREIMAGE_SHA256 = "9f5b0f986f9311cc266ebb1b73cab7ac81de3bcaad86255076b94f382b76d697"
CONFIRMED_BLOCKS_SHA256 = "35dcb0c563638ce3783fdf59521db992e908eea0f9e285e84a7dd7e86873e524"

# Valid regtest P2WPKH coinbase destination for walletless generateblock (no wallet loaded).
REGTEST_EMPTY_MINER_ADDR = "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202"

REQUIRED_RECEIPT_FIELDS = (
    "scenario_id",
    "source_revision",
    "profile",
    "funded_target",
    "action_trace",
    "observed_final_state",
    "attacker_success",
    "legitimate_success",
    "evidence_level",
)

FUNDED_TARGET = {
    "network": "regtest",
    "reserve_outpoint": f"{RESERVE_TXID}:{RESERVE_VOUT}",
    "reserve_sats": RESERVE_SATS,
    "holder_payout_sats": HOLDER_PAYOUT_SATS,
    "collateral_outpoint": f"{COLLATERAL_TXID}:{COLLATERAL_VOUT}",
    "collateral_sats": COLLATERAL_SATS,
    "holder_script": HOLDER_SCRIPT,
    "authorization": AUTHORIZATION_SCHEMA,
    "recorded_payout_txid": PAYOUT_TXID,
    "evidence_archive_sha256": ARCHIVE_SHA256,
}

# Exact witness mutations matching the recorded Spiral negative controls.
WITNESS_CONTROLS = {
    "substituted_accept_label": {
        "input_index": 1,
        "witness_index": 3,
        "byte_index": 0,
        "expected_reason_fragment": "OP_EQUALVERIFY",
        "expected_wtxid": "9bf0adf32719543dd5d7be9be091e33092731189167666eff4a7cc11d666ed85",
        "description": "Flip a bit in the 16-byte M14 accept label on collateral input 1.",
    },
    "substituted_holder_signature": {
        "input_index": 0,
        "witness_index": 1,
        "byte_index": -2,
        "expected_reason_fragment": "CHECK(MULTI)SIG",
        "expected_wtxid": "d4b8b7a6500c1f3860e1a0edc2f650dc761e52c30768c37fd9e3a15999fe58b6",
        "description": "Flip a bit in the holder ECDSA signature on reserve input 0.",
    },
    "substituted_issuance_preimage": {
        "input_index": 0,
        "witness_index": 2,
        "byte_index": 0,
        "expected_reason_fragment": "OP_EQUALVERIFY",
        "expected_wtxid": "d15b4a654a84dc11de41227a7563ad5f34807b5da7cbe1704c3b849f235a966c",
        "description": "Flip a bit in the 32-byte Cashu issuance preimage on reserve input 0.",
    },
    "substituted_challenger_approval": {
        "input_index": 1,
        "witness_index": 0,
        "byte_index": -2,
        "expected_reason_fragment": "CHECK(MULTI)SIG",
        "expected_wtxid": "184d72ca7d1cf2e8d1929eeade9bc195f22b44b2ff24336087872d4898b85a10",
        "description": "Flip a bit in the challenger approval signature on collateral input 1.",
    },
    "substituted_holder_approval": {
        "input_index": 1,
        "witness_index": 1,
        "byte_index": -2,
        "expected_reason_fragment": "CHECK(MULTI)SIG",
        "expected_wtxid": "d924cd8588e3c8270bbd1277143256942ae6919c2935b64d5971ce78e7dafb45",
        "description": "Flip a bit in the holder approval signature on collateral input 1.",
    },
}


def catalog():
    rows = [
        {
            "schema_version": 1,
            "id": f"{TRACK}.honest_payout",
            "scenario_id": f"{TRACK}.honest_payout",
            "track": TRACK,
            "recipe": "honest_payout",
            "family": "honest_joint_release",
            "profile": "pinned_upstream_v2",
            "variant": "benign",
            "expected": {
                "attacker_success": False,
                "legitimate_success": True,
                "legitimate_completion": True,
                "unauthorized_release": False,
                "diverted_principal_sats": 0,
            },
            "evidence_level": EVIDENCE_LEVEL,
        },
        {
            "schema_version": 1,
            "id": f"{TRACK}.holder_fallback_before_release",
            "scenario_id": f"{TRACK}.holder_fallback_before_release",
            "track": TRACK,
            "recipe": "holder_fallback_before_release",
            "family": "holder_csv_exit",
            "profile": "pinned_upstream_v2",
            "variant": "benign",
            "expected": {
                "attacker_success": False,
                "legitimate_success": True,
                "legitimate_completion": True,
                "unauthorized_release": False,
                "diverted_principal_sats": 0,
            },
            "evidence_level": EVIDENCE_LEVEL,
        },
        {
            "schema_version": 1,
            "id": f"{TRACK}.holder_fallback_after_release",
            "scenario_id": f"{TRACK}.holder_fallback_after_release",
            "track": TRACK,
            "recipe": "holder_fallback_after_release",
            "family": "double_spend_prevention",
            "profile": "pinned_upstream_v2",
            "variant": "attack",
            "expected": {
                "attacker_success": False,
                "legitimate_success": False,
                "legitimate_completion": False,
                "unauthorized_release": False,
                "diverted_principal_sats": 0,
            },
            "evidence_level": EVIDENCE_LEVEL,
        },
        {
            "schema_version": 1,
            "id": f"{TRACK}.substituted_beneficiary",
            "scenario_id": f"{TRACK}.substituted_beneficiary",
            "track": TRACK,
            "recipe": "substituted_beneficiary",
            "family": "settlement_binding",
            "profile": "pinned_upstream_v2",
            "variant": "attack",
            "expected": {
                "attacker_success": False,
                "legitimate_success": False,
                "legitimate_completion": False,
                "unauthorized_release": False,
                "diverted_principal_sats": 0,
            },
            "evidence_level": EVIDENCE_LEVEL,
        },
    ]
    for name in WITNESS_CONTROLS:
        rows.append(
            {
                "schema_version": 1,
                "id": f"{TRACK}.{name}",
                "scenario_id": f"{TRACK}.{name}",
                "track": TRACK,
                "recipe": name,
                "family": "witness_control",
                "profile": "pinned_upstream_v2",
                "variant": "attack",
                "expected": {
                    "attacker_success": False,
                    "legitimate_success": False,
                    "legitimate_completion": False,
                    "unauthorized_release": False,
                    "diverted_principal_sats": 0,
                },
                "evidence_level": EVIDENCE_LEVEL,
            }
        )
    rows.append(
        {
            "schema_version": 1,
            "id": f"{TRACK}.reorg_and_timeout_fork",
            "scenario_id": f"{TRACK}.reorg_and_timeout_fork",
            "track": TRACK,
            "recipe": "reorg_and_timeout_fork",
            "family": "reorg_and_timeout_exclusivity",
            "profile": "pinned_upstream_v2",
            "variant": "benign",
            "expected": {
                "attacker_success": False,
                "legitimate_success": True,
                "legitimate_completion": True,
                "unauthorized_release": False,
                "diverted_principal_sats": 0,
            },
            "evidence_level": EVIDENCE_LEVEL,
        }
    )
    return rows


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_and_load_archive(archive_path: Path) -> dict:
    """Verify the pinned Spiral evidence zip before touching bitcoind."""
    path = Path(archive_path).resolve()
    if not path.is_file():
        raise ValidationError(f"missing pinned evidence archive: {path}")
    raw_zip = path.read_bytes()
    actual_sha = _sha256_hex(raw_zip)
    if actual_sha != ARCHIVE_SHA256:
        raise ValidationError(
            f"archive sha256 mismatch: got {actual_sha}, expected {ARCHIVE_SHA256}"
        )
    with zipfile.ZipFile(path, "r") as zf:
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        files_sha = manifest.get("files_sha256", {})
        if not isinstance(files_sha, dict) or not files_sha:
            raise ValidationError("archive manifest.json missing files_sha256")
        for member, expected_hash in files_sha.items():
            member_hash = _sha256_hex(zf.read(member))
            if member_hash != expected_hash:
                raise ValidationError(
                    f"archive member {member} sha256 mismatch: got {member_hash}, expected {expected_hash}"
                )
        payout = json.loads(zf.read("bitcoin/payout.json").decode("utf-8"))
        setup = json.loads(zf.read("m14/setup.json").decode("utf-8"))
        evaluation = json.loads(zf.read("m14/evaluation.json").decode("utf-8"))
        checked_accept = json.loads(zf.read("m14/checked-accept.json").decode("utf-8"))
        final_statement = json.loads(zf.read("withdrawal/final-statement.json").decode("utf-8"))
        confirmed_blocks_bytes = zf.read("bitcoin/confirmed-blocks.hex")
        signed_withdrawal_bytes = zf.read("withdrawal/signed-withdrawal.bin")

    if _sha256_hex(confirmed_blocks_bytes) != CONFIRMED_BLOCKS_SHA256:
        raise ValidationError("confirmed-blocks.hex hash mismatch")

    confirmed_blocks = [
        line.strip()
        for line in confirmed_blocks_bytes.decode("ascii").splitlines()
        if line.strip()
    ]
    if len(confirmed_blocks) != PAYOUT_HEIGHT:
        raise ValidationError(
            f"expected {PAYOUT_HEIGHT} blocks in confirmed-blocks.hex, got {len(confirmed_blocks)}"
        )

    # Cross-check M14 metadata against on-chain payout witness items.
    joint_hex = payout["assembly"]["raw_tx_hex"]
    timeout_hex = payout["assembly"]["timeout_raw_tx_hex"]
    joint_tx = Transaction.parse(joint_hex)
    timeout_tx = Transaction.parse(timeout_hex)
    fallback_tx = Transaction.parse(signed_withdrawal_bytes)

    if joint_tx.txid != PAYOUT_TXID or joint_tx.wtxid != PAYOUT_WTXID:
        raise ValidationError("joint payout txid/wtxid mismatch against pinned target")
    if fallback_tx.txid != FALLBACK_TXID or fallback_tx.wtxid != FALLBACK_WTXID:
        raise ValidationError("holder fallback txid/wtxid mismatch against pinned target")
    if timeout_tx.txid != TIMEOUT_TXID or timeout_tx.wtxid != TIMEOUT_WTXID:
        raise ValidationError("timeout txid/wtxid mismatch against pinned target")

    if len(joint_tx.inputs) != 2 or len(joint_tx.outputs) != 2:
        raise ValidationError("unexpected joint payout tx shape")
    if (joint_tx.inputs[0].txid, joint_tx.inputs[0].vout) != (RESERVE_TXID, RESERVE_VOUT):
        raise ValidationError("joint payout input 0 does not spend pinned reserve")
    if (joint_tx.inputs[1].txid, joint_tx.inputs[1].vout) != (COLLATERAL_TXID, COLLATERAL_VOUT):
        raise ValidationError("joint payout input 1 does not spend pinned collateral")
    if joint_tx.outputs[0] != (HOLDER_PAYOUT_SATS, bytes.fromhex(HOLDER_SCRIPT)):
        raise ValidationError("joint payout output 0 does not match pinned holder payout")
    if joint_tx.outputs[1] != (COLLATERAL_REFUND_SATS, bytes.fromhex(REFUND_SCRIPT)):
        raise ValidationError("joint payout output 1 does not match pinned collateral refund")

    # Verify cryptographic bindings inside the witness stacks.
    reserve_script = joint_tx.inputs[0].witness[3]
    collateral_script = joint_tx.inputs[1].witness[5]
    issuance_preimage = joint_tx.inputs[0].witness[2]
    accept_label = joint_tx.inputs[1].witness[3]

    if _sha256_hex(reserve_script) != RESERVE_SCRIPT_SHA256:
        raise ValidationError("reserve witness script hash mismatch")
    if _sha256_hex(collateral_script) != COLLATERAL_SCRIPT_SHA256:
        raise ValidationError("collateral witness script hash mismatch")
    if _sha256_hex(issuance_preimage) != ISSUANCE_PREIMAGE_SHA256:
        raise ValidationError("issuance preimage hash mismatch")
    if _sha256_hex(accept_label) != ACCEPT_LABEL_SHA256:
        raise ValidationError("accept label hash mismatch")
    if accept_label.hex() != evaluation["output_label"]:
        raise ValidationError("joint payout accept label disagrees with m14/evaluation.json")
    if setup["accept_label_sha256"] != ACCEPT_LABEL_SHA256 or setup["reject_label_sha256"] != REJECT_LABEL_SHA256:
        raise ValidationError("m14/setup.json label commitments mismatch")
    if manifest["statement_sha256"] != STATEMENT_SHA256 or manifest["m14_setup_sha256"] != M14_SETUP_SHA256:
        raise ValidationError("manifest statement/setup pins mismatch")
    if checked_accept["verdict"] != "accept" or checked_accept["output_label_sha256"] != ACCEPT_LABEL_SHA256:
        raise ValidationError("m14/checked-accept.json verdict mismatch")

    return {
        "archive_sha256": actual_sha,
        "verified_member_count": len(files_sha),
        "manifest": manifest,
        "payout": payout,
        "setup": setup,
        "evaluation": evaluation,
        "checked_accept": checked_accept,
        "final_statement": final_statement,
        "confirmed_blocks": confirmed_blocks,
        "joint_hex": joint_hex,
        "timeout_hex": timeout_hex,
        "fallback_hex": signed_withdrawal_bytes.hex(),
    }


def _mutate_witness(raw_hex: str, input_index: int, witness_index: int, byte_index: int) -> Transaction:
    tx = Transaction.parse(raw_hex)
    buf = bytearray(tx.inputs[input_index].witness[witness_index])
    buf[byte_index] ^= 1
    tx.inputs[input_index].witness[witness_index] = bytes(buf)
    return tx


def _mutate_beneficiary(raw_hex: str) -> Transaction:
    tx = Transaction.parse(raw_hex)
    value, script = tx.outputs[0]
    # Replace output 0 P2WPKH program with a distinct 20-byte hash (attacker destination).
    attacker_prog = hashlib.sha256(b"bitvm-arena/cashu-replay/substituted-beneficiary").digest()[:20]
    assert script[:2] == b"\x00\x14" and attacker_prog != script[2:]
    tx.outputs[0] = (value, b"\x00\x14" + attacker_prog)
    return tx


def _make_receipt(row, action_trace, observed_final_state, outcome):
    return {
        **row,
        "scenario_id": row["scenario_id"],
        "source_revision": dict(SOURCE_REVISION),
        "profile": row["profile"],
        "funded_target": dict(FUNDED_TARGET),
        "action_trace": action_trace,
        "observed_final_state": observed_final_state,
        "attacker_success": outcome["attacker_success"],
        "legitimate_success": outcome["legitimate_success"],
        "legitimate_completion": outcome["legitimate_completion"],
        "unauthorized_release": outcome["unauthorized_release"],
        "diverted_principal_sats": outcome["diverted_principal_sats"],
        "outcome": outcome,
        "expectation_met": outcome == row["expected"],
        "evidence_level": EVIDENCE_LEVEL,
    }


def _test_mempool(node: Regtest, raw_hex: str) -> dict:
    return safe_json(node.rpc("testmempoolaccept", [raw_hex])[0])


def execute(binary, directory, archive_path, rows=None):
    """Execute the full walletless regtest replay of the pinned Spiral evidence archive."""
    bundle = verify_and_load_archive(Path(archive_path))
    all_rows = catalog()
    if rows is None:
        selected_rows = deepcopy(all_rows)
    else:
        selected_rows = deepcopy(rows)
    by_recipe = {r["recipe"]: r for r in selected_rows}
    cases = []

    with Regtest(binary, directory) as node:
        provenance = node.provenance
        wallets_loaded = len(node.rpc("listwallets"))
        if wallets_loaded != 0:
            raise CoreError(f"replay node must be walletless, found {wallets_loaded} wallets")
        genesis = node.rpc("getblockhash", 0)
        if genesis != REGTEST_GENESIS:
            raise CoreError(f"unexpected regtest genesis {genesis}")

        # Submit blocks 1..211 (up to collateral confirmation, before payout block 212).
        for idx, block_hex in enumerate(bundle["confirmed_blocks"][:COLLATERAL_HEIGHT], start=1):
            err = node.rpc("submitblock", block_hex)
            if err is not None:
                raise CoreError(f"submitblock failed at height {idx}: {err}")

        height_211 = node.rpc("getblockcount")
        tip_211 = node.rpc("getbestblockhash")
        if height_211 != COLLATERAL_HEIGHT or tip_211 != COLLATERAL_BLOCK_HASH:
            raise CoreError(f"pre-payout tip mismatch: {height_211} {tip_211}")

        reserve_pre = node.rpc("gettxout", RESERVE_TXID, RESERVE_VOUT)
        collateral_pre = node.rpc("gettxout", COLLATERAL_TXID, COLLATERAL_VOUT)
        if reserve_pre is None or collateral_pre is None:
            raise CoreError("pinned reserve or collateral UTXO missing at height 211")
        reserve_pre_sats = int(reserve_pre["value"] * 100_000_000)
        collateral_pre_sats = int(collateral_pre["value"] * 100_000_000)
        if reserve_pre_sats != RESERVE_SATS or collateral_pre_sats != COLLATERAL_SATS:
            raise CoreError("funded UTXO amounts mismatch pinned target")

        # 1. Test holder CSV fallback BEFORE release (at height 211).
        fb_before = _test_mempool(node, bundle["fallback_hex"])
        if "holder_fallback_before_release" in by_recipe:
            allowed = bool(fb_before["allowed"])
            outcome = {
                "attacker_success": False,
                "legitimate_success": allowed,
                "legitimate_completion": allowed,
                "unauthorized_release": False,
                "diverted_principal_sats": 0,
            }
            cases.append(
                _make_receipt(
                    by_recipe["holder_fallback_before_release"],
                    action_trace=[
                        {
                            "step": 0,
                            "action": "submit_blocks",
                            "height": height_211,
                            "tip_hash": tip_211,
                            "wallets_loaded": 0,
                        },
                        {
                            "step": 1,
                            "action": "testmempoolaccept",
                            "label": "holder_fallback_before_release",
                            "txid": FALLBACK_TXID,
                            "wtxid": FALLBACK_WTXID,
                            "raw_transaction": bundle["fallback_hex"],
                            "result": fb_before,
                        },
                    ],
                    observed_final_state={
                        "height": height_211,
                        "wallets_loaded": 0,
                        "reserve_unspent": True,
                        "fallback_allowed": allowed,
                        "holder_payout_sats": HOLDER_PAYOUT_SATS if allowed else 0,
                    },
                    outcome=outcome,
                )
            )

        # 2. Test all 5 witness substitution controls + substituted beneficiary at height 211.
        for name, spec in WITNESS_CONTROLS.items():
            if name not in by_recipe:
                continue
            mut_tx = _mutate_witness(
                bundle["joint_hex"],
                spec["input_index"],
                spec["witness_index"],
                spec["byte_index"],
            )
            mut_hex = mut_tx.serialize().hex()
            res = _test_mempool(node, mut_hex)
            allowed = bool(res["allowed"])
            reason = res.get("reject-reason", "")
            outcome = {
                "attacker_success": allowed,
                "legitimate_success": False,
                "legitimate_completion": False,
                "unauthorized_release": allowed,
                "diverted_principal_sats": HOLDER_PAYOUT_SATS if allowed else 0,
            }
            cases.append(
                _make_receipt(
                    by_recipe[name],
                    action_trace=[
                        {
                            "step": 0,
                            "action": "mutate_witness",
                            "mutation": name,
                            "description": spec["description"],
                            "input_index": spec["input_index"],
                            "witness_index": spec["witness_index"],
                            "byte_index": spec["byte_index"],
                            "wtxid_matches_upstream_control": mut_tx.wtxid == spec["expected_wtxid"],
                        },
                        {
                            "step": 1,
                            "action": "testmempoolaccept",
                            "label": name,
                            "txid": mut_tx.txid,
                            "wtxid": mut_tx.wtxid,
                            "raw_transaction": mut_hex,
                            "result": res,
                        },
                    ],
                    observed_final_state={
                        "height": height_211,
                        "wallets_loaded": 0,
                        "allowed": allowed,
                        "reject_reason": reason,
                        "expected_reason_fragment_matched": spec["expected_reason_fragment"] in reason,
                        "reserve_unspent": node.rpc("gettxout", RESERVE_TXID, RESERVE_VOUT) is not None,
                        "collateral_unspent": node.rpc("gettxout", COLLATERAL_TXID, COLLATERAL_VOUT) is not None,
                    },
                    outcome=outcome,
                )
            )

        if "substituted_beneficiary" in by_recipe:
            mut_ben = _mutate_beneficiary(bundle["joint_hex"])
            mut_ben_hex = mut_ben.serialize().hex()
            res_ben = _test_mempool(node, mut_ben_hex)
            allowed = bool(res_ben["allowed"])
            reason = res_ben.get("reject-reason", "")
            outcome = {
                "attacker_success": allowed,
                "legitimate_success": False,
                "legitimate_completion": False,
                "unauthorized_release": allowed,
                "diverted_principal_sats": HOLDER_PAYOUT_SATS if allowed else 0,
            }
            cases.append(
                _make_receipt(
                    by_recipe["substituted_beneficiary"],
                    action_trace=[
                        {
                            "step": 0,
                            "action": "mutate_output_beneficiary",
                            "original_holder_script": HOLDER_SCRIPT,
                            "substituted_script": mut_ben.outputs[0][1].hex(),
                        },
                        {
                            "step": 1,
                            "action": "testmempoolaccept",
                            "label": "substituted_beneficiary",
                            "txid": mut_ben.txid,
                            "wtxid": mut_ben.wtxid,
                            "raw_transaction": mut_ben_hex,
                            "result": res_ben,
                        },
                    ],
                    observed_final_state={
                        "height": height_211,
                        "wallets_loaded": 0,
                        "allowed": allowed,
                        "reject_reason": reason,
                        "expected_reason_fragment_matched": "CHECK(MULTI)SIG" in reason,
                        "reserve_unspent": node.rpc("gettxout", RESERVE_TXID, RESERVE_VOUT) is not None,
                        "collateral_unspent": node.rpc("gettxout", COLLATERAL_TXID, COLLATERAL_VOUT) is not None,
                    },
                    outcome=outcome,
                )
            )

        # 3. Honest joint payout: testmempoolaccept at height 211, then submit recorded block 212.
        honest_mempool = _test_mempool(node, bundle["joint_hex"])
        err_212 = node.rpc("submitblock", bundle["confirmed_blocks"][PAYOUT_HEIGHT - 1])
        if err_212 is not None:
            raise CoreError(f"submitblock failed at payout height {PAYOUT_HEIGHT}: {err_212}")
        height_212 = node.rpc("getblockcount")
        tip_212 = node.rpc("getbestblockhash")
        if height_212 != PAYOUT_HEIGHT or tip_212 != PAYOUT_BLOCK_HASH:
            raise CoreError(f"payout tip mismatch: {height_212} {tip_212}")
        payout_info = safe_json(node.rpc("getrawtransaction", PAYOUT_TXID, True))
        reserve_post = node.rpc("gettxout", RESERVE_TXID, RESERVE_VOUT)
        collateral_post = node.rpc("gettxout", COLLATERAL_TXID, COLLATERAL_VOUT)

        confirmed_ok = (
            bool(honest_mempool["allowed"])
            and payout_info.get("blockhash") == PAYOUT_BLOCK_HASH
            and payout_info.get("confirmations", 0) >= 1
            and reserve_post is None
            and collateral_post is None
        )
        if "honest_payout" in by_recipe:
            outcome = {
                "attacker_success": False,
                "legitimate_success": confirmed_ok,
                "legitimate_completion": confirmed_ok,
                "unauthorized_release": False,
                "diverted_principal_sats": 0,
            }
            cases.append(
                _make_receipt(
                    by_recipe["honest_payout"],
                    action_trace=[
                        {
                            "step": 0,
                            "action": "testmempoolaccept",
                            "label": "honest_joint_payout",
                            "txid": PAYOUT_TXID,
                            "wtxid": PAYOUT_WTXID,
                            "raw_transaction": bundle["joint_hex"],
                            "result": honest_mempool,
                        },
                        {
                            "step": 1,
                            "action": "submit_block",
                            "height": height_212,
                            "blockhash": tip_212,
                            "confirmed_txid": PAYOUT_TXID,
                            "confirmations": payout_info.get("confirmations"),
                        },
                    ],
                    observed_final_state={
                        "height": height_212,
                        "tip_hash": tip_212,
                        "wallets_loaded": len(node.rpc("listwallets")),
                        "payout_txid": PAYOUT_TXID,
                        "payout_wtxid": PAYOUT_WTXID,
                        "holder_payout_sats": HOLDER_PAYOUT_SATS,
                        "collateral_refund_sats": COLLATERAL_REFUND_SATS,
                        "fee_sats": JOINT_FEE_SATS,
                        "reserve_spent": reserve_post is None,
                        "collateral_spent": collateral_post is None,
                    },
                    outcome=outcome,
                )
            )

        # 4. Holder CSV fallback AFTER release (must be missing-inputs).
        fb_after = _test_mempool(node, bundle["fallback_hex"])
        if "holder_fallback_after_release" in by_recipe:
            allowed = bool(fb_after["allowed"])
            outcome = {
                "attacker_success": allowed,
                "legitimate_success": False,
                "legitimate_completion": False,
                "unauthorized_release": allowed,
                "diverted_principal_sats": HOLDER_PAYOUT_SATS if allowed else 0,
            }
            cases.append(
                _make_receipt(
                    by_recipe["holder_fallback_after_release"],
                    action_trace=[
                        {
                            "step": 0,
                            "action": "testmempoolaccept",
                            "label": "holder_fallback_after_release",
                            "txid": FALLBACK_TXID,
                            "wtxid": FALLBACK_WTXID,
                            "raw_transaction": bundle["fallback_hex"],
                            "result": fb_after,
                        }
                    ],
                    observed_final_state={
                        "height": height_212,
                        "wallets_loaded": len(node.rpc("listwallets")),
                        "allowed": allowed,
                        "reject_reason": fb_after.get("reject-reason"),
                    },
                    outcome=outcome,
                )
            )

        # 5. Reorg restoration & competing timeout fork (still 0 wallets loaded).
        if "reorg_and_timeout_fork" in by_recipe:
            node.rpc("invalidateblock", PAYOUT_BLOCK_HASH)
            reorg_height = node.rpc("getblockcount")
            restored = (
                reorg_height == COLLATERAL_HEIGHT
                and node.rpc("gettxout", RESERVE_TXID, RESERVE_VOUT, False) is not None
                and node.rpc("gettxout", COLLATERAL_TXID, COLLATERAL_VOUT, False) is not None
            )
            # Advance 7 empty blocks (212..218) so block 219 satisfies the 8-block collateral CSV.
            for _ in range(TIMEOUT_BLOCKS - 1):
                node.rpc("generateblock", REGTEST_EMPTY_MINER_ADDR, [])
            # Verify joint + holder or joint + timeout cannot coexist in the same block.
            joint_and_holder_err = None
            try:
                node.rpc(
                    "generateblock",
                    REGTEST_EMPTY_MINER_ADDR,
                    [bundle["joint_hex"], bundle["fallback_hex"]],
                )
            except CoreError as exc:
                joint_and_holder_err = str(exc)

            joint_and_timeout_err = None
            try:
                node.rpc(
                    "generateblock",
                    REGTEST_EMPTY_MINER_ADDR,
                    [bundle["joint_hex"], bundle["timeout_hex"]],
                )
            except CoreError as exc:
                joint_and_timeout_err = str(exc)

            # Confirm holder CSV fallback + collateral timeout together at height 219.
            fork_block = node.rpc(
                "generateblock",
                REGTEST_EMPTY_MINER_ADDR,
                [bundle["fallback_hex"], bundle["timeout_hex"]],
            )
            fork_height = node.rpc("getblockcount")
            joint_after_fork = _test_mempool(node, bundle["joint_hex"])

            # Restore canonical pinned chain tip (height 212).
            node.rpc("reconsiderblock", PAYOUT_BLOCK_HASH)
            fork_first = node.rpc("getblockhash", COLLATERAL_HEIGHT + 1)
            if fork_first != PAYOUT_BLOCK_HASH:
                node.rpc("invalidateblock", fork_first)
            final_tip = node.rpc("getbestblockhash")
            final_height = node.rpc("getblockcount")

            fork_ok = (
                restored
                and fork_height == COLLATERAL_HEIGHT + TIMEOUT_BLOCKS
                and joint_and_holder_err is not None
                and joint_and_timeout_err is not None
                and not bool(joint_after_fork["allowed"])
                and joint_after_fork.get("reject-reason") == "missing-inputs"
                and final_height == PAYOUT_HEIGHT
                and final_tip == PAYOUT_BLOCK_HASH
            )
            outcome = {
                "attacker_success": False,
                "legitimate_success": fork_ok,
                "legitimate_completion": fork_ok,
                "unauthorized_release": False,
                "diverted_principal_sats": 0,
            }
            cases.append(
                _make_receipt(
                    by_recipe["reorg_and_timeout_fork"],
                    action_trace=[
                        {"step": 0, "action": "invalidateblock", "blockhash": PAYOUT_BLOCK_HASH, "restored_both_inputs": restored},
                        {"step": 1, "action": "advance_empty_blocks", "count": TIMEOUT_BLOCKS - 1, "to_height": COLLATERAL_HEIGHT + TIMEOUT_BLOCKS - 1},
                        {"step": 2, "action": "reject_conflicting_block", "pair": "joint+holder_fallback", "error": joint_and_holder_err},
                        {"step": 3, "action": "reject_conflicting_block", "pair": "joint+timeout", "error": joint_and_timeout_err},
                        {
                            "step": 4,
                            "action": "generateblock_timeout_fork",
                            "height": fork_height,
                            "blockhash": fork_block["hash"],
                            "holder_txid": FALLBACK_TXID,
                            "timeout_txid": TIMEOUT_TXID,
                            "raw_timeout_transaction": bundle["timeout_hex"],
                        },
                        {
                            "step": 5,
                            "action": "testmempoolaccept",
                            "label": "joint_after_holder_and_timeout",
                            "txid": PAYOUT_TXID,
                            "result": joint_after_fork,
                        },
                    ],
                    observed_final_state={
                        "reorg_restored_both_inputs": restored,
                        "timeout_fork_height": fork_height,
                        "joint_rejected_after_fork": not bool(joint_after_fork["allowed"]),
                        "canonical_tip_restored": final_tip == PAYOUT_BLOCK_HASH and final_height == PAYOUT_HEIGHT,
                        "wallets_loaded": len(node.rpc("listwallets")),
                    },
                    outcome=outcome,
                )
            )

        provenance["wallets_loaded"] = len(node.rpc("listwallets"))
        provenance["genesis_hash"] = genesis

    # Preserve catalog order in report.
    order = {r["id"]: idx for idx, r in enumerate(selected_rows)}
    cases.sort(key=lambda c: order[c["id"]])

    report = {
        "schema_version": 1,
        "campaign_id": CAMPAIGN_ID,
        "track": TRACK,
        "evidence_level": EVIDENCE_LEVEL,
        "source_revision": dict(SOURCE_REVISION),
        "funded_target": dict(FUNDED_TARGET),
        "archive_verification": {
            "archive_sha256": bundle["archive_sha256"],
            "verified_member_count": bundle["verified_member_count"],
            "confirmed_blocks_sha256": CONFIRMED_BLOCKS_SHA256,
            "confirmed_blocks_count": len(bundle["confirmed_blocks"]),
            "statement_sha256": STATEMENT_SHA256,
            "m14_setup_sha256": M14_SETUP_SHA256,
            "accept_label_sha256": ACCEPT_LABEL_SHA256,
            "reject_label_sha256": REJECT_LABEL_SHA256,
            "issuance_preimage_sha256": ISSUANCE_PREIMAGE_SHA256,
        },
        "provenance": provenance,
        "catalog_hash": digest(selected_rows),
        "cases": cases,
        "summary": {
            "cases": len(cases),
            "wallets_loaded": provenance["wallets_loaded"],
            "honest_payout_confirmed": any(
                c["recipe"] == "honest_payout" and c["legitimate_completion"] for c in cases
            ),
            "substitution_controls_rejected": sum(
                1
                for c in cases
                if c["recipe"] in (*WITNESS_CONTROLS.keys(), "substituted_beneficiary")
                and not c["attacker_success"]
            ),
            "expectation_failures": [c["id"] for c in cases if not c["expectation_met"]],
        },
    }
    report["evidence_hash"] = digest(report)
    return report


def audit(report: dict) -> list[str]:
    """Offline audit of a saved BVA-CASHU-RELEASE replay report."""
    problems = []
    body = {k: v for k, v in report.items() if k != "evidence_hash"}
    if digest(body) != report.get("evidence_hash"):
        problems.append("evidence_hash does not match report body")
    if report.get("track") != TRACK:
        problems.append("wrong track")
    if report.get("evidence_level") != EVIDENCE_LEVEL:
        problems.append(f"unexpected evidence_level: {report.get('evidence_level')}")
    if report.get("provenance", {}).get("chain") != "regtest":
        problems.append("provenance chain is not regtest")
    if report.get("provenance", {}).get("wallets_loaded") != 0:
        problems.append("replay must be walletless (wallets_loaded == 0)")

    rows = catalog()
    if report.get("catalog_hash") != digest(rows):
        problems.append("catalog_hash does not match cashu-release-replay catalog")
    by_id = {r["id"]: r for r in rows}
    seen = set()

    for case in report.get("cases", []):
        cid = case.get("id")
        row = by_id.get(cid)
        if row is None:
            problems.append(f"{cid}: unknown case id")
            continue
        seen.add(cid)
        for req in REQUIRED_RECEIPT_FIELDS:
            if req not in case:
                problems.append(f"{cid}: missing required receipt field {req}")
        if case.get("funded_target") != FUNDED_TARGET:
            problems.append(f"{cid}: funded_target differs from pinned target")
        if case.get("source_revision") != SOURCE_REVISION:
            problems.append(f"{cid}: source_revision differs from pinned Spiral commit")
        if case.get("evidence_level") != EVIDENCE_LEVEL:
            problems.append(f"{cid}: wrong evidence_level")
        if case.get("expectation_met") != (case.get("outcome") == row["expected"]):
            problems.append(f"{cid}: expectation_met inconsistent with outcome")

        # Independently re-parse raw transactions and verify cryptographic bindings.
        for step in case.get("action_trace", []):
            raw = step.get("raw_transaction")
            if raw is None:
                continue
            try:
                tx = Transaction.parse(raw)
            except ValidationError as exc:
                problems.append(f"{cid}: unparsable raw_transaction ({exc})")
                continue
            if "txid" in step and tx.txid != step["txid"]:
                problems.append(f"{cid}: txid mismatch ({tx.txid} != {step['txid']})")
            if "wtxid" in step and tx.wtxid != step["wtxid"]:
                problems.append(f"{cid}: wtxid mismatch ({tx.wtxid} != {step['wtxid']})")
            if case["recipe"] == "honest_payout":
                if _sha256_hex(tx.inputs[0].witness[3]) != RESERVE_SCRIPT_SHA256:
                    problems.append(f"{cid}: reserve witness script hash mismatch")
                if _sha256_hex(tx.inputs[1].witness[5]) != COLLATERAL_SCRIPT_SHA256:
                    problems.append(f"{cid}: collateral witness script hash mismatch")
                if _sha256_hex(tx.inputs[1].witness[3]) != ACCEPT_LABEL_SHA256:
                    problems.append(f"{cid}: accept label preimage hash mismatch")
                if _sha256_hex(tx.inputs[0].witness[2]) != ISSUANCE_PREIMAGE_SHA256:
                    problems.append(f"{cid}: issuance preimage hash mismatch")
            if case["recipe"] in WITNESS_CONTROLS:
                expected_wtxid = WITNESS_CONTROLS[case["recipe"]]["expected_wtxid"]
                if tx.wtxid != expected_wtxid:
                    problems.append(f"{cid}: mutated wtxid differs from pinned Spiral control")
                if step.get("result", {}).get("allowed") is not False:
                    problems.append(f"{cid}: witness substitution was not rejected")
            if case["recipe"] == "substituted_beneficiary":
                if step.get("result", {}).get("allowed") is not False:
                    problems.append(f"{cid}: beneficiary substitution was not rejected")

    if seen != set(by_id):
        problems.append("report does not cover all cashu-release-replay cases")
    summary = report.get("summary", {})
    if summary.get("expectation_failures") != [c["id"] for c in report.get("cases", []) if not c.get("expectation_met")]:
        problems.append("summary expectation_failures inconsistent")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Walletless Core regtest replay for BVA-CASHU-RELEASE.")
    parser.add_argument("--archive", type=Path, required=True, help="Path to pinned Spiral evidence zip.")
    parser.add_argument("--bitcoind", type=Path, help="bitcoind binary (or BITVM_ARENA_BITCOIND).")
    parser.add_argument("--output", type=Path, help="Write JSON receipt to this path.")
    args = parser.parse_args(argv)
    binary = args.bitcoind or Path(os.environ.get("BITVM_ARENA_BITCOIND", ""))
    if not binary or not binary.is_file():
        raise ValidationError("provide --bitcoind or set BITVM_ARENA_BITCOIND")
    root = Path(__file__).resolve().parents[1]
    report = execute(binary, root / "work" / "regtest" / uuid.uuid4().hex, args.archive)
    problems = audit(report)
    if problems:
        raise ValidationError("self-audit failed: " + "; ".join(problems))
    text = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0 if not report["summary"]["expectation_failures"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
