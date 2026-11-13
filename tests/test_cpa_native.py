"""Receipt boundary regressions against the retained native execution evidence."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from bitvm_arena.cpa_native import (
    BINARY_SHA256, PROFILE_SHA256, _digest, _stop_group, decode_transaction,
    normalize_report, run_native, source_snapshot,
)


EVIDENCE = Path(__file__).resolve().parents[1] / "evidence" / "cpa_native"


class NativeReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = json.loads((EVIDENCE / "upstream_report.json").read_text())
        cls.profile = json.loads((EVIDENCE / "frozen_profile.json").read_text())

    def test_recorded_native_receipt_retains_each_funded_origin(self):
        result = normalize_report(self.baseline, self.profile)
        self.assertFalse(result["execution_verified"])
        self.assertEqual(_digest(self.profile), PROFILE_SHA256)
        self.assertEqual(result["score"]["rejected_attacks"], 49)
        self.assertEqual(result["score"]["beneficiary_payout_sats"], 192_000)
        self.assertEqual(result["score"]["transition_fees_sats"], 8000)
        self.assertFalse(result["score"]["attacker_success"])
        transitions = result["confirmed_transitions"]
        self.assertEqual([t["funded_target"]["origin_vout"] for t in transitions], [0, 1, 0, 1])
        self.assertEqual(transitions[2]["funded_target"]["txid"], transitions[0]["txid"])
        wider = next(c for c in result["cases"] if c["case_id"] == "wider_guard_same_child_relation")
        self.assertTrue(wider["separate_authority_control"])
        self.assertEqual(wider["funded_target"]["origin_vout"], 3)
        self.assertEqual(wider["funded_target"]["payout_cap_sats"], 9000)

    def test_missing_attack_is_not_completed_coverage(self):
        altered = copy.deepcopy(self.baseline)
        del altered["rejected"]["parent_cap_with_valid_child_trace"]
        with self.assertRaisesRegex(ValueError, "rejection coverage"):
            normalize_report(altered, self.profile)

    def test_intentional_repeat_requires_distinct_execution_stages(self):
        for name, height, tip in (("parent_cap_with_valid_child_trace", 103, self.baseline["restarts"][0]["tip"]),
                                  ("spent_input_new_transaction", 102, self.baseline["funding"]["block"])):
            altered = copy.deepcopy(self.baseline)
            entry = altered["rejected"][name]
            entry["height_before"] = entry["height_after"] = height
            entry["tip_before"] = entry["tip_after"] = tip
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "wrong fixture stage"):
                normalize_report(altered, self.profile)

    def test_copying_a_rejection_cannot_fill_another_case(self):
        altered = copy.deepcopy(self.baseline)
        altered["rejected"]["recipient_substitution"] = copy.deepcopy(altered["rejected"]["payout_plus_one"])
        with self.assertRaisesRegex(ValueError, "duplicate or omit"):
            normalize_report(altered, self.profile)

    def test_allowed_negative_cannot_be_reported_as_rejected(self):
        altered = copy.deepcopy(self.baseline)
        altered["rejected"]["parent_cap_with_valid_child_trace"]["dry_run"]["allowed"] = True
        with self.assertRaisesRegex(ValueError, "admission boundary"):
            normalize_report(altered, self.profile)

    def test_witness_change_requires_matching_wtxid(self):
        altered = copy.deepcopy(self.baseline)
        entry = altered["rejected"]["parent_cap_with_valid_child_trace"]
        before = decode_transaction(entry["raw_tx"])
        raw = bytearray.fromhex(entry["raw_tx"])
        raw[-5] ^= 1
        entry["raw_tx"] = raw.hex()
        after = decode_transaction(entry["raw_tx"])
        self.assertEqual(before["txid"], after["txid"])
        self.assertNotEqual(before["wtxid"], after["wtxid"])
        with self.assertRaisesRegex(ValueError, "different transaction bytes"):
            normalize_report(altered, self.profile)

    def test_separately_funded_wider_authority_cannot_replace_original(self):
        altered = copy.deepcopy(self.baseline)
        altered["positive"]["canonical_first_coin"] = copy.deepcopy(altered["positive"]["wider_guard_same_child_relation"])
        with self.assertRaisesRegex(ValueError, "rebound the funded target"):
            normalize_report(altered, self.profile)

    def test_child_cannot_move_to_other_root_lineage(self):
        altered = copy.deepcopy(self.baseline)
        altered["transitions"][2] = copy.deepcopy(altered["transitions"][3])
        with self.assertRaisesRegex(ValueError, "rebound the funded target"):
            normalize_report(altered, self.profile)

    def test_profile_cannot_weaken_the_cap(self):
        altered = copy.deepcopy(self.profile)
        altered["stages"]["root"]["payout_cap_sats"] = 9000
        with self.assertRaisesRegex(ValueError, "profile differs"):
            normalize_report(self.baseline, altered)

    def test_source_and_binary_identity_are_required(self):
        for kind in ("source", "binary"):
            altered = copy.deepcopy(self.baseline)
            if kind == "source":
                altered["source_sha256"]["cpa_regtest.py"] = "0" * 64
            else:
                altered["binary_sha256"] = "0" * 64
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                normalize_report(altered, self.profile)

    def test_rejected_block_must_preserve_tip(self):
        altered = copy.deepcopy(self.baseline)
        altered["rejected"]["parent_cap_with_valid_child_trace"]["tip_after"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "changed the applied tip"):
            normalize_report(altered, self.profile)

    def test_missing_or_malformed_tip_cannot_prove_preservation(self):
        for replacement in (None, "", "A" * 64, "g" * 64, "0" * 63):
            altered = copy.deepcopy(self.baseline)
            entry = altered["rejected"]["parent_cap_with_valid_child_trace"]
            for name in ("tip_before", "tip_after"):
                if replacement is None:
                    del entry[name]
                else:
                    entry[name] = replacement
            with self.subTest(replacement=replacement), self.assertRaisesRegex(ValueError, "applied tip"):
                normalize_report(altered, self.profile)

    def test_matching_tips_must_belong_to_the_funded_chain(self):
        altered = copy.deepcopy(self.baseline)
        entry = altered["rejected"]["parent_cap_with_valid_child_trace"]
        entry["tip_before"] = entry["tip_after"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "funded chain"):
            normalize_report(altered, self.profile)

    def test_boolean_schema_version_is_rejected(self):
        altered = copy.deepcopy(self.baseline)
        altered["schema_version"] = True
        with self.assertRaisesRegex(ValueError, "unsupported native receipt"):
            normalize_report(altered, self.profile)

    def test_restart_and_zero_peer_evidence_are_required(self):
        for kind in ("restart", "peer", "exit"):
            altered = copy.deepcopy(self.baseline)
            if kind == "restart":
                altered["restarts"][1]["outputs_checked"] = False
            elif kind == "peer":
                altered["peer_count"] = 1
            else:
                altered["node_exit_codes"][2] = -11
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                normalize_report(altered, self.profile)

    def test_output_metadata_cannot_override_transaction_bytes(self):
        altered = copy.deepcopy(self.baseline)
        altered["transitions"][0]["outputs"][0]["amount_sats"] = 6000
        with self.assertRaisesRegex(ValueError, "output metadata"):
            normalize_report(altered, self.profile)

    def test_noncanonical_compact_size_and_trailing_bytes_fail(self):
        raw = bytes.fromhex(self.baseline["transitions"][0]["raw_tx"])
        with self.assertRaisesRegex(ValueError, "noncanonical compact"):
            decode_transaction((raw[:6] + b"\xfd\x01\x00" + raw[7:]).hex())
        with self.assertRaisesRegex(ValueError, "trailing"):
            decode_transaction(raw.hex() + "00")

    def test_missing_source_cannot_execute(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "missing or invalid pinned"):
                source_snapshot(Path(directory))


@unittest.skipUnless(os.name == "posix", "POSIX process groups required")
class NativeProcessTests(unittest.TestCase):
    def test_failure_cleanup_signals_the_whole_owned_group(self):
        code = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); print(p.pid,flush=True); time.sleep(60)"
        process = subprocess.Popen([sys.executable, "-I", "-c", code], stdout=subprocess.PIPE,
                                   text=True, start_new_session=True)
        try:
            child_pid = int(process.stdout.readline())
            _stop_group(process)
            self.assertIsNotNone(process.poll())
            state = Path(f"/proc/{child_pid}/stat")
            if state.exists():
                self.assertIn(state.read_text().split(")", 1)[1].split()[0], {"Z", "X"})
        finally:
            _stop_group(process)
            process.stdout.close()


@unittest.skipUnless(os.environ.get("CPA_SOURCE") and os.environ.get("CPA_BINARY"), "set CPA_SOURCE and CPA_BINARY for native execution")
class NativeExecutionTests(unittest.TestCase):
    def test_actual_fresh_regtest(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_native(Path(os.environ["CPA_SOURCE"]), Path(os.environ["CPA_BINARY"]), Path(directory) / "run")
            self.assertTrue(result["execution_verified"])
            self.assertEqual(result["binary_sha256"], BINARY_SHA256)
            self.assertEqual(len(result["confirmed_transitions"]), 4)
            self.assertEqual(result["score"]["rejected_attacks"], 49)


if __name__ == "__main__":
    unittest.main()
