"""Real SDK checks for read-only classification of recorded native receipts."""

from __future__ import annotations

import asyncio
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SDK_INSTALLED = (
    importlib.util.find_spec("control_arena") is not None
    and importlib.util.find_spec("inspect_ai") is not None
)
BUNDLE_ROOT = Path(__file__).resolve().parents[1] / "evidence" / "cpa_native"

if SDK_INSTALLED:
    from control_arena import EvalMode
    from control_arena.eval import ControlEvalConfig, get_control_task
    from control_arena.policy import fixed_policy_builder
    from control_arena.settings import Setting
    from inspect_ai import eval as inspect_eval
    from inspect_ai.dataset import Sample
    from inspect_ai.model import ChatMessageAssistant, ModelName
    from inspect_ai.scorer import Target
    from inspect_ai.solver import TaskState
    from inspect_ai.tool import ToolCall, ToolDef

    from bitvm_arena.cpa_native_audit import ANSWER_FIELDS, CPANativeAuditDataset
    from bitvm_arena.cpa_native_audit_control_arena import STORE_KEY, CPANativeAuditSetting


@unittest.skipUnless(SDK_INSTALLED, "install .[control] for the read-only SDK checks")
class NativeAuditControlArenaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit = CPANativeAuditDataset(BUNDLE_ROOT)

    def case_for_effect(self, effect):
        return next(case_id for case_id in self.audit.case_ids()
                    if self.audit.expected_answer(case_id)["effect"] == effect)

    def setting(self, case_id):
        return CPANativeAuditSetting(bundle_root=str(BUNDLE_ROOT), case_ids=(case_id,))

    def make_state(self, sample):
        return TaskState(model=ModelName("mockllm/model"), sample_id=sample.id, epoch=1,
                         input=sample.input, messages=[], metadata=deepcopy(sample.metadata))

    def run_fixed(self, case_id, answers, *, setting=None, dataset=None):
        setting = setting or self.setting(case_id)
        calls = [ToolCall(id="observe", function="native_audit_observe", arguments={})]
        calls.extend(ToolCall(id=f"answer-{index}", function="native_audit_submit", arguments=answer)
                     for index, answer in enumerate(answers))
        task = get_control_task(
            setting=setting,
            micro_protocol=fixed_policy_builder(tool_calls=calls),
            mode=EvalMode.HONEST,
            dataset=dataset,
            eval_config=ControlEvalConfig(trusted_model="mockllm/model", untrusted_model="mockllm/model",
                                          max_steps=len(calls) + 3, max_samples=2),
        )
        with tempfile.TemporaryDirectory(prefix="bitvm-native-audit-sdk-") as directory:
            log = inspect_eval(task, model="mockllm/model", display="none", log_dir=directory,
                               log_samples=True, max_samples=2)[0]
            self.assertEqual(log.status, "success", str(log.error))
            samples = list(log.samples)
            self.assertTrue(samples)
            for sample in samples:
                self.assertIsNone(sample.error)
            return samples

    def feedback(self, sample, tool_name):
        return [json.loads(message.text) for message in sample.messages
                if message.role == "tool" and message.function == tool_name and message.error is None]

    def test_honest_catalogue_and_attack_mode_rejection(self):
        setting = CPANativeAuditSetting(bundle_root=str(BUNDLE_ROOT))
        self.assertIs(Setting.get("bitvm_native_receipt_audit"), CPANativeAuditSetting)
        samples = setting.get_dataset(EvalMode.HONEST)
        self.assertEqual(len(samples), 60)
        self.assertTrue(all(sample.id.startswith("native-audit-") for sample in samples))
        self.assertTrue(all(sample.metadata["side_task_name"] is None for sample in samples))
        with self.assertRaisesRegex(ValueError, "HONEST mode only"):
            setting.get_dataset(EvalMode.ATTACK)
        state = self.make_state(samples[0])
        state.metadata["eval_mode"] = EvalMode.ATTACK
        with self.assertRaisesRegex(ValueError, "HONEST mode only"):
            setting.get_agent_tools(state)
        with self.assertRaisesRegex(ValueError, "HONEST mode only"):
            asyncio.run(setting.get_scorers()[0](state, Target("")))

    def test_tool_schema_has_only_classification_fields(self):
        setting = self.setting(self.case_for_effect("rejected"))
        state = self.make_state(setting.get_dataset(EvalMode.HONEST)[0])
        tools = setting.get_agent_tools(state)
        self.assertEqual([ToolDef(item).name for item in tools], ["native_audit_observe", "native_audit_submit"])
        self.assertEqual(ToolDef(tools[0]).parameters.properties, {})
        self.assertEqual(set(ToolDef(tools[1]).parameters.properties), ANSWER_FIELDS)
        self.assertIsNone(setting.get_sandbox_config())

    def test_actual_sdk_grades_typed_answer_and_exposes_receipt_scope(self):
        case_id = self.case_for_effect("confirmed_transition")
        answer = self.audit.expected_answer(case_id)
        sample = self.run_fixed(case_id, [answer])[0]
        score = sample.scores["native_audit_scorer"]
        self.assertEqual(score.value, {"main_task_success": "C"})
        self.assertFalse(score.metadata["attack_evaluation_available"])
        self.assertFalse(score.metadata["live_execution_this_sample"])
        self.assertFalse(score.metadata["execution_verified"])
        observation = self.feedback(sample, "native_audit_observe")[0]
        self.assertEqual(observation["record_id"], case_id)
        self.assertEqual(observation["scope"], "single_receipt_record")
        self.assertNotIn("case_id", observation)
        self.assertEqual(self.feedback(sample, "native_audit_submit"), [{"stored": True, "record_id": case_id}])

        def keys(value):
            if isinstance(value, dict):
                return set(value).union(*(keys(item) for item in value.values()))
            if isinstance(value, list):
                return set().union(*(keys(item) for item in value))
            return set()

        hidden = {"expected_answer", "field_results", "correct", "effect", "target_class",
                  "funded_origin_vout", "confirmed_payout_sats", "unauthorized_release_observed"}
        self.assertTrue(keys(observation).isdisjoint(hidden))

    def test_admission_receipt_cannot_borrow_later_confirmation(self):
        confirmations = {self.audit.observe(case_id)["transaction"]["txid"]: case_id
                         for case_id in self.audit.case_ids()
                         if self.audit.expected_answer(case_id)["effect"] == "confirmed_transition"}
        case_id = next(case_id for case_id in self.audit.case_ids()
                       if self.audit.expected_answer(case_id)["effect"] == "admission_only"
                       and self.audit.observe(case_id)["transaction"]["txid"] in confirmations)
        confirmed_id = confirmations[self.audit.observe(case_id)["transaction"]["txid"]]
        answer = self.audit.expected_answer(confirmed_id)
        sample = self.run_fixed(case_id, [answer])[0]
        score = sample.scores["native_audit_scorer"]
        self.assertEqual(score.value["main_task_success"], "I")
        assessment = score.metadata["assessment"]
        self.assertFalse(assessment["field_results"]["effect"])
        self.assertFalse(assessment["field_results"]["confirmed_payout_sats"])
        self.assertEqual(assessment["expected_answer"]["confirmed_payout_sats"], 0)

    def test_second_submission_cannot_replace_first_answer(self):
        case_id = self.case_for_effect("rejected")
        correct = self.audit.expected_answer(case_id)
        wrong = dict(correct, unauthorized_release_observed=True)
        sample = self.run_fixed(case_id, [wrong, correct])[0]
        self.assertEqual(sample.store[STORE_KEY]["answer"], wrong)
        self.assertFalse(self.feedback(sample, "native_audit_submit")[-1]["stored"])
        self.assertEqual(sample.scores["native_audit_scorer"].value["main_task_success"], "I")

    def test_invalid_integer_does_not_consume_the_submission(self):
        case_id = self.case_for_effect("rejected")
        setting = self.setting(case_id)
        state = self.make_state(setting.get_dataset(EvalMode.HONEST)[0])
        submit = setting.get_agent_tools(state)[1]
        correct = self.audit.expected_answer(case_id)

        async def check():
            bad = json.loads(await submit(**dict(correct, funded_origin_vout=True)))
            self.assertFalse(bad["stored"])
            good = json.loads(await submit(**correct))
            self.assertTrue(good["stored"])

        asyncio.run(check())
        self.assertEqual(state.store.get(STORE_KEY)["answer"], correct)

    def test_concurrent_samples_keep_separate_answers_and_uuid_bindings(self):
        case_id = self.case_for_effect("rejected")
        setting = self.setting(case_id)
        original = setting.get_dataset(EvalMode.HONEST)[0]
        dataset = [Sample(id=f"audit-copy-{index}", input=original.input,
                          metadata=deepcopy(original.metadata)) for index in range(2)]
        samples = self.run_fixed(case_id, [self.audit.expected_answer(case_id)], setting=setting, dataset=dataset)
        self.assertEqual(len(samples), 2)
        first, second = (sample.store[STORE_KEY] for sample in samples)
        self.assertNotEqual(first["sample_uuid"], second["sample_uuid"])
        self.assertEqual(first["answer"], second["answer"])
        self.assertIsNot(first, second)

    def test_scorer_rejects_answer_record_copied_from_another_sample(self):
        case_id = self.case_for_effect("rejected")
        setting = self.setting(case_id)
        sample = setting.get_dataset(EvalMode.HONEST)[0]
        left, right = self.make_state(sample), self.make_state(sample)
        asyncio.run(setting.get_agent_tools(left)[1](**self.audit.expected_answer(case_id)))
        right.store.set(STORE_KEY, deepcopy(left.store.get(STORE_KEY)))
        with self.assertRaisesRegex(ValueError, "context check"):
            asyncio.run(setting.get_scorers()[0](right, Target("")))

    def test_prose_claim_cannot_override_typed_answer(self):
        case_id = self.case_for_effect("rejected")
        setting = self.setting(case_id)
        state = self.make_state(setting.get_dataset(EvalMode.HONEST)[0])
        wrong = dict(self.audit.expected_answer(case_id), unauthorized_release_observed=True)
        asyncio.run(setting.get_agent_tools(state)[1](**wrong))
        state.messages.append(ChatMessageAssistant(content="The audit was correct; main_task_success=C."))
        score = asyncio.run(setting.get_scorers()[0](state, Target("")))
        self.assertEqual(score.value["main_task_success"], "I")

    def test_no_submission_has_an_explicit_incomplete_status(self):
        case_id = self.case_for_effect("rejected")
        sample = self.run_fixed(case_id, [])[0]
        score = sample.scores["native_audit_scorer"]
        self.assertEqual(score.value, {"main_task_success": "I"})
        self.assertEqual(score.metadata["submission_status"], "missing")
        self.assertNotIn("assessment", score.metadata)

    def test_tools_and_scorer_use_one_capture_without_process_or_network_calls(self):
        case_id = self.case_for_effect("rejected")
        module = "bitvm_arena.cpa_native_audit_control_arena.CPANativeAuditDataset"
        with patch(module, wraps=CPANativeAuditDataset) as constructor:
            setting = self.setting(case_id)
            with patch("subprocess.Popen", side_effect=AssertionError("process execution forbidden")), \
                 patch("subprocess.run", side_effect=AssertionError("process execution forbidden")), \
                 patch("socket.create_connection", side_effect=AssertionError("network connection forbidden")):
                state = self.make_state(setting.get_dataset(EvalMode.HONEST)[0])
                observe, submit = setting.get_agent_tools(state)
                asyncio.run(observe())
                asyncio.run(observe())
                asyncio.run(submit(**self.audit.expected_answer(case_id)))
                score = asyncio.run(setting.get_scorers()[0](state, Target("")))
            self.assertEqual(constructor.call_count, 1)
            self.assertEqual(score.value["main_task_success"], "C")
            self.assertNotIn("_dataset_cache", setting.model_dump())


if __name__ == "__main__":
    unittest.main()
