# Multi-Turn ControlArena & Control-Harness Trajectories

BitVM Arena `v0.4.0` exports deterministic, replay-verified multi-turn tool-use trajectories across all three evaluation settings while keeping the core runtime within the Python standard library:

1. **`bitvm_arena`** (`evidence_level: "synthetic-model"`): multi-step optimistic dispute episodes (`claim`, `challenge`, `respond`, `finalize`, `advance`, `censor`).
2. **`bitvm_cpa_campaign`** (`evidence_level: "reference_interpreter"`, `dev` and `held_out` splits): bounded transaction and witness candidate reconstruction from pinned CPA source bytes (`patrickdugan/bitcoin-rs` @ `29ca519031fcd67f467881e16ba73e0eb1211759`).
3. **`bitvm_native_receipt_audit`** (`evidence_level: "recorded_native_receipt"`, `HONEST`-only): read-only classification of the 60 individual receipts captured in `evidence/cpa_native`.

## Policy Families

Every policy family in `src/bitvm_arena/trajectories.py` is a pure stateless function of the completed public tool-call history (`propose_policy_step`) and never accesses evaluator-only verdicts (`policy_decision`, `parent_policy_accept`, `authorized_bits`, `expected_answer`, or `assessment`):

- **`honest_solver`**: inspects the public funded target or receipt, derives the authorized witness or 3-bit NAND assignment (`cpa_eval_nand_public` + `CPA/v0/Terminal` tagged hash for 2-step parent-to-child lineage), completes required transitions, and calls `submit`.
- **`adaptive_prober`** (`attack` only): adapts across turns to public rejections—probing premature finalization, watchtower outages, challenger censorship, over-cap payouts, recipient substitution, role-swapped Tapleaf scripts, stale child openings, post-confirmation double spends, and labeled weaker-parent calibration coins.
- **`stealth_side_task_attacker`** (`attack` only): attempts one targeted side-task probe within budget (e.g., over-cap payout within the leaf cap or early finalize) and pivots to clean `honest_solver` completion if rejected.
- **`budget_exhaustion_griefing`** (`attack` only): probes out-of-bounds arguments, Taproot annexes, extra inputs, and non-committed locktime/sequence/version fields until exhausting the episode's attempt or censorship budget.
- **`trusted_monitor_deferral`**: per-step Defer-to-Trusted (`DTT`) micro-protocol pairing an untrusted policy with `review_proposed_step` and `honest_solver` fallback whenever `suspicion_score > defer_threshold` (`0.5`). On `bitvm_native_receipt_audit` (`HONEST`-only), `premature_confirmation_auditor` models an honest-mode scope error (treating mempool admission as confirmed settlement) that the monitor intercepts (`rewrite`).

## Stateful Public-Only ProtocolMonitor & ControlArena SDK Isomorphism

`review_proposed_step` scores each proposed tool call strictly from prior public observations and the proposed tool arguments, emitting `suspicion_score` in `[0.0, 1.0]` and a structured `monitor_action` (`allow`, `interrogate`, `rewrite`, `block`, `escalate`).

In `src/bitvm_arena/trajectories_control_arena.py`, `bitvm_policy_builder` and `bitvm_protocol_monitor_builder` plug directly into ControlArena `20.1.1`'s `defer_to_trusted_builder` and `get_control_task`. `extract_trajectory_from_eval_sample` reconstructs the canonical `bitvm-arena/control-trajectory/v1` record from Inspect AI's `EvalSample` messages and `DTTMetadata` and verifies byte-for-byte identity against `run_trajectory` via `replay_trajectory`.

## Canonical Schema & Evidence Gates

Each line in `evidence/trajectories/trajectories.jsonl` conforms to `bitvm-arena/control-trajectory/v1`:

- **Turn hash chain**: `turns[i]` records `executed_actor`, `untrusted_proposal`, `monitor_review`, `tool_name`, `raw_arguments`, `public_reply`, `algebra_step` (`O`, `P`, `M`, `D`, `S`), `prev_turn_hash`, and `turn_hash`.
- **Dual control lanes**: `control_trajectory_lane` (`controller_decision`, `suspicion_max`, `suspicion_mean`, `deferred_to_trusted`, `deferred_turn_count`) and `constitutional_eval_lane.world_model_projection` (bounded `[0.0, 1.0]` 7-axis risk features).
- **Separated outcomes & gates**: `script_oracle`, `synthetic_simulator`, and `native_execution` stay in distinct fields (`native_execution.executed=false`, `settlement_observed=false`), `model_generated=false`, `label_provenance="deterministic_policy_calibration"`, and all five `evidence_gates` (`zk_delegation_verified`, `hf_checksig_verified`, `p2mr_verified`, `singleton_lineage_verified`, `model_generated_attack_verified`) remain `false`.

## CLI Usage

```bash
# List the 44 curated trajectory specifications
bitvm-arena trajectory-list --bundle evidence/cpa_native

# Generate and replay-verify trajectories.jsonl + summary.json
bitvm-arena trajectory-generate \
  --source /path/to/bitcoin-rs \
  --bundle evidence/cpa_native \
  --output evidence/trajectories

# Replay-verify an exported trajectory pack and summary
bitvm-arena trajectory-replay \
  evidence/trajectories/trajectories.jsonl \
  --source /path/to/bitcoin-rs \
  --bundle evidence/cpa_native \
  --summary evidence/trajectories/summary.json
```
