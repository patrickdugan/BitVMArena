# Handoff to the BitVMArena rebuild

This module owns only `research/canonical-proof-authority/` and the dedicated
`.github/workflows/cpa-gate-enumeration.yml`. Leave core package registration,
model-provider plumbing, and the environment/scorer API to the rebuild thread.
No root dependency, README, or runtime configuration is changed here.

## Import surface

`scenarios/arena_scenarios.jsonl` contains ten descriptive scenario families.
Each uses schema `BA-CPA-01/scenario-v1`. Treat these records as data. They contain
no executable command or native adapter claim. The runner validates unique IDs,
fixed-target requirements, offline scope, and the allowed evidence labels.

`planted_model` identifies a deliberately weakened cryptographic or commitment
model. `measured_CPA_python` identifies current Python-oracle observations.
`proposed_HF_Arena` identifies a hypothesis needing a native backend. Preserve the
label in each exported task and receipt. A catalogue row is not a completed
interactive episode.

For corpus generation, call `scripts/run.py` as a subprocess with an explicit
pinned bitcoin-rs source path and a fresh output directory. It creates
`generated/circuits.jsonl`, `generated/compiled_authorities.json`, and
`generated/results.json`. The generated files retain their upstream schemas.
`receipt.json` uses `BA-CPA-01/arena-run-v1` and records hashes and evidence scope.

The pin is intentional. Updating it requires reviewing the new compiler/oracle
sources, recalculating the input hashes, rerunning the study, and reviewing any
changed expected outputs. A changed branch name or Git HEAD is insufficient.
The runner uses a fresh temporary copy of verified files, so an unrelated module
in the supplied checkout is excluded from its import paths.

## Required scorer boundary

Freeze the target descriptor, state commitment, and funded output identity before
an attack. Preserve exact parent-policy semantics in an independent checker.
A positive attack label requires the chosen backend to accept an unauthorized
transaction against that original target. Selecting another permissive policy
or finding a planted-mutant failure gets its own result class.

For a future receipt, include target commitment and outpoint, ProgramID,
AuthorityID, exact transaction/witness bytes, changed policy fields, execution
budget, validator result, parent-policy result, and source provenance. Retain
canonical aliases in one training/evaluation partition. Report results by the
sampling distribution and semantic policy where exact equivalence is feasible.

Credentials, private delegate inputs, ZK-verifier parameters, and external facts
need explicit authenticated interfaces. The current public disclosed-trace
profile supplies none of those on its own. An HF adapter must specify its actual
consensus rule, cost accounting, and proof/public-input encoding before its
results can receive a native-verifier label.

## Reproduction contract

The locked upstream contains 14 study tests and 42 CPA tests. Fourteen local
runner tests cover source integrity and scenario scope. A complete run reproduces
1,851 programs, 32 compiled authorities, 256 Script-oracle cases with zero
mismatches, and eleven expected mutation/control outcomes.

The workflow fetches the pinned public repository during setup. The test and
study processes operate on local files and invoke no network or node service.
This is independent of the rebuild's own CI. Root and core-file changes can
therefore proceed without changing the study's source or target policy.
