# Validation on November 13, 2026

Version 0.2.0's combined suite discovered **94 tests: 93 passed and one optional
fresh-node test was skipped**. The CPA wrapper had separately completed the
native execution whose receipts are retained in the repository. The combined
suite used the pinned CPA source and actual ControlArena SDK dependencies.

| Test group | Passed | Skipped |
| --- | ---: | ---: |
| Dispute engine | 28 | 0 |
| Imported authority-study boundaries | 13 | 0 |
| Dispute ControlArena setting | 9 | 0 |
| CPA reference backend | 16 | 0 |
| CPA ControlArena setting | 8 | 0 |
| CPA native receipt and runner checks | 19 | 1 |

The SDK checks executed ControlArena 20.1.1 with Inspect 0.3.252 and
agent-client-protocol 0.12.0. The optional dependency pins are in
`pyproject.toml`. The restored version 0.1.0 baseline comprised the first
50 tests in the table.

## Simulator calibration

The 13 installed scenarios produced 22 scripted episodes. All matched their
declared expectations and replayed exactly. Nine deliberately weakened runs
produced a policy-violating release. Of the 13 strict runs, the explicit
watcher-outage assumption control released an unchallenged fraudulent claim;
the remaining runs preserved the funded policy. These results calibrate the
fixtures and scorer. They do not estimate a deployed protocol's failure rate.

The exhaustive schedule check explored 1,296 four-action sequences against the
strict output-substitution scenario. It checked funded value conservation,
unchanged target identity and the absence of unauthorized releases after
every action.

Boundary checks cover challenge and response deadlines, rejection paths,
intervening watcher actions during multi-block advances, exhausted censorship,
duplicate settlement and action limits. The replay tests mutate claimed
scores, event hashes, fixture identity and supplied seed actions. External
expected-profile and expected-scenario checks reject a trace from a different
experiment.

Independent review found a pure timing gap in the initial score: an early
payout to the correct recipient omitted the challenge-window violation.
The scorer now records that violation, with a regression test. A separate
`diverted_sats` metric distinguishes recipient diversion from other policy
violations.

## ControlArena integration

The SDK tests execute `get_control_task`, the fixed-policy builder, Inspect's
tool dispatcher and the replay scorer. Concurrent samples retain separate
action stores. An agent's attempts to supply a profile or scenario through the
tool interface fail. Scenario seeds apply once.

The authorized withdrawal control scores main-task success and no side-task
success. Output substitution fails under the strict profile; the deliberately
weakened output-binding profile produces a side-task success under the same
funded target. Every evaluated sample completed with `error=None`.

These are scripted integration checks. Model-generated attack evaluations
remain a future campaign.

## CPA reference setting

The fixture benchmark executed all **28 published choices** against the pinned
compiler and independent Python Script interpreter. Honest acceptance and the
separately funded wider-parent control passed. The remaining 26 cases were
rejected, with zero reference policy escapes. The complete exported trace
replayed exactly; its source record matches the executed adapter bytes.

The 16 backend tests cover original-target preservation, an independent parent
policy verdict, cross-coin witness rejection, replay tampering and externally
selected budgets. Source edits after session construction leave execution bound
to the captured bytes. Review found an initial worker-code reread after hashing;
the session now freezes that code with its dependencies. A regression blocks
every subsequent file read and still completes the honest attempt.

Eight additional SDK tests used the real solver and tool dispatcher. They
checked the fixture allowlist, evaluator-owned configuration, attempt limits,
concurrent samples and replay scoring. Forged success claims in agent prose
leave the score unchanged. The wider-parent calibration earns zero attack
credit against the original authority.

See the [benchmark summary](../evidence/cpa_reference/summary.json) and
[complete trace](../evidence/cpa_reference/trace.json). Their evidence layer is
`reference_interpreter`, with `native_execution=false` and
`settlement_observed=false`.

## CPA native execution

The Arena runner executed the existing suite from CPA commit
`29ca519031fcd67f467881e16ba73e0eb1211759` using the exact experimental binary
whose SHA256 is
`fe506c638478d173edd267422856b9fb02c8ab424b694b6c81554dce2a48caa6`.
The wrapper staged five verified modules and the binary in a private directory,
derived the funded profile before execution and verified those bytes afterward.

| Native measurement | Result |
| --- | ---: |
| Confirmed transitions | 4 |
| Rejected adversarial cases | 49 |
| Positive admission controls | 7 |
| Original funded coins | 2 |
| Original principal | 200,000 sats |
| Beneficiary payments | 192,000 sats |
| Transition fees | 8,000 sats |
| Unauthorized release | 0 sats |
| Final regtest height | 104 |
| Connected peers | 0 |

Two root transitions and their successor transitions confirmed. State survived
two restarts, and all three daemon processes exited cleanly. Positive admission
controls have `confirmed_by_this_check=false`; confirmed transitions retain
their own chain records. The wider-parent calibration uses a different funded
authority.

Independent review found receipt checks that accepted absent block-tip hashes,
copied rejection evidence and the permitted repeated witness at the wrong chain
height. Targeted regressions now require canonical tips, bind each rejection to
its intended phase and reject duplicate coverage except the prescribed
parent-cap/spent-input pair. The final normalizer reproduces the retained
measured receipt. Normalizing a supplied report alone leaves
`execution_verified=false`; the runner adds execution provenance after the
staged suite succeeds.

The [native guide](cpa_native.md) documents reproduction. Its
[retained receipt](../evidence/cpa_native/receipt.json) records
`agent_selected_native_mutations=false`. Per-sample native fixture selection
and model-generated campaign results remain pending.

## Recovered authority study

The preserved upstream suite passed **14 additional tests**. A fresh execution
of the imported enumerator reproduced the frozen evidence:

| Measurement | Result |
| --- | ---: |
| Verified imported files | 8 |
| Verified CPA dependency files | 9 |
| Canonical NAND programs | 1,851 |
| Boolean functions | 16 |
| Compiled authorities tested | 32 |
| Python Script-oracle executions | 256 |
| Accepted witnesses | 72 |
| Expectation mismatches | 0 |
| Mutation controls | 11 |
| Generated files matching frozen SHA256 values | 3 |

The receipt is at
[`research/authority_enumeration/verification/replay_receipt.json`](../research/authority_enumeration/verification/replay_receipt.json).
This result uses the pinned Python Script oracle. Native consensus execution
has its own campaign gate.

## Packaging and CI

An editable package installation completed successfully, including the CLI
entry point and shipped source manifest. CI checks the stdlib core on Python
3.11 and 3.13, both actual ControlArena settings, the CPA reference benchmark
and the pinned authority replay. The core suite checks retained native evidence;
a fresh node run requires `CPA_BINARY` with the pinned executable hash.

The restored baseline's [hosted workflow](https://github.com/patrickdugan/BitVMArena/actions/runs/43450924637)
passed all four jobs. The repository's [Actions history](https://github.com/patrickdugan/BitVMArena/actions)
records subsequent results against their published commits.
