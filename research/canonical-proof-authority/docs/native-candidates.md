# BA-CPA-05: native checks for bounded CPA candidates

Date: 2026-11-14. This addition owns files inside the existing CPA research
subtree. The core simulator and PR #2's verifier/audit integration retain their
owners. Existing source pins, consensus feature gates and SDK registrations
are unchanged.

## What executes

`run_native.py` captures six hash-checked bitcoin-rs runtime files and the three
reviewed research modules. It copies the executable after matching the pinned
SHA256, then runs a bounded subprocess group with isolated Python imports.
The worker starts the captured bitcoin-rs executable on a new temporary regtest
chain with native validation. It accepts no external RPC endpoint or existing
data directory. The inherited node launcher binds loopback, disables DNS seeds,
and checks zero connected peers. A timeout terminates the worker process group.

The native executable comes from Keyless artifact `14006830303`. Its SHA256 is
`fe506c638478d173edd267422856b9fb02c8ab424b694b6c81554dce2a48caa6`, with dependency
source `188e2d78fbb623a12a42772120a2aa4e437905c1`. CPA runtime source remains pinned
to `24a5593350f42efc8a96047aa9e7e114fa22cb08`. This run reused that reviewed
executable. A fresh binary build was outside this run.

The worker mines fixture funds and confirms one 100,000-sat CPA root output at
height 102. The actual funded outpoint is frozen into the evaluator target.
Every proposal uses the existing BA-CPA-04 edit grammar. Reconstruction starts
from the pinned compiler; the independent parent-policy checker and reference
Script interpreter evaluate the resulting candidate before native RPC checks.
The funded value and script are read back from the node before each attempt.

`NativeTarget.step(proposal_bytes, finalize=False)` is a data-only interface for
a trusted orchestrator. Target setup stays outside that interface. A malformed
proposal or substituted locking path has a host-rejection receipt and no native
acceptance claim. Target-bound candidates reach `testmempoolaccept`. A rejected
candidate also reaches broadcast admission and direct `generateblock`
validation, which must report the Script rejection boundary. Each rejection
and probe preserves the applied height/tip and original coin.

Admission-only probes have zero confirmed payout. Finalization broadcasts an
accepted transaction and verifies its exact bytes in the block, then checks
that the original target is spent. Accepted policy violations retain separate
unauthorized-release and destination-diversion fields. Partial evidence is
written before exceptions propagate. Returned event objects are copies.

## Executed campaign

The campaign used the default AND-permission circuit and 8,000-sat parent cap.
It submitted 25 proposals against the original funded target:

| Outcome | Count |
|---|---:|
| Native Script rejections, including direct block validation | 18 |
| Authorized admission-only probes | 2 |
| Authorized confirmed transition | 1 |
| Host rejection of target substitutions | 3 |
| Malformed bounded JSON | 1 |

All 21 native admission decisions agreed with the reference interpreter.
There were 19 direct block-validation checks: 18 rejections and the confirmed
transaction. No unauthorized release or destination diversion was observed.

The confirmed spend paid 7,000 sats to the intended recipient and created the
91,000-sat committed successor, with a 2,000-sat fee. A restart at height 103
preserved both outputs and the spent status of the original coin. Both daemon
exits were zero, and the peer count stayed zero.

The matrix covers retained-cap rejection, denied permission, authority/state
and grant substitution, changed outputs, incorrect transaction context, a
broken gate, stale digest, and host target-rebinding checks. The broad finite
circuit corpus and semantic holdout partition retain their earlier Python
scope. This native run covers one circuit and the recorded proposal matrix.

Twenty new unit tests use synthetic RPC responses to exercise receipt handling.
The discovered research suite ran 42 tests including these new tests. Separate
runs passed 32 candidate-search tests, 26 session tests and 42 upstream CPA
tests, for 142 passing test executions. The full captured-source native runner
also completed successfully. Unit-test RPC responses remain separate from the
actual native execution receipts.

## Reproduce

Provide the pinned local bitcoin-rs source and the reviewed executable:

```sh
python3 -I -S -B -m unittest discover \
  -s research/canonical-proof-authority/tests -p test_native_candidates.py -v
python3 -I -S -B research/canonical-proof-authority/scripts/run_native.py \
  --bitcoin-rs /path/to/pinned/bitcoin-rs \
  --binary /path/to/reviewed/bitcoin-rs \
  --out /tmp/cpa-native-candidates-01 --timeout 240
```

The output directory must be new. The wrapper records source, executable and
per-file evidence hashes in `receipt.json`; `native/` retains the funding bytes,
25 individual event records, a summary report and the node log. Fresh block
identities depend on the run, so hashes identify that execution's evidence.
`fixtures/native-candidate-summary.json` records the measured run's identity.
The runner never downloads a dependency or silently substitutes a binary.

## Remaining boundary

This is native execution of the existing experimental TXCOMMIT/CAT regtest
profile with disclosed NAND traces. Native HF CHECKSIG and ZK-backed delegation
remain separate implementation work. The source keeps `HF_verified` false.
The campaign uses scripted proposals; no provider or model evaluation ran.

This worker exposes a native per-candidate evaluation primitive. Attaching its
node lifecycle to individual ControlArena samples is a further integration
step. The current SDK tools still use their existing Python backend. PR #2's
retained receipt audit and native-suite runner are unchanged. Its receipts
retain their original meanings.
