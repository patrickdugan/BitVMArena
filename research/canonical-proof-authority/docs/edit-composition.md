# BA-CPA-05: exact candidate classes under paired edits

## Scope

This extension uses the unchanged BA-CPA-04 proposal constructor and the pinned
CPA Python Script oracle. Its baseline is BitVMArena
`c296a683b5b6b3091200b106864880081be0d971`; the executable Bitcoin research source
is pinned to `24a5593350f42efc8a96047aa9e7e114fa22cb08`.

Each experiment retains its original evaluator-owned target. The parent policy,
input value, exact outputs and locking path remain fixed. The new files add a
composition experiment and tests within the CPA subtree, plus a dedicated CI
workflow. Existing runtime modules, previous workflow files and the parallel
core/verifier work are unchanged.

## Why count reconstructed candidates

Let K denote the entire frozen target and F_K(g) the exact candidate bytes
constructed from proposal g. For a fixed target, define

```
g ~_K h  iff  F_K(g) = F_K(h).
```

The relation is an equivalence relation. The current deterministic checker has
an outcome function V_K on candidate bytes. Therefore

```
g ~_K h  implies  V_K(F_K(g)) = V_K(F_K(h)).
```

Taking one representative of every exact class preserves the existence of a
counterexample in the tested finite set. The implementation uses the full bytes
as dictionary keys within a target. SHA256 identifies artifacts in the report;
hash prefixes never decide class membership. Every class representative is
reconstructed again and independently reevaluated.

The class relation supplies a coverage measure for isolated candidate checks.
Session resources still belong to the full action history. Two identical
submissions consume two attempts and two logical checks in the existing agent
interface. The new tests verify this behavior. The evaluator and session code
are unchanged, so this experiment introduces no query-cache bypass or free
retries.

## Finite experiment

The alphabet contains twelve concrete edits:

* Set payout to 7,001 or restore it to 7,000 sats.
* Set version to 1 or restore it to 2; change vout to 1 or restore it to 0.
* Swap output positions; substitute the alternate recipient or restore the
  original recipient script.
* Replace the parent witness hash with zero, submit an invalid control block,
  or give gate zero a nonminimal bit encoding.

The emitted `grammar.json` contains exact operation records. All words of length
zero, one or two are enumerated. Repetition is permitted, giving

```
|W| = 1 + 12 + 12^2 = 157.
```

The experiment uses one representative of each of the sixteen two-input
permission functions. Selection follows the existing deterministic ProgramID
ordering. Each representative receives all eight permission/selector assignments
and both digest-refresh choices, for

```
16 * 8 * 2 * 157 = 40,192 constructions.
```

The public semantic split is retained: ten training functions and six holdout
functions. All aliases of a permission function retain its original split.
These labels describe a fixed test partition; this experiment trains no model.

## Measured results

Two local runs produced byte-identical evidence for the complete experiment.

| Measurement | Result |
|---|---:|
| Constructions | 40,192 |
| Exact target/candidate classes | 9,848 |
| Duplicate constructions beyond class representatives | 30,344 |
| Classes reevaluated with identical results | 9,848 |
| Authorized classes | 30 |
| Script-rejected classes | 6,362 |
| Target-mismatch classes | 3,456 |
| Unmodified-target counterexample classes | 0 |
| Original-target Script checks, including replay | 12,784 |
| Separately funded calibration checks, including replay | 30 |

Each class was evaluated once and replayed once. Target-mismatch cases stop
before Script execution, explaining the difference between class count and
Script-check count. The summary keeps these denominators separate.

Before grouping, the observed outcomes have multiplicities 1,664 authorized,
27,008 Script-rejected and 11,520 target mismatches. Authorized multiplicity
comes from valid transactions including unchanged and restored actions. Those
acceptances receive ordinary authorization outcomes. Counting every accepted
mutation as an exploit would misclassify these cases.

Of 16,896 unordered pairs tested in both orders across the fixed assignments and
refresh settings, 14,848 produce identical candidates and 2,048 are order
sensitive. These are observations for the finite alphabet, not a proof that
arbitrary distinct edit operations commute.

There are 256 nontrivial cancellation instances. For these instances both
single edits change the baseline candidate, while their composition restores
its exact bytes. Here the operation is output-swap applied twice. Assignment
and refresh contexts are counted separately. The table includes unsatisfiable
permission inputs, whose restored candidates remain rejected.

Fifteen separately funded wider-cap controls accept their selected 9,000-sat
payout against a host-declared 8,000-sat calibration obligation. Their existing
planted labels remain bound into their target identity. Each receives a
1,000-sat calibration cap excess and zero original-target attack/diversion
credit. These controls establish that scoring can represent a planted policy
violation. They supply no escape against the original funded target.

## Algebraic checks

A repeated overwrite is idempotent. On one field, composing two overwrites
retains the last value. Reversing them can therefore change authorization.
Disjoint field updates commute in the tested representation. Output swaps
interact with indexed updates, so alphabetic sorting of arbitrary edits would
change the experiment.

The proposal constructor first applies all transaction edits, optionally
refreshes the digest, and then applies witness edits. Consequently a transaction
edit and a witness edit can appear in either proposal order and still produce
the same candidate. That property follows from the specified two-pass
constructor; it is not a generic property of an arbitrary sequential edit VM.

These properties motivate exact reconstruction before coverage grouping. The
experiment applies no speculative graph or proposal normalization.

## Tests and reproduction

The new suite contains 21 tests. The run also executes 64 existing reference
checks: 32 candidate-search tests, 26 session tests and six receipt-type tests.
The pinned CPA suite contributes 42 tests. All 127 pass without skipped cases.
The SDK integration and native node are outside this local run.

Use the existing BA-CPA-01 wrapper to obtain the checked corpus, then run:

```sh
python3 -I -S -B research/canonical-proof-authority/scripts/run_composition.py \
  --bitcoin-rs /path/to/pinned/bitcoin-rs \
  --corpus /path/to/ba-cpa-01/generated/circuits.jsonl \
  --out /tmp/cpa-composition-01
```

The output directory must be new. The wrapper verifies nine upstream input
hashes, including all six imported backend modules and the CPA regression data.
The enumeration-only test file is outside this campaign. The inherited checker
and proposal constructor have explicit hash pins. Reviewed research files and
the corpus bytes are captured into a temporary tree before isolated Python
subprocesses start. The runner imports no unrelated files from the supplied
Bitcoin checkout and invokes no network or node service.

The output contains a target catalogue, the grammar and exact class records.
Every class records a reconstruction proposal and all member indices. The
member-index formula is documented in `grammar.json`. Class records carry the
candidate SHA256 and its byte length, allowing exact reconstruction from the
pinned sources without duplicating each long candidate in the catalogue.
Calibration records preserve complete replay traces. All five generated files
must match `fixtures/composition-lock.json`.

This covers the selected twelve-edit alphabet through length two. The full
BA-CPA-04 grammar permits more values and up to eight edits. Native HF CHECKSIG,
ZK delegation, production policy security and model-generated search results
require separate evidence.
