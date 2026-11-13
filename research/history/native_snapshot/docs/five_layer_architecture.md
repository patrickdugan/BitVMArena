# BitVM Arena Five-Layer Architecture

`BitVM Arena` now models the benchmark as five explicit layers:

1. `rig`
   - Defines the committed BitVM rig surface for each circuit combination.
   - Output: rig catalog with state model, execution model, commitment surfaces, witness surfaces, and settlement surfaces.

1.5. `preflight`
   - Defines what a funding wallet should reject before money moves.
   - Output: wallet preflight catalog with detectable failures, blind spots, required checks, and bypass pressure.

2. `mutation`
   - Defines semantically related but adversarially risky circuit and witness-design mutations.
   - Output: mutation catalog per rig, covering packing, endianness, selector encoding, derived-field aliasing, proof shape, namespace projection, oracle-attestation gaps, trusted intermediates, witness defaults, and cross-route state reuse.
   - Each mutation records a canonical form, adversarial variant, binding invariant, detection terms, and concrete control focus.

3. `review`
   - Builds the actual audit dossier and prompt presented to the evaluator.
   - Output: review catalog with rig profile, mutation families in scope, review questions, and checklist.

4. `attack`
   - Searches for red-team strategies that preserve the hidden loophole while keeping the main task score high.
   - Output: attack research report over the generated attack tasks.

5. `validation`
   - Turns successful attack patterns into scorer-hardening recommendations and regression cases.
   - Output: validation report with mutation gaps, loophole gaps, and concrete assertions to add.

The latest full deterministic run evaluates `138` attack tasks across `26`
combinations and finds `101` successful semantic-aware red-team trajectories at
the default `0.75` main-task floor. The validation layer emits `10` regression
buckets from those wins, with the largest clusters in selector encoding, hash
preimage layout drift, timelock-route sanity, and Shinigami ZK receipt preflight
gaps.

## Why The Mutation Layer Matters

The mutation layer is where BitVM-specific implementation diversity becomes a red-team surface:

- the same state can be packed differently
- the same route can be encoded differently
- the same commitment can hash a different byte layout
- the same settlement field can appear under alias witness variables
- the same route story can move between oracle-attested and non-oracle-attested paths
- the same circuit can trust witness-supplied intermediates instead of recomputing them

That makes mutation pressure a first-class layer rather than just a note inside attack prompts.

## Why The Preflight Layer Matters

A bad script is not interesting if a wallet can plainly reject it before funding.
The arena now separates:

- wallet-detectable failures, such as malformed descriptors, unsafe timelocks, bad PSBT output policy, or unknown preimage domains
- wallet blind spots, such as future connector graph semantics, route-local witness meaning, hidden Taproot leaves, and typed commitment interpretation

Red-team trajectories should survive the pre-funding wallet checks or explicitly
target a wallet blind spot. Otherwise the attack is only a bad funding UX case,
not a serious BitVM arena trajectory.
