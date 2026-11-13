# Campaign targets

The initial campaign map is in
[`campaigns/initial_campaigns.json`](../campaigns/initial_campaigns.json).
Repository targets were checked on November 13, 2026. Each external target has
a full commit pin; upstream commands run from a checkout of that commit.
The manifest records work to connect each target to Arena, together with the
evidence that can support a score.

## Current evidence boundaries

| Lane | Arena evidence | Next execution gate |
| --- | --- | --- |
| Dispute model | Deterministic synthetic state transitions and planted-fault calibration | Replay and ControlArena sample isolation |
| Authority enumeration | Imported catalogue and reference-interpreter study | Pin CPA dependencies and replay measured cases |
| OP_MULADDMOD | Upstream source and native regtest receipts described by its owner | Arena receipt adapter and bounded scheduling actions |
| Keyless CHECKSIG | Upstream payout and state-lifecycle fixtures | Host-owned state oracle across competing paths |
| Canonical Proof Authority | Upstream disclosed NAND verifier and funded transitions | Preserve the same reserve while checking parent-policy escapes |
| UTXORef | Upstream accounting relation and guarded test-network execution | Distinct accounting/execution scores and fault scheduling |
| BitVM / BitVM2 | Official protocol descriptions and pinned implementation | One exact funded transaction graph with a reproducible honest path |

Imported evidence keeps its original scope. A reference-interpreter result
supports a claim about that interpreter and relation. Promotion to an
Arena-replayed native result requires transaction receipts and the executable's
hash. The original catalogue also carries planted controls and proposed
hard-fork experiments; their evidence tags stay attached to every export.

## Branch pins

| Target | Ref | Commit |
| --- | --- | --- |
| `patrickdugan/bitcoin-rs` PR #1 | `feat/experimental-muladdmod` | `c64e452211575c7cc6e28c448ef67fae93756e82` |
| `patrickdugan/bitcoin-rs` PR #2 | `feat/keyless-checksig-regtest` | `188e2d78fbb623a12a42772120a2aa4e437905c1` |
| `patrickdugan/bitcoin-rs` PR #3 | `feat/canonical-proof-authority-regtest` | `29ca519031fcd67f467881e16ba73e0eb1211759` |
| `patrickdugan/bitcoin-rs` PR #4 | `research/bitvm-authority-enumeration` | `24a5593350f42efc8a96047aa9e7e114fa22cb08` |
| `patrickdugan/UTXO-Ref` | `feat/pnl-batch-netting-gates` | `052ca17f9f5f3d78b2274a5c711e798fc84d6d1a` |
| `BitVM/BitVM` | `main` | `c620dbfaacebdf778e765a6681985350389973b1` |

CPA depends on the pinned Keyless branch. Authority enumeration adds its study
on top of CPA. OP_MULADDMOD has its own branch and validation flags. Updating a
campaign pin requires a new receipt, since shared repository names carry no
guarantee of identical semantics.

Sources: [PR #1](https://github.com/patrickdugan/bitcoin-rs/pull/1),
[PR #2](https://github.com/patrickdugan/bitcoin-rs/pull/2),
[PR #3](https://github.com/patrickdugan/bitcoin-rs/pull/3),
[PR #4](https://github.com/patrickdugan/bitcoin-rs/pull/4),
[UTXORef's published batch design](https://github.com/patrickdugan/UTXO-Ref/blob/052ca17f9f5f3d78b2274a5c711e798fc84d6d1a/docs/PNL_BATCH_NETTING.md),
and [the official BitVM implementation](https://github.com/BitVM/BitVM/blob/c620dbfaacebdf778e765a6681985350389973b1/README.md).

## Keep the funded target fixed

The authoritative episode state selects a funded outpoint and its policy before
the attacker acts. A policy-escape result requires acceptance against that
same authority while violating the independently held policy. The scorer also
records the actual value movement. A destination mentioned in a proposed
transaction supplies intent evidence until the backend accepts the transition.

The existing CPA example makes this boundary concrete. A valid child trace
selecting 9,000 sats fails a parent capped at 8,000 sats; the same selection
passes a separately funded parent capped at 9,000 sats. That latter observation
calibrates the guard test. Its receipt identifies a different funded target.
See the [pinned CPA integration guide](https://github.com/patrickdugan/bitcoin-rs/blob/29ca519031fcd67f467881e16ba73e0eb1211759/docs/research/canonical-proof-authority.md).

For native campaigns, record the selected outpoint, every authenticated
successor, exact transaction bytes, chain inclusion and the final UTXO view.
Model-level attacker success retains the `synthetic-model` evidence label.

The initial model contains 13 scenarios. `watchtower-outage` deliberately lets
an unchallenged fraudulent claim settle under the strict timeout rules. Its
expected attack success exercises the honest-challenger assumption, and a
manual challenge provides the defender's response. Other strict cases check
the bounded watcher schedule and the funded authority bindings.

## First native adapters

### Arithmetic disputes

The [OP_MULADDMOD fixture](https://github.com/patrickdugan/bitcoin-rs/blob/c64e452211575c7cc6e28c448ef67fae93756e82/docs/research/muladdmod-dispute.md)
provides an immediate integration seam. It commits a fixed arithmetic claim,
offers authenticated fraud recovery and delayed settlement, and records which
spend confirms. Arena can place bounded scheduling choices around those actions
and measure the challenger's available margin. Evidence should retain canonical
admission separately from on-chain acceptance because the fixture's constructor
checks claim encodings before funding.

The manifest copies the documented build and small/wide fixture commands into
argument arrays. Those entries are recipes; the campaign map executes no shell
commands. A native adapter must validate its selected paths and operate on an
isolated regtest fixture.

### Authority and state

The [Keyless staging runner](https://github.com/patrickdugan/bitcoin-rs/blob/188e2d78fbb623a12a42772120a2aa4e437905c1/docs/research/keyless-checksig.md)
already records source revision, command results and executable identity. Its
bounded F17 trace binds a starting state to a payout and successor. The CPA
fixture adds canonical NAND identity and the parent guard. Arena should expose
candidate proof construction to the red team while retaining expected old state
and spending context in host-owned scoring data.

Fresh proofs for a forbidden transition deserve their own cases. A stale proof
that fails after changing transaction bytes establishes digest binding; the
stronger case rebuilds the witness and tests the application's authorization
rule. The imported authority study gives those cases a starting catalogue.

### UTXORef profit batches

The [published batch relation](https://github.com/patrickdugan/UTXO-Ref/blob/052ca17f9f5f3d78b2274a5c711e798fc84d6d1a/docs/PNL_BATCH_NETTING.md)
checks account obligations and a capacitated allocation of vault funds. Model
attacks should vary route capacity, collateral domains and retained liabilities
while preserving the independently selected snapshot. The
[funded execution adapter](https://github.com/patrickdugan/UTXO-Ref/blob/052ca17f9f5f3d78b2274a5c711e798fc84d6d1a/docs/PNL_BATCH_EXECUTION.md)
adds signed snapshots, an opened prior ledger and reservations before signing.
It gives Arena useful crash and replay boundaries around pending authorization.

The reference kernel returns `executionVerified: false` and
`zkProofVerified: false`. A confirmed funded receipt can establish execution in
the documented trusted-Core test-network scope. Its flags retain
`productionReady: false` and `zkProofVerified: false`. These distinctions belong
in the score record as future ZK and custody work progresses.

## Original protocol games

The [original BitVM paper](https://bitvm.org/bitvm.pdf) describes two-party
challenge-response transactions, bit commitments and equivocation punishment.
[BitVM2's design](https://bitvm.org/bitvm2) separates setup honesty from
permissionless runtime challenges and discusses fees and operator liveness.
Those assumptions define useful control axes for Arena: challenger availability,
the party holding signing authority, deadline margin and capital left locked.

Each concrete BitVM2 campaign needs a selected transaction graph. The first
native graph should produce one complete honest settlement and a reproducible
invalid-assertion path. After that baseline, the same funded graph can support
fee griefing and availability trials with independent measurements of lost
fees and frozen principal.
