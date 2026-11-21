# Correlated setup compromise: initial BitVM Arena campaign

## Question

What changes when an attacker controls several nominally independent machines during
a BitVM signing ceremony, perhaps coordinating without producing a visible common
control channel? Does a script-only, proof-authorized reserve eliminate the
resulting signing-authority exposure?

This lane is a deterministic **synthetic threat model**. It expresses adversary
capabilities, not observed AI compromise probabilities, a steganographic
implementation, or an upstream Bitcoin exploit.

## Design and fixed policy

Five distinct setup hosts are simulated with a three-host signing threshold.
The threshold is a **declared experiment parameter**; it does not claim that
every BitVM2 or BitVM3 deployment uses 3-of-5. The presigned arm assumes that a
threshold coalition can retain a signing authority or authorize a poisoned
presignature during setup, despite a subsequent honest-key-deletion plan.

The paired arms share one logical payout and old-state policy. Each arm has its
**own synthetic funding outpoint**, as distinct locking programs would on
Bitcoin. Every attack inside an arm retains the identical frozen funding
target, regardless of how many hosts the attacker controls.

| Arm | Evaluator-owned assumptions |
| --- | --- |
| presigned-bitvm | A threshold setup signing route can bypass the application payout policy if compromised, and false optimistic claims need an available honest challenger |
| keyless-txcommit | A script-only reserve has no key-path private key, TXCOMMIT is consensus-enforced, and the full application validity verifier checks the old state and payout |
| keyless-txcommit-disabled | Planted calibration: the same policy omits TXCOMMIT's comparison to the actual transaction, allowing a witness that describes permitted outputs to accompany an unauthorized real transaction |

The last arm deliberately tests a **consensus activation error**. Unrecognized
Tapscript public-key types currently accept nonempty candidate signatures; the
research TXCOMMIT selector needs its new checking semantics before it can
authorize funds. The disabled arm assumes the other hypothetical prerequisites
are available, to isolate this one missing check. Never use a public Testnet4
output as if the new consensus rules were activated.

A scenario with compromised hosts states which host identifiers the attacker
controls. The label "covert" records a capability assumption. This first
campaign does not create covert messages, run an intrusion agent, or observe
real defender telemetry. The overt and covert three-host cases are both
successful against a presigned threshold in the model because the threshold,
rather than a telemetry classifier, determines signing authority. Independent
compromise probabilities and correlated-failure rates cannot be estimated from
these scripted cases.

## Deterministic tests

The campaign replays nine cases against all three arms, resulting in 27
synthetic receipts. The cases are honest completion, subthreshold control,
covert threshold control, overt threshold control, poisoned presignatures,
watcher outage, a mismatch between witness-described outputs and the actual
spending transaction, withheld proof fragments, and an unrelated old state.

Expected modeled results:

| Attack condition | Presigned | Keyless with validity verifier | Disabled-TXCOMMIT control |
| --- | --- | --- | --- |
| 2 of 5 setup hosts controlled | No unauthorized release | No unauthorized release | No unauthorized release |
| 3 of 5 hosts retain signing authority | Unauthorized release | Rejected | Rejected |
| 3 of 5 hosts poison presignatures | Unauthorized release | Rejected | Rejected |
| False claim with watcher offline | Unauthorized release | Rejected | Rejected |
| Wrong real transaction, permitted witness digest | Rejected | Rejected | Unauthorized release |
| Invalid prior state | Rejected | Rejected | Rejected |
| Proof fragments withheld | Settlement blocked | Settlement blocked | Settlement blocked |

These are **expectations encoded in the model**, not empirical comparisons of
live deployments. A "rejected" result means that the modeled attack does not
release assets; the remaining escrow can still be spent through a later honest
path. A "settlement blocked" result specifically marks a liveness failure.

Record separate fields for attacker success, legitimate completion, unauthorized
satoshis, diverted satoshis, remaining escrow and liveness blockage. A rejected
attempt receives no financial attack credit. The complete receipts include a
hash-chained event transcript, arm-specific frozen outpoint, source pins,
simulation assumptions, and a domain-separated evidence hash. Replay rebuilds
each result from the bundled evaluator-owned case and requires the intended
arm and case from the caller. Receipt hashes prove repeatable content, not the
author's identity or native validation.

## Commands

From the repository root with the package installed or PYTHONPATH=src:

~~~sh
python -m unittest discover -s tests -p test_setup_compromise.py -v
python -m bitvm_arena.setup_compromise benchmark --output runs/correlated-setup-01
python -m bitvm_arena.setup_compromise replay \
  runs/correlated-setup-01/receipts/quorum-covert.presigned-bitvm.json \
  --expected-case quorum-covert --expected-arm presigned-bitvm
~~~

The benchmark refuses to overwrite an existing evidence directory. Use a fresh
output path per campaign.

## Native test progression

The existing
[BitVM3 corruption corpus](../corpus/docs/BITVM3.md)
already contains Bitcoin Core 31.1 regtest evidence for the separate
desk_key_retained, claim_internal_key_spendable, watcher availability, and
transaction binding failure modes. These are valuable native controls; the
new multi-host coalition outcomes are a modeled extension of those controls.

The Keyless comparison has two concrete source references:
[TXCOMMIT proposal](https://github.com/patrickdugan/Spiral/blob/main/BIPSpace/Keyless-CHECKSIG/bip-keyless-checksig.md)
and [bitcoin-rs PR #2](https://github.com/patrickdugan/bitcoin-rs/pull/2).
The latter has actual funded regtest payout and bounded F17 state-transition
tests. The
[state-linked verifier](https://github.com/patrickdugan/Spiral/blob/main/BIPSpace/Keyless-CHECKSIG/state-linked-verifier.md)
also provides a 72-stage Circle-STARK Script-verification experiment, with a
synthetic initial coin and no mined blocks. Neither is an implemented UTXORef
validity relation.

Promotion to a native A/B campaign requires a versioned authority manifest for
each funding output, exact source and binary hashes, a controlled quorum of
test-only setup keys, actual presigned transaction bytes, adversarially mutated
candidate transactions, the accepted/rejected mempool and block verdicts,
and a host-owned final UTXO-state oracle. Preserve the genuine honest transfer
in every arm and distinguish planted setup mutants from bugs in original code.

For the experimental TXCOMMIT arm, use an isolated regtest network where every
validator has the same explicit research flags. Include tests where those flags
are disabled, verifying that the hypothetical vault would become unsafe.
Keep the actual source's 3-of-5 quorum behavior independent of any scanner
for covert communications. Repeat with sound 2-of-3, 3-of-5 and n-of-n
assumptions only after the concrete signing graph specifies each threshold.

Then connect these setup-level findings to UTXORef's ownership transfer,
permissionless challenge path, proof-fragment availability, transaction-fee
bumping and eventual redeemable payout. BIP 448 and competing covenant
constructions warrant their own native arm once their concrete interpreter
and output construction are pinned.
