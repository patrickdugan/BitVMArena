# Recovered authority-enumeration study

The eight files under `upstream/` are byte-for-byte copies of the changes in
[`bitcoin-rs` PR #4](https://github.com/patrickdugan/bitcoin-rs/pull/4), pinned to
commit `24a5593350f42efc8a96047aa9e7e114fa22cb08`. Their original paths are intact.
`recovery_manifest.json` records each Git blob ID, SHA256 digest and byte length.
The imported workflow remains an archival file under this directory.

The study uses CPA source at
`29ca519031fcd67f467881e16ba73e0eb1211759`. Its report and results retain the
scope stated when they were published. Historical native Arena source recovered
later in this task is recorded in [`../history/`](../history/README.md).

## Import the scenario catalogue

```python
from research.authority_enumeration import load_catalogue

for scenario in load_catalogue():
    print(scenario.scenario_id, scenario.evidence_level.value)
```

Ten scenario families are available. Five contain deliberately weakened
models; three have measurements from the CPA Python Script oracle. The two
remaining families describe future HF experiments. `load_catalogue()` validates
those labels and the requirement to retain the original funded target.

| Evidence level | Cases | Meaning |
| --- | ---: | --- |
| `planted_model` | 5 | A deliberately weakened construction supplies the failure. |
| `measured_CPA_python` | 3 | The independent Python Script oracle exercised the CPA construction. |
| `proposed_HF_Arena` | 2 | A native verifier or cache is still needed to execute the hypothesis. |

`assess_fixed_target()` requires the evaluator's original authority, descriptor
digest, state and outpoint to equal the identity used for the observed
execution. A successful receipt also needs acceptance, a violated parent policy
and an observed unauthorized effect. The caller supplies those results from a
trusted verifier. Agent-authored claims must stay outside that interface.

This helper carries each result's evidence level through scoring. Proposed HF
families receive no executed-attack credit. A wider-cap authority that accepts a
witness remains a positive control for a distinct funded target.

## Replay against pinned local source

From the repository root:

```sh
python3 research/authority_enumeration/replay.py \
  --bitcoin-rs /path/to/bitcoin-rs \
  --out /tmp/bitvm-authority-replay
```

The output directory must be empty. The wrapper hashes all nine dependency
files listed in the original provenance, stages only their verified bytes in
a temporary directory, and executes the preserved enumerator in isolated
Python mode. It compares the three generated evidence files with the original
SHA256 records before writing `replay_receipt.json`.

The replay uses the independent Python Script oracle. All transaction objects
stay in memory. Source verification fails before execution when a pinned file
is missing or has changed.

The original regression suite can also run against that checkout:

```sh
CPA_SOURCE=/path/to/bitcoin-rs python3 -m unittest discover \
  -s research/authority_enumeration/upstream/scripts/tests \
  -p test_bitvm_authority_enumeration.py -v
```

## Verification on November 13, 2026

The new import-boundary suite passed 13 tests. The original study passed its
14 regression tests against nine freshly retrieved and hash-verified CPA
dependency files. A fresh full enumeration reproduced all three evidence files
byte-for-byte: 1,851 canonical programs spanning 16 Boolean functions, 256
Script-oracle checks over 32 compiled authorities, and 11 mutation controls.
The oracle reported 72 accepted witnesses and zero expectation mismatches.

[`verification/replay_receipt.json`](verification/replay_receipt.json) records
the new replay. The archived `results.json` remains unchanged. Source and
receipt hashes can reproduce this result on the pinned checkout; current
`bitcoin-rs` branches may contain newer files.

The upstream CPA research license is retained in `LICENSE.upstream`.
