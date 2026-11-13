# Native CPA regtest bridge

The Arena wrapper ran the pinned CPA suite on a fresh isolated regtest chain.
It confirmed **four transitions**, rejected **49 adversarial cases** and admitted
**seven positive controls**. The chain reached height 104 with zero peers and
three clean daemon exits. Transaction receipts are retained in
[`evidence/cpa_native`](../evidence/cpa_native).

## Reproduce

Use Python 3.11 or newer on a POSIX host that can run the pinned Linux binary.
Select a separate CPA checkout and a new output directory:

```sh
python scripts/run_cpa_regtest.py \
  --source /path/to/bitcoin-rs-cpa \
  --binary /path/to/bitcoin-rs \
  --output /tmp/bitvm-arena-cpa-run-01 --timeout 180
```

| Identity | Pin |
| --- | --- |
| CPA source | `29ca519031fcd67f467881e16ba73e0eb1211759` |
| Binary source | `188e2d78fbb623a12a42772120a2aa4e437905c1` |
| CI build commit | `2e8f5f1f588ccf3bc85e8c2a8399bd1a05368a98` |
| Native source tree | `c9f0f775b4ff5b08376505bb010b63ca731ba726` |
| Actions artifact | `14006830303` |
| Executable SHA256 | `fe506c638478d173edd267422856b9fb02c8ab424b694b6c81554dce2a48caa6` |
| Artifact ZIP SHA256 | `5676cc6f044e98b134266c13133f0451339fa371ddb4c3057209847c52d730a4` |

The [CPA integration guide](https://github.com/patrickdugan/bitcoin-rs/blob/29ca519031fcd67f467881e16ba73e0eb1211759/docs/research/canonical-proof-authority.md)
records the binary's provenance. Its features are
`fjall,experimental-keyless-checksig-regtest,experimental-op-cat-regtest`.
The wrapper accepts the measured executable hash above. A later build needs an
explicit pin update and a fresh receipt.

## Execution and receipt checks

`run_native(source, binary, output, timeout=180)` verifies five source modules
under `scripts/research` and the executable, then stages their bytes in a private
temporary directory. Isolated Python derives a frozen authority profile before
the unchanged upstream suite runs. Source and binary hashes are checked again
afterward. The node uses disposable data, loopback RPC and disabled DNS seeds.
Timeout handling terminates the owned process group.

The normalizer independently parses raw transactions and recomputes `txid` and
`wtxid`. Each case must use its expected funded outpoint and show the prescribed
native rejection at admission, broadcast and direct block validation. Canonical
tip hashes must match the funding or restart block at the required height. The
sole repeated rejected witness belongs to the parent-cap case at height 102 and
its spent-input retry at height 103. Copied cases fail the coverage check.

Two main reserves each pay 7,000 sats, retain 91,000 sats in the committed
successor, then pay 89,000 sats at termination. Each transition costs 2,000 sats.
Together, the two paths account for 200,000 funded sats, 192,000 sats in
beneficiary payments and 8,000 sats in fees. Each child retains its original root
outpoint in the Arena record. The separately funded 9,000-sat-cap authority stays
a positive calibration control; the original authority's cap is 8,000 sats.

Positive admission checks carry `confirmed_by_this_check: false`. The four
confirmed transitions retain their own records and exact output vectors.
The committed bundle contains the upstream report, frozen profile, normalized
receipt, binary provenance and sanitized completion counts. Temporary node data
and RPC credentials stay outside the bundle.

## Verification scope

`normalize_report(report, profile)` validates retained evidence and returns
`execution_verified: false`. The runner sets that flag to true after completing
the staged native execution. Tests cover target substitution, changed witnesses,
missing tips, duplicated cases, execution phases and process cleanup. Set
`CPA_SOURCE` and `CPA_BINARY` to enable the fresh-node test:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p test_cpa_native.py -v
```

The native bridge executes the fixed upstream suite. The agent-facing reference
backend selects existing fixture cases. Native receipts retain
`agent_selected_native_mutations: false`. The proof relation uses disclosed
NAND traces and finite precompiled successors, with `zero_knowledge: false`
and `singleton_lineage: false`.
