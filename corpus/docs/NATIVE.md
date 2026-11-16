# Native Bitcoin tracks

The model corpus scores a deterministic coordinator. The native tracks put the same
kinds of corruption into real Taproot transactions and let Bitcoin Core judge them.
Each track runs on a regtest node the harness starts itself: a fresh empty datadir, P2P
disabled, RPC on 127.0.0.1 with a random port. It refuses non-empty datadirs and
non-regtest chains, and never attaches to an existing node.

| Track | Module | Cases | What a case is |
| --- | --- | --- | --- |
| `primitive` | [`native.py`](../bitvm_corpus/native.py) | 56 = 14 recipes x 4 | Fund one contract, optionally spend a challenge connector or wait out a timelock, then attempt one spend |
| `bitvm3` | [`bitvm3.py`](../bitvm_corpus/bitvm3.py) | 40 = 10 recipes x 4 | A garbled-circuit claim graph: setup, claim, label handover, evaluation, disprove, payout ([BITVM3.md](BITVM3.md)) |
| `bitvm2` | [`bitvm2.py`](../bitvm_corpus/bitvm2.py) + [`wots.py`](../bitvm_corpus/wots.py) | 32 = 8 recipes x 4 | The BitVM2 bridge graph at BitVM/BitVM `c620dbfa`: kick-off, challenge, take 1, assert with Winternitz commitments, disprove, take 2. It is the baseline for the comparison in [BITVM3.md](BITVM3.md) |

The four combinations per recipe are `hardened` or `mutant` crossed with `benign` or
`attack`. Expected outcomes are declared in each track's `catalog()`. Outcomes are
scored only from the transactions Core confirmed; a scorer never reads the expectation.

## Run

```bash
python -m bitvm_corpus native list --track bitvm3
python -m bitvm_corpus native run --track bitvm3 --bitcoind /path/to/bitcoind --output work/bitvm3.json
python -m bitvm_corpus native audit work/bitvm3.json
```

`--match TEXT` limits a run to case ids containing TEXT. The binary defaults to
`$BITVM_ARENA_BITCOIND`, then `work/toolchains/core-31.2/bitcoind.exe`.
`tools/prepare_core.py --download` fetches Core 31.2 for Windows and extracts it only if
the archive's SHA-256 matches the pinned value from the release's `SHA256SUMS`. It does
not check the SHA256SUMS signatures.

The live test `tests/test_native.py::LiveCoreTests` runs when `BITVM_ARENA_BITCOIND` is
set.

## Report and audit

A report records, for each case, every step:

- **Transactions:** raw hex, txid, the prevouts spent, Core's `testmempoolaccept`
  result and reject reason, whether it was broadcast, and its confirmation block.
- **Off-chain actions:** garbling commitments, cut-and-choose openings, label handover,
  evaluation results.
- **Mining:** the blocks mined between steps.

The report also carries Core's version, subversion and binary SHA-256, and a hash over
the whole body.

`native audit` needs no node. It checks:

- the body hash, and that the cases match this library's catalog row for row;
- that each txid recomputes from the raw transaction, and each input spends its
  recorded prevout;
- every Taproot script-path commitment, against BIP341, locally;
- every Schnorr signature, against the key named by the CHECKSIG that consumes it,
  with the BIP341/342 signature message recomputed. Where Core accepted, every local
  check must pass. Where Core reported `Invalid Schnorr signature` or `Witness program
  hash mismatch`, the local check must fail too;
- the deterministic setup, rebuilt from the case id: compiled leaves, graph scripts,
  garbling commitments;
- the garbled evaluations, re-run from the recorded labels (BitVM3), and the
  Winternitz signatures in each assert witness, checked against the recorded claim (BitVM2);
- the outcome, rescored from the recorded steps.

Tests show that a flipped transaction byte, an altered confirmation flag, a relabeled
expectation or a dropped case is reported, even after the attacker recomputes the body
hash.

## Primitive recipes

| Recipe | Mutant | Hardened rejects the attack because |
| --- | --- | --- |
| `and_as_or` | BOOLOR in place of BOOLAND | The false conjunction leaves false on the stack |
| `nand_truth_table` | BOOLOR in place of BOOLAND NOT | The claimed output does not equal NAND(1,1) |
| `input_push_unbound` | `DROP 1` in place of a hash-bound opening | The opening yields 0 |
| `selector_unbound` | The IF selector is not compared with the opened wire | `OVER EQUALVERIFY` fails |
| `wire_equivocation` | The two openings of one wire are not compared | EQUAL fails |
| `minimalif_normalization` | `0NOTEQUAL` normalizes the selector | Tapscript MINIMALIF (consensus) |
| `csv_removed` | No CSV in the leaf; the attacker disables nSequence | CSV fails |
| `csv_disabled_sequence` | No CSV; nSequence carries the disable flag | CSV fails |
| `csv_wrong_version` | No CSV; version-1 transaction | CSV requires version 2 |
| `recipient_sighash_none` | Presigned with SIGHASH_NONE; output redirected | Invalid Schnorr signature |
| `amount_sighash_none` | Presigned with SIGHASH_NONE; amount split off | Invalid Schnorr signature |
| `connector_anyonecanpay` | Presigned ALL\|ANYONECANPAY; settlement drops the spent challenge connector | Invalid Schnorr signature |
| `control_block_tamper` | (both profiles) parity bit flipped | Witness program hash mismatch |
| `script_tamper` | (both profiles) script not committed | Witness program hash mismatch |

## Evidence in this repository

| File | Core | Result |
| --- | --- | --- |
| [`examples/native/primitive-core31.1.json`](../examples/native/primitive-core31.1.json) | 31.1.0 | 56/56 met; 42 confirmed, 16 rejected transactions |
| [`examples/native/bitvm3-core31.1.json`](../examples/native/bitvm3-core31.1.json) | 31.1.0 | 40/40 met; 76 confirmed, 19 rejected transactions |
| [`examples/native/bitvm2-core31.1.json`](../examples/native/bitvm2-core31.1.json) | 31.1.0 | 32/32 met; 106 confirmed, 27 rejected transactions |

Core 31.1 was installed from bitcoincore.org with its SHA-256 checked against
SHA256SUMS and five builder GPG signatures verified (binary SHA-256 `f79eeb94…d3db77a`).
The BitVM3 track was also run on Core 31.2 (binary `286e32ee…c95801`, archive
checksum-matched only). Every per-step verdict was identical to 31.1.

The repository's CI audits these files offline on every push. Its
`corpus-regtest` job also downloads the Core 31.1 Linux archive, checks it
against the SHA-256 pinned in the workflow (taken from the release's
`SHA256SUMS`, signatures not checked), reruns all three tracks, audits the fresh
reports, and uploads them as the `corpus-native-reports` artifact.
