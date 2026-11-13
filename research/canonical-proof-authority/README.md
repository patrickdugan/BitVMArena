# Canonical Proof Authority research

BA-CPA-01 lives in this subfolder while BitVMArena is rebuilt independently.
The runnable study uses the bitcoin-rs compiler and independent Python Script
oracle at commit `24a5593350f42efc8a96047aa9e7e114fa22cb08`.

## Layout

```text
docs/             Applied mathematics and the rebuild handoff
scenarios/        Ten attack families with explicit evidence labels
fixtures/         Source lock and expected generated-file hashes
scripts/run.py    Offline source verification, tests, and reproduction
tests/            Runner integrity and scenario-scope tests
```

The only file outside this subfolder is the dedicated
`.github/workflows/cpa-gate-enumeration.yml`. Core Arena code and root package
configuration belong to the parallel rebuild. This module does not import them.

## Run

Python 3.10 or later and a local copy of the pinned bitcoin-rs files are required.
Prepare that checkout explicitly; the runner never downloads dependencies.

```sh
git clone https://github.com/patrickdugan/bitcoin-rs.git ../bitcoin-rs-cpa
git -C ../bitcoin-rs-cpa checkout --detach 24a5593350f42efc8a96047aa9e7e114fa22cb08
python3 -m unittest discover -s research/canonical-proof-authority/tests -v
python3 research/canonical-proof-authority/scripts/run.py \
  --bitcoin-rs ../bitcoin-rs-cpa --out /tmp/arena-cpa-run-01
```

Use a fresh output directory. The runner checks ten input-file SHA256 values
before importing upstream code. It copies only those verified bytes into a
temporary source tree, removes the `CPA_SOURCE` override from child environments,
and starts Python with `-I -S -B`. Each subprocess has a timeout. This protects
reproduction integrity for the pinned study; it is not a sandbox for hostile
Python. An archive containing the exact files is also accepted. Git metadata
alone is never used as proof of source integrity.

The run writes `receipt.json`, test logs, and `generated/` containing the circuit
corpus and compiled authority records. Each generated file must match its pinned
SHA256. Failed stages leave a failure receipt when execution has begun.

## Scope and evidence

The fixed study covers 1,851 canonical programs and all 16 two-input Boolean
permission functions. It compiles 32 authorities and checks 256 assignments,
with 72 accepts, 184 rejects, and zero mismatches. Eleven additional mutation
and positive-control cases have their expected results. Upstream suites contain
14 study tests and 42 CPA tests. This subfolder adds 14 runner tests.

These counts belong to offline Python execution. Native HF CHECKSIG, ZK-backed
delegation, and a rebuilt ControlArena episode adapter remain pending. The
scenario catalogue keeps those boundaries in every record. The runner does not
invoke node RPC, use wallet data, or broadcast transactions.

[Mathematics](docs/gate-space-mathematics.md) develops the fixed-target attack
objective. [The handoff](docs/rebuild-handoff.md) specifies the interface for the
other rebuild thread. The original full study stays pinned in
[bitcoin-rs](https://github.com/patrickdugan/bitcoin-rs/blob/24a5593350f42efc8a96047aa9e7e114fa22cb08/docs/research/bitvm-authority-enumeration.md).
