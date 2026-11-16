# Working on BitVM Arena

Use Python 3.11 or newer. The core package runs with the standard library.
Install `.[control]` for the pinned ControlArena and Inspect integration.

Before changing a campaign, read `campaigns/initial_campaigns.json` and its
linked target source. External branches can move; retain the exact commit and
binary hashes in any new execution receipt.

Preserve the evaluator's original funded target throughout an attack. Score
actual effects against that fixed policy. A different funded authority defines
a different experiment. Keep legitimate completion, unauthorized release and
diverted principal separate in reported metrics.

Tag evidence with its execution layer. Planted model faults, reference-oracle
measurements, proposed attacks and native regtest receipts have distinct
meanings. A campaign becomes executable when an adapter and checked receipt
establish that fact.

Imported files under `research/authority_enumeration/upstream` retain their
original bytes. Update imports through a new provenance manifest. Reconstructed
historical source under `research/history/native_snapshot` remains archival
until its missing dependencies and behavior are recovered and verified.

Useful checks:

```sh
python -m unittest discover -s tests -v
bitvm-arena benchmark --output /tmp/bitvm-arena-calibration
python -m unittest discover -s tests -p test_control_arena.py -v
```

The third command needs the optional SDK dependencies. The original authority
suite additionally needs `CPA_SOURCE` pointing to the pinned CPA source. The
workflow file records that replay gate.

`corpus/` is a separate package, `bitvm_corpus`, with its own tests; run its
commands from inside `corpus/`. Its native tracks start their own regtest node
from a `bitcoind` binary (`--bitcoind` or `BITVM_ARENA_BITCOIND`) and refuse
non-empty datadirs and non-regtest chains. Keep the `bitvm-arena/...` hash
domain tags in `gc.py`, `bitvm2.py` and `bitvm3.py` unchanged: they derive the
keys and garblings recorded in the saved evidence, and the offline audit
rebuilds them.

```sh
cd corpus
python -m unittest discover -s tests -v
python -m bitvm_corpus native audit examples/native/bitvm3-core31.1.json
```

Keep user-facing documentation explicit about what executed and what remains
pending. Record concrete failures and the regressions that guard their fixes.
