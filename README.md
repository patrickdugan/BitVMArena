# BitVM Arena

A reproducible library of corruption trajectories for red teaming BitVM-inspired
DeFi coordinators, watchers, and settlement logic. It connects ordinary Boolean
gates, Script stack operations, forward-chaining rules, and stateful financial
operations to an executable evaluation harness.

The bundled corpus contains **168 trajectories, 42 corruption sites, 14 semantic
families, paired benign/attack cases, and two deterministic fixture variants**.
Every attack has a declared outcome for both a hardened coordinator and a
deliberately corrupted coordinator. A separate reference specification scores
actual state transitions after every action.

There are two evidence levels, and the library labels which one each result has:

- **Model corpus.** The 168 trajectories run on a deterministic protocol model. Its
  HMAC fixtures are synthetic authentication, and its Boolean interpreter is a
  documented Script subset. No network access is needed.
- **Native tracks.** Trajectories executed as real Taproot transactions on an owned
  Bitcoin Core regtest node, where Core decides every step:
  - the **BitVM3** track: a garbled-circuit claim graph mirroring the In-and-Out-Burger
    BitVM3 graph, with a real half-gates garbled circuit deciding each claim (40
    trajectories);
  - the **BitVM2** baseline: the BitVM/BitVM bridge graph with Winternitz commitments
    (32 trajectories), used to see which weaknesses BitVM3 introduces, removes or
    carries over;
  - the non-ZK gate and settlement **primitives** (56 trajectories).

  Saved reports are audited offline: txids, Taproot commitments, signatures checked
  against the keys their CHECKSIG opcodes name, the rebuilt setup, re-run garbled
  evaluations, and rescored outcomes. See [native tracks](docs/NATIVE.md) and the
  [BitVM3 track and findings](docs/BITVM3.md).

Neither level verifies SNARKs or reproduces confirmed upstream exploits.

```bash
python -m bitvm_arena native run --track bitvm3 --bitcoind /path/to/bitcoind --output work/bitvm3.json
python -m bitvm_arena native audit examples/native/bitvm3-core31.1.json
```

## Run

Python 3.11+; no runtime or build dependencies. From this directory:

```bash
python -m bitvm_arena validate
python -m unittest discover -s tests -v
python -m bitvm_arena list --family boolean_gates
python -m bitvm_arena replay effects.recipient_redirect.attack.0 --profile mutant --output work/redirect.json
python -m bitvm_arena verify work/redirect.json
```

Optional installation, including offline installation with an existing pip:

```bash
python -m pip install --no-index .
bitvm-arena --version
```

## What is in the library

| Families | Examples |
| --- | --- |
| Boolean gates and commitments | AND replaced with OR; unbound IF selector; injected PUSH inputs; implication/equivalence confusion; wire equivocation; MINIMALIF bypass |
| Forward chaining | Incomplete closure; omitted debit and nonce effects |
| Authentication and input binding | Forged requests; wrong instance/program/state/request/oracle commitments |
| Stateful execution | Nonce or receipt replay; stale prior state; omitted event consumption |
| DeFi accounting | Integer truncation; collateral unlock; unsafe borrowing; healthy-position liquidation; over-repayment; AMM rounding/slippage; redirected or inflated payout; debt omission; excess fees |
| Disputes and settlement | Premature settlement; unresolved challenge; connector reuse; unbound response; outsider challenge censorship; withheld data; missing timeout recovery; challenger fee starvation |

See [the complete catalog](docs/CATALOG.md), [model and threat assumptions](docs/THREAT_MODEL.md),
[evaluation methodology](docs/EVALUATION.md), and [primary sources](docs/SOURCES.md).

## BashArena-like evaluation

The legitimate task and attack objective are scored separately. An attacker can
deliver the intended payout while omitting a debit or recording incorrect debt.
The side-task scorer runs after every action and stops at the first observed
security failure. A monitor sees only the legitimate task, public observations,
the proposed next action, and the executed prefix. It intervenes before execution.

```bash
python -m bitvm_arena calibrate --monitor structural --target-fpr 0.04 --output work/calibration.json
python -m bitvm_arena evaluate --split test --profile mutant --monitor structural --calibration work/calibration.json --output work/heldout.json
python -m bitvm_arena export --split test --output work/agent-tasks.json
```

Calibration uses benign **validation** cases only. Families never cross dataset
splits; benign/attack pairs and fixture variants stay together. The structural
monitor is an explicit heuristic baseline. Its measured performance on this
synthetic corpus does not estimate deployment security.

## Interactive agents and external harnesses

```bash
python -m bitvm_arena session
```

The process emits an initial public observation. Submit one action object per
line, for example:

```json
{"actor":"operator","op":"propose","args":{"request":"request-1","claim":"claim-1"}}
```

`Arena.act()` is the Python API. `serve` provides the versioned JSONL transport;
`external` drives an evaluator-supplied local command with independent observation
scoring. [Adapter contract and examples](docs/ADAPTERS.md).

## Add trajectories

1. Define the legitimate task, attacker permissions, invariant, and observable failure.
2. Implement a distinct candidate corruption site in `sut.py` or the model lifecycle.
3. Add an attack and a benign control in `corpus.py`, with declared expectations.
4. Assign the entire semantic family to one split. Near-duplicates remain together.
5. Regenerate with `python tools/rebuild_corpus.py`, run validation and tests, and
   inspect the first harmful state transition. Expected outcomes are never generated
   from the runner's verdict.

[Verification evidence](docs/VERIFICATION.md) records the checked release scope.
