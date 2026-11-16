# Local harness adapters

The adapter protocol connects an evaluator-owned executable to the trajectory
library. Commands are argv arrays executed with `shell=False`. Corpus rows never
contain executable commands. This transport is not a sandbox; select a trusted
adapter or provide OS isolation for untrusted implementations.

## Protocol v1

Use one UTF-8 JSON object per line. The first request is:

```json
{"protocol":1,"op":"reset","fixture":{"state":"...","requests":"...","quote":"...","height":100,"anchor":"canonical-100"}}
```

The `fixture` is the full fixture object from a corpus row, not those illustrative
strings. The response is `{"protocol":1,"observation":{...}}`.

Each subsequent request is:

```json
{"protocol":1,"op":"step","action":{"actor":"operator","op":"propose","args":{"request":"request-1","claim":"claim-1"}}}
```

Respond with `protocol`, `result`, and `observation`. Results have `accepted` plus
the operation's public return values. Errors at the transport level use an `error`
field and fail the evaluation. Missing, malformed, or substituted evidence is not
scored as a safe outcome.

Observations follow `Arena.observe()`: `height`, `anchor`, `state`, `state_root`,
`claims`, `requests`, `quote`, `wires`, `fee`, and `watcher_budget`. Requests and the
quote are immutable fixture evidence. A claim record includes its request ID,
committed claim/effects, commitment, phase, availability, maturity, response
deadline, and response commitment. Use `checked_observation()` to check this
contract. Adapter-specific transactions and scripts should be stored alongside
the normalized evidence for a protocol-specific verifier to inspect.

The evaluator sends no selected model defect, expected outcomes, side-task tests,
or attack label. It independently checks observed settlements, rule/gate effects,
responses, local wire/Script results, and liveness outcomes. It never accepts an
adapter-provided `attack_success` flag as the verdict.

## Try the bundled local model

From Python, which avoids shell-specific argument quoting:

```python
import sys
from bitvm_corpus.corpus import build_case
from bitvm_corpus.adapters import external_replay

case = build_case("recipient_redirect")
report = external_replay(
    case,
    [sys.executable, "-m", "bitvm_corpus", "serve", "--defect", "recipient_redirect"],
)
assert report["attack_success"]
assert "effect.recipient" in report["violations"]
```

CLI: `python -m bitvm_corpus external ID --argv '["python","-m","bitvm_corpus","serve"]'`.
Pass JSON quoting appropriate to your shell. The command-line profile is chosen by
the evaluator; it is not sent in the action stream or monitor view.

## Resource bounds

The default response timeout is 30 seconds, configurable up to 60. The default
request/response line bound is 1 MiB, configurable up to 4 MiB. Stderr is capped at
64 KiB. One reset and at most 256 actions are allowed. Request writes also time
out, preventing a non-reading child from hanging on a full stdin pipe. Timed-out
or oversized children are killed and reaped.

## Implementing an actual protocol adapter

1. Pin the upstream revision and identify the legitimate DeFi task and attacker
   capabilities. Map the abstract actions to that protocol's actual lifecycle;
   unsupported actions must fail explicitly.
2. Use an isolated regtest deployment or the protocol's deterministic test harness.
   Generate its real commitments, transactions, signatures, scripts, and traces.
3. Normalize resulting state to the Arena schema without inventing successful
   confirmations. Preserve actual txids, spent outpoints, raw witnesses, and logs
   as separate evidence. Record the network and upstream revision.
4. Add a consensus/backend-specific verifier. The generic normalized auditor does
   not validate txids, proof-of-work, Bitcoin signatures, or Script execution.
5. Run paired controls, prove the attack reaches the claimed invariant, and verify
   the repaired target blocks it. Report fixture assumptions and unsupported scope.

The included process tests exercise the model backend. No real upstream BitVM
transaction adapter is bundled or claimed as verified in this release.
