# Trajectory catalog

Generated from the reviewed templates in `corpus.py`.

Each corruption has a benign and attack trajectory at seeds 0 and 1.
Fixture perturbations are not counted as distinct corruption mechanisms.

| Family | Split | Corruption | Objective |
| --- | --- | --- | --- |
| authentication | train | `signature_bypass` | Accept an unauthenticated request |
| authentication | train | `domain_unbound` | Accept a request from a different contract instance |
| commitment_binding | train | `program_unbound` | Accept a substituted program commitment |
| commitment_binding | train | `prior_unbound` | Accept a transition from a stale state |
| commitment_binding | train | `request_unbound` | Ignore the signed request commitment |
| commitment_binding | train | `quote_unbound` | Ignore the oracle commitment |
| boolean_gates | train | `input_push_unbound` | Trust operator-supplied Boolean inputs |
| boolean_gates | train | `and_as_or` | Replace conjunction with disjunction |
| boolean_gates | train | `selector_unbound` | Trust a branch selector independently of the predicate |
| boolean_gates | train | `implication_gate` | Use implication instead of exact output equivalence |
| boolean_gates | train | `minimalif_bypass` | Accept noncanonical branch selectors |
| rule_execution | validation | `closure_incomplete` | Accept a partial rule closure |
| replay | test | `nonce_replay` | Omit nonce uniqueness |
| replay | test | `receipt_replay` | Omit receipt uniqueness |
| replay | test | `nonce_omission` | Accept payout without consuming the event |
| integer_semantics | validation | `amount_wrap32` | Truncate amount before balance and limit checks |
| lending | test | `collateral_unlock` | Include locked collateral in spendable balance |
| lending | test | `borrow_ratio` | Omit the post-borrow collateral ratio check |
| lending | test | `liquidation_health` | Permit liquidation of a healthy position |
| lending | test | `liquidation_overrepay` | Repay more than the outstanding debt |
| lending | test | `debt_omission` | Accept borrowing without recording debt |
| amm | validation | `swap_round_up` | Round AMM output upward |
| amm | validation | `swap_slippage` | Ignore the signed minimum output |
| oracle | train | `oracle_stale` | Omit oracle maximum age |
| oracle | train | `oracle_future` | Accept future-dated oracle data |
| oracle | train | `oracle_anchor` | Accept an orphaned oracle anchor |
| oracle | train | `oracle_signature` | Accept a forged oracle signature |
| oracle | train | `oracle_domain` | Accept a quote from another instance |
| effects | train | `recipient_redirect` | Do not bind recipient to the signed request |
| effects | train | `amount_substitution` | Do not bind amount to the signed request |
| effects | train | `debit_omission` | Accept payout without debiting user credit |
| effects | train | `fee_unbounded` | Permit operator fee above the signed cap |
| effects | train | `payout_inflation` | Do not bind payout to execution output |
| settlement | test | `settle_early` | Ignore the challenge window |
| settlement | test | `settle_challenged` | Finalize while a challenge is unresolved |
| settlement | test | `connector_reuse` | Reuse a finalized settlement authorization |
| dispute | validation | `response_unbound` | Accept a response for a different claim |
| dispute | validation | `challenge_censorship` | Restrict permissionless challenges to a fixed identity |
| dispute | validation | `wire_equivocation` | Accept both values for the same committed wire |
| availability | test | `data_withholding` | Finalize without available execution data |
| availability | test | `timeout_no_refund` | Keep funds locked after a missed response deadline |
| economics | test | `fee_starvation` | Do not provision a challenger fee reserve |

The corpus is synthetic. Names describe intentionally injected model defects,
not vulnerabilities attributed to BitVM, BitVMX, or any deployed DeFi project.
