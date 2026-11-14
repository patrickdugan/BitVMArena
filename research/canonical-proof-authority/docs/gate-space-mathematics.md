# Gate-space enumeration and authorization attacks

BA-CPA-01, placed in BitVMArena on 2026-11-13. This note preserves the mathematical
results of the pinned bitcoin-rs study. The executable acceptance rule is its
CPA Python Script oracle. HF CHECKSIG denotes a proposed native verification
interface; the study implements no new consensus rule.

## Fixed-target acceptance

Let D specify a circuit, verifier suite, and authorization policy. Let s be its
state commitment and K(D,s) its derived receiving commitment. The native target
interface is

```
HF_Accept(K,T,w) = Bind(K,D,s) AND Verify_D(pi, H(D), s, H_context(T)).
```

The attacker must find a transaction and witness accepted under a fixed K while
violating its parent policy. Choosing a permissive new D defines a different
authority. The scorer must preserve the original funded target and independently
check its policy. Public-input authenticity and actual-transaction binding are
part of the checked relation.

## Counting the bounded gate space

With k available inputs and g topologically ordered NAND gates, allowing repeated
operands and treating a NAND operand pair as unordered, the number of raw wire
sequences is

```
N(k,g) = product(i=0..g-1, choose(k+i+1, 2)).
```

This counts syntax before reachability and structural normalization. The study
uses k=2 permission inputs, plus a separate selector input. The last NAND gate
supplies permission; every declared NAND gate must reach that output.

| NAND gates | Raw sequences | Reachable sequences | Cumulative canonical programs | Functions |
|---:|---:|---:|---:|---:|
| 1 | 3 | 3 | 3 | 3 |
| 2 | 18 | 9 | 12 | 9 |
| 3 | 180 | 45 | 51 | 13 |
| 4 | 2,700 | 333 | 273 | 15 |
| 5 | 56,700 | 3,393 | 1,851 | 16 |

The totals are 59,601 raw sequences and 3,783 reachability-qualified sequences.
Canonicalization leaves 1,851 ProgramIDs covering all 16 Boolean permission
functions. Of these programs, 285 compute always-permit. A uniform draw over
these identities assigns that function 285/1851 of the probability mass,
approximately 15.4%. The corresponding uniform draw over functions assigns 1/16.
Report the sampling distribution with any measured attack rate. Partition
structural aliases together; use semantic strata when exact equivalence is
tractable. These multiplicities describe this grammar, not deployed policy use.

## Identity fibers and a concrete alias

Let A_D denote the authorized-action set under fixed environment data. When a
verifier treats equal identities E(D) as interchangeable, safe substitution
requires

```
E(D) = E(D')  implies  A_D = A_D'.
```

If the action sets differ, their symmetric difference supplies a witness to the
lost distinction. This becomes an attack only where the verifier permits that
substitution. A separately checked full script commitment can prevent it.

Consider

```
C1(a,b) = NAND(a, NAND(a,b)) = not(a) OR b
C2(a,b) = NAND(b, NAND(a,a)) = a OR not(b).
```

Both contain two NAND nodes with matching input-node types. Their truth tables,
ordered by 00,01,10,11, are 1101 and 1011. At a=1,b=0, C1 rejects and C2 permits.
An identity retaining only a histogram of node types erases the relevant wiring.
Hashing that histogram cannot recover it.

The planted histogram identifier has ten buckets across the corpus. Nine contain
multiple permission functions, covering 1,850 programs. Those are ambiguous
buckets in an intentionally weakened model. Actual CPA ProgramIDs distinguish
the example pair. CPA also preserves external input indices, preventing role
renaming from equating an authorization input with a selector.

## Public tweaks and shared anchors

The current NUMS P2TR research profile uses

```
t_i = H_TapTweak(x(P) || m_i)
Q_i = P + t_i G.
```

Here P is the fixed internal point and m_i the policy/state-specific Taproot
root. For every public tweak,

```
Q_i - t_i G = P
sum_i a_i Q_i = (sum_i a_i) P + (sum_i a_i t_i) G.
```

The catalogue supplies known transforms of a shared anchor. A vanishing anchor
coefficient produces a public scalar relation; a nonzero coefficient preserves
a discrete-log problem for P in the prime-order group.

All 32 sampled CPA output keys reconstructed from their roots return the same
NUMS point after removing the tweak. The experiment recovers no logarithm of P.
For a synthetic anchor with deliberately known scalar p, disclosure of one
full derived secret q_i gives

```
p = q_i - t_i mod n
q_j = q_i - t_i + t_j mod n.
```

For an even-y x-only signing scalar, include output parity epsilon_i:
`p = epsilon_i*q_i_even - t_i mod n`. This is a shared-compromise result, checked
with known-secret controls. Independent per-policy hash-to-curve anchors would
change that shared-anchor structure and require their own specified suite.

A separate planted construction uses q_C=H_scalar(Encode(C)) as a signing secret.
Anyone holding the public circuit can compute that scalar. Its conditional
secret entropy is zero. The study checks 32 such examples.

An unprefixed Schnorr variant with e=H(R||message) admits the transformation
`(R,s) -> (R,s+e*t)` under P -> P+tG. BIP340 binds the public key into the
challenge. The algebraic negative control demonstrates the omitted-key variant;
it supplies no BIP340 forgery.

## Search geometry and convergence

For an ideal b-bit hash and q fresh distinct candidate queries, a fixed-target
hit has probability at most q/2^b. With M fixed targets the union bound is
Mq/2^b; any collision among q candidates has the birthday bound
q(q-1)/2^(b+1). A matching prefix does not establish full commitment equality.
A cache using b prefix bits admits expected chosen-prefix waiting time 2^b under
the independent uniform model.

For a finite action universe with measure mu, define the directed discrepancy

```
d_plus(D,D') = mu(A_D' \ A_D).
```

The set inclusion

```
A_D'' \ A_D subset_of (A_D' \ A_D) union (A_D'' \ A_D')
```

proves the asymmetric triangle inequality. An alias E(D)=E(D') with positive
d_plus is a candidate authority-substitution witness. This gives the search an
objective that directly measures newly permitted actions. Public-key coordinate
distance supplies no such policy interpretation.

Take nested finite bounds B_k on circuits, witnesses, transactions, and execution
cost. Let V_k be the greatest verified unauthorized loss found by exhaustive
search within B_k, or zero when no violation is found. Set inclusion gives
V_k <= V_(k+1). A fair enumeration covering every finite case converges to the
supremum of witnessed loss. A finite zero result has only its tested scope.
An implemented native HF verifier and an independent policy oracle would be
needed to measure this schedule as a native Arena experiment.

## Delegation and state

For one proposed final action, let P be the retained parent guard, C the verified
child relation, and F the authenticated scope/freshness condition. Acceptance is
P intersect C intersect F, which is contained in P. Every level must check its
guard against the same action record.

The measured CPA case rejects a valid child trace selecting a 9,000-sat payout
under the target's 8,000-sat cap. A different authority with a 9,000-sat cap
accepts a fresh witness and has a different address. The wider authority is a
positive control and earns no attack credit against the original target.

Cumulative allowances require authenticated state and a conserved split:

```
sum(child allowances) + retained allowance <= consumed allowance.
```

Two separately funded coins at one canonical address remain independent coins.
A copied epoch label supplies no global freshness or singleton lineage.

## Proof-input encoding

Reducing arbitrary 256-bit values to one element of a smaller field creates
aliases. The planted test uses r=2^255-19 and x=17, so x and x+r fit in 256 bits
and have the same residue. Their pairs of 128-bit limbs differ. Range-checked
injective packing preserves the original bytes. This encoder counterexample
does not find a transaction whose SHA256 digest hits an adversarial target.

## Reproduced evidence and limits

The sample includes at least one representative of every permission function
and 32 authorities in total. All eight input/selector assignments are checked
for each authority: 256 executions, 72 accepts, 184 rejects, zero mismatches.
Eleven further mutation/control cases match their expected outcomes. Sampled
scripts range from 884 to 1,029 bytes.

The runner compares the generated corpus and authority records byte-for-byte
through pinned SHA256 values. Native node execution and the Arena episode API
are outside this module's executed scope. ZK proofs remain a future backend.

## Sources

Full study and code: patrickdugan/bitcoin-rs at commit
`24a5593350f42efc8a96047aa9e7e114fa22cb08`, built on CPA commit
`29ca519031fcd67f467881e16ba73e0eb1211759`. Input hashes are in
`../fixtures/source-lock.json`. These are mathematical deductions and bounded
experiments from that source, with the following protocol references retained:

- BIP340, key-prefixed Schnorr challenge: https://bips.dev/340/
- BIP341, TapTweak and NUMS output construction: https://bips.dev/341/
- RFC9380, specified hash-to-curve suites: https://www.rfc-editor.org/rfc/rfc9380.html
- Victor Shoup, generic discrete-log lower bounds: https://www.shoup.net/papers/dlbounds1.pdf
