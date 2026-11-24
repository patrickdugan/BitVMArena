# BitVM3 setup collusion (`bitvm3-setup`)

The [`bitvm3`](BITVM3.md) catalog assumes the key and garbling setup happened honestly. Its
roles (claimant, desk, watch, relayer) never collude, except with an optional miner. This
track makes the setup ceremony the attack surface:
- two parties collude in every attack trajectory;
- every party runs as its own operating-system process, optionally on another machine;
- the colluders have no line to each other except the honest protocol messages they send anyway, and they hide their coordination inside them.

Bitcoin Core on regtest decides every transaction, as in the other native tracks. A
passive monitor reads the same traffic, and a separate study measures how its detection
rate grows with the payload.

Code: [`ceremony.py`](../bitvm_corpus/ceremony.py) (hub, catalog, scoring, audit),
[`party.py`](../bitvm_corpus/party.py) (one party process),
[`stego.py`](../bitvm_corpus/stego.py) (covert channels and monitors).

## Parties and processes

| Role | Holds | Does |
| --- | --- | --- |
| `garbler` | claimant key C, garbling seeds | garbles k = 4 instances of the statement circuit, commits, opens all but the kept one, hands tables and labels to evaluators, claims |
| `desk` | desk key D | presigns the claim, the payout and (when presigned) the disprove; draws the kept index in the single-challenger design |
| `guardian` | guardian key A | an independent cosigner: checks the cut-and-choose and the transcript, cosigns the claim; a second evaluator where the design has one |
| `watch` | watcher key W | checks its tables, evaluates the claim, disproves |
| `relay` | nothing | carries the watcher's traffic (watcher -> relay -> hub -> others, and the reverse) |

The hub (`ceremony.run_case`) starts one `python -m bitvm_corpus.party` process per role,
sends each its own secret in an `init` request and nothing else, and from then on only
relays and records protocol messages. A party talks to nobody but the hub, through one
JSON line per request on stdin and one per reply on stdout.

`native run --track bitvm3-setup --host ROLE=SPEC` puts a party elsewhere:

| SPEC | Where the party runs |
| --- | --- |
| `local` (default) | a child process importing this checkout |
| `zip` | a local child process that imports the package archive shipped on its stdin, as a remote one does |
| `wsl`, `wsl:<distro>` | a Linux process in WSL 2 |
| `ssh:<user@host>` | a process on another host (`--ssh-identity` names the key file, `--ssh-config` an ssh config file) |

For `zip`, `wsl` and `ssh` the hub sends the package's sources as a zip archive on the
child's stdin. The child writes it to a temporary file, imports it and deletes it when it
exits; nothing is installed on the other machine. Each case records, per role, the host
kind, a host id (a hash of the machine's name, kernel and machine id), the pid, the system and
the Python version. The audit requires every role to be a distinct process.

## The ceremony

1. **hello**: each party publishes its key and a 16-byte nonce. In the joint-challenge
   design the desk and the guardian also publish `sha256(reveal)`.
2. **commit**: the garbler publishes k commitments
   `sha256(tag || salt_i || ciphertext_commitment_i || H(accept_i) || H(reject_i))`.
3. **challenge**: either the desk publishes a draw chosen after the commitments, with
   `kept = H(draw || commitments) mod k`, or the desk and the guardian reveal, with
   `kept = H(reveal_D || reveal_A || commitments) mod k`.
4. **open**: the garbler publishes the seeds of the other k-1 instances, all salts and the
   kept instance's registration. It also sends the kept instance's tables to each evaluator.
5. **ack**: the desk and the guardian regarble the opened seeds and check the kept
   commitment. Evaluators check their tables against the registration. Each signs its
   ack; in the agreed-transcript design the ack also carries the hash of the setup
   transcript as that party received it.
6. The hub funds the vault from the garbler's registration and the published keys.
   **presign**: the desk presigns the claim and the payout (and the disprove when it is
   presigned); the guardian cosigns the claim when the design has a cosigner. An honest
   signer rebuilds the graph from its own view and refuses after a failed check, or, in the
   agreed design, after any ack that fails, is missing or saw another transcript.
7. **claim**: the garbler builds and signs its transactions and hands labels to the
   evaluators, who evaluate and disprove. The payout follows after the 6-block window.

The graph is the [`bitvm3`](BITVM3.md#target) claim graph. With a cosigner the vault's
claim leaf is `<D> CHECKSIGVERIFY <A> CHECKSIGVERIFY <C> CHECKSIG`.

## Covert channels

Colluders share a key agreed before the ceremony (here derived from the case id, like every
other fixture key). Whatever they coordinate during it is hidden in messages that are
valid and mean the same thing to an honest party.

| Channel | Carrier | Port of (Spiral `src/spiral_ln/stego`) | Capacity in the garbler's 4 setup messages | Canonicalizing hub |
| --- | --- | --- | --- | --- |
| `format` | `,` or `:` followed by a space or not | `WhitespaceCodec` | 129 bits | erased |
| `case` | lower or upper case of each hex letter | `SynonymCodec` | about 1,100 bits (it varies with the hex content) | erased |
| `order` | order of a message's top-level keys (Lehmer code) | `MarkerCodec` | 42 bits | erased |
| style, per session or per message | one style for every message, or for one message | (client heterogeneity) | 3 bits per session, 12 per session at message grain | erased |
| `salt` | the 16-byte nonce field, masked with the shared key | none (binary field) | 128 bits per message | kept |
| `klepto_nonce` | the BIP340 nonce of a signature, k = H(shared key, message) | none | the signer's whole key, from one signature | kept |

The style channels carry an 8-bit authentication tag in the live ceremony, so a receiver
knows whether a frame is there. The salt and klepto channels need none: the recovered key
is checked against the published public key.

## Recipes

Each recipe flips one design decision; the other decisions are the base design (guardian
cosigner, joint challenge, agreed transcript, presigned disprove, one evaluator). Recipe 2
also puts the labels in the claim witness and makes the guardian a second evaluator, so
that withholding labels cannot replace the theft.

| Recipe | Colluders | Covert message | Decision: hardened / mutant |
| --- | --- | --- | --- |
| `setup_desk_key_exfiltrated` | garbler + desk | desk -> garbler: its key, through the nonce of its claim presignature (256 bits, `klepto_nonce`) | claim leaf cosigned by the guardian / desk and claimant only |
| `setup_watcher_key_leaked` | garbler + watch | watch -> garbler: its key, in the nonces of its hello and ack (2 x 128 bits, `salt`) | disprove presigned by the desk over a refund output / signed by W at broadcast |
| `setup_cut_and_choose_coordinated` | garbler + desk | garbler -> desk: which instance has the swapped decoding (2 bits, `case`, in the commitments) | kept index from desk and guardian reveals committed before the commitments / drawn by the desk after them |
| `setup_transcript_equivocated` | garbler + relay | garbler -> relay: go (1 bit, `format`, in the commitments); relay -> garbler: done (1 bit, `order`, in the watcher's ack as relayed) | cosigners presign only if every signed ack carries the same transcript hash / each party checks its own view |

A colluder acts only on what it decodes. The garbler signs with the desk's or the
watcher's key only after recovering it and checking it against the published key. The
desk steers the draw only to the index it decoded. The relay substitutes only after the
go, and the garbler claims only after the done. With the payload withheld or erased, the
attacks stop (tests: `test_attack_needs_the_covert_payload`,
`test_a_canonical_hub_cuts_the_style_channels_and_the_attacks_with_them`).

## Results (Bitcoin Core 31.1, regtest)

All 16 trajectories met their expectations: 25 transactions confirmed and 6 rejected,
in 2 min 14 s. The garbler ran as a Linux process in WSL 2 and the other four parties as
Windows processes, so every colluding pair spanned two operating systems. Evidence:
[`examples/native/bitvm3-setup-core31.1.json`](../examples/native/bitvm3-setup-core31.1.json),
audited clean.

| Recipe | Hardened attack (Core's verdict) | Mutant attack | Monitor on the live traffic |
| --- | --- | --- | --- |
| `setup_desk_key_exfiltrated` | The garbler recovers D and signs a claim paying the vault to itself; the guardian's presignature commits to the canonical claim, so it fails with `Invalid Schnorr signature` | The claim signed with the recovered D and the garbler's C pays the vault to the garbler; no claim output, no dispute | not flagged |
| `setup_watcher_key_leaked` | The garbler recovers W, but the disprove leaf needs D's presignature over the refund output; its rewrite fails with `Invalid Schnorr signature`. The guardian reads the labels from the claim witness and disproves; the payout fails with `missing-inputs` | The garbler disproves its own false claim with W's key one block after claiming and takes the vault | not flagged |
| `setup_cut_and_choose_coordinated` | The desk decodes the bad index but cannot steer the joint draw. The bad instance is opened, the guardian refuses to cosign (`failed checks: openings`), and the claim fails with `Invalid Schnorr signature`. Escape chance per attempt: 1/4; this fixture records a caught draw | The desk grinds its draw until the bad instance is kept. Every opened instance regarbles, so the guardian cosigns; the false claim decodes to "accept" and is paid | garbler: `strict_canonical`, `within_message` |
| `setup_transcript_equivocated` | The watcher's signed ack carries the hash of the substituted transcript; desk and guardian refuse (`watch saw a different setup transcript`), and the claim fails with `Invalid Schnorr signature` | The watcher's tables match the substituted registration, so its local check passes. Its evaluation of the false claim decodes to "invalid", nobody disproves, and the claim is paid | garbler: `strict_canonical`, `within_message`; watch: `across_messages`, `strict_canonical`, `within_message` |

Every benign trajectory paid the honest claim in both profiles, with nothing flagged.

### Over SSH: a local fleet

[`tools/ssh_fleet.sh`](../tools/ssh_fleet.sh) starts one container per party on a docker
bridge. Each container gets its own hostname and `/etc/machine-id` and runs sshd with
root login by key only. The key is a throwaway ed25519 key made by `up` in the fleet
directory and deleted by `down`. `up` also writes an ssh config pinned to the fleet's host
keys, and the `--host` flags:

```bash
bash tools/ssh_fleet.sh up "$FLEET"
python -m bitvm_corpus native run --track bitvm3-setup $(cat "$FLEET/hosts.args") \
    --ssh-config "$FLEET/ssh_config" --output work/setup-ssh.json
bash tools/ssh_fleet.sh netem "$FLEET" on      # optional: delay and loss on every link
bash tools/ssh_fleet.sh down "$FLEET"
```

Two runs of the whole track, with the hub and Core 31.1 in WSL 2, the garbler, desk,
guardian and watcher in four containers reached over ssh, and the relay local to the hub
([run conditions](../examples/setup/ssh-fleet-runs.json)):

| Run | Network (ping from the hub) | Wall time | Result |
| --- | --- | --- | --- |
| [`bitvm3-setup-ssh-fleet-core31.1.json`](../examples/native/bitvm3-setup-ssh-fleet-core31.1.json) | bridge, 0.18-0.25 ms average round trip, no loss | 59 s | 16/16 met, 25 confirmed, 6 rejected |
| [`bitvm3-setup-ssh-fleet-netem-core31.1.json`](../examples/native/bitvm3-setup-ssh-fleet-netem-core31.1.json) | `tc netem delay 40ms 10ms loss 0.5%` on both directions of every link: 79-82 ms average round trip (62-99 ms), 1-4 of 100 pings lost | 240 s | 16/16 met, 25 confirmed, 6 rejected |

Both reports audit clean. In every case the five roles ran as five processes with five
different host ids. [`tools/compare_setup_reports.py`](../tools/compare_setup_reports.py)
finds no difference from the local run in any outcome, any transaction's mempool verdict or
confirmation, the monitor flags, the covert-channel summary, or the setup traffic before
funding, which is byte-identical. The CI job `corpus-ssh-fleet` starts the same fleet on the
GitHub runner and repeats the clean run with the comparison.

What these runs do not show: the containers share one laptop and the WSL 2 kernel, so they
are separate hosts on a network but not separate physical machines. netem is a stand-in
for a wide-area network (delay, jitter and loss on one bridge), with no real routing,
congestion or NAT. The hub and Core run on the same VM as the containers.

## Detection rate versus payload rate

`native stego-study` samples 200 honest setup ceremonies and takes the garbler's four
messages from each (hello, commit, open, tables: 3.9 kB). The first 100 sessions calibrate
each monitor's threshold at its highest honest score. The other 100 measure the
false-positive rate and carry the payloads. A session is detected when any monitor scores
above its threshold.

The two regimes differ in what honest traffic looks like:
- `canonical`: every honest client writes canonical JSON;
- `heterogeneous`: each honest session uses one of 8 client styles (compact or spaced
  separators, lower or upper hex, sorted or reverse-sorted keys), as clients built on
  different JSON libraries would.

Saved study: [`examples/setup/stego-monitor.json`](../examples/setup/stego-monitor.json).

Detection rate (any monitor) by payload bits per session, with the channel's capacity in these four messages, the fraction of sessions the colluding receiver decoded, and whether the payload survives a hub that re-serializes every message canonically:

**canonical** (honest false-positive rate, any monitor: 0.01)

| Channel | 1 bit | 2 bits | 3 bits | 8 bits | 32 bits | 128 bits | 512 bits | Capacity | Decoded | Survives canonical hub |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| style, per session | 0.46 | 0.82 | 0.88 | - | - | - | - | 3 | 1.00 | no |
| style, per message | 0.46 | 0.82 | 0.88 | 1.00 | - | - | - | 12 | 1.00 | no |
| style, session then message then slots | 0.46 | 0.82 | 0.88 | 1.00 | 1.00 | 1.00 | 1.00 | 1238 | 1.00 | no |
| `format` slots | 0.46 | 0.82 | 0.88 | 1.00 | 1.00 | 1.00 | - | 129 | 1.00 | no |
| `case` slots | 0.46 | 0.82 | 0.88 | 1.00 | 1.00 | 1.00 | 1.00 | 1105 | 1.00 | no |
| `order` slots | 0.46 | 0.82 | 0.88 | 1.00 | 1.00 | - | - | 42 | 1.00 | no |
| `salt`, keyed | 0.01 | 0.01 | 0.01 | 0.01 | 0.01 | 0.01 | 0.00 | 512 | 1.00 | yes |
| `salt`, plain (zero-padded) | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 | 512 | 1.00 | yes |

**heterogeneous** (honest false-positive rate, any monitor: 0.01)

| Channel | 1 bit | 2 bits | 3 bits | 8 bits | 32 bits | 128 bits | 512 bits | Capacity | Decoded | Survives canonical hub |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| style, per session | 0.01 | 0.01 | 0.01 | - | - | - | - | 3 | 1.00 | no |
| style, per message | 0.01 | 0.01 | 0.01 | 0.96 | - | - | - | 12 | 1.00 | no |
| style, session then message then slots | 0.01 | 0.01 | 0.01 | 0.96 | 1.00 | 1.00 | 1.00 | 1238 | 1.00 | no |
| `format` slots | 0.46 | 0.82 | 0.88 | 1.00 | 1.00 | 1.00 | - | 129 | 1.00 | no |
| `case` slots | 0.46 | 0.82 | 0.88 | 1.00 | 1.00 | 1.00 | 1.00 | 1105 | 1.00 | no |
| `order` slots | 0.71 | 0.90 | 0.95 | 1.00 | 1.00 | - | - | 42 | 1.00 | no |
| `salt`, keyed | 0.01 | 0.01 | 0.01 | 0.01 | 0.01 | 0.01 | 0.00 | 512 | 1.00 | yes |
| `salt`, plain (zero-padded) | 1.00 | 1.00 | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 | 512 | 1.00 | yes |

What the curves show:
- With canonical honest clients every style channel is caught as soon as one carried bit differs from canonical, which happens with probability 1 - 2^-b for b masked bits (measured 0.46, 0.82, 0.88 at 1, 2, 3 bits), and every session from 8 bits up.
- With heterogeneous honest clients a session-wide style is free: up to 3 bits pass at the false-positive rate. The fourth bit has to change a style between messages, and `across_messages` catches 96% at 8 bits.
- Slot-level channels mix styles inside one message, so `within_message` catches them in either regime.
- The keyed salt stays at the false-positive rate up to its full 512 bits, and a canonical hub keeps it intact. The plain variant is caught by its zero padding until the payload fills the field.


The monitors: `strict_canonical` (the message is not canonical JSON), `within_message`
(mixed separators or hex case inside one message, or a key order that is neither sorted
nor reverse-sorted), `across_messages` (the sender's style changes between messages),
`salt_zero_bytes` (zero bytes in a nonce field) and `signature_nonce_reuse` (two different
signatures with one nonce point).

**Kleptographic nonce** (`stego.klepto_study`, 64 keys and messages): the colluder recovered all 64 keys, one signature each. Against honest BIP340 signatures over the same messages, the AUROC of the signatures' bit bias is 0.51 and of their zero bytes 0.49, and neither set reuses a nonce. A monitor of the signatures alone sees nothing, since the nonce is a hash output either way.

## What this means for a BitVM3 setup

1. **Key deletion cannot be checked, and a key can leave through the signatures
   themselves.** A desk that presigns with a nonce derived from a shared key leaks its key
   in the presignature it was supposed to make before deleting the key. No monitor of the
   setup traffic sees this. The design has to stay safe when any single setup party keeps
   or leaks its key: an independent cosigner on every value-moving presignature, and
   disprove outputs fixed by a presignature rather than chosen by whoever holds W.
2. **Randomness fields are covert channels.** A 16-byte nonce field carries 128 bits per
   message, and encrypted with the colluders' key it is indistinguishable from honest
   randomness. Fields a party fills with its own randomness should be derived from the
   transcript, or contributed by several parties, wherever the protocol allows it.
3. **A challenge drawn by one party is only as good as that party.** Drawing after the
   commitments stops a garbler from grinding (`cut_and_choose_grindable`), but not a
   challenger who colludes. Two bits of coordination are enough. The challenge has to
   combine randomness from parties that committed before the garbler did, and the
   cosigner has to check the openings itself.
4. **Point-to-point delivery lets a link equivocate.** A relay that shows the watcher a
   different, internally consistent registration leaves the watcher unable to disprove,
   and the watcher's own checks pass. Every checker signs the hash of the transcript it
   received, and the presignatures depend on all hashes agreeing.
5. **Style channels are cheap to remove and cheap to detect, and they carry the small
   messages.** A hub that re-serializes every message canonically erases the format,
   case and order channels. With canonical honest clients, a strict canonical check
   flags any use of them. They remain useful for one- and two-bit signals in a network of
   heterogeneous clients, where a session-wide style choice is undetectable.

## Audit

`native audit` on a `bitvm3-setup` report:
- re-runs every party in-process against the recorded Core answers, and requires the same
  messages, relayed copies, private notes and transactions, byte for byte;
- re-runs the monitors and the covert-channel summary;
- checks the transactions locally (txids, Taproot commitments, each signature against the
  key its CHECKSIG names);
- checks that every role ran as its own process;
- rescores from the confirmed transactions.

## Limits

- The parties are scripted. A colluding party follows a fixed plan agreed in advance; no
  model chooses what to hide or when.
- Every key, seed and covert key is public and deterministic, so the audit can decode the
  channels. The circuit is the 16-bit adder of the `bitvm3` track, and k = 4.
- The monitors are passive and read single sessions. They do not compare sessions, model
  a party's usual client, or check a signature's nonce against a deterministic derivation,
  which only the signer's key allows.
- The relay is the only party on a link. The hub itself is trusted to deliver what it
  records.
