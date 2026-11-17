"""BitVM3 claim-graph trajectories staged on the public testnet4 network.

The trajectories are the regtest track's (`bitvm3.run_case`), unchanged. What changes is the
session underneath them:
- transactions go to an existing testnet4 node, which relays them to real peers, and real
  testnet4 miners decide what confirms;
- nothing is mined. Where a trajectory asks for blocks, the session waits for the network's
  blocks. It also waits until every transaction the case broadcast has confirmed or been
  displaced, which is what generating a block did on regtest;
- each wave uses fresh keys and a fresh garbling-seed salt. They are kept in a state
  directory outside the repository. The report publishes the public keys and the salt, so an
  auditor can rebuild every graph and re-evaluate every garbling offline;
- the amounts are small (testnet coins are scarce), and fees are paid at about 1 sat/vB so
  that testnet4's minimum-difficulty block producers include them.

Recipes that need control of a miner or an owned P2P topology stay on regtest (EXCLUDED).
Every case of a wave runs in its own thread, so a wave takes about as long as its longest
case. `rehearse` runs a wave against an owned regtest node whose "network" mines a block
every few seconds; it exercises the same code before any testnet4 coins move.
"""

from __future__ import annotations

import base64
import http.client
import itertools
import json
import secrets as entropy
import threading
import time
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

from . import bitvm3
from .bitcoin import N, NUMS, lift, sha
from .canonical import ValidationError, digest
from .core import CoreError, Regtest, safe_json
from .track import SATS, Session

TRACK = "bitvm3-testnet4"
NETWORK = "testnet4"
EVIDENCE_LEVEL = "bitcoin-core-testnet4-transactions"
EXCLUDED = {
    "disprove_censored_by_miner": "needs a colluding miner (empty blocks, then the payout mined directly)",
    "disprove_anchor_pinned": "needs a congested fee market (blocks built with a fee floor)",
    "disprove_partitioned": "needs an owned three-node network",
}
# Small amounts. Every output stays above the 330-sat P2TR dust limit after fees.
AMOUNTS = {"vault": 2_000, "bond": 1_000, "fee": 250, "watch_funds": 1_500, "child_fee": 500,
           "claim_feerate": 1_100}
FUNDING_FEERATE = 1.2       # sat/vB for the wallet's funding transactions
COIN_MARGIN = 300           # sats a funding coin carries above its outputs (the funding fee; leftover below dust goes to fee)
PATIENCE = 18               # extra network blocks a pending broadcast gets before it is given up on
POLL = 3.0                  # seconds between chain-tip polls
RPC_SLOTS = 8               # concurrent RPC calls per node
ROLES = tuple(bitvm3.SECRETS)

# The first wave: every hardened attack whose trajectory is not decided at setup, plus the
# honest paths of the distinct transaction shapes (default graph, labels on chain, a 24-block
# window, the TRUC/P2A graph, the cosigned payout).
WAVES = {
    "wave1": [f"{TRACK}.{recipe}.hardened.{variant}" for recipe, variant in (
        ("seed_reuse_across_claims", "benign"),
        ("output_polarity_swapped", "attack"),
        ("labels_offchain_withheld", "benign"),
        ("labels_offchain_withheld", "attack"),
        ("window_below_latency", "benign"),
        ("window_below_latency", "attack"),
        ("single_watcher_disprove", "attack"),
        ("disprove_watcher_redirect", "attack"),
        ("claimant_unbonded", "attack"),
        ("bond_self_slash", "attack"),
        ("disprove_unbumpable", "attack"),
        ("desk_key_retained", "attack"),
        ("reclaim_preempts_claim", "attack"),
        ("proof_replay_across_vaults", "attack"),
        ("payout_csv_removed", "attack"),
        ("claim_internal_key_spendable", "attack"),
        ("disprove_outputs_unbound", "attack"),
        ("payout_absolute_timelock", "attack"),
    )],
    # The second wave: the mutant attacks that should succeed on the public network, so the
    # flaws are shown landing against real relay and real miners, plus the wave 1 row a reorg
    # cost (reclaim_preempts_claim.hardened.attack), run again on the reorg-aware session.
    # Sized to the staging wallet's 28,489 sats after wave 1.
    "wave2": [f"{TRACK}.{recipe}.{profile}.attack" for recipe, profile in (
        ("reclaim_preempts_claim", "hardened"),
        ("reclaim_preempts_claim", "mutant"),
        ("desk_key_retained", "mutant"),
        ("disprove_watcher_redirect", "mutant"),
        ("payout_csv_removed", "mutant"),
        ("claim_internal_key_spendable", "mutant"),
        ("disprove_outputs_unbound", "mutant"),
        ("labels_offchain_withheld", "mutant"),
        ("claimant_unbonded", "mutant"),
        ("disprove_unbumpable", "mutant"),
    )],
    # The third wave: mutant attacks whose outcome turns on public-network timing or on what
    # anyone watching the mempool can do: an absolute-timelock payout and a window shorter than
    # the watcher's latency (both race the disprove on real block intervals), the SIGHASH_NONE
    # claim and payout (rewritable by any relayer), a proof replayed across two vaults, and a
    # single watcher whose disprove fails. Sized to the 18,812 sats left after wave 2.
    "wave3": [f"{TRACK}.{recipe}.mutant.attack" for recipe in (
        "payout_absolute_timelock",
        "window_below_latency",
        "claim_sighash_none",
        "payout_sighash_none",
        "proof_replay_across_vaults",
        "single_watcher_disprove",
    )],
    # The fourth wave: a griefing disprove made with reused seeds, a disprove the swapped
    # polarity refuses, the bond self-slash replacement under full RBF, and a claim on an
    # unchecked garbling. Sized to the 12,334 sats (eight coins) left after wave 3.
    "wave4": [f"{TRACK}.{recipe}.mutant.attack" for recipe in (
        "seed_reuse_across_claims",
        "output_polarity_swapped",
        "bond_self_slash",
        "garbling_unchecked",
    )],
    # The fifth wave: the last two mutant attacks (a grindable Fiat-Shamir cut-and-choose and
    # garbled tables delivered after the claim), and the hardened cut-and-choose against the
    # same grinding. Sized to the 8,059 sats (six coins) left after wave 4: three 2,300-sat
    # coins plus the split.
    "wave5": [
        f"{TRACK}.cut_and_choose_grindable.mutant.attack",
        f"{TRACK}.tables_delivered_late.mutant.attack",
        f"{TRACK}.cut_and_choose_grindable.hardened.attack",
    ],
}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def btc(sats):
    return format(Decimal(sats) / SATS, "f")


def catalog():
    """The bitvm3 rows whose trajectories need no miner or topology control, renamed."""
    rows = []
    for row in bitvm3.catalog():
        if row["recipe"] in EXCLUDED:
            continue
        rows.append({**row, "id": TRACK + row["id"][len(bitvm3.TRACK):], "track": TRACK,
                     "evidence_level": EVIDENCE_LEVEL})
    return rows


def select(names=(), wave=None):
    rows = catalog()
    by_id = {r["id"]: r for r in rows}
    wanted = list(WAVES[wave]) if wave else []
    for name in names:
        matches = [r["id"] for r in rows if name == r["id"] or name in r["id"]]
        if not matches:
            raise ValidationError(f"no {TRACK} row matches {name!r}")
        wanted += [m for m in matches if m not in wanted]
    if not wanted:
        raise ValidationError("select a wave or rows")
    return [by_id[i] for i in wanted]


# --- keys --------------------------------------------------------------------------------

def new_stage():
    secrets = {name: entropy.randbelow(N - 1) + 1 for name in ROLES}
    return bitvm3.Stage.from_secrets(secrets, salt=entropy.token_bytes(16), **AMOUNTS)


def stage_record(stage, *, private=False):
    record = {"keys": stage.public_keys(), "salt": stage.salt.hex(),
              **{name: getattr(stage, name) for name in AMOUNTS}}
    if private:
        record["secrets"] = {name: format(value, "064x") for name, value in stage.secrets.items()}
    return record


def stage_from_record(record):
    """A stage from its record: with secrets when the record has them, else public keys only."""
    keys = {}
    for name in ROLES:
        key = bytes.fromhex(record["keys"][name])
        lift(key)       # a valid x-only point
        keys[name] = key
    fields = {name: record[name] for name in AMOUNTS}
    salt = bytes.fromhex(record["salt"])
    if "secrets" in record:
        stage = bitvm3.Stage.from_secrets({n: int(record["secrets"][n], 16) for n in ROLES}, salt=salt, **fields)
        if stage.keys != keys:
            raise ValidationError("stage secrets do not match its public keys")
        return stage
    return bitvm3.Stage(keys, None, salt, **fields)


def wif(secret, testnet=True):
    payload = bytes([0xEF if testnet else 0x80]) + secret.to_bytes(32, "big") + b"\x01"
    data = payload + sha(sha(payload))[:4]
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    number, text = int.from_bytes(data, "big"), ""
    while number:
        number, rest = divmod(number, 58)
        text = alphabet[rest] + text
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + text


def stage_descriptors(stage):
    """Descriptors for the outputs a wave pays to stage keys: every role's key path, and the
    claimant's bond-reclaim leaf (NUMS internal key)."""
    descriptors = [f"tr({wif(stage.secret(name))})" for name in ROLES]
    descriptors.append(f"tr({NUMS.hex()},pk({wif(stage.secret('claimant'))}))")
    return descriptors


# --- the node ----------------------------------------------------------------------------

class StagingNode:
    """JSON-RPC client for an existing node and one of its wallets. It never mines, and it
    refuses any chain but the one it was built for (testnet4, or regtest for a rehearsal)."""

    def __init__(self, port, cookie, wallet, *, chain=NETWORK, host="127.0.0.1", timeout=60):
        if chain not in (NETWORK, "regtest"):
            raise ValidationError("a staging node is testnet4 or a regtest rehearsal")
        self.host, self.port, self.cookie = host, int(port), Path(cookie)
        self.wallet, self.chain, self.timeout = wallet, chain, timeout
        self._ids, self._lock = itertools.count(1), threading.Lock()
        # Many cases share one node: cap concurrent calls below Core's RPC work queue.
        self._slots = threading.BoundedSemaphore(RPC_SLOTS)

    def _call(self, method, params, wallet):
        credentials = self.cookie.read_text(encoding="ascii").strip()
        with self._lock:
            request_id = next(self._ids)
        body = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        for attempt in range(6):
            with self._slots:
                connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
                try:
                    connection.request("POST", f"/wallet/{self.wallet}" if wallet else "/", body,
                                       {"Authorization": "Basic " + base64.b64encode(credentials.encode()).decode(),
                                        "Content-Type": "application/json"})
                    response = connection.getresponse()
                    status, content = response.status, response.read(8_388_609)
                finally:
                    connection.close()
            if status == 503 and attempt < 5:       # work queue full: back off and resend
                time.sleep(0.5 * 2 ** attempt)
                continue
            break
        if len(content) > 8_388_608:
            raise CoreError("RPC response exceeded 8 MiB")
        try:
            result = json.loads(content, parse_float=Decimal)
        except ValueError:
            raise CoreError(f"{method}: HTTP {status} without a JSON body") from None
        if result.get("error"):
            raise CoreError(f"{method}: {result['error']}")
        if result.get("id") != request_id:
            raise CoreError("RPC response ID mismatch")
        return result["result"]

    def rpc(self, method, *params, wallet=False):
        return self._call(method, list(params), wallet)

    def rpc_named(self, method, wallet=False, **params):
        return self._call(method, params, wallet)

    def check(self, wallet=True):
        info = self.rpc("getblockchaininfo")
        if info["chain"] != self.chain:
            raise CoreError(f"refusing chain {info['chain']!r}; this run is for {self.chain}")
        if info["initialblockdownload"]:
            raise CoreError("the node is still in initial block download")
        if self.chain == NETWORK and self.rpc("getconnectioncount") < 1:
            raise CoreError("the node has no peers")
        if wallet:
            self.rpc("getwalletinfo", wallet=True)
        return self

    def address(self, output_key):
        descriptor = self.rpc("getdescriptorinfo", f"rawtr({output_key.hex()})")["descriptor"]
        return self.rpc("deriveaddresses", descriptor)[0]

    def mine(self, count=1):
        raise CoreError("a staging node does not mine; the session waits for network blocks")

    def provenance(self):
        network = self.rpc("getnetworkinfo")
        chain = self.rpc("getblockchaininfo")
        mempool = self.rpc("getmempoolinfo")
        return {"chain": chain["chain"], "version": network["version"], "subversion": network["subversion"],
                "connections": network["connections"], "tip_height": chain["blocks"],
                "tip_hash": chain["bestblockhash"], "full_rbf": mempool.get("fullrbf"),
                "min_relay_feerate_btc_kvb": safe_json(mempool["minrelaytxfee"]), "wallet": self.wallet}

    def import_stage(self, stage):
        requests = []
        for descriptor in stage_descriptors(stage):
            checked = self.rpc("getdescriptorinfo", descriptor)["checksum"]
            requests.append({"desc": f"{descriptor}#{checked}", "timestamp": "now", "label": "bitvm-arena-stage"})
        results = self.rpc("importdescriptors", requests, wallet=True)
        if not all(r.get("success") for r in results):
            raise CoreError(f"importdescriptors failed: {results}")


class Chain:
    """Polls the tip; wakes every waiting case when the best block changes.

    `version` counts tip changes. A reorg to a branch of the same height changes the tip
    without changing the height, so the poller compares block hashes, not heights."""

    def __init__(self, node, poll=POLL):
        self.node, self.poll = node, poll
        self.tip = node.rpc("getbestblockhash")
        self.version = 0
        self.cond = threading.Condition()
        self.stopped = False
        self.thread = threading.Thread(target=self._run, name="chain-poll", daemon=True)

    def start(self):
        self.thread.start()
        return self

    def _run(self):
        while not self.stopped:
            try:
                tip = self.node.rpc("getbestblockhash")
            except Exception:       # keep polling through any transient failure
                tip = None
            if tip is not None and tip != self.tip:
                with self.cond:
                    self.tip = tip
                    self.version += 1
                    self.cond.notify_all()
            time.sleep(self.poll)

    def wait_change(self, seen, timeout=60):
        """Until `version` moves past `seen` (or `timeout` seconds pass)."""
        with self.cond:
            self.cond.wait_for(lambda: self.version != seen or self.stopped, timeout)
            return self.version

    def wait_until(self, predicate, timeout):
        """Re-check `predicate` on every tip change (and once a minute) until it holds."""
        deadline = time.monotonic() + timeout
        while True:
            seen = self.version
            if predicate():
                return True
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            self.wait_change(seen, min(60, left))

    def stop(self):
        self.stopped = True
        with self.cond:
            self.cond.notify_all()


class Journal:
    """Append-only JSONL of every recorded step, so a crashed wave can still be accounted for."""

    def __init__(self, path):
        self.path, self.lock = Path(path), threading.Lock()

    def write(self, **entry):
        line = json.dumps({"at": now(), **safe_json(entry)}, sort_keys=True) + "\n"
        with self.lock, self.path.open("a", encoding="utf-8") as handle:
            handle.write(line)


class CoinPool:
    """Confirmed wallet coins, one per funding step, so concurrent cases never chain on
    each other's unconfirmed change."""

    def __init__(self, coins):
        self.coins, self.lock = sorted(coins, key=lambda c: c["amount"]), threading.Lock()

    def take(self, need):
        with self.lock:
            for index, coin in enumerate(self.coins):
                if coin["amount"] >= need:
                    return self.coins.pop(index)
        raise ValidationError(f"no funding coin of at least {need} sats is left")

    @classmethod
    def split(cls, node, chain, sizes, journal, feerate=FUNDING_FEERATE, timeout=6 * 3600):
        addresses = [node.rpc("getnewaddress", "bitvm-arena-coin", "bech32m", wallet=True) for _ in sizes]
        result = node.rpc_named("send", wallet=True, outputs=[{a: btc(s)} for a, s in zip(addresses, sizes)],
                                fee_rate=feerate)
        txid = result["txid"]
        journal.write(kind="coin split", txid=txid, sizes=list(sizes))
        raw = node.rpc("gettransaction", txid, wallet=True)["hex"]

        def settled():
            if confirmations(node, txid) >= 1:
                return True
            if not in_mempool(node, txid):
                # A reorg that lowers the tip evicts the split: the wallet set its nLockTime to
                # the tip, and in a rehearsal it can spend a coinbase that is immature again.
                # Send it again on every block until it is back, as its owner's wallet would.
                try:
                    node.rpc("sendrawtransaction", raw)
                    journal.write(kind="coin split resent", txid=txid)
                except CoreError:
                    pass
            return False

        if not chain.wait_until(settled, timeout):
            raise CoreError(f"coin split {txid} did not confirm")
        info = node.rpc("getrawtransaction", txid, True)
        coins = []
        for output in info["vout"]:
            address = output["scriptPubKey"].get("address")
            if address in addresses:
                coins.append({"txid": txid, "vout": output["n"], "amount": int(output["value"] * SATS)})
        record = {"txid": txid, "raw_transaction": info["hex"], "blockhash": info["blockhash"],
                  "coins": len(coins), "sizes": sorted(c["amount"] for c in coins)}
        return cls(coins), record


def confirmations(node, txid):
    try:
        return node.rpc("getrawtransaction", txid, True).get("confirmations", 0)
    except CoreError:
        return 0


def in_mempool(node, txid):
    try:
        node.rpc("getmempoolentry", txid)
        return True
    except CoreError:
        return False


def coin_sizes(rows, stage):
    """One coin per funding step of each row, sized to its outputs plus a margin."""
    sizes = []
    for row in rows:
        cfg = bitvm3.config(row["recipe"], row["profile"])
        need = stage.vault + (stage.bond if cfg.bond else 0)
        if row["recipe"] == "disprove_unbumpable":
            need += stage.watch_funds
        count = 2 if row["recipe"] == "proof_replay_across_vaults" and row["variant"] == "attack" else 1
        sizes += [need + COIN_MARGIN] * count
    return sizes


# --- the session -------------------------------------------------------------------------

class StagingSession(Session):
    """A Session whose blocks come from the network."""

    def __init__(self, node, chain, pool, journal, case_id, *, feerate=FUNDING_FEERATE, patience=PATIENCE):
        super().__init__(node)
        self.chain, self.pool, self.journal, self.case_id = chain, pool, journal, case_id
        self.feerate, self.patience = feerate, patience
        self.blocks_seen = {}   # txid -> every block it has been seen confirmed in, in order
        self.last_block = {}    # txid -> the block it was in at its latest check
        self.raws = {}          # txid -> serialized transaction, for rebroadcasts
        self.rebroadcasts = {}  # txid -> how many times it was sent again

    def _record(self, **step):
        step["time"] = now()
        recorded = super()._record(**step)
        if recorded.get("raw_transaction") and recorded.get("txid"):
            self.raws[recorded["txid"]] = recorded["raw_transaction"]
        self.journal.write(case=self.case_id, **{k: v for k, v in recorded.items() if k != "raw_transaction"})
        return recorded

    def _confirmations(self, txid):
        """Confirmations in the node's current best chain: 0 while the transaction waits in the
        mempool, None when it is in neither (replaced, spent around by a conflict, or dropped).

        Never cached. On testnet4 a minimum-difficulty block is routinely reorganized away by
        a real-difficulty block on a sibling branch, and the transactions in it confirm again
        later, which restarts every relative timelock that counts from them."""
        for attempt in range(2):
            try:
                info = self.node.rpc("getrawtransaction", txid, True)
            except CoreError:
                info = {}
            count = info.get("confirmations", 0)
            if count >= 1:
                seen = self.blocks_seen.setdefault(txid, [])
                if info["blockhash"] not in seen:
                    seen.append(info["blockhash"])
                self.last_block[txid] = info["blockhash"]
                return count
            if attempt == 0:
                if in_mempool(self.node, txid):
                    return 0
                # While a reorg is being applied, a transaction from a disconnected block is
                # briefly in neither the mempool nor the active chain (and txindex still
                # answers from the stale block). A block may also land between the calls.
                # Look once more before calling it gone.
                time.sleep(0.5)
        return None

    def _resend(self, txid):
        """Send a transaction that left the mempool without confirming once more, as its
        owner's software would. True when it is back in the mempool or already in a block."""
        raw = self.raws.get(txid)
        if raw is None:
            return False
        try:
            self.node.rpc("sendrawtransaction", raw)
        except CoreError as exc:
            if "already" not in str(exc):   # "txn-already-in-mempool", "...already in block chain"
                return False
        self.rebroadcasts[txid] = self.rebroadcasts.get(txid, 0) + 1
        self.journal.write(case=self.case_id, kind="rebroadcast", txid=txid, at_height=self.height())
        return True

    def _owed(self, blocks=0):
        """The confirmations each broadcast of this case has on regtest once `blocks` more
        blocks are mined. On regtest a funding transaction confirms in its own block and any
        other broadcast in the first block of the next mine(); each later block adds one."""
        owed, after = {}, blocks
        for step in reversed(self.steps):
            if step["kind"] == "blocks":
                after += step["blocks"]
            elif step["kind"] == "fund":
                owed.setdefault(step["txid"], 1 + after)
            elif step["kind"] == "tx" and step["broadcast"]:
                owed.setdefault(step["txid"], after)
        return owed

    def _check(self, owed):
        """One pass over `owed`: (the txids with fewer confirmations than they are owed,
        {txid: confirmations or None}). A transaction that is in neither the chain nor the
        mempool is sent again; if the node refuses it (an input is spent by a conflict, or it
        cannot pay its way alone) it is displaced or dropped, and is never short: nothing will
        confirm it."""
        short, snapshot = [], {}
        for txid, need in owed.items():
            have = self._confirmations(txid)
            if have is None and self._resend(txid):
                have = 0
            snapshot[txid] = have
            if have is not None and have < need:
                short.append(txid)
        return short, snapshot

    def _wait(self, target, owed):
        """Until the tip reaches `target` and every transaction in `owed` has at least its owed
        confirmations in the current best chain (or has been displaced). Confirmations are read
        again on every tip change, so a reorg that moves a transaction to a later block extends
        the wait. Returns (the txids still short after `patience` more blocks, the snapshot the
        decision was made on). Callers use the snapshot rather than asking again: the next
        reorg can land between two calls."""
        while True:
            seen = self.chain.version
            tip = self.height()
            short, snapshot = self._check(owed)
            if tip >= target and not short:
                return [], snapshot
            if tip >= target + self.patience:
                return short, snapshot
            self.chain.wait_change(seen, 60)

    def fund(self, outputs, label="fund"):
        payments, wanted = [], {}
        for name, (tree, sats) in outputs.items():
            address = self.node.address(tree.output_key)
            if any(address in p for p in payments):
                raise ValidationError("duplicate funding address in one case")
            payments.append({address: btc(sats)})
            wanted[name] = (tree.script_pubkey, sats)
        coin = self.pool.take(sum(s for _, s in wanted.values()) + COIN_MARGIN // 2)
        result = self.node.rpc_named("send", wallet=True, outputs=payments, fee_rate=self.feerate,
                                     options={"inputs": [{"txid": coin["txid"], "vout": coin["vout"]}],
                                              "add_inputs": False})
        txid = result["txid"]
        self.raws[txid] = self.node.rpc("gettransaction", txid, wallet=True)["hex"]
        stalled, snapshot = self._wait(self.height() + 1, {txid: 1})
        if stalled or not snapshot[txid]:
            raise CoreError(f"{label} {txid} did not confirm")
        blockhash = self.last_block[txid]
        funding = self.node.rpc("getrawtransaction", txid, True, blockhash)
        utxos = {}
        for name, (spk, sats) in wanted.items():
            output = next(v for v in funding["vout"] if v["scriptPubKey"]["hex"] == spk.hex())
            utxos[name] = {"txid": txid, "vout": output["n"], "amount": sats, "script_pubkey": spk.hex()}
        extra = {"rebroadcasts": self.rebroadcasts[txid]} if self.rebroadcasts.get(txid) else {}
        self._record(kind="fund", label=label, actor="evaluator", txid=txid, raw_transaction=funding["hex"],
                     outputs=utxos, coin=coin, blockhash=blockhash, **extra)
        return utxos

    def mine(self, count, note=None):
        """The network's equivalent of regtest's mine(count): at least `count` more blocks, and
        every broadcast of this case as deep as regtest would have it."""
        start, began = self.height(), time.monotonic()
        stalled, _ = self._wait(start + count, self._owed(count))
        self._record(kind="blocks", label=f"{count} network block{'s' if count != 1 else ''}", actor="network",
                     blocks=count, from_height=start, seconds=round(time.monotonic() - began),
                     stalled=stalled, note=note)

    def mine_congested(self, *_args, **_kwargs):
        raise ValidationError("a congested fee market cannot be staged on a public network")

    def mine_empty(self, *_args, **_kwargs):
        raise ValidationError("empty blocks cannot be staged on a public network")

    def submit_in_block(self, *_args, **_kwargs):
        raise ValidationError("mining a transaction directly cannot be staged on a public network")

    def finish(self):
        """Wait for this case's broadcasts, then attach what the network did with each one.
        Nothing is mined; a transaction still unconfirmed at the end is recorded as such. A
        transaction that was seen in blocks a reorg later removed lists them in
        `reorged_out_of`."""
        _, snapshot = self._wait(self.height(), {t: max(n, 1) for t, n in self._owed().items()})
        for step in self.steps:
            if step["kind"] != "tx":
                continue
            step["confirmed"] = False
            if not step["broadcast"]:
                continue
            have = snapshot[step["txid"]]
            if have is None:
                # Displaced: an input is spent by something else. Dropped: the inputs are
                # unspent but no mempool holds the transaction any more.
                spent = any(self.node.rpc("gettxout", p["txid"], p["vout"]) is None for p in step["prevouts"])
                step["displaced" if spent else "dropped"] = True
            elif have == 0:
                step["unconfirmed"] = True
            else:
                # The block it was in when the wait was satisfied; a later reorg is the chain
                # audit's to report (verify_chain).
                blockhash = self.last_block[step["txid"]]
                info = self.node.rpc("getrawtransaction", step["txid"], True, blockhash)
                if info["hex"] != step["raw_transaction"]:
                    raise CoreError("the confirmed transaction differs from the submitted one")
                header = self.node.rpc("getblockheader", blockhash)
                step.update(confirmed=True, blockhash=blockhash, block_height=header["height"],
                            block_time=header["time"])
            stale = [b for b in self.blocks_seen.get(step["txid"], []) if b != step.get("blockhash")]
            if stale:
                step["reorged_out_of"] = stale
            if self.rebroadcasts.get(step["txid"]):
                step["rebroadcasts"] = self.rebroadcasts[step["txid"]]
        return self.steps


# --- waves -------------------------------------------------------------------------------

def run_wave(node, rows, stage, state, *, wave, feerate=FUNDING_FEERATE, patience=PATIENCE, poll=POLL,
             rehearsal=None):
    """Run `rows` concurrently on `node`. `state` is a directory outside the repository.
    `rehearsal` is a callable returning the rehearsal network's settings for the report."""
    state = Path(state)
    (state / "cases").mkdir(parents=True, exist_ok=True)
    journal = Journal(state / "events.jsonl")
    started, start_prov = now(), node.provenance()
    journal.write(kind="wave start", wave=wave, rows=[r["id"] for r in rows], provenance=start_prov)
    node.import_stage(stage)
    chain = Chain(node, poll).start()
    results = {}
    try:
        pool, split = CoinPool.split(node, chain, coin_sizes(rows, stage), journal, feerate)

        def work(row):
            session = StagingSession(node, chain, pool, journal, row["id"], feerate=feerate, patience=patience)
            try:
                _, steps = bitvm3.run_case(session, row, stage)
                outcome = bitvm3.score(row, steps, stage)
                case = {**row, "keys": stage.public_keys(), "steps": steps, "outcome": outcome,
                        "expectation_met": outcome == row["expected"]}
            except Exception as exc:    # one failing case must not take the wave down
                case = {**row, "keys": stage.public_keys(), "steps": session.steps, "outcome": None,
                        "expectation_met": False, "error": f"{type(exc).__name__}: {exc}"}
            (state / "cases" / f"{row['id']}.json").write_text(json.dumps(case, indent=1, sort_keys=True),
                                                             encoding="utf-8")
            journal.write(kind="case end", case=row["id"], outcome=case["outcome"], error=case.get("error"))
            results[row["id"]] = case

        threads = [threading.Thread(target=work, args=(row,), name=row["id"]) for row in rows]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        chain.stop()
    cases = [results[r["id"]] for r in rows]
    report = finalize(wave, start_prov, node.provenance(), started, now(), stage, split, cases, patience,
                      rehearsal() if rehearsal else None)
    journal.write(kind="wave end", wave=wave, summary=report["summary"])
    return report


def finalize(wave, start_prov, end_prov, started, ended, stage, split, cases, patience, rehearsal=None):
    tx_steps = [s for c in cases for s in c["steps"] if s["kind"] == "tx"]
    provenance = {"start": start_prov, "end": end_prov, "started": started, "ended": ended,
                  "patience_blocks": patience}
    if rehearsal is not None:
        provenance["rehearsal_network"] = rehearsal
    report = {"schema_version": 1, "track": TRACK, "network": start_prov["chain"], "wave": wave,
              "evidence_level": EVIDENCE_LEVEL if start_prov["chain"] == NETWORK else "staging-rehearsal-regtest",
              "provenance": provenance,
              "stage": stage_record(stage), "funding": split, "catalog_hash": digest(catalog()),
              "rows": [c["id"] for c in cases], "cases": cases,
              "summary": {"cases": len(cases),
                          "confirmed_transactions": sum(1 for s in tx_steps if s.get("confirmed")),
                          "rejected_transactions": sum(1 for s in tx_steps if not s["allowed"]),
                          "displaced_transactions": sum(1 for s in tx_steps if s.get("displaced")),
                          "unconfirmed_transactions": sum(1 for s in tx_steps if s.get("unconfirmed")),
                          "dropped_transactions": sum(1 for s in tx_steps if s.get("dropped")),
                          "reorged_transactions": sum(1 for s in tx_steps if s.get("reorged_out_of")),
                          "rebroadcast_transactions": sum(1 for s in tx_steps if s.get("rebroadcasts")),
                          "errors": [c["id"] for c in cases if c.get("error")],
                          "expectation_failures": [c["id"] for c in cases if not c["expectation_met"]]}}
    report["evidence_hash"] = digest(report)
    return report


# --- rehearsal ---------------------------------------------------------------------------

class NetworkMiner:
    """The rehearsal's network: a block every `interval` seconds with whatever is in the mempool.

    With `reorg_every=k`, every k-th tick is a reorg of the shape testnet4 showed in wave 1
    (a real-difficulty block replacing minimum-difficulty blocks): the tip is invalidated, so
    its transactions return to the mempool, and two empty blocks replace it. Those
    transactions then confirm two blocks later than they first did.

    k must be 0 or at least 3. With k=2 the block every reorg invalidates is the only block
    since the last reorg that carried transactions, so no transaction is ever confirmed
    twice and a run stalls; k=1 never mines a transaction at all. That is a censoring miner,
    which the regtest track models directly (`disprove_censored_by_miner`)."""

    def __init__(self, node, address, interval, reorg_every=0):
        self.check_reorg_every(reorg_every)
        self.node, self.address, self.interval, self.reorg_every = node, address, interval, reorg_every
        self.ticks = self.reorgs = 0
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._run, name="network-miner", daemon=True)

    def _run(self):
        while not self.stopped.wait(self.interval):
            self.ticks += 1
            try:
                if self.reorg_every and self.ticks % self.reorg_every == 0:
                    self.node.rpc("invalidateblock", self.node.rpc("getbestblockhash"))
                    for _ in range(2):
                        self.node.rpc("generateblock", self.address, [])
                    self.reorgs += 1
                else:
                    self.node.rpc("generatetoaddress", 1, self.address)
            except Exception:       # keep mining through any transient failure
                pass

    @staticmethod
    def check_reorg_every(reorg_every):
        if reorg_every != 0 and reorg_every < 3:
            raise ValidationError(f"--reorg-every {reorg_every}: use 0 (no reorgs) or at least 3; with 1 or 2 "
                                  "every block that carries transactions is reorganized away and nothing confirms")

    def settings(self):
        return {"interval_seconds": self.interval, "reorg_every": self.reorg_every, "reorgs": self.reorgs}

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stopped.set()
        self.thread.join(timeout=30)


def rehearse(binary, directory, rows, *, wave="rehearsal", interval=1.5, reorg_every=0, stage=None,
             patience=PATIENCE):
    """Run a wave against an owned regtest node that mines on a timer, as testnet4 would, and
    with `reorg_every` also reorganizes it the way testnet4 does."""
    NetworkMiner.check_reorg_every(reorg_every)
    directory = Path(directory)
    with Regtest(binary, directory / "node", timeout=60) as owned:
        owned.initialize_wallet()
        node = StagingNode(owned.port, owned.cookie, "arena", chain="regtest").check()
        with NetworkMiner(node, owned.miner, interval, reorg_every) as miner:
            return run_wave(node, rows, stage or new_stage(), directory / "state", wave=wave,
                            patience=patience, poll=0.25, rehearsal=miner.settings)


# --- audit -------------------------------------------------------------------------------

def audit(report):
    """Offline audit of a staging report: envelope, keys, rebuilt graphs, signatures, scores."""
    problems = []
    body = {k: v for k, v in report.items() if k != "evidence_hash"}
    if digest(body) != report.get("evidence_hash"):
        problems.append("evidence_hash does not match the report body")
    if report.get("track") != TRACK:
        problems.append("wrong track")
    rows = catalog()
    if report.get("catalog_hash") != digest(rows):
        problems.append("catalog_hash does not match this library's catalog")
    by_id = {r["id"]: r for r in rows}
    cases = report.get("cases", [])
    if report.get("rows") != [c.get("id") for c in cases]:
        problems.append("rows do not list the cases in order")
    try:
        stage = stage_from_record(report["stage"])
    except (KeyError, ValueError, ValidationError) as exc:
        return problems + [f"stage record is invalid: {exc}"]
    if stage.secrets is not None:
        problems.append("the report carries stage secrets")
    for case in cases:
        row = by_id.get(case.get("id"))
        if row is None:
            problems.append(f"{case.get('id')}: not in catalog")
            continue
        for key, value in row.items():
            if case.get(key) != value:
                problems.append(f"{row['id']}: field {key} differs from the catalog")
        if case.get("keys") != stage.public_keys():
            problems.append(f"{row['id']}: party keys differ from the stage keys")
        if case.get("error"):
            problems.append(f"{row['id']}: the case ended with an error: {case['error']}")
        if case.get("expectation_met") != (case.get("outcome") == row["expected"]):
            problems.append(f"{row['id']}: expectation_met is inconsistent")
        for s in case.get("steps", []):
            if s["kind"] == "tx" and s.get("confirmed") and not (s.get("blockhash") and s.get("block_height")):
                problems.append(f"{row['id']}: {s['label']} is confirmed without a block")
    problems += bitvm3.audit_cases([c for c in cases if not c.get("error")], rows, stage, cltv_slack=2)
    summary = report.get("summary", {})
    if summary.get("expectation_failures") != [c["id"] for c in cases if not c.get("expectation_met")]:
        problems.append("summary expectation_failures inconsistent")
    return problems


def _chain_records(report):
    """The transactions a report puts on chain, as (owner, label, record, recorded as confirmed):
    the split, each vault funding and each broadcast step."""
    if report.get("funding"):
        yield "funding", "split", report["funding"], True
    for case in report.get("cases", []):
        for s in case["steps"]:
            if s["kind"] == "fund":
                yield case["id"], s["label"], s, True
            elif s["kind"] == "tx" and s.get("broadcast"):
                yield case["id"], s["label"], s, bool(s.get("confirmed"))


def verify_chain(report, node):
    """Re-check the split, every vault funding and every confirmed transaction against a
    testnet4 node's current best chain."""
    problems, notes = [], []
    for owner, label, s, recorded in _chain_records(report):
        try:
            info = node.rpc("getrawtransaction", s["txid"], True)
        except CoreError:
            info = None
        confirmed = bool(info and info.get("confirmations", 0) >= 1)
        if recorded:
            if not confirmed:
                problems.append(f"{owner}: {label} {s['txid']} is not in the best chain")
            elif info["hex"] != s["raw_transaction"]:
                problems.append(f"{owner}: {label} differs from the chain's transaction")
            elif info["blockhash"] != s["blockhash"]:
                notes.append(f"{owner}: {label} was reorganized into block {info['blockhash']}")
        elif confirmed:
            notes.append(f"{owner}: {label} confirmed after its case ended")
    return problems, notes
