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
    """Polls the tip; wakes every waiting case when a block arrives."""

    def __init__(self, node, poll=POLL):
        self.node, self.poll = node, poll
        self.height = node.rpc("getblockcount")
        self.cond = threading.Condition()
        self.stopped = False
        self.thread = threading.Thread(target=self._run, name="chain-poll", daemon=True)

    def start(self):
        self.thread.start()
        return self

    def _run(self):
        while not self.stopped:
            try:
                height = self.node.rpc("getblockcount")
            except Exception:       # keep polling through any transient failure
                height = None
            if height is not None and height != self.height:
                with self.cond:
                    self.height = height
                    self.cond.notify_all()
            time.sleep(self.poll)

    def wait_change(self, seen, timeout=60):
        with self.cond:
            self.cond.wait_for(lambda: self.height != seen or self.stopped, timeout)
            return self.height

    def wait_until(self, predicate, timeout):
        """Re-check `predicate` on every new block (and once a minute) until it holds."""
        deadline = time.monotonic() + timeout
        while True:
            if predicate():
                return True
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            self.wait_change(self.height, min(60, left))

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
        if not chain.wait_until(lambda: confirmations(node, txid) >= 1, timeout):
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
        self.settled = {}       # txid -> "confirmed" | "displaced"

    def _record(self, **step):
        step["time"] = now()
        recorded = super()._record(**step)
        self.journal.write(case=self.case_id, **{k: v for k, v in recorded.items() if k != "raw_transaction"})
        return recorded

    def _state(self, txid):
        if txid in self.settled:
            return self.settled[txid]
        if confirmations(self.node, txid) >= 1:
            self.settled[txid] = "confirmed"
        elif not in_mempool(self.node, txid):
            # A block may have confirmed it between the two calls; ask again before calling it
            # displaced (replaced, or spent around by a conflict).
            self.settled[txid] = "confirmed" if confirmations(self.node, txid) >= 1 else "displaced"
        return self.settled.get(txid, "pending")

    def _pending(self, extra=()):
        txids = [s["txid"] for s in self.steps if s["kind"] == "tx" and s["broadcast"]] + list(extra)
        return [t for t in dict.fromkeys(txids) if self._state(t) == "pending"]

    def _wait(self, target, extra=()):
        """Until the tip reaches `target` and every broadcast of this case has confirmed or been
        displaced. Returns the txids still pending after `patience` more blocks."""
        while True:
            tip = self.height()
            pending = self._pending(extra)
            if tip >= target and not pending:
                return []
            if tip >= target + self.patience:
                return pending
            self.chain.wait_change(tip, 60)

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
        stalled = self._wait(self.height() + 1, extra=[txid])
        if stalled:
            raise CoreError(f"{label} {txid} did not confirm")
        funding = self.node.rpc("getrawtransaction", txid, True)
        utxos = {}
        for name, (spk, sats) in wanted.items():
            output = next(v for v in funding["vout"] if v["scriptPubKey"]["hex"] == spk.hex())
            utxos[name] = {"txid": txid, "vout": output["n"], "amount": sats, "script_pubkey": spk.hex()}
        self._record(kind="fund", label=label, actor="evaluator", txid=txid, raw_transaction=funding["hex"],
                     outputs=utxos, coin=coin, blockhash=funding["blockhash"])
        return utxos

    def mine(self, count, note=None):
        start, began = self.height(), time.monotonic()
        stalled = self._wait(start + count)
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
        Nothing is mined; a transaction still unconfirmed at the end is recorded as such."""
        self._wait(self.height())
        for step in self.steps:
            if step["kind"] != "tx":
                continue
            step["confirmed"] = False
            if not step["broadcast"]:
                continue
            state = self._state(step["txid"])
            if state == "displaced":
                # Displaced: an input is spent by something else. Dropped: the inputs are
                # unspent but no mempool holds the transaction any more.
                spent = any(self.node.rpc("gettxout", p["txid"], p["vout"]) is None for p in step["prevouts"])
                step["displaced" if spent else "dropped"] = True
                continue
            if state == "pending":
                step["unconfirmed"] = True
                continue
            info = self.node.rpc("getrawtransaction", step["txid"], True)
            if info["hex"] != step["raw_transaction"]:
                raise CoreError("the confirmed transaction differs from the submitted one")
            header = self.node.rpc("getblockheader", info["blockhash"])
            step.update(confirmed=True, blockhash=info["blockhash"], block_height=header["height"],
                        block_time=header["time"])
        return self.steps


# --- waves -------------------------------------------------------------------------------

def run_wave(node, rows, stage, state, *, wave, feerate=FUNDING_FEERATE, patience=PATIENCE, poll=POLL):
    """Run `rows` concurrently on `node`. `state` is a directory outside the repository."""
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
    report = finalize(wave, start_prov, node.provenance(), started, now(), stage, split, cases, patience)
    journal.write(kind="wave end", wave=wave, summary=report["summary"])
    return report


def finalize(wave, start_prov, end_prov, started, ended, stage, split, cases, patience):
    tx_steps = [s for c in cases for s in c["steps"] if s["kind"] == "tx"]
    report = {"schema_version": 1, "track": TRACK, "network": start_prov["chain"], "wave": wave,
              "evidence_level": EVIDENCE_LEVEL if start_prov["chain"] == NETWORK else "staging-rehearsal-regtest",
              "provenance": {"start": start_prov, "end": end_prov, "started": started, "ended": ended,
                             "patience_blocks": patience},
              "stage": stage_record(stage), "funding": split, "catalog_hash": digest(catalog()),
              "rows": [c["id"] for c in cases], "cases": cases,
              "summary": {"cases": len(cases),
                          "confirmed_transactions": sum(1 for s in tx_steps if s.get("confirmed")),
                          "rejected_transactions": sum(1 for s in tx_steps if not s["allowed"]),
                          "displaced_transactions": sum(1 for s in tx_steps if s.get("displaced")),
                          "unconfirmed_transactions": sum(1 for s in tx_steps if s.get("unconfirmed")),
                          "dropped_transactions": sum(1 for s in tx_steps if s.get("dropped")),
                          "errors": [c["id"] for c in cases if c.get("error")],
                          "expectation_failures": [c["id"] for c in cases if not c["expectation_met"]]}}
    report["evidence_hash"] = digest(report)
    return report


# --- rehearsal ---------------------------------------------------------------------------

class NetworkMiner:
    """The rehearsal's network: a block every `interval` seconds with whatever is in the mempool."""

    def __init__(self, node, address, interval):
        self.node, self.address, self.interval = node, address, interval
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self._run, name="network-miner", daemon=True)

    def _run(self):
        while not self.stopped.wait(self.interval):
            try:
                self.node.rpc("generatetoaddress", 1, self.address)
            except Exception:       # keep mining through any transient failure
                pass

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.stopped.set()
        self.thread.join(timeout=30)


def rehearse(binary, directory, rows, *, wave="rehearsal", interval=1.5, stage=None, patience=PATIENCE):
    """Run a wave against an owned regtest node that mines on a timer, as testnet4 would."""
    directory = Path(directory)
    with Regtest(binary, directory / "node") as owned:
        owned.initialize_wallet()
        node = StagingNode(owned.port, owned.cookie, "arena", chain="regtest").check()
        with NetworkMiner(node, owned.miner, interval):
            return run_wave(node, rows, stage or new_stage(), directory / "state", wave=wave,
                            patience=patience, poll=0.25)


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


def verify_chain(report, node):
    """Re-check every confirmed transaction against a testnet4 node's current best chain."""
    problems, notes = [], []
    for case in report.get("cases", []):
        for s in case["steps"]:
            if s["kind"] != "tx" or not s.get("broadcast"):
                continue
            try:
                info = node.rpc("getrawtransaction", s["txid"], True)
            except CoreError:
                info = None
            confirmed = bool(info and info.get("confirmations", 0) >= 1)
            if s.get("confirmed"):
                if not confirmed:
                    problems.append(f"{case['id']}: {s['label']} {s['txid']} is not in the best chain")
                elif info["hex"] != s["raw_transaction"]:
                    problems.append(f"{case['id']}: {s['label']} differs from the chain's transaction")
                elif info["blockhash"] != s["blockhash"]:
                    notes.append(f"{case['id']}: {s['label']} was reorganized into block {info['blockhash']}")
            elif confirmed:
                notes.append(f"{case['id']}: {s['label']} confirmed after its case ended")
    return problems, notes
