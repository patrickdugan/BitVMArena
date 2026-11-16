"""Isolated, owned Bitcoin Core regtest process. Never attach to a user's node."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import socket
import subprocess
import time
from decimal import Decimal
from pathlib import Path


class CoreError(RuntimeError):
    pass


def safe_json(value):
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, dict):
        return {key: safe_json(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [safe_json(item) for item in value]
    return value


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Regtest:
    """An owned regtest node. By default P2P is off. With `p2p` it joins a cluster of other
    owned nodes only: it listens on 127.0.0.1:`p2p["port"]` and connects to exactly the listed
    127.0.0.1 ports, with DNS seeds, fixed seeds, discovery and NAT mapping off. Start refuses a
    peer that is not one of those loopback connections."""

    def __init__(self, binary, directory, *, timeout=30, p2p=None):
        self.binary, self.directory = Path(binary).resolve(), Path(directory).resolve()
        if not self.binary.is_file():
            raise CoreError("provide an existing bitcoind binary")
        if self.directory.exists() and any(self.directory.iterdir()):
            raise CoreError("regtest directory must be new or empty; refusing existing data")
        self.directory.mkdir(parents=True, exist_ok=True)
        if not 1 <= timeout <= 60:
            raise CoreError("timeout must be in [1,60]")
        self.timeout, self.counter = timeout, 0
        self.process = None
        self.log = None
        self.cookie = self.directory / "regtest/.cookie"
        self.port = free_port()
        self.p2p = None
        if p2p is not None:
            connect = [int(port) for port in p2p.get("connect", ())]
            self.p2p = {"port": int(p2p["port"]), "connect": connect, "blocksonly": bool(p2p.get("blocksonly"))}

    def start(self):
        self.log = (self.directory / "process.log").open("wb")
        command = [str(self.binary), "-regtest=1", "-server=1", "-dnsseed=0", "-discover=0", "-txindex=1",
                   "-fallbackfee=0.0001", f"-datadir={self.directory}", f"-rpcport={self.port}",
                   "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-printtoconsole=0"]
        if self.p2p is None:
            command += ["-networkactive=0", "-listen=0"]
        else:
            command += ["-listen=1", f"-bind=127.0.0.1:{self.p2p['port']}", f"-port={self.p2p['port']}",
                        "-fixedseeds=0", "-natpmp=0", "-listenonion=0", "-onlynet=ipv4"]
            command += [f"-connect=127.0.0.1:{port}" for port in self.p2p["connect"]] or ["-connect=0"]
            if self.p2p["blocksonly"]:
                command.append("-blocksonly=1")
        self.process = subprocess.Popen(command, stdout=self.log, stderr=subprocess.STDOUT,
                                        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise CoreError("Core exited during startup: " + self.log_tail())
            try:
                chain = self.rpc("getblockchaininfo")
                if chain["chain"] != "regtest":
                    raise CoreError("refusing a non-regtest chain")
                network = self.rpc("getnetworkinfo")
                if self.p2p is None and (network["networkactive"] or network["connections"]):
                    raise CoreError("test node must have P2P networking disabled")
                if self.p2p is not None:
                    self.check_peers()
                return self
            except (OSError, CoreError):
                time.sleep(0.1)
        self.close()
        raise CoreError("Core startup timed out: " + self.log_tail())

    def rpc(self, method, *params, wallet=False):
        if not self.cookie.is_file():
            raise CoreError("RPC cookie not ready")
        credentials = self.cookie.read_text(encoding="ascii").strip()
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=self.timeout)
        self.counter += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self.counter, "method": method, "params": params})
        try:
            connection.request("POST", "/wallet/arena" if wallet else "/", body,
                               {"Authorization": "Basic " + base64.b64encode(credentials.encode()).decode(),
                                "Content-Type": "application/json"})
            response = connection.getresponse()
            content = response.read(4_194_305)
        finally:
            connection.close()
        if len(content) > 4_194_304:
            raise CoreError("RPC response exceeded 4 MiB")
        result = json.loads(content, parse_float=Decimal)
        if result.get("error"):
            raise CoreError(f"{method}: {result['error']}")
        if result.get("id") != self.counter:
            raise CoreError("RPC response ID mismatch")
        return result["result"]

    def check_peers(self, allowed_ports=()):
        """Every peer must be a loopback connection: an outbound one to a listed port, or an
        inbound one (from another owned node's ephemeral port)."""
        allowed = set(self.p2p["connect"]) | set(allowed_ports)
        peers = self.rpc("getpeerinfo")
        for peer in peers:
            host, _, port = peer["addr"].rpartition(":")
            if host != "127.0.0.1" or (not peer["inbound"] and int(port) not in allowed):
                raise CoreError(f"unexpected peer {peer['addr']}; refusing")
        return peers

    def initialize_wallet(self):
        self.rpc("createwallet", "arena")
        self.miner = self.rpc("getnewaddress", "", "bech32m", wallet=True)
        self.rpc("generatetoaddress", 101, self.miner)

    def mine(self, count=1):
        return self.rpc("generatetoaddress", count, self.miner)

    def address(self, output_key):
        descriptor = self.rpc("getdescriptorinfo", f"rawtr({output_key.hex()})")["descriptor"]
        return self.rpc("deriveaddresses", descriptor)[0]

    def destination(self):
        address = self.rpc("getnewaddress", "", "bech32m", wallet=True)
        return bytes.fromhex(self.rpc("getaddressinfo", address, wallet=True)["scriptPubKey"])

    def log_tail(self):
        path = self.directory / "process.log"
        return path.read_text(encoding="utf-8", errors="replace")[-4000:] if path.exists() else ""

    def close(self):
        if self.process is not None and self.process.poll() is None:
            try:
                self.rpc("stop")
                self.process.wait(timeout=10)
            except (OSError, CoreError, subprocess.TimeoutExpired):
                self.process.kill()
                self.process.wait(timeout=5)
        if self.log is not None:
            self.log.close()

    @property
    def provenance(self):
        network = self.rpc("getnetworkinfo")
        return {"version": network["version"], "subversion": network["subversion"],
                "binary_sha256": hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                "chain": "regtest", "p2p_network_active": network["networkactive"]}

    def __enter__(self):
        try:
            return self.start()
        except BaseException:
            self.close()
            raise

    def __exit__(self, *_):
        self.close()
