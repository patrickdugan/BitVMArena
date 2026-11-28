"""Cashu M14 joint-release trajectories (track `cashu-release`) staged on the public testnet4 network.

The trajectories are the regtest track's (`cashu_release.run_case`), unchanged, run through the
BitVM3 staging session (`testnet4.StagingSession`): transactions go to an existing testnet4 node
and real miners decide what confirms; where a trajectory asks for blocks (the reserve's 6-block
CSV), the session waits for the network's blocks.

What changes is the stage:
- every wave has fresh random keys for all ten Cashu roles and a fresh garbling-seed salt,
  kept in a state directory outside the repository. With the corpus's fixed test scalars,
  anyone watching testnet4 could spend the funded reserve and collateral;
- the holder and guardian challenge reveals are keyed by those fresh secrets, so each row's
  cut-and-choose draw (and with it its pre-registered expectation) is fixed when the stage is
  made, before anything is broadcast;
- the amounts are small: a 1,000-sat reserve and a 1,250-sat collateral. The pinned Cashu fee
  deltas are kept: the joint release pays 750 to the holder and refunds 750 (750 sats fee,
  as in the pinned 24,750/24,750 release), and the holder CSV exit pays 750 (250 sats fee).

`rehearse` runs a wave against an owned regtest node that mines on a timer (and, with
`reorg_every`, reorganizes the way testnet4 does) before any testnet4 coin moves.
"""

from __future__ import annotations

import json
import secrets as entropy
import threading
from pathlib import Path

from . import cashu_release as cr
from . import testnet4 as t4
from .bitcoin import N, lift
from .canonical import ValidationError, digest
from .core import Regtest

TRACK = "cashu-release-testnet4"
NETWORK = t4.NETWORK
EVIDENCE_LEVEL = t4.EVIDENCE_LEVEL
REHEARSAL_LEVEL = "staging-rehearsal-regtest"
AMOUNTS = {"reserve": 1_000, "collateral": 1_250, "payout": 750, "refund": 750}
ROLES = tuple(cr.SECRETS)
PREFIX = cr.TRACK + "."

# cashu1: the honest k=4 ceremony and joint release end to end on testnet4. Sized to the
# staging wallet's 2,954 sats on 2026-11-28 (one 2,550-sat coin plus the split's fee); its
# reserve and collateral come back to stage keys the wallet imports.
WAVES = {
    "cashu1": [f"{TRACK}.wrong_circuit_under_pin.hardened.benign"],
}


# --- stage --------------------------------------------------------------------------------

def new_stage() -> cr.CashuStage:
    secrets = {name: entropy.randbelow(N - 1) + 1 for name in ROLES}
    return cr.CashuStage.from_secrets(secrets, salt=entropy.token_bytes(16), **AMOUNTS)


def stage_record(stage: cr.CashuStage, *, private: bool = False) -> dict:
    record = {"keys": stage.public_keys(), "salt": stage.salt.hex(),
              **{name: getattr(stage, name) for name in AMOUNTS}}
    if private:
        record["secrets"] = {name: format(value, "064x") for name, value in stage.secrets.items()}
    return record


def stage_from_record(record: dict) -> cr.CashuStage:
    """A stage from its record: with secrets when the record has them, else public keys only."""
    keys = {}
    for name in ROLES:
        key = bytes.fromhex(record["keys"][name])
        lift(key)       # a valid x-only point
        keys[name] = key
    fields = {name: int(record[name]) for name in AMOUNTS}
    salt = bytes.fromhex(record["salt"])
    if "secrets" in record:
        stage = cr.CashuStage.from_secrets({n: int(record["secrets"][n], 16) for n in ROLES}, salt=salt, **fields)
        if stage.keys != keys:
            raise ValidationError("stage secrets do not match its public keys")
        return stage
    return cr.CashuStage(keys, None, salt, **fields)


def stage_descriptors(stage: cr.CashuStage) -> list[str]:
    """Key-path descriptors for every role, so the funding wallet sees what the wave pays back."""
    return [f"tr({t4.wif(stage.secret(name))})" for name in ROLES]


def import_stage(node, stage: cr.CashuStage) -> None:
    requests = []
    for descriptor in stage_descriptors(stage):
        checked = node.rpc("getdescriptorinfo", descriptor)["checksum"]
        requests.append({"desc": f"{descriptor}#{checked}", "timestamp": "now", "label": "bitvm-arena-cashu-stage"})
    results = node.rpc("importdescriptors", requests, wallet=True)
    if not all(r.get("success") for r in results):
        raise ValidationError(f"importdescriptors failed: {results}")


# --- rows ---------------------------------------------------------------------------------

def catalog(stage: cr.CashuStage) -> list[dict]:
    """The cashu-release rows under `stage`, renamed. Expectations depend on the stage: its
    secrets fix each row's joint cut-and-choose draw."""
    rows = []
    for row in cr.catalog(stage):
        rid = TRACK + "." + row["id"][len(PREFIX):]
        rows.append({**row, "id": rid, "scenario_id": rid, "track": TRACK, "evidence_level": EVIDENCE_LEVEL})
    return rows


def select(stage: cr.CashuStage, names=(), wave=None) -> list[dict]:
    rows = catalog(stage)
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


def coin_sizes(rows: list[dict], stage: cr.CashuStage) -> list[int]:
    """One coin per funding step: reserve + collateral plus the funding margin. proof_replay
    funds a second reserve and collateral in its own funding step."""
    need = stage.reserve + stage.collateral + t4.COIN_MARGIN
    return [need] * sum(2 if r["recipe"] == "proof_replay" else 1 for r in rows)


# --- waves --------------------------------------------------------------------------------

def run_wave(node, rows, stage, state, *, wave, feerate=t4.FUNDING_FEERATE, patience=t4.PATIENCE,
             poll=t4.POLL, rehearsal=None) -> dict:
    """Run `rows` concurrently on `node`; `state` is a directory outside the repository."""
    state = Path(state)
    (state / "cases").mkdir(parents=True, exist_ok=True)
    journal = t4.Journal(state / "events.jsonl")
    started, start_prov = t4.now(), node.provenance()
    journal.write(kind="wave start", wave=wave, rows=[r["id"] for r in rows], provenance=start_prov)
    import_stage(node, stage)
    chain = t4.Chain(node, poll).start()
    results = {}
    try:
        pool, split = t4.CoinPool.split(node, chain, coin_sizes(rows, stage), journal, feerate)

        def work(row):
            session = t4.StagingSession(node, chain, pool, journal, row["id"], feerate=feerate, patience=patience)
            try:
                steps, funded_target, observed = cr.run_case(session, row, stage)
                outcome = cr.score(row, steps, observed, stage)
                case = {**row, "keys": stage.public_keys(), "funded_target": funded_target, "steps": steps,
                        "action_trace": steps, "observed_final_state": observed, **outcome, "outcome": outcome,
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
    report = finalize(wave, start_prov, node.provenance(), started, t4.now(), stage, split, cases, patience,
                      rehearsal() if rehearsal else None)
    journal.write(kind="wave end", wave=wave, summary=report["summary"])
    return report


def finalize(wave, start_prov, end_prov, started, ended, stage, split, cases, patience, rehearsal=None) -> dict:
    tx_steps = [s for c in cases for s in c["steps"] if s["kind"] == "tx"]
    provenance = {"start": start_prov, "end": end_prov, "started": started, "ended": ended,
                  "patience_blocks": patience}
    if rehearsal is not None:
        provenance["rehearsal_network"] = rehearsal
    report = {"schema_version": 1, "track": TRACK, "campaign_id": cr.CAMPAIGN_ID, "network": start_prov["chain"],
              "wave": wave,
              "evidence_level": EVIDENCE_LEVEL if start_prov["chain"] == NETWORK else REHEARSAL_LEVEL,
              "source_revision": dict(cr.SOURCE_REVISION), "provenance": provenance,
              "stage": stage_record(stage), "funding": split,
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


def rehearse(binary, directory, *, names=(), wave=None, interval=1.5, reorg_every=0,
             patience=t4.PATIENCE) -> dict:
    """Run a wave against an owned regtest node that mines on a timer, as testnet4 would."""
    t4.NetworkMiner.check_reorg_every(reorg_every)
    directory = Path(directory)
    stage = new_stage()
    rows = select(stage, names, wave)
    with Regtest(binary, directory / "node", timeout=60) as owned:
        owned.initialize_wallet()
        node = t4.StagingNode(owned.port, owned.cookie, "arena", chain="regtest").check()
        with t4.NetworkMiner(node, owned.miner, interval, reorg_every) as miner:
            return run_wave(node, rows, stage, directory / "state", wave=wave or "rehearsal",
                            patience=patience, poll=0.25, rehearsal=miner.settings)


# --- audit --------------------------------------------------------------------------------

def audit(report: dict) -> list[str]:
    """Offline audit from public data: envelope, stage keys, the cut-and-choose draw behind each
    expectation, rebuilt funding scripts, every step against Core's recorded result, scores.

    Not rechecked offline here: the selective-failure leak (its evaluation needs the stage's
    garbling inputs; the regtest track's audit recomputes it) and whether confirmed blocks are
    still in the best chain (testnet4.verify_chain does that against a node for bitvm3 waves).
    """
    problems = []
    body = {k: v for k, v in report.items() if k != "evidence_hash"}
    if digest(body) != report.get("evidence_hash"):
        problems.append("evidence_hash does not match the report body")
    if report.get("track") != TRACK:
        problems.append(f"wrong track: {report.get('track')}")
    network = report.get("network")
    if network not in (NETWORK, "regtest"):
        problems.append(f"unexpected network {network!r}")
    if report.get("evidence_level") != (EVIDENCE_LEVEL if network == NETWORK else REHEARSAL_LEVEL):
        problems.append("evidence_level does not match the network")
    try:
        stage = stage_from_record(report["stage"])
    except (KeyError, ValueError, ValidationError) as exc:
        return problems + [f"stage record unusable: {exc}"]
    if "secrets" in report["stage"]:
        problems.append("the report publishes stage secrets")

    for case in report.get("cases", []):
        cid = case.get("id", "?")
        if case.get("error"):
            problems.append(f"{cid}: case error: {case['error']}")
            continue
        if case.get("keys") != stage.public_keys():
            problems.append(f"{cid}: keys differ from the stage's public keys")
        cfg = cr.config_for(case["recipe"], case["profile"])
        cer_step = next((s for s in case["steps"] if s["label"] == "ceremony"), None)
        if cer_step is None:
            problems.append(f"{cid}: no ceremony step")
            continue
        challenge = cer_step["challenge"]
        if challenge["mode"] == "joint":
            kept = cr.joint_draw(challenge, cer_step["commitments"], cer_step["k"])
            bad = set(cer_step["bad_indices"])
            escaped = bool(bad) and bad <= {kept}
            if kept != cer_step["kept"] or escaped != challenge["escaped"]:
                problems.append(f"{cid}: recorded joint draw does not follow from its reveals and commitments")
        else:
            escaped = False
        if case.get("cut_and_choose_escaped") != escaped:
            problems.append(f"{cid}: pre-registered cut_and_choose_escaped differs from the recorded draw")
        expected = cr.expected_for(case["recipe"], case["profile"], case["variant"], escaped, stage.payout)
        if case.get("expected") != expected:
            problems.append(f"{cid}: expected outcome is not the catalog's for this draw")

        registration = {"statement_sha256": cer_step["statement_sha256"],
                        "ciphertext_commitment": cer_step["ciphertext_commitment"],
                        "accept_label_sha256": cer_step["accept_label_sha256"],
                        "reject_label_sha256": cer_step["reject_label_sha256"]}
        graph = cr.CashuGraph(cid, cfg, registration, index=0, stage=stage)
        fund_step = next((s for s in case["steps"] if s["label"] == "fund"), None)
        for name, tree, sats in (("reserve", graph.R, stage.reserve), ("collateral", graph.C, stage.collateral)):
            output = (fund_step or {}).get("outputs", {}).get(name, {})
            if output.get("script_pubkey") != tree.script_pubkey.hex() or output.get("amount") != sats:
                problems.append(f"{cid}: funded {name} differs from the graph rebuilt from public data")

        problems += cr.step_problems(cid, case["steps"])
        observed = case.get("observed_final_state", {})
        if observed.get("diverted_principal_sats") != cr.paid_to_attacker(case["steps"], stage):
            problems.append(f"{cid}: diverted_principal_sats differs from confirmed outputs paying the attacker")
        rescored = cr.score(case, case["steps"], observed, stage)
        if rescored != case.get("outcome"):
            problems.append(f"{cid}: recorded outcome differs from rescored steps")
        if case.get("expectation_met") != (case.get("outcome") == expected):
            problems.append(f"{cid}: expectation_met inconsistent with outcome")

    summary = report.get("summary", {})
    if summary.get("expectation_failures") != [c["id"] for c in report.get("cases", []) if not c.get("expectation_met")]:
        problems.append("summary expectation_failures inconsistent")
    return problems
