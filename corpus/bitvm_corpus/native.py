"""Non-ZK BitVM primitive trajectories executed as real Taproot transactions.

Original native contracts built from BitVM gate and transaction-binding primitives
(hash-bound bit openings, Boolean gates, selectors, relative timelocks, presigned
sighash policies, Taproot commitments). Each case funds one contract and attempts
one spend; Bitcoin Core decides. They are not an upstream bridge or exploit claim.
"""

from __future__ import annotations

from copy import deepcopy

from .bitcoin import (SIGHASH_ALL, SIGHASH_NONE, ANYONECANPAY, TapLeaf, Transaction, opening, ops, number,
                      public, push, sha)
from .core import Regtest
from .track import (Session, audit_transactions, check_report_envelope, confirmed, finalize_report, step,
                    utxo_input)

TRACK = "primitive"
TEST_SECRET = 7
VALUE = 100_000
PAYOUT = 99_000
CONNECTOR = 1_000
CSV_DELAY = 6
RECIPES = {
    "and_as_or": ("boolean", "Reject a false conjunction before releasing the payout"),
    "nand_truth_table": ("boolean", "Reject a NAND output inconsistent with its authenticated inputs"),
    "input_push_unbound": ("authentication", "Require a hash-bound input instead of a literal approval"),
    "selector_unbound": ("conditional", "Bind an IF selector to the committed condition"),
    "wire_equivocation": ("wire_consistency", "Reject conflicting openings of the same wire"),
    "minimalif_normalization": ("encoding", "Reject a noncanonical branch selector"),
    "csv_removed": ("timelock", "Prevent withdrawal before its relative challenge window"),
    "csv_disabled_sequence": ("timelock", "Reject a disabled relative-lock sequence"),
    "csv_wrong_version": ("timelock", "Require transaction version 2 for CSV enforcement"),
    "recipient_sighash_none": ("settlement", "Keep a pre-signed withdrawal bound to its recipient"),
    "amount_sighash_none": ("settlement", "Keep a pre-signed withdrawal bound to its amounts"),
    "connector_anyonecanpay": ("transaction_graph", "Keep settlement bound to the challenge connector input"),
    "control_block_tamper": ("consensus_control", "Reject a substituted Taproot control block"),
    "script_tamper": ("consensus_control", "Reject a script not committed by the output key"),
}


def catalog():
    rows = []
    for recipe, (family, task) in RECIPES.items():
        for profile in ("hardened", "mutant"):
            for variant in ("benign", "attack"):
                negative = family == "consensus_control"
                allowed = variant == "benign" or (profile == "mutant" and not negative)
                rows.append({"schema_version": 1, "id": f"native.{recipe}.{profile}.{variant}", "track": TRACK,
                             "recipe": recipe, "family": family, "profile": profile, "variant": variant,
                             "main_task": task, "expected": {"spend_confirmed": allowed},
                             "evidence_level": "bitcoin-core-regtest-transactions",
                             "upstream_exploit_claim": False})
    return rows


def keys():
    return {"signer": public(TEST_SECRET).hex()}


def compile_contract(row):
    """Return committed leaf, witness data and any required signature policy."""
    recipe = row["recipe"]
    attack, corrupt = row["variant"] == "attack", row["profile"] == "mutant"
    a, a_values = opening(row["id"] + ":a")
    b, b_values = opening(row["id"] + ":b")
    z, z_values = opening(row["id"] + ":z")
    prefix = push(sha(row["id"].encode())) + ops("DROP")
    witness, policy = [], None
    if recipe == "and_as_or":
        code = b + ops("TOALT") + a + ops("FROMALT", "BOOLOR" if corrupt else "BOOLAND")
        witness = [a_values[1], b_values[0 if attack else 1]]
    elif recipe == "nand_truth_table":
        gate = ops("BOOLOR") if corrupt else ops("BOOLAND", "NOT")
        code = z + ops("TOALT") + b + ops("TOALT") + a + ops("FROMALT") + gate + ops("FROMALT", "EQUAL")
        # Correct NAND(0,1)=1 is a positive control for both tables.
        witness = [a_values[1 if attack else 0], b_values[1], z_values[1]]
    elif recipe == "input_push_unbound":
        code = ops("DROP", "1") if corrupt else a
        witness = [a_values[0 if attack else 1]]
    elif recipe == "selector_unbound":
        # The selector chooses the release branch; hardened binds it to the opened wire.
        branch = ops("IF", "1", "ELSE", "0", "ENDIF")
        code = (a + ops("DROP") + branch) if corrupt else (a + ops("OVER", "EQUALVERIFY") + branch)
        witness = [b"\x01", a_values[0 if attack else 1]]
    elif recipe == "wire_equivocation":
        code = a + ops("TOALT") + a + ops("FROMALT")
        code += ops("DROP", "DROP", "1") if corrupt else ops("EQUAL")
        witness = [a_values[1], a_values[0 if attack else 1]]
    elif recipe == "minimalif_normalization":
        code = (ops("0NOTEQUAL") if corrupt else b"") + ops("IF", "1", "ELSE", "0", "ENDIF")
        witness = [b"\x02" if attack else b"\x01"]
    elif recipe.startswith("csv_"):
        code = ops("1") if corrupt else number(CSV_DELAY) + ops("CSV", "DROP", "1")
    else:
        code = push(public(TEST_SECRET)) + ops("CHECKSIG")
        policy = ((SIGHASH_ALL | ANYONECANPAY) if corrupt and recipe == "connector_anyonecanpay"
                  else SIGHASH_NONE if corrupt and recipe.endswith("sighash_none") else SIGHASH_ALL)
    return TapLeaf(prefix + code), witness, policy


def connector_leaf(row):
    return TapLeaf(push(sha((row["id"] + ":connector").encode())) + ops("DROP", "1"))


def build_transaction(row, leaf, witness, policy, utxo, destination, attacker, connector=None):
    """Presign authorized intent, then apply the red-team action without keys."""
    txin = utxo_input(utxo)
    tx = Transaction([txin], [(PAYOUT, destination)])
    if row["recipe"].startswith("csv_"):
        txin.sequence = CSV_DELAY
    if connector is not None:
        cleaf = connector_leaf(row)
        tx.inputs.append(utxo_input(connector))
        tx.inputs[-1].witness = [cleaf.script, cleaf.control]
    signature = tx.signature(0, leaf, TEST_SECRET, policy) if policy is not None else None
    if row["variant"] == "attack":
        recipe = row["recipe"]
        if recipe == "recipient_sighash_none":
            tx.outputs = [(PAYOUT, attacker)]
        elif recipe == "amount_sighash_none":
            tx.outputs = [(PAYOUT - 10_000, destination), (10_000, attacker)]
        elif recipe == "connector_anyonecanpay":
            tx.inputs.pop()
        elif recipe in ("csv_removed", "csv_disabled_sequence"):
            txin.sequence = 0xffffffff if recipe == "csv_removed" else 0x80000000 | CSV_DELAY
        elif recipe == "csv_wrong_version":
            tx.version = 1
    txin.witness = ([signature] if signature is not None else []) + list(witness) + [leaf.script, leaf.control]
    if row["variant"] == "attack":
        if row["recipe"] == "control_block_tamper":
            txin.witness[-1] = bytes([leaf.control[0] ^ 1]) + leaf.control[1:]
        if row["recipe"] == "script_tamper":
            txin.witness[-2] = leaf.script + ops("1")
    return tx


def run_case(session, row, destination, attacker):
    leaf, witness, policy = compile_contract(row)
    session.begin(keys())
    outputs = {"contract": (leaf._tree, VALUE)}
    if row["recipe"] == "connector_anyonecanpay":
        outputs["connector"] = (connector_leaf(row)._tree, CONNECTOR)
    utxos = session.fund(outputs)
    connector = utxos.get("connector")
    if connector is not None and row["variant"] == "attack":
        # The challenge spends the connector first; the attack then drops it from settlement.
        cleaf = connector_leaf(row)
        challenge = Transaction([utxo_input(connector)], [(CONNECTOR // 2, attacker)])
        challenge.inputs[0].witness = [cleaf.script, cleaf.control]
        session.submit("challenge", "watcher", challenge)
        session.mine(1)
    if row["recipe"].startswith("csv_") and row["variant"] == "benign":
        session.mine(CSV_DELAY, "relative timelock matures")
    tx = build_transaction(row, leaf, witness, policy, utxos["contract"], destination, attacker, connector)
    session.submit("spend", "attacker" if row["variant"] == "attack" else "operator", tx)
    return session.finish()


def score(row, steps):
    return {"spend_confirmed": confirmed(steps, "spend")}


def execute(binary, directory, rows=None):
    rows = deepcopy(rows or catalog())
    cases = []
    with Regtest(binary, directory) as node:
        node.initialize_wallet()
        provenance = node.provenance
        destination, attacker = node.destination(), node.destination()
        session = Session(node)
        for row in rows:
            steps = run_case(session, row, destination, attacker)
            outcome = score(row, steps)
            cases.append({**row, "keys": keys(), "steps": steps, "outcome": outcome,
                          "expectation_met": outcome == row["expected"]})
    return finalize_report(TRACK, provenance, rows, cases)


def audit(report):
    rows = catalog()
    problems = check_report_envelope(report, TRACK, rows)
    by_id = {r["id"]: r for r in rows}
    for case in report.get("cases", []):
        row = by_id.get(case.get("id"))
        if row is None:
            continue
        cid = row["id"]
        problems += [f"{cid}: {p}" for p in audit_transactions(case)]
        leaf, _, _ = compile_contract(row)
        fund = step(case["steps"], "fund")
        if fund is None or fund["outputs"]["contract"]["script_pubkey"] != leaf.script_pubkey.hex():
            problems.append(f"{cid}: funded contract differs from the compiled leaf")
        spend = step(case["steps"], "spend")
        if spend is None:
            problems.append(f"{cid}: no spend attempt")
        elif row["recipe"] not in ("control_block_tamper", "script_tamper") or row["variant"] == "benign":
            witness = Transaction.parse(spend["raw_transaction"]).inputs[0].witness
            if witness[-2:] != [leaf.script, leaf.control]:
                problems.append(f"{cid}: spend does not reveal the compiled leaf")
        if score(row, case["steps"]) != case.get("outcome"):
            problems.append(f"{cid}: outcome does not follow from the recorded steps")
    return problems
