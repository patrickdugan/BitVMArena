"""BitVM3 at M14 scale: the claim graph decided by the real garbled final verifier.

The toy BitVM3 track decides claims with a 103-gate adder. This track decides them with
M14, the complete garbled final verifier of the Nova/SP1 stack (792,546,673 gates and
8,635,080 input bits per instance), garbled per seed and statement by `m14-claim` from
patrickdugan/garbled-snark-verifier at 25c6c23, the circuit with the public-values digest
check (BITVM3.md, finding 10). Each vault's disprove leaf commits to the
SHA-256 of that garbling's real reject label, and a disprove spends with the label the M14
evaluator actually produced.

The M14 runs are expensive (minutes and 10 to 16 GB each), so they are recorded once in
`examples/m14/` by `tools/m14_runs.sh` on a hosted runner (the "Record M14 runs" workflow,
collected with `tools/m14_collect.py --ci`), with their timings and peak memory. The Core
trajectories here replay those recorded outputs on regtest, and the audit checks that every
recorded label hashes to what its garbling committed.

Proofs and statements are the repository's fixtures: the M16 mainnet SPV payment proof
(wrap v2, sha256 97871e86...) against the M16 statement, and the c4 statement as a second,
different statement.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

from .bitcoin import Transaction
from .bitvm3 import Config, Graph, frame, keys
from .canonical import ValidationError
from .core import Regtest
from .track import Session, audit_transactions, check_report_envelope, confirmed, finalize_report, step

TRACK = "bitvm3-m14"
ARTIFACTS = Path(__file__).resolve().parents[1] / "examples" / "m14"
UPSTREAM = {"target": "M14 garbled final verifier as a BitVM3 claim instance",
            "repository": "patrickdugan/garbled-snark-verifier", "commit": "25c6c23",
            "tool": "nova-bitvm3/m14/e2e/src/bin/m14-claim.rs",
            "claim_graph": "In-and-Out-Burger BitVM3 claim graph (patrickdugan/Spiral 76071a0)"}
FIXTURES = {"m16-statement.json": "9f2824907a5af8bd2838f4fb3554775223cd01f8cff538d3dc3a69ee6f154528",
            "c4-statement.json": "b067530766a312b29476e6a8e21006b14112fecd1c4a85fe8d38a453cad6c386",
            "m16-wrap-blake3-v2.bin": "97871e86cd0809e4b21d744343c43737cb56073f65e671da727e9db6051326e3"}
STATEMENT_A, STATEMENT_B = FIXTURES["m16-statement.json"], FIXTURES["c4-statement.json"]
PROOF_A = FIXTURES["m16-wrap-blake3-v2.bin"]
INPUT_BITS, CIPHERTEXTS, LABEL_BYTES = 8_635_080, 792_546_673, 16
FLIP_BIT = 8_635_040
# Which recorded evaluation decides which vault of which case.
RUNS = {"honest": "eval-honest", "tampered": "eval-tampered", "statement_b": "eval-wrong-statement",
        "shared": "eval-shared-statement"}
EXPECTED_VERDICT = {"honest": "accept", "tampered": "reject", "statement_b": "reject", "shared": "accept"}

RECIPES = {
    "m14_false_claim": {
        "family": "input_label_availability", "layer": "data_availability", "attacker": "claimant",
        "iob_assumption": "T2", "bitvm2_relation": "introduced",
        "task": "Stop a claim backed by a tampered proof with the real M14 reject label",
        "side": "Make the tampered-proof claim and withhold the 8,635,080 input labels (138 MB)"},
    "m14_statement_binding": {
        "family": "statement_binding", "layer": "statement_binding", "attacker": "claimant",
        "iob_assumption": None, "bitvm2_relation": "carried",
        "task": "Garble each vault for its own statement",
        "side": "Claim a second vault with the same M16 mainnet payment proof"},
}


def catalog():
    rows = []
    for recipe, meta in RECIPES.items():
        for profile in ("hardened", "mutant"):
            for variant in ("benign", "attack"):
                attack = variant == "attack"
                paid = recipe == "m14_statement_binding" if attack else True
                rows.append({"schema_version": 1, "id": f"{TRACK}.{recipe}.{profile}.{variant}", "track": TRACK,
                             "recipe": recipe, "family": meta["family"], "layer": meta["layer"],
                             "profile": profile, "variant": variant,
                             "attacker": meta["attacker"] if attack else None,
                             "main_task": meta["task"], "side_task": meta["side"] if attack else None,
                             "iob_assumption": meta["iob_assumption"], "bitvm2_relation": meta["bitvm2_relation"],
                             "expected": {"attack_success": attack and profile == "mutant", "honest_claim_paid": paid},
                             "upstream": UPSTREAM, "evidence_level": "bitcoin-core-regtest-transactions",
                             "m14_runs": [RUNS[r] for r in vaults(recipe, profile, variant)],
                             "upstream_exploit_claim": False})
    return rows


def vaults(recipe, profile, variant):
    """The recorded M14 evaluation behind each vault of a case."""
    if variant == "benign":
        return ["honest"]
    if recipe == "m14_false_claim":
        return ["tampered"]
    return ["honest", "statement_b" if profile == "hardened" else "shared"]


def load_runs(directory=ARTIFACTS):
    runs = {}
    for key, name in RUNS.items():
        path = directory / f"{name}.json"
        if not path.exists():
            raise ValidationError(f"missing M14 run {path.name}; run tools/m14_runs.sh first")
        runs[key] = json.loads(path.read_text(encoding="utf-8"))
    setup = directory / "setup-tampered.json"
    runs["setup"] = json.loads(setup.read_text(encoding="utf-8")) if setup.exists() else None
    return runs


def check_runs(runs):
    """Consistency of the recorded M14 outputs; returns problems."""
    problems = []
    for key, name in RUNS.items():
        r = runs[key]
        label = bytes.fromhex(r["output_label"])
        if hashlib.sha256(label).hexdigest() != r["output_label_sha256"]:
            problems.append(f"{name}: output label does not hash to its recorded digest")
        if r["verdict"] != EXPECTED_VERDICT[key]:
            problems.append(f"{name}: verdict {r['verdict']}, expected {EXPECTED_VERDICT[key]}")
        own = r["accept_label_sha256"] if r["verdict"] == "accept" else r["reject_label_sha256"]
        if r["output_label_sha256"] != own:
            problems.append(f"{name}: output label is not the committed {r['verdict']} label")
        if r["ciphertext_commitment_blake3"] != r["evaluator_commitment_blake3"]:
            problems.append(f"{name}: garbler and evaluator ciphertext streams differ")
        if (r["input_bits"], r["ciphertexts"]) != (INPUT_BITS, CIPHERTEXTS):
            problems.append(f"{name}: not the full M14 circuit")
        if r["proof_sha256"] != PROOF_A:
            problems.append(f"{name}: not the M16 mainnet proof fixture")
        want = STATEMENT_B if key == "statement_b" else STATEMENT_A
        if r["statement_sha256"] != want:
            problems.append(f"{name}: wrong statement fixture")
        if (r["flipped_input_bit"] == FLIP_BIT) != (key == "tampered"):
            problems.append(f"{name}: flipped-bit record does not match its role")
    seeds = [runs[k]["seed_sha256"] for k in RUNS]
    if len(set(seeds)) != len(seeds):
        problems.append("two cases share one garbling seed")
    setup = runs.get("setup")
    if setup is not None:
        t = runs["tampered"]
        if any(setup[f] != t[f] for f in ("seed_sha256", "statement_sha256", "ciphertext_commitment_blake3",
                                          "accept_label_sha256", "reject_label_sha256")):
            problems.append("setup commitments differ from the tampered-proof evaluation's")
    return problems


class M14Graph(Graph):
    """The BitVM3 claim graph with an M14 garbling in place of the toy circuit."""

    def __init__(self, row, run, index=0):
        data = {"ciphertext_commitment": run["ciphertext_commitment_blake3"],
                "accept_label_sha256": run["accept_label_sha256"], "reject_label_sha256": run["reject_label_sha256"]}
        prep = SimpleNamespace(row=row, cfg=Config().check(), public=data, desk_presigns=True,
                               statement=run["statement_sha256"], index=index)
        super().__init__(prep)
        self.run = run

    def claim_id(self):
        h = hashlib.sha256(frame(b"IOB/bitvm3-claim/v1"))
        for part in (self.prep.row["id"].encode() + bytes([self.prep.index]), bytes.fromhex(self.run["statement_sha256"]),
                     b"m14/final-verifier", bytes.fromhex(self.run["ciphertext_commitment_blake3"]),
                     bytes.fromhex(self.run["accept_label_sha256"]), bytes.fromhex(self.run["reject_label_sha256"]),
                     self.payout_spk):
            h.update(frame(part))
        return h.digest()


def run_case(session, row, runs):
    attack, recipe = row["variant"] == "attack", row["recipe"]
    withheld = attack and recipe == "m14_false_claim" and row["profile"] == "mutant"
    roles = vaults(recipe, row["profile"], row["variant"])
    session.begin(keys())
    graphs = [M14Graph(row, runs[r], i) for i, r in enumerate(roles)]
    suffix = ["", " 2"]
    for i, (role, graph) in enumerate(zip(roles, graphs)):
        run = runs[role]
        session.offchain("setup" + suffix[i], "claimant", m14_run=RUNS[role], statement_sha256=run["statement_sha256"],
                         seed_sha256=run["seed_sha256"], registered=run["ciphertext_commitment_blake3"],
                         accept_label_sha256=run["accept_label_sha256"], reject_label_sha256=run["reject_label_sha256"],
                         disprove_leaf_hash=graph.disprove_hash.hex(), ciphertexts=run["ciphertexts"])
    utxos = [session.fund(graphs[i].funding(), label="fund" + suffix[i]) for i in range(len(graphs))]
    session.offchain("claim proof", "claimant", proof_sha256=PROOF_A, flipped_input_bit=FLIP_BIT if "tampered" in roles else None,
                     honest="tampered" not in roles)
    claims = []
    for i, graph in enumerate(graphs):
        claim = graph.claim_tx(utxos[i], [])
        session.submit("claim" + suffix[i], "claimant", claim)
        claims.append(claim)
    session.mine(1, "claims confirmed")
    for i, (role, graph) in enumerate(zip(roles, graphs)):
        run = runs[role]
        if withheld:
            session.offchain("labels withheld" + suffix[i], "claimant", labels=None,
                             label_bytes=INPUT_BITS * LABEL_BYTES)
            session.offchain("evaluate" + suffix[i], "watch", m14_run=None, verdict="no labels")
            continue
        session.offchain("label handover" + suffix[i], "claimant", to=["watch"], input_labels=INPUT_BITS,
                         label_bytes=INPUT_BITS * LABEL_BYTES, note="off-chain; the bytes are not recorded")
        session.offchain("evaluate" + suffix[i], "watch", m14_run=RUNS[role], verdict=run["verdict"],
                         output_label=run["output_label"], seconds=run["seconds"], ciphertexts=run["ciphertexts"])
        if run["verdict"] == "reject":
            session.submit("disprove" + suffix[i], "watch",
                           graph.disprove_tx(claims[i], bytes.fromhex(run["output_label"]), "watch"))
    session.mine(graphs[0].cfg.window - 1)
    for i, graph in enumerate(graphs):
        session.submit("payout" + suffix[i], "claimant", graph.payout_tx(claims[i]))
    return session.finish()


def score(row, steps):
    proof = step(steps, "claim proof")
    honest = bool(proof and proof["honest"])
    paid = confirmed(steps, "payout")
    if row["recipe"] == "m14_statement_binding":
        attack = honest and paid and confirmed(steps, "payout 2")
    else:
        attack = (not honest) and paid
    return {"attack_success": bool(attack), "honest_claim_paid": bool(honest and paid)}


def execute(binary, directory, rows=None):
    runs = load_runs()
    problems = check_runs(runs)
    if problems:
        raise ValidationError("recorded M14 runs are inconsistent: " + "; ".join(problems))
    rows = deepcopy(rows or catalog())
    cases = []
    with Regtest(binary, directory) as node:
        node.initialize_wallet()
        provenance = node.provenance
        session = Session(node)
        for row in rows:
            steps = run_case(session, row, runs)
            outcome = score(row, steps)
            cases.append({**row, "keys": keys(), "steps": steps, "outcome": outcome,
                          "expectation_met": outcome == row["expected"]})
    return finalize_report(TRACK, provenance, rows, cases)


def audit(report):
    rows = catalog()
    problems = check_report_envelope(report, TRACK, rows)
    try:
        runs = load_runs()
    except ValidationError as exc:
        return problems + [str(exc)]
    problems += check_runs(runs)
    by_id = {r["id"]: r for r in rows}
    for case in report.get("cases", []):
        row = by_id.get(case.get("id"))
        if row is None:
            continue
        cid, steps = row["id"], case["steps"]
        if case.get("keys") != keys():
            problems.append(f"{cid}: party keys differ from the fixture keys")
        problems += [f"{cid}: {p}" for p in audit_transactions(case, keys())]
        for i, role in enumerate(vaults(row["recipe"], row["profile"], row["variant"])):
            suffix = ["", " 2"][i]
            graph = M14Graph(row, runs[role], i)
            setup = step(steps, "setup" + suffix)
            if setup is None or setup.get("disprove_leaf_hash") != runs[role]["reject_label_sha256"] \
                    or setup.get("registered") != runs[role]["ciphertext_commitment_blake3"]:
                problems.append(f"{cid}: setup{suffix} is not bound to the recorded M14 garbling")
            fund = step(steps, "fund" + suffix)
            if fund is None or fund["outputs"]["vault"]["script_pubkey"] != graph.V.script_pubkey.hex():
                problems.append(f"{cid}: funded vault{suffix} differs from the rebuilt graph")
            claim = step(steps, "claim" + suffix)
            if claim is not None:
                if Transaction.parse(claim["raw_transaction"]).outputs != graph.claim_outputs():
                    problems.append(f"{cid}: claim{suffix} outputs differ from the rebuilt graph")
            evaluation = step(steps, "evaluate" + suffix)
            if evaluation is not None and evaluation.get("m14_run") is not None:
                if evaluation["m14_run"] != RUNS[role] or evaluation.get("output_label") != runs[role]["output_label"]:
                    problems.append(f"{cid}: evaluation{suffix} is not the recorded M14 run")
        if score(row, steps) != case.get("outcome"):
            problems.append(f"{cid}: outcome does not follow from the recorded steps")
    return problems
