"""Evaluator-owned targets and bounded candidates for the CPA Python oracle.

This module checks a single-input research profile. The caller owns the target;
only candidate JSON crosses the attacker interface. No node validation is run.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

MAX_CANDIDATE_BYTES = 65_536
MAX_MONEY = 21_000_000 * 100_000_000
MODES = {'unmodified_cpa', 'planted_guard_mutant'}


class CandidateError(ValueError):
    pass


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def tagged(tag: str, data: bytes) -> str:
    h = hashlib.sha256(tag.encode('ascii')).digest()
    return hashlib.sha256(h + h + data).hexdigest()


def exact_keys(value: Any, names: set[str]) -> dict:
    if type(value) is not dict or set(value) != names:
        raise CandidateError('unexpected fields')
    return value


def integer(value: Any, lower: int, upper: int) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise CandidateError('integer outside profile')
    return value


def hex_bytes(value: Any, maximum: int, size: int | None = None) -> bytes:
    if (type(value) is not str or len(value) > 2 * maximum or len(value) % 2
            or re.fullmatch('[0-9a-f]*', value) is None):
        raise CandidateError('invalid canonical hex')
    result = bytes.fromhex(value)
    if size is not None and len(result) != size:
        raise CandidateError('wrong hex width')
    return result


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CandidateError('duplicate JSON key')
        result[key] = value
    return result


def parse_json(payload: bytes) -> dict:
    if type(payload) is not bytes or len(payload) > MAX_CANDIDATE_BYTES:
        raise CandidateError('candidate byte budget')
    try:
        def forbidden_constant(value):
            raise CandidateError('non-finite number')
        value = json.loads(payload, object_pairs_hook=_object, parse_constant=forbidden_constant)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise CandidateError('invalid candidate JSON') from error
    return exact_keys(value, {'version', 'locktime', 'inputs', 'outputs', 'witness'})


@dataclass(frozen=True)
class Target:
    stage: Any
    txid: str
    vout: int
    permission_table: str
    policy_cap: int
    mode: str
    script_pubkey: bytes
    control: bytes
    expected_outputs: tuple
    input_positions: tuple
    witness_count: int
    target_id: str

    def public(self) -> dict:
        return {
            'schema': 'BA-CPA-02/target-v1', 'target_id': self.target_id,
            'evidence_mode': self.mode, 'program_id': self.stage.program.program_id.hex(),
            'authority_id': self.stage.authority.hex(), 'state_root': self.stage.state_root.hex(),
            'outpoint': {'txid': self.txid, 'vout': self.vout}, 'amount_sats': self.stage.amount,
            'script_pubkey': self.script_pubkey.hex(), 'script_hex': self.stage.leaf.script.hex(),
            'control_hex': self.control.hex(), 'permission_table_00_01_10_11': self.permission_table,
            'parent_cap_sats': self.policy_cap, 'input_positions': list(self.input_positions),
            'outputs_by_selector': [[{'value': value, 'script_hex': script.hex()}
                                     for value, script in outputs] for outputs in self.expected_outputs],
            'native_node_verified': False, 'HF_verified': False,
        }


def freeze(backend: tuple, stage: Any, permission_table: str = '0001',
           policy_cap: int = 8000, mode: str = 'unmodified_cpa',
           txid: str = '43' * 32, vout: int = 0) -> Target:
    _, machine, base, _, _, _ = backend
    if mode not in MODES or re.fullmatch('[01]{4}', permission_table) is None:
        raise ValueError('unknown target mode or permission table')
    integer(policy_cap, 0, MAX_MONEY)
    hex_bytes(txid, 32, 32)
    integer(vout, 0, 2**32 - 1)
    if stage.amount != 100_000 or stage.epoch != 0 or stage.program.output_hashes[-1] not in dict(stage.program.records):
        raise ValueError('only root-stage targets are supported')
    if mode == 'unmodified_cpa' and policy_cap != stage.cap:
        raise ValueError('cap mismatch requires a planted-mutant target')
    if mode == 'planted_guard_mutant' and (policy_cap != 8000 or stage.cap != 9000):
        raise ValueError('unknown planted mutation')
    for a in (0, 1):
        for b in (0, 1):
            for selector in (0, 1):
                values = {}
                for node_hash, record in stage.program.records:
                    if record[0] == 0:
                        index = int.from_bytes(record[1:], 'little')
                        if index > 2:
                            raise ValueError('input index exceeds episode grammar')
                        value = (a, b, selector)[index]
                    elif record[0] == 1:
                        value = record[1]
                    elif record[0] == 2:
                        value = 1 - values[record[1:33]] * values[record[33:65]]
                    else:
                        raise ValueError('unknown graph record')
                    values[node_hash] = value
                if values[stage.program.output_hashes[0]] != int(permission_table[2 * a + b]):
                    raise ValueError('permission table disagrees with locked circuit')
                if values[stage.program.output_hashes[1]] != selector:
                    raise ValueError('selector output disagrees with the profile')
    positions = [-1, -1, -1]
    for offset, (_, record) in enumerate(stage.program.records, len(machine.FIELDS)):
        if record[0] == 0:
            index = int.from_bytes(record[1:], 'little')
            if index > 2:
                raise ValueError('input index exceeds episode grammar')
            positions[index] = offset
    if positions[2] < 0:
        raise ValueError('missing selector input')
    for missing in (i for i in (0, 1) if positions[i] == -1):
        for assignment in range(4):
            if permission_table[assignment] != permission_table[assignment ^ (2 if missing == 0 else 1)]:
                raise ValueError('policy depends on an absent input')
    outputs = []
    for selector, payout in enumerate((7000, 9000)):
        successor = stage.actions[selector].successor
        if successor is None:
            raise ValueError('expected a bounded successor')
        outputs.append(((payout, b'\x51\x20' + base.RECIPIENTS[selector]),
                        (100_000 - payout - 2000, successor.leaf.output()[0])))
    script_pubkey, control = stage.leaf.output()
    identity = {'script_pubkey': script_pubkey.hex(), 'script_hex': stage.leaf.script.hex(),
                'control': control.hex(), 'txid': txid, 'vout': vout, 'amount': stage.amount,
                'permission_table': permission_table, 'cap': policy_cap, 'mode': mode,
                'outputs': [[(v, s.hex()) for v, s in pair] for pair in outputs]}
    return Target(stage, txid, vout, permission_table, policy_cap, mode, script_pubkey, control,
                  tuple(outputs), tuple(positions), len(machine.FIELDS) + stage.program.node_count + 2,
                  tagged('BA-CPA-02/Target', canonical(identity)))


def encode_candidate(tx: Any, witness: list[bytes]) -> bytes:
    return canonical({'version': tx.version, 'locktime': tx.locktime,
                      'inputs': [{'txid': item.txid[::-1].hex(), 'vout': item.index,
                                  'sequence': item.sequence} for item in tx.inputs],
                      'outputs': [{'value': item.amount, 'script_hex': item.script.hex()}
                                  for item in tx.outputs], 'witness': [item.hex() for item in witness]})


def decode(backend: tuple, target: Target, payload: bytes):
    base = backend[2]
    obj = parse_json(payload)
    version = integer(obj['version'], -(2**31), 2**31 - 1)
    locktime = integer(obj['locktime'], 0, 2**32 - 1)
    if type(obj['inputs']) is not list or len(obj['inputs']) != 1:
        raise CandidateError('single-input profile required')
    inp = exact_keys(obj['inputs'][0], {'txid', 'vout', 'sequence'})
    txid = hex_bytes(inp['txid'], 32, 32)
    vout = integer(inp['vout'], 0, 2**32 - 1)
    sequence = integer(inp['sequence'], 0, 2**32 - 1)
    if type(obj['outputs']) is not list or not 1 <= len(obj['outputs']) <= 8:
        raise CandidateError('output count outside profile')
    outputs = []
    for item in obj['outputs']:
        item = exact_keys(item, {'value', 'script_hex'})
        outputs.append(base.Output(integer(item['value'], 0, MAX_MONEY), hex_bytes(item['script_hex'], 520)))
    if sum(item.amount for item in outputs) > target.stage.amount:
        raise CandidateError('outputs exceed evaluator-owned input value')
    if type(obj['witness']) is not list or len(obj['witness']) != target.witness_count:
        raise CandidateError('witness count outside profile; annex unsupported')
    witness = [hex_bytes(item, 10_000 if i == len(obj['witness']) - 2 else 520)
               for i, item in enumerate(obj['witness'])]
    tx = base.Tx((base.Input(txid[::-1], vout, target.stage.amount, target.script_pubkey, sequence),),
                 tuple(outputs), version, locktime)
    return tx, witness


def policy_violations(target: Target, tx: Any, witness: list[bytes]) -> tuple[str, ...]:
    violations = []
    bits = []
    for position in target.input_positions:
        value = b'' if position == -1 else witness[position]
        if value not in (b'', b'\x01'):
            return ('noncanonical_request_bit',)
        bits.append(int(bool(value)))
    if target.permission_table[bits[0] * 2 + bits[1]] != '1':
        violations.append('permission_predicate')
    actual = tuple((item.amount, item.script) for item in tx.outputs)
    if actual != target.expected_outputs[bits[2]]:
        violations.append('exact_action_outputs')
    if tx.outputs[0].amount > target.policy_cap:
        violations.append('retained_parent_cap')
    if (tx.version, tx.locktime, tx.inputs[0].sequence) != (2, 0, 0xfffffffd):
        violations.append('transaction_context')
    if target.stage.amount - sum(item.amount for item in tx.outputs) != 2000:
        violations.append('fixed_fee')
    expected_context = (target.stage.state, target.stage.authority, target.stage.state_root, target.stage.grant)
    if tuple(witness[:4]) != expected_context:
        violations.append('state_or_grant_binding')
    return tuple(violations)


def evaluate(backend: tuple, target: Target, payload: bytes) -> dict:
    _, _, _, execute, digest, failure = backend
    if type(payload) is not bytes:
        raise TypeError('candidate interface requires bytes')
    result = {'schema': 'BA-CPA-02/score-v1', 'target_id': target.target_id,
              'candidate_sha256': hashlib.sha256(payload).hexdigest(), 'evidence_mode': target.mode,
              'outcome': 'malformed_candidate', 'target_bound': False, 'backend_accepted': None,
              'parent_policy_allowed': None, 'parent_violations': [], 'attack_credit': False,
              'planted_counterexample': False, 'native_node_verified': False, 'HF_verified': False}
    try:
        tx, witness = decode(backend, target, payload)
    except CandidateError as error:
        result['reason'] = str(error)
        return result
    raw, txid = tx.serialize([witness])
    result.update(raw_transaction=raw, transaction_id=txid)
    supplied = tx.inputs[0]
    if (supplied.txid[::-1].hex(), supplied.index) != (target.txid, target.vout):
        result.update(outcome='target_mismatch', reason='outpoint')
        return result
    if witness[-2] != target.stage.leaf.script or witness[-1] != target.control:
        result.update(outcome='target_mismatch', reason='locking_path')
        return result
    violations = policy_violations(target, tx, witness)
    result.update(target_bound=True, parent_policy_allowed=not violations,
                  parent_violations=list(violations), payout_sats=tx.outputs[0].amount,
                  cap_excess_sats=max(0, tx.outputs[0].amount - target.policy_cap))
    try:
        accepted = execute(target.stage.leaf.script, witness[:-2], digest(tx, target.stage.leaf.script)) == [b'\x01']
    except failure as error:
        result['reason'] = str(error)
        accepted = False
    result['backend_accepted'] = accepted
    if not accepted:
        result['outcome'] = 'script_rejected'
    elif not violations:
        result['outcome'] = 'authorized'
    elif target.mode == 'planted_guard_mutant':
        result.update(outcome='planted_counterexample', planted_counterexample=True)
    else:
        result.update(outcome='cpa_counterexample', attack_credit=True)
    return result
