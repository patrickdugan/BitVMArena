"""Bounded candidate checks against a freshly funded, evaluator-owned regtest coin.

Invoked by run_native.py after source and executable capture. No external RPC
endpoint, existing data directory, wallet, or production network is accepted.
"""
from __future__ import annotations

import argparse
from collections import Counter
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import candidate_search as search
import fixed_target as ft

GENESIS = '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'
MAX_PROPOSALS = 32


class EvidenceError(ValueError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise EvidenceError(reason)


def admission_result(observed, txid: str) -> bool:
    require(type(observed) is list and len(observed) == 1, 'one admission record required')
    row = observed[0]
    require(type(row) is dict and row.get('txid') == txid, 'admission transaction mismatch')
    require(type(row.get('allowed')) is bool, 'typed admission verdict required')
    if not row['allowed']:
        require(type(row.get('reject-reason')) is str and bool(row['reject-reason']),
                'rejection reason missing')
    return row['allowed']


def check_coin(base, target, coin) -> None:
    require(type(coin) is dict, 'original funded coin unavailable')
    require(type(coin.get('confirmations')) is int and coin['confirmations'] >= 1,
            'confirmed funding required')
    require(base.satoshis(coin.get('value')) == target.stage.amount, 'funded amount changed')
    script = coin.get('scriptPubKey')
    require(type(script) is dict and script.get('hex') == target.script_pubkey.hex(),
            'funded authority changed')


def snapshot(rpc) -> dict:
    require(rpc('getconnectioncount') == 0, 'unexpected peer')
    return {'height': rpc('getblockcount'), 'tip': rpc('getbestblockhash')}


def proposals(backend, target):
    """Public deterministic cases for this native smoke campaign; no hidden labels."""
    yield 'honest_probe', search.proposal()
    yield 'child_over_cap', search.proposal((1, 1, 1))
    yield 'permission_denied', search.proposal((0, 1, 0))
    for field, width in (('parent_id', 32), ('current_state', 32), ('grant_id', 32),
                         ('child_statement', 32), ('outpoint', 36)):
        yield 'replace_' + field, search.proposal(edits=(
            {'op': 'witness', 'field': field, 'hex': '00' * width},))
    recipient = (b'\x51\x20' + backend[2].RECIPIENTS[1]).hex()
    for name, edit in (
        ('payout_6999', {'op': 'output_value', 'index': 0, 'value': 6999}),
        ('payout_7001', {'op': 'output_value', 'index': 0, 'value': 7001}),
        ('recipient', {'op': 'output_script', 'index': 0, 'hex': recipient}),
        ('successor', {'op': 'output_script', 'index': 1, 'hex': target.script_pubkey.hex()}),
        ('successor_value', {'op': 'output_value', 'index': 1, 'value': 90999}),
        ('output_order', {'op': 'swap_outputs'}),
        ('version', {'op': 'version', 'value': 1}),
        ('locktime', {'op': 'locktime', 'value': 1}),
        ('sequence', {'op': 'sequence', 'value': 0xfffffffe}),
        ('foreign_outpoint', {'op': 'vout', 'value': target.vout + 1}),
        ('foreign_script', {'op': 'locking_script', 'hex': '51'}),
        ('foreign_control', {'op': 'control', 'hex': '51'}),
    ):
        yield name, search.proposal(edits=(edit,))
    gate = next(i for i, (_, record) in enumerate(target.stage.program.records) if record[0] == 2)
    value = backend[1].trace(target.stage.program, (1, 1, 0))[gate]
    yield 'broken_gate', search.proposal(edits=({'op': 'gate', 'index': gate,
                                               'hex': '' if value else '01'},))
    yield 'stale_digest', search.proposal(edits=({'op': 'locktime', 'value': 1},), refresh=False)
    yield 'malformed_json', b'{'
    yield 'honest_after_rejections', search.proposal()


class NativeTarget:
    """One host-created funded target; step accepts only bounded proposal bytes."""
    def __init__(self, backend, target, node, miner_address: str, output: Path):
        self.backend, self.target, self.node = backend, target, node
        self.miner_address, self.output = miner_address, output
        self._events = []
        self.consumed = False
        check_coin(backend[2], target, node.rpc('gettxout', [target.txid, target.vout]))

    @property
    def events(self) -> list[dict]:
        return deepcopy(self._events)

    def step(self, payload: bytes, *, finalize: bool = False) -> dict:
        if type(payload) is not bytes or len(payload) > search.PROPOSAL_LIMIT or type(finalize) is not bool:
            raise ft.CandidateError('bounded bytes and boolean finalize required')
        require(len(self._events) < MAX_PROPOSALS, 'native proposal budget exhausted')
        require(not self.consumed, 'native target already consumed')
        base, rpc = self.backend[2], self.node.rpc
        event = {'index': len(self._events), 'target_id': self.target.target_id,
                 'proposal_hex': payload.hex(), 'finalize': finalize,
                 'native_admission_checked': False, 'native_block_checked': False,
                 'confirmed_this_event': False, 'confirmed_beneficiary_sats': 0,
                 'unauthorized_release_sats': 0, 'diverted_sats': 0, 'HF_verified': False}
        self._events.append(event)
        def execute_candidate():
            check_coin(base, self.target, rpc('gettxout', [self.target.txid, self.target.vout]))
            event['before'] = snapshot(rpc)
            try:
                candidate = search.reconstruct(self.backend, self.target, payload)
            except ft.CandidateError as error:
                event.update(outcome='invalid_proposal', reason=str(error))
                return event
            event['candidate_json'] = candidate.decode('ascii')
            reference = ft.evaluate(self.backend, self.target, candidate)
            event['reference'] = reference
            if reference['target_bound'] is not True:
                event['outcome'] = 'host_rejected'
                return event
            tx, witness = ft.decode(self.backend, self.target, candidate)
            raw, txid = tx.serialize([witness])
            event.update(raw_transaction=raw, transaction_id=txid)
            admission = rpc('testmempoolaccept', [[raw]])
            event.update(admission=admission, native_admission_checked=True)
            accepted = admission_result(admission, txid)
            event['native_allowed'] = accepted
            if accepted and finalize:
                # Inclusion is checked against the exact serialized transaction.
                observed_id = rpc('sendrawtransaction', [raw])
                event['broadcast_transaction_id'] = observed_id
                require(observed_id == txid, 'broadcast transaction mismatch')
                block = rpc('generatetoaddress', [1, self.miner_address])[0]
                event['block_hash'] = block
                decoded = rpc('getblock', [block, 2])
                matching = [item for item in decoded['tx'] if item['txid'] == txid]
                require(len(matching) == 1 and matching[0].get('hex') == raw,
                        'confirmed transaction bytes differ')
                require(rpc('gettxout', [self.target.txid, self.target.vout]) is None,
                        'confirmed target remained unspent')
                event.update(native_block_checked=True, confirmed_this_event=True)
                self.consumed = True
                if reference['parent_policy_allowed'] is True:
                    event.update(outcome='authorized_confirmation', confirmed_beneficiary_sats=tx.outputs[0].amount)
                else:
                    allowed = {script for _, script in self.target.expected_outputs[0]}
                    event.update(outcome='native_policy_counterexample',
                                 unauthorized_release_sats=sum(item.amount for item in tx.outputs),
                                 diverted_sats=sum(item.amount for item in tx.outputs if item.script not in allowed))
            elif accepted:
                event['outcome'] = 'admission_only'
            else:
                try:
                    result = rpc('sendrawtransaction', [raw])
                    event['unexpected_broadcast_acceptance'] = result
                    raise EvidenceError('rejected candidate entered the mempool')
                except base.RpcError as error:
                    event['broadcast_error'] = error.error
                    require(error.error.get('code') == -26, 'unrelated broadcast failure')
                try:
                    result = rpc('generateblock', [self.miner_address, [raw]])
                    event['unexpected_block_acceptance'] = result
                    raise EvidenceError('rejected candidate entered a block')
                except base.RpcError as error:
                    event['block_error'] = error.error
                    require(error.error.get('code') == -25 and
                            'block-script-verify-flag-failed' in error.error.get('message', ''),
                            'block failure did not reach Script validation')
                    event['native_block_checked'] = True
                event['outcome'] = 'native_script_rejected'
            require(accepted is reference['backend_accepted'], 'native/reference admission mismatch')
            return event

        try:
            execute_candidate()
        except Exception as error:
            event['error'] = f'{type(error).__name__}: {error}'
            raise
        finally:
            # Preserve partial failures and all raw evidence before propagating.
            try:
                event['after'] = snapshot(rpc)
                if not self.consumed:
                    if 'before' in event:
                        require(event['after'] == event['before'], 'probe or rejection changed the applied tip')
                    check_coin(base, self.target, rpc('gettxout', [self.target.txid, self.target.vout]))
            except Exception as error:
                event['boundary_error'] = f'{type(error).__name__}: {error}'
                raise
            finally:
                (self.output / f"event-{event['index']:03d}.json").write_text(
                    json.dumps(event, sort_keys=True, indent=2) + '\n')
        return deepcopy(event)


def campaign(backend, binary: Path, output: Path) -> dict:
    base, machine = backend[2], backend[1]
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema': 'BA-CPA-05/native-candidates-v1', 'status': 'running',
              'source_pin': '24a5593350f42efc8a96047aa9e7e114fa22cb08',
              'binary_sha256': sha256(binary.read_bytes()).hexdigest(),
              'model_generated_run': False, 'HF_verifier_run': False,
              'execution_layer': 'native bitcoin-rs TXCOMMIT/CAT isolated regtest'}
    node = None
    with tempfile.TemporaryDirectory(prefix='cpa-native-candidates-') as tmp:
        root = Path(tmp)
        try:
            node = base.Node(binary, root)
            info = node.start()
            require(info['blocks'] == 0 and info['bestblockhash'] == GENESIS, 'fresh regtest genesis required')
            rpc = node.rpc
            stage = machine.compile_machine()
            miner = base.Leaf(b'\x51')
            miner_script, miner_control = miner.output()
            address = base.address(miner_script[2:])
            blocks = rpc('generatetoaddress', [101, address])
            coinbase = rpc('getblock', [blocks[0], 2])['tx'][0]
            origin = next(o for o in coinbase['vout'] if o['scriptPubKey']['hex'] == miner_script.hex())
            amount = base.satoshis(origin['value'])
            funding = base.Tx((base.Input(bytes.fromhex(coinbase['txid'])[::-1], origin['n'], amount, miner_script),),
                              (base.Output(100_000, stage.leaf.output()[0]),
                               base.Output(amount - 102_000, miner_script)))
            raw, txid = funding.serialize([[miner.script, miner_control]])
            require(rpc('sendrawtransaction', [raw]) == txid, 'funding transaction mismatch')
            block = rpc('generatetoaddress', [1, address])[0]
            require(txid in rpc('getblock', [block])['tx'], 'funding absent from block')
            target = ft.freeze(backend, stage, txid=txid, vout=0)
            report.update(target=target.public(), funding={'raw_transaction': raw, 'txid': txid,
                          'block': block, 'height': rpc('getblockcount'),
                          'coinbase_txid': coinbase['txid'], 'coinbase_block': blocks[0]})
            (output / 'funding.json').write_text(json.dumps(report['funding'], indent=2) + '\n')
            evaluator = NativeTarget(backend, target, node, address, output)
            plan = list(proposals(backend, target))
            require(len(plan) + 1 <= MAX_PROPOSALS, 'campaign exceeds evaluator budget')
            for name, payload in plan:
                observed = evaluator.step(payload)
                report.setdefault('cases', []).append({'name': name, 'event_index': observed['index']})
            confirmed = evaluator.step(search.proposal(), finalize=True)
            report['cases'].append({'name': 'honest_finalize', 'event_index': confirmed['index']})
            require(confirmed['outcome'] == 'authorized_confirmation', 'honest finalization failed')
            before = snapshot(rpc)
            node.stop()
            node.start()
            require(snapshot(rpc) == before, 'restart changed committed tip')
            require(rpc('gettxout', [target.txid, target.vout]) is None, 'restart restored spent target')
            for index, (value, script) in enumerate(target.expected_outputs[0]):
                observed = rpc('gettxout', [confirmed['transaction_id'], index])
                require(type(observed) is dict and base.satoshis(observed['value']) == value and
                        observed['scriptPubKey']['hex'] == script.hex(), 'restart changed authorized outputs')
            events = evaluator.events
            report.update(status='passed', proposals=len(events),
                          outcomes=dict(sorted(Counter(e['outcome'] for e in events).items())),
                          admission_checks=sum(e['native_admission_checked'] for e in events),
                          block_checks=sum(e['native_block_checked'] for e in events),
                          confirmed_transitions=sum(e['confirmed_this_event'] for e in events),
                          confirmed_beneficiary_sats=sum(e['confirmed_beneficiary_sats'] for e in events),
                          successor_sats=91_000, transaction_fee_sats=2_000,
                          unauthorized_release_sats=sum(e['unauthorized_release_sats'] for e in events),
                          diverted_sats=sum(e['diverted_sats'] for e in events),
                          restart_verified=True, final_height=before['height'], peers=0)
        except Exception as error:
            report.update(status='failed', error=f'{type(error).__name__}: {error}')
            raise
        finally:
            try:
                if node is not None:
                    node.stop()
            except Exception as error:
                report.update(status='failed', cleanup_error=f'{type(error).__name__}: {error}')
                raise
            finally:
                if node is not None:
                    node.log.close()
                    report['node_exit_codes'] = node.exit_codes
                    (output / 'node.log').write_bytes((root / 'node.log').read_bytes())
                (output / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bitcoin-rs', type=Path, required=True)
    p.add_argument('--binary', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    require(__debug__, 'optimized Python unsupported')
    sys.path.insert(0, str(a.bitcoin_rs / 'scripts/research'))
    import bitvm_authority_enumeration as upstream
    print(json.dumps(campaign(upstream.load_backend(a.bitcoin_rs), a.binary, a.out), indent=2))


if __name__ == '__main__':
    main()
