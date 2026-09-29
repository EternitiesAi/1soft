#!/usr/bin/env python3
"""Run a private one-host protocol-4 money and validator-change scenario.

This gate uses disposable fixture identities and no public RPC or real funds.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'src'), str(ROOT/'scripts')]
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from commit_verifier import encode
from native_core import NativeLedger, address, canonical, digest, public, sign
from registry_rules_core import GENESIS_FORMAT, RegistryRules
from validator_sets_core import ValidatorSet, canonical_roster, validator_updates
from run_devnet import free_ports, patch_toml, rpc, wait_until

PIN = '0.38.25'
MAX_LOG = 1_048_576


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True, timeout=10).strip()


def key_from_genesis(row):
    return base64.b64decode(row['pub_key']['value']).hex()


def app_query(port, path):
    answer = rpc(port, 'abci_query', {'path': path, 'prove': False})['response']
    if int(answer['code']) != 0:
        raise RuntimeError('protocol-4 application query rejected: ' + path)
    return json.loads(base64.b64decode(answer['value']))


def app_state(port):
    return app_query(port, '/registry-state')


def payment(genesis, key, recipient, *, nonce, units, valid_until):
    ledger = NativeLedger(':memory:', genesis)
    try:
        body = ledger.body(address(public(key)), nonce,
                           {'type': 'transfer', 'to': recipient, 'units': units},
                           valid_until=valid_until)
    finally:
        ledger.close()
    return canonical(sign(key, body))


def block_header(port, height):
    return rpc(port, 'block', {'height': str(height)})['block']['header']


def signed_header(port, height):
    return rpc(port, 'commit', {'height': str(height)})['signed_header']['header']


def rpc_validator_set(port, height):
    page = rpc(port, 'validators', {'height': str(height), 'per_page': '100'})
    rows = page['validators']
    if int(page['total']) != len(rows):
        raise AssertionError('validator RPC result was truncated')
    return {row['address'].lower(): int(row['voting_power']) for row in rows}


def stop(process):
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def run(engine, output, expected_sha256):
    output = Path(output).resolve()
    if output.exists() or output.with_name(output.name + '.logs').exists():
        raise FileExistsError('report or log path already exists')
    output.parent.mkdir(parents=True, exist_ok=True)
    binary = Path(engine).resolve()
    report = {'schema': 1, 'status': 'unassessed', 'source_commit': git('rev-parse', 'HEAD'),
              'source_tree': git('rev-parse', 'HEAD^{tree}'), 'source_dirty_before': bool(git('status', '--porcelain')),
              'engine_required': PIN, 'engine_required_sha256': expected_sha256,
              'checks': [], 'scope': 'one-host disposable protocol-4 money plus registry network',
              'native_payments_integrated': False, 'independent_operators': False,
              'public_network_ready': False, 'real_funds_ready': False,
              'started_at': datetime.now(timezone.utc).isoformat()}
    def check(name, passed, details=None):
        report['checks'].append({'name': name, 'passed': bool(passed), 'details': details})
        if not passed:
            raise AssertionError(name)
    if not binary.is_file():
        report['reason'] = 'pinned engine absent'
        output.write_text(json.dumps(report, indent=2) + '\n')
        return report
    if len(expected_sha256) != 64 or any(c not in '0123456789abcdef' for c in expected_sha256):
        raise ValueError('expected engine SHA-256 must be canonical lowercase hex')
    report['engine_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
    if report['engine_sha256'] != expected_sha256:
        report['status'] = 'failed'
        report['reason'] = 'engine binary differs from external pin'
        output.write_text(json.dumps(report, indent=2) + '\n')
        return report
    version = subprocess.check_output([str(binary), 'version'], text=True, timeout=10).strip()
    if version.lstrip('v') != PIN:
        raise ValueError('engine version differs')
    report['engine_version'] = version
    engines, apps, handles = {}, {}, []
    runtime = None
    temp_handle = None
    try:
        temp_handle = tempfile.TemporaryDirectory(prefix='one-protocol4-engine-')
        runtime = Path(temp_handle.name)
        homes = runtime/'nodes'
        subprocess.run([str(binary), 'testnet', '--v', '4', '--n', '1', '--o', str(homes), '--initial-height', '1'],
                       check=True, capture_output=True, text=True, timeout=40)
        for item in homes.rglob('*'):
            os.chmod(item, 0o700 if item.is_dir() else 0o600)
        chain = 'one-protocol4-' + os.urandom(6).hex()
        rootgen = json.loads((homes/'node0/config/genesis.json').read_text())
        initial = rootgen['validators']
        if len(initial) != 4:
            raise AssertionError('engine testnet did not create exactly four initial validators')
        newcomer = {'pub_key': json.loads((homes/'node4/config/priv_validator_key.json').read_text())['pub_key'],
                    'power': '9'}
        for row in initial:
            row['power'] = '10'
        newcomer['power'] = '9'
        old = canonical_roster([{'public_key': key_from_genesis(row), 'power': 10} for row in initial])
        after = canonical_roster([{'public_key': key_from_genesis(row), 'power': power}
                                  for row, power in zip(initial[1:] + [newcomer], (12, 10, 10, 9))])
        admins = [Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(171, 175)]
        payers = [Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in (1, 2)]
        registry = {'schema': 1, 'format': GENESIS_FORMAT, 'mode': 'development-only',
                    'chain_id': chain, 'validators': old,
                    'administrators': {'format': 'threshold-ed25519-v1',
                                       'public_keys': sorted(public(k) for k in admins), 'threshold': 3},
                    'minimum_delay_blocks': 2, 'cooldown_blocks': 1,
                    'minimum_validators': 4, 'maximum_power_bps': 3333}
        genesis = {'chain_id': chain, 'asset': 'ONE', 'fee': 1,
                   'allocations': [{'public_key': public(k), 'units': 100_000} for k in payers],
                   'protocol_version': 4, 'validator_registry': registry}
        rules = RegistryRules(registry, bound_genesis_sha256=digest(genesis))
        gfile = runtime/'protocol4-genesis.json'
        gbytes = encode(genesis)
        gfile.write_bytes(gbytes)
        ghash = hashlib.sha256(gbytes).hexdigest()
        rootgen.update(chain_id=chain, initial_height='1', app_state=genesis, validators=initial)
        rootgen['consensus_params']['block'].update(max_bytes='1048576', max_gas='-1')
        public_genesis = output.parent/'protocol4-engine-public-genesis.json'
        if public_genesis.exists():
            raise FileExistsError('public genesis output already exists')
        public_genesis.write_text(json.dumps(rootgen, indent=2) + '\n')
        report['engine_genesis_sha256'] = hashlib.sha256(public_genesis.read_bytes()).hexdigest()
        report['protocol4_genesis_sha256'] = ghash
        report['protocol4_canonical_genesis_sha256'] = digest(genesis)
        report['old_roster_hash'] = ValidatorSet.parse(old).hash
        report['new_roster_hash'] = ValidatorSet.parse(after).hash
        report['expected_updates'] = validator_updates(ValidatorSet.parse(old), ValidatorSet.parse(after))
        ports = free_ports(10)
        p2p, http = ports[:5], ports[5:]
        ids = [subprocess.check_output([str(binary), 'show-node-id', '--home', str(homes/f'node{i}')],
                                       text=True, timeout=10).strip() for i in range(5)]
        for i in range(5):
            home = homes/f'node{i}'
            (home/'config/genesis.json').write_text(json.dumps(rootgen, indent=2) + '\n')
            socket_dir = runtime/f'app{i}'
            socket_dir.mkdir(mode=0o700)
            socket = socket_dir/'a.sock'
            conf = home/'config/config.toml'
            conf.write_text(patch_toml(conf.read_text(), {
                'proxy_app': f'unix://{socket}', 'abci': 'socket',
                'rpc.laddr': f'tcp://127.0.0.1:{http[i]}', 'rpc.unsafe': False,
                'p2p.laddr': f'tcp://127.0.0.1:{p2p[i]}',
                'p2p.persistent_peers': ','.join(f'{ids[j]}@127.0.0.1:{p2p[j]}' for j in range(5) if j != i),
                'p2p.addr_book_strict': False, 'p2p.allow_duplicate_ip': True, 'p2p.pex': False,
                'consensus.timeout_commit': '500ms', 'mempool.max_tx_bytes': 65536,
            }))
        def start_app(i):
            db = runtime/f'app{i}/state.sqlite'
            sock = runtime/f'app{i}/a.sock'
            if sock.exists():
                if i in apps and apps[i].poll() is None:
                    raise AssertionError('existing ABCI app still owns socket')
                sock.unlink()
            logfile = (runtime/f'app{i}.log').open('ab')
            handles.append(logfile)
            command = [sys.executable, str(ROOT/'scripts/serve_abci_p4.py'),
                       '--genesis', str(gfile), '--genesis-sha256', ghash,
                       '--database', str(db), '--socket', str(sock)]
            apps[i] = subprocess.Popen(command, stdout=logfile, stderr=logfile)
            wait_until(lambda: sock.exists() and apps[i].poll() is None, 15)
        def start_engine(i):
            logfile = (runtime/f'engine{i}.log').open('ab')
            handles.append(logfile)
            engines[i] = subprocess.Popen([str(binary), 'start', '--home', str(homes/f'node{i}')],
                                          stdout=logfile, stderr=logfile)
        def height(i):
            if engines[i].poll() is not None:
                raise RuntimeError(f'engine node{i} exited {engines[i].returncode}')
            return int(rpc(http[i], 'status')['sync_info']['latest_block_height'])
        for i in range(5):
            start_app(i)
        for i in range(5):
            start_engine(i)
        wait_until(lambda: all(height(i) >= 2 for i in range(5)), 80)
        check('four validators and one nonvalidator engine advance',
              len({p.pid for p in engines.values()}) == 5 and all(height(i) >= 2 for i in range(5)))
        current = height(0)
        payer_address = address(public(payers[0]))
        recipient_address = address(public(payers[1]))
        payment_wire = payment(genesis, payers[0], recipient_address,
                               nonce=0, units=7, valid_until=current+30)
        payment_hash = hashlib.sha256(payment_wire).hexdigest()
        payment_admission = rpc(http[0], 'broadcast_tx_sync',
                                {'tx': base64.b64encode(payment_wire).decode()})
        check('protocol-4 native payment passes real-engine CheckTx',
              int(payment_admission['code']) == 0)
        payment_receipt = wait_until(lambda: rpc(http[0], 'tx',
            {'hash': base64.b64encode(bytes.fromhex(payment_hash)).decode()})
            if height(0) > current else None, 45)
        check('protocol-4 native payment commits with success',
              int(payment_receipt['tx_result']['code']) == 0,
              {'height': int(payment_receipt['height']), 'tx_hash': payment_hash})
        payment_height = int(payment_receipt['height'])
        payment_state = app_query(http[0], '/state')
        balances = {row[0]: row[4] for row in payment_state['native']['accounts']}
        check('money balances and receipt live in composite application state',
              balances[payer_address] == 99_992 and balances[recipient_address] == 100_007
              and len(payment_state['native']['receipts']) == 1 and
              payment_state['registry']['sequence'] == 0)
        wait_until(lambda: height(0) >= payment_height + 1, 20)
        check('signed header binds committed payment AppHash',
              signed_header(http[0], payment_height + 1)['app_hash'].lower() ==
              app_query(http[0], f'/block/{payment_height}')['app_hash'])
        current = height(0)
        state = app_state(http[0])
        emission = current + 10
        operation = {'kind': 'schedule', 'emitted_height': emission, 'target_validators': after}
        body = rules.body(state, operation, valid_from=1, valid_until=current + 6)
        material = rules.signing_bytes(body)
        approvals = sorted([{'public_key': public(k), 'signature': k.sign(material).hex()} for k in admins[:3]],
                           key=lambda row: row['public_key'])
        wire = encode({'body': body, 'approvals': approvals})
        txhash = hashlib.sha256(wire).hexdigest()
        observed = rpc(http[0], 'broadcast_tx_sync', {'tx': base64.b64encode(wire).decode()})
        check('authorized action passes real-engine CheckTx', int(observed['code']) == 0)
        committed = wait_until(lambda: rpc(http[0], 'tx',
                                             {'hash': base64.b64encode(bytes.fromhex(txhash)).decode()})
                               if height(0) > current else None, 45)
        check('authorized action included with success', int(committed['tx_result']['code']) == 0,
              {'height': int(committed['height']), 'tx_hash': txhash})
        scheduled = int(committed['height'])
        check('action inclusion leaves emission delay', emission >= scheduled + 2)
        scheduled_state = app_query(http[0], '/state')
        check('admin action and existing payment share one committed AppHash',
              scheduled_state['registry']['sequence'] == 1 and
              len(scheduled_state['native']['receipts']) == 1 and
              app_query(http[0], f'/block/{scheduled}')['app_hash'] !=
              app_query(http[0], f'/block/{payment_height}')['app_hash'])
        wait_until(lambda: all(height(i) >= emission + 3 for i in range(5)), 100)
        header_next = signed_header(http[0], emission + 1)
        header_active = signed_header(http[0], emission + 2)
        emitted_app_hash = app_query(http[0], f'/block/{emission}')['app_hash']
        activated_app_hash = app_query(http[0], f'/block/{emission + 1}')['app_hash']
        check('H+1 signed header commits combined payment/registry AppHash',
              header_next['app_hash'].lower() == emitted_app_hash,
              {'height': emission + 1, 'observed_app_hash': header_next['app_hash'].lower()})
        check('H+2 signed header commits combined post-emission AppHash',
              header_active['app_hash'].lower() == activated_app_hash,
              {'height': emission + 2, 'observed_app_hash': header_active['app_hash'].lower()})
        expected_set = {v.address.hex(): v.power for v in ValidatorSet.parse(after).validators}
        check('H+1 signed header announces new next set',
              header_next['next_validators_hash'].lower() == report['new_roster_hash'],
              {'height': emission + 1, 'observed_hash': header_next['next_validators_hash'].lower()})
        check('H+2 signed header uses new active set',
              header_active['validators_hash'].lower() == report['new_roster_hash'],
              {'height': emission + 2, 'observed_hash': header_active['validators_hash'].lower()})
        observed_set = rpc_validator_set(http[0], emission + 2)
        check('H+2 Comet validator RPC shows exact new addresses and powers',
              observed_set == expected_set,
              {'height': emission + 2, 'observed': observed_set})
        check('H+3 engine and registry accept new-set last-commit context',
              signed_header(http[0], emission + 3)['validators_hash'].lower() == report['new_roster_hash']
              and all(height(i) >= emission + 3 for i in range(5)),
              {'height': emission + 3})
        votes = app_query(http[0], f'/block/{emission + 3}')['last_commit_votes']
        observed_votes = {v['address']: v['power'] for v in votes}
        committed_power = sum(v['power'] for v in votes if v['block_id_flag'] == 2)
        check('H+3 actual FinalizeBlock last-commit votes use new roster',
              len(observed_votes) == len(votes) and observed_votes == expected_set and
              committed_power * 3 > sum(expected_set.values()) * 2,
              {'height': emission + 3, 'votes': votes})
        check('candidate validator tracked chain before admission', height(4) >= emission + 3)
        stop(engines.pop(0))
        stop(apps.pop(0))
        remaining_start = max(height(i) for i in (1, 2, 3, 4))
        wait_until(lambda: all(height(i) >= remaining_start + 2 for i in (1, 2, 3, 4)), 80)
        check('chain advances after removed validator stops',
              all(height(i) >= remaining_start + 2 for i in (1, 2, 3, 4)))
        restart_base = height(1)
        stop(engines.pop(1))
        stop(apps.pop(1))
        start_app(1)
        start_engine(1)
        wait_until(lambda: height(1) >= restart_base + 2, 80)
        check('new-set validator resumes with same database and node home',
              height(1) >= restart_base + 2 and
              rpc_validator_set(http[1], height(1)) == expected_set,
              {'restart_height': restart_base, 'resumed_height': height(1)})
        check('all live combined states agree on active set and first payment',
              all(app_state(http[i])['active_hash'] == report['new_roster_hash'] and
                  len(app_query(http[i], '/state')['native']['receipts']) == 1
                  for i in (1, 2, 3, 4)))
        for i in (1, 2, 3, 4):
            result = app_query(http[i], f'/block/{emission}')
            check(f'node{i} committed exact emission response',
                  result['validator_updates'] == report['expected_updates'])
        later_height = max(height(i) for i in (1, 2, 3, 4))
        later_wire = payment(genesis, payers[0], recipient_address,
                             nonce=1, units=5, valid_until=later_height+20)
        later_hash = hashlib.sha256(later_wire).hexdigest()
        admission = rpc(http[1], 'broadcast_tx_sync', {'tx': base64.b64encode(later_wire).decode()})
        check('payment after validator turnover passes real-engine CheckTx',
              int(admission['code']) == 0)
        later_receipt = wait_until(lambda: rpc(http[1], 'tx',
            {'hash': base64.b64encode(bytes.fromhex(later_hash)).decode()}), 45)
        check('payment after validator turnover commits',
              int(later_receipt['tx_result']['code']) == 0,
              {'height': int(later_receipt['height']), 'tx_hash': later_hash})
        final_state = app_query(http[1], '/state')
        final_balances = {row[0]: row[4] for row in final_state['native']['accounts']}
        check('post-turnover money and registry remain in one committed state',
              final_balances[payer_address] == 99_986 and
              final_balances[recipient_address] == 100_012 and
              len(final_state['native']['receipts']) == 2 and
              final_state['registry']['active_hash'] == report['new_roster_hash'])
        report['native_payments_integrated'] = True
        report['payment_before_height'] = payment_height
        report['payment_after_height'] = int(later_receipt['height'])
        report['emission_height'] = emission
        report['scheduled_height'] = scheduled
        report['status'] = 'passed'
    except BaseException as exc:
        report['status'] = 'failed'
        report['reason'] = f'{type(exc).__name__}: {exc}'
    finally:
        for process in list(engines.values()):
            stop(process)
        for process in list(apps.values()):
            stop(process)
        for handle in handles:
            handle.close()
        if runtime is not None and runtime.exists():
            logs = output.with_name(output.name + '.logs')
            logs.mkdir(mode=0o700)
            entries = []
            for path in sorted(runtime.glob('*.log')):
                raw = path.read_bytes()
                truncated = len(raw) > MAX_LOG
                if b'-----BEGIN ' in raw or b'PRIVATE KEY' in raw:
                    report['status'] = 'failed'
                    report['reason'] = 'sensitive material found in process log'
                    raw = b'[suppressed sensitive log]\n'
                else:
                    if truncated:
                        raw = raw[:MAX_LOG]
                    raw = raw.replace(str(runtime).encode(), b'<private-run>')
                target = logs/path.name
                target.write_bytes(raw)
                entries.append({'name': path.name, 'sha256': hashlib.sha256(raw).hexdigest(),
                                'bytes': len(raw), 'truncated': truncated,
                                'sanitized': True})
            (logs/'manifest.json').write_text(json.dumps(entries, indent=2) + '\n')
            report['logs'] = entries
        if temp_handle is not None:
            temp_handle.cleanup()
        report['source_dirty_after'] = bool(git('status', '--porcelain'))
        report['source_qualified'] = (not report['source_dirty_before'] and
                                      not report['source_dirty_after'] and
                                      report['source_commit'] == git('rev-parse', 'HEAD'))
        report['engine_sha256_after'] = hashlib.sha256(binary.read_bytes()).hexdigest()
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        output.write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', required=True)
    parser.add_argument('--engine-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.engine, args.output, args.engine_sha256)
    print(json.dumps({'status': result['status'], 'checks': len(result['checks']),
                      'reason': result.get('reason'), 'report': str(args.output)}))
    raise SystemExit(0 if result['status'] == 'passed' else 1)
