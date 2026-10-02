#!/usr/bin/env python3
"""Bounded one-host P4 client acceptance with real CometBFT and disposable funds.

The three process exits are client recovery drills, not node Commit crash tests.
All listeners are loopback; generated keys and databases stay in a private tempdir.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'src'), str(ROOT/'scripts'), str(ROOT/'tools/validator-transition/src')]
for component in ('protocol4-client', 'protocol4-wallet', 'protocol4-delivery', 'protocol4-custody', 'protocol4-explorer'):
    sys.path.insert(0, str(ROOT/'tools'/component/'src'))

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from block_application import encode, restore
from commit_verifier import header_hash
from native_core import address, canonical, digest, public, sign, FEE_ACCOUNT
from p4_delivery import P4Delivery, collect_evidence
from p4_evidence import POLICY_FORMAT
from p4_wallet import P4Wallet
from registry_rules_core import GENESIS_FORMAT, RegistryRules
from run_devnet import free_ports, patch_toml, rpc, wait_until
from run_protocol4_engine import git, key_from_genesis, app_query, stop, MAX_LOG, PIN
from validator_sets_core import ValidatorSet, canonical_roster


def process_fault(config_path, phase):
    """Exit only this child at the specified durable client boundary."""
    import p4_delivery as module
    cfg = json.loads(Path(config_path).read_bytes())
    root = Path(cfg['runtime'])
    with P4Delivery(root/'wallet.sqlite', root/'delivery.sqlite',
                    (root/'engine-genesis.json').read_bytes(), cfg['policy'], cfg['endpoint']) as delivery:
        if phase == 'after_claim':
            module.submit_once = lambda *args: os._exit(73)
        elif phase == 'after_submission':
            original = module.submit_once
            def submit(*args):
                original(*args)
                os._exit(74)
            module.submit_once = submit
        elif phase == 'after_wallet_sync':
            original = delivery.wallet.sync
            def sync(*args, **kwargs):
                original(*args, **kwargs)
                os._exit(75)
            delivery.wallet.sync = sync
            delivery.reconcile(cfg['decision_id'], payer=cfg['payer'], grant_id=cfg['grant'],
                               expected_revision=cfg['revision'])
            raise AssertionError('fault hook did not terminate child')
        else:
            raise ValueError('unsupported fault phase')
        delivery.send(cfg['review']['review'], cfg['review']['confirmation'])
        raise AssertionError('fault hook did not terminate child')


class Proxy:
    """Forward exact JSON RPC bytes, dropping only a successful CheckTx response."""
    def __init__(self, upstream):
        self.upstream = upstream
        self.drop_next = True
        self.submissions = []
        self.observations = []
        outer = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_POST(self):
                raw = self.rfile.read(int(self.headers['Content-Length']))
                request = json.loads(raw)
                conn = http.client.HTTPConnection('127.0.0.1', outer.upstream, timeout=3)
                try:
                    conn.request('POST', '/', raw, {'Content-Type': 'application/json'})
                    response = conn.getresponse()
                    body = response.read(8 * 1024 * 1024)
                    if request['method'] == 'broadcast_tx_sync':
                        wire = base64.b64decode(request['params']['tx'], validate=True)
                        result = json.loads(body)['result']
                        outer.submissions.append(wire)
                        dropped = outer.drop_next and type(result['code']) is int and result['code'] == 0
                        outer.observations.append({'wire_sha256': hashlib.sha256(wire).hexdigest(),
                            'upstream_result': result, 'downstream_dropped': dropped})
                        if dropped:
                            outer.drop_next = False
                            self.close_connection = True
                            self.connection.shutdown(socket.SHUT_RDWR)
                            self.connection.close()
                            return
                    self.send_response(response.status)
                    self.send_header('Content-Type', 'application/json')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                finally:
                    conn.close()
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=.05), daemon=True)
        self.thread.start()
        self.endpoint = f'http://127.0.0.1:{self.server.server_port}/'

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(3)


def run(engine, expected_sha256, output, *, key_rotation=False, custody_format=None, read_store_format=None):
    if custody_format is not None and (type(custody_format) is not int or custody_format != 3):
        raise ValueError("only explicit custody format 3 is qualified by this profile")
    if read_store_format is not None and (type(read_store_format) is not int or read_store_format != 2):
        raise ValueError('only explicit read-store format 2 is qualified by this profile')
    output = Path(output).resolve()
    if output.is_relative_to(ROOT):
        raise ValueError('acceptance output must be outside the source checkout')
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    binary = Path(engine).resolve()
    report = {'schema': 1, 'status': 'unassessed', 'checks': [], 'stages': [],
        'source_commit': git('rev-parse', 'HEAD'), 'source_tree': git('rev-parse', 'HEAD^{tree}'),
        'source_dirty_before': bool(git('status', '--porcelain')),
        'engine_required_sha256': expected_sha256, 'scope': 'eight local nodes, one host, disposable keys',
        'real_funds': False, 'independent_hosts': False, 'public_release_ready': False,
        'node_commit_crash_assessed': False, 'node_bootstrap_assessed': False,
        'started_at': datetime.now(timezone.utc).isoformat()}
    def check(name, condition, details=None):
        report['checks'].append({'name': name, 'passed': bool(condition), 'details': details})
        if not condition:
            raise AssertionError(name)
    apps, engines, handles = [], [], []
    proxy = wallet = delivery = runtime = temp = None
    try:
        if not binary.is_file():
            report['reason'] = 'pinned engine absent'
            return report
        observed = hashlib.sha256(binary.read_bytes()).hexdigest()
        check('engine matches independent SHA256 pin', len(expected_sha256) == 64 and observed == expected_sha256)
        report['engine_sha256'] = observed
        report['engine_version'] = subprocess.check_output([str(binary), 'version'], text=True).strip()
        check('engine version is pinned', report['engine_version'].lstrip('v') == PIN)
        temp = tempfile.TemporaryDirectory(prefix='one-p4-delivery-')
        runtime = Path(temp.name)
        homes = runtime/'nodes'
        subprocess.run([str(binary), 'testnet', '--v', '4', '--n', '4', '--o', str(homes)],
                       check=True, capture_output=True, timeout=40)
        for item in homes.rglob('*'):
            item.chmod(0o700 if item.is_dir() else 0o600)
        chain = 'one-p4-delivery-' + os.urandom(6).hex()
        rootgen = json.loads((homes/'node0/config/genesis.json').read_bytes())
        initial = rootgen['validators']
        for row in initial:
            row['power'] = '10'
        old = canonical_roster([{'public_key': key_from_genesis(r), 'power': 10} for r in initial])
        target = canonical_roster([{'public_key': key_from_genesis(json.loads(
            (homes/f'node{i}/config/priv_validator_key.json').read_bytes())), 'power': 10} for i in range(4, 8)])
        admins = [Ed25519PrivateKey.generate() for _ in range(4)]
        keys = {name: Ed25519PrivateKey.generate() for name in ('owner', 'merchant', 'raven', 'atlas', 'claim', 'decline')}
        payer, merchant = address(public(keys['owner'])), address(public(keys['merchant']))
        registry = {'schema': 1, 'format': GENESIS_FORMAT, 'mode': 'development-only', 'chain_id': chain,
            'validators': old, 'administrators': {'format': 'threshold-ed25519-v1',
            'public_keys': sorted(public(k) for k in admins), 'threshold': 3},
            'minimum_delay_blocks': 2, 'cooldown_blocks': 1, 'minimum_validators': 4, 'maximum_power_bps': 3333}
        genesis = {'chain_id': chain, 'asset': 'DEV', 'fee': 2, 'protocol_version': 4,
            'allocations': [{'public_key': public(keys['owner']), 'units': 1000},
                            {'public_key': public(keys['merchant']), 'units': 0}], 'validator_registry': registry}
        rules = RegistryRules(registry, bound_genesis_sha256=digest(genesis))
        gfile = runtime/'app-genesis.json'
        gfile.write_bytes(encode(genesis))
        rootgen.update(chain_id=chain, initial_height='1', app_state=genesis, validators=initial)
        rootgen['consensus_params']['block'].update(max_bytes='1048576', max_gas='-1')
        full_genesis = encode(rootgen)
        (runtime/'engine-genesis.json').write_bytes(full_genesis)
        (output/'engine-genesis.json').write_bytes(full_genesis)
        ports = free_ports(16)
        p2p, http = ports[:8], ports[8:]
        ids = [subprocess.check_output([str(binary), 'show-node-id', '--home', str(homes/f'node{i}')], text=True).strip() for i in range(8)]
        for i in range(8):
            home = homes/f'node{i}'
            (home/'config/genesis.json').write_bytes(full_genesis)
            private = runtime/f'app{i}'
            private.mkdir(mode=0o700)
            sock = private/'a.sock'
            conf = home/'config/config.toml'
            conf.write_text(patch_toml(conf.read_text(), {
                'proxy_app': f'unix://{sock}', 'abci': 'socket',
                'rpc.laddr': f'tcp://127.0.0.1:{http[i]}', 'rpc.unsafe': False,
                'p2p.laddr': f'tcp://127.0.0.1:{p2p[i]}',
                'p2p.persistent_peers': ','.join(f'{ids[j]}@127.0.0.1:{p2p[j]}' for j in range(8) if j != i),
                'p2p.addr_book_strict': False, 'p2p.allow_duplicate_ip': True, 'p2p.pex': False,
                'consensus.timeout_commit': '2s', 'mempool.max_tx_bytes': 65536}))
            log = (runtime/f'app{i}.log').open('wb'); handles.append(log)
            apps.append(subprocess.Popen([sys.executable, str(ROOT/'scripts/serve_abci_p4.py'),
                '--genesis', str(gfile), '--genesis-sha256', hashlib.sha256(gfile.read_bytes()).hexdigest(),
                '--database', str(private/'state.sqlite'), '--socket', str(sock)], stdout=log, stderr=log))
            wait_until(lambda: sock.exists(), 15)
        for i in range(8):
            log = (runtime/f'engine{i}.log').open('wb'); handles.append(log)
            engines.append(subprocess.Popen([str(binary), 'start', '--home', str(homes/f'node{i}')], stdout=log, stderr=log))
        def height(i=4):
            if engines[i].poll() is not None:
                raise RuntimeError(f'engine {i} exited')
            return int(rpc(http[i], 'status')['sync_info']['latest_block_height'])
        wait_until(lambda: all(height(i) >= 2 for i in range(8)), 80)
        check('four validators and four future validators advance', all(height(i) >= 2 for i in range(8)))
        report['initial_roster_hash'] = ValidatorSet.parse(old).hash
        report['replacement_roster_hash'] = ValidatorSet.parse(target).hash
        check('full replacement rosters are disjoint', not ({r['public_key'] for r in old} & {r['public_key'] for r in target}))
        def confirmed(wire, label):
            admission = rpc(http[4], 'broadcast_tx_sync', {'tx': base64.b64encode(wire).decode()})
            check(label + ' admitted', type(admission['code']) is int and admission['code'] == 0)
            result = wait_until(lambda: rpc(http[4], 'tx', {'hash': base64.b64encode(hashlib.sha256(wire).digest()).decode()}), 30)
            check(label + ' executed', result['tx_result']['code'] == 0, {'height': result['height']})
            return result
        setup = []
        for bid, names in (('studio', ('raven', 'atlas')), ('diagnostics', ('claim', 'decline'))):
            setup.append({'type': 'budget_create', 'id': bid, 'cap': 100, 'expires': 500, 'recipients': [merchant]})
            for name in names:
                setup.append({'type': 'grant', 'id': name, 'public_key': public(keys[name]), 'cap': 100,
                              'expires': 500, 'recipients': [merchant], 'budget_id': bid})
        for nonce, op in enumerate(setup):
            ledger = restore(genesis, app_query(http[4], '/state')['native'])
            try:
                wire = canonical(sign(keys['owner'], ledger.body(payer, nonce, op, valid_until=100)))
            finally:
                ledger.close()
            confirmed(wire, f'setup {nonce}')
            (output/f'setup-{nonce}.json').write_bytes(wire)
        first = rpc(http[4], 'commit', {'height': '1'})['signed_header']['header']
        policy = {'schema': 1, 'format': POLICY_FORMAT, 'genesis_sha256': hashlib.sha256(full_genesis).hexdigest(),
            'anchor_height': 1, 'anchor_hash': header_hash(first).hex(), 'anchor_time': first['time'],
            'trust_period_seconds': 3600, 'max_clock_drift_seconds': 5, 'expected_block_version': 11}
        (output/'policy.json').write_bytes(encode(policy))
        report['trust_origin'] = 'private operator-created genesis and first committed header of this disposable engine network'
        proxy = Proxy(http[4])
        wallet = P4Wallet(runtime/'wallet.sqlite', full_genesis, policy, create=True)
        proof = collect_evidence(proxy.endpoint, full_genesis, policy, time.time_ns())['evidence']
        wallet.sync(proof, expected_revision=None)
        delivery = P4Delivery(runtime/'wallet.sqlite', runtime/'delivery.sqlite', full_genesis, policy, proxy.endpoint, create=True)
        password = os.urandom(32)
        for name in ('raven', 'atlas', 'claim', 'decline'):
            path = runtime/f'{name}.pem'
            path.write_bytes(keys[name].private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.BestAvailableEncryption(password)))
            path.chmod(0o600)
        def selection(name):
            return {'payer': payer, 'grant_id': name}
        def sign_decision(name, units, valid_until=None):
            if valid_until is None:
                valid_until = wallet.status()['state_height'] + 30
            review = wallet.prepare(payer=payer, recipient=merchant, units=units, valid_until=valid_until, grant_id=name)
            return wallet.approve(review['review'], review['confirmation'], vault=runtime/f'{name}.pem', password=password)['decision_id']
        def rows():
            return tuple(wallet.db.iterdump())
        def stage(label):
            status = wallet.status()
            report['stages'].append({'stage': label, 'wallet': status, 'submissions': len(proxy.submissions)})
            return status
        def refused(action):
            try:
                action()
            except ValueError:
                return True
            return False
        raven = sign_decision('raven', 58)
        with patch('p4_wallet._load_vault', side_effect=AssertionError('overcommit reached key unlock')):
            check('overcommit refuses before key unlock', refused(lambda: sign_decision('atlas', 39)))
        atlas = sign_decision('atlas', 38)
        originals = {name: wallet.recover(did, **selection(name)) for name, did in (('raven', raven), ('atlas', atlas))}
        for name in ('raven', 'atlas'):
            (runtime/f'{name}.pem').unlink()
        check('two fee-inclusive holds exactly fill shared budget', int(stage('both_signed')['pending_debit_units']) == 100)
        def crash(did, name, phase, review=None):
            cfg = {'runtime': str(runtime), 'policy': policy, 'endpoint': proxy.endpoint,
                'decision_id': did, 'payer': payer, 'grant': name, 'revision': wallet.status()['revision'], 'review': review}
            path = runtime/'fault.json'; path.write_bytes(encode(cfg))
            child = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--fault-config', str(path),
                                    '--fault-phase', phase], capture_output=True, timeout=40)
            raw = child.stdout + child.stderr
            if b'PRIVATE KEY' in raw or b'-----BEGIN ' in raw:
                (output/f'{phase}.log').write_bytes(b'[suppressed sensitive child log]\n')
                raise ValueError('sensitive child process output refused')
            retained = raw[:MAX_LOG].replace(str(runtime).encode(), b'<private-run>').replace(str(ROOT).encode(), b'<source>')
            (output/f'{phase}.log').write_bytes(retained)
            report.setdefault('fault_child_logs', []).append({'phase': phase,
                'original_bytes': len(raw), 'original_sha256': hashlib.sha256(raw).hexdigest(),
                'retained_bytes': len(retained), 'retained_sha256': hashlib.sha256(retained).hexdigest(),
                'truncated': len(raw) > MAX_LOG})
            if len(raw) > MAX_LOG:
                raise ValueError('client fault child log exceeded its complete-evidence bound')
            check(phase + ' child exits at exact boundary', child.returncode == {'after_claim': 73, 'after_submission': 74, 'after_wallet_sync': 75}[phase], {'exit_code': child.returncode})
        review = delivery.prepare(raven, **selection('raven'))
        crash(raven, 'raven', 'after_submission', review)
        check('first original submitted once and downstream response dropped after successful CheckTx',
            proxy.submissions == [originals['raven']] and proxy.observations[0]['downstream_dropped'] and proxy.observations[0]['upstream_result']['code'] == 0)
        delivery.close(); wallet.close()
        wallet = P4Wallet(runtime/'wallet.sqlite', full_genesis, policy)
        delivery = P4Delivery(runtime/'wallet.sqlite', runtime/'delivery.sqlite', full_genesis, policy, proxy.endpoint)
        check('reopened dispatch remains unknown and cannot resend', delivery.inspect(raven, **selection('raven'))['transport_observation'] == 'unresolved'
              and refused(lambda: delivery.send(review['review'], review['confirmation'])))
        wait_until(lambda: rpc(http[4], 'tx', {'hash': base64.b64encode(hashlib.sha256(originals['raven']).digest()).decode()}), 30)
        before = rows(); result = delivery.collect(raven, **selection('raven'))
        check('first receipt requires native execution and collection leaves every wallet row unchanged', result['status'] == 'receipt_collected' and rows() == before)
        stage('raven_collected')
        crash(raven, 'raven', 'after_wallet_sync')
        delivery.close(); wallet.close()
        wallet = P4Wallet(runtime/'wallet.sqlite', full_genesis, policy)
        delivery = P4Delivery(runtime/'wallet.sqlite', runtime/'delivery.sqlite', full_genesis, policy, proxy.endpoint)
        before = rows()
        result = delivery.reconcile(raven, **selection('raven'), expected_revision=wallet.status()['revision'])
        check('committed wallet sync survives lost return without another release', result['status'] == 'already_recorded' and rows() == before and int(wallet.status()['pending_debit_units']) == 40)
        stage('raven_reconciled')
        current = height(); emission = current + 6
        body = rules.body(app_query(http[4], '/registry-state'), {'kind': 'schedule', 'emitted_height': emission, 'target_validators': target}, valid_from=1, valid_until=current+4)
        material = rules.signing_bytes(body)
        adminwire = encode({'body': body, 'approvals': sorted([{'public_key': public(k), 'signature': k.sign(material).hex()} for k in admins[:3]], key=lambda r: r['public_key'])})
        confirmed(adminwire, 'full validator turnover')
        (output/'turnover.json').write_bytes(adminwire)
        wait_until(lambda: all(height(i) >= emission+3 for i in range(8)), 80)
        headers = [rpc(http[4], 'commit', {'height': str(emission+n)})['signed_header'] for n in (1, 2, 3)]
        check('real signed headers announce and activate full replacement', headers[0]['header']['next_validators_hash'].lower() == report['replacement_roster_hash']
            and all(h['header']['validators_hash'].lower() == report['replacement_roster_hash'] for h in headers[1:]))
        votes = app_query(http[4], f'/block/{emission+3}')['last_commit_votes']
        expected_voters = {v.address.hex(): v.power for v in ValidatorSet.parse(target).validators}
        actual_voters = {v['address']: v['power'] for v in votes}
        check('actual H+3 commit votes contain only replacement roster with quorum',
            actual_voters == expected_voters and len(actual_voters) == len(votes)
            and 3*sum(v['power'] for v in votes if v['block_id_flag'] == 2) > 2*sum(expected_voters.values()), votes)
        for i in range(4):
            stop(engines[i]); stop(apps[i])
        at = height(); wait_until(lambda: all(height(i) >= at+1 for i in range(4, 8)), 30)
        check('replacement validators advance after all old validators stop', all(height(i) >= at+1 for i in range(4, 8)))
        proof = collect_evidence(proxy.endpoint, full_genesis, policy, time.time_ns())['evidence']
        wallet.sync(proof, expected_revision=wallet.status()['revision'])
        check('turnover import retains second original signature and hold', wallet.recover(atlas, **selection('atlas')) == originals['atlas']
            and wallet.status()['registry_epoch'] == 1 and int(wallet.status()['pending_debit_units']) == 40)
        stage('full_turnover_imported')
        review = delivery.prepare(atlas, **selection('atlas'))
        result = delivery.send(review['review'], review['confirmation'])
        check('second original admitted under replacement roster', result['transport_observation'] == 'endpoint_admitted' and not result['execution_proven'])
        wait_until(lambda: rpc(http[4], 'tx', {'hash': base64.b64encode(hashlib.sha256(originals['atlas']).digest()).decode()}), 30)
        before = rows(); result = delivery.collect(atlas, **selection('atlas'))
        check('second collection leaves every logical wallet row and hold unchanged', result['status'] == 'receipt_collected' and rows() == before)
        stage('atlas_collected')
        result = delivery.reconcile(atlas, **selection('atlas'), expected_revision=wallet.status()['revision'])
        check('explicit second reconciliation releases only matching hold', result['status'] == 'wallet_reconciled' and int(wallet.status()['pending_debit_units']) == 0)
        stage('both_reconciled')
        before = rows()
        result = delivery.reconcile(raven, **selection('raven'), expected_revision=wallet.status()['revision'])
        check('earlier receipt under later roster checkpoint is already recorded without rollback', result['status'] == 'already_recorded' and rows() == before)
        check('exactly two principal original wires submitted', proxy.submissions == [originals['raven'], originals['atlas']])
        for name, did in (('raven', raven), ('atlas', atlas)):
            (output/f'{name}-signed.json').write_bytes(originals[name])
            (output/f'{name}-receipt-evidence.json').write_bytes(encode(delivery.export_receipt(did, **selection(name))))
        state = app_query(http[4], '/state')['native']
        balances = {a[0]: a[4] for a in state['accounts']}
        studio = next(b for b in state['budgets'] if b[0] == payer+'::studio')
        setup_fees = len(setup)*genesis['fee']; payment_fees = 2*genesis['fee']; transferred = 58+38
        check('account budget and fees conserve actual genesis arithmetic', balances[payer] == 1000-setup_fees-transferred-payment_fees
            and balances[merchant] == transferred and studio[4] == transferred+payment_fees
            and balances[FEE_ACCOUNT] == setup_fees+payment_fees and sum(balances.values()) == 1000)
        report['arithmetic'] = {'initial_payer': 1000, 'setup_operations': len(setup), 'setup_fees': setup_fees,
            'payment_fees': payment_fees, 'transferred': transferred, 'payer_final': balances[payer], 'merchant_final': balances[merchant], 'studio_spent': studio[4]}
        claim = sign_decision('claim', 1)
        decline = sign_decision('decline', 1, valid_until=wallet.status()['state_height']+3)
        decline_wire = wallet.recover(decline, **selection('decline'))
        for name, did in (('claim', claim), ('decline', decline)):
            (output/f'{name}-signed.json').write_bytes(wallet.recover(did, **selection(name)))
            (runtime/f'{name}.pem').unlink()
        claim_review = delivery.prepare(claim, **selection('claim'))
        before_count = len(proxy.submissions)
        crash(claim, 'claim', 'after_claim', claim_review)
        check('claim-before-I/O crash sends zero bytes and remains unknown', len(proxy.submissions) == before_count
            and delivery.inspect(claim, **selection('claim'))['transport_observation'] == 'unresolved'
            and refused(lambda: delivery.send(claim_review['review'], claim_review['confirmation'])))
        decline_review = delivery.prepare(decline, **selection('decline'))
        wait_until(lambda: height() > decline_review['review']['valid_until'], 30)
        before = rows(); result = delivery.send(decline_review['review'], decline_review['confirmation'])
        check('actual engine decline preserves hold and consumes attempt', result['transport_observation'] == 'endpoint_declined'
            and rows() == before and refused(lambda: delivery.send(decline_review['review'], decline_review['confirmation'])))
        result = delivery.collect(decline, **selection('decline'))
        check('declined payment has no positive receipt and collection cannot retire hold', result['status'] == 'unavailable' and rows() == before)
        check('diagnostic claims retain six units without changing settled main budget', int(wallet.status()['pending_debit_units']) == 6
            and next(b for b in wallet.status()['budgets'] if b['id'] == payer+'::studio')['spent'] == '100')
        check('total broadcasts are exactly two originals and one declined diagnostic',
            proxy.submissions == [originals['raven'], originals['atlas'], decline_wire]
            and type(proxy.observations[-1]['upstream_result']['code']) is int
            and proxy.observations[-1]['upstream_result']['code'] != 0)
        report['diagnostics'] = {'claim_submissions': 0, 'declined_submissions': 1, 'unresolved_hold_units': 6,
            'principal_submissions': 2, 'total_proxy_submissions': len(proxy.submissions)}
        if custody_format is not None:
            from p4_custody import backup, restore_backup, RecoveryArchive
            from p4_custody_stream import stream_pair, TABLES
            def pair_rows(wdb, ddb):
                return tuple(tuple((wdb if source == 0 else ddb).execute(
                    f'SELECT * FROM {table} ORDER BY 1')) for source, table, _, _ in TABLES)
            before_pair = pair_rows(wallet.db, delivery.db)
            before_submissions = tuple(proxy.submissions)
            private = runtime/'custody'
            private.mkdir(mode=0o700)
            bp, ap = private/'encrypted-v3.backup', private/'historical.sqlite'
            secret = os.urandom(32)
            saved = backup(delivery, bp, secret, format_version=custody_format)
            check('custody backup explicitly uses format 3', saved['backup_format_version'] == 3)
            restored = restore_backup(bp, ap, full_genesis, policy, secret)
            check('custody restore preserves the original snapshot identity',
                  restored['backup_format_version'] == 3 and restored['snapshot_id'] == saved['snapshot_id'])
            with RecoveryArchive(ap, full_genesis, policy) as archive:
                view = archive.inspect()
                with stream_pair(archive._chunks) as pair:
                    check('custody restores every exact cell of all seven tables',
                          pair_rows(pair[0], pair[1]) == before_pair)
                check('custody retains both original principal signatures after key removal',
                      all(archive.recover(did, **selection(name)) == originals[name]
                          for name, did in (('raven', raven), ('atlas', atlas))))
                check('custody retains exact receipts across full validator turnover',
                      all(encode(archive.export_receipt(did, **selection(name))) ==
                          encode(delivery.export_receipt(did, **selection(name)))
                          for name, did in (('raven', raven), ('atlas', atlas))))
                recovered = {r['id']: r for r in view['decisions']}
                check('custody preserves the unresolved and declined holds without resend',
                      view['pending_debit_units'] == '6' and
                      recovered[claim]['transport_observation'] == 'unresolved' and
                      recovered[decline]['transport_observation'] == 'endpoint_declined' and
                      all(not row['safe_to_resend'] for row in view['decisions']))
                check('custody remains historical without authority or trust renewal',
                      all(view[field] is False for field in ('signing_enabled', 'dispatch_enabled',
                          'current_spending_authority', 'trust_policy_renewed',
                          'old_device_fenced', 'latestness_established')))
            def activation_refused(factory):
                try:
                    with factory():
                        return False
                except ValueError:
                    return True
            check('custody archive refuses both active wallet and delivery constructors',
                  activation_refused(lambda: P4Wallet(ap, full_genesis, policy)) and
                  activation_refused(lambda: P4Delivery(ap, private/'active-delivery.sqlite',
                      full_genesis, policy, proxy.endpoint, create=True)) and
                  not (private/'active-delivery.sqlite').exists())
            check('custody leaves the source journals and all submissions unchanged',
                  pair_rows(wallet.db, delivery.db) == before_pair and
                  tuple(proxy.submissions) == before_submissions)
            check('custody encrypted backup and plaintext archive have private permissions',
                  bp.stat().st_mode & 0o077 == 0 and ap.stat().st_mode & 0o077 == 0)
            report['custody'] = {'assessed': True, 'backup_format_version': custody_format,
                'backup_bytes': bp.stat().st_size, 'backup_sha256': hashlib.sha256(bp.read_bytes()).hexdigest(),
                'archive_bytes': ap.stat().st_size, 'archive_sha256': hashlib.sha256(ap.read_bytes()).hexdigest(),
                'snapshot_id': saved['snapshot_id'], 'exact_table_rows_preserved': True,
                'principal_receipts_preserved': 2, 'pending_debit_units': view['pending_debit_units'],
                'new_submissions': 0, 'source_journals_changed': False,
                'independent_hosts': False, 'production_custody_certified': False}
        if read_store_format is not None:
            from commit_verifier import load_json
            from p4_read_store import P4ReadStore
            from p4_explorer import current_view
            before_read_submissions = tuple(proxy.submissions)
            before_wallet = tuple(wallet.db.iterdump())
            with wallet.atomic(write=False):
                _, observations, _, _ = wallet._catalog()
                retained_packets = [bytes(observations[index][4]) for index in (0, -1)]
            expected_ids = [hashlib.sha256(raw).hexdigest() for raw in retained_packets]
            private = runtime/'read-storage'
            private.mkdir(mode=0o700)
            stores = {}; read_views = {}; projections = {}; statistics = {}
            for version in (1, 2):
                path = private/(f'read-v{version}.sqlite')
                with P4ReadStore(path, full_genesis, policy, create=True,
                                 storage_version=version) as ledger:
                    tip = None
                    for raw, expected in zip(retained_packets, expected_ids):
                        imported = ledger.import_evidence(load_json(raw, max_bytes=16*1024*1024),
                                                          expected_tip=tip)
                        if imported['status'] != 'recorded' or imported['evidence_id'] != expected:
                            raise ValueError('read-store changed an original validator packet identity')
                        tip = imported['evidence_id']
                    read_views[version] = ledger.current()
                    statistics[version] = ledger.storage_stats()
                    check(f'read-store format {version} exports both original validator packets exactly',
                          all(encode(ledger.export(identity)) == raw
                              for identity, raw in zip(expected_ids, retained_packets)))
                    account = ledger.account(payer)['account']
                    check(f'read-store format {version} verifies original payment receipts and recorded balance',
                          account['recorded_balance'] == '888' and
                          all(ledger.receipt(originals[name], payer=payer)['status'] == 'recorded'
                              for name in ('raven', 'atlas')))
                stores[version] = path
                projections[version] = current_view(path, full_genesis, policy)
            # Verification times may advance. All cryptographic/state claims must
            # remain identical under the original fixed external policy.
            def without_clock(value):
                return {k:v for k,v in value.items() if k != 'checked_at_ns'}
            check('read-store formats retain the same fully verified state and trust',
                  without_clock(read_views[1]) == without_clock(read_views[2]) and
                  read_views[2]['native_execution_replayed'] is True and
                  read_views[2]['spending_authority'] is False)
            for view in projections.values():
                view['checkpoint'].pop('checked_at_ns')
            check('existing explorer reads compact proofs without changing its projection',
                  projections[1] == projections[2] and
                  projections[2]['checkpoint']['registry_epoch'] == '1' and
                  projections[2]['spending_authority'] is False)
            check('compact read storage charges exact original logical evidence bytes',
                  statistics[1]['logical_evidence_bytes'] == sum(map(len, retained_packets)) and
                  statistics[2]['logical_evidence_bytes'] == statistics[1]['logical_evidence_bytes'] and
                  statistics[1]['format_version'] == 1 and statistics[2]['format_version'] == 2 and
                  statistics[2]['stored_payload_bytes'] < statistics[1]['stored_payload_bytes'])
            check('read storage adds no submissions and changes no monetary journal rows',
                  tuple(proxy.submissions) == before_read_submissions and
                  tuple(wallet.db.iterdump()) == before_wallet)
            report['read_storage'] = {'assessed': True, 'formats': [1, 2],
                'observations_per_store': 2, 'original_evidence_ids': expected_ids,
                'statistics': statistics, 'same_original_exports': True,
                'same_verified_reports_except_clock': True, 'same_explorer_projection_except_clock': True,
                'receipt_results_recorded_per_store': 2, 'new_submissions': 0,
                'source_wallet_changed': False, 'independent_hosts': False,
                'production_read_service_certified': False}
        if key_rotation:
            # Extend the complete existing acceptance profile. Its checks and
            # six units of unresolved diagnostic holds remain unchanged.
            proof=collect_evidence(proxy.endpoint,full_genesis,policy,time.time_ns())['evidence']
            wallet.sync(proof,expected_revision=wallet.status()['revision'])
            incoming=Ed25519PrivateKey.generate()
            for name,key in (('owner',keys['owner']),('incoming',incoming)):
                path=runtime/f'{name}.pem'
                path.write_bytes(key.private_bytes(ser.Encoding.PEM,ser.PrivateFormat.PKCS8,ser.BestAvailableEncryption(password)))
                path.chmod(0o600)
            q=wallet.prepare_rotation(payer=payer,new_public_key=public(incoming),valid_until=wallet.status()['state_height']+30)
            # Same-height sync can legitimately retain an earlier valid commit
            # packet. Export the exact canonical observation used by this wallet,
            # not a newly queried/reconstructed packet with another signature set.
            with wallet.atomic(write=False):
                _,observations,_,_=wallet._catalog()
                origin=bytes(observations[-1][4])
            check('exact rotation review source packet retained',
                  hashlib.sha256(origin).hexdigest()==q['review']['evidence_id'])
            (output/'rotation-origin-evidence.json').write_bytes(origin)
            accepted=wallet.accept_rotation(q['review'],q['confirmation'],incoming_vault=runtime/'incoming.pem',password=password)
            check('incoming rotation consent has no fee hold or owner signature',
                  wallet.status()['pending_debit_units']=='6' and not accepted['owner_signed'])
            decision=wallet.approve_rotation(accepted['review'],accepted['confirmation'],owner_vault=runtime/'owner.pem',password=password)
            rotation=decision['decision_id'];selection_owner={'payer':payer,'grant_id':''}
            rotation_wire=wallet.recover(rotation,**selection_owner)
            check('rotation reserves exactly two additional units',wallet.status()['pending_debit_units']=='8')
            check('pending rotation quiesces all new payer signing',refused(lambda:wallet.prepare(payer=payer,recipient=merchant,units=1,valid_until=wallet.status()['state_height']+30)))
            q=delivery.prepare(rotation,**selection_owner);sent=delivery.send(q['review'],q['confirmation'])
            check('exact rotation admitted under replacement validators',sent['transport_observation']=='endpoint_admitted' and not sent['execution_proven'])
            tx=wait_until(lambda:rpc(http[4],'tx',{'hash':base64.b64encode(hashlib.sha256(rotation_wire).digest()).decode()}),30)
            wait_until(lambda:height()>=int(tx['height'])+1,30)
            check('rotation executes through real ABCI',tx['tx_result']['code']==0)
            check('rotation positive receipt collected',delivery.collect(rotation,**selection_owner)['status']=='receipt_collected')
            rotation_evidence=delivery.export_receipt(rotation,**selection_owner)
            view=wallet.rotation_status(rotation,payer=payer,evidence=rotation_evidence)
            check('verified rotation retires original authority at checkpoint',view['old_owner_retired_at_checkpoint'] and view['original_grants_retired_at_checkpoint'] and view['replacement_owner_active_at_checkpoint'] and view['receipt_epoch_before']==0 and view['receipt_epoch_after']==1)
            delivery.reconcile(rotation,**selection_owner,expected_revision=wallet.status()['revision'])
            check('rotation reconciliation preserves six unknown diagnostic units',wallet.status()['pending_debit_units']=='6')
            state=app_query(http[4],'/state')['native'];ledger=restore(genesis,state)
            try:
                owner=ledger._account(payer)
                old_owner=canonical(sign(keys['owner'],ledger.body(payer,owner['nonce'],{'type':'transfer','to':merchant,'units':1},valid_until=height()+30)))
                old_grant=canonical(sign(keys['claim'],ledger.body(payer,0,{'type':'transfer','to':merchant,'units':1},grant_id='claim',valid_until=height()+30)))
            finally:ledger.close()
            for label,wire in (('old owner',old_owner),('old epoch grant',old_grant)):
                response=rpc(http[4],'broadcast_tx_sync',{'tx':base64.b64encode(wire).decode()})
                check(label+' rejected by actual engine CheckTx',type(response['code']) is int and response['code']!=0)
                (output/(label.replace(' ','-')+'-checktx.json')).write_bytes(encode(response))
            q=wallet.prepare(payer=payer,recipient=merchant,units=1,valid_until=wallet.status()['state_height']+30)
            next_decision=wallet.approve(q['review'],q['confirmation'],vault=runtime/'incoming.pem',password=password)
            next_id=next_decision['decision_id'];next_wire=wallet.recover(next_id,**selection_owner)
            q=delivery.prepare(next_id,**selection_owner);delivery.send(q['review'],q['confirmation'])
            tx=wait_until(lambda:rpc(http[4],'tx',{'hash':base64.b64encode(hashlib.sha256(next_wire).digest()).decode()}),30)
            wait_until(lambda:height()>=int(tx['height'])+1,30)
            check('replacement owner payment executes from same account',tx['tx_result']['code']==0 and next_decision['transaction']['body']['sender']==payer)
            check('replacement owner receipt collected',delivery.collect(next_id,**selection_owner)['status']=='receipt_collected')
            delivery.reconcile(next_id,**selection_owner,expected_revision=wallet.status()['revision'])
            check('replacement payment clears only its three-unit hold',wallet.status()['pending_debit_units']=='6')
            state=app_query(http[4],'/state')['native'];balances={a[0]:a[4] for a in state['accounts']}
            check('rotation and replacement payment conserve all native funds',balances[payer]==report['arithmetic']['payer_final']-5 and balances[merchant]==97 and sum(balances.values())==1000)
            for name,raw in (('rotation-signed.json',rotation_wire),('rotation-review.json',encode(accepted['review'])),
                             ('rotation-receipt-evidence.json',encode(rotation_evidence)),('rotation-status.json',encode(view)),
                             ('replacement-signed.json',next_wire),('replacement-receipt-evidence.json',encode(delivery.export_receipt(next_id,**selection_owner)))):
                (output/name).write_bytes(raw)
            report['key_rotation']={'assessed':True,'payer':payer,'rotation_decision_id':rotation,
                'replacement_decision_id':next_id,'remaining_unknown_hold_units':6,
                'physical_device_fenced':False,'latestness_guaranteed':False,'checked_at_ns':view['checked_at_ns'],
                'prior_diagnostics_scope':'before key rotation','additional_positive_proxy_submissions':2,
                'final_proxy_submissions':len(proxy.submissions),'additional_direct_negative_checktx':2}
        report['status'] = 'passed'
    except BaseException as exc:
        report['status'] = 'failed'
        report['reason'] = f'{type(exc).__name__}: {exc}'
        import traceback
        report['traceback'] = traceback.format_exc().replace(str(ROOT), '<source>').replace(str(runtime), '<private-run>')
    finally:
        if delivery is not None: delivery.close()
        if wallet is not None: wallet.close()
        if proxy is not None:
            proxy.close()
            (output/'submissions.json').write_bytes(encode(proxy.observations))
        for process in engines + apps: stop(process)
        for handle in handles: handle.close()
        logs = []
        if runtime is not None:
            for path in sorted(runtime.glob('*.log')):
                raw = path.read_bytes()
                truncated = len(raw) > MAX_LOG
                if b'PRIVATE KEY' in raw or b'-----BEGIN ' in raw:
                    raw = b'[suppressed sensitive process log]\n'
                    report['status'] = 'failed'; report['reason'] = 'sensitive process log refused'
                else:
                    raw = raw[:MAX_LOG].replace(str(runtime).encode(), b'<private-run>').replace(str(ROOT).encode(), b'<source>')
                (output/path.name).write_bytes(raw)
                logs.append({'path': path.name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(), 'truncated': truncated})
        report['logs'] = logs
        if temp is not None: temp.cleanup()
        report['source_dirty_after'] = bool(git('status', '--porcelain'))
        report['source_qualified'] = not report['source_dirty_before'] and not report['source_dirty_after'] and report['source_commit'] == git('rev-parse', 'HEAD')
        report['engine_sha256_after'] = hashlib.sha256(binary.read_bytes()).hexdigest() if binary.is_file() else None
        report['finished_at'] = datetime.now(timezone.utc).isoformat()
        (output/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--engine'); p.add_argument('--engine-sha256'); p.add_argument('--output', type=Path)
    p.add_argument('--fault-config', type=Path)
    p.add_argument('--fault-phase', choices=('after_claim', 'after_submission', 'after_wallet_sync'))
    p.add_argument('--key-rotation',action='store_true',help='also qualify owner replacement and retained uncertain holds')
    p.add_argument('--custody-format', type=int, choices=(3,),
                   help='also qualify compact encrypted backup and historical recovery on actual validator journals')
    p.add_argument('--read-store-format', type=int, choices=(2,),
                   help='also qualify compact read storage and original receipt/explorer consumers')
    args = p.parse_args()
    if args.fault_config:
        process_fault(args.fault_config, args.fault_phase)
    else:
        if not args.engine or not args.engine_sha256 or not args.output: p.error('engine, hash and output are required')
        result = run(args.engine, args.engine_sha256, args.output,key_rotation=args.key_rotation,custody_format=args.custody_format,read_store_format=args.read_store_format)
        print(json.dumps({k: result.get(k) for k in ('status', 'reason', 'source_qualified')}))
        raise SystemExit(0 if result['status'] == 'passed' else 1)
