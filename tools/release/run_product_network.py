#!/usr/bin/env python3
"""Opt-in real-engine product acceptance: four local validators, no deployment.

Reuses the pinned CometBFT driver helpers and all existing financial components.
Missing binary => UNASSESSED. There is no synthetic engine or automatic download.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
PATHS = [ROOT/'tools/release', ROOT/'scripts', ROOT/'src', ROOT/'tools/wallet-account/src',
         ROOT/'tools/wallet-delivery/src', ROOT/'tools/explorer/src', ROOT/'tools/receipt-archive/src']
sys.path[:0] = [str(p) for p in PATHS]

from check_release import source_identity, checked_manifests, store_json
from run_devnet import (PIN, DecisionDeliveryRpcProxy, build_native_case, free_ports,
                        patch_toml, rpc, wait_until)
from run_state_sync import ExecutionLogBundle
from product_observer import ProductObserver, validate_history, require
from certified_wallet import CertifiedWallet
from commit_verifier import header_hash, verify_state_witness, verify_packet, trust_from_genesis
from decision_delivery import DecisionDelivery
from native_core import canonical, parse_wire, public, Reject, address
from cryptography.hazmat.primitives import serialization


def application_command(db, sock, genesis, keep, *, restart=False):
    require(type(keep) is int and 2 <= keep <= 16, 'retention window must be 2..16 for this finite gate')
    args = [sys.executable, str(ROOT/'scripts/serve_abci.py'), '--db', str(db),
            '--socket', str(sock), '--genesis', str(genesis)]
    # Omission on restart deliberately tests the node's persisted retention policy.
    if not restart: args += ['--block-history-keep', str(keep)]
    return args


def engine_preflight(engine, expected_sha256):
    binary = shutil.which(engine) if '/' not in engine else str(Path(engine).resolve())
    if not binary or not Path(binary).is_file():
        return {'status': 'unassessed', 'reason': 'pinned engine executable absent'}
    if expected_sha256 is None:
        return {'status': 'unassessed', 'reason': 'explicit engine SHA-256 pin required'}
    require(type(expected_sha256) is str and len(expected_sha256) == 64 and
            all(c in '0123456789abcdef' for c in expected_sha256), 'invalid engine digest pin')
    observed = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    require(observed == expected_sha256, 'engine bytes differ from explicit pin')
    version = subprocess.check_output([binary, 'version'], text=True, timeout=10).strip()
    require(version.lstrip('v') == PIN, 'engine version differs from pinned version')
    return {'status': 'matched', 'binary': binary, 'sha256': observed, 'version': version}


def query(port, path):
    response = rpc(port, 'abci_query', {'path': path, 'prove': False})['response']
    require(type(response.get('code')) is int, 'missing ABCI query status')
    return response


def query_value(port, path):
    response = query(port, path)
    require(response['code'] == 0, 'native query unavailable: ' + path.split('/')[1])
    return json.loads(base64.b64decode(response['value'], validate=True))


def live_witness(port, trust):
    state = query_value(port, '/state')  # Capture ONCE, then wait only for fixed H+1.
    target = state['height'] + 1
    wait_until(lambda: int(rpc(port, 'status')['sync_info']['latest_block_height']) >= target, 30)
    signed = rpc(port, 'commit', {'height': str(target)})['signed_header']
    verify_state_witness(state, signed, trust)
    return {'schema': 1, 'state': state, 'state_commit': signed}


def continuation(port, origin, target):
    require(type(origin) is int and type(target) is int and origin < target <= origin + 65,
            'wallet continuation outside bounded gate')
    return [rpc(port, 'commit', {'height': str(h)})['signed_header'] for h in range(origin+1, target)]


def output_directory(output):
    p = Path(os.path.abspath(output))
    require(not p.is_relative_to(ROOT), 'evidence must be outside source checkout')
    for parent in (p.parent, *p.parent.parents):
        require(not parent.is_symlink(), 'evidence ancestor symlink refused')
    p.mkdir(mode=0o700, exist_ok=False)
    return p


def run(engine, output, *, engine_sha256=None, compact=False, keep_blocks=3):
    require(type(compact) is bool, 'compact mode must be explicit boolean')
    require(type(keep_blocks) is int and 2 <= keep_blocks <= 16, 'retention window must be 2..16')
    source = source_identity(ROOT); inventories = checked_manifests(ROOT)
    output = output_directory(output)
    report = {'schema': 1, 'status': 'unassessed', 'stage': 'engine_preflight', 'checks': [],
              'source_commit': source['commit'], 'source_tree': source['tree'], 'source_id': source['source_id'],
              'source_files': source['tracked_files'], 'inventories': inventories,
              'required_engine': PIN, 'keep_blocks': keep_blocks,
              'state_commitment': 'smt-v1' if compact else 'legacy-flat-v1',
              'scope': 'one-host four-validator product journey, not independent operators',
              'engine_processes_started': 0, 'consensus_executed': False,
              'release_status': 'blocked', 'public_network': False, 'real_funds': False,
              'state_sync_engine_qualified': False, 'final_apply_crash_qualified': False}
    store_json(output/'started.json', report)
    logs = []; processes = {}; wallet = delivery = observer = proxy = None
    keys = {}; packets = []; decisions = []
    def persist():
        p = output/'progress.json'; store_json(p, report, replace=p.exists())
    def check(name, condition, details=None):
        report['checks'].append({'name': name, 'passed': bool(condition), 'details': details})
        persist(); require(condition, name)
    def stop(kind, i):
        p = processes.pop((kind, i), None)
        if p is None: return
        if p.poll() is None:
            p.terminate()
            try: p.wait(timeout=10)
            except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)
    try:
        match = engine_preflight(engine, engine_sha256)
        report['engine'] = {k: v for k, v in match.items() if k != 'binary'}
        if match['status'] != 'matched':
            report['reason'] = match['reason']
            return report
        binary = match['binary']
        os.environ['PYTHONPATH'] = os.pathsep.join(map(str, PATHS))
        logs.append(ExecutionLogBundle(output/'initial-processes'))
        logs.append(ExecutionLogBundle(output/'restarted-processes'))
        with tempfile.TemporaryDirectory(prefix='1soft-product-') as temp:
            runtime = Path(temp); runtime.chmod(0o700); homes = runtime/'nodes'
            report['stage'] = 'create_disposable_network'; persist()
            setup = subprocess.run([binary, 'testnet', '--v', '4', '--o', str(homes), '--initial-height', '1'],
                                   capture_output=True, check=True, timeout=30)
            logs[0].record_runner(setup.stdout); logs[0].record_runner(setup.stderr)
            try:
                case = build_native_case('1soft-product-'+os.urandom(6).hex(), 3,
                        state_commitment='smt-v1' if compact else None, wallet_key_sink=keys)
                genesis = case['genesis']; rootgen = json.loads((homes/'node0/config/genesis.json').read_bytes())
                rootgen.update(chain_id=genesis['chain_id'], initial_height='1', app_state=genesis)
                rootgen['consensus_params']['block'].update(max_bytes='1048576', max_gas='-1')
                public_genesis = (json.dumps(rootgen, indent=2)+'\n').encode()
                ghash = hashlib.sha256(public_genesis).hexdigest(); trust = trust_from_genesis(rootgen)
                store_json(output/'public-genesis.json', rootgen)
                # Preserve exact bytes separately: the wallet pins these, not pretty-print normalization.
                (output/'public-genesis-exact.json').write_bytes(public_genesis)
                (output/'public-genesis-exact.json').chmod(0o600)
                report['genesis_sha256'] = ghash
                native_file = runtime/'native.json'; native_file.write_bytes(canonical(genesis))
                allports = free_ports(8); p2p, http = allports[:4], allports[4:]
                ids = [subprocess.check_output([binary, 'show-node-id', '--home', str(homes/f'node{i}')],
                                               text=True, timeout=10).strip() for i in range(4)]
                apps = {}
                for i in range(4):
                    home = homes/f'node{i}'; (home/'config/genesis.json').write_bytes(public_genesis)
                    appdir = runtime/f'app{i}'; appdir.mkdir(mode=0o700)
                    apps[i] = (appdir/'state.sqlite', appdir/'a.sock')
                    conf = home/'config/config.toml'
                    conf.write_text(patch_toml(conf.read_text(), {
                        'proxy_app': f'unix://{apps[i][1]}', 'abci': 'socket',
                        'rpc.laddr': f'tcp://127.0.0.1:{http[i]}', 'rpc.unsafe': False,
                        'p2p.laddr': f'tcp://127.0.0.1:{p2p[i]}',
                        'p2p.persistent_peers': ','.join(f'{ids[j]}@127.0.0.1:{p2p[j]}' for j in range(4) if j != i),
                        'p2p.addr_book_strict': False, 'p2p.allow_duplicate_ip': True, 'p2p.pex': False,
                        'consensus.timeout_commit': '500ms', 'mempool.max_tx_bytes': 16384}))
                for p in homes.rglob('*'):
                    if p.is_dir(): p.chmod(0o700)
                    elif p.is_file(): p.chmod(0o600)
                def start(i, *, restart=False):
                    db, sock = apps[i]; selected = logs[1 if restart else 0]
                    processes[('app', i)] = selected.start('source', i, 'app',
                                    application_command(db, sock, native_file, keep_blocks, restart=restart))
                    wait_until(lambda: sock.exists() and processes[('app', i)].poll() is None, 10)
                    processes[('engine', i)] = selected.start('source', i, 'engine',
                                    [binary, 'start', '--home', str(homes/f'node{i}')])
                    report['engine_processes_started'] += 1
                for i in range(4): start(i)
                height = lambda i: int(rpc(http[i], 'status')['sync_info']['latest_block_height'])
                wait_until(lambda: all(height(i) >= 2 for i in range(4)), 45)
                check('four separate real-engine processes produced blocks',
                      len({processes[('engine', i)].pid for i in range(4)}) == 4)
                report['consensus_executed'] = True
                report['stage'] = 'native_setup'; persist()
                for name, raw in case['accepted'][:4]:
                    sent = rpc(http[0], 'broadcast_tx_commit', {'tx': base64.b64encode(raw).decode()})
                    check(name, int(sent['check_tx']['code']) == 0 and int(sent['tx_result']['code']) == 0)
                captured = live_witness(http[0], trust)
                work = runtime/'wallet'; work.mkdir(mode=0o700)
                policy = {'schema': 1, 'genesis_sha256': ghash,
                    'trust_expires_utc': (datetime.now(timezone.utc)+timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
                    'minimum_header_height': 1, 'maximum_age_seconds': 300, 'future_skew_seconds': 5}
                wallet = CertifiedWallet(work/'decisions.sqlite', public_genesis, policy)
                password = os.urandom(32)
                for (name, raw), role in zip(case['accepted'][4:6], ('raven', 'atlas')):
                    key = keys[role]; vault = work/(role+'.pem')
                    vault.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.BestAvailableEncryption(password)))
                    vault.chmod(0o600); body = parse_wire(raw)['body']
                    if role == 'atlas':
                        bad = case['rejections_before'][name][0][1]
                        try: wallet.review(captured, parse_wire(bad)['body'], public(key))
                        except Reject as exc: denied = 'shared budget insufficient' in str(exc)
                        else: denied = False
                        check('Atlas overcommit refused before vault unlock', denied)
                    review = wallet.review(captured, body, public(key))
                    result = wallet.approve(captured, body, public(key), review['confirmation'], vault, password)
                    check(role+' signed original native payment', canonical(result['result']) == raw)
                    decisions.append({'name': role, 'label': name, 'raw': raw, 'id': result['decision_id'],
                                      'account': body['sender'], 'grant_id': body['grant_id']})
                    vault.unlink()
                keys.clear(); key = password = None
                check('fixture signing files absent before delivery', not list(work.glob('*.pem')))
                proxy = DecisionDeliveryRpcProxy(http[0], [(d['label'], d['raw']) for d in decisions])
                def open_delivery(create=False):
                    return DecisionDelivery(work/'decisions.sqlite', work/'delivery.sqlite', public_genesis,
                                            policy, proxy.endpoint, create=create)
                delivery = open_delivery(True)
                observer = ProductObserver(runtime/'product', output/'product', public_genesis, policy,
                                            f'http://127.0.0.1:{http[0]}/', case['budget_id'])
                observer.begin(captured, wallet, delivery)
                for n, decision in enumerate(decisions):
                    role = decision['name']; selection = {'account': decision['account'], 'grant_id': role}
                    report['stage'] = role+'_delivery'; persist()
                    queued = delivery.queue(decision['id'], **selection)
                    sent = delivery.send(decision['id'], queued['delivery_confirmation'], **selection)
                    store_json(output/(role+'-send.json'), sent)  # Save exact result before checking.
                    ps = proxy.snapshot(); item = ps['payments'][-1]
                    check(role+' reached upstream CheckTx once', len(ps['payments']) == n+1 and
                          item['upstream_check_tx_code'] == 0 and item['upstream_tx_hash_matches'] is True and
                          sent['submission_attempts'] == 1)
                    if n == 0:
                        check('real successful upstream reply dropped downstream',
                              item['downstream_reply_dropped'] is True and sent['transport_status'] == 'unresolved')
                    else:
                        check('second upstream reply returned', item['downstream_reply_forwarded'] is True and
                              sent['transport_status'] == 'endpoint_admitted')
                    delivery.close(); delivery = None; wallet.close(); wallet = None
                    wallet = CertifiedWallet(work/'decisions.sqlite', public_genesis, policy)
                    delivery = open_delivery()
                    check(role+' original signature survives reopening', canonical(wallet.export(decision['id'])['result']) == decision['raw'])
                    def collected():
                        r = delivery.refresh(decision['id'], **selection, read_attempts=4)
                        if r['collection_status'] == 'evidence_rejected':
                            raise AssertionError('live receipt rejected')
                        return r if r['exact_transport_receipt_verified'] else None
                    receipt = wait_until(collected, 20)
                    store_json(output/(role+'-collected.json'), receipt)
                    packet = json.loads(delivery.export_receipt(decision['id'], **selection)); packets.append(packet)
                    store_json(output/(role+'-packet.json'), packet)
                    held = 100 if n == 0 else 40; spent = 60 if n == 0 else 100
                    observer.before_reconcile(role, packet, decision['raw'], wallet, delivery,
                                               expected_pending=held, expected_spent=spent)
                    origin = wallet.db.execute('SELECT height FROM checkpoint WHERE id=1').fetchone()[0]
                    target_height = int(packet['state_commit']['header']['height'])
                    links = continuation(http[0], origin, target_height)
                    synced = delivery.reconcile(decision['id'], **selection, continuation=links)
                    store_json(output/(role+'-reconciled.json'), synced)
                    check(role+' wallet reconciled only after independent product observation',
                          synced['wallet_obligation_status'] == 'recorded' and synced['submission_attempts'] == 1)
                    observer.after_reconcile(role, wallet, expected_pending=40 if n == 0 else 0, expected_spent=spent)
                report['stage'] = 'retention_and_restart'; persist()
                oldest = observer.receipts[0]['inclusion_height']
                wait_until(lambda: all(height(i) >= oldest+keep_blocks+2 for i in range(4)), 30)
                histories = []
                for i in range(4):
                    hist = query_value(http[i], '/history'); verified = validate_history(hist, keep_blocks, minimum_height=oldest+keep_blocks)
                    old = query(http[i], '/block/'+str(oldest))
                    check('node '+str(i)+' pruned old local result, not native receipt',
                          old['code'] == 2 and json.loads(base64.b64decode(old['value']))['status'] == 'pruned_local_block_results' and
                          query_value(http[i], '/receipt/'+observer.receipts[0]['verified']['native_txid']) == observer.receipts[0]['verified']['receipt'])
                    histories.append({'node': i, 'history': hist, 'validated': verified})
                store_json(output/'retention-before-restart.json', histories)
                before_height = height(0)
                stop('engine', 3); stop('app', 3)
                start(3, restart=True)  # No retention flag on this second launch.
                wait_until(lambda: height(3) >= before_height+2, 45)
                restarted = query_value(http[3], '/history')
                validate_history(restarted, keep_blocks, minimum_height=before_height)
                check('application and engine restart reused persisted retention policy',
                      restarted['availability']['keep_blocks'] == keep_blocks and
                      restarted['native_receipt_count'] == 6, restarted)
                store_json(output/'retention-after-restart.json', restarted)
                def matching():
                    states = [query_value(port, '/state') for port in http]
                    return states[0] if all(s == states[0] for s in states) else None
                final = wait_until(matching, 30)
                wait_until(lambda: height(0) >= final['height']+1, 30)
                final_commit = rpc(http[0], 'commit', {'height': str(final['height']+1)})['signed_header']
                certificate = {'schema': 1, 'state': final, 'state_commit': final_commit,
                               'transactions': [p['transactions'][0] for p in packets]}
                proof = verify_packet(certificate, trust,
                                      expected_txids=[x['verified']['native_txid'] for x in observer.receipts])
                store_json(output/'final-certificate.json', certificate)
                store_json(output/'final-certificate-verification.json', proof)
                check('four applications converge with certified original payments', len(final['native']['receipts']) == 6 and
                      sum(r[4] for r in final['native']['accounts']) == 100_000_000 and
                      sum(r[4] for r in final['native']['budgets']) == 100)
                ps = proxy.snapshot()
                check('product reads did not add a payment submission', ps['forwarded_payment_submissions'] == 2 and
                      len(ps['payments']) == 2 and not ps['unexpected_requests'] and not ps['unexpected_http_methods'])
                report['transport'] = ps
                # Stop all source services before the final archive/index checks.
                for i in range(4): stop('engine', i); stop('app', i)
                report['stage'] = 'offline_product_reopen'; persist()
                observer.index.close(); observer.index = None
                observer.archive.close(); observer.archive = None
                from explorer_index import ExplorerIndex
                from receipt_archive import ReceiptArchive
                observer.index = ExplorerIndex(observer.work/'explorer.sqlite', public_genesis, ghash)
                observer.archive = ReceiptArchive(observer.work/'archive.sqlite', public_genesis, ghash)
                report['product'] = observer.finish(wallet, delivery, expected_receipt_count=6)
                first = decisions[0]
                older = delivery.reconcile(first['id'], account=first['account'], grant_id=first['grant_id'])
                check('older receipt remains recorded with all source processes stopped',
                      older['reconciliation_outcome'] == 'already_recorded' and older['network_requested'] is False)
                report.update(status='passed', stage='completed')
            finally:
                for kind, i in list(processes): stop(kind, i)
                if observer is not None: observer.close()
                if delivery is not None: delivery.close()
                if wallet is not None: wallet.close()
                if proxy is not None: proxy.close()
                keys.clear()
        require(source_identity(ROOT) == source, 'source changed during acceptance')
        require(hashlib.sha256(Path(binary).read_bytes()).hexdigest() == engine_sha256, 'engine changed during acceptance')
        report['source_unchanged'] = True
    except BaseException as exc:
        report.update(status='failed', error_type=type(exc).__name__)
        if observer is not None:
            observer.report.update(status='failed', outer_stage=report['stage'], error_type=type(exc).__name__)
            observer.persist()
    finally:
        for log in logs:
            log.finish(report['status'])
        if logs:
            report['execution_logs'] = [log.summary() for log in logs]
            for log in logs:
                capture = json.loads(log.manifest_path.read_bytes())
                if capture['runner_log']['truncated'] or any(item['truncated'] or item['capture_error'] for item in capture['logs']):
                    report.update(status='failed', error_type='IncompleteProcessLog')
        report['passed_checks'] = sum(c['passed'] for c in report['checks'])
        store_json(output/'result.json', report)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cometbft', default='cometbft')
    p.add_argument('--engine-sha256', help='Explicit SHA-256 of the locally built pinned engine')
    p.add_argument('--output', type=Path, required=True, help='New private evidence directory outside source')
    p.add_argument('--smt', action='store_true')
    p.add_argument('--keep-blocks', type=int, default=3)
    a = p.parse_args()
    result = run(a.cometbft, a.output, engine_sha256=a.engine_sha256, compact=a.smt, keep_blocks=a.keep_blocks)
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'passed' else 2


if __name__ == '__main__': raise SystemExit(main())
