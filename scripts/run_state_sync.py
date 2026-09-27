#!/usr/bin/env python3
"""Run a disposable local CometBFT state-sync bootstrap acceptance gate.

This is a development gate, not a public testnet. It requires the pinned real
CometBFT binary, four source validators, and one fresh non-validator. The fifth
node must restore application state through ABCI state sync, then execute later
blocks through normal block sync. Missing engine => UNASSESSED, never simulated.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'scripts'))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import NativeLedger, address, canonical, public, sign
from run_devnet import PIN, free_ports, patch_toml, rpc, wait_until


def _git_bytes(*args):
    try:
        result=subprocess.run(['git','-C',str(ROOT),*args],capture_output=True,timeout=3,check=False)
    except (OSError,subprocess.SubprocessError):
        return None
    return result.stdout if result.returncode==0 else None


def source_provenance(started_at: datetime) -> dict:
    runner=Path(__file__).resolve(); manifest=ROOT/'SOURCE_MANIFEST.json'
    status=_git_bytes('status','--porcelain','--untracked-files=no')
    diff=_git_bytes('diff','--binary','HEAD')
    commit=_git_bytes('rev-parse','HEAD'); tree=_git_bytes('rev-parse','HEAD^{tree}')
    return {'started_at_utc':started_at.isoformat(timespec='milliseconds').replace('+00:00','Z'),
            'runner_relative_path':str(runner.relative_to(ROOT)),
            'runner_sha256':hashlib.sha256(runner.read_bytes()).hexdigest(),
            'source_commit':commit.decode().strip() if commit is not None else None,
            'source_tree':tree.decode().strip() if tree is not None else None,
            'tracked_worktree_dirty':bool(status.strip()) if status is not None else None,
            'tracked_diff_sha256':hashlib.sha256(diff).hexdigest() if diff is not None else None,
            'source_manifest_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest() if manifest.is_file() else None}


def build_case(chain: str, protocol_version: int, *, state_commitment=None):
    if type(protocol_version) is not int or protocol_version not in (1, 3):
        raise ValueError('state-sync gate supports protocol 1 or 3')
    if state_commitment is not None and (protocol_version != 3 or state_commitment != 'smt-v1'):
        raise ValueError('smt-v1 state sync requires protocol 3')
    owner = Ed25519PrivateKey.generate(); merchant = Ed25519PrivateKey.generate()
    owner_id = address(public(owner)); merchant_id = address(public(merchant))
    genesis = {'chain_id': chain, 'asset': 'DEV', 'fee': 2,
               'allocations': [{'public_key': public(owner), 'units': 1_000_000},
                               {'public_key': public(merchant), 'units': 0}]}
    if protocol_version == 3:
        genesis['protocol_version'] = 3
    if state_commitment is not None:
        genesis['state_commitment'] = state_commitment
    ledger = NativeLedger(':memory:', genesis)
    try:
        pre = canonical(sign(owner, ledger.body(owner_id, 0,
            {'type': 'transfer', 'to': merchant_id, 'units': 111}, valid_until=10_000)))
        # The second transfer is intentionally created with the next owner nonce;
        # it is submitted only AFTER the new node has recorded a state-sync marker.
        post = canonical(sign(owner, ledger.body(owner_id, 1,
            {'type': 'transfer', 'to': merchant_id, 'units': 77}, valid_until=10_000)))
    finally:
        ledger.close()
    return {'genesis': genesis, 'owner': owner_id, 'merchant': merchant_id,
            'pre_snapshot_tx': pre, 'post_snapshot_tx': post}


def _db(path: Path):
    uri = path.resolve().as_uri() + '?mode=ro'
    db = sqlite3.connect(uri, uri=True, timeout=2)
    db.row_factory = sqlite3.Row
    return db


def marker(path: Path):
    if not path.exists():
        return None
    try:
        db = _db(path)
        try:
            row = db.execute('SELECT height,app_hash FROM state_sync_marker WHERE id=1').fetchone()
            return None if row is None else {'height': int(row['height']), 'app_hash': row['app_hash']}
        finally:
            db.close()
    except sqlite3.Error:
        return None


def committed(path: Path):
    db = _db(path)
    try:
        row = db.execute('SELECT height,app_hash,state FROM committed WHERE id=1').fetchone()
        if row is None:
            return None
        return {'height': int(row['height']), 'app_hash': row['app_hash'], 'state': json.loads(row['state'])}
    finally:
        db.close()


def block_record(path: Path, height: int):
    db = _db(path)
    try:
        row = db.execute('SELECT block_hash,tx_digest,app_hash,results FROM blocks WHERE height=?', (height,)).fetchone()
        if row is None:
            return None
        return {'block_hash': row['block_hash'], 'tx_digest': row['tx_digest'],
                'app_hash': row['app_hash'], 'results': json.loads(row['results'])}
    finally:
        db.close()


def min_block_height(path: Path):
    db = _db(path)
    try:
        row = db.execute('SELECT min(height) FROM blocks').fetchone()
        return None if row[0] is None else int(row[0])
    finally:
        db.close()


def run(engine: str, output: Path, protocol_version: int = 1, *, state_commitment=None):
    if type(protocol_version) is not int or protocol_version not in (1, 3):
        raise ValueError('state-sync gate supports protocol 1 or 3')
    if state_commitment is not None and (protocol_version != 3 or state_commitment != 'smt-v1'):
        raise ValueError('smt-v1 state sync requires protocol 3')
    started = datetime.now(timezone.utc)
    report = {'schema': 1, 'status': 'unassessed', 'engine_required': PIN,
              'protocol_version': protocol_version,
              'state_commitment': state_commitment or 'legacy-flat-v1',
              'scope': 'four local source validators plus one fresh local non-validator; not independent operators',
              'source_provenance': source_provenance(started), 'checks': [],
              'state_sync_verified': False, 'continued_execution_verified': False,
              'public_network': False, 'real_funds': False}
    output.parent.mkdir(parents=True, exist_ok=True)
    binary = shutil.which(engine) if '/' not in engine else str(Path(engine).resolve())
    if not binary or not Path(binary).is_file():
        report['reason'] = 'Pinned CometBFT executable is not installed. No state-sync engine step occurred.'
        output.write_text(json.dumps(report, indent=2) + '\n'); return report
    try:
        version = subprocess.check_output([binary, 'version'], text=True, timeout=10).strip()
        if version.lstrip('v') != PIN:
            raise ValueError(f'requires CometBFT {PIN}; found {version!r}')
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        report.update(status='failed', reason=f'Engine version check failed: {exc}')
        output.write_text(json.dumps(report, indent=2) + '\n'); return report
    report['engine_version'] = version
    report['engine_sha256'] = hashlib.sha256(Path(binary).read_bytes()).hexdigest()

    engine_processes = {}; app_processes = {}; handles = []
    def checked(name, condition, details=None):
        report['checks'].append({'name': name, 'passed': bool(condition), 'details': details})
        if not condition:
            raise AssertionError(name)
    def stop(table, index):
        proc = table.pop(index, None)
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try: proc.wait(10)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()

    with tempfile.TemporaryDirectory(prefix='1soft-state-sync-') as raw:
        runtime = Path(raw); homes = runtime / 'nodes'
        try:
            subprocess.run([binary, 'testnet', '--v', '4', '--n', '1', '--o', str(homes),
                            '--initial-height', '1'], check=True, capture_output=True, text=True, timeout=30)
            for path in homes.rglob('*'):
                if path.is_dir(): os.chmod(path, 0o700)
                elif path.is_file(): os.chmod(path, 0o600)
            chain = '1soft-statesync-' + os.urandom(6).hex()
            case = build_case(chain, protocol_version, state_commitment=state_commitment)
            genesis = case['genesis']
            app_genesis = runtime / 'app-genesis.json'; app_genesis.write_bytes(canonical(genesis))
            p2p = free_ports(5); http = free_ports(5)
            ids = [subprocess.check_output([binary, 'show-node-id', '--home', str(homes/f'node{i}')],
                                           text=True).strip() for i in range(5)]
            rootgen = json.loads((homes/'node0/config/genesis.json').read_text())
            rootgen.update(chain_id=chain, initial_height='1', app_state=genesis)
            rootgen['consensus_params']['block'].update(max_bytes='1048576', max_gas='-1')
            public_genesis = (json.dumps(rootgen, indent=2) + '\n').encode()
            (output.parent/'state-sync-public-genesis.json').write_bytes(public_genesis)
            report['genesis_file_sha256'] = hashlib.sha256(public_genesis).hexdigest()

            app_db = {}; sockets = {}
            for i in range(5):
                home = homes/f'node{i}'
                (home/'config/genesis.json').write_text(json.dumps(rootgen, indent=2) + '\n')
                appdir = runtime/f'app{i}'; appdir.mkdir(mode=0o700)
                sockets[i] = appdir/'a.sock'; app_db[i] = appdir/'app.sqlite'
                peers = range(4) if i == 4 else [j for j in range(4) if j != i]
                updates = {'proxy_app': f'unix://{sockets[i]}', 'abci': 'socket',
                           'rpc.laddr': f'tcp://127.0.0.1:{http[i]}', 'rpc.unsafe': False,
                           'p2p.laddr': f'tcp://127.0.0.1:{p2p[i]}',
                           'p2p.persistent_peers': ','.join(f'{ids[j]}@127.0.0.1:{p2p[j]}' for j in peers),
                           'p2p.addr_book_strict': False, 'p2p.allow_duplicate_ip': True, 'p2p.pex': False,
                           'consensus.timeout_commit': '500ms', 'mempool.max_tx_bytes': 16384}
                conf = home/'config/config.toml'; conf.write_text(patch_toml(conf.read_text(), updates))
                log = open(runtime/f'app{i}.log', 'ab'); handles.append(log)
                app_processes[i] = subprocess.Popen([sys.executable, str(ROOT/'scripts/serve_abci.py'),
                    '--db', str(app_db[i]), '--socket', str(sockets[i]), '--genesis', str(app_genesis)],
                    stdout=log, stderr=log)
                wait_until(lambda i=i: sockets[i].exists() and app_processes[i].poll() is None, 10)

            def start_engine(i):
                log = open(runtime/f'engine{i}.log', 'ab'); handles.append(log)
                engine_processes[i] = subprocess.Popen([binary, 'start', '--home', str(homes/f'node{i}')],
                                                        stdout=log, stderr=log)
            for i in range(4): start_engine(i)
            def height(i): return int(rpc(http[i], 'status')['sync_info']['latest_block_height'])
            wait_until(lambda: all(height(i) >= 2 for i in range(4)), 45)
            checked('four source validators are producing blocks', True,
                    {'heights': [height(i) for i in range(4)]})

            first = rpc(http[0], 'broadcast_tx_commit', {'tx': base64.b64encode(case['pre_snapshot_tx']).decode()})
            checked('pre-snapshot native transfer committed', int(first['check_tx']['code']) == 0 and
                    int(first['tx_result']['code']) == 0, {'height': first.get('height')})
            wait_until(lambda: all(height(i) >= int(first['height']) for i in range(4)), 30)

            trust_height = max(1, height(0) - 1)
            trust_block = rpc(http[0], 'block', {'height': str(trust_height)})
            trust_hash = trust_block['block_id']['hash']
            require_hash = isinstance(trust_hash, str) and len(trust_hash) == 64
            checked('state-sync trust height/hash captured from running source chain', require_hash,
                    {'trust_height': trust_height, 'trust_hash': trust_hash})

            # Configure the fifth, never-started CometBFT node for state sync. The
            # application was already started empty with an explicit expected genesis.
            conf = homes/'node4/config/config.toml'
            conf.write_text(patch_toml(conf.read_text(), {
                'statesync.enable': True,
                'statesync.rpc_servers': f'http://127.0.0.1:{http[0]},http://127.0.0.1:{http[1]}',
                'statesync.trust_height': trust_height,
                'statesync.trust_hash': trust_hash,
                'statesync.trust_period': '168h0m0s',
                'statesync.discovery_time': '5s',
                'statesync.chunk_request_timeout': '5s',
                'statesync.chunk_fetchers': 2,
                'statesync.max_snapshot_chunks': 64,
            }))
            start_engine(4)
            restored = wait_until(lambda: marker(app_db[4]), 75)
            checked('fresh non-validator application was installed through state sync',
                    restored is not None and restored['height'] > 0, restored)
            marker_height = restored['height']
            source_marker_block = block_record(app_db[0], marker_height)
            checked('restored marker AppHash matches source block at that exact height',
                    source_marker_block is not None and source_marker_block['app_hash'] == restored['app_hash'],
                    {'marker': restored, 'source_block': source_marker_block})
            checked('restored application did not invent source block metadata at snapshot height',
                    block_record(app_db[4], marker_height) is None)

            # This transaction is created ahead of time but submitted only after
            # state sync has durably installed the earlier account nonce/state.
            second = rpc(http[0], 'broadcast_tx_commit', {'tx': base64.b64encode(case['post_snapshot_tx']).decode()})
            checked('post-snapshot transfer committed on source chain', int(second['check_tx']['code']) == 0 and
                    int(second['tx_result']['code']) == 0 and int(second['height']) > marker_height,
                    {'height': second.get('height'), 'snapshot_height': marker_height})
            wait_until(lambda: height(0) >= max(marker_height + 3, int(second['height']) + 1), 30)

            # Drop below 2/3 validator power but keep two source peers online so
            # the target can finish block sync against a stable chain head.
            stop(engine_processes, 3); stop(engine_processes, 2)
            time.sleep(2)
            def stable_head():
                a = height(0); time.sleep(2); b = height(0)
                return a if a == b else None
            final_height = wait_until(stable_head, 20)
            checked('source chain head is stable after quorum loss', final_height > marker_height,
                    {'snapshot_height': marker_height, 'final_height': final_height})
            wait_until(lambda: height(4) >= final_height, 60)
            checked('state-synced node continued through ordinary block sync', height(4) == final_height,
                    {'target_height': height(4), 'final_height': final_height})

            def state(i):
                response = rpc(http[i], 'abci_query', {'path': '/state', 'prove': False})['response']
                if int(response['code']) != 0: raise RuntimeError('full-state query failed')
                return json.loads(base64.b64decode(response['value']))
            source_state = state(0); target_state = state(4)
            checked('source and state-synced applications agree at frozen head', source_state == target_state,
                    {'height': source_state['height'], 'app_hash': source_state['app_hash']})
            checked('post-snapshot transaction exists in target native receipt history',
                    len(target_state['native']['receipts']) == 2)
            persisted_marker = marker(app_db[4])
            checked('state-sync provenance marker survives later block execution', persisted_marker == restored,
                    persisted_marker)
            first_target_block = min_block_height(app_db[4])
            checked('target block metadata starts strictly after restored snapshot',
                    first_target_block is not None and first_target_block > marker_height,
                    {'first_target_block': first_target_block, 'snapshot_height': marker_height})
            target_committed = committed(app_db[4]); source_committed = committed(app_db[0])
            checked('target durable application checkpoint equals source checkpoint',
                    target_committed == source_committed)
            if state_commitment == 'smt-v1':
                response = rpc(http[4], 'abci_query', {'path': '/proof/accounts/' + case['owner'].encode().hex(),
                                                       'prove': False})['response']
                checked('state-synced SMT node serves compact proof after continuation', int(response['code']) == 0)

            report.update(status='passed', state_sync_verified=True, continued_execution_verified=True,
                          snapshot_height=marker_height, final_height=final_height,
                          trust_height=trust_height, trust_hash=trust_hash,
                          state_sync_marker=restored)
        except Exception as exc:
            report.update(status='failed', reason=f'{type(exc).__name__}: {exc}')
        finally:
            for i in list(engine_processes): stop(engine_processes, i)
            for i in list(app_processes): stop(app_processes, i)
            for handle in handles: handle.close()
    output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cometbft', default='cometbft')
    p.add_argument('--output', type=Path, default=ROOT/'evidence/state-sync/devnet.json')
    p.add_argument('--protocol-version', type=int, choices=(1, 3), default=1)
    p.add_argument('--state-commitment', choices=('smt-v1',), default=None)
    args = p.parse_args()
    report = run(args.cometbft, args.output, args.protocol_version, state_commitment=args.state_commitment)
    return 0 if report['status'] == 'passed' else 2


if __name__ == '__main__':
    raise SystemExit(main())
