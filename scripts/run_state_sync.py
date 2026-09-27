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
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'scripts'))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import NativeLedger, address, canonical, public, sign
from run_devnet import PIN, free_ports, patch_toml, rpc, wait_until
from block_application import transaction_id
from state_tree import MAX_WITNESS_BYTES, StateTree, bind_root, enabled, encoded, hash32, verify_proof

MAX_EXECUTION_LOG_BYTES = 1_048_576
_LOG_KINDS = ('app', 'engine')
_PRIVATE_OBJECT_VALUE = re.compile(
    r"""(?is)((?:["']?)(?:priv(?:ate)?[_ -]?validator[_ -]?key|priv[_ -]?key|node[_ -]?key)(?:["']?)\s*:\s*\{[^}]{0,2048}?["']value["']\s*:\s*["'])([^"']+)(["'])"""
)
_SECRET_VALUE = re.compile(
    r"""(?i)(\b(?:private[_ -]?key|priv(?:ate)?[_ -]?validator[_ -]?key|priv[_ -]?key|privkey|node[_ -]?key|mnemonic|seed|secret|token)\b\s*[:=]\s*["']?)([^"'\s,;}]+)"""
)


def _sanitize_log(raw: bytes) -> bytes:
    text = raw.decode('utf-8', errors='replace')
    text = _PRIVATE_OBJECT_VALUE.sub(r'\g<1>[REDACTED]\g<3>', text)
    text = _SECRET_VALUE.sub(r'\g<1>[REDACTED]', text)
    return text.encode('utf-8')


class _BoundedLogCapture:
    def __init__(self, stream, path: Path, max_bytes: int):
        self.stream = stream
        self.path = path
        self.max_bytes = max_bytes
        self.buffer = bytearray()
        self.total_bytes = 0
        self.error = None
        self._thread = threading.Thread(target=self._drain, name='state-sync-log-drain', daemon=True)
        self._thread.start()

    def _drain(self):
        try:
            while True:
                chunk = self.stream.read(65536)
                if not chunk:
                    break
                self.total_bytes += len(chunk)
                remaining = self.max_bytes - len(self.buffer)
                if remaining > 0:
                    self.buffer.extend(chunk[:remaining])
        except OSError as exc:
            self.error = str(exc)
        finally:
            try:
                self.stream.close()
            except OSError:
                pass

    def finish(self) -> dict:
        self._thread.join()
        sanitized = _sanitize_log(bytes(self.buffer))
        truncated = self.total_bytes > len(self.buffer)
        if truncated:
            marker = f'\n[TRUNCATED: observed {self.total_bytes} bytes; cap={self.max_bytes}]\n'.encode()
            marker = marker[-self.max_bytes:]
            sanitized = sanitized[:max(0, self.max_bytes - len(marker))] + marker
        else:
            sanitized = sanitized[:self.max_bytes]
        self.path.write_bytes(sanitized)
        os.chmod(self.path, 0o600)
        return {'bytes': len(sanitized), 'max_bytes': self.max_bytes,
                'truncated': truncated, 'observed_bytes': self.total_bytes,
                'capture_error': self.error}


class ExecutionLogBundle:
    """Retain only sanitized, capped process output beside one runner report."""
    def __init__(self, output: Path, max_log_bytes: int = MAX_EXECUTION_LOG_BYTES):
        if type(max_log_bytes) is not int or max_log_bytes < 1:
            raise ValueError('log bound must be a positive integer')
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        self.log_dir = output.parent / f'{output.name}.logs'
        if self.log_dir.is_symlink():
            raise ValueError('refusing a symlinked execution-log directory')
        self.log_dir.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.log_dir, 0o700)
        self.max_log_bytes = max_log_bytes
        self.manifest_path = self.log_dir / 'manifest.json'
        self.runner_log = self.log_dir / 'runner.log'
        self.paths = {}
        self.captures = {}
        self.started = set()
        self.runner_bytes = bytearray()
        self.runner_total_bytes = 0
        self._finished = False

        for index in range(5):
            role = 'source' if index < 4 else 'target'
            for kind in _LOG_KINDS:
                name = f'{role}-node{index}-{kind}.log'
                path = self.log_dir / name
                if path.is_symlink():
                    raise ValueError(f'refusing a symlinked log file: {name}')
                self.paths[(role, index, kind)] = path
        allowed = {path.name for path in self.paths.values()} | {'runner.log', 'manifest.json'}
        unexpected = {path.name for path in self.log_dir.iterdir()} - allowed
        if unexpected:
            raise ValueError('execution-log directory contains unmanaged entries')
        for path in (*self.paths.values(), self.runner_log):
            path.write_bytes(b'')
            os.chmod(path, 0o600)

    def start(self, role: str, node: int, kind: str, argv: list[str]):
        key = (role, node, kind)
        if key not in self.paths:
            raise ValueError('invalid source/target process log identity')
        if key in self.started:
            raise ValueError('process log already started')
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        self.started.add(key)
        self.captures[key] = _BoundedLogCapture(proc.stdout, self.paths[key], self.max_log_bytes)
        return proc

    def record_runner(self, message):
        raw = message if isinstance(message, bytes) else str(message).encode('utf-8', errors='replace')
        if not raw:
            return
        self.runner_total_bytes += len(raw)
        remaining = self.max_log_bytes - len(self.runner_bytes)
        if remaining > 0:
            self.runner_bytes.extend(raw[:remaining])

    def finish(self, status: str):
        if self._finished:
            return
        details = {key: capture.finish() for key, capture in self.captures.items()}
        runner = _sanitize_log(bytes(self.runner_bytes))
        runner_truncated = self.runner_total_bytes > len(self.runner_bytes)
        if runner_truncated:
            marker = f'\n[TRUNCATED: observed {self.runner_total_bytes} bytes; cap={self.max_log_bytes}]\n'.encode()
            marker = marker[-self.max_log_bytes:]
            runner = runner[:max(0, self.max_log_bytes-len(marker))] + marker
        else:
            runner = runner[:self.max_log_bytes]
        self.runner_log.write_bytes(runner)
        os.chmod(self.runner_log, 0o600)

        entries = []
        for key, path in sorted(self.paths.items()):
            data = path.read_bytes()
            capture = details.get(key, {})
            role, node, kind = key
            entries.append({'path': path.name, 'role': role, 'node': node, 'process': kind,
                'started': key in self.started, 'bytes': len(data),
                'sha256': hashlib.sha256(data).hexdigest(),
                'max_bytes': self.max_log_bytes, 'truncated': capture.get('truncated', False),
                'observed_bytes': capture.get('observed_bytes', 0),
                'capture_error': capture.get('capture_error')})
        runner_entry = {'path': self.runner_log.name, 'bytes': len(runner),
            'sha256': hashlib.sha256(runner).hexdigest(), 'max_bytes': self.max_log_bytes,
            'truncated': runner_truncated, 'observed_bytes': self.runner_total_bytes}
        manifest = {'schema': 1, 'status': status, 'sanitized': True,
            'retained_content': 'bounded engine/application stdout and stderr only; no node homes, databases, or key files',
            'max_bytes_per_log': self.max_log_bytes, 'log_files': len(entries),
            'logs': entries, 'runner_log': runner_entry}
        self.manifest_path.write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
        os.chmod(self.manifest_path, 0o600)
        self._summary = {'directory': self.log_dir.name,
            'manifest': str(self.manifest_path.relative_to(self.log_dir.parent)),
            'log_files': len(entries), 'max_bytes_per_log': self.max_log_bytes,
            'max_total_log_bytes': self.max_log_bytes * (len(entries) + 1)}
        self._finished = True

    def summary(self):
        if not self._finished:
            raise RuntimeError('execution log bundle is not finalized')
        return dict(self._summary)


def receipt_history_contains(state: dict, expected_txid: str) -> bool:
    if type(state) is not dict or type(expected_txid) is not str:
        return False
    native = state.get('native')
    if type(native) is not dict:
        return False
    receipts = native.get('receipts')
    if type(receipts) is not list:
        return False
    return any(type(row) is list and bool(row) and row[0] == expected_txid for row in receipts)


def verify_compact_proof_response(response: dict, state: dict, table: str, key: str) -> dict:
    """Verify an ABCI compact proof against the recomputed matched full-state root."""
    if type(response) is not dict or type(response.get('code')) is not int or response['code'] != 0:
        raise ValueError('compact ABCI query did not succeed')
    if type(state) is not dict or set(state) != {'genesis', 'height', 'app_hash', 'native'}:
        raise ValueError('invalid matched application state')
    height = state['height']
    genesis = state['genesis']
    native = state['native']
    if type(height) is not int or height < 0 or not enabled(genesis):
        raise ValueError('matched state is not an SMT snapshot')
    response_height = response.get('height')
    if type(response_height) is int:
        decoded_height = response_height
    elif type(response_height) is str and response_height.isascii() and response_height.isdecimal():
        decoded_height = int(response_height)
        if str(decoded_height) != response_height:
            raise ValueError('noncanonical compact query height')
    else:
        raise ValueError('compact query did not return a canonical height')
    if decoded_height != height:
        raise ValueError('compact proof response height differs from matched state')

    root = StateTree(native).root
    app_hash = bind_root(hash32(encoded(genesis)).hex(), height, root)
    if state['app_hash'] != app_hash:
        raise ValueError('matched full state does not recompute to its AppHash')

    encoded_value = response.get('value')
    if type(encoded_value) is not str or not encoded_value:
        raise ValueError('compact query returned an empty proof')
    try:
        raw = base64.b64decode(encoded_value, validate=True)
        if len(raw) > MAX_WITNESS_BYTES:
            raise ValueError('compact proof exceeds its byte bound')
        witness = json.loads(raw)
    except (ValueError, TypeError) as exc:
        raise ValueError('compact query returned an invalid proof encoding') from exc
    if type(witness) is not dict or set(witness) != {
        'schema', 'commitment', 'genesis', 'height', 'root', 'app_hash', 'entries'
    }:
        raise ValueError('compact witness fields are incomplete or unexpected')
    if witness['schema'] != 1 or type(witness['schema']) is not int or witness['commitment'] != 'smt-v1':
        raise ValueError('unsupported compact witness version')
    if witness['genesis'] != genesis or witness['height'] != height or type(witness['height']) is not int:
        raise ValueError('compact witness is not bound to the matched state')
    if witness['root'] != root.hex() or witness['app_hash'] != app_hash:
        raise ValueError('compact witness root or AppHash differs from matched state')
    entries = witness['entries']
    if type(entries) is not list or len(entries) != 1:
        raise ValueError('compact witness does not contain exactly one requested proof')
    proof = entries[0]
    value = verify_proof(root, table, key, proof)
    rows = native.get(table)
    if type(rows) is not list:
        raise ValueError('requested compact state table is missing')
    matches = [row for row in rows if type(row) is list and bool(row) and row[0] == key]
    if len(matches) > 1 or value != (matches[0] if matches else None):
        raise ValueError('compact proof value differs from matched full state')
    return {'height': height, 'app_hash': app_hash, 'root': root.hex(),
            'table': table, 'key': key, 'record': value}


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
    logs = ExecutionLogBundle(output)
    try:
        version = subprocess.check_output([binary, 'version'], text=True, timeout=10).strip()
        logs.record_runner(f'CometBFT version command returned: {version}\n')
        if version.lstrip('v') != PIN:
            raise ValueError(f'requires CometBFT {PIN}; found {version!r}')
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        report.update(status='failed', reason=f'Engine version check failed: {exc}')
        if isinstance(exc, subprocess.CalledProcessError) and exc.output:
            logs.record_runner(exc.output)
        logs.record_runner(report['reason'])
        logs.finish('failed')
        report['execution_logs'] = logs.summary()
        output.write_text(json.dumps(report, indent=2) + '\n'); return report
    report['engine_version'] = version
    report['engine_sha256'] = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    logs.record_runner('Pinned engine version accepted; starting disposable state-sync run.\n')

    engine_processes = {}; app_processes = {}
    def checked(name, condition, details=None):
        report['checks'].append({'name': name, 'passed': bool(condition), 'details': details})
        if not condition:
            raise AssertionError(name)
    def stop(table, index):
        proc = table.pop(index, None)
        if proc is None:
            return
        if proc.poll() is None:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
        try:
            proc.wait(10)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            proc.wait()

    with tempfile.TemporaryDirectory(prefix='1soft-state-sync-') as raw:
        runtime = Path(raw); homes = runtime / 'nodes'
        try:
            setup = subprocess.run([binary, 'testnet', '--v', '4', '--n', '1', '--o', str(homes),
                                    '--initial-height', '1'], check=False, capture_output=True, text=True, timeout=30)
            logs.record_runner(setup.stdout or '')
            logs.record_runner(setup.stderr or '')
            if setup.returncode != 0:
                raise subprocess.CalledProcessError(setup.returncode, setup.args,
                                                    output=setup.stdout, stderr=setup.stderr)
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
                role = 'target' if i == 4 else 'source'
                app_processes[i] = logs.start(role, i, 'app', [sys.executable, str(ROOT/'scripts/serve_abci.py'),
                    '--db', str(app_db[i]), '--socket', str(sockets[i]), '--genesis', str(app_genesis)])
                wait_until(lambda i=i: sockets[i].exists() and app_processes[i].poll() is None, 10)

            def start_engine(i):
                role = 'target' if i == 4 else 'source'
                engine_processes[i] = logs.start(role, i, 'engine',
                                                  [binary, 'start', '--home', str(homes/f'node{i}')])
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
            post_snapshot_txid = transaction_id(case['post_snapshot_tx'])
            receipt_rows = target_state['native']['receipts']
            checked('post-snapshot transaction exists in target native receipt history',
                    len(receipt_rows) == 2 and receipt_history_contains(target_state, post_snapshot_txid),
                    {'transaction_id': post_snapshot_txid, 'receipt_count': len(receipt_rows)})
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
                proof = verify_compact_proof_response(response, target_state, 'accounts', case['owner'])
                checked('state-synced SMT node serves a verified compact account proof after continuation',
                        proof['record'] is not None, proof)

            report.update(status='passed', state_sync_verified=True, continued_execution_verified=True,
                          snapshot_height=marker_height, final_height=final_height,
                          trust_height=trust_height, trust_hash=trust_hash,
                          state_sync_marker=restored)
        except Exception as exc:
            report.update(status='failed', reason=f'{type(exc).__name__}: {exc}')
            logs.record_runner(report['reason'])
        finally:
            for i in list(engine_processes): stop(engine_processes, i)
            for i in list(app_processes): stop(app_processes, i)
            logs.finish(report['status'])
            report['execution_logs'] = logs.summary()
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
