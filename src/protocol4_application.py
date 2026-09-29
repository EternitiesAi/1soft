"""Fresh-genesis protocol-4 monetary and validator state in one durable commit.

This bounded development application does not migrate an older chain, expose a
public service, or qualify custody. P1/P2/P3 application bytes stay separate.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
from typing import Any

from block_application import (BlockApplication, StoreLock, encode, restore, snapshot,
                               transaction_data_size)
from commit_verifier import VerificationError, load_json
from native_core import NativeLedger, Reject, digest, parse_wire, require
from protocol4_abci_wire import encode_finalization
from registry_rules_core import RegistryRules, RegistryReject
from validator_sets_core import ValidatorSet

APP_NAME = '1soft-protocol4-development'
APP_VERSION = 4
MAX_HEIGHT = 512  # Shared with the retained development registry history.
MAX_TXS = 64
MAX_TX_BYTES = 65_536
MAX_BLOCK_BYTES = 1_048_576
MAX_CANDIDATES = 128
STATE_DOMAIN = b'1soft/protocol4/composite-apphash/v1\x00'


def application_hash(genesis: dict, height: int, state: dict) -> str:
    material = {'genesis_sha256': digest(genesis), 'height': height,
                'native': state['native'], 'registry': state['registry']}
    return hashlib.sha256(STATE_DOMAIN + encode(material)).hexdigest()


def _classify(raw: bytes) -> str:
    try:
        packet = load_json(raw, max_bytes=MAX_TX_BYTES)
        if type(packet) is not dict or encode(packet) != raw:
            return 'invalid'
        if set(packet) == {'body', 'signature'}:
            return 'money'
        if set(packet) == {'body', 'approvals'}:
            return 'registry'
    except (VerificationError, ValueError, UnicodeError):
        pass
    return 'invalid'


def _votes(rows: list[dict], expected: list[dict], height: int) -> None:
    if height == 1:
        require(not rows, 'height-one last commit must be empty')
        return
    validators = ValidatorSet.parse(expected).validators
    wanted = {v.address.hex(): v.power for v in validators}
    observed = {v['address']: v['power'] for v in rows}
    require(len(observed) == len(rows) and observed == wanted,
            'last-commit validator roster differs from protocol-4 state')
    require(all(type(v['block_id_flag']) is int for v in rows),
            'invalid last-commit vote flag')
    require(all(v['block_id_flag'] in (1, 2, 3) for v in rows),
            'unsupported last-commit vote flag')
    require(sum(v['power'] for v in rows if v['block_id_flag'] == 2) * 3 >
            sum(wanted.values()) * 2, 'insufficient last-commit voting power')


class Protocol4Application:
    def __init__(self, path: str | Path, *, expected_genesis: dict | None = None):
        self.lock = threading.RLock()
        self.pending: dict | None = None
        self.expected_genesis = expected_genesis
        self.genesis: dict | None = None
        self.rules: RegistryRules | None = None
        self.state: dict | None = None
        self.height = 0
        self.app_hash = ''
        self.closed = False
        self.store_lock = None
        if str(path) != ':memory:':
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self.store_lock = StoreLock(p.with_name(p.name + '.lock'))
        try:
            self.db = sqlite3.connect(str(path), isolation_level=None, timeout=10,
                                      check_same_thread=False)
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.executescript('''
              CREATE TABLE IF NOT EXISTS committed (id INTEGER PRIMARY KEY CHECK(id=1),
                genesis TEXT NOT NULL, height INTEGER NOT NULL,
                app_hash TEXT NOT NULL, state TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS blocks (height INTEGER PRIMARY KEY,
                block_hash TEXT NOT NULL, request_sha256 TEXT NOT NULL,
                txs TEXT NOT NULL, result TEXT NOT NULL, response BLOB NOT NULL);
              CREATE TABLE IF NOT EXISTS history (height INTEGER PRIMARY KEY,
                txs TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS snapshot_marker (id INTEGER PRIMARY KEY CHECK(id=1),
                height INTEGER NOT NULL, app_hash TEXT NOT NULL);
            ''')
            row = self.db.execute(
                'SELECT genesis,height,app_hash,state FROM committed WHERE id=1').fetchone()
            if row is not None:
                genesis, height, app_hash, state = row
                genesis, state = json.loads(genesis), json.loads(state)
                require(expected_genesis is None or digest(expected_genesis) == digest(genesis),
                        'protocol-4 genesis differs')
                self._validate_genesis(genesis)
                self.rules = RegistryRules(genesis['validator_registry'],
                                           bound_genesis_sha256=digest(genesis))
                self._audit_state(genesis, state, height, app_hash)
                if height > 0:
                    block = self.db.execute(
                        'SELECT result,response FROM blocks WHERE height=?', (height,)).fetchone()
                    marker = self.db.execute(
                        'SELECT height,app_hash FROM snapshot_marker WHERE id=1').fetchone()
                    require(block is not None or marker == (height, app_hash),
                            'committed protocol-4 response or snapshot marker missing')
                    if block is not None:
                        result = json.loads(block[0])
                        require(result['app_hash'] == app_hash and
                                bytes(block[1]) == encode_finalization(result),
                                'committed protocol-4 response differs')
                    self._audit_history(genesis, state, height, app_hash, self.history())
                self.genesis, self.state, self.height, self.app_hash = genesis, state, height, app_hash
            from protocol4_state_sync import Protocol4StateSync
            self.state_sync = Protocol4StateSync(self)
        except BaseException:
            if hasattr(self, 'db'):
                self.db.close()
            if self.store_lock is not None:
                self.store_lock.close()
            raise

    @staticmethod
    def _validate_genesis(genesis: dict) -> None:
        require(type(genesis) is dict and genesis.get('protocol_version') == 4,
                'fresh protocol-4 genesis required')
        ledger = NativeLedger(':memory:', genesis)
        try:
            ledger.verify_receipts()
        finally:
            ledger.close()

    def _audit_state(self, genesis: dict, state: dict, height: int, app_hash: str) -> None:
        require(type(state) is dict and set(state) == {'native', 'registry'},
                'invalid protocol-4 composite state')
        require(type(height) is int and 0 <= height <= MAX_HEIGHT,
                'protocol-4 height out of development bound')
        rules = RegistryRules(genesis['validator_registry'], bound_genesis_sha256=digest(genesis))
        rules.audit_state(state['registry'])
        require(state['registry']['height'] == height, 'registry height differs from money checkpoint')
        ledger = restore(genesis, state['native'])
        try:
            ledger.verify_receipts()
        finally:
            ledger.close()
        require(application_hash(genesis, height, state) == app_hash,
                'composite protocol-4 AppHash differs')

    def history(self) -> list[dict]:
        """Replay inputs only; block identities and votes are not state-sync trust."""
        rows = self.db.execute('SELECT height,txs FROM history ORDER BY height').fetchall()
        return [{'height': h, 'txs': json.loads(txs)} for h, txs in rows]

    @staticmethod
    def _wire_from_b64(value: str) -> bytes:
        require(type(value) is str, 'invalid protocol-4 transaction encoding')
        try:
            raw = base64.b64decode(value, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise Reject('invalid protocol-4 transaction encoding') from exc
        require(base64.b64encode(raw).decode('ascii') == value,
                'noncanonical protocol-4 transaction encoding')
        return raw

    @classmethod
    def _audit_history(cls, genesis: dict, state: dict, height: int,
                       app_hash: str, history: list[dict], *, strict_txs: bool = False) -> None:
        require(type(history) is list and len(history) == height,
                'protocol-4 block history is incomplete')
        candidate = cls(':memory:', expected_genesis=genesis)
        try:
            candidate.init_chain(genesis['chain_id'], genesis,
                                 genesis['validator_registry']['validators'])
            for expected_height, row in enumerate(history, 1):
                require(type(row) is dict and set(row) == {'height', 'txs'} and
                        type(row['height']) is int and row['height'] == expected_height,
                        'invalid protocol-4 block history row')
                require(type(row['txs']) is list, 'invalid protocol-4 transaction history')
                txs = [cls._wire_from_b64(value) for value in row['txs']]
                cls._bounds(txs)
                next_state, replay = candidate._execute(txs, expected_height)
                if strict_txs:
                    require(all(item['code'] == 0 for item in replay['tx_results']),
                            'snapshot history contains nonexecuting transactions')
                candidate.state, candidate.height, candidate.app_hash = (
                    next_state, expected_height, replay['app_hash'])
            require(candidate.state == state and candidate.app_hash == app_hash,
                    'protocol-4 history does not reach committed state')
        finally:
            candidate.close()

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.pending = None
            self.db.close()
            if self.store_lock is not None:
                self.store_lock.close()
            self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def info(self) -> dict:
        with self.lock:
            return {'name': APP_NAME, 'version': APP_VERSION, 'height': self.height,
                    'app_hash': self.app_hash, 'initialized': self.genesis is not None}

    def init_chain(self, chain_id: str, genesis: dict, initial_validators: list[dict],
                   initial_height: int = 1) -> str:
        with self.lock:
            require(type(initial_height) is int and initial_height in (0, 1),
                    'unsupported initial protocol-4 height')
            require(chain_id == genesis.get('chain_id'), 'engine chain differs')
            if self.expected_genesis is not None:
                require(digest(genesis) == digest(self.expected_genesis),
                        'unexpected protocol-4 genesis')
            self._validate_genesis(genesis)
            rules = RegistryRules(genesis['validator_registry'],
                                  bound_genesis_sha256=digest(genesis))
            wanted = {v.public_key.hex(): v.power for v in
                      ValidatorSet.parse(rules.genesis['validators']).validators}
            observed = {v['public_key']: v['power'] for v in initial_validators}
            require(len(observed) == len(initial_validators) and observed == wanted,
                    'engine initial validators differ from protocol-4 genesis')
            if self.genesis is not None:
                require(digest(genesis) == digest(self.genesis) and self.height == 0,
                        'protocol-4 chain already initialized')
                return self.app_hash
            ledger = NativeLedger(':memory:', genesis)
            try:
                state = {'native': snapshot(ledger), 'registry': rules.initial_state()}
            finally:
                ledger.close()
            app_hash = application_hash(genesis, 0, state)
            self._audit_state(genesis, state, 0, app_hash)
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute('INSERT INTO committed VALUES (1,?,?,?,?)',
                                (encode(genesis).decode(), 0, app_hash, encode(state).decode()))
                self.db.execute('COMMIT')
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute('ROLLBACK')
                raise
            self.genesis, self.rules, self.state, self.app_hash = genesis, rules, state, app_hash
            return app_hash

    @staticmethod
    def _bounds(txs: list[bytes]) -> None:
        require(type(txs) is list and len(txs) <= MAX_TXS and
                all(type(raw) is bytes and len(raw) <= MAX_TX_BYTES for raw in txs),
                'protocol-4 block transaction bound exceeded')
        require(transaction_data_size(txs) <= MAX_BLOCK_BYTES,
                'protocol-4 block byte bound exceeded')

    def _execute(self, txs: list[bytes], height: int) -> tuple[dict, dict]:
        require(self.genesis is not None and self.state is not None and self.rules is not None,
                'protocol-4 chain not initialized')
        self._bounds(txs)
        require(type(height) is int and height == self.height + 1 and height <= MAX_HEIGHT,
                'protocol-4 block height differs')
        classes = [_classify(raw) for raw in txs]
        registry_txs = [raw for raw, kind in zip(txs, classes) if kind == 'registry']
        registry_state, registry_result = self.rules.transition(
            self.state['registry'], registry_txs, height)
        registry_results = iter(registry_result['tx_results'])
        ledger = restore(self.genesis, self.state['native'])
        results = []
        try:
            # Money and administration mutate disjoint domains; each domain keeps
            # its original relative transaction order and results retain block order.
            for raw, kind in zip(txs, classes):
                if kind == 'registry':
                    results.append(next(registry_results))
                elif kind == 'money':
                    try:
                        receipt = BlockApplication._apply(ledger, raw, height)
                        results.append({'code': 0, 'log': '', 'data': receipt['txid']})
                    except Reject as exc:
                        results.append({'code': 1, 'log': str(exc), 'data': ''})
                else:
                    results.append({'code': 1, 'log': 'unrecognized protocol-4 transaction', 'data': ''})
            state = {'native': snapshot(ledger), 'registry': registry_state}
        finally:
            ledger.close()
        app_hash = application_hash(self.genesis, height, state)
        result = {'height': height, 'app_hash': app_hash, 'tx_results': results,
                  'validator_updates': registry_result['validator_updates'],
                  'validators_hash': registry_result['validators_hash'],
                  'next_validators_hash': registry_result['next_validators_hash']}
        return state, result

    def check_tx(self, raw: bytes) -> dict:
        with self.lock:
            try:
                _, result = self._execute([raw], self.height + 1)
                return result['tx_results'][0]
            except (Reject, RegistryReject, VerificationError) as exc:
                return {'code': 1, 'log': str(exc), 'data': ''}

    def prepare_proposal(self, candidates: list[bytes], height: int, max_bytes: int) -> list[bytes]:
        with self.lock:
            require(height == self.height + 1 and type(max_bytes) is int and max_bytes >= 0,
                    'invalid protocol-4 proposal context')
            accepted: list[bytes] = []
            used = 0
            for raw in candidates[:MAX_CANDIDATES]:
                if len(accepted) >= MAX_TXS or type(raw) is not bytes or len(raw) > MAX_TX_BYTES:
                    continue
                cost = transaction_data_size([raw])
                if used + cost > min(max_bytes, MAX_BLOCK_BYTES):
                    continue
                try:
                    _, result = self._execute(accepted + [raw], height)
                except (Reject, RegistryReject, VerificationError):
                    continue
                if all(item['code'] == 0 for item in result['tx_results']):
                    accepted.append(raw)
                    used += cost
            return accepted

    def process_proposal(self, txs: list[bytes], height: int,
                         next_validators_hash: bytes) -> bool:
        with self.lock:
            try:
                _, result = self._execute(txs, height)
                return (all(item['code'] == 0 for item in result['tx_results']) and
                        type(next_validators_hash) is bytes and len(next_validators_hash) == 32 and
                        next_validators_hash.hex() == result['next_validators_hash'])
            except (Reject, RegistryReject, VerificationError):
                return False

    def finalize_block(self, txs: list[bytes], height: int, block_hash: bytes,
                       next_validators_hash: bytes, last_commit_votes: list[dict],
                       request_wire: bytes) -> tuple[dict, bytes]:
        with self.lock:
            require(type(block_hash) is bytes and len(block_hash) == 32 and
                    type(request_wire) is bytes and len(request_wire) <= 2_097_152,
                    'invalid protocol-4 finalization identity')
            request_sha = hashlib.sha256(request_wire).hexdigest()
            if height == self.height and self.height > 0:
                row = self.db.execute(
                    'SELECT block_hash,request_sha256,result,response FROM blocks WHERE height=?',
                    (height,)).fetchone()
                require(row is not None and row[0] == block_hash.hex() and row[1] == request_sha,
                        'conflicting committed protocol-4 FinalizeBlock replay')
                return json.loads(row[2]), bytes(row[3])
            require(height == self.height + 1, 'protocol-4 finalize height differs')
            if self.pending is not None:
                require(self.pending['request_sha256'] == request_sha and
                        self.pending['block_hash'] == block_hash.hex(),
                        'conflicting pending protocol-4 FinalizeBlock')
                return json.loads(encode(self.pending['result'])), self.pending['response']
            require(self.state is not None, 'protocol-4 chain not initialized')
            _votes(last_commit_votes, self.state['registry']['active_validators'], height)
            state, result = self._execute(txs, height)
            require(type(next_validators_hash) is bytes and len(next_validators_hash) == 32 and
                    next_validators_hash.hex() == result['next_validators_hash'],
                    'engine next-validator commitment differs from protocol-4 result')
            result['last_commit_votes'] = json.loads(encode(last_commit_votes))
            response = encode_finalization(result)
            self.pending = {'state': state, 'result': result, 'response': response,
                            'request_sha256': request_sha, 'block_hash': block_hash.hex(),
                            'txs': [base64.b64encode(raw).decode('ascii') for raw in txs]}
            return json.loads(encode(result)), response

    def commit(self, *, fault: str = '') -> dict:
        with self.lock:
            require(fault in ('', 'after_state', 'after_result', 'before_commit',
                              'exit_before_commit', 'exit_after_commit'),
                    'unknown protocol-4 fault hook')
            if self.pending is None:
                return self.info()
            pending = self.pending
            result = pending['result']
            self._audit_state(self.genesis, pending['state'], result['height'], result['app_hash'])
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute('UPDATE committed SET height=?,app_hash=?,state=? WHERE id=1',
                                (result['height'], result['app_hash'], encode(pending['state']).decode()))
                if fault == 'after_state':
                    raise RuntimeError('injected protocol-4 fault after composite state')
                self.db.execute('INSERT INTO blocks VALUES (?,?,?,?,?,?)',
                                (result['height'], pending['block_hash'], pending['request_sha256'],
                                 encode(pending['txs']).decode(), encode(result).decode(),
                                 pending['response']))
                self.db.execute('INSERT INTO history VALUES (?,?)',
                                (result['height'], encode(pending['txs']).decode()))
                self.db.execute('DELETE FROM snapshot_marker')
                if fault == 'after_result':
                    raise RuntimeError('injected protocol-4 fault after response')
                if fault == 'before_commit':
                    raise RuntimeError('injected protocol-4 fault before commit')
                if fault == 'exit_before_commit':
                    os._exit(94)
                self.db.execute('COMMIT')
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute('ROLLBACK')
                raise
            if fault == 'exit_after_commit':
                os._exit(95)
            self.state = pending['state']
            self.height = result['height']
            self.app_hash = result['app_hash']
            self.pending = None
            return self.info()

    def committed_result(self, height: int) -> dict:
        with self.lock:
            row = self.db.execute('SELECT result,response FROM blocks WHERE height=?', (height,)).fetchone()
            require(row is not None, 'protocol-4 response unavailable')
            result = json.loads(row[0])
            require(bytes(row[1]) == encode_finalization(result),
                    'protocol-4 response bytes differ')
            return result

    def list_snapshots(self) -> list[dict]:
        return self.state_sync.list()

    def load_snapshot_chunk(self, height: int, format_: int, index: int) -> bytes:
        return self.state_sync.load(height, format_, index)

    def offer_snapshot(self, snapshot: dict, app_hash: bytes) -> int:
        return self.state_sync.offer(snapshot, app_hash)

    def apply_snapshot_chunk(self, index: int, chunk: bytes, sender: str) -> dict:
        return self.state_sync.apply(index, chunk, sender)

    def query(self, path: str, height: int = 0, prove: bool = False) -> dict:
        with self.lock:
            try:
                require(not prove and height in (0, self.height) and self.state is not None,
                        'unsupported protocol-4 query context')
                if path == '/state':
                    value = {'genesis': self.genesis, 'height': self.height,
                             'app_hash': self.app_hash, **self.state}
                elif path == '/registry-state':
                    value = self.state['registry']
                elif path == '/info':
                    value = self.info()
                elif path.startswith('/block/'):
                    suffix = path[len('/block/'):]
                    require(re.fullmatch(r'[1-9][0-9]{0,2}', suffix) is not None,
                            'invalid protocol-4 block height')
                    wanted = int(suffix)
                    require(wanted <= MAX_HEIGHT, 'protocol-4 block height out of bound')
                    value = self.committed_result(wanted)
                elif path.startswith('/account/'):
                    name = path[len('/account/'):]
                    rows = [r for r in self.state['native']['accounts'] if r[0] == name]
                    require(bool(rows), 'unknown account')
                    value = rows[0]
                else:
                    raise Reject('unknown protocol-4 query path')
                return {'code': 0, 'height': self.height, 'value': encode(value), 'log': ''}
            except (Reject, ValueError) as exc:
                return {'code': 1, 'height': self.height, 'value': b'', 'log': str(exc)}
