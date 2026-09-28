"""ABCI-facing native application; no consensus algorithm lives in this module.

Only Commit persists a decided block. Proposal/check calls use isolated copies.
The durable snapshot includes receipts because replay detection is consensus state.
This full-snapshot design is intentionally a bounded-development implementation.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
from typing import Any

from native_core import NativeLedger, Reject, canonical, digest, integer, parse_wire, require, DOMAIN
from execution_snapshot import ExecutionSnapshot, ExecutionSnapshotFault
from admission_cache import AdmissionCache, AdmissionLimits

APP_VERSION = 3  # highest supported; each genesis pins its own execution version
APP_NAME = '1soft-native-dev'
MAX_BLOCK_TXS = 64
MAX_BLOCK_BYTES = 1_048_576
MAX_TX_BYTES = 16_384
# Local proposer selection only. Not used to reject a peer's valid block.
MAX_PROPOSAL_CANDIDATES = 1024
MAX_PROPOSAL_INSPECT_BYTES = 4 * 1024 * 1024
TABLES = {
    'meta': ('k', 'v'),
    'accounts': ('id', 'public_key', 'nonce', 'epoch', 'balance'),
    'grants': ('id', 'owner', 'public_key', 'epoch', 'nonce', 'cap', 'spent', 'expires', 'recipients', 'revoked'),
    'receipts': ('txid', 'sequence', 'previous', 'record', 'hash'),
}
ORDER = {'meta': 'k', 'accounts': 'id', 'grants': 'id', 'receipts': 'sequence'}


def tables_for(genesis):
    if genesis.get('protocol_version', 1) == 3:
        from native_budgets import BUDGET_COLUMNS, LINK_COLUMNS
        return {**TABLES, 'budgets': BUDGET_COLUMNS, 'grant_budgets': LINK_COLUMNS}
    return TABLES


def order_for(name):
    return {'budgets': 'id', 'grant_budgets': 'grant_id'}.get(name, ORDER.get(name))


def encode(value: Any) -> bytes:
    """Internal state encoding. Not the bounded transaction serializer."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def snapshot(ledger: NativeLedger) -> dict[str, list[list[Any]]]:
    return {name: [list(row) for row in ledger.db.execute(
        f"SELECT {','.join(cols)} FROM {name} ORDER BY {order_for(name)}")]
        for name, cols in tables_for(ledger.genesis).items()}


def restore(genesis: dict[str, Any], state: dict[str, Any] | None = None) -> NativeLedger:
    ledger = NativeLedger(':memory:', genesis)
    if state is not None:
        require(type(state) is dict and set(state) == set(tables_for(genesis)), 'invalid snapshot tables')
        ledger.db.execute('BEGIN IMMEDIATE')
        try:
            for name, cols in tables_for(genesis).items():
                require(type(state[name]) is list, 'invalid snapshot rows')
                require(all(type(row) is list and len(row) == len(cols) for row in state[name]),
                        'invalid snapshot row shape')
                ledger.db.execute(f'DELETE FROM {name}')
                ledger.db.executemany(f"INSERT INTO {name} VALUES ({','.join('?' for _ in cols)})", state[name])
            ledger.db.execute('COMMIT')
            require(dict(ledger.db.execute('SELECT k,v FROM meta'))['genesis'] == digest(genesis),
                    'snapshot genesis mismatch')
            ledger.verify_receipts()
        except Exception:
            if ledger.db.in_transaction:
                ledger.db.execute('ROLLBACK')
            ledger.close()
            raise
    return ledger


def application_hash(genesis: dict[str, Any], height: int, state: dict[str, Any]) -> str:
    # Opt-in commitment changes only on a freshly pinned genesis. Legacy byte
    # commitments remain unchanged when this field is absent.
    from state_tree import enabled, StateTree, bind_root
    if enabled(genesis):
        return bind_root(digest(genesis), height, StateTree(state).root)
    # Receipt data participates: a different replay set must NOT share an AppHash.
    material = {'domain': 'ETERNITIES/ABCI-STATE/v1', 'genesis': digest(genesis),
                'height': height, 'native': state}
    return hashlib.sha256(encode(material)).hexdigest()


def transaction_data_size(txs: list[bytes]) -> int:
    """Exact size of CometBFT's protobuf Data.txs (field 1, repeated bytes).

    Matches types.ComputeProtoSizeForTxs: each entry has a one-byte field
    tag and a varint length delimiter. Even an empty entry occupies two bytes.
    """
    require(type(txs) is list and all(type(tx) is bytes for tx in txs), 'invalid transactions')
    return sum(1 + max(1, (len(tx).bit_length() + 6) // 7) + len(tx) for tx in txs)


def transaction_id(raw: bytes) -> str:
    envelope = parse_wire(raw)
    require(canonical(envelope) == raw, 'noncanonical transaction')
    require(type(envelope.get('body')) is dict, 'invalid transaction body')
    return hashlib.sha256(DOMAIN + canonical(envelope['body'])).hexdigest()


class StoreLock:
    """Single writer process for a local node. Never reset a validator to recover it."""
    def __init__(self, path: Path):
        self.handle = path.open('a+b')
        try:
            if os.name == 'posix':
                import fcntl
                fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                import msvcrt
                self.handle.seek(0)
                if not self.handle.read(1):
                    self.handle.write(b'\0'); self.handle.flush()
                self.handle.seek(0)
                msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as exc:
            self.handle.close()
            raise Reject('node store already in use') from exc

    def close(self):
        self.handle.close()


class BlockApplication:
    """Serialized ABCI lifecycle with atomic durable height/hash/native-state commit."""
    def __init__(self, path: str | Path, *, expected_genesis: dict[str, Any] | None = None,
                 proof_index: bool = True, execution_cache: bool = True,
                 admission_cache: bool = True, admission_limits: AdmissionLimits | None = None,
                 block_history_keep: int | None = None):
        from block_history import validate_keep
        validate_keep(block_history_keep)
        self.block_history = None
        require(type(proof_index) is bool, 'proof_index must be a boolean')
        require(type(execution_cache) is bool, 'execution_cache must be a boolean')
        require(type(admission_cache) is bool, 'admission_cache must be a boolean')
        self._admission = AdmissionCache(admission_limits) if admission_cache else None
        if not admission_cache and admission_limits is not None:
            raise ValueError('admission limits require an enabled admission cache')
        self.use_execution_cache = execution_cache
        self._execution: ExecutionSnapshot | None = None
        self._pending_execution: ExecutionSnapshot | None = None
        self.use_proof_index = proof_index
        self.proof_index = None
        self.lock = threading.RLock()
        self.pending: dict[str, Any] | None = None
        self.genesis: dict[str, Any] | None = None
        self.height = 0
        self.app_hash = ''
        self.native: dict[str, Any] | None = None
        self.expected_genesis = expected_genesis
        self.store_lock = None
        self.closed = False
        if str(path) != ':memory:':
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self.store_lock = StoreLock(p.with_name(p.name + '.lock'))
        try:
            self.db = sqlite3.connect(str(path), isolation_level=None, timeout=10, check_same_thread=False)
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.executescript('''
              CREATE TABLE IF NOT EXISTS committed (id INTEGER PRIMARY KEY CHECK(id=1),
                genesis TEXT NOT NULL, height INTEGER NOT NULL, app_hash TEXT NOT NULL, state TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS blocks (height INTEGER PRIMARY KEY, block_hash TEXT NOT NULL,
                tx_digest TEXT NOT NULL, app_hash TEXT NOT NULL, results TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS state_sync_marker (id INTEGER PRIMARY KEY CHECK(id=1),
                height INTEGER NOT NULL, app_hash TEXT NOT NULL);
            ''')
            from state_sync import StateSyncManager
            self.state_sync = StateSyncManager(self)
            row = self.db.execute('SELECT genesis,height,app_hash,state FROM committed WHERE id=1').fetchone()
            if row is not None:
                genesis, height, app_hash, state = row
                genesis = json.loads(genesis); state = json.loads(state)
                require(expected_genesis is None or digest(expected_genesis) == digest(genesis), 'genesis mismatch')
                require(application_hash(genesis, height, state) == app_hash, 'stored application hash mismatch')
                # Disk input always takes the full validation path before any
                # process-local execution image is trusted. Never load a cache
                # from a peer or restore one from a second persistent file.
                checked = restore(genesis, state)
                try:
                    if height > 0:
                        block = self.db.execute('SELECT app_hash FROM blocks WHERE height=?', (height,)).fetchone()
                        if block is None:
                            marker = self.db.execute('SELECT height,app_hash FROM state_sync_marker WHERE id=1').fetchone()
                            require(marker == (height, app_hash), 'incomplete committed block without state-sync marker')
                        else:
                            require(block[0] == app_hash, 'incomplete committed block')
                    self.genesis, self.height, self.app_hash, self.native = genesis, height, app_hash, state
                    self._open_proof_index()
                    if self.use_execution_cache:
                        self._execution = ExecutionSnapshot.from_validated_ledger(checked, height, app_hash)
                finally:
                    checked.close()
            from block_history import BlockHistory
            self.block_history = BlockHistory.open(self.db, block_history_keep, self.height, self.app_hash)
        except Exception:
            if self._execution is not None: self._execution.close()
            if hasattr(self, 'db'): self.db.close()
            if self.store_lock: self.store_lock.close()
            raise

    def _open_proof_index(self):
        """Build a missing derived index once, or audit it without silent repair."""
        from state_tree import enabled
        if self.genesis is None or not enabled(self.genesis):
            return
        if not self.use_proof_index:
            exists = self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='proof_checkpoint'").fetchone()
            require(exists is None or self.db.execute('SELECT 1 FROM proof_checkpoint').fetchone() is None,
                    'cannot disable an initialized proof index on this node')
            return
        from state_index import StateIndex
        self.db.execute('BEGIN IMMEDIATE')
        try:
            index = StateIndex(self.db)
            if index.checkpoint() is None:
                index.initialize(digest(self.genesis), self.height, self.native, self.app_hash)
            else:
                index.audit(digest(self.genesis), self.height, self.app_hash)
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise
        self.proof_index = index

    def close(self):
        with self.lock:
            if not self.closed:
                self.pending = None
                if hasattr(self, 'state_sync'): self.state_sync.clear()
                if self._admission is not None: self._admission.clear()
                if self._pending_execution is not None: self._pending_execution.close()
                if self._execution is not None: self._execution.close()
                self._pending_execution = self._execution = None
                self.db.close()
                if self.store_lock: self.store_lock.close()
                self.closed = True

    def info(self) -> dict[str, Any]:
        with self.lock:
            version = (self.genesis or self.expected_genesis or {}).get('protocol_version', 1)
            return {'name': APP_NAME, 'version': version, 'height': self.height,
                    'app_hash': self.app_hash, 'initialized': self.genesis is not None}

    def init_chain(self, chain_id: str, genesis: dict[str, Any], initial_height: int = 1) -> str:
        with self.lock:
            require(initial_height in (0, 1) and type(initial_height) is int, 'only initial height 1 supported')
            require(chain_id == genesis.get('chain_id'), 'engine/application chain mismatch')
            if self.expected_genesis is not None:
                require(digest(genesis) == digest(self.expected_genesis), 'unexpected genesis')
            if self.genesis is not None:
                require(digest(genesis) == digest(self.genesis), 'genesis mismatch')
                # A restarted initialized app reports Info; InitChain is only a height-zero operation.
                require(self.height == 0, 'already started chain')
                return self.app_hash
            ledger = restore(genesis)
            candidate = None
            try:
                state = snapshot(ledger)
                genesis = json.loads(encode(genesis))
                app_hash = application_hash(genesis, 0, state)
                if self.use_execution_cache:
                    candidate = ExecutionSnapshot.from_validated_ledger(ledger, 0, app_hash)
            finally:
                ledger.close()
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute('INSERT INTO committed VALUES (1,?,?,?,?)',
                                (encode(genesis).decode(), 0, app_hash, encode(state).decode()))
                self.db.execute('DELETE FROM state_sync_marker')
                from state_tree import enabled
                index = None
                if self.use_proof_index and enabled(genesis):
                    from state_index import StateIndex
                    index = StateIndex(self.db)
                    index.initialize(digest(genesis), 0, state, app_hash)
                if self.block_history is not None:
                    self.block_history.init_chain(app_hash)
                self.db.execute('COMMIT')
            except BaseException:
                if self.db.in_transaction: self.db.execute('ROLLBACK')
                if candidate is not None: candidate.close()
                raise
            self.genesis, self.native, self.app_hash = genesis, state, app_hash
            self.proof_index = index
            self._execution = candidate
            return app_hash

    def _copy(self) -> NativeLedger:
        require(self.genesis is not None, 'chain not initialized')
        if self.use_execution_cache:
            if self._execution is None:
                raise ExecutionSnapshotFault('committed execution image is missing')
            return self._execution.fork(digest(self.genesis), self.height, self.app_hash)
        # Explicit slow reference for regression/equivalence tests, not a fallback
        # that hides a missing or inconsistent execution image.
        return restore(self.genesis, self.native)

    @staticmethod
    def _bounds(txs: list[bytes]):
        require(type(txs) is list and len(txs) <= MAX_BLOCK_TXS, 'too many transactions')
        require(all(type(tx) is bytes and len(tx) <= MAX_TX_BYTES for tx in txs), 'transaction too large')
        require(transaction_data_size(txs) <= MAX_BLOCK_BYTES, 'block too large')

    @staticmethod
    def _apply(ledger: NativeLedger, raw: bytes, height: int) -> dict[str, Any]:
        txid = transaction_id(raw)
        # NativeLedger's offline idempotence must not make chain replays charge-free valid txs.
        require(ledger.db.execute('SELECT 1 FROM receipts WHERE txid=?', (txid,)).fetchone() is None,
                'transaction already executed')
        return ledger.apply(parse_wire(raw), height=height)

    def check_tx(self, raw: bytes) -> dict[str, Any]:
        """Same deterministic admission answer; exact repeats may reuse it.

        Cache entries are scoped to committed state AND height. Nothing from
        this cache is used for Prepare/ProcessProposal, FinalizeBlock or Commit.
        Cache misses and changed signed bytes still execute native validation.
        """
        with self.lock:
            ledger = None
            retain = False
            try:
                self._bounds([raw])
                require(self.genesis is not None, 'chain not initialized')
                # A memoized answer must not hide a damaged execution image.
                if self.use_execution_cache:
                    if self._execution is None:
                        raise ExecutionSnapshotFault('committed execution image is missing')
                    self._execution.assert_checkpoint(digest(self.genesis), self.height, self.app_hash)
                if self._admission is not None:
                    self._admission.bind(digest(self.genesis), self.height, self.app_hash)
                    answer = self._admission.get(raw)
                    if answer is not None:
                        return answer
                    retain = True
                # Reject malformed/noncanonical JSON before cloning database pages.
                # Same precondition and error as _apply; not a signature shortcut.
                transaction_id(raw)
                ledger = self._copy()
                record = self._apply(ledger, raw, self.height + 1)
                answer = {'code': 0, 'log': '', 'data': record['txid']}
            except Reject as exc:
                answer = {'code': 1, 'log': str(exc), 'data': ''}
            finally:
                if ledger is not None: ledger.close()
            if retain:
                self._admission.put(raw, answer)
            return answer

    def admission_stats(self) -> dict[str, Any]:
        """Operator-local diagnostic only; no unauthenticated metrics service."""
        with self.lock:
            return {'enabled':False} if self._admission is None else {'enabled':True, **self._admission.stats()}

    def prepare_proposal(self, txs: list[bytes], height: int, max_bytes: int) -> list[bytes]:
        with self.lock:
            require(height == self.height + 1, 'proposal height mismatch')
            require(type(max_bytes) is int and max_bytes >= 0, 'invalid proposal bound')
            require(type(txs) is list, 'invalid proposal candidates')
            ledger = self._copy(); accepted = []; used = 0; inspected_bytes = 0
            try:
                for index, raw in enumerate(txs):
                    if index >= MAX_PROPOSAL_CANDIDATES or len(accepted) >= MAX_BLOCK_TXS: break
                    if type(raw) is bytes:
                        inspected_bytes += len(raw)
                        if inspected_bytes > MAX_PROPOSAL_INSPECT_BYTES: break
                    if type(raw) is not bytes or len(raw) > MAX_TX_BYTES: continue
                    cost = transaction_data_size([raw])
                    if used + cost > min(max_bytes, MAX_BLOCK_BYTES): continue
                    try: self._apply(ledger, raw, height)
                    except Reject: continue
                    accepted.append(raw); used += cost
                return accepted
            finally:
                ledger.close()

    def process_proposal(self, txs: list[bytes], height: int) -> bool:
        with self.lock:
            ledger = None
            try:
                require(height == self.height + 1, 'proposal height mismatch')
                self._bounds(txs); ledger = self._copy()
                for raw in txs: self._apply(ledger, raw, height)
                return True
            except Reject:
                return False
            finally:
                if ledger is not None: ledger.close()

    def finalize_block(self, txs: list[bytes], height: int, block_hash: bytes) -> dict[str, Any]:
        with self.lock:
            require(height == self.height + 1, 'finalize height mismatch')
            require(type(block_hash) is bytes and len(block_hash) == 32, 'invalid block hash')
            self._bounds(txs)
            tx_digest = hashlib.sha256(encode([base64.b64encode(x).decode() for x in txs])).hexdigest()
            identity = (height, block_hash.hex(), tx_digest)
            if self.pending is not None:
                require(identity == self.pending['identity'], 'conflicting pending block')
                return json.loads(encode(self.pending['result']))
            ledger = self._copy(); results = []
            try:
                for raw in txs:
                    try:
                        record = self._apply(ledger, raw, height)
                        results.append({'code': 0, 'log': '', 'data': record['txid']})
                    except Reject as exc:
                        # Defensive deterministic execution of an already-decided block.
                        # Honest ProcessProposal rejects such candidates before voting.
                        results.append({'code': 1, 'log': str(exc), 'data': ''})
                state = snapshot(ledger)
                app_hash = application_hash(self.genesis, height, state)
                result = {'height': height, 'app_hash': app_hash, 'tx_results': results}
                candidate = (ExecutionSnapshot.from_validated_ledger(ledger, height, app_hash)
                             if self.use_execution_cache else None)
                self.pending = {'identity': identity, 'state': state, 'result': result}
                self._pending_execution = candidate
                return json.loads(encode(result))
            finally:
                ledger.close()

    def commit(self, *, fault: str = '') -> dict[str, Any]:
        """The sole durable block transition. Fault hooks are local test-only inputs."""
        with self.lock:
            if self.pending is None:
                return self.info()  # commit retry with no pending work is a no-op
            p = self.pending
            height, block_hash, tx_digest = p['identity']
            result = p['result']
            if self.use_execution_cache:
                if self._execution is None or self._pending_execution is None:
                    raise ExecutionSnapshotFault('execution image missing at commit')
                self._execution.assert_checkpoint(digest(self.genesis), self.height, self.app_hash)
                self._pending_execution.assert_checkpoint(digest(self.genesis), height, result['app_hash'])
            self.db.execute('BEGIN IMMEDIATE')
            try:
                self.db.execute('UPDATE committed SET height=?,app_hash=?,state=? WHERE id=1',
                                (height, result['app_hash'], encode(p['state']).decode()))
                if fault == 'after_state': raise RuntimeError('injected failure after state update')
                if fault == 'exit_after_state': os._exit(91)
                if self.proof_index is not None:
                    self.proof_index.advance(digest(self.genesis), self.height, self.app_hash,
                                             height, self.native, p['state'], result['app_hash'])
                if fault == 'after_index': raise RuntimeError('injected failure after proof index update')
                if fault == 'exit_after_index': os._exit(93)
                self.db.execute('INSERT INTO blocks VALUES (?,?,?,?,?)',
                                (height, block_hash, tx_digest, result['app_hash'], encode(result['tx_results']).decode()))
                if self.block_history is not None:
                    self.block_history.advance(self.height, self.app_hash, height, result['app_hash'])
                # Preserve the state-sync marker as a local recovery/provenance receipt.
                # It is not consensus state and is ignored once later block metadata exists.
                if fault == 'before_commit': raise RuntimeError('injected failure before commit')
                self.db.execute('COMMIT')
            except Exception:
                if self.db.in_transaction: self.db.execute('ROLLBACK')
                raise
            if fault == 'exit_after_commit': os._exit(92)
            self.height, self.app_hash, self.native = height, result['app_hash'], p['state']
            old_execution = self._execution
            self._execution, self._pending_execution = self._pending_execution, None
            self.pending = None
            if self._admission is not None: self._admission.clear()
            if old_execution is not None: old_execution.close()
            return self.info()


    def list_snapshots(self) -> list[dict[str, Any]]:
        with self.lock:
            return self.state_sync.list()

    def offer_snapshot(self, snapshot: dict[str, Any], app_hash: bytes) -> int:
        with self.lock:
            return self.state_sync.offer(snapshot, app_hash)

    def load_snapshot_chunk(self, height: int, format_: int, index: int) -> bytes:
        with self.lock:
            return self.state_sync.load(height, format_, index)

    def apply_snapshot_chunk(self, index: int, chunk: bytes, sender: str) -> dict[str, Any]:
        with self.lock:
            return self.state_sync.apply(index, chunk, sender)

    def compact_witness(self, queries: list[tuple[str, str]]) -> dict[str, Any]:
        """Prove committed records only; never exposes a pending proposal root.

        JSON project proofs, not ICS23/ABCI ProofOps. SMT chains use a persistent
        derived index by default. The reference rebuild path remains selectable.
        """
        from state_tree import make_witness
        with self.lock:
            require(self.genesis is not None, 'chain not initialized')
            if self.proof_index is not None:
                witness = self.proof_index.witness(self.genesis, self.height, self.app_hash, queries)
            else:
                witness = make_witness(self.genesis, self.height, self.native, queries)
            require(witness['app_hash'] == self.app_hash, 'proof/committed-state mismatch')
            return witness

    def query(self, path: str, height: int = 0, prove: bool = False) -> dict[str, Any]:
        with self.lock:
            try:
                require(not prove, 'authenticated query proofs not implemented')
                require(height in (0, self.height), 'historical queries not implemented')
                require(self.genesis is not None, 'chain not initialized')
                if path.startswith('/proof/'):
                    # Exact path; no untrusted SQL identifiers or arbitrary paths.
                    from state_tree import selector, ProofError
                    try:
                        parts = path.split('/')
                        require(len(parts) == 4 and len(parts[3]) <= 1024,
                                'invalid compact query path')
                        key = bytes.fromhex(parts[3]).decode('ascii')
                        require(key.encode('ascii').hex() == parts[3], 'noncanonical query key')
                        table, key = selector(parts[2], key)
                        value = self.compact_witness([(table, key)])
                    except (ValueError, UnicodeError) as exc:
                        raise Reject(str(exc)) from exc
                elif path == '/state':
                    value = {'genesis': self.genesis, 'height': self.height,
                             'app_hash': self.app_hash, 'native': self.native}
                elif path == '/history':
                    from block_history import describe
                    value = describe(self)
                elif path == '/info': value = self.info()
                elif path.startswith('/block/'):
                    text = path[len('/block/'):]
                    require(text.isascii() and text.isdecimal() and len(text) <= 16 and
                            text == str(int(text)) and int(text) > 0, 'invalid committed block height')
                    wanted = int(text)
                    require(wanted <= self.height, 'block not committed')
                    row = self.db.execute('SELECT block_hash,tx_digest,app_hash,results FROM blocks WHERE height=?',
                                          (wanted,)).fetchone()
                    if row is None and self.block_history is not None:
                        reason = self.block_history.classify_missing(wanted, self.height, self.app_hash)
                        return {'code': 2, 'height': self.height,
                                'value': encode({'schema': 1, 'status': reason, 'requested_height': wanted,
                                                 'historical_transaction_absence_proven': False}),
                                'log': 'Local history unavailable; this does not prove nonexecution.'}
                    require(row is not None, 'committed block unavailable')
                    value = {'height': wanted, 'block_hash': row[0], 'tx_digest': row[1],
                             'app_hash': row[2], 'tx_results': json.loads(row[3])}
                elif path.startswith('/account/'):
                    account = path[len('/account/'):]
                    rows = [dict(zip(TABLES['accounts'], r)) for r in self.native['accounts'] if r[0] == account]
                    require(bool(rows), 'unknown account'); value = rows[0]
                elif path.startswith('/receipt/'):
                    txid = path[len('/receipt/'):]
                    rows = [json.loads(r[3]) for r in self.native['receipts'] if r[0] == txid]
                    require(bool(rows), 'unknown transaction'); value = rows[0]
                else: raise Reject('unknown query path')
                return {'code': 0, 'height': self.height, 'value': encode(value), 'log': ''}
            except Reject as exc:
                return {'code': 1, 'height': self.height, 'value': b'', 'log': str(exc)}
