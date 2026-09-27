"""Bounded ABCI state snapshots for trusted-light-client state sync.

Only CometBFT's light-client-verified AppHash is authoritative. Snapshot metadata,
peer senders and chunk contents are untrusted until the complete payload is
reconstructed, hashed, re-executed through native snapshot validation, and matched
against the offered AppHash. Restores are accepted only into an uninitialized application or its untouched
state-sync checkpoint after an interrupted CometBFT bootstrap. Both require an
explicitly expected native genesis.

This remains a development state-sync design: snapshots contain the complete
native state including receipts, so size grows with history. No pruning, remote
snapshot store, dynamic validator trust, public service, or production operator
claim is introduced here.
"""
from __future__ import annotations

from collections import OrderedDict
import hashlib
import sqlite3
from typing import Any

from commit_verifier import load_json
from execution_snapshot import ExecutionSnapshot
from native_core import Reject, digest, require

FORMAT = 1
DOMAIN = '1soft/state-sync/v1'
HASH_DOMAIN = b'1soft/state-sync/v1\x00'
CHUNK_BYTES = 262_144
MAX_CHUNKS = 64
MAX_SNAPSHOT_BYTES = CHUNK_BYTES * MAX_CHUNKS
MAX_METADATA_BYTES = 4096
MAX_CACHED_SNAPSHOTS = 2

# CometBFT v0.38 ResponseOfferSnapshot.Result
OFFER_ACCEPT = 1
OFFER_ABORT = 2
OFFER_REJECT = 3
OFFER_REJECT_FORMAT = 4
# CometBFT v0.38 ResponseApplySnapshotChunk.Result
APPLY_ACCEPT = 1
APPLY_ABORT = 2
APPLY_RETRY = 3
APPLY_RETRY_SNAPSHOT = 4
APPLY_REJECT_SNAPSHOT = 5


def _encoded(value: Any) -> bytes:
    # Imported lazily to avoid a module-import cycle with block_application.
    from block_application import encode
    return encode(value)


def _snapshot_hash(payload: bytes) -> bytes:
    return hashlib.sha256(HASH_DOMAIN + payload).digest()


def _metadata(genesis: dict, height: int, app_hash: str, payload_bytes: int, chunks: int) -> bytes:
    return _encoded({'schema': 1, 'domain': DOMAIN, 'format': FORMAT, 'height': height,
                     'chunks': chunks, 'chunk_bytes': CHUNK_BYTES,
                     'payload_bytes': payload_bytes, 'genesis_sha256': digest(genesis),
                     'app_hash': app_hash})


def _descriptor(height: int, payload: bytes, genesis: dict, app_hash: str) -> dict:
    require(type(height) is int and 1 <= height <= 2**63-2, 'invalid snapshot height')
    require(type(payload) is bytes and 0 < len(payload) <= MAX_SNAPSHOT_BYTES,
            'snapshot exceeds state-sync bound')
    chunks = (len(payload) + CHUNK_BYTES - 1) // CHUNK_BYTES
    require(1 <= chunks <= MAX_CHUNKS, 'invalid snapshot chunk count')
    metadata = _metadata(genesis, height, app_hash, len(payload), chunks)
    require(len(metadata) <= MAX_METADATA_BYTES, 'snapshot metadata exceeds bound')
    return {'height': height, 'format': FORMAT, 'chunks': chunks,
            'hash': _snapshot_hash(payload), 'metadata': metadata}


def _parse_metadata(raw: bytes) -> dict:
    require(type(raw) is bytes and len(raw) <= MAX_METADATA_BYTES, 'invalid snapshot metadata')
    try:
        value = load_json(raw, max_bytes=MAX_METADATA_BYTES)
    except Exception as exc:
        raise Reject('invalid snapshot metadata') from exc
    expected = {'schema','domain','format','height','chunks','chunk_bytes','payload_bytes',
                'genesis_sha256','app_hash'}
    require(type(value) is dict and set(value) == expected, 'invalid snapshot metadata fields')
    require(_encoded(value) == raw, 'snapshot metadata must use canonical JSON')
    require(value['schema'] == 1 and type(value['schema']) is int and value['domain'] == DOMAIN,
            'unsupported snapshot metadata')
    require(type(value['format']) is int and value['format'] == FORMAT, 'unsupported snapshot format')
    require(type(value['height']) is int and 1 <= value['height'] <= 2**63-2,
            'invalid metadata height')
    require(type(value['chunks']) is int and 1 <= value['chunks'] <= MAX_CHUNKS,
            'invalid metadata chunk count')
    require(type(value['chunk_bytes']) is int and value['chunk_bytes'] == CHUNK_BYTES,
            'unsupported snapshot chunk size')
    require(type(value['payload_bytes']) is int and 0 < value['payload_bytes'] <= MAX_SNAPSHOT_BYTES,
            'invalid snapshot payload size')
    require((value['payload_bytes'] + CHUNK_BYTES - 1) // CHUNK_BYTES == value['chunks'],
            'snapshot size/chunk count mismatch')
    require(type(value['genesis_sha256']) is str and len(value['genesis_sha256']) == 64,
            'invalid snapshot genesis digest')
    require(type(value['app_hash']) is str and len(value['app_hash']) == 64,
            'invalid snapshot app hash')
    try:
        bytes.fromhex(value['genesis_sha256']); bytes.fromhex(value['app_hash'])
    except ValueError as exc:
        raise Reject('invalid snapshot digest encoding') from exc
    return value


class StateSyncManager:
    """Process-local snapshot serving/restoration state owned by one application."""
    def __init__(self, app):
        self.app = app
        self._served: OrderedDict[tuple[int,int,str], tuple[dict,bytes]] = OrderedDict()
        self._offer: dict | None = None

    def clear(self) -> None:
        self._served.clear(); self._offer = None

    def _checkpoint_only(self) -> bool:
        """Whether only a prior snapshot install, not block sync, changed the app."""
        app = self.app
        if app.genesis is None or app.expected_genesis is None or app.height <= 0:
            return False
        committed = app.db.execute(
            'SELECT height,app_hash FROM committed WHERE id=1').fetchone()
        marker = app.db.execute(
            'SELECT height,app_hash FROM state_sync_marker WHERE id=1').fetchone()
        return (committed == (app.height, app.app_hash) and
                marker == (app.height, app.app_hash) and
                digest(app.genesis) == digest(app.expected_genesis) and
                app.db.execute('SELECT 1 FROM blocks LIMIT 1').fetchone() is None)

    def _payload(self) -> bytes:
        app = self.app
        require(app.genesis is not None and app.native is not None and app.height > 0,
                'no committed state-sync snapshot available')
        payload = _encoded({'schema':1, 'domain':DOMAIN, 'genesis':app.genesis,
                            'height':app.height, 'app_hash':app.app_hash, 'native':app.native})
        require(len(payload) <= MAX_SNAPSHOT_BYTES, 'committed state exceeds snapshot bound')
        return payload

    def list(self) -> list[dict]:
        app = self.app
        if app.genesis is None or app.height <= 0:
            return []
        try:
            payload = self._payload()
            desc = _descriptor(app.height, payload, app.genesis, app.app_hash)
        except Reject:
            # An oversized development chain advertises no snapshot rather than
            # emitting an unusable descriptor or destabilizing the ABCI server.
            return []
        key = (desc['height'], desc['format'], desc['hash'].hex())
        self._served[key] = (desc, payload)
        self._served.move_to_end(key)
        while len(self._served) > MAX_CACHED_SNAPSHOTS:
            self._served.popitem(last=False)
        return [dict(desc)]

    def load(self, height: int, format_: int, index: int) -> bytes:
        require(type(height) is int and 1 <= height <= 2**63-2, 'invalid snapshot height')
        require(type(format_) is int and format_ == FORMAT, 'unsupported snapshot format')
        require(type(index) is int and 0 <= index < MAX_CHUNKS, 'invalid snapshot chunk index')
        found = None
        for key, item in reversed(self._served.items()):
            if key[0] == height and key[1] == format_:
                found = item; break
        if found is None and self.app.genesis is not None and self.app.height == height:
            snapshots = self.list()
            if snapshots:
                return self.load(height, format_, index)
        if found is None:
            return b''
        desc, payload = found
        if index >= desc['chunks']:
            return b''
        start = index * CHUNK_BYTES
        return payload[start:start + CHUNK_BYTES]

    def offer(self, snapshot: dict, app_hash: bytes) -> int:
        self._offer = None
        app = self.app
        checkpoint_recovery = self._checkpoint_only()
        has_committed = app.db.execute('SELECT 1 FROM committed').fetchone() is not None
        if (app.genesis is not None or has_committed) and not checkpoint_recovery:
            return OFFER_ABORT
        if app.expected_genesis is None:
            return OFFER_ABORT
        if type(snapshot) is not dict:
            return OFFER_REJECT
        format_ = snapshot.get('format')
        if type(format_) is not int or format_ != FORMAT:
            return OFFER_REJECT_FORMAT
        try:
            height = snapshot.get('height'); chunks = snapshot.get('chunks')
            hash_ = snapshot.get('hash'); metadata_raw = snapshot.get('metadata')
            require(type(height) is int and 1 <= height <= 2**63-2, 'invalid offered height')
            if checkpoint_recovery and height < app.height:
                return OFFER_REJECT
            require(type(chunks) is int and 1 <= chunks <= MAX_CHUNKS, 'invalid offered chunk count')
            require(type(hash_) is bytes and len(hash_) == 32, 'invalid offered snapshot hash')
            require(type(app_hash) is bytes and len(app_hash) == 32, 'invalid trusted app hash')
            metadata = _parse_metadata(metadata_raw)
            require(metadata['height'] == height and metadata['format'] == format_ and
                    metadata['chunks'] == chunks, 'snapshot descriptor/metadata mismatch')
            require(metadata['genesis_sha256'] == digest(app.expected_genesis),
                    'snapshot is for a different native genesis')
            require(bytes.fromhex(metadata['app_hash']) == app_hash,
                    'snapshot metadata differs from trusted app hash')
            self._offer = {'height':height, 'format':format_, 'chunks':chunks,
                           'hash':hash_, 'app_hash':app_hash.hex(), 'metadata':metadata,
                           'parts':[], 'bytes':0, 'checkpoint_recovery':checkpoint_recovery}
            return OFFER_ACCEPT
        except Reject:
            self._offer = None
            return OFFER_REJECT

    def _validate_payload(self, raw: bytes, offer: dict):
        from block_application import application_hash, restore, tables_for
        try:
            payload = load_json(raw, max_bytes=MAX_SNAPSHOT_BYTES)
        except Exception as exc:
            raise Reject('invalid snapshot payload') from exc
        require(type(payload) is dict and set(payload) ==
                {'schema','domain','genesis','height','app_hash','native'},
                'invalid snapshot payload fields')
        try:
            canonical_payload = _encoded(payload)
        except (TypeError, ValueError, OverflowError) as exc:
            raise Reject('invalid snapshot payload values') from exc
        require(canonical_payload == raw, 'snapshot payload must use canonical JSON')
        require(payload['schema'] == 1 and type(payload['schema']) is int and payload['domain'] == DOMAIN,
                'unsupported snapshot payload')
        require(payload['height'] == offer['height'] and type(payload['height']) is int,
                'snapshot payload height mismatch')
        require(payload['app_hash'] == offer['app_hash'] and type(payload['app_hash']) is str,
                'snapshot payload AppHash mismatch')
        genesis = payload['genesis']; state = payload['native']
        require(type(genesis) is dict and digest(genesis) == digest(self.app.expected_genesis),
                'snapshot payload genesis mismatch')
        tables = tables_for(genesis)
        require(type(state) is dict and set(state) == set(tables),
                'snapshot payload native tables mismatch')
        for name, columns in tables.items():
            rows = state[name]
            require(type(rows) is list and
                    all(type(row) is list and len(row) == len(columns) for row in rows),
                    'invalid snapshot native rows')
            require(all(type(value) is str or
                        (type(value) is int and -(2**63) <= value < 2**63)
                        for row in rows for value in row),
                    'invalid snapshot native row value')
        try:
            checked = restore(genesis, state)
        except sqlite3.IntegrityError as exc:
            # Constraints raised while loading peer rows into restore()'s fresh
            # in-memory ledger reject that candidate. _install() runs later on
            # the application database and remains fail-stop on local faults.
            raise Reject('snapshot native rows violate ledger constraints') from exc
        try:
            require(application_hash(genesis, payload['height'], state) == offer['app_hash'],
                    'snapshot state does not match trusted AppHash')
        except BaseException:
            checked.close()
            raise
        return payload, checked

    def _install(self, payload: dict, checked, *, checkpoint_recovery: bool = False) -> None:
        from block_application import encode
        from state_tree import enabled
        app = self.app
        candidate = None
        index = None
        try:
            if app.use_execution_cache:
                candidate = ExecutionSnapshot.from_validated_ledger(
                    checked, payload['height'], payload['app_hash'])
            app.db.execute('BEGIN IMMEDIATE')
            try:
                if checkpoint_recovery:
                    require(self._checkpoint_only() and payload['height'] >= app.height,
                            'state-sync checkpoint changed before recovery install')
                    app.db.execute('DELETE FROM committed')
                else:
                    require(app.genesis is None and
                            app.db.execute('SELECT 1 FROM committed').fetchone() is None,
                            'application initialized during state sync')
                app.db.execute('DELETE FROM blocks')
                app.db.execute('DELETE FROM state_sync_marker')
                app.db.execute('INSERT INTO committed VALUES (1,?,?,?,?)',
                    (encode(payload['genesis']).decode(), payload['height'], payload['app_hash'],
                     encode(payload['native']).decode()))
                app.db.execute('INSERT INTO state_sync_marker VALUES (1,?,?)',
                               (payload['height'], payload['app_hash']))
                if app.use_proof_index and enabled(payload['genesis']):
                    from state_index import StateIndex
                    index = StateIndex(app.db)
                    if checkpoint_recovery:
                        app.db.execute('DELETE FROM proof_checkpoint')
                        app.db.execute('DELETE FROM proof_nodes')
                    index.initialize(digest(payload['genesis']), payload['height'],
                                     payload['native'], payload['app_hash'])
                app.db.execute('COMMIT')
            except BaseException:
                if app.db.in_transaction: app.db.execute('ROLLBACK')
                raise
            old = app._execution
            app.genesis = payload['genesis']
            app.height = payload['height']
            app.app_hash = payload['app_hash']
            app.native = payload['native']
            app.proof_index = index
            app._execution = candidate
            candidate = None
            app.pending = None
            if app._pending_execution is not None:
                app._pending_execution.close(); app._pending_execution = None
            if app._admission is not None: app._admission.clear()
            if old is not None: old.close()
        finally:
            if candidate is not None: candidate.close()

    def apply(self, index: int, chunk: bytes, sender: str) -> dict:
        offer = self._offer
        if offer is None:
            return {'result': APPLY_ABORT, 'refetch_chunks': [], 'reject_senders': []}
        try:
            require(type(index) is int and 0 <= index < offer['chunks'], 'invalid chunk index')
            require(type(chunk) is bytes and 0 < len(chunk) <= CHUNK_BYTES, 'invalid snapshot chunk')
            require(type(sender) is str and len(sender.encode('utf-8')) <= 256, 'invalid snapshot sender')
            expected = len(offer['parts'])
            if index < expected:
                if offer['parts'][index] == chunk:
                    return {'result': APPLY_ACCEPT, 'refetch_chunks': [], 'reject_senders': []}
                self._offer = None
                return {'result': APPLY_REJECT_SNAPSHOT, 'refetch_chunks': [], 'reject_senders': []}
            if index > expected:
                return {'result': APPLY_RETRY, 'refetch_chunks': [expected], 'reject_senders': []}
            if index + 1 < offer['chunks']:
                require(len(chunk) == CHUNK_BYTES, 'short non-final snapshot chunk')
            new_total = offer['bytes'] + len(chunk)
            require(new_total <= offer['metadata']['payload_bytes'] <= MAX_SNAPSHOT_BYTES,
                    'snapshot chunks exceed declared size')
            offer['parts'].append(bytes(chunk)); offer['bytes'] = new_total
            if len(offer['parts']) < offer['chunks']:
                return {'result': APPLY_ACCEPT, 'refetch_chunks': [], 'reject_senders': []}
            raw = b''.join(offer['parts'])
            require(len(raw) == offer['metadata']['payload_bytes'], 'snapshot payload length mismatch')
            require(_snapshot_hash(raw) == offer['hash'], 'snapshot hash mismatch')
            payload, checked = self._validate_payload(raw, offer)
            try:
                self._install(payload, checked,
                              checkpoint_recovery=offer['checkpoint_recovery'])
            finally:
                checked.close()
            self._offer = None
            return {'result': APPLY_ACCEPT, 'refetch_chunks': [], 'reject_senders': []}
        except Reject:
            self._offer = None
            # A whole-snapshot/hash failure cannot safely identify which peer
            # supplied the bad chunk, so do not ask CometBFT to ban a sender.
            return {'result': APPLY_REJECT_SNAPSHOT, 'refetch_chunks': [], 'reject_senders': []}
