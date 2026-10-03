"""Versioned composite snapshots for the bounded fresh-genesis protocol-4 chain.

The engine supplies a light-client-verified AppHash in OfferSnapshot. Neither a
peer's metadata nor a snapshot's self-reported hash is a trust root. Ordered
transaction inputs are carried so monetary execution and signed registry actions
can be replayed from the exact expected genesis before a checkpoint is installed.
They are not authenticated block IDs, votes, or historical response evidence.
"""
from __future__ import annotations

from development_profile import max_height_for

from collections import OrderedDict
import hashlib
import sqlite3
from typing import Any

from commit_verifier import VerificationError, load_json
from native_core import Reject, digest, require
from registry_rules_core import RegistryReject
from state_sync import (APPLY_ABORT, APPLY_ACCEPT, APPLY_REJECT_SNAPSHOT, APPLY_RETRY,
                        CHUNK_BYTES, MAX_CHUNKS, MAX_METADATA_BYTES, MAX_SNAPSHOT_BYTES,
                        OFFER_ABORT, OFFER_ACCEPT, OFFER_REJECT, OFFER_REJECT_FORMAT)

FORMAT = 2
DOMAIN = '1soft/protocol4/composite-state-sync/v1'
HASH_DOMAIN = b'1soft/protocol4/composite-state-sync/v1\x00'
MAX_CACHED_SNAPSHOTS = 2


def _encoded(value: Any) -> bytes:
    from block_application import encode
    return encode(value)


def _hash(payload: bytes) -> bytes:
    return hashlib.sha256(HASH_DOMAIN + payload).digest()


def _metadata(genesis: dict, height: int, app_hash: str, size: int, chunks: int) -> bytes:
    return _encoded({'schema': 2, 'domain': DOMAIN, 'format': FORMAT, 'height': height,
                     'chunks': chunks, 'chunk_bytes': CHUNK_BYTES, 'payload_bytes': size,
                     'genesis_sha256': digest(genesis), 'app_hash': app_hash})


def _parse_metadata(raw: bytes, *, max_height: int = 512) -> dict:
    require(type(raw) is bytes and len(raw) <= MAX_METADATA_BYTES,
            'invalid protocol-4 snapshot metadata')
    try:
        value = load_json(raw, max_bytes=MAX_METADATA_BYTES)
    except Exception as exc:
        raise Reject('invalid protocol-4 snapshot metadata') from exc
    require(type(value) is dict and set(value) ==
            {'schema', 'domain', 'format', 'height', 'chunks', 'chunk_bytes',
             'payload_bytes', 'genesis_sha256', 'app_hash'} and _encoded(value) == raw,
            'invalid protocol-4 snapshot metadata fields')
    require(type(value['schema']) is int and value['schema'] == 2 and
            value['domain'] == DOMAIN and type(value['format']) is int and
            value['format'] == FORMAT, 'unsupported protocol-4 snapshot metadata')
    require(type(value['height']) is int and 1 <= value['height'] <= max_height and
            type(value['chunks']) is int and 1 <= value['chunks'] <= MAX_CHUNKS and
            type(value['chunk_bytes']) is int and value['chunk_bytes'] == CHUNK_BYTES and
            type(value['payload_bytes']) is int and 0 < value['payload_bytes'] <= MAX_SNAPSHOT_BYTES and
            (value['payload_bytes'] + CHUNK_BYTES - 1) // CHUNK_BYTES == value['chunks'],
            'invalid protocol-4 snapshot bounds')
    for field in ('genesis_sha256', 'app_hash'):
        item = value[field]
        require(type(item) is str and len(item) == 64,
                'invalid protocol-4 snapshot digest')
        try:
            bytes.fromhex(item)
        except ValueError as exc:
            raise Reject('invalid protocol-4 snapshot digest') from exc
    return value


class Protocol4StateSync:
    def __init__(self, app):
        self.app = app
        self._served: OrderedDict[tuple[int, int, str], tuple[dict, bytes]] = OrderedDict()
        self._offer: dict | None = None

    def _checkpoint_only(self) -> bool:
        app = self.app
        if app.genesis is None or app.expected_genesis is None or app.height <= 0:
            return False
        committed = app.db.execute(
            'SELECT height,app_hash FROM committed WHERE id=1').fetchone()
        marker = app.db.execute(
            'SELECT height,app_hash FROM snapshot_marker WHERE id=1').fetchone()
        return (committed == (app.height, app.app_hash) and
                marker == (app.height, app.app_hash) and
                digest(app.genesis) == digest(app.expected_genesis) and
                app.db.execute('SELECT 1 FROM blocks LIMIT 1').fetchone() is None)

    def list(self) -> list[dict]:
        app = self.app
        with app.lock:
            if app.genesis is None or app.height <= 0:
                return []
            try:
                payload = _encoded({'schema': 2, 'domain': DOMAIN, 'genesis': app.genesis,
                                    'height': app.height, 'app_hash': app.app_hash,
                                    'state': app.state, 'history': app.history()})
                require(0 < len(payload) <= MAX_SNAPSHOT_BYTES,
                        'protocol-4 history exceeds snapshot bound')
                chunks = (len(payload) + CHUNK_BYTES - 1) // CHUNK_BYTES
                require(1 <= chunks <= MAX_CHUNKS, 'protocol-4 snapshot chunk bound')
                metadata = _metadata(app.genesis, app.height, app.app_hash, len(payload), chunks)
                require(len(metadata) <= MAX_METADATA_BYTES,
                        'protocol-4 snapshot metadata bound')
            except Reject:
                return []
            desc = {'height': app.height, 'format': FORMAT, 'chunks': chunks,
                    'hash': _hash(payload), 'metadata': metadata}
            key = (app.height, FORMAT, desc['hash'].hex())
            self._served[key] = (desc, payload)
            self._served.move_to_end(key)
            while len(self._served) > MAX_CACHED_SNAPSHOTS:
                self._served.popitem(last=False)
            return [dict(desc)]

    def load(self, height: int, format_: int, index: int) -> bytes:
        require(type(height) is int and 1 <= height <= max_height_for(self.app.expected_genesis or self.app.genesis) and
                type(format_) is int and format_ == FORMAT and
                type(index) is int and 0 <= index < MAX_CHUNKS,
                'invalid protocol-4 snapshot chunk request')
        with self.app.lock:
            found = next((item for key, item in reversed(self._served.items())
                          if key[0] == height and key[1] == format_), None)
            if found is None and self.app.height == height and self.list():
                return self.load(height, format_, index)
            if found is None:
                return b''
            desc, payload = found
            if index >= desc['chunks']:
                return b''
            return payload[index * CHUNK_BYTES:(index + 1) * CHUNK_BYTES]

    def offer(self, snapshot: dict, app_hash: bytes) -> int:
        with self.app.lock:
            self._offer = None
            app = self.app
            checkpoint_recovery = self._checkpoint_only()
            if app.expected_genesis is None or (app.genesis is not None and
                                                not checkpoint_recovery):
                return OFFER_ABORT
            if type(snapshot) is not dict:
                return OFFER_REJECT
            if type(snapshot.get('format')) is not int or snapshot['format'] != FORMAT:
                return OFFER_REJECT_FORMAT
            try:
                height, chunks, hash_ = (snapshot.get('height'), snapshot.get('chunks'),
                                         snapshot.get('hash'))
                metadata = _parse_metadata(snapshot.get('metadata'), max_height=max_height_for(app.expected_genesis))
                require(type(height) is int and 1 <= height <= max_height_for(self.app.expected_genesis or self.app.genesis) and
                        (not checkpoint_recovery or height >= app.height) and
                        type(chunks) is int and 1 <= chunks <= MAX_CHUNKS and
                        type(hash_) is bytes and len(hash_) == 32 and
                        type(app_hash) is bytes and len(app_hash) == 32,
                        'invalid protocol-4 snapshot offer')
                require(metadata['height'] == height and metadata['chunks'] == chunks and
                        metadata['genesis_sha256'] == digest(app.expected_genesis) and
                        metadata['app_hash'] == app_hash.hex(),
                        'protocol-4 snapshot offer differs from trusted checkpoint')
            except Reject:
                return OFFER_REJECT
            self._offer = {'height': height, 'chunks': chunks, 'hash': hash_,
                           'app_hash': app_hash.hex(), 'metadata': metadata,
                           'parts': [], 'bytes': 0,
                           'checkpoint_recovery': checkpoint_recovery}
            return OFFER_ACCEPT

    def _validate(self, raw: bytes, offer: dict) -> dict:
        try:
            payload = load_json(raw, max_bytes=MAX_SNAPSHOT_BYTES)
        except Exception as exc:
            raise Reject('invalid protocol-4 snapshot payload') from exc
        try:
            canonical = _encoded(payload)
        except (TypeError, ValueError, OverflowError) as exc:
            raise Reject('invalid protocol-4 snapshot values') from exc
        require(type(payload) is dict and set(payload) ==
                {'schema', 'domain', 'genesis', 'height', 'app_hash', 'state', 'history'} and
                canonical == raw and type(payload['schema']) is int and
                payload['schema'] == 2 and payload['domain'] == DOMAIN and
                type(payload['height']) is int and payload['height'] == offer['height'] and
                payload['app_hash'] == offer['app_hash'] and
                type(payload['genesis']) is dict and
                digest(payload['genesis']) == digest(self.app.expected_genesis),
                'invalid protocol-4 snapshot identity')
        from protocol4_application import Protocol4Application
        try:
            Protocol4Application._validate_genesis(payload['genesis'])
            candidate = Protocol4Application(':memory:', expected_genesis=payload['genesis'])
            try:
                candidate._audit_state(payload['genesis'], payload['state'],
                                       payload['height'], payload['app_hash'])
            finally:
                candidate.close()
            Protocol4Application._audit_history(payload['genesis'], payload['state'],
                                                 payload['height'], payload['app_hash'],
                                                 payload['history'], strict_txs=True)
        except (Reject, RegistryReject, VerificationError, ValueError, TypeError,
                OverflowError, sqlite3.IntegrityError) as exc:
            raise Reject('invalid protocol-4 composite snapshot') from exc
        return payload

    def _install(self, payload: dict, checkpoint_recovery: bool) -> None:
        app = self.app
        from protocol4_application import RegistryRules
        history = payload['history']
        app.db.execute('BEGIN IMMEDIATE')
        try:
            if checkpoint_recovery:
                require(self._checkpoint_only() and payload['height'] >= app.height,
                        'protocol-4 checkpoint changed during restoration')
                app.db.execute('DELETE FROM blocks')
                app.db.execute('DELETE FROM history')
                app.db.execute('DELETE FROM committed')
                app.db.execute('DELETE FROM snapshot_marker')
            else:
                require(app.genesis is None and
                        app.db.execute('SELECT 1 FROM committed').fetchone() is None,
                        'protocol-4 application initialized during restoration')
            app.db.execute('INSERT INTO committed VALUES (1,?,?,?,?)',
                           (_encoded(payload['genesis']).decode(), payload['height'],
                            payload['app_hash'], _encoded(payload['state']).decode()))
            for row in history:
                app.db.execute('INSERT INTO history VALUES (?,?)',
                               (row['height'], _encoded(row['txs']).decode()))
            app.db.execute('INSERT INTO snapshot_marker VALUES (1,?,?)',
                           (payload['height'], payload['app_hash']))
            app.db.execute('COMMIT')
        except BaseException:
            if app.db.in_transaction:
                app.db.execute('ROLLBACK')
            raise
        app.genesis = payload['genesis']
        app.rules = RegistryRules(app.genesis['validator_registry'],
                                  bound_genesis_sha256=digest(app.genesis))
        app.state = payload['state']
        app.height = payload['height']
        app.app_hash = payload['app_hash']
        app.pending = None

    def apply(self, index: int, chunk: bytes, sender: str) -> dict:
        with self.app.lock:
            offer = self._offer
            reply = lambda result, refetch=[]: {'result': result, 'refetch_chunks': refetch,
                                                 'reject_senders': []}
            if offer is None:
                return reply(APPLY_ABORT)
            try:
                require(type(index) is int and 0 <= index < offer['chunks'] and
                        type(chunk) is bytes and 0 < len(chunk) <= CHUNK_BYTES and
                        type(sender) is str and len(sender.encode('utf-8')) <= 256,
                        'invalid protocol-4 snapshot chunk')
                expected = len(offer['parts'])
                if index < expected:
                    if offer['parts'][index] == chunk:
                        return reply(APPLY_ACCEPT)
                    self._offer = None
                    return reply(APPLY_REJECT_SNAPSHOT)
                if index > expected:
                    return reply(APPLY_RETRY, [expected])
                if index + 1 < offer['chunks']:
                    require(len(chunk) == CHUNK_BYTES, 'short non-final protocol-4 chunk')
                require(offer['bytes'] + len(chunk) <= offer['metadata']['payload_bytes'],
                        'protocol-4 snapshot chunk exceeds declared size')
                offer['parts'].append(bytes(chunk))
                offer['bytes'] += len(chunk)
                if len(offer['parts']) < offer['chunks']:
                    return reply(APPLY_ACCEPT)
                raw = b''.join(offer['parts'])
                require(len(raw) == offer['metadata']['payload_bytes'] and
                        _hash(raw) == offer['hash'], 'protocol-4 snapshot hash differs')
                payload = self._validate(raw, offer)
                self._install(payload, offer['checkpoint_recovery'])
                self._offer = None
                return reply(APPLY_ACCEPT)
            except (Reject, UnicodeError, ValueError, TypeError):
                self._offer = None
                return reply(APPLY_REJECT_SNAPSHOT)
