"""Read-only-chain explorer index. No wallet, keys, signing, submission or pruning.

Input is a verified historical full state plus an explicit chain of signed headers.
The index is replaceable derived data, not chain authority. Updates use one SQLite
transaction. Missing indexed bodies are not proof of transaction nonexecution.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
from typing import Any

from block_application import restore, snapshot
from commit_verifier import (b64, block_id, encode, exact, load_json, pinned_genesis,
    timestamp, verify_block_transactions, verify_signed_header, verify_state_witness)
from native_core import DOMAIN, FEE_ACCOUNT, canonical

MAX_INPUT = 16 * 1024 * 1024
MAX_STORED = 32 * 1024 * 1024
MAX_BATCH_HEADERS = 65
MAX_INDEX_HEADERS = 4096
MAX_ROWS = 20000
APP_ID = 0x31584558
SCHEMA = 1


class ExplorerError(ValueError):
    """Refused or unavailable evidence, never an instruction to retry a payment."""


def need(ok: bool, message: str) -> None:
    if not ok:
        raise ExplorerError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def hash_value(value: Any) -> str:
    need(type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value),
         'explicit lowercase 32-byte hash required')
    return value


def same_signed_block(left: dict, right: dict) -> bool:
    # Different >2/3 signature subsets can certify the same block. Both are
    # independently verified; preserve the existing certificate, not a false fork.
    return (encode(left['header']) == encode(right['header']) and
            block_id(left['commit']['block_id']).SerializeToString() ==
            block_id(right['commit']['block_id']).SerializeToString())


def bounded(value: Any, limit: int = MAX_INPUT) -> Any:
    raw = encode(value)
    need(len(raw) <= limit, 'explorer evidence exceeds configured bound')
    return load_json(raw, max_bytes=limit)


def ns(value: str) -> int:
    t = timestamp(value)
    return t.seconds * 1000000000 + t.nanos


def _private(path: Path) -> Path:
    need(os.name == 'posix', 'local explorer storage requires POSIX')
    p = Path(os.path.abspath(path))
    for ancestor in (p.parent, *p.parent.parents):
        need(not ancestor.is_symlink(), 'symlink ancestor refused')
    parent = p.parent.stat()
    need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.geteuid() and not parent.st_mode & 0o077,
         'private owned output directory required')
    for f in (p, *(Path(str(p) + suffix) for suffix in ('-wal', '-shm', '-journal'))):
        if f.exists() or f.is_symlink():
            m = f.lstat()
            need(stat.S_ISREG(m.st_mode) and m.st_uid == os.geteuid() and m.st_nlink == 1
                 and not m.st_mode & 0o077, 'unsafe index file or sidecar')
    return p


def write_new(path: Path, raw: bytes) -> None:
    p = _private(path)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())


def validate_evidence(evidence: dict, trust, *, max_headers=MAX_BATCH_HEADERS) -> dict:
    """Authenticate state, native invariants, contiguous ancestry and block bodies."""
    exact(evidence, {'schema', 'state', 'state_commit', 'headers', 'blocks'}, 'explorer evidence')
    need(type(evidence['schema']) is int and evidence['schema'] == 1, 'unknown explorer evidence schema')
    state = evidence['state']; cert = verify_state_witness(state, evidence['state_commit'], trust)
    rows = state['native']
    need(all(type(r) is list for r in rows.values()) and sum(map(len, rows.values())) <= MAX_ROWS,
         'explorer native row bound exceeded')
    ledger = restore(state['genesis'], rows)
    try:
        # Require canonical table ordering; do not quietly normalize signed state.
        need(snapshot(ledger) == rows, 'noncanonical native snapshot ordering')
        need(int(dict(ledger.db.execute('SELECT k,v FROM meta'))['height']) <= state['height'],
             'native execution height exceeds witnessed application')
    finally:
        ledger.close()
    headers = evidence['headers']
    need(type(headers) is list and 1 <= len(headers) <= max_headers, 'invalid header window')
    verified = {}; previous = None
    for signed in headers:
        info = verify_signed_header(signed, trust)
        h = info['height']
        need(h not in verified and h <= cert['height'], 'duplicate/future indexed header')
        if previous is not None:
            need(h == previous[0] + 1, 'missing consecutive signed header')
            need(block_id(signed['header']['last_block_id']).SerializeToString() ==
                 block_id(previous[1]['commit']['block_id']).SerializeToString(), 'header ancestry conflict')
            need(ns(signed['header']['time']) >= ns(previous[1]['header']['time']), 'header time regression')
        verified[h] = signed; previous = (h, signed)
    need(encode(headers[-1]) == encode(evidence['state_commit']), 'final indexed header is not state commitment')
    blocks = evidence['blocks']
    need(type(blocks) is list and len(blocks) <= max_headers, 'block body count exceeds bound')
    blockmap = {}
    for result in blocks:
        need(type(result) is dict and type(result.get('block')) is dict, 'invalid indexed block')
        h = int(result['block']['header']['height'])
        need(h in verified and h <= state['height'] and h not in blockmap, 'unlinked/duplicate/future body')
        verify_block_transactions(result, verified[h], trust)
        blockmap[h] = result
    # When a body was actually collected, every receipt at that height must match
    # its exact signed bytes, not merely a transaction ID or an endpoint label.
    for row in rows['receipts']:
        record = load_json(row[3].encode(), max_bytes=32768)
        need(type(record['height']) is int and 1 <= record['height'] <= state['height'], 'receipt outside state')
        if record['height'] in blockmap:
            encoded = blockmap[record['height']]['block']['data']['txs'] or []
            need([b64(x) for x in encoded].count(canonical(record['envelope'])) == 1,
                 'recorded transaction differs from verified block body')
    return {'certificate': cert, 'headers': verified, 'blocks': blockmap}


def projection(evidence: dict, verified: dict, config: dict) -> dict:
    state = evidence['state']; native = state['native']; version = state['genesis'].get('protocol_version', 1)
    account_rows = {r[0]: r for r in native['accounts']}
    links = dict(native.get('grant_budgets', []))
    grants = []
    for r in native['grants']:
        owner = account_rows[r[1]]
        active = not r[9] and r[3] == owner[3] and r[7] >= state['height'] + 1
        grants.append({'id': r[0], 'label': r[0].split('::')[-1], 'owner': r[1], 'public_key': r[2],
                       'epoch': r[3], 'nonce': r[4], 'cap': str(r[5]), 'spent': str(r[6]),
                       'remaining': str(r[5] - r[6]), 'expires_height': r[7],
                       'recipients': json.loads(r[8]), 'revoked': bool(r[9]),
                       'active_at_next_height': active, 'budget_id': links.get(r[0])})
    budgets = []
    for r in native.get('budgets', []):
        active = not r[7] and r[2] == account_rows[r[1]][3] and r[5] >= state['height'] + 1
        budgets.append({'id': r[0], 'label': r[0].split('::')[-1], 'owner': r[1], 'epoch': r[2],
                        'cap': str(r[3]), 'spent': str(r[4]), 'remaining': str(r[3] - r[4]),
                        'expires_height': r[5], 'recipients': json.loads(r[6]), 'revoked': bool(r[7]),
                        'active_at_next_height': active, 'grant_count': sum(v == r[0] for v in links.values())})
    bybudget = {b['id']: b for b in budgets}
    for grant in grants:
        if grant['budget_id'] is not None:
            grant['active_at_next_height'] &= bybudget[grant['budget_id']]['active_at_next_height']
    txs = []
    for row in native['receipts']:
        record = load_json(row[3].encode(), max_bytes=32768); body = record['envelope']['body']; op = body['op']
        # All amounts are decimal strings: browsers must not round atomic units.
        recipient = op.get('to')
        if op['type'] == 'open_account':
            from native_core import address
            recipient = address(op['public_key'])
        txs.append({'id': row[0], 'sequence': row[1], 'height': record['height'],
                    'sender': body['sender'], 'recipient': recipient, 'kind': op['type'],
                    'units': str(op.get('units', 0)), 'fee': str(record['fee_units']),
                    'grant_id': body['grant_id'] or None, 'nonce': body['nonce'],
                    'valid_until': body['valid_until'], 'receipt_hash': row[4],
                    'wire_hash': sha(canonical(record['envelope'])), 'record': record,
                    'block_inclusion_verified': record['height'] in verified['blocks'],
                    'status': 'recorded-in-verified-state'})
    activity = {k: [] for k in account_rows}
    for tx in txs:
        for who in {tx['sender'], tx['recipient']}:
            if who in activity: activity[who].append(tx['id'])
    accounts = [{'id': r[0], 'public_key': r[1], 'nonce': r[2], 'epoch': r[3], 'balance': str(r[4]),
                 'system_account': r[0] == FEE_ACCOUNT, 'transaction_ids': list(reversed(activity[r[0]])),
                 'grant_count': sum(g['owner'] == r[0] for g in grants),
                 'budget_count': sum(b['owner'] == r[0] for b in budgets)} for r in native['accounts']]
    transactions_by_height = {}
    for tx in txs: transactions_by_height.setdefault(tx['height'], []).append(tx['id'])
    blocks = []
    for h, signed in sorted(verified['headers'].items(), reverse=True):
        if h > state['height']: continue  # H+1 anchors state H; do not call H+1 executed.
        info = verify_signed_header(signed, verified['trust'])
        body = verified['blocks'].get(h)
        raws = [] if body is None else [b64(t) for t in (body['block']['data']['txs'] or [])]
        blocks.append({'height': h, 'hash': info['block_hash'].lower(), 'time': signed['header']['time'],
                       'proposer': signed['header']['proposer_address'].lower(),
                       'signed_power': info['signed_power'], 'total_power': info['total_power'],
                       'body_available': body is not None,
                       'included_transaction_count': len(raws) if body is not None else None,
                       'included_wire_hashes': [sha(raw) for raw in raws] if body is not None else None,
                       'recorded_transaction_ids': transactions_by_height.get(h, [])})
    cert = verified['certificate']
    validators = [{'address': v.address.hex(), 'public_key': v.public_key.hex(), 'power': str(v.power),
                   'committed_at_anchor': v.address.hex().upper() in cert['signers'],
                   'live_online_status': None} for v in verified['trust'].validators]
    return {'schema': 1, 'product': '1soft Explorer', 'profile': config['profile'],
            'chain_id': state['genesis']['chain_id'], 'asset': state['genesis']['asset'],
            'protocol_version': version, 'state_commitment': state['genesis'].get('state_commitment', 'legacy-flat-v1'),
            'state_height': state['height'], 'app_hash': state['app_hash'],
            'anchor_height': cert['height'], 'anchor_hash': cert['block_hash'].lower(),
            'anchor_time': evidence['state_commit']['header']['time'],
            'genesis_file_sha256': config['genesis_sha256'],
            'supply_units': str(sum(r[4] for r in native['accounts'])),
            'fee_pool_units': str(account_rows[FEE_ACCOUNT][4]),
            'account_count': len(accounts) - 1, 'transaction_count': len(txs),
            'indexed_block_count': len(blocks), 'indexed_body_count': len(verified['blocks']),
            'first_indexed_header': min(verified['headers']),
            'latest_state_guaranteed': False, 'wallet_pending_debits_included': False,
            'live_validator_status_established': False, 'monetary_value_established': False,
            'accounts': accounts, 'transactions': list(reversed(txs)), 'blocks': blocks,
            'grants': grants, 'budgets': budgets, 'validators': validators}


class ExplorerIndex:
    """Verified persistent read model. No writes to source nodes or wallet files."""
    def __init__(self, path: Path, genesis_bytes: bytes, genesis_sha256: str, *, create=False,
                 read_only=False, profile='unattributed-development'):
        hash_value(genesis_sha256)
        self.trust = pinned_genesis(genesis_bytes, genesis_sha256)
        need(type(create) is bool and type(read_only) is bool and not (create and read_only), 'invalid index mode')
        need(profile in ('synthetic-fixture', 'unattributed-development'), 'invalid evidence profile')
        self.path = _private(Path(path)); self.db = None
        self.genesis = genesis_bytes; self.genesis_sha256 = genesis_sha256; self.read_only = read_only
        if create:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600); os.close(fd)
        else: need(self.path.is_file(), 'index not initialized')
        try:
            self.db = sqlite3.connect(self.path.as_uri() + ('?mode=ro' if read_only else '?mode=rw'),
                                     uri=True, isolation_level=None, timeout=5)
            if create:
                self.db.execute('PRAGMA journal_mode=WAL'); self.db.execute('PRAGMA synchronous=FULL')
                with self.atomic():
                    self.db.execute(f'PRAGMA application_id={APP_ID}')
                    self.db.execute('CREATE TABLE config(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, genesis_sha256 TEXT NOT NULL, profile TEXT NOT NULL)')
                    self.db.execute('CREATE TABLE current(id INTEGER PRIMARY KEY CHECK(id=1), evidence BLOB NOT NULL, evidence_hash TEXT NOT NULL, view BLOB NOT NULL, view_hash TEXT NOT NULL)')
                    self.db.execute('INSERT INTO config VALUES (1,?,?,?)', (SCHEMA, genesis_sha256, profile))
            self.config = self._config()
            if not read_only:
                need(self.db.execute('PRAGMA journal_mode').fetchone()[0] == 'wal', 'index journal mode differs')
                self.db.execute('PRAGMA synchronous=FULL')
        except BaseException:
            self.close(); raise

    def close(self):
        if self.db is not None: self.db.close(); self.db = None
    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    @contextmanager
    def atomic(self, write=True):
        need(not self.db.in_transaction and not (write and self.read_only), 'index transaction/mode conflict')
        self.db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise

    def _config(self):
        need(self.db.execute('PRAGMA application_id').fetchone()[0] == APP_ID, 'not an explorer database')
        objects = self.db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        need(set(objects) == {('table', 'config'), ('table', 'current')}, 'unknown explorer schema')
        rows = self.db.execute('SELECT * FROM config').fetchall()
        need(len(rows) == 1 and rows[0][:3] == (1, SCHEMA, self.genesis_sha256) and
             rows[0][3] in ('synthetic-fixture', 'unattributed-development'), 'index trust/configuration mismatch')
        return {'genesis_sha256': rows[0][2], 'profile': rows[0][3]}

    def _read(self):
        need(self._config() == self.config, 'index configuration changed')
        rows = self.db.execute('SELECT * FROM current').fetchall()
        need(len(rows) <= 1, 'invalid explorer checkpoint count')
        if not rows: return None
        _, raw, digest, viewraw, viewhash = rows[0]
        need(type(raw) is bytes and len(raw) <= MAX_STORED and sha(raw) == digest,
             'stored evidence changed')
        evidence = load_json(raw, max_bytes=MAX_STORED)
        need(encode(evidence) == raw and type(viewraw) is bytes and len(viewraw) <= MAX_STORED
             and sha(viewraw) == viewhash, 'stored index encoding/integrity differs')
        v = validate_evidence(evidence, self.trust, max_headers=MAX_INDEX_HEADERS); v['trust'] = self.trust
        view = projection(evidence, v, self.config)
        need(encode(view) == viewraw, 'derived index differs from verified evidence')
        return evidence, view

    def current(self):
        with self.atomic(write=False):
            loaded = self._read()
            return None if loaded is None else loaded[1]

    def evidence(self):
        with self.atomic(write=False):
            loaded = self._read(); need(loaded is not None, 'no indexed checkpoint')
            return loaded[0]

    def ingest(self, value, *, initial_header_hash=None):
        incoming = bounded(value)  # Freeze once before validation, no mutable-input gap.
        iv = validate_evidence(incoming, self.trust)
        # Store only header/data fields actually authenticated by the verifier.
        incoming['blocks'] = [{'block_id': b['block_id'], 'block': {
            'header': b['block']['header'], 'data': b['block']['data']}} for b in incoming['blocks']]
        iv['blocks'] = {int(b['block']['header']['height']): b for b in incoming['blocks']}
        if initial_header_hash is not None:
            need(iv['certificate']['block_hash'].lower() == hash_value(initial_header_hash), 'supplied header pin differs')
        with self.atomic():
            loaded = self._read()
            if loaded is None:
                need(iv['certificate']['block_hash'].lower() == hash_value(initial_header_hash),
                     'initial signed checkpoint differs from external pin')
                combined = incoming
            else:
                old, view = loaded; oldheight = view['anchor_height']; newheight = iv['certificate']['height']
                need(newheight >= oldheight, 'explorer checkpoint rollback refused')
                overlap = {int(h['header']['height']): h for h in old['headers']}
                oldreceipts, newreceipts = old['state']['native']['receipts'], incoming['state']['native']['receipts']
                need(newreceipts[:len(oldreceipts)] == oldreceipts, 'recorded receipt history changed or disappeared')
                if newheight == oldheight:
                    need(incoming['state_commit']['commit']['block_id'] == old['state_commit']['commit']['block_id']
                         and incoming['state'] == old['state'], 'same-height checkpoint conflict')
                else:
                    need(oldheight in iv['headers'] or oldheight + 1 in iv['headers'], 'missing checkpoint continuation')
                for h, signed in iv['headers'].items():
                    if h in overlap:
                        need(same_signed_block(overlap[h], signed), 'indexed signed-header conflict')
                    else:
                        overlap[h] = signed
                bodymap = {int(b['block']['header']['height']): b for b in old['blocks']}
                for h, body in iv['blocks'].items():
                    if h in bodymap: need(encode(bodymap[h]) == encode(body), 'indexed block body conflict')
                    bodymap[h] = body
                combined = {**incoming, 'state_commit': overlap[newheight], 'headers': [overlap[h] for h in sorted(overlap)],
                            'blocks': [bodymap[h] for h in sorted(bodymap)]}
            raw = encode(combined); need(len(raw) <= MAX_STORED, 'index evidence capacity reached; nothing evicted')
            verified = validate_evidence(combined, self.trust, max_headers=MAX_INDEX_HEADERS); verified['trust'] = self.trust
            view = projection(combined, verified, self.config); data = encode(view)
            need(len(data) <= MAX_STORED, 'index projection capacity reached')
            existing = self.db.execute('SELECT evidence_hash FROM current WHERE id=1').fetchone()
            if existing and existing[0] == sha(raw):
                return {'status': 'already_indexed', 'state_height': view['state_height'], 'view_hash': sha(data)}
            self.db.execute('INSERT OR REPLACE INTO current VALUES (1,?,?,?,?)', (raw, sha(raw), data, sha(data)))
            return {'status': 'indexed', 'state_height': view['state_height'], 'view_hash': sha(data),
                    'transactions': view['transaction_count'], 'block_bodies': view['indexed_body_count']}
