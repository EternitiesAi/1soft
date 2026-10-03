"""Encrypted P4 journal backup; restore is historical and recovery-only.

No keys, signing, network, resend, activation, trust renewal or rollback fencing.
Canonical journals are captured together, never restored as active databases.
"""
from __future__ import annotations

import base64
from contextlib import closing, contextmanager
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from block_application import encode
from commit_verifier import exact, load_json
from offline_signer import _parent, _password
from p4_delivery import APP_ID as DELIVERY_ID, P4Delivery
from p4_wallet import APPLICATION_ID as WALLET_ID, P4Wallet, pending, revision
from p4_evidence import content_id, hash_text, integer, need, policy_checked
from p4_read_store import private_path

SNAPSHOT_FORMAT = '1soft/p4-journal-snapshot/v1'
BACKUP_FORMAT = '1soft/p4-recovery-backup/v1'
ARCHIVE_ID = 0x31503443
MAX_JOURNAL_BYTES = 7*1024*1024
MAX_PLAINTEXT_BYTES = 16*1024*1024
MAX_BACKUP_BYTES = 23*1024*1024
MAX_ARCHIVE_BYTES = 17*1024*1024
KDF = {'name':'scrypt', 'n':32768, 'r':8, 'p':1, 'length':32}
_CEILING_UNSET = object()


class LegacyCapacityError(ValueError):
    """Only a legacy representation bound; it grants no financial authority."""

# These fixed schemas are used only in memory to reuse the original auditors.
# No SQL, module path or filename is accepted from a backup.
WALLET_SCHEMA = {
    'config': ('id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, wallet_id TEXT NOT NULL, policy BLOB NOT NULL, created_ns INTEGER NOT NULL', 1),
    'observations': ('seq INTEGER PRIMARY KEY, evidence_id TEXT UNIQUE NOT NULL, parent_id TEXT NOT NULL, checked_ns INTEGER NOT NULL, payload BLOB NOT NULL', 32),
    'decisions': ('seq INTEGER PRIMARY KEY, decision_id TEXT UNIQUE NOT NULL, signed_ns INTEGER NOT NULL, payload BLOB NOT NULL', 256),
}
DELIVERY_SCHEMA = {
    'config': ('id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, delivery_id TEXT NOT NULL, wallet_id TEXT NOT NULL, policy_id TEXT NOT NULL, genesis_sha256 TEXT NOT NULL, endpoint TEXT NOT NULL, created_ns INTEGER NOT NULL', 1),
    'attempts': ('seq INTEGER PRIMARY KEY, decision_id TEXT UNIQUE NOT NULL, claimed_ns INTEGER NOT NULL, review BLOB NOT NULL', 256),
    'responses': ('decision_id TEXT PRIMARY KEY, observed_ns INTEGER NOT NULL, payload BLOB NOT NULL', 256),
    'receipts': ('seq INTEGER PRIMARY KEY, decision_id TEXT UNIQUE NOT NULL, evidence_id TEXT NOT NULL, checked_ns INTEGER NOT NULL, payload BLOB NOT NULL', 32),
}


def _cell(value):
    need(type(value) in (int, str, bytes), 'unsupported journal cell')
    return {'hex':value.hex()} if type(value) is bytes else value


def _decoded(value):
    if type(value) is dict:
        exact(value, {'hex'}, 'journal byte cell')
        raw = value['hex']
        need(type(raw) is str and len(raw) <= 2*MAX_JOURNAL_BYTES, 'journal byte cell exceeds bound')
        try: data = bytes.fromhex(raw)
        except ValueError as exc: raise ValueError('invalid journal byte cell') from exc
        need(data.hex() == raw, 'journal byte cell is not canonical')
        return data
    need(type(value) in (int, str), 'invalid journal cell type')
    if type(value) is int: integer(value, 0, 2**63-1)
    else: need(len(value) <= 4096, 'journal text exceeds bound')
    return value


def _rows(db, schema):
    result = {}
    for table, (_, limit) in schema.items():
        rows = db.execute(f'SELECT * FROM {table} ORDER BY 1').fetchall()
        need(len(rows) <= limit, 'journal row bound exceeded')
        result[table] = [[_cell(v) for v in row] for row in rows]
    return result


def _memory(data, schema, app_id):
    exact(data, set(schema), 'journal tables')
    db = sqlite3.connect(':memory:', isolation_level=None)
    try:
        db.execute(f'PRAGMA application_id={app_id}')
        for table, (columns, limit) in schema.items():
            rows = data[table]
            need(type(rows) is list and len(rows) <= limit, 'journal row bound exceeded')
            db.execute(f'CREATE TABLE {table}({columns})')
            count = len(db.execute(f'PRAGMA table_info({table})').fetchall())
            for row in rows:
                need(type(row) is list and len(row) == count, 'journal row shape differs')
                cells = [_decoded(v) for v in row]
                db.execute(f'INSERT INTO {table} VALUES ({",".join("?" for _ in cells)})', cells)
        need(_rows(db, schema) == data, 'journal row encoding changed on reconstruction')
        return db
    except BaseException:
        db.close()
        raise


class _WalletAudit:
    """Audit facade; deliberately has no approval, signing or mutable wallet API."""
    def __init__(self, db, path, genesis, policy):
        self.db, self.path, self.genesis = db, path, bytes(genesis)
        self.policy = policy_checked(policy)
        self.policy_id = content_id(self.policy)
        self._policy_bytes = encode(self.policy)

    _check_clock = P4Wallet._check_clock
    _fresh = P4Wallet._fresh
    _transfer_review = P4Wallet._transfer_review
    _rotation_review = P4Wallet._rotation_review
    _decision_review = P4Wallet._decision_review

    def _catalog(self): return P4Wallet._catalog(self)
    def load(self): return P4Wallet._load(self, historical=True)


class _DeliveryAudit:
    """Only the existing historical audit/selection functions are exposed."""
    def __init__(self, db, wallet, wallet_id):
        self.db, self.wallet, self.wallet_id = db, wallet, wallet_id
        row = db.execute('SELECT * FROM config').fetchone()
        need(row is not None and len(row) == 8, 'delivery configuration unavailable')
        self.endpoint = row[6]
        from payment_rpc import endpoint_port
        endpoint_port(self.endpoint)
        self.config = self._config()

    APPLICATION_ID = DELIVERY_ID
    VERSION = 1
    REVIEW_FORMAT = P4Delivery.REVIEW_FORMAT
    _fresh = P4Delivery._fresh
    _check_clock = P4Delivery._check_clock
    _derive_review = P4Delivery._derive_review

    def _config(self): return P4Delivery._config(self)
    def _review(self, *args): return P4Delivery._review(self, *args)
    def audit(self, decisions): return P4Delivery._audit(self, decisions)


def _validate(snapshot, genesis, policy, path):
    exact(snapshot, {'schema','format','captured_ns','genesis_hex','policy','wallet','delivery'}, 'journal snapshot')
    need(type(snapshot['schema']) is int and snapshot['schema'] == 1 and
         snapshot['format'] == SNAPSHOT_FORMAT, 'unsupported snapshot format')
    integer(snapshot['captured_ns'])
    policy = policy_checked(policy)
    need(snapshot['genesis_hex'] == bytes(genesis).hex() and
         encode(snapshot['policy']) == encode(policy), 'externally selected genesis or policy differs')
    need(hashlib.sha256(bytes(genesis)).hexdigest() == policy['genesis_sha256'], 'external genesis pin differs')
    if len(encode(snapshot)) > MAX_PLAINTEXT_BYTES:
        raise LegacyCapacityError('snapshot exceeds plaintext bound')
    dbs = []
    try:
        wdb = _memory(snapshot['wallet'], WALLET_SCHEMA, WALLET_ID); dbs.append(wdb)
        ddb = _memory(snapshot['delivery'], DELIVERY_SCHEMA, DELIVERY_ID); dbs.append(ddb)
        # Total BLOB bytes, including policy bytes, are bounded independently.
        total = sum(len(v) for db, schema in ((wdb,WALLET_SCHEMA),(ddb,DELIVERY_SCHEMA))
                    for table in schema for row in db.execute(f'SELECT * FROM {table}')
                    for v in row if type(v) is bytes)
        if total > MAX_JOURNAL_BYTES:
            raise LegacyCapacityError('complete journal payload exceeds backup bound; nothing evicted')
        wallet = _WalletAudit(wdb, private_path(path), genesis, policy)
        wid, evidence, report, decisions, last = wallet.load()
        delivery = _DeliveryAudit(ddb, wallet, wid)
        attempts, responses, receipts, delivery_last = delivery.audit(decisions)
        held = pending(report, decisions)
        return dict(wallet_id=wid, delivery_id=delivery.config[2], policy_id=wallet.policy_id,
                    report=report, decisions=decisions, held=held, attempts=attempts,
                    responses=responses, receipts=receipts, last_ns=max(last,delivery_last))
    except (sqlite3.Error, KeyError, TypeError, OverflowError) as exc:
        raise ValueError('invalid retained journal snapshot') from exc
    finally:
        for db in dbs: db.close()


def capture(delivery):
    """Consistent logical snapshot; no WAL copy, source write or clock renewal."""
    need(type(delivery) is P4Delivery, 'one existing bound P4 delivery pair required')
    wallet = delivery.wallet
    with wallet.atomic():
        with delivery.atomic():
            _, _, _, decisions, _ = wallet._load(historical=True)
            delivery._audit(decisions)
            snapshot = {'schema':1, 'format':SNAPSHOT_FORMAT, 'captured_ns':time.time_ns(),
                        'genesis_hex':wallet.genesis.hex(), 'policy':wallet.policy,
                        'wallet':_rows(wallet.db, WALLET_SCHEMA),
                        'delivery':_rows(delivery.db, DELIVERY_SCHEMA)}
    _validate(snapshot, wallet.genesis, wallet.policy, wallet.path)
    return snapshot


def _seal(snapshot, password):
    _password(password)
    plaintext = encode(snapshot)
    need(len(plaintext) <= MAX_PLAINTEXT_BYTES, 'snapshot exceeds plaintext bound')
    salt, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    header = {'schema':1, 'format':BACKUP_FORMAT, 'kdf':KDF.copy(),
              'cipher':'aes-256-gcm', 'salt':salt.hex(), 'nonce':nonce.hex()}
    key = Scrypt(salt=salt, length=32, n=32768, r=8, p=1).derive(password)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, encode(header))
    raw = encode({'header':header, 'ciphertext':base64.b64encode(ciphertext).decode('ascii')})
    need(len(raw) <= MAX_BACKUP_BYTES, 'encrypted backup exceeds bound')
    return raw


def _unseal(raw, password):
    _password(password)
    envelope = load_json(raw, max_bytes=MAX_BACKUP_BYTES)
    exact(envelope, {'header','ciphertext'}, 'backup envelope')
    need(encode(envelope) == raw, 'backup envelope encoding differs')
    h = envelope['header']
    exact(h, {'schema','format','kdf','cipher','salt','nonce'}, 'backup header')
    need(type(h['schema']) is int and h['schema'] == 1 and h['format'] == BACKUP_FORMAT and
         h['cipher'] == 'aes-256-gcm' and encode(h['kdf']) == encode(KDF), 'unsupported backup parameters')
    for name, size in (('salt',32),('nonce',12)):
        text = h[name]
        need(type(text) is str and len(text) == size*2, 'invalid encryption metadata')
        try: value = bytes.fromhex(text)
        except ValueError as exc: raise ValueError('invalid encryption metadata') from exc
        need(value.hex() == text, 'noncanonical encryption metadata')
    need(type(envelope['ciphertext']) is str, 'invalid backup ciphertext')
    try: ct = base64.b64decode(envelope['ciphertext'], validate=True)
    except ValueError as exc: raise ValueError('invalid backup ciphertext') from exc
    need(16 <= len(ct) <= MAX_PLAINTEXT_BYTES+16 and
         base64.b64encode(ct).decode('ascii') == envelope['ciphertext'], 'ciphertext size or encoding differs')
    key = Scrypt(salt=bytes.fromhex(h['salt']), length=32, n=32768, r=8, p=1).derive(password)
    try: plaintext = AESGCM(key).decrypt(bytes.fromhex(h['nonce']), ct, encode(h))
    except InvalidTag as exc: raise ValueError('unable to authenticate backup') from exc
    snapshot = load_json(plaintext, max_bytes=MAX_PLAINTEXT_BYTES)
    need(encode(snapshot) == plaintext, 'snapshot encoding differs')
    return snapshot


@contextmanager
def _private_source(path, limit):
    parent, name = _parent(Path(path))
    try:
        fd = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC, dir_fd=parent)
        with os.fdopen(fd, 'rb') as source:
            s = os.fstat(source.fileno())
            need(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and s.st_nlink == 1 and
                 not s.st_mode & 0o077 and 0 < s.st_size <= limit, 'private bounded regular file required')
            yield source
    finally: os.close(parent)


def _read(path, limit):
    with _private_source(path, limit) as source:
        raw = source.read(limit+1)
        need(len(raw) <= limit, 'input grew beyond bound')
        return raw


def separate_paths(*paths):
    """Reject even absent database/sidecar aliases before reading or publishing."""
    normalized = [Path(os.path.abspath(p)) for p in paths]
    seen = set()
    for path in normalized:
        family = {str(path)+suffix for suffix in ('','-wal','-shm','-journal')}
        need(not family.intersection(seen), 'recovery input/output database or sidecar paths overlap')
        seen.update(family)
    return tuple(private_path(p) for p in normalized)


def _publish_parts(path, parts, limit):
    """Durably publish a bounded complete stream without overwriting a sidecar."""
    p = private_path(path)
    need(not any(Path(str(p)+s).exists() or Path(str(p)+s).is_symlink()
                 for s in ('','-wal','-shm','-journal')), 'output or sidecar already exists')
    parent, name = _parent(p)
    tmp = '.1soft-recovery-'+secrets.token_hex(16)+'.tmp'
    created = False
    try:
        fd = os.open(tmp, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        created = True
        with os.fdopen(fd, 'wb') as out:
            total = 0
            for raw in parts:
                need(type(raw) is bytes, 'byte output required')
                total += len(raw); need(total <= limit, 'bounded output required')
                out.write(raw)
            need(total > 0, 'empty output refused')
            out.flush(); os.fsync(out.fileno())
        os.link(tmp, name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        os.unlink(tmp, dir_fd=parent); created = False
        try: os.fsync(parent)
        except OSError as exc:
            raise OSError('complete output was published but directory durability is unconfirmed; inspect the existing output before retrying') from exc
    finally:
        if created: os.unlink(tmp, dir_fd=parent)
        os.close(parent)


def publish_new(path, raw):
    """The legacy/export byte interface retains its original bound."""
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BACKUP_BYTES, 'bounded output required')
    _publish_parts(path, (raw,), MAX_BACKUP_BYTES)


def backup(delivery, output, password, *, format_version=None,
           max_capture_blob_bytes=_CEILING_UNSET, max_backup_bytes=_CEILING_UNSET):
    need(type(delivery) is P4Delivery, 'one existing bound P4 delivery pair required')
    need(format_version is None or type(format_version) is int and format_version in (1,2,3),
         'unsupported backup format selection')
    if max_capture_blob_bytes is not _CEILING_UNSET or max_backup_bytes is not _CEILING_UNSET:
        need(format_version == 3, 'caller ceilings require explicit backup format 3')
        import p4_custody_compressed as compressed
        from p4_custody_stream import MAX_PAIR_BYTES
        for value,bound in ((max_capture_blob_bytes,MAX_PAIR_BYTES),
                            (max_backup_bytes,compressed.MAX_BACKUP_BYTES)):
            need(value is _CEILING_UNSET or type(value) is int and 0 < value <= bound,
                 'caller ceiling must be an exact positive bounded integer')
    max_capture_blob_bytes = None if max_capture_blob_bytes is _CEILING_UNSET else max_capture_blob_bytes
    max_backup_bytes = None if max_backup_bytes is _CEILING_UNSET else max_backup_bytes
    _, _, output = separate_paths(delivery.wallet.path, delivery.path, output)
    from p4_custody_stream import blob_size, capture_pair, sealed_parts, MAX_BACKUP_BYTES as stream_bound
    if format_version == 3:
        import p4_custody_compressed as compressed
        result = {}; digest = hashlib.sha256()
        with capture_pair(delivery) as pair:
            if max_capture_blob_bytes is not None:
                from p4_custody_stream import captured_blob_size
                need(captured_blob_size(pair) <= max_capture_blob_bytes,
                     'captured journal exceeds caller ceiling; nothing evicted')
            def parts():
                for raw in compressed.sealed_parts(pair, password, result):
                    digest.update(raw); yield raw
            _publish_parts(output, parts(), compressed.MAX_BACKUP_BYTES if max_backup_bytes is None else max_backup_bytes)
        return {'status':'encrypted-journal-backup-created','backup_format_version':3,
                'backup_sha256':digest.hexdigest(),'snapshot_id':result['snapshot_id'],
                'private_keys_included':False,'source_journals_changed':False,
                'latestness_established':False,'old_device_fenced':False}
    if format_version == 2 or format_version is None and blob_size(delivery) > 7*1024*1024:
        result = {}; digest = hashlib.sha256()
        with capture_pair(delivery) as pair:
            def parts():
                for raw in sealed_parts(pair, password, result):
                    digest.update(raw); yield raw
            _publish_parts(output, parts(), stream_bound)
        return {'status':'encrypted-journal-backup-created','backup_format_version':2,
                'backup_sha256':digest.hexdigest(),'snapshot_id':result['snapshot_id'],
                'private_keys_included':False,'source_journals_changed':False,
                'latestness_established':False,'old_device_fenced':False}
    try: snapshot = capture(delivery)
    except LegacyCapacityError:
        if format_version is not None: raise
        # A large genesis can fill legacy JSON first. Concurrent journal growth
        # can also cross the size preflight; v2 captures and audits a fresh pair.
        return backup(delivery,output,password,format_version=2)
    raw = _seal(snapshot, password)
    publish_new(output, raw)
    return {'status':'encrypted-journal-backup-created', 'backup_format_version':1,
            'backup_sha256':hashlib.sha256(raw).hexdigest(),
            'snapshot_id':content_id(snapshot), 'private_keys_included':False,
            'source_journals_changed':False, 'latestness_established':False, 'old_device_fenced':False}


def restore_backup(backup_path, output, genesis, policy, password):
    backup_path, output = separate_paths(backup_path, output)
    import p4_custody_stream as stream
    import p4_custody_compressed as compressed
    with _private_source(backup_path, max(stream.MAX_BACKUP_BYTES, compressed.MAX_BACKUP_BYTES)) as source:
        prefix = source.read(len(stream.MAGIC)); source.seek(0)
        if prefix in (stream.MAGIC, compressed.MAGIC):
            codec = stream if prefix == stream.MAGIC else compressed
            chunks, manifest = codec.unseal(source, password)
            stream.audit_chunks(chunks, genesis, policy, output)
            archive = stream.make_archive(chunks, manifest)
            _publish_parts(output, (archive,), stream.MAX_ARCHIVE_BYTES)
            return {'status':'restored-recovery-only','backup_format_version':2 if codec is stream else 3,
                    'snapshot_id':stream.snapshot_id(manifest),'signing_enabled':False,
                    'dispatch_enabled':False,'old_device_fenced':False,
                    'latestness_established':False,'private_keys_restored':False}
        raw = source.read(MAX_BACKUP_BYTES+1)
        need(len(raw)<=MAX_BACKUP_BYTES,'legacy backup exceeds bound')
        snapshot = _unseal(raw, password)
    _validate(snapshot, genesis, policy, output)
    raw = encode(snapshot)
    with closing(sqlite3.connect(':memory:')) as db:
        db.execute(f'PRAGMA application_id={ARCHIVE_ID}')
        db.execute('CREATE TABLE recovery(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, snapshot_id TEXT NOT NULL, payload BLOB NOT NULL)')
        db.execute('INSERT INTO recovery VALUES (1,1,?,?)', (content_id(snapshot),raw))
        db.commit()
        archive = db.serialize()
    need(len(archive) <= MAX_ARCHIVE_BYTES, 'recovery archive exceeds bound')
    publish_new(output, archive)
    return {'status':'restored-recovery-only', 'snapshot_id':content_id(snapshot),
            'signing_enabled':False, 'dispatch_enabled':False, 'old_device_fenced':False,
            'latestness_established':False, 'private_keys_restored':False}


class RecoveryArchive:
    """Private historical record. No inherited active wallet/delivery methods."""
    def __init__(self, path, genesis, policy):
        self.path, self.genesis, self.policy = private_path(path), bytes(genesis), policy_checked(policy)
        import p4_custody_stream as stream
        self._chunks = None
        raw = _read(self.path, stream.MAX_ARCHIVE_BYTES)
        try:
            result = stream.archive_chunks(raw)
            if result is not None:
                self._chunks, self.snapshot_id = result
                self._raw = None
                stream.audit_chunks(self._chunks, self.genesis, self.policy, self.path)
                return
            need(len(raw)<=MAX_ARCHIVE_BYTES,'legacy recovery archive exceeds bound')
            with closing(sqlite3.connect(':memory:')) as db:
                db.deserialize(raw)
                need(db.execute('PRAGMA application_id').fetchone()[0] == ARCHIVE_ID, 'not a recovery-only archive')
                objects = set(db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
                need(objects == {('table','recovery')} and
                     tuple(r[1] for r in db.execute('PRAGMA table_info(recovery)')) ==
                     ('id','version','snapshot_id','payload'), 'recovery schema differs')
                rows = db.execute('SELECT * FROM recovery').fetchall()
                need(len(rows) == 1 and rows[0][:2] == (1,1) and type(rows[0][3]) is bytes and
                     len(rows[0][3]) <= MAX_PLAINTEXT_BYTES, 'recovery record differs')
                hash_text(rows[0][2])
                snapshot = load_json(rows[0][3], max_bytes=MAX_PLAINTEXT_BYTES)
                need(encode(snapshot) == rows[0][3] and content_id(snapshot) == rows[0][2], 'recovery content changed')
        except sqlite3.Error as exc: raise ValueError('invalid recovery archive') from exc
        self._raw = encode(snapshot)
        self.snapshot_id = content_id(snapshot)
        _validate(snapshot, self.genesis, self.policy, self.path)

    def close(self):
        self._raw = None
        self._chunks = None
    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    def _audit(self):
        if self._chunks is not None:
            from p4_custody_stream import audit_chunks
            return audit_chunks(self._chunks, self.genesis, self.policy, self.path)
        need(self._raw is not None, 'recovery archive is closed')
        # Reverify frozen records; no current authority or fresh source query.
        return _validate(load_json(self._raw, max_bytes=MAX_PLAINTEXT_BYTES),
                         self.genesis, self.policy, self.path)



    def inspect(self):
        a = self._audit(); held_ids = {d['id'] for d in a['held']}
        budgets = [{'id':b[0], 'cap':str(b[3]), 'spent':str(b[4]),
                    'pending_debit_units':str(sum(int(d['review']['debit_units']) for d in a['held']
                                                if d['review']['budget_id'] == b[0]))}
                   for b in a['report']['budgets']]
        decisions = []
        for d in a['decisions']:
            did = d['id']
            decisions.append({'id':did, 'payer':d['review']['body']['sender'],
                'grant_id':d['review']['body']['grant_id'], 'debit_units':d['review']['debit_units'],
                'pending':did in held_ids, 'attempt_recorded':did in a['attempts'],
                'transport_observation':a['responses'].get(did,{}).get('observation',
                    'unresolved' if did in a['attempts'] else 'not_attempted'),
                'wallet_receipt_status':'unavailable' if did in held_ids else 'recorded',
                'delivery_receipt_status':'verified_historical_receipt' if did in a['receipts'] else 'unavailable',
                'wire_sha256':hashlib.sha256(bytes.fromhex(d['wire_hex'])).hexdigest(),
                'safe_to_resend':False})
        return {'status':'verified-historical-recovery-archive', 'snapshot_id':self.snapshot_id,
                'wallet_id':a['wallet_id'], 'delivery_id':a['delivery_id'],
                'wallet_revision':revision(a['wallet_id'],a['policy_id'],a['report']['evidence_id'],a['decisions']),
                'state_height':a['report']['state_height'], 'registry_epoch':a['report']['registry_epoch'],
                'historical_checked_at_ns':a['last_ns'], 'budgets':budgets, 'decisions':decisions,
                'pending_debit_units':str(sum(int(d['review']['debit_units']) for d in a['held'])),
                'latestness_established':False, 'old_device_fenced':False, 'current_spending_authority':False,
                'signing_enabled':False, 'dispatch_enabled':False, 'automatic_resend':False,
                'trust_policy_renewed':False, 'private_keys_restored':False}

    def recover(self, decision_id, *, payer, grant_id=''):
        a = self._audit()
        decision = P4Delivery._selected(a['decisions'], decision_id, payer, grant_id)
        return bytes.fromhex(decision['wire_hex'])

    def export_receipt(self, decision_id, *, payer, grant_id=''):
        a = self._audit()
        P4Delivery._selected(a['decisions'], decision_id, payer, grant_id)
        need(decision_id in a['receipts'], 'exact receipt unavailable; outcome unknown')
        return load_json(encode(a['receipts'][decision_id]['evidence']), max_bytes=MAX_PLAINTEXT_BYTES)
