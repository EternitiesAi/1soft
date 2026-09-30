"""Immutable encrypted invoice data, separate from every financial journal/key.

The dedicated encrypted PKCS8 seed is used only as HKDF input for invoice data.
It is never registered as a native spending key and no signing function exists
here. Existing cryptography primitives and private vault I/O are reused. This is
trusted-host software custody: no hostile-OS, rollback or memory-erasure claim.
"""
from contextlib import contextmanager
from dataclasses import asdict
import hashlib
from pathlib import Path
import sqlite3
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from block_application import encode
from commit_verifier import load_json
from invoice_privacy import encrypt_invoice, decrypt_invoice, validate_envelope, MAX_ENVELOPE_BYTES
from local_devnet import ROOT, private_new, read_private
from native_core import pubkey, public
from offline_signer import create_vault, _load_vault
from p4_evidence import hash_text, integer, need
from p4_read_store import private_path
from payment_requests import parse_request
from payment_x402 import NativePaymentExpectation, parse_payment_required

APPLICATION_ID = 0x31504956
FORMAT = '1soft/private-invoice-storage/v1'
MAX_INVOICES = 64
MAX_DATABASE_BYTES = 8 * 1024 * 1024
KEY_INFO = b'1soft/private-invoice-data-key/v1\x00'
CONFIG_FIELDS = {'schema', 'format', 'genesis_sha256', 'invoice_key_public', 'vault_sha256'}
SCHEMA = {
    'config': 'CREATE TABLE config(id INTEGER PRIMARY KEY CHECK(id=1),payload BLOB NOT NULL,last_ns INTEGER NOT NULL)',
    'invoices': 'CREATE TABLE invoices(request_id TEXT PRIMARY KEY,quote_id TEXT UNIQUE NOT NULL,required_header TEXT NOT NULL,expectation BLOB NOT NULL,request BLOB NOT NULL,envelope BLOB NOT NULL,envelope_sha256 TEXT NOT NULL)',
}


def sha(raw): return hashlib.sha256(raw).hexdigest()


def configuration(root, genesis):
    root = Path(root).absolute(); hash_text(genesis)
    raw = read_private(root / 'storage.json', 4096)
    value = load_json(raw, max_bytes=4096)
    need(type(value) is dict and set(value) == CONFIG_FIELDS and encode(value) == raw,
         'invoice storage configuration differs')
    need(type(value['schema']) is int and value['schema'] == 1 and
         value['format'] == FORMAT and value['genesis_sha256'] == genesis,
         'invoice storage belongs to another context')
    pubkey(value['invoice_key_public']); hash_text(value['vault_sha256'])
    need(sha(read_private(root / 'invoice-data.pem', 8192)) == value['vault_sha256'],
         'dedicated invoice vault bytes changed; no replacement or repair')
    return value


def initialize_invoice_storage(directory, genesis_sha256, *, password, clock=time.time_ns):
    root = Path(directory).absolute(); hash_text(genesis_sha256); integer(clock(), 1)
    need(not root.is_relative_to(ROOT), 'private runtime must be outside source')
    need(not root.exists() and not root.is_symlink(), 'invoice storage exists; no overwrite or repair')
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    # Interrupted initialization is retained and refused, never reset or repaired.
    key_public = create_vault(root / 'invoice-data.pem', password)
    value = dict(schema=1, format=FORMAT, genesis_sha256=genesis_sha256,
                 invoice_key_public=key_public,
                 vault_sha256=sha(read_private(root / 'invoice-data.pem', 8192)))
    private_new(root / 'storage.json', encode(value))
    with InvoiceBook(root / 'invoices.sqlite', value, create=True, clock=clock): pass
    return {'status': 'dedicated_invoice_storage_initialized',
            'genesis_sha256': genesis_sha256, 'onchain_privacy': False,
            'financial_journal_created': False, 'production_custody': False}


def open_invoice_storage(directory, genesis_sha256, *, clock=time.time_ns):
    root = Path(directory).absolute()
    return InvoiceBook(root / 'invoices.sqlite', configuration(root, genesis_sha256), clock=clock)


class InvoiceBook:
    """Append-only ciphertext/quote correlation; never authority to spend."""
    def __init__(self, path, config, *, create=False, clock=time.time_ns):
        need(type(create) is bool and callable(clock), 'explicit invoice storage mode/clock required')
        self.path = private_path(path); self.root = self.path.parent; self.clock = clock
        self.config = configuration(self.root, config['genesis_sha256'])
        need(self.config == config, 'invoice storage configuration changed')
        self.genesis = self.config['genesis_sha256']
        self.invoice_key_public = self.config['invoice_key_public']; self.db = None
        if create: private_new(self.path, b'')
        else: need(self.path.is_file(), 'invoice storage is not initialized')
        try:
            self.db = sqlite3.connect(self.path.as_uri() + '?mode=rw', uri=True,
                                      isolation_level=None, timeout=5)
            self.db.execute('PRAGMA trusted_schema=OFF')
            if create:
                self.db.execute('PRAGMA journal_mode=WAL'); self.db.execute('PRAGMA synchronous=FULL')
                with self.atomic():
                    self.db.execute(f'PRAGMA application_id={APPLICATION_ID}')
                    for sql in SCHEMA.values(): self.db.execute(sql)
                    self.db.execute('INSERT INTO config VALUES(1,?,?)', (encode(self.config), integer(self.clock(), 1)))
                # private_new already fsynced the directory containing the DB name.
            need(self.db.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID,
                 'unknown invoice database')
            need(self.db.execute('PRAGMA journal_mode').fetchone()[0] == 'wal', 'invoice journal mode differs')
            self.db.execute('PRAGMA synchronous=FULL'); self._catalog()
        except BaseException: self.close(); raise

    def close(self):
        if self.db is not None: self.db.close(); self.db = None
    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    @contextmanager
    def atomic(self, *, write=True):
        self.db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK'); raise

    def _catalog(self):
        need(configuration(self.root, self.genesis) == self.config, 'invoice configuration changed')
        for file in (self.path, Path(str(self.path) + '-wal'), Path(str(self.path) + '-shm')):
            private_path(file)
            if file.exists(): need(file.stat().st_size <= MAX_DATABASE_BYTES, 'invoice storage exceeds bound')
        objects = {name: (kind, sql) for kind, name, sql in self.db.execute(
            "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
        need(objects == {name: ('table', sql) for name, sql in SCHEMA.items()},
             'invoice schema or uniqueness constraints differ')
        config = self.db.execute('SELECT id,payload,last_ns FROM config').fetchall()
        need(len(config) == 1 and config[0][:2] == (1, encode(self.config)), 'invoice database identity differs')
        last = integer(config[0][2], 1); entries = {}
        rows = self.db.execute('SELECT * FROM invoices ORDER BY rowid').fetchall()
        need(len(rows) <= MAX_INVOICES, 'invoice capacity exceeded')
        for rid, qid, header, expectation_raw, request_raw, envelope, envelope_hash in rows:
            hash_text(rid); hash_text(qid); hash_text(envelope_hash)
            need(type(expectation_raw) is bytes and len(expectation_raw) <= 4096,
                 'invoice expectation exceeds bound')
            e = load_json(expectation_raw, max_bytes=4096)
            need(encode(e) == expectation_raw, 'invoice expectation bytes differ')
            expected = NativePaymentExpectation(**e)
            request = parse_request(request_raw, self.genesis, now_ns=last, historical=True)
            # Structural historical validation only; never fresh spending authority.
            quote = parse_payment_required(header, expected, now_ns=request['created_ns'])
            need(quote['request_id'] == rid and quote['quote_sha256'] == qid and
                 encode(quote['request']) == request_raw, 'invoice quote/request correlation differs')
            need(type(envelope) is bytes and 0 < len(envelope) <= MAX_ENVELOPE_BYTES and
                 sha(envelope) == envelope_hash, 'retained encrypted invoice changed')
            validate_envelope(envelope, genesis_sha256=self.genesis, request_sha256=rid)
            need(rid not in entries, 'duplicate retained invoice identity')
            entries[rid] = dict(request_id=rid, quote_sha256=qid, required_header=header,
                expectation=e, request=request, envelope_sha256=envelope_hash,
                application_data_encrypted=True, onchain_privacy=False,
                ciphertext_authenticity_verified=False, execution_proven=False, spending_authority=False)
        return last, entries

    def _key(self, password):
        key = _load_vault(self.root / 'invoice-data.pem', password)
        need(public(key) == self.invoice_key_public, 'invoice key identity differs')
        seed = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
        return HKDF(algorithm=hashes.SHA256(), length=32,
                    salt=bytes.fromhex(self.genesis), info=KEY_INFO).derive(seed)

    def retain(self, *, required_header, expectation, content, password):
        # Live offer validation precedes key access or any persistent change.
        now = integer(self.clock(), 1)
        quote = parse_payment_required(required_header, expectation, now_ns=now)
        need(expectation.genesis_sha256 == self.genesis, 'invoice belongs to another genesis')
        key = self._key(password); rid = quote['request_id']
        with self.atomic():
            # Vault unlock and lock acquisition may outlive a short quote. The
            # transaction rechecks the trusted current time before retention.
            now = integer(self.clock(), now)
            quote = parse_payment_required(required_header, expectation, now_ns=now)
            last, entries = self._catalog(); integer(now, last)
            if rid in entries:
                entry = entries[rid]
                need(entry['required_header'] == required_header and entry['expectation'] == asdict(expectation),
                     'invoice already has different merchant terms')
                raw = self.db.execute('SELECT envelope FROM invoices WHERE request_id=?', (rid,)).fetchone()[0]
                old = decrypt_invoice(raw, key=key, genesis_sha256=self.genesis, request_sha256=rid)
                need(type(content) is dict and old == content, 'invoice already contains different private data')
                self.db.execute('UPDATE config SET last_ns=? WHERE id=1', (now,))
                return {**entry, 'status': 'already_retained'}
            need(len(entries) < MAX_INVOICES, 'invoice capacity reached; no eviction')
            raw = encrypt_invoice(content, key=key, genesis_sha256=self.genesis, request_sha256=rid)
            self.db.execute('INSERT INTO invoices VALUES(?,?,?,?,?,?,?)',
                (rid, quote['quote_sha256'], required_header, encode(asdict(expectation)),
                 encode(quote['request']), raw, sha(raw)))
            self.db.execute('UPDATE config SET last_ns=? WHERE id=1', (now,))
        return {**self.selected(rid), 'status': 'encrypted_invoice_retained'}

    def entries(self):
        with self.atomic(write=False): return list(self._catalog()[1].values())

    def selected(self, rid):
        hash_text(rid)
        with self.atomic(write=False):
            _, entries = self._catalog(); need(rid in entries, 'invoice unavailable')
            return entries[rid]

    def envelope(self, rid):
        self.selected(rid)
        with self.atomic(write=False):
            return self.db.execute('SELECT envelope FROM invoices WHERE request_id=?', (rid,)).fetchone()[0]

    def decrypt(self, rid, *, password):
        row = self.selected(rid); key = self._key(password)
        return decrypt_invoice(self.envelope(rid), key=key,
            genesis_sha256=self.genesis, request_sha256=row['request_id'])
