"""Private local merchant quote/consumption journal; never a funds journal.

Public resource bytes are fixed at quote creation. A transaction retains one
verified native consumption and exact local result before return. There is no
external side-effect callback and no database/HTTP atomicity claim. Every repeat
fulfillment rechecks actual proof under the original independent trust inputs.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import os
from pathlib import Path
import sqlite3

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from block_application import restore
from commit_verifier import encode, exact, load_json
from native_core import DOMAIN, canonical, digest
from p4_evidence import (MAX_EVIDENCE_BYTES, check_clock, content_id, freeze,
                         hash_text, integer, need, p4_genesis, policy_checked,
                         verify_evidence)
from p4_read_store import private_path
from p4_receipt_capsule import MAX_CAPSULE_BYTES, encode_capsule, parse_capsule
from payment_x402 import (MAX_REQUIRED_HEADER, MAX_SIGNATURE_HEADER,
    NativePaymentExpectation, TrustedMerchantAssignment, _decode, _expectation,
    _sha, _wire, make_payment_signature, parse_payment_required,
    parse_payment_response, verify_merchant_payment, invoice_binding)

APPLICATION_ID = 0x31504D42
FORMAT = '1soft/private-merchant-book/v1'
MAX_QUOTES = 64
MAX_RESOURCE_BYTES = 64 * 1024
MAX_STORED_BYTES = 64 * 1024 * 1024
MAX_DB_BYTES = 80 * 1024 * 1024
EXPECTATION_FIELDS = {'merchant_origin', 'resource_url', 'network', 'asset',
                      'genesis_sha256', 'recipient', 'amount_units'}
SCHEMA = {
    'config': 'CREATE TABLE config(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, format TEXT NOT NULL, genesis_sha256 TEXT NOT NULL, policy_id TEXT NOT NULL, policy BLOB NOT NULL, last_ns INTEGER NOT NULL)',
    'quotes': 'CREATE TABLE quotes(quote_id TEXT PRIMARY KEY, recipient TEXT NOT NULL UNIQUE, required BLOB NOT NULL, expectation BLOB NOT NULL, resource BLOB NOT NULL, resource_sha256 TEXT NOT NULL, retained_ns INTEGER NOT NULL)',
    'enrollments': 'CREATE TABLE enrollments(quote_id TEXT PRIMARY KEY REFERENCES quotes(quote_id), payer TEXT NOT NULL, wire BLOB NOT NULL, wire_sha256 TEXT NOT NULL UNIQUE, signer_public_key TEXT NOT NULL, evidence BLOB NOT NULL, evidence_id TEXT NOT NULL, enrolled_ns INTEGER NOT NULL)',
    'fulfillments': 'CREATE TABLE fulfillments(quote_id TEXT PRIMARY KEY REFERENCES enrollments(quote_id), native_txid TEXT NOT NULL UNIQUE, wire_sha256 TEXT NOT NULL UNIQUE, capsule BLOB NOT NULL, capsule_sha256 TEXT NOT NULL, signature_header TEXT NOT NULL, response_header TEXT NOT NULL, resource BLOB NOT NULL, resource_sha256 TEXT NOT NULL, fulfilled_ns INTEGER NOT NULL)',
}


def _path(path):
    p = private_path(path)
    for file in (p, *(Path(str(p) + s) for s in ('-wal', '-shm', '-journal'))):
        if file.exists(): need(file.stat().st_size <= MAX_DB_BYTES, 'merchant file exceeds physical bound')
    return p


def _resource(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_RESOURCE_BYTES,
         'bounded nonempty immutable public resource bytes required')
    return raw


def _evidence(raw):
    if type(raw) is bytes:
        need(0 < len(raw) <= MAX_EVIDENCE_BYTES, 'bounded independent enrollment evidence required')
        value = load_json(raw, max_bytes=MAX_EVIDENCE_BYTES)
        need(encode(value) == raw, 'enrollment evidence must be canonical')
    else:
        value = freeze(raw, MAX_EVIDENCE_BYTES)
        raw = encode(value)
    need(type(value) is dict, 'independent P4 enrollment evidence required')
    return value, raw


def _stored_quote(header_raw, expectation_raw):
    need(type(header_raw) is bytes and 0 < len(header_raw) <= MAX_REQUIRED_HEADER,
         'invalid retained merchant header')
    need(type(expectation_raw) is bytes and len(expectation_raw) <= 8192,
         'invalid retained merchant expectation')
    value = load_json(expectation_raw, max_bytes=8192)
    exact(value, EXPECTATION_FIELDS, 'retained merchant expectation')
    need(encode(value) == expectation_raw, 'retained expectation spelling changed')
    expectation = NativePaymentExpectation(**value)
    try: header = header_raw.decode('ascii')
    except UnicodeError as exc: raise ValueError('invalid retained header text') from exc
    offer, _ = _decode(header, MAX_REQUIRED_HEADER)
    accepts = offer.get('accepts')
    need(type(accepts) is list and len(accepts) == 1 and type(accepts[0]) is dict and
         type(accepts[0].get('extra')) is dict, 'invalid retained quote shape')
    start = integer(accepts[0]['extra'].get('createdNs'), 1)
    # Retained records remain inspectable after quote expiry; only their shape is
    # checked at creation time here. Enroll/fulfill separately check current time.
    quote = parse_payment_required(header, expectation, now_ns=start)
    return header, expectation, quote


class MerchantBook:
    """One local merchant's immutable assignments and durable consumption.

    The caller MUST share this book for every merchant invoice. Copies or separate
    books do not coordinate replay claims. Trusted same-user POSIX storage/clock
    and an intact original database are assumptions, not hostile-OS protections.
    """
    def __init__(self, path, genesis_bytes, policy, *, clock, create=False, read_only=False):
        need(type(create) is bool and type(read_only) is bool and not (create and read_only),
             'invalid merchant book mode')
        need(callable(clock) and type(genesis_bytes) is bytes, 'trusted clock and independent genesis bytes required')
        self._policy_raw = encode(policy_checked(policy)); self.policy_id = _sha(self._policy_raw)
        self.genesis = bytes(genesis_bytes)
        native, _ = p4_genesis(self.genesis, self.policy['genesis_sha256'])
        need(native['asset'] == 'DEV', 'merchant supports development native DEV only')
        self._native_raw = encode(native)
        self.clock = clock; self.read_only = read_only; self.db = None
        now = integer(self.clock(), 1); check_clock(self.policy, now)
        self.path = _path(path)
        if create:
            need(not any(p.exists() or p.is_symlink() for p in
                 (self.path, *(Path(str(self.path) + s) for s in ('-wal', '-shm', '-journal')))),
                 'merchant book or sidecar already exists; no overwrite or repair')
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        else: need(self.path.is_file(), 'merchant book is not initialized')
        try:
            self.db = sqlite3.connect(self.path.as_uri() + ('?mode=ro' if read_only else '?mode=rw'),
                                      uri=True, isolation_level=None, timeout=5)
            self.db.execute('PRAGMA trusted_schema=OFF'); self.db.execute('PRAGMA foreign_keys=ON')
            if create:
                self.db.execute('PRAGMA journal_mode=WAL'); self.db.execute('PRAGMA synchronous=FULL')
                with self.atomic():
                    self.db.execute(f'PRAGMA application_id={APPLICATION_ID}')
                    for sql in SCHEMA.values(): self.db.execute(sql)
                    self.db.execute('INSERT INTO config VALUES(1,1,?,?,?,?,?)',
                        (FORMAT, self.policy['genesis_sha256'], self.policy_id, self._policy_raw, now))
                parent = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try: os.fsync(parent)
                finally: os.close(parent)
            self._catalog(now)
            need(self.db.execute('PRAGMA journal_mode').fetchone()[0] == 'wal',
                 'merchant journal mode differs; no repair')
            if not read_only: self.db.execute('PRAGMA synchronous=FULL')
        except BaseException: self.close(); raise

    @property
    def policy(self): return load_json(self._policy_raw, max_bytes=4096)
    @property
    def native_genesis(self): return load_json(self._native_raw, max_bytes=1024 * 1024)

    def close(self):
        if self.db is not None: self.db.close(); self.db = None
    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    @contextmanager
    def atomic(self, write=True):
        need(self.db is not None and not self.db.in_transaction and not (write and self.read_only),
             'merchant transaction or read-only mode conflict')
        self.db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise

    def _catalog(self, now):
        _path(self.path)
        need(self.db.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID,
             'unknown merchant database; no repair')
        objects = {name: (kind, sql) for kind, name, sql in self.db.execute(
            "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
        need(objects == {name: ('table', sql) for name, sql in SCHEMA.items()},
             'merchant schema or uniqueness constraints differ')
        config = self.db.execute('SELECT * FROM config').fetchall()
        need(len(config) == 1 and config[0][:-1] ==
             (1, 1, FORMAT, self.policy['genesis_sha256'], self.policy_id, self._policy_raw),
             'merchant independent genesis/policy identity differs')
        last = integer(config[0][-1], 1); check_clock(self.policy, now, last)
        sizes = [self.db.execute(sql).fetchone() for sql in (
            'SELECT count(*),coalesce(sum(length(required)+length(expectation)+length(resource)),0) FROM quotes',
            'SELECT count(*),coalesce(sum(length(wire)+length(evidence)),0) FROM enrollments',
            'SELECT count(*),coalesce(sum(length(capsule)+length(signature_header)+length(response_header)+length(resource)),0) FROM fulfillments')]
        need(all(0 <= count <= MAX_QUOTES and 0 <= size <= MAX_STORED_BYTES for count, size in sizes) and
             sum(size for _, size in sizes) <= MAX_STORED_BYTES, 'merchant capacity exceeded; no eviction')
        entries = {}; recipients = set()
        for qid, recipient, header_raw, expectation_raw, resource, resource_hash, retained in self.db.execute(
                'SELECT * FROM quotes ORDER BY rowid'):
            hash_text(qid); hash_text(resource_hash); integer(retained, 1, last)
            header, expectation, quote = _stored_quote(header_raw, expectation_raw)
            need(quote['quote_sha256'] == qid and expectation.recipient == recipient and
                 recipient not in recipients and _sha(_resource(resource)) == resource_hash,
                 'merchant quote identity, recipient uniqueness or resource changed')
            need(expectation.genesis_sha256 == self.policy['genesis_sha256'], 'merchant quote changes genesis')
            invoice=quote.get('invoice_terms')
            if invoice is not None:
                need(self.native_genesis.get('invoice_commitment_version')==1 and
                     invoice['resource_sha256']==resource_hash,'retained invoice capability or resource digest differs')
            recipients.add(recipient)
            entries[qid] = dict(quote=quote, required=header, expectation=expectation,
                resource=resource, resource_sha256=resource_hash, retained_ns=retained,
                enrollment=None, fulfillment=None)
        enrolled_wires = set()
        for qid, payer, wire, wire_hash, signer, evidence_raw, evidence_id, enrolled in self.db.execute(
                'SELECT * FROM enrollments ORDER BY rowid'):
            need(qid in entries and entries[qid]['enrollment'] is None, 'unknown or duplicate merchant enrollment')
            row = entries[qid]; packet = _wire(wire, row['expectation'], payer)
            invoice_binding(packet, row['quote'].get('invoice_terms'))
            hash_text(wire_hash); hash_text(signer); hash_text(evidence_id); integer(enrolled, row['retained_ns'], last)
            _, original_evidence = _evidence(evidence_raw)
            need(_sha(wire) == wire_hash and wire_hash not in enrolled_wires and
                 _sha(original_evidence) == evidence_id, 'enrollment wire/evidence identity changed')
            enrolled_wires.add(wire_hash)
            row['enrollment'] = dict(payer=payer, wire=wire, wire_sha256=wire_hash,
                signer_public_key=signer, evidence=evidence_raw, evidence_id=evidence_id, enrolled_ns=enrolled)
        consumed_ids = set(); consumed_wires = set()
        for (qid, txid, wire_hash, capsule_raw, capsule_hash, signature, response,
             resource, resource_hash, fulfilled) in self.db.execute('SELECT * FROM fulfillments ORDER BY rowid'):
            need(qid in entries and entries[qid]['enrollment'] is not None, 'fulfillment lacks independent enrollment')
            row = entries[qid]; enrollment = row['enrollment']
            hash_text(txid); hash_text(wire_hash); hash_text(capsule_hash); hash_text(resource_hash)
            integer(fulfilled, enrollment['enrolled_ns'], last)
            capsule = parse_capsule(capsule_raw)
            need(type(capsule_raw) is bytes and len(capsule_raw) <= MAX_CAPSULE_BYTES and
                 _sha(capsule_raw) == capsule_hash and txid not in consumed_ids and wire_hash not in consumed_wires and
                 wire_hash == enrollment['wire_sha256'] and txid == _sha(DOMAIN + canonical(
                     _wire(enrollment['wire'], row['expectation'], enrollment['payer'])['body'])) and
                 capsule['binding']['native_txid'] == txid and
                 resource == row['resource'] and resource_hash == row['resource_sha256'] and
                 _sha(_resource(resource)) == resource_hash, 'consumption identity or immutable result changed')
            need(type(signature) is str and len(signature) <= MAX_SIGNATURE_HEADER and signature ==
                 make_payment_signature(required_header=row['required'], expectation=row['expectation'],
                    exact_wire=enrollment['wire'], capsule=capsule_raw, payer=enrollment['payer'],
                    now_ns=row['quote']['request']['created_ns']), 'retained fulfillment wrapper changed')
            declaration = parse_payment_response(response, row['expectation'], payer=enrollment['payer'],
                quote_sha256=qid, wire_sha256=wire_hash, capsule_sha256=capsule_hash)
            need(declaration['response']['transaction'] == txid, 'retained response changes native identity')
            consumed_ids.add(txid); consumed_wires.add(wire_hash)
            row['fulfillment'] = dict(native_txid=txid, wire_sha256=wire_hash,
                capsule=capsule_raw, capsule_sha256=capsule_hash, signature_header=signature,
                payment_response_header=response, resource=resource, resource_sha256=resource_hash,
                fulfilled_ns=fulfilled)
        return last, entries

    def _now(self): return integer(self.clock(), 1)

    def _advance(self, now):
        self.db.execute('UPDATE config SET last_ns=? WHERE id=1', (now,))

    def add_quote(self, required_header, expectation, *, resource):
        """Explicit operator quote creation; recipient is never reused or evicted."""
        now = self._now(); _expectation(expectation); _resource(resource)
        quote = parse_payment_required(required_header, expectation, now_ns=now)
        expectation_raw = encode(asdict(expectation)); resource_hash = _sha(resource); qid = quote['quote_sha256']
        need(expectation.genesis_sha256 == self.policy['genesis_sha256'], 'quote belongs to another genesis')
        invoice=quote.get('invoice_terms')
        if invoice is not None:
            need(self.native_genesis.get('invoice_commitment_version')==1 and
                 invoice['resource_sha256']==resource_hash,'invoice capability or resource digest differs')
        with self.atomic():
            _, entries = self._catalog(now)
            if qid in entries:
                old = entries[qid]
                need(old['required'] == required_header and encode(asdict(old['expectation'])) == expectation_raw and
                     old['resource'] == resource, 'retained quote/result is immutable')
                self._advance(now)
                return {'status': 'already_retained', 'quote_sha256': qid, 'execution_proven': False}
            need(len(entries) < MAX_QUOTES and not any(r['expectation'].recipient == expectation.recipient
                 for r in entries.values()), 'recipient already assigned or quote capacity reached; no reuse')
            self.db.execute('INSERT INTO quotes VALUES(?,?,?,?,?,?,?)',
                (qid, expectation.recipient, required_header.encode('ascii'), expectation_raw,
                 resource, resource_hash, now))
            self._advance(now); self._catalog(now)
        return {'status': 'quote_retained', 'quote_sha256': qid, 'execution_proven': False}

    def _verified_enrollment(self, row, payer, wire, evidence, now):
        packet = _wire(wire, row['expectation'], payer); body = packet['body']
        need(body['chain_id'] == self.native_genesis['chain_id'] and
             body['genesis_hash'] == digest(self.native_genesis), 'enrolled wire changes pinned native chain/genesis')
        supplied, raw = _evidence(evidence)
        report = verify_evidence(supplied, self.genesis, self.policy, now_ns=now)
        matches = [r for r in report['receipts'] if r['wire_sha256'] == _sha(wire) and
                   canonical(r['record']['envelope']) == wire]
        need(len(matches) <= 1, 'ambiguous historical enrollment signer')
        if matches:
            signer = matches[0]['record']['signer_public_key']
        else:
            # Only independently verified current state supplies a pending wire's
            # key. No unknown/revoked grant falls back to the owner key.
            with_ledger = restore(self.native_genesis, supplied['state']['native'])
            try:
                owner = with_ledger._account(payer); with_ledger._account(row['expectation'].recipient)
                chosen = owner
                if body['grant_id']:
                    chosen = with_ledger.db.execute('SELECT * FROM grants WHERE id=?',
                        (with_ledger.grant_storage_id(payer, body['grant_id']),)).fetchone()
                    need(chosen is not None and chosen['owner'] == payer and not chosen['revoked'] and
                         chosen['epoch'] == owner['epoch'] and report['state_height'] < chosen['expires'] and
                         body['valid_until'] <= chosen['expires'], 'verified grant cannot authenticate this enrollment')
                need(body['nonce'] == chosen['nonce'] and body['valid_until'] > report['state_height'],
                     'current verified signer does not authenticate a pending wire at this nonce/expiry')
                signer = chosen['public_key']
            finally: with_ledger.close()
        hash_text(signer)
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer)).verify(
                bytes.fromhex(packet['signature']), DOMAIN + canonical(body))
        except (InvalidSignature, ValueError) as exc:
            raise ValueError('enrolled native wire signature is invalid under independently verified key') from exc
        invoice_binding(packet,row['quote'].get('invoice_terms'))
        return signer, raw, report['evidence_id']

    def enroll_wire(self, quote_id, payer, wire, *, evidence):
        """Explicit merchant confirmation of independently retained original wire.

        Incoming PAYMENT-SIGNATURE cannot invoke this implicitly or supply a key.
        A verified historical receipt can name its historical signer; otherwise
        only the exact currently verified account/grant state is accepted.
        """
        hash_text(quote_id); now = self._now()
        with self.atomic():
            _, entries = self._catalog(now); need(quote_id in entries, 'merchant quote unavailable')
            row = entries[quote_id]
            parse_payment_required(row['required'], row['expectation'], now_ns=now)
            signer, raw_evidence, evidence_id = self._verified_enrollment(row, payer, wire, evidence, now)
            old = row['enrollment']
            if old is not None:
                need(old['payer'] == payer and old['wire'] == wire and old['signer_public_key'] == signer,
                     'merchant wire assignment is immutable')
                self._advance(now)
                return {'status': 'already_enrolled', 'quote_sha256': quote_id,
                        'wire_sha256': old['wire_sha256'], 'execution_proven': False,
                        'wallet_reservations_changed': False}
            need(not any(r['enrollment'] is not None and r['enrollment']['wire'] == wire
                 for r in entries.values()), 'original native wire already assigned globally')
            self.db.execute('INSERT INTO enrollments VALUES(?,?,?,?,?,?,?,?)',
                (quote_id, payer, wire, _sha(wire), signer, raw_evidence, evidence_id, now))
            self._advance(now); self._catalog(now)
        return {'status': 'wire_enrolled', 'quote_sha256': quote_id, 'wire_sha256': _sha(wire),
                'execution_proven': False, 'wallet_reservations_changed': False}

    def fulfill(self, quote_id, signature_header, capsule):
        """Reverify then atomically consume and retain one exact local result.

        Duplicate identical fulfillment returns its retained bytes only after
        complete current proof verification. No external callback is executed.
        """
        hash_text(quote_id); now = self._now()
        with self.atomic():
            _, entries = self._catalog(now); need(quote_id in entries, 'merchant quote unavailable')
            row = entries[quote_id]; enrollment = row['enrollment']
            need(enrollment is not None, 'independent explicit wire enrollment required before fulfillment')
            signer, _, _ = self._verified_enrollment(row, enrollment['payer'], enrollment['wire'],
                                                    enrollment['evidence'], now)
            need(signer == enrollment['signer_public_key'], 'retained enrollment key changed')
            assignment = TrustedMerchantAssignment(quote_id, row['quote']['request_id'],
                row['expectation'].recipient, enrollment['payer'], enrollment['wire_sha256'])
            proof = verify_merchant_payment(signature_header=signature_header,
                required_header=row['required'], expectation=row['expectation'], assignment=assignment,
                exact_wire=enrollment['wire'], capsule=capsule, genesis_bytes=self.genesis,
                policy=self.policy, payer=enrollment['payer'], now_ns=now)
            capsule_raw = encode_capsule(capsule); capsule_hash = _sha(capsule_raw)
            old = row['fulfillment']
            if old is not None:
                need(old['signature_header'] == signature_header and old['capsule'] == capsule_raw and
                     old['native_txid'] == proof['native_txid'] and old['wire_sha256'] == proof['wire_sha256'] and
                     old['resource'] == row['resource'] and
                     old['payment_response_header'] == proof['payment_response_header'],
                     'completed fulfillment has different quote/payment/proof/result; no cache shortcut')
                saved = old; status = 'original_local_fulfillment_retained'
            else:
                need(not any(r['fulfillment'] is not None and (
                    r['fulfillment']['native_txid'] == proof['native_txid'] or
                    r['fulfillment']['wire_sha256'] == proof['wire_sha256']) for r in entries.values()),
                    'native payment identity already consumed globally')
                saved = dict(native_txid=proof['native_txid'], wire_sha256=proof['wire_sha256'],
                    capsule=capsule_raw, capsule_sha256=capsule_hash, signature_header=signature_header,
                    payment_response_header=proof['payment_response_header'], resource=row['resource'],
                    resource_sha256=row['resource_sha256'], fulfilled_ns=now)
                self.db.execute('INSERT INTO fulfillments VALUES(?,?,?,?,?,?,?,?,?,?)',
                    (quote_id, saved['native_txid'], saved['wire_sha256'], capsule_raw, capsule_hash,
                     signature_header, saved['payment_response_header'], saved['resource'],
                     saved['resource_sha256'], now))
                status = 'local_fulfillment_retained'
            self._advance(now); self._catalog(now)
        return {key: saved[key] for key in ('native_txid', 'wire_sha256', 'resource', 'resource_sha256',
            'payment_response_header', 'fulfilled_ns')} | {'status': status, 'quote_sha256': quote_id,
            'native_execution_reverified': True, 'merchant_consumption_retained': True,
            'wallet_reservations_changed': False, 'external_service_delivery_verified': False,
            'external_settlement_verified': False, 'globally_exactly_once_service_delivery': False}

    def _display(self, qid, row):
        enrollment = row['enrollment']; fulfillment = row['fulfillment']
        return {'quote_sha256': qid, 'required_header': row['required'], 'expectation': row['expectation'],
            'resource_sha256': row['resource_sha256'], 'retained_ns': row['retained_ns'],
            'enrollment': None if enrollment is None else {k: enrollment[k] for k in
                ('payer', 'wire_sha256', 'signer_public_key', 'evidence_id', 'enrolled_ns')},
            'fulfillment': None if fulfillment is None else {k: fulfillment[k] for k in
                ('native_txid', 'wire_sha256', 'capsule_sha256', 'resource_sha256', 'fulfilled_ns')},
            'execution_proven': False, 'resource_delivery_authorized': False,
            'wallet_reservations_changed': False}

    def selected(self, quote_id):
        hash_text(quote_id)
        with self.atomic(write=False):
            _, entries = self._catalog(self._now()); need(quote_id in entries, 'merchant quote unavailable')
            return self._display(quote_id, entries[quote_id])

    def entries(self):
        with self.atomic(write=False):
            _, entries = self._catalog(self._now())
            return [self._display(qid, row) for qid, row in entries.items()]
