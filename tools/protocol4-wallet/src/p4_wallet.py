"""Development P4 payments and explicit owner rotation in one financial journal.

No network, governance, dispatch, legacy-wallet migration or trust renewal. Only
exact verified execution retires a hold. A signed-but-unobserved payment stays
reserved even when expired or revoked. The filesystem, clock and caller are
trusted; copied journals, external signers and hostile-host rollback are excluded.
"""
from __future__ import annotations

from contextlib import contextmanager
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from block_application import encode, restore
from commit_verifier import exact, load_json
from native_core import (BODY_FIELDS, DOMAIN, FEE_ACCOUNT, MAX_UNITS, canonical,
                         digest, identifier, public, pubkey, sign,
                         accept_account_key, verify_account_key_acceptance)
from invoice_terms import terms_checked, terms_commitment
from offline_signer import _load_vault
from p4_evidence import (MAX_EVIDENCE_BYTES, check_clock, content_id, extends,
                         freeze, hash_text, integer, need, p4_genesis,
                         policy_checked, verify_evidence)
from p4_read_store import private_path
from validator_witness import nanos

APPLICATION_ID = 0x31503457
REVIEW_FORMAT = '1soft/p4-transfer-review/v1'
INVOICE_REVIEW_FORMAT = '1soft/p4-invoice-transfer-review/v1'
ROTATION_REVIEW_FORMAT = '1soft/p4-key-rotation-review/v1'
MAX_OBSERVATIONS = 32
MAX_PAYLOAD = 64 * 1024 * 1024
MAX_DECISIONS = 256
MAX_AGE_SECONDS = 300
MAX_VALIDITY_BLOCKS = 32
ZERO = '0' * 64


class _EvidenceAudit:
    """One exact proof, for one audit only; never persistent financial authority.

    A full miss establishes strictly increasing header times, original signatures
    and complete native/registry execution. Every use still checks its own time.
    The authenticated H+1 tip is the maximum header time, so its future bound
    covers every header when repeating only the time-dependent proof checks.
    """
    def __init__(self, genesis, policy):
        self.genesis = bytes(genesis)
        self.policy = policy_checked(policy)
        self._cached = None

    def verify(self, raw, *, now_ns):
        need(type(raw) is bytes and 0 < len(raw) <= MAX_EVIDENCE_BYTES,
             'invalid bounded observation bytes')
        expiry = check_clock(self.policy, now_ns)
        cached = self._cached
        if cached is None or cached[0] != raw:
            e = load_json(raw, max_bytes=MAX_EVIDENCE_BYTES)
            need(encode(e) == raw, 'wallet evidence encoding differs')
            report = verify_evidence(e, self.genesis, self.policy, now_ns=now_ns)
            tip = nanos(e['headers'][-1]['signed_header']['header']['time'])
            cached = raw, e, report, tip
            self._cached = cached  # Only complete successful verification is retained.
        need(cached[3] <= now_ns + self.policy['max_clock_drift_seconds'] * 10**9,
             'header is too far in the future')
        report = copy.deepcopy(cached[2])
        report['checked_at_ns'] = now_ns
        report['trust_expires_ns'] = expiry
        return copy.deepcopy(cached[1]), report


def revision(wallet_id, policy_id, proof_id, decisions):
    return content_id({'wallet_id': wallet_id, 'policy_id': policy_id,
                       'evidence_id': proof_id,
                       'decisions': [d['id'] for d in decisions]})


def matched_receipt(report, decision):
    raw = bytes.fromhex(decision['wire_hex'])
    txid = hashlib.sha256(DOMAIN + canonical(decision['review']['body'])).hexdigest()
    matches = [r for r in report['receipts'] if r['native_txid'] == txid]
    need(len(matches) <= 1, 'ambiguous native receipt')
    if not matches:
        return None
    row = matches[0]
    need(canonical(row['record']['envelope']) == raw and
         row['record']['signer_public_key'] == decision['review']['signer_public_key'],
         'recorded receipt conflicts with the original signed decision')
    return row


def pending(report, decisions):
    return [d for d in decisions if matched_receipt(report, d) is None]


def rotation_pending(report, decisions, payer):
    return any(d['review']['format'] == ROTATION_REVIEW_FORMAT and
               d['review']['body']['sender'] == payer for d in pending(report, decisions))


def fresh(evidence, policy, now_ns, previous_ns=None):
    check_clock(policy, now_ns, previous_ns)
    tip_ns = nanos(evidence['headers'][-1]['signed_header']['header']['time'])
    need(now_ns - MAX_AGE_SECONDS * 10**9 <= tip_ns <=
         now_ns + policy['max_clock_drift_seconds'] * 10**9,
         'signing requires a recent authenticated checkpoint')
    need(evidence['state']['height'] < 512, 'P4 development height limit reached')


def transfer_review(evidence, report, prior, wallet_id, policy_id, *, payer,
                    recipient, units, valid_until, grant_id='', invoice_terms=None, genesis_sha256=None, height_limit=512):
    """Internal: report must have been reverified from the supplied evidence."""
    identifier(payer); identifier(recipient)
    integer(units, 1, MAX_UNITS)
    need(type(grant_id) is str, 'explicit owner or grant role required')
    if grant_id:
        identifier(grant_id)
    height = report['state_height']
    integer(valid_until, height + 1, min(height_limit, height + MAX_VALIDITY_BLOCKS))
    need(payer != FEE_ACCOUNT and recipient not in (payer, FEE_ACCOUNT), 'invalid transfer endpoint')
    held = pending(report, prior)
    need(not rotation_pending(report, prior, payer),
         'payer key rotation is unresolved; payment signing is paused')
    # Deliberately no speculative nonce ladder: each owner/grant lane has at most
    # one unresolved signed transfer. Different grant lanes share account/budget holds.
    need(not any(d['review']['body']['sender'] == payer and
                 d['review']['body']['grant_id'] == grant_id for d in held),
         'this owner/grant has an unresolved signed transfer; recover or reconcile it')
    g = evidence['state']['genesis']; fee = g['fee']; debit = units + fee
    invoice = None
    if invoice_terms is not None:
        need(g.get('invoice_commitment_version') == 1 and genesis_sha256 is not None,
             'invoice review requires explicit fresh genesis capability')
        need(g['asset'] == 'DEV', 'invoice asset differs from authenticated native asset')
        invoice = terms_checked(invoice_terms, genesis_sha256=genesis_sha256,
                                recipient=recipient, units=units)
    integer(debit, 1, MAX_UNITS)
    ledger = restore(g, evidence['state']['native'])
    try:
        owner = ledger._account(payer); ledger._account(recipient)
        grant = budget = None
        if grant_id:
            grant = ledger.db.execute('SELECT * FROM grants WHERE id=?',
                (ledger.grant_storage_id(payer, grant_id),)).fetchone()
            need(grant is not None and grant['owner'] == payer, 'unknown agent grant; no owner fallback')
            need(not grant['revoked'] and grant['epoch'] == owner['epoch'] and
                 height + 1 <= grant['expires'] and valid_until <= grant['expires'],
                 'agent grant inactive or transfer outlives it')
            need(recipient in json.loads(grant['recipients']), 'recipient outside agent grant')
            budget = ledger.budgets.for_grant(owner, grant, height+1, recipient, debit)
            need(valid_until <= budget['expires'], 'transfer outlives shared budget')
        account_held = sum(int(d['review']['debit_units']) for d in held
                           if d['review']['body']['sender'] == payer)
        need(debit + account_held <= owner['balance'], 'account funds already committed')
        budget_held = 0
        if budget is not None:
            budget_held = sum(int(d['review']['debit_units']) for d in held
                              if d['review']['budget_id'] == budget['id'])
            need(budget['spent'] + budget_held + debit <= budget['cap'],
                 'shared budget funds already committed')
            need(grant['spent'] + debit <= grant['cap'], 'individual grant cap exceeded')
        signer = grant if grant is not None else owner
        op = {'type': 'transfer', 'to': recipient, 'units': units}
        if invoice is not None: op['invoice_commitment'] = terms_commitment(invoice)
        body = ledger.body(payer, signer['nonce'], op,
                           grant_id=grant_id, valid_until=valid_until)
        result = {'schema': 1, 'format': REVIEW_FORMAT, 'wallet_id': wallet_id, 'policy_id': policy_id,
                'evidence_id': report['evidence_id'],
                'revision': revision(wallet_id, policy_id, report['evidence_id'], prior),
                'state_height': height, 'header_hash': report['header_hash'],
                'registry_epoch': report['registry_epoch'], 'payer_epoch': owner['epoch'],
                'signer_public_key': signer['public_key'], 'body': body,
                'budget_id': None if budget is None else budget['id'],
                'debit_units': str(debit), 'account_pending_units': str(account_held),
                'budget_pending_units': str(budget_held)}
        if invoice is not None:
            result.update(format=INVOICE_REVIEW_FORMAT, invoice_terms=invoice)
        return result
    finally:
        ledger.close()


def invoice_review_context(review, genesis, genesis_sha256, now_ns):
    body = review['body']; op = body['op']
    invoice = review.get('invoice_terms')
    if review.get('format') == INVOICE_REVIEW_FORMAT:
        need(genesis.get('invoice_commitment_version') == 1 and invoice is not None,
             'invoice review requires explicit fresh genesis capability')
        exact(op, {'type','to','units','invoice_commitment'}, 'committed transfer operation')
        need(genesis['asset'] == 'DEV', 'invoice asset differs from authenticated native asset')
        value = terms_checked(invoice, genesis_sha256=genesis_sha256,
                              recipient=op['to'], units=op['units'], now_ns=now_ns)
        need(op['invoice_commitment'] == terms_commitment(value),
             'native operation changes reviewed invoice commitment')
        return value
    need(review.get('format') == REVIEW_FORMAT and invoice is None and 'invoice_terms' not in review,
         'unsupported transfer review format')
    exact(op, {'type','to','units'}, 'transfer operation')
    return None


def rotation_review(evidence, report, prior, wallet_id, policy_id, *, payer,
                    new_public_key, valid_until, acceptance='', height_limit=512):
    """Derive fee/nonce/authority solely from reverified canonical wallet state."""
    identifier(payer); pubkey(new_public_key)
    need(payer != FEE_ACCOUNT, 'system account cannot rotate')
    height = report['state_height']
    integer(valid_until, height+1, min(height_limit, height+MAX_VALIDITY_BLOCKS))
    need(type(acceptance) is str, 'invalid incoming consent')
    held = pending(report, prior)
    need(not any(d['review']['body']['sender'] == payer and
                 d['review']['body']['grant_id'] == '' for d in held),
         'owner has an unresolved signed decision; recover or reconcile it')
    g = evidence['state']['genesis']; ledger = restore(g, evidence['state']['native'])
    try:
        owner = ledger._account(payer)
        need(new_public_key != owner['public_key'], 'replacement key is already active')
        need(ledger.db.execute('SELECT 1 FROM accounts WHERE public_key=?',
                             (new_public_key,)).fetchone() is None,
             'replacement key already controls an account')
        integer(owner['epoch']+1, 1, MAX_UNITS); integer(owner['nonce']+1, 1, MAX_UNITS)
        account_held = sum(int(d['review']['debit_units']) for d in held
                           if d['review']['body']['sender'] == payer)
        need(g['fee']+account_held <= owner['balance'], 'account funds already committed')
        body = ledger.body(payer,owner['nonce'],{'type':'rotate_key',
            'public_key':new_public_key,'acceptance':acceptance},valid_until=valid_until)
        if acceptance: verify_account_key_acceptance(body)
        grants = [dict(id=r['id'],public_key=r['public_key'],epoch=r['epoch']) for r in
                  ledger.db.execute('SELECT * FROM grants WHERE owner=? AND epoch=? ORDER BY id',
                                    (payer,owner['epoch']))]
        return {'schema':1,'format':ROTATION_REVIEW_FORMAT,'wallet_id':wallet_id,'policy_id':policy_id,
                'evidence_id':report['evidence_id'],
                'revision':revision(wallet_id,policy_id,report['evidence_id'],prior),
                'state_height':height,'header_hash':report['header_hash'],
                'registry_epoch':report['registry_epoch'],'payer_epoch':owner['epoch'],
                'signer_public_key':owner['public_key'],'body':body,'budget_id':None,
                'debit_units':str(g['fee']),'account_pending_units':str(account_held),
                'budget_pending_units':'0','affected_grants':grants}
    finally: ledger.close()


def rotation_review_context(review, *, accepted):
    need(type(review) is dict, 'rotation review object required')
    need(review.get('format') == ROTATION_REVIEW_FORMAT, 'explicit rotation review required')
    body = review.get('body'); exact(body,BODY_FIELDS,'reviewed rotation body')
    op = body['op']; exact(op,{'type','public_key','acceptance'},'rotation operation')
    need(op['type'] == 'rotate_key' and body['grant_id'] == '', 'rotation requires owner role')
    if accepted:
        need(op['acceptance'] != '', 'incoming key consent required')
        verify_account_key_acceptance(body)
    else: need(op['acceptance'] == '', 'incoming key consent already present')
    return body


def decision_review(e, r, prior, wallet_id, policy_id, review, genesis_sha256, now_ns, *, height_limit=512):
    """Exact format dispatch for stored decisions; legacy transfer bytes unchanged."""
    if review.get('format') == ROTATION_REVIEW_FORMAT:
        body = rotation_review_context(review,accepted=True)
        return rotation_review(e,r,prior,wallet_id,policy_id,payer=body['sender'],
            new_public_key=body['op']['public_key'],valid_until=body['valid_until'],
            acceptance=body['op']['acceptance'],height_limit=height_limit)
    body = review['body']; exact(body,BODY_FIELDS,'reviewed transfer body'); op=body['op']
    invoice = invoice_review_context(review,e['state']['genesis'],genesis_sha256,now_ns)
    need(op['type'] == 'transfer', 'wallet transfer review only supports transfers')
    return transfer_review(e,r,prior,wallet_id,policy_id,payer=body['sender'],
        recipient=op['to'],units=op['units'],valid_until=body['valid_until'],
        grant_id=body['grant_id'],invoice_terms=invoice,genesis_sha256=genesis_sha256,height_limit=height_limit)


class P4Wallet:
    """Offline payment and explicit key-rotation wallet; one shared journal.

    A new P4 journal, never the old CertifiedWallet/read-store/node database.
    Preparing has no financial effect. Approval records signed bytes before return.
    Stored observations and decisions are append-only and reverified, not authority
    inferred from cached balance/status columns. No external signing callback.
    """
    def __init__(self, path, genesis_bytes, policy, *, create=False, clock=time.time_ns):
        need(type(create) is bool, 'invalid creation mode')
        self._policy_bytes = encode(policy_checked(policy))
        self.policy_id = content_id(self.policy)
        self.genesis = bytes(genesis_bytes)
        p4_genesis(self.genesis, self.policy['genesis_sha256'])
        self.clock = clock; self.db = None; self.path = private_path(path)
        if create:
            now = self.clock(); self._check_clock(now)
            fd = os.open(self.path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
            os.close(fd)
        else:
            need(self.path.is_file(), 'wallet is not initialized; no implicit creation')
        try:
            self.db = sqlite3.connect(self.path.as_uri()+'?mode=rw', uri=True,
                                      isolation_level=None, timeout=5)
            if create:
                self.db.execute('PRAGMA journal_mode=WAL')
                self.db.execute('PRAGMA synchronous=FULL')
                with self.atomic():
                    self.db.execute(f'PRAGMA application_id={APPLICATION_ID}')
                    self.db.execute('CREATE TABLE config(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, wallet_id TEXT NOT NULL, policy BLOB NOT NULL, created_ns INTEGER NOT NULL)')
                    self.db.execute('CREATE TABLE observations(seq INTEGER PRIMARY KEY, evidence_id TEXT UNIQUE NOT NULL, parent_id TEXT NOT NULL, checked_ns INTEGER NOT NULL, payload BLOB NOT NULL)')
                    self.db.execute('CREATE TABLE decisions(seq INTEGER PRIMARY KEY, decision_id TEXT UNIQUE NOT NULL, signed_ns INTEGER NOT NULL, payload BLOB NOT NULL)')
                    self.db.execute('INSERT INTO config VALUES (1,1,?,?,?)',
                                    (secrets.token_hex(32), self._policy_bytes, now))
                parent = os.open(self.path.parent, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try: os.fsync(parent)
                finally: os.close(parent)
            self._catalog()
            need(self.db.execute('PRAGMA journal_mode').fetchone()[0] == 'wal', 'wallet journal mode differs')
            self.db.execute('PRAGMA synchronous=FULL')
        except BaseException:
            self.close(); raise

    def _check_clock(self, now, previous_ns=None):
        return check_clock(self.policy, now, previous_ns)

    def _fresh(self, context, now, previous_ns=None):
        return fresh(context, self.policy, now, previous_ns)

    def _transfer_review(self, *args, **kwargs):
        return transfer_review(*args, **kwargs)

    def _rotation_review(self, *args, **kwargs):
        return rotation_review(*args, **kwargs)

    def _decision_review(self, *args, **kwargs):
        return decision_review(*args, **kwargs)

    @property
    def policy(self):
        return load_json(self._policy_bytes, max_bytes=4096)

    def close(self):
        if self.db is not None:
            self.db.close(); self.db = None
    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    @contextmanager
    def atomic(self, write=True):
        need(not self.db.in_transaction, 'wallet transaction already active')
        self.db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction: self.db.execute('ROLLBACK')
            raise

    def _catalog(self):
        private_path(self.path)
        need(self.db.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID,
             'not a P4 wallet; existing database not repaired')
        objects = set(self.db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
        need(objects == {('table','config'), ('table','observations'), ('table','decisions')},
             'unrecognized wallet schema')
        columns = {'config': ('id','version','wallet_id','policy','created_ns'),
                   'observations': ('seq','evidence_id','parent_id','checked_ns','payload'),
                   'decisions': ('seq','decision_id','signed_ns','payload')}
        for table, names in columns.items():
            need(tuple(row[1] for row in self.db.execute(f'PRAGMA table_info({table})')) == names,
                 'wallet columns differ')
        config = self.db.execute('SELECT * FROM config').fetchall()
        need(len(config) == 1 and config[0][:2] == (1,1) and config[0][3] == self._policy_bytes,
             'wallet external policy differs or is missing')
        wallet_id, created = hash_text(config[0][2]), integer(config[0][4])
        for table, limit in (('observations',MAX_OBSERVATIONS), ('decisions',MAX_DECISIONS)):
            n, size = self.db.execute(f'SELECT count(*),coalesce(sum(length(payload)),0) FROM {table}').fetchone()
            need(n <= limit and size <= MAX_PAYLOAD, 'wallet storage capacity exceeded')
        observations = self.db.execute('SELECT * FROM observations ORDER BY seq').fetchall()
        previous, prior_ns, prior_h, old = ZERO, created, -1, None
        for n, row in enumerate(observations, 1):
            seq, evidence_id, parent, checked, raw = row
            integer(seq,n,n); hash_text(evidence_id); integer(checked,prior_ns)
            need(type(raw) is bytes and 0 < len(raw) <= MAX_EVIDENCE_BYTES and
                 hashlib.sha256(raw).hexdigest() == evidence_id and parent == previous,
                 'wallet observation content or lineage differs')
            e = load_json(raw, max_bytes=MAX_EVIDENCE_BYTES)
            need(encode(e) == raw, 'wallet evidence encoding differs')
            height = integer(e['state']['height'], 0, 512)
            need(height > prior_h, 'wallet observations do not increase')
            if old is not None: extends(old, e)
            previous, prior_ns, prior_h, old = evidence_id, checked, height, e
        decisions = []; prior_ns = created
        for n, (seq, decision_id, signed, raw) in enumerate(
                self.db.execute('SELECT * FROM decisions ORDER BY seq'), 1):
            integer(seq,n,n); integer(signed,prior_ns); hash_text(decision_id)
            need(type(raw) is bytes and 0 < len(raw) <= 32768, 'invalid signed decision size')
            d = load_json(raw, max_bytes=32768)
            exact(d, {'id','review','wire_hex','signed_ns'}, 'wallet signing decision')
            need(encode(d) == raw and d['id'] == decision_id == content_id(d['review']) and
                 type(d['signed_ns']) is int and d['signed_ns'] == signed,
                 'wallet decision identity changed')
            need(type(d['wire_hex']) is str and len(d['wire_hex']) <= 32768 and
                 bytes.fromhex(d['wire_hex']).hex() == d['wire_hex'], 'invalid signed wire encoding')
            decisions.append(d); prior_ns = signed
        latest_ns = max([created] + [r[3] for r in observations] + [d['signed_ns'] for d in decisions])
        return wallet_id, observations, decisions, latest_ns

    def _load(self, *, historical=False):
        wallet_id, obs, decisions, latest_ns = self._catalog()
        now = latest_ns if historical else self.clock()
        self._check_clock(now, latest_ns)
        need(obs, 'no authenticated P4 wallet checkpoint')
        raw_by_id = {r[1]: r for r in obs}
        audit = _EvidenceAudit(self.genesis, self.policy)
        def verify_at(proof_id, at):
            need(proof_id in raw_by_id, 'decision source evidence is missing')
            row = raw_by_id[proof_id]
            integer(at, row[3])
            return audit.verify(row[4], now_ns=at)
        # Authenticate saved signing context, exact bytes, and original reservation
        # calculation for every decision. No cached public key/status is sufficient.
        last_proof_seq = 0
        for n, d in enumerate(decisions):
            review = d['review']; proof = review['evidence_id']
            e, r = verify_at(proof, d['signed_ns'])
            need(raw_by_id[proof][0] >= last_proof_seq, 'signing evidence moved backward')
            last_proof_seq = raw_by_id[proof][0]
            self._fresh(e,d['signed_ns'])
            body = review['body']
            expected = self._decision_review(e,r,decisions[:n],wallet_id,self.policy_id,review,
                                       self.policy['genesis_sha256'],d['signed_ns'])
            need(encode(review) == encode(expected), 'stored review differs from verified origin')
            wire = bytes.fromhex(d['wire_hex']); packet = load_json(wire, max_bytes=16384)
            exact(packet, {'body','signature'}, 'signed transfer')
            need(canonical(packet) == wire and packet['body'] == body, 'signed payment differs from approved review')
            pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(review['signer_public_key']))
            try:
                pk.verify(bytes.fromhex(packet['signature']), DOMAIN + canonical(body))
            except (InvalidSignature, ValueError) as exc:
                raise ValueError('stored signature is invalid') from exc
            ledger = restore(e['state']['genesis'], e['state']['native'])
            try: ledger.apply(packet, height=r['state_height']+1)
            finally: ledger.close()
        e, report = verify_at(obs[-1][1], now)
        # Previously confirmed execution may never disappear/change in later state.
        for d in decisions: matched_receipt(report, d)
        if not historical:
            self._check_clock(self.clock(), now)
        return wallet_id, e, report, decisions, latest_ns

    def _revision(self, wallet_id, report, decisions):
        return revision(wallet_id, self.policy_id, None if report is None else report['evidence_id'], decisions)

    def sync(self, evidence, *, expected_revision):
        e = freeze(evidence)
        with self.atomic():
            wallet_id, obs, decisions, latest_ns = self._catalog()
            now = self.clock(); self._check_clock(now, latest_ns)
            if obs:
                wallet_id, previous, old, decisions, latest_ns = self._load()
                need(expected_revision == self._revision(wallet_id, old, decisions), 'reviewed wallet revision changed')
            else:
                need(not decisions and expected_revision is None, 'initial wallet revision must be empty')
            report = verify_evidence(e, self.genesis, self.policy, now_ns=now)
            if obs:
                extends(previous, e)
                if report['state_height'] == old['state_height']:
                    self._check_clock(self.clock(), now)
                    return {'status':'already_recorded','revision':self._revision(wallet_id,old,decisions)}
            for d in decisions: matched_receipt(report, d)
            raw = encode(e)
            need(len(obs) < MAX_OBSERVATIONS and sum(len(r[4]) for r in obs)+len(raw) <= MAX_PAYLOAD,
                 'wallet observation capacity reached; no evidence evicted')
            checked = self.clock(); self._check_clock(checked, max(now,latest_ns))
            self.db.execute('INSERT INTO observations VALUES (?,?,?,?,?)',
                (len(obs)+1, report['evidence_id'], obs[-1][1] if obs else ZERO, checked, raw))
        return {'status':'checkpoint_recorded','revision':self._revision(wallet_id,report,decisions),
                'state_height':report['state_height'], 'signing_performed':False}

    def status(self):
        with self.atomic(write=False):
            wallet_id, e, report, decisions, _ = self._load()
            return self._status_from_verified(wallet_id,e,report,decisions)

    def _status_from_verified(self,wallet_id,e,report,decisions):
        """Projection only: callers must authenticate the original journal first."""
        held = pending(report, decisions)
        def total_for(field, value):
            return sum(int(d['review']['debit_units']) for d in held
                       if (d['review']['body']['sender'] if field=='payer' else d['review']['budget_id']) == value)
        accounts = [{**a, 'pending_debit_units':str(total_for('payer',a['id'])),
                     'uncommitted_units':str(max(0,int(a['recorded_balance'])-total_for('payer',a['id']))),
                     'reservation_deficit_units':str(max(0,total_for('payer',a['id'])-int(a['recorded_balance'])))}
                    for a in report['accounts']]
        return {'status':'verified-wallet-observation',
                'revision':self._revision(wallet_id,report,decisions),
                'state_height':report['state_height'], 'registry_epoch':report['registry_epoch'],
                'accounts':accounts, 'budgets':[{'id':b[0],'cap':str(b[3]),'spent':str(b[4]),
                'pending_debit_units':str(total_for('budget',b[0])),
                'uncommitted_units':str(max(0,b[3]-b[4]-total_for('budget',b[0]))),
                'reservation_deficit_units':str(max(0,b[4]+total_for('budget',b[0])-b[3]))}
                for b in report['budgets']],
                'decisions':[{'id':d['id'],'status':'pending' if d in held else 'recorded',
                              'debit_units':d['review']['debit_units']} for d in decisions],
                'pending_debit_units':str(sum(int(d['review']['debit_units']) for d in held)),
                'latest_state_guaranteed':False, 'spending_authorized':False,
                'coordination_scope':'this local journal only', 'broadcast':False}

    def prepare(self, *, payer, recipient, units, valid_until, grant_id='', invoice_terms=None):
        with self.atomic(write=False):
            wallet_id, e, report, decisions, latest_ns = self._load()
            self._fresh(e,self.clock(),latest_ns)
            need(len(decisions) < MAX_DECISIONS,'wallet decision capacity reached')
            review = self._transfer_review(e,report,decisions,wallet_id,self.policy_id,payer=payer,
                recipient=recipient,units=units,valid_until=valid_until,grant_id=grant_id,
                invoice_terms=invoice_terms,genesis_sha256=self.policy['genesis_sha256'])
            invoice_review_context(review,e['state']['genesis'],self.policy['genesis_sha256'],self.clock())
            self._fresh(e,self.clock(),latest_ns)
            return {'review':review,'confirmation':content_id(review),
                    'reserved':False,'signed':False,'broadcast':False}

    def approve(self, review, confirmation, *, vault, password):
        review = freeze(review,32768)
        need(type(confirmation) is str and hmac.compare_digest(content_id(review),confirmation),
             'explicit review confirmation differs')
        with self.atomic():
            wallet_id, e, report, decisions, latest_ns = self._load()
            need(len(decisions)<MAX_DECISIONS,'wallet decision capacity reached')
            now = self.clock(); self._fresh(e,now,latest_ns)
            body = review['body']; exact(body, BODY_FIELDS, 'reviewed body')
            op = body['op']
            invoice = invoice_review_context(review,e['state']['genesis'],
                self.policy['genesis_sha256'],now)
            need(op['type']=='transfer','wallet only supports transfers')
            expected = self._transfer_review(e,report,decisions,wallet_id,self.policy_id,
                payer=body['sender'],recipient=op['to'],units=op['units'],
                valid_until=body['valid_until'],grant_id=body['grant_id'],
                invoice_terms=invoice,genesis_sha256=self.policy['genesis_sha256'])
            need(encode(review)==encode(expected),'reviewed wallet state or transfer changed; review again')
            # No password/key access occurs until evidence, reservations and review
            # have all passed within the one writer transaction.
            key = _load_vault(Path(vault),password)
            need(public(key)==review['signer_public_key'],'vault does not control the reviewed role')
            self._fresh(e,self.clock(),now)
            invoice_review_context(review,e['state']['genesis'],self.policy['genesis_sha256'],self.clock())
            packet = sign(key,body)
            ledger = restore(e['state']['genesis'],e['state']['native'])
            try: ledger.apply(packet,height=report['state_height']+1)
            finally: ledger.close()
            signed = self.clock(); self._fresh(e,signed,now)
            invoice_review_context(review,e['state']['genesis'],self.policy['genesis_sha256'],signed)
            decision = {'id':confirmation,'review':review,
                        'wire_hex':canonical(packet).hex(),'signed_ns':signed}
            self.db.execute('INSERT INTO decisions VALUES (?,?,?,?)',
                (len(decisions)+1,confirmation,signed,encode(decision)))
        # A failed return/output after COMMIT must use recover(id), never re-sign.
        return {'status':'signed_and_reserved','decision_id':confirmation,
                'transaction':packet,'broadcast':False}

    def recover(self, decision_id, *, payer, grant_id=''):
        hash_text(decision_id)
        with self.atomic(write=False):
            # Historical audit at retained observation/signing times; explicitly
            # not renewed trust, new approval, current balance or dispatch advice.
            _, _, _, decisions, _ = self._load(historical=True)
            rows = [d for d in decisions if d['id']==decision_id]
            need(len(rows)==1,'signed decision unavailable; no outcome inferred')
            d = rows[0]
            need(d['review']['body']['sender']==payer and d['review']['body']['grant_id']==grant_id,
                 'recovery account or role differs')
            return bytes.fromhex(d['wire_hex'])

    def prepare_rotation(self, *, payer, new_public_key, valid_until):
        with self.atomic(write=False):
            wallet_id,e,r,decisions,latest = self._load()
            self._fresh(e,self.clock(),latest)
            need(len(decisions)<MAX_DECISIONS,'wallet decision capacity reached')
            review = self._rotation_review(e,r,decisions,wallet_id,self.policy_id,payer=payer,
                                     new_public_key=new_public_key,valid_until=valid_until)
            self._fresh(e,self.clock(),latest)
            return {'review':review,'confirmation':content_id(review),'reserved':False,
                    'owner_signed':False,'incoming_consent':False,'broadcast':False}

    def accept_rotation(self, review, confirmation, *, incoming_vault, password):
        review = freeze(review,32768)
        need(type(confirmation) is str and hmac.compare_digest(content_id(review),confirmation),
             'explicit rotation confirmation differs')
        with self.atomic():
            wallet_id,e,r,decisions,latest = self._load()
            now=self.clock(); self._fresh(e,now,latest)
            need(len(decisions)<MAX_DECISIONS,'wallet decision capacity reached')
            body=rotation_review_context(review,accepted=False)
            expected=self._rotation_review(e,r,decisions,wallet_id,self.policy_id,payer=body['sender'],
                new_public_key=body['op']['public_key'],valid_until=body['valid_until'])
            need(encode(review)==encode(expected),'reviewed wallet state or rotation changed; review again')
            key=_load_vault(Path(incoming_vault),password)
            need(public(key)==body['op']['public_key'],'vault does not control incoming key')
            self._fresh(e,self.clock(),now)
            accepted=accept_account_key(key,body)
            result={**review,'body':accepted}
            self._fresh(e,self.clock(),now)
        return {'review':result,'confirmation':content_id(result),'reserved':False,
                'owner_signed':False,'incoming_consent':True,'broadcast':False}

    def approve_rotation(self, review, confirmation, *, owner_vault, password):
        review = freeze(review,32768)
        need(type(confirmation) is str and hmac.compare_digest(content_id(review),confirmation),
             'explicit rotation confirmation differs')
        with self.atomic():
            wallet_id,e,r,decisions,latest=self._load()
            now=self.clock(); self._fresh(e,now,latest)
            need(len(decisions)<MAX_DECISIONS,'wallet decision capacity reached')
            body=rotation_review_context(review,accepted=True)
            expected=self._decision_review(e,r,decisions,wallet_id,self.policy_id,review,
                                     self.policy['genesis_sha256'],now)
            need(encode(review)==encode(expected),'reviewed wallet state or rotation changed; review again')
            key=_load_vault(Path(owner_vault),password)
            need(public(key)==review['signer_public_key'],'vault does not control reviewed owner')
            self._fresh(e,self.clock(),now)
            packet=sign(key,body); ledger=restore(e['state']['genesis'],e['state']['native'])
            try: ledger.apply(packet,height=r['state_height']+1)
            finally: ledger.close()
            signed=self.clock(); self._fresh(e,signed,now)
            decision={'id':confirmation,'review':review,'wire_hex':canonical(packet).hex(),'signed_ns':signed}
            self.db.execute('INSERT INTO decisions VALUES (?,?,?,?)',
                            (len(decisions)+1,confirmation,signed,encode(decision)))
        return {'status':'signed_and_reserved','decision_id':confirmation,'transaction':packet,'broadcast':False}

    def rotation_status(self, decision_id, *, payer, evidence):
        """Fresh extending proof, historical receipt boundary and checkpoint owner.

        Read only. Does not sync evidence, release holds or promise latestness.
        """
        hash_text(decision_id); identifier(payer); incoming=freeze(evidence)
        with self.atomic(write=False):
            _,e,_,decisions,latest=self._load()
            now=self.clock(); self._check_clock(now,latest)
            rows=[d for d in decisions if d['id']==decision_id]
            need(len(rows)==1,'rotation decision unavailable')
            d=rows[0]; body=rotation_review_context(d['review'],accepted=True)
            need(body['sender']==payer,'rotation payer differs')
            r=verify_evidence(incoming,self.genesis,self.policy,now_ns=now)
            self._fresh(incoming,now,latest); extends(e,incoming)
            found=matched_receipt(r,d)
            owner=next(a for a in r['accounts'] if a['id']==payer)
            result={'status':'rotation-unobserved' if found is None else 'rotation-recorded',
                    'checked_at_ns':now,
                    'decision_id':decision_id,'payer':payer,'evidence_id':r['evidence_id'],
                    'state_height':r['state_height'],'checkpoint_public_key':owner['public_key'],
                    'checkpoint_epoch':owner['epoch'],'rotation_receipt_height':None,
                    'receipt_epoch_before':None,'receipt_epoch_after':None,
                    'old_owner_retired_at_checkpoint':False,
                    'replacement_owner_active_at_checkpoint':False,
                    'original_grants_retired_at_checkpoint':False,
                    'physical_device_fenced':False,'latest_state_guaranteed':False,
                    'signing_performed':False,'submission_performed':False,'holds_changed':False}
            if found is not None:
                # Only reverified successful native receipts are replayed, in exact
                # sequence. Failed attempts have no native state effect. Derive
                # receipt-time epoch rather than trusting a caller/cached field.
                ledger=restore(incoming['state']['genesis'])
                try:
                    for row in sorted(r['receipts'],key=lambda x:x['record']['sequence']):
                        record=row['record']
                        target=row['native_txid']==found['native_txid']
                        if target:
                            before=dict(ledger._account(payer))
                            need(before['public_key']==d['review']['signer_public_key'] and
                                 before['epoch']==d['review']['payer_epoch'],
                                 'receipt boundary differs from original rotation authority')
                        ledger.apply(record['envelope'],height=record['height'])
                        if target:
                            after=dict(ledger._account(payer)); break
                finally: ledger.close()
                result.update(rotation_receipt_height=found['height'],
                    receipt_epoch_before=before['epoch'],receipt_epoch_after=after['epoch'],
                    old_owner_retired_at_checkpoint=owner['public_key']!=before['public_key'],
                    replacement_owner_active_at_checkpoint=owner['public_key']==body['op']['public_key'])
                grants={g[0]:g for g in r['grants']}
                result['original_grants_retired_at_checkpoint']=all(
                    g['id'] in grants and (grants[g['id']][3]!=owner['epoch'] or
                    bool(grants[g['id']][9]) or grants[g['id']][7]<r['state_height']+1)
                    for g in d['review']['affected_grants'])
            self._fresh(incoming,self.clock(),now)
            return result
