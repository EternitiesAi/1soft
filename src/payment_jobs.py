"""Stable payment-job identities over the existing local native dispatcher.

A job is an immutable local request, not a new asset, signed invoice, on-chain
idempotency key or authority grant. The adapter never signs or unlocks. Existing
wallets supply a canonical envelope; its body and signer must match the job.
One job has one native intention for its entire lifetime, including after receipt
verification. All participating agents must share this trusted local workspace.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import time

from native_core import DOMAIN, canonical, identifier, require
from offline_signer import review_intent
from payment_transport import DispatchJournal, MAX_INTENTIONS

JOB_DOMAIN = b'1soft/payment-job/v1\x00'


class PaymentJobs:
    """Crash-recoverable job/signature handoff without a second accounting store.

    Uses the dispatcher's same SQLite transaction store and exclusive process
    lock. Preparation persists before any external signing. Attaching the exact
    signature delegates to the already-atomic queue; status is derived from that
    queue, so there is no second 'signed' flag to race or lose. No database move,
    signature import from arbitrary files, or automatic dispatch is performed.
    """
    def __init__(self, path: Path, genesis_bytes: bytes, genesis_sha256: str,
                 endpoint: str, trust_expires_utc: str, *, clock=time.time_ns):
        self._dispatch = DispatchJournal(path, genesis_bytes, genesis_sha256,
                                        endpoint, trust_expires_utc, clock=clock)
        try:
            with self._dispatch._atomic():
                self._dispatch.db.execute('''CREATE TABLE IF NOT EXISTS payment_jobs (
                    job_id TEXT PRIMARY KEY, body TEXT NOT NULL, signer TEXT NOT NULL,
                    txid TEXT UNIQUE NOT NULL, slot TEXT UNIQUE NOT NULL,
                    commitment TEXT NOT NULL)''')
                self._dispatch.db.execute('''CREATE TABLE IF NOT EXISTS payment_jobs_schema (
                    id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL)''')
                row = self._dispatch.db.execute('SELECT version FROM payment_jobs_schema WHERE id=1').fetchone()
                if row is None:
                    require(not self._dispatch.db.execute('SELECT 1 FROM payment_jobs').fetchone(),
                            'unversioned payment jobs are not accepted')
                    self._dispatch.db.execute('INSERT INTO payment_jobs_schema VALUES (1,1)')
                else:
                    require(type(row[0]) is int and row[0] == 1, 'unsupported payment-job schema')
        except BaseException:
            self.close()
            raise

    def close(self):
        self._dispatch.close()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    def _binding(self, job_id: str, body: dict, signer: str) -> dict:
        identifier(job_id)
        review = review_intent(self._dispatch.genesis, body, signer)
        body = review['body']
        require(body['op']['type'] == 'transfer', 'payment jobs support native transfers only')
        body_bytes = canonical(body)
        txid = hashlib.sha256(DOMAIN + body_bytes).hexdigest()
        slot = hashlib.sha256(canonical([self._dispatch.trust.native_genesis_hash,
            body['sender'], body['grant_id'], body['nonce']])).hexdigest()
        binding = {'schema': 1, 'job_id': job_id, 'body': body,
                   'signer_public_key': signer, 'dispatch_policy': self._dispatch.config}
        # The review envelope is larger than a native body. Use the already
        # validated canonical body, not the transaction serializer's size budget.
        encoded = json.dumps(binding, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
        return {'body': body_bytes.decode('ascii'), 'signer': signer, 'txid': txid,
                'slot': slot, 'commitment': hashlib.sha256(JOB_DOMAIN + encoded).hexdigest()}

    def _job(self, job_id: str):
        identifier(job_id)
        row = self._dispatch.db.execute('SELECT * FROM payment_jobs WHERE job_id=?', (job_id,)).fetchone()
        require(row is not None, 'unknown payment job')
        body = json.loads(row['body'])
        binding = self._binding(job_id, body, row['signer'])
        require(all(row[k] == v for k, v in binding.items()), 'stored payment job failed integrity check')
        return row

    def _payment(self, job):
        row = self._dispatch.db.execute('SELECT * FROM payments WHERE txid=?', (job['txid'],)).fetchone()
        if row is not None:
            # Also validate signatures/proof through the dispatcher's existing
            # read path; an untrusted state label alone can never close a job.
            status = self._dispatch.status(job['txid'])
            envelope = json.loads(self._dispatch.export(job['txid']))
            require(row['signer'] == job['signer'] and
                    canonical(envelope['body']).decode() == job['body'],
                    'queued signature does not belong to the prepared job')
            return status
        return None

    def prepare(self, job_id: str, body: dict, signer_public_key: str) -> dict:
        """Persist one exact intention before signing; identical retries reuse it.

        A changed nonce, amount, recipient, fee cap, expiry or signer under the
        same job is a conflict, even after the original receipt was verified.
        Another job cannot claim the same transaction or initial nonce slot.
        """
        binding = self._binding(job_id, body, signer_public_key)
        with self._dispatch._atomic():
            self._dispatch._time()
            old = self._dispatch.db.execute('SELECT 1 FROM payment_jobs WHERE job_id=?', (job_id,)).fetchone()
            if old:
                current = self._job(job_id)
                require(all(current[k] == v for k, v in binding.items()),
                        'job already exists with a different intention; resume the original job')
            else:
                require(self._dispatch.db.execute('SELECT count(*) FROM payment_jobs').fetchone()[0] < MAX_INTENTIONS,
                        'development payment-job limit reached')
                require(not self._dispatch.db.execute('SELECT 1 FROM payment_jobs WHERE txid=? OR slot=?',
                        (binding['txid'], binding['slot'])).fetchone(),
                        'another job already owns this transaction or authority nonce')
                require(not self._dispatch.db.execute('SELECT 1 FROM payments WHERE txid=? OR slot=?',
                        (binding['txid'], binding['slot'])).fetchone(),
                        'an existing queued payment cannot be relabelled as a new job')
                self._dispatch.db.execute('INSERT INTO payment_jobs VALUES (?,?,?,?,?,?)',
                    (job_id, binding['body'], binding['signer'], binding['txid'], binding['slot'], binding['commitment']))
                self._dispatch._event(binding['txid'], 'job_prepared_before_signing',
                    {'job_id': job_id, 'request_commitment': binding['commitment']})
        return self.status(job_id)

    def status(self, job_id: str) -> dict:
        job = self._job(job_id)
        payment = self._payment(job)
        body = json.loads(job['body'])
        result = {'schema': 1, 'job_id': job_id, 'request_commitment': job['commitment'],
            'native_txid': job['txid'], 'network': body['chain_id'], 'asset': self._dispatch.genesis['asset'],
            'account': body['sender'], 'recipient': body['op']['to'], 'amount_atomic': body['op']['units'],
            'fee_atomic': self._dispatch.genesis['fee'], 'grant_id': body['grant_id'],
            'signer_public_key': job['signer'], 'status': 'awaiting_signature', 'attempts': 0,
            'signature_required': payment is None, 'receipt_verified': False,
            'scope': 'same-workspace payment-job continuity, not on-chain idempotency',
            'current_authority_verified': False, 'live_network_provenance_established': False}
        if payment:
            result.update({k: payment[k] for k in ('status', 'attempts', 'receipt_verified',
                           'dispatch_confirmation', 'wire_sha256')})
        return result

    def signing_request(self, job_id: str) -> dict:
        job = self._job(job_id)
        require(self._payment(job) is None, 'job already has a signature; export or resume it instead')
        return {'job_id': job_id, 'body': json.loads(job['body']),
                'signer_public_key': job['signer'], 'request_commitment': job['commitment'],
                'authority_verified': False, 'network_contacted': False}

    def attach(self, job_id: str, raw: bytes) -> dict:
        """Queue the matching public signature atomically; never request a key."""
        job = self._job(job_id)
        item = self._dispatch._intention(raw, job['signer'])
        require(item['txid'] == job['txid'] and item['slot'] == job['slot'] and
                canonical(json.loads(raw)['body']).decode() == job['body'],
                'signed envelope differs from the prepared payment job')
        self._dispatch.queue(raw, job['signer'])
        # No follow-up database mutation: a crash here is recovered by status().
        return self.status(job_id)

    def send(self, job_id: str, confirmation: str, *, replay: bool = False) -> dict:
        job = self._job(job_id)
        require(self._payment(job) is not None, 'attach the approved signature before dispatch')
        self._dispatch.dispatch(job['txid'], confirmation, replay=replay)
        return self.status(job_id)

    def refresh(self, job_id: str, *, read_attempts: int = 1) -> dict:
        job = self._job(job_id)
        require(self._payment(job) is not None, 'no signed payment to reconcile')
        result = self._dispatch.refresh_receipt(job['txid'], read_attempts=read_attempts)
        return {**self.status(job_id), 'collection_status': result['collection_status'],
                'read_requests': result['read_requests']}

    def export(self, job_id: str) -> bytes:
        job = self._job(job_id)
        require(self._payment(job) is not None, 'job has no signed envelope')
        return self._dispatch.export(job['txid'])

    def export_receipt(self, job_id: str) -> bytes:
        job = self._job(job_id)
        require(self._payment(job) is not None, 'job has no signed envelope')
        return self._dispatch.export_receipt(job['txid'])

    def events(self, job_id: str) -> list[dict]:
        job = self._job(job_id)
        self._payment(job)
        return [{'id': r['id'], 'event': r['event'], 'detail': json.loads(r['detail'])}
                for r in self._dispatch.db.execute('SELECT * FROM events WHERE txid=? ORDER BY id', (job['txid'],))]
