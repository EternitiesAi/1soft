"""Job-level retry/crash tests. HTTP is real; committee certificates are fixtures."""
import copy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization as ser
from native_core import canonical, public, sign
from commit_verifier import encode, sha, verify_packet, pinned_genesis
from offline_signer import review_intent, approve_intent
from payment_jobs import PaymentJobs
from payment_transport import DispatchJournal
from transport_fixture import fixture, packet, NOW_NS, DEADLINE
from test_receipt_collection import rpc_fixture

ROOT = Path(__file__).resolve().parents[1]


class PaymentJobTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.owner, self.merchant, self.native, engine, _, _, self.raw = fixture()
        self.body = json.loads(self.raw)['body']; self.genesis = encode(engine)
        self.digest = sha(self.genesis).hex(); self.now = NOW_NS
        self.url = 'http://127.0.0.1:27657/'; self.jobs = None
    def tearDown(self):
        if self.jobs: self.jobs.close()
        self.tmp.cleanup()
    def open(self, url=None):
        if self.jobs: self.jobs.close(); self.jobs = None
        self.url = url or self.url
        self.jobs = PaymentJobs(self.root/'jobs.sqlite', self.genesis, self.digest, self.url,
                                DEADLINE, clock=lambda: self.now)
        return self.jobs
    def prepare(self, job='atlas:order-149', body=None):
        return self.jobs.prepare(job, self.body if body is None else body, public(self.owner))
    def test_preparation_is_durable_before_signing_and_no_network(self):
        self.open()
        with patch('offline_signer._load_vault', side_effect=AssertionError('must not unlock')), \
             patch('payment_transport._worker', side_effect=AssertionError('must not send')):
            status = self.prepare()
            db = sqlite3.connect(self.root/'jobs.sqlite')
            self.assertEqual(db.execute('SELECT count(*) FROM payment_jobs').fetchone()[0], 1); db.close()
            self.assertEqual(status['status'], 'awaiting_signature')
            self.assertEqual(self.jobs.signing_request(status['job_id'])['body'], self.body)
            self.assertFalse(status['current_authority_verified'])
    def test_identical_job_prepare_reuses_same_record(self):
        self.open(); a = self.prepare(); b = self.prepare()
        self.assertEqual(a, b); self.assertEqual(len(self.jobs.events(a['job_id'])), 1)
    def test_changed_intention_under_same_job_is_rejected(self):
        self.open(); self.prepare()
        for field, value in [('nonce', 1), ('valid_until', 2000), ('max_fee', 3), ('grant_id', 'different')]:
            body = copy.deepcopy(self.body); body[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'different intention'):
                self.prepare(body=body)
        for field, value in [('units', 21), ('to', 'other-recipient')]:
            body = copy.deepcopy(self.body); body['op'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'different intention'):
                self.prepare(body=body)
        with self.assertRaisesRegex(ValueError, 'different intention'):
            self.jobs.prepare('atlas:order-149', self.body, public(self.merchant))
    def test_one_payment_cannot_be_used_for_two_job_ids(self):
        self.open(); self.prepare()
        with self.assertRaisesRegex(ValueError, 'another job already owns'):
            self.prepare('atlas:order-150')
    def test_unsigned_jobs_cannot_conflict_on_same_authority_nonce(self):
        self.open(); self.prepare(); changed = copy.deepcopy(self.body); changed['op']['units'] = 21
        with self.assertRaisesRegex(ValueError, 'another job already owns'):
            self.prepare('atlas:order-150', changed)
    def test_genuinely_separate_job_can_use_different_nonce(self):
        self.open(); self.prepare(); changed = copy.deepcopy(self.body); changed['nonce'] = 1
        self.assertEqual(self.prepare('atlas:order-150', changed)['status'], 'awaiting_signature')
    def test_existing_dispatch_cannot_be_relabelled_as_fresh_job(self):
        with DispatchJournal(self.root/'jobs.sqlite', self.genesis, self.digest, self.url, DEADLINE,
                             clock=lambda: self.now) as d:
            d.queue(self.raw, public(self.owner))
        self.open()
        with self.assertRaisesRegex(ValueError, 'relabelled'):
            self.prepare()
    def test_only_transfers_and_strict_identifiers_are_allowed(self):
        self.open()
        body = copy.deepcopy(self.body); body['op'] = {'type':'fence'}
        with self.assertRaisesRegex(ValueError, 'native transfers'): self.prepare(body=body)
        for job in ('', '../invoice', 'pay\nagain', '订单', 'a'*129):
            with self.subTest(job=job), self.assertRaises(ValueError): self.prepare(job)
    def test_prepare_does_not_mutate_body(self):
        self.open(); before = copy.deepcopy(self.body); self.prepare()
        self.assertEqual(self.body, before)
    def test_attach_records_exact_signature_without_unlock_or_send(self):
        self.open(); row = self.prepare()
        with patch('offline_signer._load_vault', side_effect=AssertionError('no unlock')), \
             patch('payment_transport._worker', side_effect=AssertionError('no send')):
            status = self.jobs.attach(row['job_id'], self.raw)
        self.assertEqual(status['status'], 'queued'); self.assertFalse(status['signature_required'])
        self.assertEqual(self.jobs.export(row['job_id']), self.raw)
    def test_attach_is_idempotent(self):
        self.open(); row = self.prepare()
        first = self.jobs.attach(row['job_id'], self.raw)
        self.assertEqual(first, self.jobs.attach(row['job_id'], self.raw))
        self.assertEqual([x['event'] for x in self.jobs.events(row['job_id'])].count('queued'), 1)
    def test_wrong_body_or_wrong_signature_cannot_attach(self):
        self.open(); row = self.prepare(); changed = copy.deepcopy(self.body); changed['nonce'] = 1
        for raw in (canonical(sign(self.owner, changed)), canonical(sign(self.merchant, self.body)), self.raw+b'\n'):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                self.jobs.attach(row['job_id'], raw)
        self.assertEqual(self.jobs.status(row['job_id'])['status'], 'awaiting_signature')
    def test_queued_job_refuses_new_signing_request(self):
        self.open(); row = self.prepare(); self.jobs.attach(row['job_id'], self.raw)
        with self.assertRaisesRegex(ValueError, 'already has a signature'):
            self.jobs.signing_request(row['job_id'])
    def test_send_or_refresh_requires_attached_signature(self):
        self.open(); row = self.prepare()
        with patch('payment_transport._worker', side_effect=AssertionError('no send')):
            with self.assertRaises(ValueError): self.jobs.send(row['job_id'], row['request_commitment'])
            with self.assertRaises(ValueError): self.jobs.refresh(row['job_id'])
            with self.assertRaises(ValueError): self.jobs.export(row['job_id'])
    def test_request_commitment_is_not_dispatch_confirmation(self):
        self.open(); row = self.prepare(); self.jobs.attach(row['job_id'], self.raw)
        with patch('payment_transport._worker', side_effect=AssertionError('no send')):
            with self.assertRaisesRegex(ValueError, 'dispatch confirmation'):
                self.jobs.send(row['job_id'], row['request_commitment'])
    def test_same_job_cannot_pay_again_after_receipt_and_nonce_advance(self):
        with rpc_fixture(mode='wait_for_actual_payment', ledger_path=self.root/'ledger.sqlite') as (url, seen):
            self.open(url); row = self.prepare(); attached = self.jobs.attach(row['job_id'], self.raw)
            sent = self.jobs.send(row['job_id'], attached['dispatch_confirmation'])
            self.assertEqual(sent['status'], 'unresolved')
            closed = self.jobs.refresh(row['job_id']); self.assertTrue(closed['receipt_verified'])
            changed = copy.deepcopy(self.body); changed['nonce'] = 1
            with self.assertRaisesRegex(ValueError, 'different intention'):
                self.prepare(body=changed)
            self.assertEqual(self.prepare()['status'], 'receipt_verified')
            self.assertEqual(sum(x['method']=='broadcast_tx_sync' for x in seen), 1)
            for replay in (False, True):
                with self.assertRaisesRegex(ValueError, 'must not be dispatched again'):
                    self.jobs.send(row['job_id'], attached['dispatch_confirmation'], replay=replay)
    def test_refresh_recovery_after_restart_does_not_resend(self):
        with rpc_fixture(mode='wait_for_actual_payment', ledger_path=self.root/'ledger.sqlite') as (url, seen):
            self.open(url); row = self.prepare(); attached = self.jobs.attach(row['job_id'], self.raw)
            self.jobs.send(row['job_id'], attached['dispatch_confirmation'])
            self.open(); self.assertEqual(self.jobs.status(row['job_id'])['status'], 'unresolved')
            self.assertTrue(self.jobs.refresh(row['job_id'])['receipt_verified'])
            self.assertEqual(sum(x['method']=='broadcast_tx_sync' for x in seen), 1)
    def test_prepared_job_survives_abrupt_process_exit(self):
        (self.root/'genesis.json').write_bytes(self.genesis); (self.root/'body.json').write_bytes(canonical(self.body))
        code = '''from pathlib import Path
import json,os,sys
from payment_jobs import PaymentJobs
with PaymentJobs(Path(sys.argv[1]),Path(sys.argv[2]).read_bytes(),sys.argv[3],sys.argv[4],sys.argv[5],clock=lambda:int(sys.argv[7])) as j:
 j.prepare('atlas:order-149',json.loads(Path(sys.argv[6]).read_bytes()),sys.argv[8])
 os._exit(71)
'''
        result = subprocess.run([sys.executable, '-c', code, str(self.root/'jobs.sqlite'), str(self.root/'genesis.json'),
            self.digest, self.url, DEADLINE, str(self.root/'body.json'), str(self.now), public(self.owner)],
            env=dict(os.environ,PYTHONPATH=str(ROOT/'src')),capture_output=True,timeout=8)
        self.assertEqual(result.returncode,71,result.stderr); self.open()
        self.assertEqual(self.prepare()['status'], 'awaiting_signature')
        self.assertEqual(len(self.jobs.events('atlas:order-149')),1)
    def test_crash_after_queue_commit_recovers_without_new_signature(self):
        self.open(); row = self.prepare(); self.jobs.close(); self.jobs = None
        (self.root/'genesis.json').write_bytes(self.genesis); (self.root/'signed.json').write_bytes(self.raw)
        code = '''from pathlib import Path
import os,sys
from payment_jobs import PaymentJobs
with PaymentJobs(Path(sys.argv[1]),Path(sys.argv[2]).read_bytes(),sys.argv[3],sys.argv[4],sys.argv[5],clock=lambda:int(sys.argv[7])) as j:
 original=j._dispatch.queue
 def crash(*a,**k):
  original(*a,**k)
  os._exit(72)
 j._dispatch.queue=crash
 j.attach('atlas:order-149',Path(sys.argv[6]).read_bytes())
'''
        result=subprocess.run([sys.executable,'-c',code,str(self.root/'jobs.sqlite'),str(self.root/'genesis.json'),
            self.digest,self.url,DEADLINE,str(self.root/'signed.json'),str(self.now)],
            env=dict(os.environ,PYTHONPATH=str(ROOT/'src')),capture_output=True,timeout=8)
        self.assertEqual(result.returncode,72,result.stderr); self.open()
        self.assertEqual(self.jobs.status(row['job_id'])['status'],'queued')
        self.assertEqual(self.jobs.export(row['job_id']),self.raw)
        with self.assertRaises(ValueError): self.jobs.signing_request(row['job_id'])
    def test_second_workspace_process_is_excluded(self):
        self.open(); self.prepare()
        with self.assertRaises(BlockingIOError):
            PaymentJobs(self.root/'jobs.sqlite',self.genesis,self.digest,self.url,DEADLINE,clock=lambda:self.now)
    def test_reopen_does_not_rewrite_legacy_payments(self):
        self.open(); row=self.prepare(); self.jobs.attach(row['job_id'],self.raw)
        before=self.jobs._dispatch.db.execute('SELECT * FROM payments').fetchall()
        self.open(); after=self.jobs._dispatch.db.execute('SELECT * FROM payments').fetchall()
        self.assertEqual([tuple(r) for r in before],[tuple(r) for r in after])
    def test_job_binding_corruption_is_rejected(self):
        self.open(); row=self.prepare()
        self.jobs._dispatch.db.execute("UPDATE payment_jobs SET commitment=?",('0'*64,))
        with self.assertRaisesRegex(ValueError,'integrity'): self.jobs.status(row['job_id'])
    def test_job_cannot_claim_another_signers_queued_envelope(self):
        self.open(); row=self.prepare()
        self.jobs._dispatch.queue(canonical(sign(self.merchant,self.body)), public(self.merchant))
        with self.assertRaisesRegex(ValueError,'does not belong'): self.jobs.status(row['job_id'])
    def test_verified_status_still_rechecks_the_proof(self):
        with rpc_fixture() as (url, _):
            self.open(url); row=self.prepare(); self.jobs.attach(row['job_id'],self.raw)
            self.jobs.refresh(row['job_id'])
            self.jobs._dispatch.db.execute('UPDATE payments SET proof=?',(b'{}',))
            with self.assertRaises(ValueError): self.jobs.status(row['job_id'])
    def test_receipt_export_is_independently_verifiable(self):
        with rpc_fixture() as (url, seen):
            self.open(url); row=self.prepare(); self.jobs.attach(row['job_id'],self.raw)
            self.jobs.refresh(row['job_id']); count=len(seen)
            verified=verify_packet(json.loads(self.jobs.export_receipt(row['job_id'])),pinned_genesis(self.genesis,self.digest),
                expected_txids=[row['native_txid']])
            self.assertEqual(verified['status'],'verified');self.assertEqual(len(seen),count)
    def test_expired_policy_stops_attach_and_send_but_preserves_export(self):
        self.open(); row=self.prepare(); self.jobs.attach(row['job_id'],self.raw);self.now+=2*86400*10**9
        with self.assertRaises(ValueError): self.jobs.send(row['job_id'],self.jobs.status(row['job_id'])['dispatch_confirmation'])
        self.assertEqual(self.jobs.export(row['job_id']),self.raw)
    def test_unknown_schema_is_not_silently_migrated(self):
        self.open();self.prepare();self.jobs._dispatch.db.execute('UPDATE payment_jobs_schema SET version=2')
        self.jobs.close();self.jobs=None
        with self.assertRaisesRegex(ValueError,'unsupported payment-job schema'):self.open()
    def test_one_thousand_job_limit_is_fail_closed(self):
        self.open()
        with patch('payment_jobs.MAX_INTENTIONS',1):
            self.prepare();body=copy.deepcopy(self.body);body['nonce']=1
            with self.assertRaisesRegex(ValueError,'limit reached'):self.prepare('another',body)


class JobCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.owner,_,self.native,engine,_,_,self.raw=fixture()
        self.genesis=encode(engine);self.digest=sha(self.genesis).hex();self.body=json.loads(self.raw)['body']
        (self.root/'genesis.json').write_bytes(self.genesis);(self.root/'body.json').write_bytes(canonical(self.body))
        (self.root/'signed.json').write_bytes(self.raw+b'\n')
    def tearDown(self):self.tmp.cleanup()
    def call(self,*args,url='http://127.0.0.1:27657/'):
        return subprocess.run([sys.executable,str(ROOT/'scripts/jobs.py'),'--genesis',str(self.root/'genesis.json'),
            '--genesis-sha256',self.digest,'--journal',str(self.root/'jobs.sqlite'),'--endpoint',url,
            '--trust-expires-utc','2030-01-01T00:00:00Z',*args],capture_output=True,text=True,timeout=10)
    def prepare(self,url='http://127.0.0.1:27657/'):
        p=self.call('prepare','--job-id','render:149','--body',str(self.root/'body.json'),
            '--signer-public-key',public(self.owner),url=url)
        self.assertEqual(p.returncode,0,p.stderr);return json.loads(p.stdout)
    def test_cli_prepare_request_attach_status_across_processes(self):
        row=self.prepare();target=self.root/'request.json'
        p=self.call('signing-request','--job-id',row['job_id'],'--output',str(target))
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(target.read_bytes()),self.body)
        p=self.call('attach','--job-id',row['job_id'],'--envelope',str(self.root/'signed.json'))
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout)['status'],'queued')
        p=self.call('status','--job-id',row['job_id'])
        self.assertFalse(json.loads(p.stdout)['signature_required'])
    def test_cli_request_does_not_overwrite(self):
        row=self.prepare();target=self.root/'request.json';target.write_bytes(b'preserve')
        p=self.call('signing-request','--job-id',row['job_id'],'--output',str(target))
        self.assertEqual(p.returncode,2);self.assertEqual(target.read_bytes(),b'preserve')
    def test_cli_changed_body_for_same_job_fails(self):
        self.prepare();body=copy.deepcopy(self.body);body['nonce']=1;(self.root/'body.json').write_bytes(canonical(body))
        p=self.call('prepare','--job-id','render:149','--body',str(self.root/'body.json'),'--signer-public-key',public(self.owner))
        self.assertEqual(p.returncode,2);self.assertIn('different intention',p.stderr)
    def test_complete_job_vault_signature_lost_reply_refresh_export(self):
        # Fresh encrypted test file contains a PUBLIC FIXTURE seed, never real funds.
        password=b'public-fixture-password-not-a-secret'
        vault=self.root/'fixture.pem'
        vault.write_bytes(self.owner.private_bytes(ser.Encoding.PEM,ser.PrivateFormat.PKCS8,ser.BestAvailableEncryption(password)))
        vault.chmod(0o600)
        with rpc_fixture(mode='wait_for_actual_payment',ledger_path=self.root/'merchant.sqlite') as (url,seen):
            row=self.prepare(url)
            view=review_intent(self.native,self.body,public(self.owner))
            envelope=approve_intent(vault,password,self.native,self.body,public(self.owner),view['confirmation'])
            (self.root/'signed.json').write_bytes(canonical(envelope)+b'\n')
            p=self.call('attach','--job-id',row['job_id'],'--envelope',str(self.root/'signed.json'),url=url)
            self.assertEqual(p.returncode,0,p.stderr);attached=json.loads(p.stdout)
            p=self.call('send','--job-id',row['job_id'],'--confirm',attached['dispatch_confirmation'],url=url)
            self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout)['status'],'unresolved')
            p=self.call('refresh','--job-id',row['job_id'],url=url)
            self.assertEqual(p.returncode,0,p.stderr);self.assertTrue(json.loads(p.stdout)['receipt_verified'])
            target=self.root/'receipt.json';p=self.call('export-proof','--job-id',row['job_id'],'--output',str(target),url=url)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertEqual(verify_packet(json.loads(target.read_bytes()),pinned_genesis(self.genesis,self.digest),
                expected_txids=[row['native_txid']])['status'],'verified')
            self.assertEqual(sum(r['method']=='broadcast_tx_sync' for r in seen),1)
            self.assertNotIn(password.decode(),p.stdout+p.stderr)
    def test_cli_unknown_job_fails_without_key_or_network(self):
        p=self.call('status','--job-id','missing');self.assertEqual(p.returncode,2)
    def test_cli_events_preserve_job_creation_before_signature(self):
        row=self.prepare();p=self.call('events','--job-id',row['job_id'])
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['events'][0]['event'],'job_prepared_before_signing')


if __name__ == '__main__':unittest.main()
