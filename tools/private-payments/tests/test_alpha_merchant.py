"""Alpha merchant contracts: actual native execution, synthetic quorum/clock."""
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch
import test_alpha_invoices as invoice_fixture
from alpha_wallet_fixture import PASSWORD
from payment_x402 import NativePaymentExpectation, make_payment_required
from merchant_alpha import AlphaMerchantBook, make_signature, verify_proof

class AlphaMerchantTests(unittest.TestCase):
    setUp = invoice_fixture.AlphaInvoiceTests.setUp
    append = invoice_fixture.AlphaInvoiceTests.append
    sign = invoice_fixture.AlphaInvoiceTests.sign
    counts = invoice_fixture.AlphaInvoiceTests.counts
    def merchant(self):
        return AlphaMerchantBook(self.root/'merchant-alpha.sqlite',self.c.genesis,self.c.policy,clock=self.c.clock)
    def invoice(self,units='7',path='/premium'):
        e=NativePaymentExpectation('https://merchant.example','https://merchant.example'+path,
            '1soft:local-dev','1soft:DEV',self.c.policy['genesis_sha256'],self.c.merchant,units)
        resource=('public '+path).encode()
        h=make_payment_required(e,created_ns=self.c.now-1,expires_ns=self.c.now+600*10**9,
            quote_nonce=hashlib.sha256(path.encode()).hexdigest(),resource_sha256=hashlib.sha256(resource).hexdigest())
        if not (self.root/'merchant-alpha.sqlite').exists():
            with AlphaMerchantBook(self.root/'merchant-alpha.sqlite',self.c.genesis,self.c.policy,clock=self.c.clock,create=True):pass
        with self.merchant() as m:q=m.add_quote(h,e,resource=resource)
        rid=self.desk.import_invoice(h,e,dict(description='private',contact='',content='INVOICE_PRIVATE'),invoice_password=PASSWORD)['request_id']
        return rid,q['quote_sha256'],e,h,resource
    def paid(self,role='raven',path='/premium'):
        self.s.sync(expected_revision=self.s.state()['wallet']['revision'])
        rid,q,e,h,resource=self.invoice(path=path);p,s,wire=self.sign(rid,role)
        self.c.block([wire]);self.append()
        self.s.delivery.import_receipt(s['decision_id'],self.tip,payer=self.c.payer,grant_id='' if role=='owner' else role)
        cid=self.browser.retain_receipt(rid)['capsule_id'];raw=self.browser.capsule(rid,cid)
        with patch('p4_alpha_custody.time.time_ns',self.c.clock):
            header=self.desk.payment_header(rid,cid)['payment_signature_header']
        return rid,q,e,h,resource,wire,raw,header
    def enroll(self,m,q,wire,raw):
        return m.enroll_wire(q,self.c.payer,wire,evidence=raw)
    def test_paid_resource_restart_expiry_and_public_proof(self):
        rid,q,e,h,resource,wire,raw,header=self.paid()
        before=self.counts();hold=self.s.state()['wallet']['pending_debit_units']
        with patch('p4_alpha_custody.time.time_ns',self.c.clock),self.merchant() as m:
            self.enroll(m,q,wire,raw);first=m.fulfill(q,header,raw);proof=m.export_proof(q)
            assignment=m.assignment(q)
        self.assertEqual(first['resource'],resource)
        self.c.now+=700*10**9
        with patch('p4_alpha_custody.time.time_ns',self.c.clock),self.merchant() as m:
            again=m.fulfill(q,header,raw)
            self.assertEqual(again['fulfilled_ns'],first['fulfilled_ns'])
            self.assertEqual(again['status'],'original_local_fulfillment_retained')
            self.assertEqual(m.db.execute('SELECT count(*) FROM payments WHERE fulfilled_ns IS NOT NULL').fetchone()[0],1)
            report=verify_proof(proof,genesis_bytes=self.c.genesis,policy=self.c.policy,expectation=e,assignment=assignment,now_ns=first['fulfilled_ns'])
        self.assertTrue(report['native_signature_authenticates_resource']);self.assertFalse(report['merchant_consumption_proven'])
        self.assertEqual(self.counts(),before);self.assertEqual(self.s.state()['wallet']['pending_debit_units'],hold)
    def test_shared_recipient_distinct_committed_resources_and_cross_payment_refusal(self):
        a=self.paid('owner','/a');b=self.paid('raven','/b')
        with patch('p4_alpha_custody.time.time_ns',self.c.clock),self.merchant() as m:
            for row in (a,b):self.enroll(m,row[1],row[5],row[6]);self.assertEqual(m.fulfill(row[1],row[7],row[6])['resource'],row[4])
            with self.assertRaises(ValueError):m.fulfill(b[1],a[7],a[6])
            with self.assertRaises(ValueError):m.enroll_wire(b[1],self.c.payer,a[5],evidence=a[6])
            self.assertEqual(len(m.entries()),2)
    def test_unpaid_or_tampered_proof_never_enrolls_or_consumes(self):
        rid,q,e,h,resource=self.invoice();_,_,wire=self.sign(rid)
        with self.merchant() as m:
            with self.assertRaises(ValueError):m.enroll_wire(q,self.c.payer,wire,evidence=b'{}')
            with self.assertRaises(ValueError):m.fulfill(q,'bad',b'{}')
            self.assertEqual(m.db.execute('SELECT count(*) FROM payments').fetchone()[0],0)
    def test_expiry_at_fulfillment_insert_rolls_back_consumption(self):
        row=self.paid();rid,q,e,h,resource,wire,raw,header=row
        with patch('p4_alpha_custody.time.time_ns',self.c.clock),self.merchant() as m:
            self.enroll(m,q,wire,raw)
            expiry=m.selected(q)['expires_ns']
            def expire():self.c.now=expiry;return 0
            m.db.create_function('expire_quote',0,expire)
            m.db.execute('CREATE TEMP TRIGGER expire_after_fulfillment AFTER UPDATE OF fulfilled_ns ON payments BEGIN SELECT expire_quote(); END')
            with self.assertRaises(ValueError):m.fulfill(q,header,raw)
            self.assertIsNone(m.selected(q)['fulfillment'])
    def test_original_horizon_blocks_new_consumption_but_keeps_historical_result(self):
        row=self.paid();rid,q,e,h,resource,wire,raw,header=row
        with patch('p4_alpha_custody.time.time_ns',self.c.clock),self.merchant() as m:
            self.enroll(m,q,wire,raw);first=m.fulfill(q,header,raw)
        self.c.now=self.c.policy['absolute_not_after_ns']
        with patch('p4_alpha_custody.time.time_ns',self.c.clock),self.merchant() as m:
            self.assertEqual(m.fulfill(q,header,raw)['resource'],resource)
            self.assertTrue(m.export_proof(q))
            with self.assertRaises(ValueError):m.add_quote(h,e,resource=resource)
    def test_replay_crossing_quote_expiry_refuses_before_consumption(self):
        import merchant_alpha
        row=self.paid();rid,q,e,h,resource,wire,raw,header=row
        with patch('p4_alpha_custody.time.time_ns',self.c.clock),self.merchant() as m:
            self.enroll(m,q,wire,raw);expiry=m.selected(q)['expires_ns'];original=merchant_alpha.verify_receipt
            def delayed(*a,**kw):
                result=original(*a,**kw);self.c.now=expiry;return result
            with patch('merchant_alpha.verify_receipt',side_effect=delayed):
                with self.assertRaises(ValueError):m.fulfill(q,header,raw)
            self.assertIsNone(m.selected(q)['fulfillment'])
    def test_live_quote_after_original_hour_uses_historical_receipt_without_new_authority(self):
        from p4_evidence import nanos
        self.c.time_step_seconds=240
        for _ in range(10):self.c.block([]);self.append();self.s.sync(expected_revision=self.s.state()['wallet']['revision'])
        self.assertGreater(self.c.now,nanos(self.c.policy['anchor_time'])+3600*10**9)
        row=self.paid();rid,q,e,h,resource,wire,raw,header=row
        with patch('p4_alpha_custody.time.time_ns',self.c.clock),self.merchant() as m:
            self.enroll(m,q,wire,raw);self.assertEqual(m.fulfill(q,header,raw)['resource'],resource)
    def test_public_proof_resource_assignment_profile_and_asof_mismatches_refuse(self):
        from dataclasses import replace
        from block_application import encode
        from commit_verifier import load_json
        from merchant_proof import verify_merchant_proof
        import base64
        row=self.paid();rid,q,e,h,resource,wire,raw,header=row
        with patch('p4_alpha_custody.time.time_ns',self.c.clock),self.merchant() as m:
            self.enroll(m,q,wire,raw);first=m.fulfill(q,header,raw);proof=m.export_proof(q);a=m.assignment(q)
            pins=dict(genesis_bytes=self.c.genesis,policy=self.c.policy,expectation=e,assignment=a,now_ns=first['fulfilled_ns'])
            bad=load_json(proof);bad['resource_b64']=base64.b64encode(b'wrong resource').decode()
            with self.assertRaises(ValueError):verify_proof(encode(bad),**pins)
            with self.assertRaises(ValueError):verify_proof(proof,**dict(pins,assignment=replace(a,wire_sha256='0'*64)))
            with self.assertRaises(ValueError):verify_merchant_proof(proof,**pins)
            with self.assertRaises(ValueError):verify_proof(proof,**dict(pins,now_ns=self.c.now-100*10**9))
            with self.assertRaises(ValueError):m.fulfill(q,header+'A',raw)
            self.assertEqual(m.fulfill(q,header,raw)['fulfilled_ns'],first['fulfilled_ns'])
    def test_existing_sidecars_preserved_without_creating_database(self):
        for suffix in ('-wal','-shm','-journal'):
            p=self.root/('new-'+suffix+'.sqlite');side=Path(str(p)+suffix);side.write_bytes(b'original remnant');side.chmod(0o600)
            with self.assertRaises(ValueError):AlphaMerchantBook(p,self.c.genesis,self.c.policy,clock=self.c.clock,create=True)
            self.assertFalse(p.exists());self.assertEqual(side.read_bytes(),b'original remnant')
    def test_clock_regression_after_catalog_rolls_back_consumption(self):
        row=self.paid();rid,q,e,h,resource,wire,raw,header=row
        with patch('p4_alpha_custody.time.time_ns',self.c.clock),self.merchant() as m:
            self.enroll(m,q,wire,raw);original=m._catalog;calls=0
            def regressing(now):
                nonlocal calls
                result=original(now);calls+=1
                if calls==2:self.c.now-=1
                return result
            with patch.object(m,'_catalog',side_effect=regressing):
                with self.assertRaises(ValueError):m.fulfill(q,header,raw)
            self.c.now+=1
            self.assertIsNone(m.selected(q)['fulfillment'])
    def test_quota_refusal_preserves_original_rows(self):
        rid,q,e,h,resource=self.invoice()
        with self.merchant() as m,patch('merchant_alpha.MAX_STORED_BYTES',1):
            with self.assertRaises(ValueError):m.selected(q)
        with self.merchant() as m:self.assertEqual(len(m.entries()),1)
    def test_clock_regression_and_independent_pin_mismatch_refused(self):
        rid,q,e,h,resource=self.invoice();self.c.now-=1
        with self.assertRaises(ValueError):self.merchant()
        bad=dict(self.c.policy,anchor_hash='0'*64)
        with self.assertRaises(ValueError):AlphaMerchantBook(self.root/'merchant-alpha.sqlite',self.c.genesis,bad,clock=self.c.clock)

if __name__=='__main__':unittest.main()
