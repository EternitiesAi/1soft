"""Durable invoice payer contracts: real native execution, synthetic quorum/clock."""
from contextlib import contextmanager
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from block_application import encode
from commit_verifier import load_json
from alpha_wallet_fixture import AlphaChain, PASSWORD
from invoice_book import initialize_invoice_storage, open_invoice_storage
from payment_x402 import NativePaymentExpectation, make_payment_required
from p4_alpha_platform_service import AlphaPlatformService
import private_payment_desk
from merchant_browser import MerchantBrowserService

class AlphaInvoiceTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(private_payment_desk, 'AlphaPrivatePaymentDesk'),
                        'explicit durable invoice payer adapter is missing')
        self.Desk=private_payment_desk.AlphaPrivatePaymentDesk
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.addCleanup(self.tmp.cleanup)
        self.c=AlphaChain(self.root,invoice_commitments=True);self.addCleanup(self.c.close)
        self.roles={n:dict(payer=self.c.payer,grant_id='' if n=='owner' else n,vault=n+'.pem')
                    for n in ('owner','raven','atlas')}
        self.s=AlphaPlatformService(self.root,self.c.genesis,self.c.policy,'http://127.0.0.1:39099/',
                                   self.roles,create=True,clock=self.c.clock)
        self.addCleanup(self.s.close)
        self.tip=None;self.height=0;self.append();self.s.sync(expected_revision=None)
        self.storage=self.root/'invoice-data'
        initialize_invoice_storage(self.storage,self.c.policy['genesis_sha256'],password=PASSWORD,clock=self.c.clock)
        self.inv=open_invoice_storage(self.storage,self.c.policy['genesis_sha256'],clock=self.c.clock)
        self.addCleanup(self.inv.close)
        self.desk=self.Desk(self.s,self.inv);self.browser=MerchantBrowserService(self.desk)
    def append(self):
        e=self.c.evidence()
        seg=dict(schema=1,format='1soft/protocol4-incremental-segment/v1',parent_checkpoint=self.tip,
                 from_height=self.height,state=e['state'],history=e['history'][self.height:],headers=e['headers'][self.height:])
        saved=self.s.import_checkpoint(seg,expected_tip=self.tip)
        self.tip=saved['checkpoint']['id'];self.height=e['state']['height'];return saved
    def invoice(self, units='7', *, committed=True):
        expected=NativePaymentExpectation('https://merchant.example','https://merchant.example/premium',
            '1soft:local-dev','1soft:DEV',self.c.policy['genesis_sha256'],self.c.merchant,units)
        extra=dict(resource_sha256=hashlib.sha256(b'public resource').hexdigest()) if committed else {}
        header=make_payment_required(expected,created_ns=self.c.now-1,expires_ns=self.c.now+600*10**9,
                                    quote_nonce=hashlib.sha256(str(len(self.inv.entries())).encode()).hexdigest(),**extra)
        rid=self.desk.import_invoice(header,expected,dict(description='private invoice',contact='private@example.invalid',
            content='ALPHA_PRIVATE_INVOICE_SENTINEL'),invoice_password=PASSWORD)['request_id']
        return rid
    def sign(self,rid,role='raven'):
        p=self.browser.prepare(rid,role,valid_until=self.height+30)
        result=self.browser.approve_invoice(rid,role,p['review'],p['confirmation'],p['terms'],p['terms_confirmation'],password=PASSWORD)
        return p,result,self.browser.recover(rid)
    def counts(self):
        return tuple(self.s.wallet.db.execute('SELECT count(*) FROM decisions').fetchone())+tuple(
            self.s.delivery.db.execute('SELECT count(*) FROM attempts').fetchone())
    def test_committed_invoice_above512_keeps_shared_hold_and_original_receipt(self):
        while self.height<514:
            for _ in range(32):self.c.block([])
            self.append()
        self.s.sync(expected_revision=self.s.state()['wallet']['revision'])
        rid=self.invoice('58');p,signed,wire=self.sign(rid)
        self.assertGreater(p['review']['state_height'],512)
        self.assertEqual(p['review']['body']['op']['invoice_commitment'],p['terms']['invoice_commitment'])
        self.assertEqual(self.s.state()['wallet']['pending_debit_units'],'60')
        self.c.block([wire]);self.append()
        self.s.delivery.import_receipt(signed['decision_id'],self.tip,payer=self.c.payer,grant_id='raven')
        capsule=self.browser.retain_receipt(rid)['capsule_id'];packet=self.browser.capsule(rid,capsule)
        self.assertEqual(self.s.state()['wallet']['pending_debit_units'],'60')
        self.browser.reconcile(rid,expected_revision=self.s.state()['wallet']['revision'])
        self.assertEqual(self.s.state()['wallet']['pending_debit_units'],'0')
        self.assertEqual(self.browser.recover(rid),wire)
        from p4_alpha_custody import verify_receipt
        with patch('p4_alpha_custody.time.time_ns',self.c.clock):
            checked=verify_receipt(packet,self.c.genesis,self.c.policy,payer=self.c.payer,wire_sha256=hashlib.sha256(wire).hexdigest())
        self.assertFalse(checked['current_spending_authority'])
        self.assertNotIn(b'ALPHA_PRIVATE_INVOICE_SENTINEL',encode(self.browser.state()))
    def test_continuously_admitted_invoice_signing_survives_original_hour(self):
        from p4_evidence import nanos
        self.c.time_step_seconds=240
        for _ in range(10):
            self.c.block([]);self.append()
            self.s.sync(expected_revision=self.s.state()['wallet']['revision'])
        self.assertGreater(self.c.now,nanos(self.c.policy['anchor_time'])+3600*10**9)
        rid=self.invoice();_,_,wire=self.sign(rid)
        self.assertTrue(wire)
        self.assertTrue(self.browser.submission_review(rid)['confirmation'])

    def test_tampered_consent_refuses_before_unlock_and_plain_quote_refuses(self):
        rid=self.invoice();p=self.browser.prepare(rid,'raven',valid_until=30)
        bad=dict(p['terms'],resource_url='https://merchant.example/other')
        with patch('p4_wallet._load_vault',side_effect=AssertionError('unauthorized unlock')):
            with self.assertRaises(ValueError):self.browser.approve_invoice(rid,'raven',p['review'],p['confirmation'],bad,
                hashlib.sha256(encode(bad)).hexdigest(),password=PASSWORD)
        self.assertEqual(self.counts(),(0,0))
        with self.assertRaises(ValueError):self.invoice(committed=False)
        self.assertEqual(len(self.inv.entries()),1)
    def test_alpha_payment_header_cannot_enter_legacy_merchant_authority(self):
        rid=self.invoice();self.sign(rid)
        with self.assertRaises(ValueError):self.desk.payment_header(rid,'0'*64)
        self.assertEqual(self.counts(),(1,0))
    def test_quote_expiry_at_decision_insert_rolls_back_signature_and_hold(self):
        rid=self.invoice();p=self.browser.prepare(rid,'raven',valid_until=30)
        expiry=p['review']['invoice_terms']['expires_ns']
        def expire():self.c.now=expiry;return 0
        self.s.wallet.db.create_function('expire_quote',0,expire)
        self.s.wallet.db.execute('CREATE TEMP TRIGGER expire_after_sign AFTER INSERT ON decisions BEGIN SELECT expire_quote(); END')
        with self.assertRaises(ValueError):self.browser.approve_invoice(rid,'raven',p['review'],p['confirmation'],
            p['terms'],p['terms_confirmation'],password=PASSWORD)
        self.assertEqual(self.counts(),(0,0));self.assertEqual(self.s.state()['wallet']['pending_debit_units'],'0')
    def test_quote_expiry_at_attempt_insert_rolls_back_claim_without_dispatch(self):
        rid=self.invoice();p,_,_=self.sign(rid);q=self.browser.submission_review(rid)
        expiry=p['review']['invoice_terms']['expires_ns']
        def expire():self.c.now=expiry;return 0
        self.s.delivery.db.create_function('expire_quote',0,expire)
        self.s.delivery.db.execute('CREATE TEMP TRIGGER expire_after_claim AFTER INSERT ON attempts BEGIN SELECT expire_quote(); END')
        with patch('p4_delivery.submit_once',side_effect=AssertionError('must not dispatch')):
            with self.assertRaises(ValueError):self.browser.submit(rid,q['review'],q['confirmation'])
        self.assertEqual(self.counts(),(1,0));self.assertEqual(self.s.state()['wallet']['pending_debit_units'],'9')
        self.assertTrue(self.browser.recover(rid))
    def test_expired_original_remains_readable_without_new_authority(self):
        rid=self.invoice();p,_,wire=self.sign(rid)
        self.c.now=p['review']['invoice_terms']['expires_ns']
        self.assertEqual(self.browser.recover(rid),wire)
        self.assertFalse(self.browser.state()['requests'][0]['request_open'])
        with self.assertRaises(ValueError):self.browser.submission_review(rid)
        self.assertEqual(self.counts(),(1,0))

if __name__=='__main__':unittest.main()
