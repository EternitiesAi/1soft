"""Native invoice approval uses the sole original wallet writer and holds."""
import copy
import hashlib
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path
from block_application import encode
from p4_evidence import content_id
from p4_wallet import P4Wallet
from wallet_fixture import Chain,PASSWORD

class InvoiceWalletTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.chain=Chain(self.root,invoice_commitments=True)
        self.wallet=P4Wallet(self.root/'invoice-wallet.sqlite',self.chain.genesis,
                             self.chain.policy,create=True,clock=self.chain.clock)
        self.wallet.sync(self.chain.evidence(),expected_revision=None)
        self.terms={'schema':1,'format':'1soft/invoice-terms/v1','quote_sha256':'a'*64,
            'genesis_sha256':self.chain.policy['genesis_sha256'],
            'merchant_origin':'http://127.0.0.1:39080',
            'resource_url':'http://127.0.0.1:39080/premium/one','resource_sha256':'c'*64,
            'network':'1soft:local-dev','asset':'1soft:DEV','recipient':self.chain.merchant,
            'amount_units':'7','created_ns':self.chain.now-10**9,'expires_ns':self.chain.now+60*10**9}
    def tearDown(self):
        self.wallet.close();self.chain.close();self.temp.cleanup()
    def prepare(self,grant=''):
        try:
            return self.wallet.prepare(payer=self.chain.payer,recipient=self.chain.merchant,
                units=7,valid_until=20,grant_id=grant,invoice_terms=self.terms)
        except TypeError as exc:self.fail('wallet invoice approval API missing: '+str(exc))
    def approve(self,p,role='owner'):
        return self.wallet.approve(p['review'],p['confirmation'],vault=self.root/(role+'.pem'),password=PASSWORD)

    def test_owner_signature_retains_exact_invoice_commitment(self):
        p=self.prepare();result=self.approve(p)
        op=result['transaction']['body']['op']
        self.assertIn('invoice_commitment',op)
        self.assertEqual(p['review']['invoice_terms'],self.terms)
        self.assertEqual(self.wallet.status()['pending_debit_units'],'9')
        self.assertEqual(self.wallet.recover(result['decision_id'],payer=self.chain.payer),encode(result['transaction']))

    def test_two_agents_share_original_account_and_budget_holds(self):
        self.approve(self.prepare('raven'),'raven')
        self.approve(self.prepare('atlas'),'atlas')
        state=self.wallet.status();self.assertEqual(state['pending_debit_units'],'18')
        self.assertEqual(state['budgets'][0]['pending_debit_units'],'18')
        self.assertEqual(self.wallet.db.execute('SELECT count(*) FROM decisions').fetchone()[0],2)

    def test_expiry_after_unlock_refuses_without_signature_or_hold(self):
        import p4_wallet
        self.terms['expires_ns']=self.chain.now+10**9;p=self.prepare()
        original=p4_wallet._load_vault
        def delayed(*args):
            key=original(*args);self.chain.now+=2*10**9;return key
        with patch('p4_wallet._load_vault',side_effect=delayed),self.assertRaisesRegex(ValueError,'invoice.*open|invoice.*expir'):
            self.approve(p)
        self.assertEqual(self.wallet.db.execute('SELECT count(*) FROM decisions').fetchone()[0],0)
        self.assertEqual(self.wallet.status()['pending_debit_units'],'0')

    def test_native_operation_cannot_substitute_reviewed_commitment(self):
        p=self.prepare();review=copy.deepcopy(p['review']);review['body']['op']['invoice_commitment']='f'*64
        with self.assertRaises(ValueError):
            self.wallet.approve(review,content_id(review),vault=self.root/'owner.pem',password=PASSWORD)
        self.assertEqual(self.wallet.status()['pending_debit_units'],'0')

    def test_expired_quote_cannot_prepare(self):
        self.terms['expires_ns']=self.chain.now
        with self.assertRaisesRegex(ValueError,'invoice.*open|invoice.*expir'):self.prepare()

    def test_recover_after_expiry_keeps_original_wire_and_hold(self):
        p=self.prepare();result=self.approve(p);wire=encode(result['transaction'])
        self.chain.now=self.terms['expires_ns']+1
        self.assertEqual(self.wallet.recover(result['decision_id'],payer=self.chain.payer),wire)
        self.assertEqual(self.wallet.status()['pending_debit_units'],'9')

    def test_plain_owner_transfer_keeps_original_review_format(self):
        p=self.wallet.prepare(payer=self.chain.payer,recipient=self.chain.merchant,units=7,valid_until=20)
        self.assertEqual(p['review']['format'],'1soft/p4-transfer-review/v1')
        self.assertNotIn('invoice_terms',p['review'])
        self.assertNotIn('invoice_commitment',p['review']['body']['op'])

    def test_other_native_asset_cannot_claim_dev_invoice_terms(self):
        other=self.root/'other';other.mkdir(mode=0o700)
        c=Chain(other,invoice_commitments=True,native_asset='OTHER')
        try:
            with P4Wallet(other/'wallet.sqlite',c.genesis,c.policy,create=True,clock=c.clock) as w:
                w.sync(c.evidence(),expected_revision=None)
                value=dict(self.terms,genesis_sha256=c.policy['genesis_sha256'])
                with self.assertRaisesRegex(ValueError,'asset'):
                    w.prepare(payer=c.payer,recipient=c.merchant,units=7,valid_until=20,invoice_terms=value)
                self.assertEqual(w.db.execute('SELECT count(*) FROM decisions').fetchone()[0],0)
        finally:c.close()

if __name__=='__main__':unittest.main()
