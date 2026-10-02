"""Committed invoices over real native execution and synthetic header fixtures."""
import base64
import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from block_application import encode
from native_core import canonical
from p4_evidence import content_id
from p4_receipt_capsule import make_capsule,encode_capsule,verify_capsule
from wallet_fixture import Chain,PASSWORD
from invoice_book import initialize_invoice_storage,open_invoice_storage
from merchant_book import MerchantBook
from platform_service import PlatformService
from private_payment_desk import PrivatePaymentDesk
from payment_x402 import (NativePaymentExpectation,TrustedMerchantAssignment,
    make_payment_required,parse_payment_required,make_payment_signature,verify_merchant_payment)

class CommittedInvoiceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.addCleanup(self.temp.cleanup)
        self.chain=Chain(self.root,invoice_commitments=True);self.addCleanup(self.chain.close)
        self.workspace=self.root/'payer';self.workspace.mkdir(mode=0o700)
        for name in ('owner','raven','atlas'):
            shutil.copyfile(self.root/(name+'.pem'),self.workspace/(name+'.pem'))
            (self.workspace/(name+'.pem')).chmod(0o600)
        c=self.chain
        roles={name:dict(payer=c.payer,grant_id='' if name=='owner' else name,vault=name+'.pem')
               for name in ('owner','raven','atlas')}
        self.service=PlatformService(self.workspace,c.genesis,c.policy,'http://127.0.0.1:39099/',roles,
                                     create=True,clock=c.clock);self.addCleanup(self.service.close)
        self.proof=c.evidence();self.service.import_checkpoint(self.proof,expected_tip=None)
        self.service.sync(expected_revision=None)
        self.storage=self.root/'invoices'
        initialize_invoice_storage(self.storage,c.policy['genesis_sha256'],password=PASSWORD,clock=c.clock)
        self.invoices=open_invoice_storage(self.storage,c.policy['genesis_sha256'],clock=c.clock)
        self.addCleanup(self.invoices.close)
        self.desk=PrivatePaymentDesk(self.service,self.invoices)
        self.merchant=MerchantBook(self.root/'merchant.sqlite',c.genesis,c.policy,create=True,clock=c.clock)
        self.addCleanup(self.merchant.close)
        self.resource=b'public premium report\n'
        self.expected=NativePaymentExpectation('https://merchant.example','https://merchant.example/report',
            '1soft:local-dev','1soft:DEV',c.policy['genesis_sha256'],c.merchant,'7')
        self.header=self.offer(self.expected,self.resource)

    def offer(self,e,resource,nonce='a'*64):
        try:return make_payment_required(e,created_ns=self.chain.now-10**9,
            expires_ns=self.chain.now+60*10**9,quote_nonce=nonce,
            resource_sha256=hashlib.sha256(resource).hexdigest())
        except TypeError as exc:self.fail('committed resource quote API missing: '+str(exc))

    def imported(self):
        return self.desk.import_invoice(self.header,self.expected,{'description':'private brief','contact':'client@example.invalid','content':'private content'},
                                        invoice_password=PASSWORD)['request_id']

    def signed(self):
        rid=self.imported();p=self.desk.prepare(rid,'raven',valid_until=20)
        self.desk.approve(rid,'raven',p['review'],p['confirmation'],p['terms_confirmation'],payment_password=PASSWORD)
        return rid,p,self.desk.recover(rid)

    def capsule(self,wire):
        result=self.chain.block([wire]);self.assertEqual(result['tx_results'][0]['code'],0)
        c=self.chain
        raw=encode_capsule(make_capsule(c.evidence(),c.genesis,c.policy,wire,payer=c.payer,now_ns=c.now))
        proof=verify_capsule(raw,c.genesis,c.policy,now_ns=c.now,expected_payer=c.payer,
                             expected_wire_sha256=hashlib.sha256(wire).hexdigest())
        self.assertEqual(proof['amount_units'],'7')
        return raw

    def test_private_desk_approval_binds_resource_digest_in_original_signature(self):
        rid,p,wire=self.signed();packet=json.loads(wire)
        self.assertIn('invoice_commitment',packet['body']['op'])
        self.assertEqual(p['review']['invoice_terms']['resource_sha256'],hashlib.sha256(self.resource).hexdigest())
        self.assertEqual(p['terms']['resource_sha256'],hashlib.sha256(self.resource).hexdigest())
        self.assertEqual(self.service.state()['wallet']['pending_debit_units'],'9')

    def test_wrong_resource_bytes_refuse_quote_retention(self):
        with self.assertRaisesRegex(ValueError,'resource'):
            self.merchant.add_quote(self.header,self.expected,resource=b'changed resource')
        self.assertEqual(self.merchant.entries(),[])

    def test_original_committed_payment_enrolls_and_fulfills(self):
        qid=self.merchant.add_quote(self.header,self.expected,resource=self.resource)['quote_sha256']
        rid,p,wire=self.signed();self.merchant.enroll_wire(qid,self.chain.payer,wire,evidence=self.proof)
        capsule=self.capsule(wire)
        header=make_payment_signature(required_header=self.header,expectation=self.expected,
            exact_wire=wire,capsule=capsule,payer=self.chain.payer,now_ns=self.chain.now)
        result=self.merchant.fulfill(qid,header,capsule)
        self.assertEqual(result['resource'],self.resource)
        self.assertTrue(result['native_execution_reverified'])
        self.assertEqual(self.service.state()['wallet']['pending_debit_units'],'9')

    def test_genuine_same_amount_recipient_proof_cannot_pay_other_terms(self):
        rid,p,wire=self.signed();capsule=self.capsule(wire)
        signature=make_payment_signature(required_header=self.header,expectation=self.expected,
            exact_wire=wire,capsule=capsule,payer=self.chain.payer,now_ns=self.chain.now)
        e2=replace(self.expected,resource_url='https://merchant.example/other')
        required2=self.offer(e2,b'different resource',nonce='b'*64)
        q2=parse_payment_required(required2,e2,now_ns=self.chain.now)
        forged=json.loads(base64.b64decode(signature));forged['resource']=q2['offer']['resource']
        forged['accepted']=q2['offer']['accepts'][0]
        forged['payload'].update(quoteSha256=q2['quote_sha256'],requestId=q2['request_id'])
        forged_header=base64.b64encode(encode(forged)).decode('ascii')
        assignment=TrustedMerchantAssignment(q2['quote_sha256'],q2['request_id'],e2.recipient,
                                             self.chain.payer,hashlib.sha256(wire).hexdigest())
        with self.assertRaisesRegex(ValueError,'commitment'):
            verify_merchant_payment(signature_header=forged_header,required_header=required2,
                expectation=e2,assignment=assignment,exact_wire=wire,capsule=capsule,
                genesis_bytes=self.chain.genesis,policy=self.chain.policy,payer=self.chain.payer,
                now_ns=self.chain.now)

    def test_plain_native_payment_cannot_enroll_for_committed_invoice(self):
        qid=self.merchant.add_quote(self.header,self.expected,resource=self.resource)['quote_sha256']
        wire=self.chain.owner_wire({'type':'transfer','to':self.chain.merchant,'units':7})
        with self.assertRaisesRegex(ValueError,'commitment'):
            self.merchant.enroll_wire(qid,self.chain.payer,wire,evidence=self.proof)
        self.assertIsNone(self.merchant.selected(qid)['enrollment'])

    def test_substituted_full_review_cannot_override_retained_invoice(self):
        rid=self.imported();p=self.desk.prepare(rid,'raven',valid_until=20)
        bad=copy.deepcopy(p['review']);bad['invoice_terms']['resource_sha256']='f'*64
        from invoice_terms import terms_commitment
        bad['body']['op']['invoice_commitment']=terms_commitment(bad['invoice_terms'])
        with self.assertRaises(ValueError):
            self.desk.approve(rid,'raven',bad,content_id(bad),p['terms_confirmation'],payment_password=PASSWORD)
        self.assertEqual(self.service.wallet.db.execute('SELECT count(*) FROM decisions').fetchone()[0],0)
        self.assertEqual(self.service.state()['wallet']['pending_debit_units'],'0')

    def test_operator_quotes_resource_digest_from_authenticated_native_capability(self):
        from unittest.mock import patch
        import merchant_ops
        from test_merchant_ops import SyntheticNetworkContext
        root=self.root/'operator';root.mkdir(mode=0o700)
        c=self.chain;case=dict(now_ns=c.now,policy=c.policy,genesis=c.genesis,merchant=c.merchant,payer=c.payer)
        network=SyntheticNetworkContext(root,case)
        with patch.object(merchant_ops,'MerchantNetwork',SyntheticNetworkContext):
            ops=merchant_ops.MerchantOps(network);ops.init_book()
            qid=ops.add_quote(recipient_index=0,merchant_origin='http://127.0.0.1:18947',
                resource_path='/premium',amount_units='7',resource=self.resource,expires_ns=c.now+60*10**9)['quote_sha256']
            with ops.book() as book:row=book.selected(qid)
        quote=parse_payment_required(row['required_header'],row['expectation'],now_ns=c.now)
        self.assertEqual(quote['offer']['accepts'][0]['extra']['format'],'1soft/x402-native-offer/v2')
        self.assertEqual(quote['invoice_terms']['resource_sha256'],hashlib.sha256(self.resource).hexdigest())

    def test_retained_enrollment_commitment_mismatch_refuses_inspection(self):
        qid=self.merchant.add_quote(self.header,self.expected,resource=self.resource)['quote_sha256']
        rid,p,wire=self.signed();self.merchant.enroll_wire(qid,self.chain.payer,wire,evidence=self.proof)
        changed=json.loads(wire);changed['body']['op']['invoice_commitment']='0'*64
        changed=canonical(changed)
        self.merchant.db.execute('UPDATE enrollments SET wire=?,wire_sha256=? WHERE quote_id=?',
            (changed,hashlib.sha256(changed).hexdigest(),qid))
        with self.assertRaisesRegex(ValueError,'commitment'):self.merchant.entries()
        self.assertEqual(self.merchant.db.execute('SELECT count(*) FROM fulfillments').fetchone()[0],0)

    def test_retained_public_proof_replay_detects_changed_report_commitment(self):
        from dataclasses import asdict
        from native_invoice_qualification import public_artifacts_match
        rid,p,wire=self.signed();capsule=self.capsule(wire);c=self.chain
        signature=make_payment_signature(required_header=self.header,expectation=self.expected,
            exact_wire=wire,capsule=capsule,payer=c.payer,now_ns=c.now)
        quote=parse_payment_required(self.header,self.expected,now_ns=c.now)
        root=self.root/'proof';root.mkdir(mode=0o700)
        (root/'engine-genesis.json').write_bytes(c.genesis);(root/'policy.json').write_bytes(encode(c.policy))
        artifact=encode(dict(schema=1,required_header=self.header,expectation=asdict(self.expected),
            invoice_terms=quote['invoice_terms'],public_resource=base64.b64encode(self.resource).decode(),
            resource_sha256=hashlib.sha256(self.resource).hexdigest(),payment_signature_header=signature,historical_verification_ns=c.now))
        (root/'public-invoice-raven.json').write_bytes(artifact)
        (root/'wire-raven.json').write_bytes(wire);(root/'capsule-raven.json').write_bytes(capsule)
        packet=json.loads(wire)
        verified=verify_capsule(capsule,c.genesis,c.policy,now_ns=c.now,expected_payer=c.payer,
                              expected_wire_sha256=hashlib.sha256(wire).hexdigest())
        payment=dict(role='raven',recipient=c.merchant,units='7',fee='2',quote_sha256=quote['quote_sha256'],
            request_id=quote['request_id'],wire_sha256=hashlib.sha256(wire).hexdigest(),
            capsule_sha256=hashlib.sha256(capsule).hexdigest(),native_txid=verified['binding']['native_txid'],
            invoice_commitment=packet['body']['op']['invoice_commitment'],resource_sha256=hashlib.sha256(self.resource).hexdigest(),
            invoice_artifact_sha256=hashlib.sha256(artifact).hexdigest())
        other=replace(self.expected,resource_url='https://merchant.example/other')
        required=self.offer(other,b'other bytes',nonce='b'*64)
        q2=parse_payment_required(required,other,now_ns=c.now)
        wrong=json.loads(base64.b64decode(signature));wrong.update(resource=q2['offer']['resource'],accepted=q2['offer']['accepts'][0])
        wrong['payload'].update(quoteSha256=q2['quote_sha256'],requestId=q2['request_id'])
        negative=encode(dict(schema=1,original_role='raven',required_header=required,expectation=asdict(other),
            payment_signature_header=base64.b64encode(encode(wrong)).decode(),original_wire_sha256=payment['wire_sha256'],
            original_capsule_sha256=payment['capsule_sha256'],historical_verification_ns=c.now,refused_for_commitment=True))
        (root/'wrong-invoice-proof.json').write_bytes(negative)
        report=dict(payments=[payment],wrong_invoice_proof_sha256=hashlib.sha256(negative).hexdigest())
        self.assertTrue(public_artifacts_match(report,root))
        for key in ('invoice_commitment','resource_sha256','native_txid','invoice_artifact_sha256'):
            bad=copy.deepcopy(report);bad['payments'][0][key]='0'*64
            self.assertFalse(public_artifacts_match(bad,root),key)
        (root/'public-invoice-raven.json').write_bytes(artifact+b' ')
        self.assertFalse(public_artifacts_match(report,root))

if __name__=='__main__':unittest.main()
