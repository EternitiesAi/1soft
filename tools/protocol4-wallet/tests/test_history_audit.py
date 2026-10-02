"""Real-wallet regressions for operation-scoped proof reuse and its boundaries."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from block_application import encode
from validator_witness import nanos
import p4_wallet
from wallet_fixture import Chain, PASSWORD


class HistoryAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
        self.c=Chain(self.root); self.e=self.c.evidence(); self.raw=encode(self.e)
    def tearDown(self): self.c.close(); self.tmp.cleanup()

    def test_two_original_times_replay_one_proof_per_status_and_preserve_holds(self):
        w=p4_wallet.P4Wallet(self.root/'wallet.sqlite',self.c.genesis,self.c.policy,
                            clock=self.c.clock,create=True)
        try:
            w.sync(self.e,expected_revision=None); ids=[]; wires=[]
            for role in ('raven','atlas'):
                self.c.now+=1
                q=w.prepare(payer=self.c.payer,recipient=self.c.merchant,units=1,
                            valid_until=30,grant_id=role)
                s=w.approve(q['review'],q['confirmation'],vault=self.root/(role+'.pem'),password=PASSWORD)
                ids.append(s['decision_id']); wires.append(encode(s['transaction']))
            self.c.now+=1; before=(self.root/'wallet.sqlite').read_bytes()
            calls=[]; real=p4_wallet.verify_evidence
            def counted(*a,**kw):
                calls.append(kw['now_ns']); return real(*a,**kw)
            with patch('p4_wallet.verify_evidence',side_effect=counted):
                first=w.status(); second=w.status()
            self.assertEqual(first,second); self.assertEqual(first['pending_debit_units'],'6')
            self.assertEqual(len(calls),2,'each separate status must fully verify once')
            for role, identity, wire in zip(('raven','atlas'),ids,wires):
                self.assertEqual(w.recover(identity,payer=self.c.payer,grant_id=role),wire)
            self.assertEqual((self.root/'wallet.sqlite').read_bytes(),before)
        finally:w.close()

    def audit(self,policy=None,genesis=None):
        return p4_wallet._EvidenceAudit(genesis or self.c.genesis,policy or self.c.policy)

    def test_later_validation_never_authorizes_an_earlier_future_header(self):
        # Keep the earlier request inside anchor trust but below the tip's bound.
        for _ in range(5):self.c.block()
        proof=self.c.evidence(); raw=encode(proof)
        a=self.audit(); tip=nanos(proof['headers'][-1]['signed_header']['header']['time'])
        a.verify(raw,now_ns=self.c.now)
        with self.assertRaisesRegex(ValueError,'future'):
            a.verify(raw,now_ns=tip-5*10**9-1)
        _,r=a.verify(raw,now_ns=tip-5*10**9)
        self.assertEqual(r['checked_at_ns'],tip-5*10**9)

    def test_fixed_expiry_and_bad_time_types_are_rechecked(self):
        a=self.audit(); a.verify(self.raw,now_ns=self.c.now)
        expiry=nanos(self.c.policy['anchor_time'])+3600*10**9
        for stamp in (expiry,True,False,float(self.c.now),-1):
            with self.subTest(stamp=stamp),self.assertRaises(ValueError):a.verify(self.raw,now_ns=stamp)
        _,r=a.verify(self.raw,now_ns=expiry-1)
        self.assertEqual(r['trust_expires_ns'],expiry)
        self.assertEqual(r['checked_at_ns'],expiry-1)

    def test_returned_nested_objects_cannot_change_retained_authority(self):
        a=self.audit(); e,r=a.verify(self.raw,now_ns=self.c.now)
        e['state']['native']['accounts'][0][4]=999999
        r['accounts'][0]['public_key']='0'*64; r['receipts'].clear()
        e2,r2=a.verify(self.raw,now_ns=self.c.now+7)
        self.assertEqual(encode(e2),self.raw)
        self.assertNotEqual(r2['accounts'][0]['public_key'],'0'*64)
        self.assertEqual(len(r2['receipts']),3)
        self.assertEqual(r2['checked_at_ns'],self.c.now+7)

    def test_policy_is_frozen_and_other_genesis_cannot_reuse_verification(self):
        p=copy.deepcopy(self.c.policy); a=self.audit(policy=p)
        a.verify(self.raw,now_ns=self.c.now); p['trust_period_seconds']=7200
        with self.assertRaises(ValueError):
            a.verify(self.raw,now_ns=nanos(p['anchor_time'])+3600*10**9)
        with self.assertRaises(ValueError):self.audit(genesis=self.c.genesis+b' ').verify(self.raw,now_ns=self.c.now)

    def test_changed_signature_or_noncanonical_bytes_are_not_hits(self):
        a=self.audit(); a.verify(self.raw,now_ns=self.c.now)
        broken=copy.deepcopy(self.e)
        broken['headers'][-1]['signed_header']['commit']['signatures'][0]['signature']='A'*88
        for raw in (encode(broken),self.raw+b' ',b'{}',b''):
            with self.subTest(digest=hashlib.sha256(raw).hexdigest()),self.assertRaises(ValueError):
                a.verify(raw,now_ns=self.c.now)
        self.assertEqual(encode(a.verify(self.raw,now_ns=self.c.now)[0]),self.raw)

    def test_successful_replacement_keeps_only_one_proof_and_new_audit_reverifies(self):
        newer=encode(self.c.evidence()); real=p4_wallet.verify_evidence; calls=[]
        def counted(*a,**kw):calls.append(kw['now_ns']);return real(*a,**kw)
        with patch('p4_wallet.verify_evidence',side_effect=counted):
            a=self.audit()
            for raw in (self.raw,self.raw,newer,self.raw):a.verify(raw,now_ns=self.c.now)
            self.audit().verify(self.raw,now_ns=self.c.now)
        self.assertEqual(len(calls),4)

    def test_same_header_different_valid_commit_bytes_require_full_verification(self):
        other=copy.deepcopy(self.e)
        other['headers'][-1]['signed_header']['commit']['signatures'][-1]={
            'block_id_flag':1,'validator_address':'','timestamp':'0001-01-01T00:00:00Z','signature':None}
        real=p4_wallet.verify_evidence; calls=[]
        def counted(*a,**kw):calls.append(1);return real(*a,**kw)
        with patch('p4_wallet.verify_evidence',side_effect=counted):
            a=self.audit(); _,r=a.verify(self.raw,now_ns=self.c.now)
            _,s=a.verify(encode(other),now_ns=self.c.now)
        self.assertEqual(r['header_hash'],s['header_hash'])
        self.assertNotEqual(r['evidence_id'],s['evidence_id'])
        self.assertEqual(len(calls),2)

    def test_mutable_genesis_input_is_copied_before_any_verification(self):
        genesis=bytearray(self.c.genesis); a=self.audit(genesis=genesis)
        genesis[-1]^=1
        _,r=a.verify(self.raw,now_ns=self.c.now)
        self.assertEqual(r['genesis_sha256'],hashlib.sha256(self.c.genesis).hexdigest())

    def test_failed_signature_checks_are_never_cached(self):
        broken=copy.deepcopy(self.e)
        broken['headers'][-1]['signed_header']['commit']['signatures'][0]['signature']='A'*88
        raw=encode(broken); real=p4_wallet.verify_evidence; calls=[]
        def counted(*a,**kw):calls.append(1);return real(*a,**kw)
        with patch('p4_wallet.verify_evidence',side_effect=counted):
            a=self.audit()
            for _ in range(2):
                with self.assertRaises(ValueError):a.verify(raw,now_ns=self.c.now)
        self.assertEqual(len(calls),2)


if __name__=='__main__':unittest.main()
