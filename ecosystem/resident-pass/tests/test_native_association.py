"""Optional integration: real local native application, synthetic committee only.

Run via tools/verify.py --native-root PATH_TO_COMPLETE_V013. No live Resident or
private biography is used, and no existing node/database is modified.
"""
import base64,copy,hashlib,tempfile,unittest
from pathlib import Path
from fixtures import *
from resident_pass.protocol import canonical,digest,Refused
from resident_pass.verifier import Verifier
from resident_pass.native_bridge import association_for,sign_association,accept_association
from block_application import BlockApplication
from native_core import NativeLedger,address,sign,accept_account_key,Reject
from certificate_fixture import validators,make_header,make_commit

class AssociationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.now=NOW
        self.owner=key(71);self.recipient=key(72);self.account=address(public(self.owner))
        self.genesis={'protocol_version':3,'state_commitment':'smt-v1','chain_id':'resident-pass-dev',
                      'asset':'DEV','fee':2,'allocations':[{'public_key':public(self.owner),'units':1000},
                      {'public_key':public(self.recipient),'units':0}]}
        self.app=BlockApplication(self.root/'app.sqlite',expected_genesis=self.genesis)
        self.app.init_chain(self.genesis['chain_id'],self.genesis)
        self.engine,self.trust,self.validators=validators(self.genesis)
        self.v=Verifier(self.root/'verifier.sqlite',[RULE],AUDIENCE,NOW+3600,clock=lambda:self.now)
        self.card=card();self.v.install_status(status([self.card]))
    def tearDown(self):self.app.close();self.v.close();self.tmp.cleanup()
    def snapshot(self):
        w=self.app.compact_witness([('accounts',self.account)])
        header=make_header(self.trust,self.app.height+1,self.app.app_hash,[])
        header['time']='2026-09-24T12:00:00Z';header['version']['app']='3'
        if self.app.height:header['last_block_id']={'hash':'12'*32,'parts':{'total':1,'hash':'13'*32}}
        return w,make_commit(header,self.trust,self.validators)
    def proposal(self,w=None,h=None,holder=HOLDER,wallet=None):
        w,h=self.snapshot() if w is None else (w,h)
        a=association_for(self.card,w,h,self.trust,self.account)
        ch=self.v.begin(self.card,purpose='link-native-account',context_digest=digest(a))
        p=present(holder,ch);s=sign_association(wallet or self.owner,a,ch)
        return a,ch,p,s,w,h
    def accept(self,x):
        a,ch,p,s,w,h=x
        return accept_association(self.v,self.card,p,a,s,w,h,self.trust)
    def block(self,raws):
        h=self.app.height+1;r=self.app.finalize_block(raws,h,hashlib.sha256(str(h).encode()).digest());self.app.commit();return r
    def test_two_separate_keys_and_proof_link_without_native_mutation(self):
        before=self.app.app_hash;r=self.accept(self.proposal())
        self.assertEqual(before,self.app.app_hash);self.assertFalse(r['native_mutation_performed'])
        self.assertFalse(r['financial_authority_created']);self.assertTrue(r['wallet_key_at_snapshot_verified'])
        self.assertFalse(r['latest_native_state_guaranteed'])
    def test_identity_key_alone_cannot_spend_native_money(self):
        self.accept(self.proposal());db=NativeLedger(':memory:',self.genesis)
        try:
            body=db.body(self.account,0,{'type':'transfer','to':address(public(self.recipient)),'units':10})
            with self.assertRaises(Reject):db.apply(sign(HOLDER,body),height=1)
            self.assertEqual(db.balance(self.account),1000)
        finally:db.close()
    def test_issuer_key_cannot_spend_native_money(self):
        db=NativeLedger(':memory:',self.genesis)
        try:
            body=db.body(self.account,0,{'type':'transfer','to':address(public(self.recipient)),'units':10})
            with self.assertRaises(Reject):db.apply(sign(ISSUER,body),height=1)
        finally:db.close()
    def test_forged_financial_signature_rejected(self):
        x=list(self.proposal());x[3]='0'*128
        with self.assertRaises(Refused):self.accept(x)
    def test_forged_identity_signature_rejected(self):
        x=list(self.proposal());x[2]['signature']='0'*128
        with self.assertRaises(Refused):self.accept(x)
    def test_changed_wallet_association_rejected(self):
        x=list(self.proposal());x[0]['wallet_epoch']=123
        with self.assertRaises(Refused):self.accept(x)
    def test_bad_account_merkle_proof_rejected(self):
        x=list(self.proposal());x[4]['entries'][0]['value'][4]+=100
        with self.assertRaises(ValueError):self.accept(x)
    def test_forged_committee_signature_rejected(self):
        x=list(self.proposal());x[5]['commit']['signatures'][0]['signature']=base64.b64encode(bytes(64)).decode()
        with self.assertRaises(ValueError):self.accept(x)
    def test_same_key_for_identity_and_money_refused(self):
        self.card=card(holder=self.owner,epoch=1,credential='card-002');self.v.install_status(status([self.card],sequence=2))
        with self.assertRaises(Refused):self.proposal(holder=self.owner)
    def test_replay_of_association_rejected(self):
        x=self.proposal();self.accept(x)
        with self.assertRaises(Refused):self.accept(x)
    def test_stale_native_proof_does_not_link(self):
        x=self.proposal();self.now+=121;self.v.install_status(status([self.card],sequence=2,now=self.now))
        with self.assertRaises(Refused):self.accept(x)
    def test_identity_revocation_prevents_link_not_financial_account(self):
        x=self.proposal();self.v.install_status(status([self.card],sequence=2,revoked=('card-001',)))
        with self.assertRaises(Refused):self.accept(x)
        db=NativeLedger(':memory:',self.genesis)
        try:
            b=db.body(self.account,0,{'type':'transfer','to':address(public(self.recipient)),'units':10})
            r=self.block([canonical(sign(self.owner,b))]);self.assertEqual(r['tx_results'][0]['code'],0)
        finally:db.close()
    def test_native_rotation_old_key_fails_new_snapshot(self):
        replacement=key(73);db=NativeLedger(':memory:',self.genesis)
        try:
            b=db.body(self.account,0,{'type':'rotate_key','public_key':public(replacement),'acceptance':''})
            raw=canonical(sign(self.owner,accept_account_key(replacement,b)));self.block([raw])
            with self.assertRaises(Refused):self.proposal()
            r=self.accept(self.proposal(wallet=replacement));self.assertEqual(r['native_account_association']['account_id'],self.account)
            self.assertEqual(r['native_account_association']['wallet_epoch'],1)
        finally:db.close()
    def test_observed_native_checkpoint_cannot_roll_back(self):
        old=self.snapshot();self.block([]);self.accept(self.proposal())
        with self.assertRaises(Refused):self.accept(self.proposal(*old))
    def test_identity_rotation_preserves_alias_without_native_key_rotation(self):
        old_alias=self.card['body']['subject_id'];before=self.app.app_hash
        old=self.card;self.card=card(holder=OTHER,epoch=1,credential='card-002')
        self.v.install_status(status([old,self.card],sequence=2,revoked=('card-001',)))
        r=self.accept(self.proposal(holder=OTHER))
        self.assertEqual(r['subject_id'],old_alias);self.assertEqual(self.app.app_hash,before)
        self.assertEqual(r['native_account_association']['wallet_public_key'],public(self.owner))

if __name__=='__main__':unittest.main()
