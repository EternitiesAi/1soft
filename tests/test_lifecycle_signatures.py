import base64
import copy
import json
import unittest
from native_core import NativeLedger, canonical, sign, public, DOMAIN
from block_application import BlockApplication, transaction_id
from commit_verifier import (VerificationError, verify_native_signatures, verify_packet,
                             header_hash)
from certificate_fixture import validators, make_header, make_commit
from test_account_lifecycle import KEYS, IDS, genesis_v2, independently_accept


def lifecycle_fixture():
    g=genesis_v2();m=NativeLedger(':memory:',g)
    opened=independently_accept(KEYS[3],m.body(IDS[0],0,{
        'type':'open_account','public_key':public(KEYS[3]),'units':100,'acceptance':''}))
    rotated=independently_accept(KEYS[4],m.body(IDS[0],1,{
        'type':'rotate_key','public_key':public(KEYS[4]),'acceptance':''}))
    raws=[canonical(sign(KEYS[0],b)) for b in (opened,rotated)];m.close()
    engine,trust,keys=validators(g)
    app=BlockApplication(':memory:');app.init_chain(g['chain_id'],g)
    h1=make_header(trust,1,app.app_hash,raws);h1['version']['app']='2'
    c1=make_commit(h1,trust,keys)
    app.finalize_block(raws,1,header_hash(h1));app.commit()
    state=json.loads(app.query('/state')['value']);app.close()
    h2=make_header(trust,2,state['app_hash'],previous=c1['commit']['block_id']);h2['version']['app']='2'
    c2=make_commit(h2,trust,keys)
    result={'block_id':c1['commit']['block_id'],'block':{'header':h1,
        'data':{'txs':[base64.b64encode(raw).decode() for raw in raws]}}}
    packet={'schema':1,'state':state,'state_commit':c2,'transactions':[
        {'tx':base64.b64encode(raw).decode(),'block':copy.deepcopy(result),'commit':copy.deepcopy(c1)} for raw in raws]}
    return engine,trust,keys,packet,raws


class LifecycleSignatureTests(unittest.TestCase):
    def setUp(self):
        self.m=NativeLedger(':memory:',genesis_v2())
        self.body=independently_accept(KEYS[4],self.m.body(IDS[0],0,
            {'type':'rotate_key','public_key':public(KEYS[4]),'acceptance':''}))
        self.env=sign(KEYS[0],self.body)
    def tearDown(self):self.m.close()
    def verify(self,env=None,key=None,version=2):
        return verify_native_signatures(env or self.env,key or public(KEYS[0]),protocol_version=version)
    def test_independent_acceptance_verifier(self):self.assertTrue(self.verify())
    def test_independent_verifier_bad_owner_signature(self):
        with self.assertRaises(VerificationError):self.verify(sign(KEYS[4],self.body))
    def test_independent_verifier_bad_incoming_signature_after_owner_resigns(self):
        body=copy.deepcopy(self.body);body['op']['acceptance']='0'*128
        with self.assertRaises(VerificationError):self.verify(sign(KEYS[0],body))
    def test_independent_verifier_mutated_fee_after_owner_resigns(self):
        body=copy.deepcopy(self.body);body['max_fee']=20
        with self.assertRaises(VerificationError):self.verify(sign(KEYS[0],body))
    def test_independent_verifier_mutated_nonce_after_owner_resigns(self):
        body=copy.deepcopy(self.body);body['nonce']=1
        with self.assertRaises(VerificationError):self.verify(sign(KEYS[0],body))
    def test_independent_verifier_cross_domain_signature(self):
        body=copy.deepcopy(self.body);payload=copy.deepcopy(body);payload['op'].pop('acceptance')
        body['op']['acceptance']=KEYS[4].sign(DOMAIN+canonical(payload)).hex()
        with self.assertRaises(VerificationError):self.verify(sign(KEYS[0],body))
    def test_independent_verifier_wrong_protocol(self):
        with self.assertRaises(VerificationError):self.verify(version=1)
    def test_independent_verifier_unknown_protocol(self):
        with self.assertRaises(VerificationError):self.verify(version=4)
    def test_independent_verifier_delegation_cannot_rotate(self):
        body=copy.deepcopy(self.body);body['grant_id']='raven'
        with self.assertRaises(VerificationError):self.verify(sign(KEYS[0],body))
    def test_independent_verifier_extra_fields(self):
        body=copy.deepcopy(self.body);body['op']['inherit_grants']=True
        with self.assertRaises(VerificationError):self.verify(sign(KEYS[0],body))
    def test_regular_transfer_does_not_claim_second_signature(self):
        body=self.m.body(IDS[0],0,{'type':'transfer','to':IDS[1],'units':10})
        self.assertFalse(self.verify(sign(KEYS[0],body)))
    def test_opening_verifies_incoming_signature(self):
        body=independently_accept(KEYS[3],self.m.body(IDS[0],0,
            {'type':'open_account','public_key':public(KEYS[3]),'units':100,'acceptance':''}))
        self.assertTrue(self.verify(sign(KEYS[0],body)))
    def test_opening_negative_amount_rejected_even_after_all_signatures(self):
        body=self.m.body(IDS[0],0,{'type':'open_account','public_key':public(KEYS[3]),'units':-1,'acceptance':''})
        body=independently_accept(KEYS[3],body)
        with self.assertRaises(VerificationError):self.verify(sign(KEYS[0],body))
    def test_v2_synthetic_packet_verifies_both_intended_operations(self):
        _,trust,_,packet,raws=lifecycle_fixture()
        result=verify_packet(packet,trust,expected_txids=[transaction_id(raw) for raw in raws])
        self.assertEqual(result['status'],'verified')
        self.assertTrue(all(p['incoming_key_consent_verified'] for p in result['transactions']))
    def test_v2_synthetic_packet_cannot_omit_requested_rotation(self):
        _,trust,_,packet,raws=lifecycle_fixture();packet['transactions'].pop()
        with self.assertRaises(VerificationError):
            verify_packet(packet,trust,expected_txids=[transaction_id(raw) for raw in raws])
