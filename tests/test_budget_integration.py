"""Budget state through block commits, signed witnesses, wallets and crash recovery.

Committee signatures below are synthetic, never live CometBFT certificates.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives import serialization as ser
from native_core import NativeLedger, Reject, sign, public, canonical
from block_application import BlockApplication, transaction_id
from commit_verifier import encode, verify_packet, verify_state_witness, header_hash
from certified_wallet import CertifiedWallet, nanos
from offline_signer import review_intent, approve_intent
from test_native_budgets import KEYS, IDS, genesis, budget_op, grant_op
from certificate_fixture import validators, make_header, make_commit, STAMP

ROOT=Path(__file__).resolve().parents[1]
PASSWORD=b'public-disposable-budget-test-passphrase'


def setup_transactions(g):
    m=NativeLedger(':memory:',g)
    try:
        return [canonical(sign(KEYS[0],m.body(IDS[0],n,op))) for n,op in enumerate(
            [budget_op(),grant_op(),grant_op('atlas',KEYS[3])])]
    finally:m.close()


def payment(g,which,amount):
    m=NativeLedger(':memory:',g)
    try:return canonical(sign(KEYS[2+which],m.body(IDS[0],0,{'type':'transfer','to':IDS[1],'units':amount},grant_id=('raven','atlas')[which])))
    finally:m.close()


class BudgetIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.path=self.root/'app.sqlite';self.g=genesis()
        self.app=BlockApplication(self.path,expected_genesis=self.g);self.app.init_chain(self.g['chain_id'],self.g)
        self.engine,self.trust,self.valkeys=validators(self.g);self.rawgen=encode(self.engine)
        self.setup=setup_transactions(self.g)
    def tearDown(self):self.app.close();self.tmp.cleanup()
    def state(self):return json.loads(self.app.query('/state')['value'])
    def block(self,txs):
        h=self.app.height+1;r=self.app.finalize_block(txs,h,hashlib.sha256(str(h).encode()).digest());self.app.commit();return r
    def witness(self):
        s=self.state();header=make_header(self.trust,self.app.height+1,s['app_hash']);header['version']['app']='3'
        if self.app.height: header['last_block_id']={'hash':'12'*32,'parts':{'total':1,'hash':'13'*32}}
        return {'schema':1,'state':s,'state_commit':make_commit(header,self.trust,self.valkeys)}
    def wallet(self):
        policy={'schema':1,'genesis_sha256':hashlib.sha256(self.rawgen).hexdigest(),'trust_expires_utc':'2026-09-25T00:00:00Z',
                'minimum_header_height':1,'maximum_age_seconds':300,'future_skew_seconds':5}
        return CertifiedWallet(self.root/'wallet.sqlite',self.rawgen,policy,clock=lambda:nanos(STAMP)+10**9)
    def vault(self,index=3):
        p=self.root/'test-key.pem';p.write_bytes(KEYS[index].private_bytes(ser.Encoding.PEM,ser.PrivateFormat.PKCS8,ser.BestAvailableEncryption(PASSWORD)));p.chmod(0o600);return p
    def test_checks_and_proposals_do_not_spend_or_create_budget(self):
        before=self.state();self.assertEqual(self.app.check_tx(self.setup[0])['code'],0)
        self.assertEqual(self.app.prepare_proposal(self.setup,1,100000),self.setup)
        self.assertTrue(self.app.process_proposal(self.setup,1));self.assertEqual(self.state(),before)
    def test_finalized_budget_is_invisible_until_commit(self):
        self.app.finalize_block(self.setup,1,b'x'*32);self.assertEqual(self.state()['native']['budgets'],[])
        self.app.commit();self.assertEqual(len(self.state()['native']['budgets']),1)
    def test_conflicting_agents_same_block_filter_and_reject(self):
        self.block(self.setup);a=payment(self.g,0,58);b=payment(self.g,1,39)
        self.assertEqual(self.app.check_tx(a)['code'],0);self.assertEqual(self.app.check_tx(b)['code'],0)
        self.assertEqual(self.app.prepare_proposal([a,b],2,100000),[a]);self.assertFalse(self.app.process_proposal([a,b],2))
        self.assertEqual(self.state()['native']['budgets'][0][4],0)
    def test_defensive_finalization_does_not_partially_apply_rejected_debit(self):
        self.block(self.setup);r=self.block([payment(self.g,0,58),payment(self.g,1,39)])
        self.assertEqual([x['code'] for x in r['tx_results']],[0,1]);self.assertEqual(self.state()['native']['budgets'][0][4],60)
        self.assertEqual(sorted(r[6] for r in self.state()['native']['grants']),[0,60])
    def test_new_block_sees_previously_committed_aggregate(self):
        self.block(self.setup);self.block([payment(self.g,0,58)])
        self.assertNotEqual(self.app.check_tx(payment(self.g,1,39))['code'],0)
        self.assertEqual(self.app.check_tx(payment(self.g,1,38))['code'],0)
    def test_empty_block_expiry_still_enforced(self):
        ops=copy.deepcopy(self.setup)
        for i,raw in enumerate(ops):
            env=json.loads(raw);env['body']['op']['expires']=1;ops[i]=canonical(sign(KEYS[0],env['body']))
        self.block(ops);self.block([]);self.assertNotEqual(self.app.check_tx(payment(self.g,0,1))['code'],0)
    def test_budget_is_committed_in_signed_state_witness(self):
        self.block(self.setup);w=self.witness()
        self.assertEqual(verify_state_witness(w['state'],w['state_commit'],self.trust)['state_height'],1)
        w['state']['native']['budgets'][0][4]=1
        with self.assertRaises(ValueError):verify_state_witness(w['state'],w['state_commit'],self.trust)
    def test_stripping_budget_tables_from_signed_witness_fails(self):
        self.block(self.setup);w=self.witness();del w['state']['native']['grant_budgets']
        with self.assertRaises(ValueError):verify_state_witness(w['state'],w['state_commit'],self.trust)
    def test_wallet_displays_shared_remaining_and_individual_remaining(self):
        self.block(self.setup);self.block([payment(self.g,0,58)]);w=self.wallet()
        try:
            r=w.review(self.witness(),json.loads(payment(self.g,1,38))['body'],public(KEYS[3]))
            self.assertEqual(r['grant_remaining_units'],100);self.assertEqual(r['shared_budget_remaining_units'],40)
            self.assertTrue(r['shared_budget_id'].endswith('::project'));self.assertFalse(r['latest_state_guaranteed'])
        finally:w.close()
    def test_wallet_rejects_excess_before_unlock(self):
        self.block(self.setup);self.block([payment(self.g,0,58)]);w=self.wallet()
        try:
            with patch('certified_wallet._load_vault',side_effect=AssertionError('no unlock')):
                with self.assertRaisesRegex(Reject,'shared native budget exceeded'):
                    w.review(self.witness(),json.loads(payment(self.g,1,39))['body'],public(KEYS[3]))
        finally:w.close()
    def test_encrypted_wallet_signs_boundary_debit_and_block_accepts(self):
        self.block(self.setup);self.block([payment(self.g,0,58)]);w=self.wallet()
        try:
            witness=self.witness();body=json.loads(payment(self.g,1,38))['body'];r=w.review(witness,body,public(KEYS[3]))
            signed=w.approve(witness,body,public(KEYS[3]),r['confirmation'],self.vault(),PASSWORD)
            result=self.block([canonical(signed['result'])]);self.assertEqual(result['tx_results'][0]['code'],0)
            self.assertEqual(self.state()['native']['budgets'][0][4],100)
        finally:w.close()
    def test_budget_admin_review_does_not_consume_its_own_operation(self):
        w=self.wallet()
        try:
            body=json.loads(self.setup[0])['body'];witness=self.witness();r=w.review(witness,body,public(KEYS[0]))
            approved=w.approve(witness,body,public(KEYS[0]),r['confirmation'],self.vault(0),PASSWORD)
            self.assertEqual(self.block([canonical(approved['result'])])['tx_results'][0]['code'],0)
        finally:w.close()
    def test_grant_review_does_not_preinsert_its_own_binding(self):
        self.block([self.setup[0]]);w=self.wallet()
        try:
            body=json.loads(self.setup[1])['body'];witness=self.witness();r=w.review(witness,body,public(KEYS[0]))
            approved=w.approve(witness,body,public(KEYS[0]),r['confirmation'],self.vault(0),PASSWORD)
            self.assertEqual(self.block([canonical(approved['result'])])['tx_results'][0]['code'],0)
        finally:w.close()
    def test_static_offline_review_supports_budget_controls_without_claiming_state(self):
        for raw in self.setup:
            r=review_intent(self.g,json.loads(raw)['body'],public(KEYS[0]));self.assertFalse(r['current_authority_verified'])
        bad=json.loads(self.setup[1])['body'];del bad['op']['budget_id']
        with self.assertRaises(Reject):review_intent(self.g,bad,public(KEYS[0]))
    def test_commit_interruption_preserves_old_or_new_budget_atomically(self):
        self.block(self.setup);self.app.close()
        code='''import json,sys
from pathlib import Path
from block_application import BlockApplication
app=BlockApplication(sys.argv[1]);tx=bytes.fromhex(sys.argv[2])
app.finalize_block([tx],2,b'z'*32);app.commit(fault=sys.argv[3])
'''
        for fault,exitcode,expected in [('exit_after_state',91,0),('exit_after_commit',92,60)]:
            run=subprocess.run([sys.executable,'-c',code,str(self.path),payment(self.g,0,58).hex(),fault],env=dict(os.environ,PYTHONPATH=str(ROOT/'src')),capture_output=True,timeout=10)
            self.assertEqual(run.returncode,exitcode,run.stderr)
            self.app=BlockApplication(self.path,expected_genesis=self.g)
            self.assertEqual(self.state()['native']['budgets'][0][4],expected)
            self.assertEqual(sum(r[6] for r in self.state()['native']['grants']),expected)
            self.app.close()
        self.app=BlockApplication(self.path,expected_genesis=self.g)
    def test_replica_replay_is_deterministic(self):
        other=BlockApplication(':memory:');other.init_chain(self.g['chain_id'],self.g)
        try:
            for h,txs in enumerate([self.setup,[payment(self.g,0,58),payment(self.g,1,39)],[payment(self.g,1,38)]],1):
                a=self.app.finalize_block(txs,h,bytes([h])*32);b=other.finalize_block(txs,h,bytes([h])*32)
                self.assertEqual(a,b);self.app.commit();other.commit()
                self.assertEqual(self.app.query('/state'),other.query('/state'))
        finally:other.close()


class BudgetNetworkPlanTests(unittest.TestCase):
    def test_authored_engine_case_replays_and_checks_aggregate_at_correct_point(self):
        sys.path.insert(0,str(ROOT/'scripts'))
        from run_devnet import build_native_case
        case=build_native_case('1soft-budget-network-plan',3);m=NativeLedger(':memory:',case['genesis'])
        rejected=0
        try:
            for name,raw in case['accepted']:
                for reason,bad in case.get('rejections_before',{}).get(name,[]):
                    before=m.state_hash()
                    with self.assertRaisesRegex(Reject,'shared native budget exceeded'):m.apply(json.loads(bad),height=1)
                    self.assertEqual(m.state_hash(),before);rejected+=1
                m.apply(json.loads(raw),height=1)
            for _,bad in case['rejected']:
                with self.assertRaises(Reject):m.apply(json.loads(bad),height=1)
            self.assertEqual(rejected,1);self.assertEqual(m.state()['budgets'][0]['spent'],100)
        finally:m.close()
    def test_v3_full_receipt_packet_verifies_against_separate_genesis_trust(self):
        g=genesis();engine,trust,keys=validators(g)
        a=BlockApplication(':memory:');a.init_chain(g['chain_id'],g)
        try:
            raws=setup_transactions(g)+[payment(g,0,58),payment(g,1,38)]
            h1=make_header(trust,1,a.app_hash,raws);h1['version']['app']='3';c1=make_commit(h1,trust,keys)
            a.finalize_block(raws,1,header_hash(h1));a.commit();state=json.loads(a.query('/state')['value'])
            h2=make_header(trust,2,state['app_hash'],previous=c1['commit']['block_id']);h2['version']['app']='3'
            block={'block_id':c1['commit']['block_id'],'block':{'header':h1,'data':{'txs':[base64.b64encode(raw).decode() for raw in raws]}}}
            p={'schema':1,'state':state,'state_commit':make_commit(h2,trust,keys),'transactions':[
                {'tx':base64.b64encode(raw).decode(),'block':block,'commit':c1} for raw in raws]}
            verified=verify_packet(p,trust,expected_txids=[transaction_id(raw) for raw in raws])
            self.assertEqual(verified['status'],'verified');self.assertEqual(state['native']['budgets'][0][4],100)
        finally:a.close()

if __name__ == '__main__':
    unittest.main()
