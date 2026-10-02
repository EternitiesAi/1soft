"""Committed application queries and synthetic static-validator certificates.

Real signatures, local commits and process crashes; NO real consensus engine.
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

from block_application import BlockApplication, application_hash, transaction_id
from compact_verifier import verify_compact_witness, verify_compact_receipt, review_compact_transfer
from commit_verifier import encode, verify_state_witness
from native_core import NativeLedger, Reject, canonical, sign, public
from state_tree import StateTree, bind_root, make_witness, verify_proof, ProofError
from test_native_budgets import KEYS, IDS, genesis
from test_budget_integration import setup_transactions, payment
from certificate_fixture import validators, make_header, make_commit

ROOT=Path(__file__).resolve().parents[1]


class CompactStateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.g={**genesis(),'state_commitment':'smt-v1'}
        self.path=self.root/'node.sqlite'
        self.app=BlockApplication(self.path,expected_genesis=self.g)
        self.app.init_chain(self.g['chain_id'],self.g)
        self.engine,self.trust,self.keys=validators(self.g)
    def tearDown(self):
        self.app.close();self.tmp.cleanup()
    def block(self,txs):
        height=self.app.height+1
        result=self.app.finalize_block(txs,height,hashlib.sha256(str(height).encode()).digest())
        self.app.commit();return result
    def certificate(self,height=None,root=None,txs=None):
        height=self.app.height+1 if height is None else height
        header=make_header(self.trust,height,root or self.app.app_hash,txs or [])
        header['version']['app']='3'
        if height>1:header['last_block_id']={'hash':'12'*32,'parts':{'total':1,'hash':'13'*32}}
        return make_commit(header,self.trust,self.keys)
    def witness(self,queries):return self.app.compact_witness(queries)
    def checked(self,w,queries,cert=None):
        return verify_compact_witness(w,cert or self.certificate(),self.trust,expected_queries=queries)
    def budget_queries(self,which=1):
        label=('raven','atlas')[which];grant=IDS[0]+'::'+label
        return [('accounts',IDS[0]),('accounts',IDS[1]),('meta','height'),
                ('grants',grant),('grant_budgets',grant),('budgets',IDS[0]+'::project')]
    def receipt_parts(self):
        self.block(setup_transactions(self.g))
        raw=payment(self.g,0,58);before=self.app.app_hash;self.block([raw])
        cert=self.certificate(2,before,[raw])
        block={'block_id':cert['commit']['block_id'],'block':{'header':cert['header'],
               'data':{'txs':[base64.b64encode(raw).decode()]}}}
        w=self.witness([('receipts',transaction_id(raw))])
        return raw,w,block,cert,self.certificate()
    def test_explicit_mode_requires_protocol_three(self):
        for version in (1,2):
            with self.assertRaises(Reject):NativeLedger(':memory:',{**self.g,'protocol_version':version})
    def test_unknown_commitment_refused_not_silently_ignored(self):
        for mode in ('',None,True,'flat-v1','SMT-V1'):
            with self.subTest(mode=mode),self.assertRaises(Reject):NativeLedger(':memory:',{**self.g,'state_commitment':mode})
    def test_smt_genesis_differs_from_legacy_and_cannot_reopen_it(self):
        other=BlockApplication(self.root/'legacy.sqlite',expected_genesis=genesis())
        other.init_chain(self.g['chain_id'],genesis());other.close()
        with self.assertRaises(Reject):BlockApplication(self.root/'legacy.sqlite',expected_genesis=self.g)
    def test_compact_proofs_refused_for_legacy_genesis(self):
        a=BlockApplication(':memory:');a.init_chain(self.g['chain_id'],genesis())
        try:
            with self.assertRaises(ProofError):a.compact_witness([('accounts',IDS[0])])
        finally:a.close()
    def test_genesis_account_proof_reaches_next_header_root(self):
        q=[('accounts',IDS[0])];w=self.witness(q);r=self.checked(w,q)
        self.assertEqual(r['state_height'],0);self.assertEqual(r['records'][0]['row'][4],10000)
        self.assertFalse(r['whole_ledger_downloaded']);self.assertNotIn('native',w)
    def test_single_query_json_path_matches_direct_witness(self):
        path='/proof/accounts/'+IDS[0].encode().hex()
        r=self.app.query(path);self.assertEqual(r['code'],0)
        self.assertEqual(json.loads(r['value']),self.witness([('accounts',IDS[0])]))
    def test_query_returns_proven_nonmembership_not_missing_untrusted_response(self):
        q=[('accounts','missing')];w=self.witness(q);r=self.checked(w,q)
        self.assertFalse(r['records'][0]['exists']);self.assertIsNone(r['records'][0]['row'])
    def test_query_does_not_advertise_standard_abci_proofops(self):
        self.assertEqual(self.app.query('/proof/accounts/'+IDS[0].encode().hex(),prove=True)['code'],1)
    def test_invalid_query_paths_refused(self):
        for path in ('/proof/evil/61','/proof/accounts/zz','/proof/accounts/','/proof/accounts/41/extra',
                     '/proof/accounts/FF','/proof/accounts/'+'61'*513):
            with self.subTest(path=path):self.assertEqual(self.app.query(path)['code'],1)
    def test_pending_proposal_is_not_visible_in_proof(self):
        q=[('budgets',IDS[0]+'::project')];old=self.witness(q)
        self.app.finalize_block(setup_transactions(self.g),1,b'a'*32)
        self.assertEqual(self.witness(q),old)
        self.app.commit();new=self.witness(q)
        self.assertIsNotNone(self.checked(new,q)['records'][0]['row']);self.assertNotEqual(old['app_hash'],new['app_hash'])
    def test_prepare_and_process_leave_proof_unchanged(self):
        q=[('accounts',IDS[0])];old=self.witness(q);raws=setup_transactions(self.g)
        self.app.prepare_proposal(raws,1,100000);self.app.process_proposal(raws,1)
        self.assertEqual(self.witness(q),old)
    def test_empty_committed_block_changes_height_binding(self):
        q=[('accounts',IDS[0])];before=self.witness(q);self.block([]);after=self.witness(q)
        self.assertEqual(before['root'],after['root']);self.assertNotEqual(before['app_hash'],after['app_hash'])
    def test_state_record_mutation_rejected(self):
        q=[('accounts',IDS[0])];w=self.witness(q);w['entries'][0]['value'][4]+=10
        with self.assertRaises(ValueError):self.checked(w,q)
    def test_signed_header_from_wrong_height_rejected(self):
        self.block([]);q=[('accounts',IDS[0])]
        with self.assertRaises(ValueError):self.checked(self.witness(q),q,self.certificate(1))
    def test_forged_validator_signature_rejected(self):
        q=[('accounts',IDS[0])];cert=self.certificate();cert['commit']['signatures'][0]['signature']=base64.b64encode(bytes(64)).decode()
        with self.assertRaises(ValueError):self.checked(self.witness(q),q,cert)
    def test_missing_requested_record_is_rejected(self):
        q=[('accounts',IDS[0]),('accounts',IDS[1])];w=self.witness(q);w['entries'].pop()
        with self.assertRaises(ValueError):self.checked(w,q)
    def test_unrequested_extra_record_is_rejected(self):
        w=self.witness([('accounts',IDS[0]),('accounts',IDS[1])])
        with self.assertRaises(ValueError):self.checked(w,[('accounts',IDS[0])])
    def test_duplicate_expected_key_refused(self):
        q=[('accounts',IDS[0])];w=self.witness(q)
        with self.assertRaises(ValueError):self.checked(w,q+q)
    def test_empty_expected_set_refused(self):
        with self.assertRaises(ValueError):self.checked(self.witness([('accounts',IDS[0])]),[])
    def test_duplicate_proof_key_refused(self):
        q=[('accounts',IDS[0]),('accounts',IDS[1])];w=self.witness(q);w['entries'][1]=copy.deepcopy(w['entries'][0])
        with self.assertRaises(ValueError):self.checked(w,q)
    def test_proofs_from_different_roots_cannot_mix(self):
        q=[('accounts',IDS[0])];old=self.witness(q);self.block(setup_transactions(self.g));new=self.witness(q)
        new['entries']=old['entries']
        with self.assertRaises(ValueError):self.checked(new,q)
    def test_proof_genesis_cannot_be_changed(self):
        q=[('accounts',IDS[0])];w=self.witness(q);w['genesis']['asset']='FAKE'
        with self.assertRaises(ValueError):self.checked(w,q)
    def test_full_snapshot_verifier_still_accepts_smt_commitment(self):
        self.block(setup_transactions(self.g));state=json.loads(self.app.query('/state')['value'])
        r=verify_state_witness(state,self.certificate(),self.trust)
        self.assertEqual(r['state_app_hash'],self.app.app_hash)
    def test_legacy_full_snapshot_claim_not_accepted_for_smt_chain(self):
        q=[('accounts',IDS[0])];w=self.witness(q)
        state=json.loads(self.app.query('/state')['value'])
        flat=hashlib.sha256(encode({'domain':'ETERNITIES/ABCI-STATE/v1','genesis':self.trust.native_genesis_hash,
                                   'height':0,'native':state['native']})).hexdigest()
        with self.assertRaises(ValueError):self.checked(w,q,self.certificate(root=flat))
    def test_restart_recomputes_matching_committed_proof(self):
        self.block(setup_transactions(self.g));q=self.budget_queries();before=self.witness(q)
        self.app.close();self.app=BlockApplication(self.path,expected_genesis=self.g)
        self.assertEqual(self.witness(q),before)
    def test_real_process_crash_old_or_new_root_only(self):
        self.block(setup_transactions(self.g));q=self.budget_queries(0);old=self.witness(q)
        raw=payment(self.g,0,58);self.app.close()
        code='''import sys
from block_application import BlockApplication
app=BlockApplication(sys.argv[1]);app.finalize_block([bytes.fromhex(sys.argv[2])],2,b'z'*32)
app.commit(fault=sys.argv[3])
'''
        for fault,exitcode,spent in [('exit_after_state',91,0),('exit_after_commit',92,60)]:
            r=subprocess.run([sys.executable,'-c',code,str(self.path),raw.hex(),fault],
                             env=dict(os.environ,PYTHONPATH=str(ROOT/'src')),capture_output=True,timeout=10)
            self.assertEqual(r.returncode,exitcode,r.stderr)
            self.app=BlockApplication(self.path,expected_genesis=self.g);w=self.witness(q)
            verified=self.checked(w,q);budget=verified['records'][-1]['row'];self.assertEqual(budget[4],spent)
            if spent==0:self.assertEqual(w,old)
            else:self.assertNotEqual(w['app_hash'],old['app_hash'])
            self.app.close()
        self.app=BlockApplication(self.path,expected_genesis=self.g)
    def test_two_application_instances_commit_identical_merkle_root(self):
        other=BlockApplication(':memory:');other.init_chain(self.g['chain_id'],self.g)
        try:
            for h,txs in enumerate([setup_transactions(self.g),[payment(self.g,0,58)],[]],1):
                a=self.app.finalize_block(txs,h,bytes([h])*32)
                b=other.finalize_block(txs,h,bytes([h])*32)
                self.assertEqual(a,b);self.app.commit();other.commit()
                self.assertEqual(self.witness(self.budget_queries()),other.compact_witness(self.budget_queries()))
        finally:other.close()
    def test_readonly_agent_preflight_uses_six_rows(self):
        self.block(setup_transactions(self.g));self.block([payment(self.g,0,58)])
        body=json.loads(payment(self.g,1,38))['body'];q=self.budget_queries()
        r=review_compact_transfer(self.witness(q),self.certificate(),self.trust,body,public(KEYS[3]))
        self.assertEqual(r['record_count'],6);self.assertEqual(r['grant_remaining_units'],100)
        self.assertEqual(r['shared_budget_remaining_units'],40);self.assertFalse(r['signed'])
    def test_compact_preflight_rejects_aggregate_overspend(self):
        self.block(setup_transactions(self.g));self.block([payment(self.g,0,58)])
        with self.assertRaisesRegex(ValueError,'shared budget exceeded'):
            review_compact_transfer(self.witness(self.budget_queries()),self.certificate(),self.trust,
                                    json.loads(payment(self.g,1,39))['body'],public(KEYS[3]))
    def test_compact_preflight_rejects_wrong_signer(self):
        self.block(setup_transactions(self.g))
        with self.assertRaisesRegex(ValueError,'signer or nonce'):
            review_compact_transfer(self.witness(self.budget_queries()),self.certificate(),self.trust,
                                    json.loads(payment(self.g,1,20))['body'],public(KEYS[2]))
    def test_compact_preflight_does_not_trust_budget_link_hint(self):
        self.block(setup_transactions(self.g));w=self.witness(self.budget_queries());w['entries'][-2]['value'][1]='fake-budget'
        with self.assertRaises(ValueError):review_compact_transfer(w,self.certificate(),self.trust,
            json.loads(payment(self.g,1,20))['body'],public(KEYS[3]))
    def test_compact_preflight_rejects_revoked_parent(self):
        self.block(setup_transactions(self.g));m=NativeLedger(':memory:',self.g)
        try:raw=canonical(sign(KEYS[0],m.body(IDS[0],3,{'type':'budget_revoke','id':'project'})))
        finally:m.close()
        self.block([raw])
        with self.assertRaisesRegex(ValueError,'inactive'):
            review_compact_transfer(self.witness(self.budget_queries()),self.certificate(),self.trust,
                                    json.loads(payment(self.g,1,20))['body'],public(KEYS[3]))
    def test_preflight_is_not_a_future_reservation(self):
        self.block(setup_transactions(self.g));w=self.witness(self.budget_queries());cert=self.certificate()
        raw=payment(self.g,1,98)
        self.assertEqual(review_compact_transfer(w,cert,self.trust,json.loads(raw)['body'],public(KEYS[3]))['status'],
                         'eligible-at-witnessed-height')
        self.block([payment(self.g,0,58)])
        self.assertEqual(self.app.check_tx(raw)['code'],1)
    def test_record_capacity_rejection_is_atomic_during_proposal(self):
        m=NativeLedger(':memory:',self.g)
        try:
            a=canonical(sign(KEYS[0],m.body(IDS[0],0,{'type':'transfer','to':IDS[1],'units':1})))
            b=canonical(sign(KEYS[0],m.body(IDS[0],1,{'type':'transfer','to':IDS[1],'units':1})))
        finally:m.close()
        # Genesis has seven rows. Exactly one new receipt fits this test cap.
        with patch('state_tree.MAX_ROWS',8):
            self.assertEqual(self.app.prepare_proposal([a,b],1,100000),[a])
            self.assertFalse(self.app.process_proposal([a,b],1))
            result=self.block([a,b])
            self.assertEqual([r['code'] for r in result['tx_results']],[0,1])
            state=json.loads(self.app.query('/state')['value'])
            self.assertEqual(len(state['native']['receipts']),1)
            account=next(r for r in state['native']['accounts'] if r[0]==IDS[0])
            self.assertEqual(account[2],1);self.assertEqual(account[4],9997)
            self.assertEqual(self.app.check_tx(b)['code'],1)
            # Block production need not crash when the state reaches the cap.
            self.block([]);self.checked(self.witness([('accounts',IDS[0])]),[('accounts',IDS[0])])

    def test_native_capacity_rejects_before_durable_transaction_commit(self):
        m=NativeLedger(':memory:',self.g)
        try:
            with patch('state_tree.MAX_ROWS',8):
                one=sign(KEYS[0],m.body(IDS[0],0,{'type':'transfer','to':IDS[1],'units':1}))
                two=sign(KEYS[0],m.body(IDS[0],1,{'type':'transfer','to':IDS[1],'units':1}))
                m.apply(one,height=1);before=m.state_hash()
                with self.assertRaisesRegex(Reject,'capacity'):m.apply(two,height=1)
                self.assertEqual(m.state_hash(),before)
                self.assertEqual(m.db.execute('SELECT count(*) FROM receipts').fetchone()[0],1)
        finally:m.close()

    def test_all_legacy_commitment_vectors_match_parent_v012(self):
        vectors=json.loads((ROOT/'tests/fixtures/legacy-state-v012.json').read_text())
        for vector in vectors:
            with self.subTest(version=vector['version']):
                a=BlockApplication(':memory:');a.init_chain(vector['genesis']['chain_id'],vector['genesis'])
                try:
                    self.assertEqual(json.loads(a.query('/state')['value']),vector['before'])
                    a.finalize_block([bytes.fromhex(vector['transaction_hex'])],1,b'a'*32);a.commit()
                    self.assertEqual(json.loads(a.query('/state')['value']),vector['after'])
                finally:a.close()

    def test_compact_receipt_proves_exact_execution_record_and_inclusion(self):
        raw,w,block,commit,header=self.receipt_parts()
        r=verify_compact_receipt(w,header,self.trust,expected_transaction=raw,block=block,commit=commit)
        self.assertEqual(r['native_txid'],transaction_id(raw));self.assertFalse(r['whole_ledger_downloaded'])
        self.assertEqual(len(w['entries']),1)
    def test_compact_receipt_rejects_another_requested_payment(self):
        raw,w,block,commit,header=self.receipt_parts()
        with self.assertRaises(ValueError):verify_compact_receipt(w,header,self.trust,
            expected_transaction=payment(self.g,1,38),block=block,commit=commit)
    def test_compact_receipt_rejects_altered_signature(self):
        raw,w,block,commit,header=self.receipt_parts();env=json.loads(raw);env['signature']='0'*128
        with self.assertRaises(ValueError):verify_compact_receipt(w,header,self.trust,
            expected_transaction=canonical(env),block=block,commit=commit)
    def test_missing_receipt_proves_absence_but_not_payment(self):
        raw=payment(self.g,0,58);q=[('receipts',transaction_id(raw))];w=self.witness(q)
        self.assertFalse(self.checked(w,q)['records'][0]['exists'])
        with self.assertRaisesRegex(ValueError,'no execution receipt'):verify_compact_receipt(w,self.certificate(),self.trust,
            expected_transaction=raw,block={},commit={})
    def test_cli_verifies_independently_selected_account(self):
        q=[('accounts',IDS[0])];w=self.witness(q);gen=encode(self.engine)
        for name,value in [('genesis',self.engine),('witness',w),('header',self.certificate())]:
            (self.root/(name+'.json')).write_bytes(encode(value))
        cmd=[sys.executable,str(ROOT/'scripts/verify_compact.py'),'--genesis',str(self.root/'genesis.json'),
             '--genesis-sha256',hashlib.sha256(gen).hexdigest(),'--witness',str(self.root/'witness.json'),
             '--header',str(self.root/'header.json'),'records','--expect','accounts',IDS[0]]
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout)['status'],'verified')
        r=subprocess.run(cmd[:-1]+[IDS[1]],capture_output=True,text=True,timeout=10)
        self.assertEqual(r.returncode,2)


class CompactNetworkPlanTests(unittest.TestCase):
    def test_authored_compact_case_executes_real_local_state_machine(self):
        sys.path.insert(0,str(ROOT/'scripts'))
        from run_devnet import build_native_case
        plan=build_native_case('compact-network-plan',3,state_commitment='smt-v1')
        model=NativeLedger(':memory:',plan['genesis'])
        try:
            for name,raw in plan['accepted']:
                for _,bad in plan.get('rejections_before',{}).get(name,[]):
                    with self.assertRaises(Reject):model.apply(json.loads(bad),height=1)
                model.apply(json.loads(raw),height=1)
            self.assertTrue(model.verify_receipts())
            self.assertEqual(model.state()['budgets'][0]['spent'],100)
        finally:model.close()
    def test_no_engine_cannot_pass_compact_network_case(self):
        sys.path.insert(0,str(ROOT/'scripts'))
        from run_devnet import run
        with tempfile.TemporaryDirectory() as d:
            out=run(str(Path(d)/'missing'),Path(d)/'result.json',3,state_commitment='smt-v1')
        self.assertEqual(out['status'],'unassessed');self.assertEqual(out['checks'],[])
        self.assertEqual(out['state_commitment'],'smt-v1')
    def test_other_protocol_cannot_silently_opt_into_new_commitment(self):
        sys.path.insert(0,str(ROOT/'scripts'))
        from run_devnet import build_native_case
        for version,mode in ((1,'smt-v1'),(2,'smt-v1'),(3,'unknown')):
            with self.assertRaises(ValueError):build_native_case('bad',version,state_commitment=mode)


if __name__=='__main__':unittest.main()
