"""Synthetic matrix controls. A valid fixture report is NOT engine execution."""
import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_state_sync_faults as gate
from block_application import BlockApplication, encode
from certificate_fixture import validators, make_header, make_commit
from commit_verifier import header_hash
from run_state_sync import build_case
from state_sync_acceptance import verify_marker_commitment, validate_payment_continuation
from test_state_sync_faults import history, event, RUN_ID

SOURCE = {'commit':'1'*40,'tree':'2'*40,'source_id':'3'*64,'files':[
    {'path':'scripts/run_state_sync.py','sha256':'4'*64},
    {'path':'SOURCE_MANIFEST.json','sha256':'5'*64}]}
ENGINE = 'f'*64
PROCESS = {'returncode':0,'timed_out':False,'log_truncated':False}


def fixture(smt):
    c=build_case('matrix-synthetic',3 if smt else 1,state_commitment='smt-v1' if smt else None)
    g,trust,keys=validators(c['genesis']);genesis=encode(g)
    a=BlockApplication(':memory:',expected_genesis=c['genesis']);a.init_chain(c['genesis']['chain_id'],c['genesis'])
    previous=None;marker=None;signed=None
    try:
        for h in range(1,7):
            txs=[c['pre_snapshot_tx']] if h==1 else [c['post_snapshot_tx']] if h==3 else []
            header=make_header(trust,h,a.app_hash,txs,previous)
            header['version']['app']='3' if smt else '1'
            certified=make_commit(header,trust,keys);previous=certified['commit']['block_id']
            if h==3:signed=certified
            a.finalize_block(txs,h,header_hash(header));a.commit()
            if h==2:marker={'height':2,'app_hash':a.app_hash}
        state=json.loads(a.query('/state')['value'])
    finally:a.close()
    return c,genesis,marker,signed,state


class MatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fixtures={False:fixture(False),True:fixture(True)}
    def report(self,name):
        _,args=gate.profile(name);smt='--state-commitment' in args;crash='--final-apply-crash' in args
        c,g,marker,signed,state=copy.deepcopy(self.fixtures[smt])
        anchor=verify_marker_commitment(marker,signed,g)
        rcpts=validate_payment_continuation(state,marker,c['pre_snapshot_tx'],c['post_snapshot_tx'])
        names=[n for n in gate.SYNC_CORE_CHECKS if n!=gate.LEGACY_MARKER_CHECK or crash]
        checks=[{'name':n,'passed':True} for n in names]
        checks.extend([{'name':gate.SIGNED_CHECK,'passed':True,'details':anchor},
                       {'name':gate.PAYMENT_CHECK,'passed':True,'details':rcpts}])
        if smt:checks.append({'name':gate.SMT_CHECK,'passed':True})
        v={'status':'passed','protocol_version':3 if smt else 1,'state_commitment':'smt-v1' if smt else 'legacy-flat-v1',
            'block_history_keep':None if crash else 2,'final_apply_crash':crash,'final_apply_recovery_verified':crash,
            'state_sync_verified':True,'continued_execution_verified':True,'public_network':False,'real_funds':False,
            'engine_version':'0.38.25','engine_sha256':ENGINE,'source_provenance':{'source_commit':SOURCE['commit'],
                'source_tree':SOURCE['tree'],'tracked_worktree_dirty':False,'runner_relative_path':'scripts/run_state_sync.py',
                'runner_sha256':'4'*64,'source_manifest_sha256':'5'*64},'checks':checks,
            'state_sync_marker':marker,'snapshot_height':2,'final_height':6,'acceptance_run_id':RUN_ID,
            'genesis_file_sha256':gate.digest(g),'snapshot_signed_commitment':signed,'continued_state':state,
            'pre_snapshot_transaction':base64.b64encode(c['pre_snapshot_tx']).decode(),
            'post_snapshot_transaction':base64.b64encode(c['post_snapshot_tx']).decode()}
        if crash:
            killed=event();killed['app_hash']=marker['app_hash'];recovered=event('recovery');recovered['app_hash']=marker['app_hash']
            durable={'marker':marker,'block_rows':0,'native_receipts':1}
            v['final_apply_recovery']={'crash':killed,'exit_code':-9,'durable':durable,'recovery':recovered,
                'same_node_home':True,'engine_restarted':True,'recovery_retention_flag':None}
            checks.extend([{'name':gate.CRASH_CHECKS[0],'passed':True,'details':{'observation':killed,'exit_code':-9}},
                           {'name':gate.CRASH_CHECKS[1],'passed':True,'details':durable},
                           {'name':gate.CRASH_CHECKS[2],'passed':True,'details':recovered}])
        else:
            v['local_history']={'source':history(6,0),'target':history(6,2),'source_snapshot_block_pruned':True}
            checks.append({'name':gate.HISTORY_CHECK,'passed':True,'details':v['local_history']})
        return v,g
    def validate(self,v,g,name):return gate.validate_result(v,name,SOURCE,ENGINE,PROCESS,genesis_bytes=g)
    def test_four_explicit_profiles_verify_only_synthetic_report_contract(self):
        self.assertEqual(len(set(n for n,_ in gate.PROFILES)),4)
        for name,_ in gate.PROFILES:
            v,g=self.report(name);self.assertEqual(self.validate(v,g,name),len(v['checks']))
    def reject(self,name,mutate):
        v,g=self.report(name);mutate(v)
        with self.assertRaises((ValueError,KeyError,TypeError)):self.validate(v,g,name)
    def test_generic_checks_cannot_qualify_any_profile(self):
        for name,_ in gate.PROFILES:
            self.reject(name,lambda v:v.__setitem__('checks',[{'name':'passed','passed':True}]))
    def test_semantic_check_with_wrong_details_refused(self):
        def mutate(v):
            next(c for c in v['checks'] if c['name']==gate.PAYMENT_CHECK)['details']=[]
        self.reject('retained-state-sync-p1',mutate)
    def test_no_proof_at_all_refused(self):
        self.reject('retained-state-sync-p1',lambda v:v.pop('snapshot_signed_commitment'))
    def test_unsigned_rpc_header_not_a_signed_commitment(self):
        self.reject('retained-state-sync-p1',lambda v:v.__setitem__('snapshot_signed_commitment',v['snapshot_signed_commitment']['header']))
    def test_forged_quorum_signature_refused(self):
        def mutate(v):v['snapshot_signed_commitment']['commit']['signatures'][0]['signature']='AA=='
        self.reject('retained-state-sync-p1',mutate)
    def test_marker_hash_or_height_mismatch_refused(self):
        for key,value in [('app_hash','0'*64),('height',3)]:
            self.reject('retained-state-sync-p1',lambda v:v['state_sync_marker'].__setitem__(key,value))
    def test_wrong_genesis_bytes_refused(self):
        v,g=self.report('retained-state-sync-p1')
        with self.assertRaises(ValueError):self.validate(v,g+b' ','retained-state-sync-p1')
    def test_wrong_exact_source_or_binary_refused(self):
        self.reject('crash-state-sync-p1',lambda v:v['source_provenance'].__setitem__('source_commit','0'*40))
        self.reject('crash-state-sync-p1',lambda v:v.__setitem__('engine_sha256','0'*64))
    def test_retention_requires_pruned_source_and_target_window(self):
        self.reject('retained-state-sync-p1',lambda v:v['local_history'].__setitem__('source_snapshot_block_pruned',False))
        self.reject('retained-state-sync-p1',lambda v:v['local_history']['target']['availability'].__setitem__('retained_count',1))
    def test_removing_native_receipts_cannot_pass(self):
        self.reject('retained-state-sync-p1',lambda v:v['continued_state']['native']['receipts'].pop())
    def test_two_receipts_not_the_requested_post_snapshot_payment_refused(self):
        self.reject('crash-state-sync-p1',lambda v:v.__setitem__('post_snapshot_transaction',v['pre_snapshot_transaction']))
    def test_future_or_stale_final_height_refused(self):
        for h in (2,5,7,True):self.reject('retained-state-sync-p1',lambda v:v.__setitem__('final_height',h))
    def test_crash_requires_observed_sigkill_not_sigterm(self):
        self.reject('crash-state-sync-p1',lambda v:v['final_apply_recovery'].__setitem__('exit_code',-15))
    def test_crash_requires_recovery_install_not_normal_fresh_restore(self):
        self.reject('crash-state-sync-p1',lambda v:v['final_apply_recovery']['recovery'].__setitem__('checkpoint_recovery',False))
    def test_crash_cannot_change_same_height_snapshot_hash(self):
        self.reject('crash-state-sync-p1',lambda v:v['final_apply_recovery']['crash'].__setitem__('app_hash','0'*64))
    def test_crash_requires_same_node_home_and_new_process(self):
        self.reject('crash-state-sync-p1',lambda v:v['final_apply_recovery'].__setitem__('same_node_home',False))
        self.reject('crash-state-sync-p1',lambda v:v['final_apply_recovery']['recovery'].__setitem__('pid',101))
    def test_crash_durable_boolean_counts_are_rejected(self):
        self.reject('crash-state-sync-p1',lambda v:v['final_apply_recovery']['durable'].__setitem__('native_receipts',True))
    def test_wrong_run_receipt_cannot_be_reused(self):
        self.reject('crash-state-sync-p1',lambda v:v['final_apply_recovery']['crash'].__setitem__('run_id','f'*32))
    def test_booleans_do_not_impersonate_heights_and_counts(self):
        for field in ('snapshot_height','final_height','protocol_version','block_history_keep'):
            self.reject('retained-state-sync-p1',lambda v:v.__setitem__(field,True))
    def test_failure_timeout_or_truncation_refused(self):
        v,g=self.report('crash-state-sync-p1')
        for f,val in [('returncode',1),('returncode',False),('timed_out',True),('log_truncated',True)]:
            with self.assertRaises(ValueError):gate.validate_result(v,'crash-state-sync-p1',SOURCE,ENGINE,{**PROCESS,f:val},genesis_bytes=g)
    def test_missing_engine_keeps_zero_scenarios_and_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);src=root/'source';src.mkdir();out=root/'result'
            with patch.object(gate,'ROOT',src),patch.object(gate,'source_identity',return_value=SOURCE),patch.object(gate,'checked_manifests',return_value=[]),patch.object(gate,'run_process',side_effect=AssertionError('no launch')):
                self.assertEqual(gate.run(str(root/'absent'),ENGINE,out),2)
            v=json.loads((out/'result.json').read_bytes());self.assertEqual(v['status'],'unassessed');self.assertEqual(v['scenarios'],[])
            self.assertEqual(v['release_status'],'blocked');self.assertFalse(v['consensus_executed'])
    def test_output_inside_source_or_existing_folder_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);src=root/'source';src.mkdir();out=root/'result';out.mkdir()
            with patch.object(gate,'ROOT',src),patch.object(gate,'source_identity',return_value=SOURCE),patch.object(gate,'checked_manifests',return_value=[]):
                with self.assertRaises(ValueError):gate.run('absent',ENGINE,src/'evidence')
                with self.assertRaises(FileExistsError):gate.run('absent',ENGINE,out)
    def test_invalid_timeout_and_engine_digest_refused(self):
        with self.assertRaises(ValueError):gate.run('missing',ENGINE,Path('/unused'),timeout=True)
        with self.assertRaises(ValueError):gate.run('missing','INVALID',Path('/unused'))
    def test_wrong_engine_retains_failed_final_report(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);src=root/'source';src.mkdir();binary=root/'engine';binary.write_bytes(b'not-executed')
            with patch.object(gate,'ROOT',src),patch.object(gate,'source_identity',return_value=SOURCE),patch.object(gate,'checked_manifests',return_value=[]),patch.object(gate,'run_process',side_effect=AssertionError('no launch')):
                self.assertEqual(gate.run(str(binary),ENGINE,root/'evidence'),1)
            self.assertEqual(json.loads((root/'evidence/result.json').read_bytes())['status'],'failed')


if __name__=='__main__':unittest.main()
