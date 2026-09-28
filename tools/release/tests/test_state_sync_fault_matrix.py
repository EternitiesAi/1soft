import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import check_state_sync_faults as gate

ENGINE='a'*64
PROCESS={'returncode':0,'timed_out':False,'log_truncated':False}
SOURCE={'commit':'1'*40,'tree':'2'*40,'source_id':'3'*64,'files':[
    {'path':'scripts/run_state_sync.py','sha256':'4'*64},
    {'path':'SOURCE_MANIFEST.json','sha256':'5'*64},
]}
CORE=list(gate.CORE)

def fixture(name):
    _,args=gate.profile(name);protocol=int(args[args.index('--protocol-version')+1])
    commitment=args[args.index('--state-commitment')+1] if '--state-commitment' in args else 'legacy-flat-v1'
    keep=int(args[args.index('--block-history-keep')+1]) if '--block-history-keep' in args else None
    crash='--final-apply-crash' in args; marker={'height':6,'app_hash':'6'*64};final=12
    checks=[{'name':n,'passed':True} for n in CORE]
    checks.append({'name':'restored marker AppHash matches retained source signed state commitment' if keep else
                          'restored marker AppHash matches source block at that exact height','passed':True})
    if keep:checks.append({'name':'state-synced target retains bounded local block history without pruning native receipts','passed':True})
    if crash:checks.extend({'name':n,'passed':True} for n in gate.CRASH_CHECKS)
    if commitment=='smt-v1':checks.append({'name':'state-synced SMT node serves a verified compact account proof after continuation','passed':True})
    value={'status':'passed','checks':checks,'engine_sha256':ENGINE,'engine_version':'0.38.25',
        'protocol_version':protocol,'state_commitment':commitment,'block_history_keep':keep,
        'final_apply_crash':crash,'state_sync_verified':True,'continued_execution_verified':True,
        'final_apply_recovery_verified':crash,'public_network':False,'real_funds':False,
        'state_sync_marker':marker,'final_height':final,'source_provenance':{
            'source_commit':SOURCE['commit'],'source_tree':SOURCE['tree'],'tracked_worktree_dirty':False,
            'runner_relative_path':'scripts/run_state_sync.py','runner_sha256':'4'*64,'source_manifest_sha256':'5'*64}}
    if keep:value['local_history']={'enabled':True,'keep_blocks':2,'source_snapshot_block_pruned':True,
        'target':{'application_height':final,'availability':{'bootstrap_height':6,'keep_blocks':2,
        'retained_count':2,'retained_from':11,'retained_through':12,'pruned_through':10},
        'native_receipts_pruned':False,'native_receipt_count':2}}
    if crash:value['final_apply_recovery']={'engine_restarted':True,'killed':{
        'schema':1,'phase':'killed-after-durable-install','signal':'SIGKILL','exit_code':-9},
        'durable_marker':marker,'recovery_install':{'schema':1,'phase':'checkpoint-recovery-install',
        'checkpoint_recovery':True,'height':6,'app_hash':'6'*64}}
    return value

class MatrixTests(unittest.TestCase):
    def validate(self,name):return gate.validate_result(fixture(name),name,SOURCE,ENGINE,PROCESS)
    def test_four_profiles_are_unique_and_cover_both_commitments(self):
        self.assertEqual(len(gate.PROFILES),4);self.assertEqual(len({p[0] for p in gate.PROFILES}),4)
        for name in ('retained-state-sync-p1','retained-state-sync-p3-smt','crash-state-sync-p1','crash-state-sync-p3-smt'):
            self.assertGreater(self.validate(name),10)
    def test_retention_profile_requires_target_history(self):
        r=fixture('retained-state-sync-p1');r['local_history']['target']['availability']['retained_count']=1
        with self.assertRaises(ValueError):gate.validate_result(r,'retained-state-sync-p1',SOURCE,ENGINE,PROCESS)
    def test_retention_profile_requires_source_snapshot_block_pruned(self):
        r=fixture('retained-state-sync-p1');r['local_history']['source_snapshot_block_pruned']=False
        with self.assertRaises(ValueError):gate.validate_result(r,'retained-state-sync-p1',SOURCE,ENGINE,PROCESS)
    def test_crash_profile_requires_actual_sigkill_receipt(self):
        r=fixture('crash-state-sync-p1');r['final_apply_recovery']['killed']['signal']='SIGTERM'
        with self.assertRaises(ValueError):gate.validate_result(r,'crash-state-sync-p1',SOURCE,ENGINE,PROCESS)
    def test_crash_profile_requires_checkpoint_recovery_install(self):
        r=fixture('crash-state-sync-p1');r['final_apply_recovery']['recovery_install']['checkpoint_recovery']=False
        with self.assertRaises(ValueError):gate.validate_result(r,'crash-state-sync-p1',SOURCE,ENGINE,PROCESS)
    def test_generic_pass_cannot_replace_semantic_checks(self):
        r=fixture('crash-state-sync-p1');r['checks']=[{'name':'generic pass','passed':True}]
        with self.assertRaises(ValueError):gate.validate_result(r,'crash-state-sync-p1',SOURCE,ENGINE,PROCESS)
    def test_wrong_source_or_engine_refused(self):
        r=fixture('retained-state-sync-p1');r['source_provenance']['source_commit']='0'*40
        with self.assertRaises(ValueError):gate.validate_result(r,'retained-state-sync-p1',SOURCE,ENGINE,PROCESS)
        r=fixture('retained-state-sync-p1');r['engine_sha256']='0'*64
        with self.assertRaises(ValueError):gate.validate_result(r,'retained-state-sync-p1',SOURCE,ENGINE,PROCESS)
    def test_timeout_or_truncation_refused(self):
        for field in ('timed_out','log_truncated'):
            with self.subTest(field=field):
                p={**PROCESS,field:True}
                with self.assertRaises(ValueError):gate.validate_result(fixture('crash-state-sync-p1'),'crash-state-sync-p1',SOURCE,ENGINE,p)
    def test_missing_engine_runs_zero_scenarios(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out=root/'out'
            with patch.object(gate,'ROOT',root),patch.object(gate,'source_identity',return_value=SOURCE),\
                 patch.object(gate,'checked_manifests',return_value=[]),\
                 patch.object(gate,'run_process',side_effect=AssertionError('must not launch')):
                code=gate.run(str(root/'missing'),ENGINE,out)
            self.assertEqual(code,2);result=json.loads((out/'result.json').read_bytes())
            self.assertEqual(result['status'],'unassessed');self.assertEqual(result['scenarios'],[])
    def test_existing_output_directory_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);out=root/'out';out.mkdir()
            with patch.object(gate,'ROOT',root),patch.object(gate,'source_identity',return_value=SOURCE),\
                 patch.object(gate,'checked_manifests',return_value=[]):
                with self.assertRaises(FileExistsError):gate.run(str(root/'missing'),ENGINE,out)

if __name__=='__main__':unittest.main()
