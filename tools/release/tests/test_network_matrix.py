"""Matrix report/pin controls; synthetic reports here are never engine evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_network as matrix

SOURCE={'commit':'a'*40,'tree':'b'*40,'source_id':'c'*64,'files':[
    {'path':'scripts/run_devnet.py','sha256':'d'*64},
    {'path':'scripts/run_state_sync.py','sha256':'e'*64},
    {'path':'SOURCE_MANIFEST.json','sha256':'f'*64}]}
PROCESS={'returncode':0,'timed_out':False,'log_truncated':False}
ENGINE='1'*64

def fixture(name='native-p1'):
    _,script,args=matrix.expected_profile(name)
    r={'status':'passed','checks':[{'name':'synthetic control','passed':True}],
       'engine_sha256':ENGINE,'engine_version':'0.38.25',
       'public_network':False,'real_funds':False,
       'native_protocol_version':int(args[args.index('--protocol-version')+1]),
       'state_commitment':'smt-v1' if '--state-commitment' in args else 'legacy-flat-v1',
       'run_provenance':{'source_commit':SOURCE['commit'],'source_tree':SOURCE['tree'],
         'tracked_worktree_dirty':False,'runner_relative_path':script,
         'runner_sha256':next(f['sha256'] for f in SOURCE['files'] if f['path']==script),
         'source_manifest_sha256':'f'*64}}
    if '--decision-delivery' in args:
        r.update(wallet_integration_verified=True,decision_delivery={'enabled':True,'status':'passed',
            'receipt_convergence':{'reconciliation_outcome':'already_recorded'}})
    if '--block-history-keep' in args:
        r['local_history']={'status':'passed','keep_blocks':2,'application_restart_verified':True}
    if '--product-journey' in args:
        r['product_journey']={'status':'passed','payments':[{},{}],
            'stages':[{'wallet_pending_units':p,'explorer_spent_units':s} for p,s in
                      [(100,0),(100,60),(40,60),(40,100),(0,100)]],
            'verification_after_local_pruning':[{},{}]}
    if script.endswith('run_state_sync.py'):
        r.update(state_sync_verified=True,continued_execution_verified=True)
    return r

class NetworkMatrixTests(unittest.TestCase):
    def validate(self,r,name='native-p1',process=None):
        return matrix.validate_result(r,name,SOURCE,ENGINE,process or PROCESS)
    def test_exact_profile_can_pass_structural_checks_only(self):self.assertEqual(self.validate(fixture()),1)
    def test_all_nine_profiles_are_unique(self):
        self.assertEqual(len(matrix.PROFILES),9);self.assertEqual(len({p[0] for p in matrix.PROFILES}),9)
    def test_product_profiles_explicitly_enable_retention_and_delivery(self):
        for name in ('product-p3-flat','product-p3-smt'):
            args=matrix.expected_profile(name)[2]
            self.assertIn('--decision-delivery',args);self.assertIn('--receipt-convergence',args)
            self.assertEqual(args[args.index('--block-history-keep')+1],'2')
            self.assertEqual(self.validate(fixture(name),name),1)
    def test_missing_checks_cannot_be_hidden_under_pass(self):
        r=fixture();r['checks']=[]
        with self.assertRaises(ValueError):self.validate(r)
    def test_failed_check_cannot_be_hidden_under_pass(self):
        r=fixture();r['checks'][0]['passed']=False
        with self.assertRaises(ValueError):self.validate(r)
    def test_boolean_like_check_is_not_pass(self):
        r=fixture();r['checks'][0]['passed']=1
        with self.assertRaises(ValueError):self.validate(r)
    def test_ancestor_revision_is_not_current_candidate(self):
        r=fixture();r['run_provenance']['source_commit']='0'*40
        with self.assertRaises(ValueError):self.validate(r)
    def test_dirty_runner_refused(self):
        r=fixture();r['run_provenance']['tracked_worktree_dirty']=True
        with self.assertRaises(ValueError):self.validate(r)
    def test_mismatched_binary_refused(self):
        r=fixture();r['engine_sha256']='0'*64
        with self.assertRaises(ValueError):self.validate(r)
    def test_mismatched_runner_bytes_refused(self):
        r=fixture();r['run_provenance']['runner_sha256']='0'*64
        with self.assertRaises(ValueError):self.validate(r)
    def test_wrong_protocol_and_commitment_refused(self):
        for key,value in (('native_protocol_version',3),('state_commitment','smt-v1')):
            r=fixture();r[key]=value
            with self.assertRaises(ValueError):self.validate(r)
    def test_timeout_and_truncated_log_refused(self):
        for key in ('timed_out','log_truncated'):
            with self.assertRaises(ValueError):self.validate(fixture(),process={**PROCESS,key:True})
    def test_source_inventory_mismatch_refused(self):
        r=fixture();r['run_provenance']['source_manifest_sha256']='0'*64
        with self.assertRaises(ValueError):self.validate(r)
    def test_missing_application_restart_refused(self):
        r=fixture('retained-p1');r['local_history']['application_restart_verified']=False
        with self.assertRaises(ValueError):self.validate(r,'retained-p1')
    def test_product_not_allowed_to_release_hold_before_reconciliation(self):
        r=fixture('product-p3-flat');r['product_journey']['stages'][1]['wallet_pending_units']=40
        with self.assertRaises(ValueError):self.validate(r,'product-p3-flat')
    def test_missing_pruned_receipt_verification_refused(self):
        r=fixture('product-p3-flat');r['product_journey']['verification_after_local_pruning']=[]
        with self.assertRaises(ValueError):self.validate(r,'product-p3-flat')
    def test_state_sync_requires_continued_execution(self):
        r=fixture('state-sync-p1');r['continued_execution_verified']=False
        with self.assertRaises(ValueError):self.validate(r,'state-sync-p1')
    def test_missing_engine_does_not_execute_any_scenario_or_go_probe(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'source';source.mkdir();output=root/'evidence'
            with patch.object(matrix,'ROOT',source),patch.object(matrix,'source_identity',return_value=SOURCE),\
                 patch.object(matrix,'checked_manifests',return_value=[]),\
                 patch.object(matrix,'run_process',side_effect=AssertionError('must not launch')):
                result=matrix.run(str(root/'missing'),ENGINE,output)
            self.assertEqual(result,2)
            report=json.loads((output/'result.json').read_bytes())
            self.assertEqual(report['status'],'unassessed');self.assertEqual(report['scenarios'],[])
            self.assertNotIn('wire',report);self.assertEqual(report['release_status'],'blocked')
    def test_old_output_directory_never_reused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'source';source.mkdir();output=root/'evidence';output.mkdir()
            (output/'prior.log').write_text('preserve')
            with patch.object(matrix,'ROOT',source),patch.object(matrix,'source_identity',return_value=SOURCE),\
                 patch.object(matrix,'checked_manifests',return_value=[]):
                with self.assertRaises(FileExistsError):matrix.run(str(root/'missing'),ENGINE,output)
            self.assertEqual((output/'prior.log').read_text(),'preserve')

if __name__=='__main__':unittest.main()
