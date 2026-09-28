"""Synthetic report-validator controls, not real engine qualification."""
import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import base64
import hashlib

import check_state_sync_faults as gate
from block_application import BlockApplication
from certificate_fixture import validators,make_header,make_commit
from commit_verifier import encode
from run_state_sync import build_case,verify_snapshot_anchor

ENGINE='a'*64
SOURCE={'commit':'1'*40,'tree':'2'*40,'source_id':'3'*64,'files':[
 {'path':'scripts/run_state_sync.py','sha256':'4'*64}, {'path':'SOURCE_MANIFEST.json','sha256':'5'*64}]}
PROCESS={'returncode':0,'timed_out':False,'log_truncated':False}


def history(height,bootstrap):
 return {'scope':'local_application_block_results','application_height':height,
    'native_receipt_count':2,'native_receipts_pruned':False,'cometbft_retain_height':0,
    'engine_history_pruning_requested':False,'historical_transaction_absence_proven':False,
    'total_storage_bounded':False,'availability':{'keep_blocks':2,'bootstrap_height':bootstrap,
    'pruned_through':height-2,'retained_from':height-1,'retained_through':height,
    'retained_count':2,'within_configured_window':True}}


def fixture(name):
 _,version,commitment,keep,crash=gate.profile(name)
 case=build_case('synthetic-report',version,state_commitment=commitment);g=case['genesis']
 engine,trust,keys=validators(g);genesis=encode(engine)
 app=BlockApplication(':memory:',expected_genesis=g);app.init_chain(g['chain_id'],g)
 try:
  for h in range(1,10):
   if h==5:
    marker={'height':4,'app_hash':app.app_hash}
    head=make_header(trust,5,app.app_hash,previous={'hash':'b'*64,'parts':{'total':1,'hash':'c'*64}})
    signed=make_commit(head,trust,keys)
   txs=[case['pre_snapshot_tx']] if h==1 else [case['post_snapshot_tx']] if h==5 else []
   app.finalize_block(txs,h,hashlib.sha256(str(h).encode()).digest());app.commit()
  state=json.loads(app.query('/state')['value'])
 finally:app.close()
 checks=[{'name':n,'passed':True} for n in gate.SYNC_CORE_CHECKS if n!=gate.MARKER_CHECK]
 for check in checks:
  if check['name']=='source and state-synced applications agree at frozen head':check['details']={'height':9,'app_hash':state['app_hash']}
 r={'status':'passed','checks':checks,'protocol_version':version,'state_commitment':commitment or 'legacy-flat-v1',
  'block_history_keep':keep,'final_apply_crash':crash,'engine_version':'0.38.25','engine_sha256':ENGINE,
  'public_network':False,'real_funds':False,'state_sync_verified':True,'continued_execution_verified':True,
  'final_apply_recovery_verified':crash,'snapshot_height':4,'final_height':9,'state_sync_marker':marker,
  'genesis_file_sha256':gate.digest(genesis),'final_state':state,
  'post_snapshot_transaction':base64.b64encode(case['post_snapshot_tx']).decode(),
  'source_provenance':{'source_commit':SOURCE['commit'],'source_tree':SOURCE['tree'],'tracked_worktree_dirty':False,
   'runner_relative_path':'scripts/run_state_sync.py','runner_sha256':'4'*64,'source_manifest_sha256':'5'*64}}
 if keep is not None:
  verified=verify_snapshot_anchor(signed,genesis,marker)
  r['snapshot_anchor']={'signed_header':signed,'verified':verified}
  r['local_history']={'source':history(9,0),'target':history(9,4),'source_snapshot_block_pruned':True}
  checks.extend([{'name':gate.SIGNED_CHECK,'passed':True,'details':verified},
                 {'name':gate.HISTORY_CHECK,'passed':True,'details':{k:r['local_history'][k] for k in ('source','target')}}])
 else:checks.append({'name':gate.MARKER_CHECK,'passed':True})
 if crash:
  run='d'*32;install={'schema':1,'run_id':run,'pid':101,**marker,'transaction_active':False,'checkpoint_recovery':False}
  snap={**marker,'local_block_rows':0};killed={'schema':1,'run_id':run,'pid':101,'signal':'SIGKILL','returncode':-9,'install':install,'checkpoint':snap}
  recovered={**install,'pid':102,'checkpoint_recovery':True}
  r['final_apply_recovery']={'run_id':run,'killed':killed,'recovered':recovered,
     'same_node_home':True,'engine_restarted':True,'retention_flag_repeated':False}
  checks.extend([{'name':n,'passed':True,'details':d} for n,d in zip(gate.CRASH_CHECKS,(killed,{'checkpoint':snap,'marker':marker},recovered))])
 if commitment:checks.append({'name':'state-synced SMT node serves a verified compact account proof after continuation','passed':True})
 return r,genesis


class GateTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.fixtures={n:fixture(n) for n,*_ in gate.PROFILES}
 def sample(self,name='retained-crash-sync-p3-smt'):return copy.deepcopy(self.fixtures[name])
 def validate(self,r,g,name='retained-crash-sync-p3-smt',process=PROCESS):return gate.validate_result(r,name,SOURCE,ENGINE,process,g)
 def test_all_six_complete_synthetic_reports_satisfy_structure(self):
  for name,(r,g) in self.fixtures.items():self.assertEqual(self.validate(r,g,name),len(r['checks']))
 def test_profiles_cover_both_individual_and_combined_modes(self):
  self.assertEqual(len(gate.PROFILES),6)
  self.assertEqual(len({n for n,*_ in gate.PROFILES}),6)
  self.assertIn('--final-apply-crash',gate.command_args('retained-crash-sync-p1'))
  self.assertIn('--block-history-keep',gate.command_args('retained-crash-sync-p1'))
 def test_generic_pass_not_sufficient(self):
  r,g=self.sample();r['checks']=[{'name':'passed','passed':True}]
  with self.assertRaises(ValueError):self.validate(r,g)
 def test_false_or_boolean_numeric_evidence_refused(self):
  mutations=[lambda r:r.update(protocol_version=True),lambda r:r['final_apply_recovery']['killed'].update(schema=True),
    lambda r:r['local_history']['target'].update(native_receipt_count=True),
    lambda r:r['final_apply_recovery']['recovered'].update(pid=True)]
  for mutate in mutations:
   r,g=self.sample();mutate(r)
   with self.assertRaises(ValueError):self.validate(r,g)
 def test_source_and_runner_bytes_must_match(self):
  for key in ('source_commit','source_tree','runner_sha256','source_manifest_sha256'):
   r,g=self.sample();r['source_provenance'][key]='0'*64
   with self.assertRaises(ValueError):self.validate(r,g)
 def test_timeout_truncation_and_nonzero_exit_refuse(self):
  r,g=self.sample()
  for key,v in (('returncode',2),('timed_out',True),('log_truncated',True)):
   with self.assertRaises(ValueError):self.validate(r,g,process={**PROCESS,key:v})
 def test_different_binary_refused(self):
  r,g=self.sample();r['engine_sha256']='0'*64
  with self.assertRaises(ValueError):self.validate(r,g)
 def test_bare_marker_hash_cannot_replace_signature(self):
  r,g=self.sample();r['snapshot_anchor']['signed_header']={'app_hash':r['state_sync_marker']['app_hash']}
  with self.assertRaises(ValueError):self.validate(r,g)
 def test_forged_snapshot_anchor_refused(self):
  r,g=self.sample();r['snapshot_anchor']['signed_header']['commit']['signatures'][0]['signature']='AA=='
  with self.assertRaises(ValueError):self.validate(r,g)
 def test_old_genesis_pin_refused(self):
  r,g=self.sample();r['genesis_file_sha256']='0'*64
  with self.assertRaises(ValueError):self.validate(r,g)
 def test_changed_native_state_refused(self):
  r,g=self.sample();r['final_state']['native']['accounts'][0][4]+=1
  with self.assertRaises(ValueError):self.validate(r,g)
 def test_pre_snapshot_payment_cannot_substitute_for_post_payment(self):
  r,g=self.sample();first=json.loads(r['final_state']['native']['receipts'][0][3])
  r['post_snapshot_transaction']=base64.b64encode(encode(first['envelope'])).decode()
  with self.assertRaises(ValueError):self.validate(r,g)
 def test_changed_or_missing_history_window_refused(self):
  r,g=self.sample();r['local_history']['target']['availability']['retained_count']=1
  with self.assertRaises(ValueError):self.validate(r,g)
 def test_sigterm_cannot_substitute_for_sigkill(self):
  r,g=self.sample();r['final_apply_recovery']['killed']['returncode']=-15
  with self.assertRaises(ValueError):self.validate(r,g)
 def test_active_transaction_is_wrong_kill_window(self):
  r,g=self.sample();r['final_apply_recovery']['killed']['install']['transaction_active']=True
  with self.assertRaises(ValueError):self.validate(r,g)
 def test_recovery_must_bind_same_checkpoint(self):
  r,g=self.sample();r['final_apply_recovery']['recovered']['app_hash']='0'*64
  with self.assertRaises(ValueError):self.validate(r,g)
 def test_old_event_from_another_run_refused(self):
  r,g=self.sample();r['final_apply_recovery']['recovered']['run_id']='e'*32
  with self.assertRaises(ValueError):self.validate(r,g)
 def test_reused_pid_is_not_reopened_application(self):
  r,g=self.sample();r['final_apply_recovery']['recovered']['pid']=101
  with self.assertRaises(ValueError):self.validate(r,g)
 def test_missing_engine_records_zero_scenarios(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);src=root/'src';src.mkdir();out=root/'out'
   with patch.object(gate,'ROOT',src),patch.object(gate,'source_identity',return_value=SOURCE),patch.object(gate,'checked_manifests',return_value=[]),patch.object(gate,'run_process',side_effect=AssertionError('no engine')):
    self.assertEqual(gate.run(str(root/'missing'),ENGINE,out),2)
   r=json.loads((out/'result.json').read_bytes());self.assertEqual(r['scenarios'],[]);self.assertFalse(r['consensus_executed'])
 def test_wrong_binary_keeps_failed_terminal_report(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);src=root/'src';src.mkdir();out=root/'out';binary=root/'binary';binary.write_bytes(b'not an engine')
   with patch.object(gate,'ROOT',src),patch.object(gate,'source_identity',return_value=SOURCE),patch.object(gate,'checked_manifests',return_value=[]),redirect_stdout(io.StringIO()):
    self.assertEqual(gate.run(str(binary),ENGINE,out),1)
   self.assertEqual(json.loads((out/'result.json').read_bytes())['status'],'failed')
 def test_existing_report_directory_is_not_reused(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);src=root/'src';src.mkdir();out=root/'out';out.mkdir()
   with patch.object(gate,'ROOT',src),patch.object(gate,'source_identity',return_value=SOURCE),patch.object(gate,'checked_manifests',return_value=[]):
    with self.assertRaises(FileExistsError):gate.run('missing',ENGINE,out)
 def test_output_cannot_be_inside_source(self):
  with tempfile.TemporaryDirectory() as d,patch.object(gate,'ROOT',Path(d)):
   with self.assertRaises(ValueError):gate.run('missing',ENGINE,Path(d)/'out')

if __name__=='__main__':unittest.main()
