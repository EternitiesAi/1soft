"""Incremental caller/storage behavior against the unchanged full-history oracle.

Synthetic validator signatures, actual P4 native/admin execution and private SQLite.
These checks do not claim real CometBFT or independent validator execution.
"""
import copy
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from block_application import encode
from p4_evidence import nanos, verify_evidence
from p4_fixture import build, bundle, rechain
from incremental_fixture import policy, segment, build_alpha
from p4_incremental_evidence import policy_v2_checked, check_clock
from p4_incremental_store import P4IncrementalStore


class IncrementalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case=build_alpha(count=80,rejected=True)
        cls.legacy=build(count=80,rejected=True)

    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=Path(self.temp.name)/'incremental.sqlite'
        self.now=nanos(self.case['headers'][32]['signed_header']['header']['time'])+10**9
        self.policy=policy(self.case)
        self.store=P4IncrementalStore(self.path,self.case['genesis'],self.policy,
                                     create=True,clock=lambda:self.now)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def append(self,height,start=0,parent=None):
        self.now=nanos(self.case['headers'][height]['signed_header']['header']['time'])+10**9
        return self.store.import_segment(segment(self.case,height,start=start,parent=parent),
                                         expected_tip=parent)

    def rows(self):
        return {name:self.store.db.execute('SELECT * FROM '+name+' ORDER BY 1').fetchall()
                for name in ('config','headers','blocks','checkpoints')}

    def test_delta_crosses64_matches_original_financial_and_registry_oracle(self):
        first=self.append(32)
        second=self.append(64,32,first['checkpoint']['id'])
        last=self.append(80,64,second['checkpoint']['id'])
        old=verify_evidence(bundle(self.legacy),self.legacy['genesis'],self.legacy['policy'],now_ns=self.now)
        for key in ('state_height','registry_epoch','accounts',
                    'grants','budgets','grant_budgets','validator_updates',
                    'validator_transitions'):
            self.assertEqual(last['report'][key],old[key],key)
        self.assertEqual(last['context']['state'],self.case['states'][80])
        self.assertEqual([(a['height'],a['index'],a['code'],a['kind']) for a in last['report']['attempts']],
                         [(a['height'],a['index'],a['code'],a['kind']) for a in old['attempts']])
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM blocks').fetchone()[0],80)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM headers').fetchone()[0],81)
        self.assertEqual(last['report']['evidence_id'],last['checkpoint']['id'])

    def test_previous_lookahead_body_is_required_and_consumed_once(self):
        first=self.append(6)
        last=self.append(8,6,first['checkpoint']['id'])
        receipt=[r for r in last['report']['receipts'] if r['wire_sha256']==
                 __import__('hashlib').sha256(self.case['wires']['after']).hexdigest()]
        self.assertEqual(len(receipt),1)
        self.assertEqual(receipt[0]['height'],7)
        self.assertEqual(len([a for a in last['report']['attempts'] if a['height']==8 and a['code']==0]),0)

    def test_queries_reuse_verified_cursor_without_reading_prior_blocks(self):
        self.append(32)
        calls=[]
        self.store.db.set_trace_callback(calls.append)
        self.store.current();self.store.current()
        self.assertFalse(any('FROM blocks' in q for q in calls),calls)

    def test_cold_reopen_authenticates_prefix_then_reuses_cursor(self):
        first=self.append(32);self.store.close()
        self.store=P4IncrementalStore(self.path,self.case['genesis'],self.policy,clock=lambda:self.now)
        self.assertEqual(self.store.current()['checkpoint']['id'],first['checkpoint']['id'])
        with patch('p4_incremental_evidence.Protocol4Replay.advance',side_effect=AssertionError('replayed twice')):
            self.assertEqual(self.store.current()['report']['state_height'],32)

    def test_missing_boundary_block_refused_atomically(self):
        first=self.append(6);before=self.rows()
        bad=segment(self.case,8,start=6,parent=first['checkpoint']['id'])
        bad['history'].pop(0)
        with self.assertRaises(ValueError):self.store.import_segment(bad,expected_tip=first['checkpoint']['id'])
        self.assertEqual(self.rows(),before)

    def test_valid_signed_changed_boundary_identity_cannot_rewrite_prefix(self):
        first=self.append(6);before=self.rows()
        alternate=bundle(self.case)
        alternate['headers'][6]['signed_header']['header']['consensus_hash']='AE'*32
        rechain(alternate,self.case['keys'])
        bad=segment(self.case,8,start=6,parent=first['checkpoint']['id'])
        bad['headers']=alternate['headers'][6:9]
        with self.assertRaises(ValueError):self.store.import_segment(bad,expected_tip=first['checkpoint']['id'])
        self.assertEqual(self.rows(),before)

    def test_same_height_and_stale_cas_are_refused(self):
        first=self.append(6);before=self.rows()
        with self.assertRaises(ValueError):self.store.import_segment(segment(self.case,8,start=6,parent=first['checkpoint']['id']),expected_tip=None)
        with self.assertRaises(ValueError):self.store.import_segment(segment(self.case,6,start=6,parent=first['checkpoint']['id']),expected_tip=first['checkpoint']['id'])
        self.assertEqual(self.rows(),before)

    def test_external_sql_tamper_invalidates_cached_authority(self):
        self.append(6)
        other=sqlite3.connect(self.path)
        raw=encode({'height':1,'txs':[]})
        other.execute('UPDATE blocks SET payload=? WHERE height=1',(raw,))
        other.commit();other.close()
        with self.assertRaises(ValueError):self.store.current()

    def test_same_connection_sql_tamper_invalidates_cached_authority(self):
        self.append(6)
        self.store.db.execute('UPDATE checkpoints SET checked_ns=checked_ns+1')
        with self.assertRaises(ValueError):self.store.current()

    def test_failed_sql_commit_discards_half_advanced_replay(self):
        first=self.append(6);before=self.rows()
        self.store.db.set_authorizer(lambda action,*_:sqlite3.SQLITE_DENY if action==sqlite3.SQLITE_INSERT else sqlite3.SQLITE_OK)
        with self.assertRaises(sqlite3.DatabaseError):self.append(8,6,first['checkpoint']['id'])
        self.store.db.set_authorizer(None)
        self.assertEqual(self.rows(),before)
        self.assertEqual(self.store.current()['report']['state_height'],6)
        self.assertEqual(self.append(8,6,first['checkpoint']['id'])['report']['state_height'],8)

    def test_expiry_before_commit_preserves_exact_original_tip(self):
        first=self.append(6);before=self.rows()
        self.now=nanos(self.case['headers'][8]['signed_header']['header']['time'])+10**9
        expiry=first['checkpoint']['lookahead_time_ns']+3600*10**9
        values=iter([self.now,self.now,expiry,expiry])
        self.store.clock=lambda:next(values,expiry)
        with self.assertRaises(ValueError):self.store.import_segment(segment(self.case,8,start=6,parent=first['checkpoint']['id']),expected_tip=first['checkpoint']['id'])
        self.assertEqual(self.rows(),before)

    def test_expiry_during_return_view_refuses_before_commit(self):
        first=self.append(6);before=self.rows()
        self.now=nanos(self.case['headers'][8]['signed_header']['header']['time'])+10**9
        expiry=first['checkpoint']['lookahead_time_ns']+3600*10**9
        original=self.store._cursor.view
        def slow_view(*args,**kwargs):
            result=original(*args,**kwargs)
            if kwargs.get('current_authority'):self.now=expiry
            return result
        self.store._cursor.view=slow_view
        with self.assertRaises(ValueError):self.store.import_segment(segment(self.case,8,start=6,parent=first['checkpoint']['id']),expected_tip=first['checkpoint']['id'])
        self.assertEqual(self.rows(),before)

    def test_expired_or_backdated_import_cannot_renew_trust(self):
        first=self.append(6);before=self.rows()
        old=self.now
        self.now=first['checkpoint']['lookahead_time_ns']+3600*10**9
        with self.assertRaises(ValueError):self.store.import_segment(segment(self.case,8,start=6,parent=first['checkpoint']['id']),now=old,expected_tip=first['checkpoint']['id'])
        self.assertEqual(self.rows(),before)

    def test_fixed_absolute_horizon_and_typed_policy_cannot_slide(self):
        p=policy_v2_checked(self.policy)
        self.assertEqual(check_clock(p,nanos(p['anchor_time'])),nanos(p['anchor_time'])+3600*10**9)
        for key,value in [('checkpoint_progression',1),('absolute_not_after_ns',True),
                          ('absolute_not_after_ns',p['absolute_not_after_ns']+1),
                          ('trust_period_seconds',7200),('schema',True)]:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                policy_v2_checked({**p,key:value})

    def test_historical_checkpoint_has_context_but_no_current_authority(self):
        first=self.append(6);last=self.append(8,6,first['checkpoint']['id'])
        self.now=last['checkpoint']['lookahead_time_ns']+3600*10**9
        with self.assertRaises(ValueError):self.store.current()
        old=self.store.checkpoint_at(first['checkpoint']['id'],historical=True)
        self.assertEqual(old['report']['state_height'],6)
        self.assertFalse(old['context']['current_authority'])
        self.assertEqual(old['context']['state'],self.case['states'][6])
        self.assertNotIn('headers',old['context'])
        self.assertEqual(old['context']['lookahead'],self.case['headers'][6])

    def test_quota_failure_does_not_evict_or_partial_commit(self):
        first=self.append(6);before=self.rows()
        self.store.limits={**self.store.limits,'max_blocks':6}
        with self.assertRaises(ValueError):self.append(8,6,first['checkpoint']['id'])
        self.assertEqual(self.rows(),before)


    def test_tampered_native_state_and_signed_body_are_refused_without_observation(self):
        for kind in ('state','body','signature','parent','roster'):
            with self.subTest(kind=kind):
                candidate=segment(self.case,6)
                if kind=='state':candidate['state']['native']['accounts'][0][4]+=1
                elif kind=='body':candidate['history'][0]['txs']=[]
                elif kind=='signature':
                    candidate['headers'][2]['signed_header']['commit']['signatures'][0]['signature']='AA=='
                elif kind=='parent':
                    candidate['headers'][2]['signed_header']['header']['last_block_id']['parts']['hash']='AC'*32
                else:candidate['headers'][2]['validators'][0]['power']+=1
                with self.assertRaises(ValueError):self.store.import_segment(candidate,expected_tip=None)
                self.assertEqual(self.store.db.execute('SELECT count(*) FROM checkpoints').fetchone()[0],0)

    def test_batch_contexts_share_one_authenticated_prefix_and_exact_origin(self):
        first=self.append(6);second=self.append(8,6,first['checkpoint']['id'])
        third=self.append(16,8,second['checkpoint']['id'])
        self.store.close()
        self.store=P4IncrementalStore(self.path,self.case['genesis'],self.policy,clock=lambda:self.now)
        from protocol4_application import Protocol4Replay
        original=Protocol4Replay.advance;seen=[]
        def observe(replay,txs,height):
            seen.append(height);return original(replay,txs,height)
        with patch('p4_incremental_evidence.Protocol4Replay.advance',new=observe):
            views=self.store.checkpoint_batch([first['checkpoint']['id'],third['checkpoint']['id']])
        self.assertEqual(seen,list(range(1,17)))
        self.assertEqual(views[first['checkpoint']['id']]['context']['state'],self.case['states'][6])
        descriptors=self.store.checkpoint_descriptors()
        self.assertEqual(descriptors[second['checkpoint']['id']]['height'],8)
        self.assertNotIn('state',descriptors[second['checkpoint']['id']])

    def test_context_mutation_does_not_corrupt_cursor_or_retained_origin(self):
        first=self.append(6);view=self.store.current()
        view['context']['state']['native']['accounts'][0][4]+=10**6
        view['report']['receipts'].clear()
        self.assertEqual(self.store.current()['context']['state'],self.case['states'][6])
        self.assertEqual(self.store.checkpoint_at(first['checkpoint']['id'])['context']['state'],self.case['states'][6])

    def test_root_policy_store_identity_and_existing_format_are_not_swapped(self):
        first=self.append(6);original_id=self.store.store_id
        self.store.close()
        with self.assertRaises(ValueError):
            P4IncrementalStore(self.path,self.case['genesis'],{**self.policy,'anchor_hash':'a'*64},clock=lambda:self.now)
        self.store=P4IncrementalStore(self.path,self.case['genesis'],self.policy,clock=lambda:self.now)
        self.assertEqual(self.store.history_id,original_id)
        with self.assertRaises(FileExistsError):
            P4IncrementalStore(self.path,self.case['genesis'],self.policy,create=True,clock=lambda:self.now)
        self.assertEqual(self.store.current()['checkpoint']['id'],first['checkpoint']['id'])

    def test_unknown_receipt_is_unavailable_and_does_not_release_holds(self):
        self.append(6)
        result=self.store.receipt(self.case['wires']['after'],payer=self.case['payer'])
        self.assertEqual(result['status'],'unavailable')
        self.assertFalse(result['wallet_reservations_changed'])
        self.assertFalse(result['historical_absence_proven'])

    def test_rpc_captures_fixed_target_and_requests_only_new_history(self):
        from test_rpc import rpc
        self.now=nanos(self.case['headers'][80]['signed_header']['header']['time'])+10**9
        with rpc(self.case,height=80) as (endpoint,requests):
            first=self.store.collect(endpoint,expected_tip=None)
        self.assertEqual(first['report']['state_height'],64)
        self.assertEqual(first['captured_source_height'],80)
        self.assertEqual(first['rpc_requests'],130)
        with rpc(self.case,height=80) as (endpoint,requests):
            second=self.store.collect(endpoint,expected_tip=first['checkpoint']['id'])
        self.assertEqual(second['report']['state_height'],80)
        self.assertEqual(second['rpc_requests'],34)
        self.assertEqual([int(q['params']['height']) for q in requests if q['method']=='block'],
                         list(range(65,81)))
        self.assertEqual(sum(q['method']=='abci_query' for q in requests),1)

    def test_rpc_stale_cas_invalid_endpoint_and_sameheight_stop_without_import(self):
        from test_rpc import rpc
        first=self.append(6)
        with rpc(self.case,height=6) as (endpoint,requests):
            with self.assertRaises(ValueError):self.store.collect(endpoint,expected_tip=None)
            self.assertEqual(requests,[])
            with self.assertRaises(ValueError):self.store.collect(endpoint,expected_tip=first['checkpoint']['id'])
        self.assertEqual(self.store.current()['report']['state_height'],6)
        with self.assertRaises(ValueError):self.store.collect('http://localhost:26657/',expected_tip=first['checkpoint']['id'])

    def test_readonly_view_and_archive_preserve_original_bytes(self):
        first=self.append(6)
        original=self.store.export_history()
        self.store.close()
        self.store=P4IncrementalStore(self.path,self.case['genesis'],self.policy,
                                     read_only=True,clock=lambda:self.now)
        self.assertEqual(self.store.export_history(),original)
        self.assertEqual(self.store.current()['checkpoint']['id'],first['checkpoint']['id'])
        with self.assertRaises(ValueError):self.store.import_segment(segment(self.case,8,start=6,parent=first['checkpoint']['id']),expected_tip=first['checkpoint']['id'])


    def test_live_progress_crosses_original_fixed_root_expiry_but_cannot_fill_offline_gap(self):
        from datetime import datetime,timedelta,timezone
        from p4_fixture import sign_header
        from validator_sets_core import ValidatorSet
        from commit_verifier import header_hash
        case={**self.case,'headers':copy.deepcopy(self.case['headers']),'policy':copy.deepcopy(self.case['policy'])}
        origin=datetime.fromisoformat(case['headers'][0]['signed_header']['header']['time'].replace('Z','+00:00'))
        for index,entry in enumerate(case['headers']):
            entry['signed_header']['header']['time']=(origin+timedelta(seconds=index*60)).isoformat().replace('+00:00','Z')
        rechain({'headers':case['headers']},case['keys'])
        p=policy(case);p['anchor_time']=case['headers'][0]['signed_header']['header']['time']
        p['anchor_hash']=header_hash(case['headers'][0]['signed_header']['header']).hex()
        p['absolute_not_after_ns']=nanos(p['anchor_time'])+86400*10**9
        self.store.close()
        path=Path(self.temp.name)/'progress.sqlite'
        self.now=nanos(case['headers'][6]['signed_header']['header']['time'])+10**9
        self.store=P4IncrementalStore(path,case['genesis'],p,create=True,clock=lambda:self.now)
        first=self.store.import_segment(segment(case,6),expected_tip=None)
        self.now=nanos(case['headers'][64]['signed_header']['header']['time'])+10**9
        second=self.store.import_segment(segment(case,64,start=6,parent=first['checkpoint']['id']),
                                         expected_tip=first['checkpoint']['id'])
        self.assertGreater(self.now,nanos(p['anchor_time'])+3600*10**9)
        self.assertEqual(second['report']['state_height'],64)
        self.store.close()
        self.store=P4IncrementalStore(path,case['genesis'],p,clock=lambda:self.now)
        self.assertEqual(self.store.current()['checkpoint']['id'],second['checkpoint']['id'])
        before=self.rows()
        self.now=second['checkpoint']['lookahead_time_ns']+3600*10**9
        with self.assertRaises(ValueError):
            self.store.import_segment(segment(case,80,start=64,parent=second['checkpoint']['id']),
                                      expected_tip=second['checkpoint']['id'])
        self.assertEqual(self.rows(),before)

    def test_valid_alternate_boundary_signature_subset_keeps_original_header_bytes(self):
        from p4_fixture import sign_header
        from validator_sets_core import ValidatorSet
        first=self.append(6)
        original=self.store.db.execute('SELECT payload FROM headers WHERE height=7').fetchone()[0]
        candidate=segment(self.case,8,start=6,parent=first['checkpoint']['id'])
        entry=candidate['headers'][0]
        entry['signed_header']=sign_header(entry['signed_header']['header'],
            ValidatorSet.parse(entry['validators']),self.case['keys'],[2,2,2,1])
        self.now=nanos(self.case['headers'][8]['signed_header']['header']['time'])+10**9
        self.store.import_segment(candidate,expected_tip=first['checkpoint']['id'])
        self.assertEqual(self.store.db.execute('SELECT payload FROM headers WHERE height=7').fetchone()[0],original)
        self.store.close()
        self.store=P4IncrementalStore(self.path,self.case['genesis'],self.policy,clock=lambda:self.now)
        self.assertEqual(self.store.current()['report']['state_height'],8)

    def test_sqlite_trigger_or_unknown_schema_is_refused_before_cursor_reuse(self):
        self.append(6)
        self.store.db.execute('CREATE TRIGGER altered AFTER INSERT ON blocks BEGIN SELECT 1; END')
        with self.assertRaises(ValueError):self.store.current()

    def test_legacy_genesis_v1_policy_and_fullproof_cannot_be_mislabeled_incremental(self):
        with self.assertRaises(ValueError):policy_v2_checked(self.case['policy'])
        with self.assertRaises(ValueError):
            P4IncrementalStore(Path(self.temp.name)/'old.sqlite',self.legacy['genesis'],
                               policy(self.legacy),create=True,clock=lambda:self.now)
        with self.assertRaises(ValueError):
            self.store.import_segment(bundle(self.case,6),expected_tip=None)

    def test_current_clock_regression_and_historical_selector_are_typed(self):
        first=self.append(6)
        self.now-=1
        with self.assertRaises(ValueError):self.store.current()
        with self.assertRaises(ValueError):self.store.current(historical=1)
        historical=self.store.checkpoint_at(first['checkpoint']['id'])
        self.assertFalse(historical['context']['current_authority'])

    def test_rpc_worker_timeout_refuses_without_partial_history(self):
        from p4_incremental_rpc import collect_segment
        import subprocess
        with patch('p4_incremental_rpc.subprocess.run',side_effect=subprocess.TimeoutExpired(['owned-python'],45)):
            with self.assertRaises(ValueError):
                collect_segment('http://127.0.0.1:26657/',self.case['genesis'],self.policy,self.now)
        self.assertIsNone(self.store.current())


    def actual_child_exit(self,after):
        import os,subprocess,sys,json
        first=self.append(6)
        self.now=nanos(self.case['headers'][8]['signed_header']['header']['time'])+10**9
        root=Path(self.temp.name)
        (root/'genesis.json').write_bytes(self.case['genesis'])
        (root/'policy.json').write_bytes(encode(self.policy))
        (root/'segment.json').write_bytes(encode(segment(self.case,8,start=6,parent=first['checkpoint']['id'])))
        code="""import json,os,sys
from pathlib import Path
from p4_incremental_store import P4IncrementalStore
root=Path(sys.argv[1])
with P4IncrementalStore(root/'incremental.sqlite',(root/'genesis.json').read_bytes(),
 json.loads((root/'policy.json').read_bytes()),clock=lambda:int(sys.argv[3])) as store:
 if sys.argv[4]=='before':
  def stop(sql):
   if sql=='COMMIT':os._exit(41)
  store.db.set_trace_callback(stop)
 store.import_segment(json.loads((root/'segment.json').read_bytes()),expected_tip=sys.argv[2])
 os._exit(42)
"""
        child=subprocess.run([sys.executable,'-B','-c',code,str(root),first['checkpoint']['id'],
                              str(self.now),'after' if after else 'before'],
                             capture_output=True,timeout=10)
        self.assertEqual(child.returncode,42 if after else 41,child.stderr)
        self.store.close()
        self.store=P4IncrementalStore(self.path,self.case['genesis'],self.policy,clock=lambda:self.now)
        return self.store.current()

    def test_actual_owned_child_exit_before_commit_retains_previous_complete_prefix(self):
        view=self.actual_child_exit(False)
        self.assertEqual(view['report']['state_height'],6)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM blocks').fetchone()[0],6)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM checkpoints').fetchone()[0],1)

    def test_actual_owned_child_exit_after_commit_retains_new_complete_prefix(self):
        view=self.actual_child_exit(True)
        self.assertEqual(view['report']['state_height'],8)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM blocks').fetchone()[0],8)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM checkpoints').fetchone()[0],2)


    def test_incremental_profile_crosses512_without_new_genesis_or_policy(self):
        case=build_alpha(count=520,rejected=True)
        p=policy(case)
        self.store.close()
        path=Path(self.temp.name)/'beyond512.sqlite'
        self.now=nanos(case['headers'][64]['signed_header']['header']['time'])+10**9
        self.store=P4IncrementalStore(path,case['genesis'],p,create=True,clock=lambda:self.now)
        original_store=self.store.store_id;original_policy=self.store.policy_id
        start=0;parent=None
        for height in (64,128,192,256,320,384,448,512,520):
            self.now=nanos(case['headers'][height]['signed_header']['header']['time'])+10**9
            view=self.store.import_segment(segment(case,height,start=start,parent=parent),expected_tip=parent)
            start=height;parent=view['checkpoint']['id']
            self.assertEqual(self.store.store_id,original_store)
            self.assertEqual(self.store.policy_id,original_policy)
        self.assertEqual(view['context']['state'],case['states'][520])
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM blocks').fetchone()[0],520)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM headers').fetchone()[0],521)
        self.store.close()
        self.store=P4IncrementalStore(path,case['genesis'],p,clock=lambda:self.now)
        self.assertEqual(self.store.current()['checkpoint']['id'],parent)
        self.assertEqual(self.store.current()['report']['state_height'],520)


    def test_replaced_database_path_cannot_reuse_open_connection_identity(self):
        self.append(6)
        moved=self.path.with_suffix('.owned-moved')
        self.path.rename(moved)
        self.path.write_bytes(moved.read_bytes())
        self.path.chmod(0o600)
        with self.assertRaises(ValueError):self.store.current()

if __name__=='__main__':unittest.main()
