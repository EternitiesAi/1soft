import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from commit_verifier import encode,header_hash
from validator_store import ValidatorStore
from transition_fixture import fixture,resign

class StoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.f=fixture()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.path=self.root/'continuity.sqlite'
        self.now=self.f['now'];self.store=self.open(anchor=self.f['steps'][0])
    def tearDown(self):self.store.close();self.tmp.cleanup()
    def open(self,**kw):return ValidatorStore(self.path,self.f['genesis'],self.f['policy'],clock=lambda:self.now,**kw)
    def advance(self,stop=10):
        start=self.store.inspect()['height']
        return self.store.advance(self.f['steps'][start:stop],expected_tip_hash=self.store.inspect()['header_hash'])
    def test_reopen_across_addition_removal_and_full_replacement(self):
        self.advance(4);self.store.close();self.store=self.open();self.advance(7)
        self.store.close();self.store=self.open();self.advance(10)
        r=self.store.inspect();self.assertEqual((r['height'],r['observed_set_changes']),(10,3));self.assertFalse(r['financial_authority'])
    def test_expired_checkpoint_cannot_be_resurrected_by_new_chain(self):
        self.now+=3600*10**9
        self.assertFalse(self.store.inspect()['continuation_within_local_time_policy'])
        old=list(self.store.db.iterdump())
        with self.assertRaisesRegex(ValueError,'expired'):self.advance()
        self.assertEqual(list(self.store.db.iterdump()),old)
    def test_expired_history_still_exports_exact_evidence(self):
        self.advance();self.now+=7200*10**9
        self.assertEqual(self.store.export(),self.f['steps']);self.assertFalse(self.store.inspect()['continuation_within_local_time_policy'])
    def test_wrong_expected_tip_refuses_concurrent_stale_input(self):
        with self.assertRaises(ValueError):self.store.advance(self.f['steps'][1:3],expected_tip_hash='aa'*32)
        self.assertEqual(self.store.inspect()['height'],1)
    def test_last_bad_header_rolls_back_entire_batch(self):
        batch=copy.deepcopy(self.f['steps'][1:5]);batch[-1]['signed_header']['commit']['signatures'][-1]['signature']='AA=='
        old=list(self.store.db.iterdump())
        with self.assertRaises(ValueError):self.store.advance(batch,expected_tip_hash=self.store.inspect()['header_hash'])
        self.assertEqual(list(self.store.db.iterdump()),old)
    def test_clock_rollback_refused(self):
        self.now-=1
        with self.assertRaisesRegex(ValueError,'backwards'):self.advance()
    def test_expiry_during_verification_refuses_before_commit(self):
        old=list(self.store.db.iterdump());self.store.clock=iter([self.now,self.now+3600*10**9]).__next__
        with self.assertRaises(ValueError):self.store.advance(self.f['steps'][1:3],expected_tip_hash=self.f['policy']['initial_header_hash'])
        self.assertEqual(list(self.store.db.iterdump()),old)
    def test_callback_clock_backwards_before_commit(self):
        self.store.clock=iter([self.now,self.now-1]).__next__
        with self.assertRaises(ValueError):self.store.advance(self.f['steps'][1:3],expected_tip_hash=self.f['policy']['initial_header_hash'])
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM headers').fetchone()[0],1)
    def test_readonly_mode_refuses_advancement(self):
        self.store.close();self.store=self.open(read_only=True)
        with self.assertRaises(ValueError):self.advance()
    def test_existing_file_cannot_be_reinitialized(self):
        with self.assertRaises(FileExistsError):self.open(anchor=self.f['steps'][0])
    def test_different_policy_not_silently_adopted(self):
        p={**self.f['policy'],'trust_period_seconds':7200}
        with self.assertRaises(ValueError):ValidatorStore(self.path,self.f['genesis'],p,clock=lambda:self.now)
    def test_missing_config_not_repaired(self):
        self.store.db.execute('DELETE FROM policy');self.store.close()
        with self.assertRaises(ValueError):self.open()
    def test_unknown_wallet_database_not_changed(self):
        p=self.root/'wallet.sqlite';db=sqlite3.connect(p);db.execute('CREATE TABLE decisions(x)');db.close();p.chmod(0o600)
        before=p.read_bytes()
        with self.assertRaises(ValueError):ValidatorStore(p,self.f['genesis'],self.f['policy'])
        self.assertEqual(before,p.read_bytes())
    def test_missing_file_not_created_on_open(self):
        p=self.root/'missing.sqlite'
        with self.assertRaises(ValueError):ValidatorStore(p,self.f['genesis'],self.f['policy'])
        self.assertFalse(p.exists())
    def test_bad_anchor_not_created(self):
        p=self.root/'bad.sqlite';anchor=copy.deepcopy(self.f['steps'][0]);anchor['signed_header']['commit']['signatures'][0]['signature']='AA=='
        with self.assertRaises(ValueError):ValidatorStore(p,self.f['genesis'],self.f['policy'],anchor=anchor,clock=lambda:self.now)
        self.assertFalse(p.exists())
    def test_corrupted_body_and_index_does_not_verify(self):
        raw=copy.deepcopy(self.f['steps'][0]);raw['signed_header']['commit']['signatures'][0]['signature']='AA=='
        self.store.db.execute('UPDATE headers SET body=?',(encode(raw),))
        with self.assertRaises(ValueError):self.store.inspect()
    def test_changed_header_hash_index_refused(self):
        self.store.db.execute('UPDATE headers SET header_hash=?',('ab'*32,))
        with self.assertRaises(ValueError):self.store.inspect()
    def test_missing_middle_header_refused(self):
        self.advance();self.store.db.execute('DELETE FROM headers WHERE height=4')
        with self.assertRaises(ValueError):self.store.inspect()
    def test_equal_height_conflict_cannot_replace_tip(self):
        self.advance(3);b=copy.deepcopy(self.f['steps'][2]);b['signed_header']['header']['consensus_hash']='ae'*32;resign(self.f,b)
        before=self.store.export()
        with self.assertRaises(ValueError):self.store.advance([b],expected_tip_hash=self.store.inspect()['header_hash'])
        self.assertEqual(self.store.export(),before)
    def test_capacity_stops_without_eviction(self):
        with patch('validator_store.MAX_RECORDS',3):
            with self.assertRaises(ValueError):self.advance(4)
        self.assertEqual(self.store.inspect()['records'],1)
    def test_empty_batch_refused(self):
        with self.assertRaises(ValueError):self.store.advance([],expected_tip_hash=self.store.inspect()['header_hash'])
    def test_too_many_steps_refused(self):
        with self.assertRaises(ValueError):self.store.advance(self.f['steps']*7,expected_tip_hash=self.store.inspect()['header_hash'])
    def test_symlink_and_sidecar_alias_refused(self):
        self.store.close();wal=Path(str(self.path)+'-wal');wal.unlink(missing_ok=True);wal.symlink_to(self.path)
        with self.assertRaises(ValueError):self.open()
    def test_public_permissions_refused(self):
        self.store.close();self.path.chmod(0o644)
        with self.assertRaises(ValueError):self.open()
    def test_failed_insert_leaves_old_checkpoint(self):
        old=list(self.store.db.iterdump())
        def deny(code,*_):return sqlite3.SQLITE_DENY if code==sqlite3.SQLITE_INSERT else sqlite3.SQLITE_OK
        self.store.db.set_authorizer(deny)
        with self.assertRaises(sqlite3.DatabaseError):self.advance(4)
        self.store.db.set_authorizer(None);self.assertEqual(list(self.store.db.iterdump()),old)
    def test_two_writers_do_not_overwrite_frontier(self):
        start=self.store.inspect()['header_hash']
        def run(_):
            with self.open() as s:
                try:return s.advance(self.f['steps'][1:4],expected_tip_hash=start)['status']
                except ValueError:return 'stale-frontier'
        with ThreadPoolExecutor(max_workers=2) as p:results=list(p.map(run,range(2)))
        self.assertEqual(sorted(results),['headers-advanced','stale-frontier'])
    def crash(self,before):
        for n,data in [('genesis',self.f['genesis']),('policy',encode(self.f['policy'])),('batch',encode(self.f['steps'][1:6]))]:
            (self.root/n).write_bytes(data)
        code='''import json,os,sys
from pathlib import Path
from validator_store import ValidatorStore
p=Path(sys.argv[1]);pol=json.loads((p/'policy').read_bytes());s=ValidatorStore(p/'continuity.sqlite',(p/'genesis').read_bytes(),pol,clock=lambda:int(sys.argv[2]))
if sys.argv[3]=='before':
 def kill(sql):
  if sql=='COMMIT':os._exit(31)
 s.db.set_trace_callback(kill)
s.advance(json.loads((p/'batch').read_bytes()),expected_tip_hash=pol['initial_header_hash'])
os._exit(32)
'''
        r=subprocess.run([sys.executable,'-c',code,str(self.root),str(self.now),'before' if before else 'after'],capture_output=True,timeout=10)
        self.assertEqual(r.returncode,31 if before else 32,r.stderr)
    def test_actual_exit_before_commit_keeps_anchor(self):
        self.crash(True);self.assertEqual(self.store.inspect()['height'],1)
    def test_actual_exit_after_commit_keeps_transition(self):
        self.crash(False);self.store.close();self.store=self.open();self.assertEqual(self.store.inspect()['height'],6)
        self.advance(10);self.assertEqual(self.store.inspect()['height'],10)
    def test_no_key_or_network_access(self):
        with patch('socket.socket',side_effect=AssertionError('network')),patch('certified_wallet._load_vault',side_effect=AssertionError('key')):
            self.advance();self.store.inspect();self.store.export()

if __name__=='__main__':unittest.main()
