import copy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from commit_verifier import encode
from registry_application import RegistryApplication
from registry_rules import initial_state,state_hash,sha
from registry_fixture import fixture,schedule,cancel,block
from validator_wire import FinalizeBlock


class RegistryStorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.g,self.admins,self.vals,self.target=fixture();self.path=self.root/'registry.sqlite'
        self.app=self.open(create=True)
        self.raw=schedule(self.g,self.app.state(),self.admins[:2],self.target)
    def tearDown(self):self.app.close();self.tmp.cleanup()
    def open(self,**kw):return RegistryApplication(self.path,self.g,**kw)
    def step(self,txs=()):
        h=self.app.state()['height']+1
        result=self.app.finalize_block(list(txs),h,sha(str(h).encode()));self.app.commit();return result
    def test_finalize_has_no_durable_effect(self):
        before=list(self.app.db.iterdump())
        r=self.app.finalize_block([self.raw],1,sha(b'1'))
        self.assertEqual(r['tx_results'][0]['code'],0)
        self.assertEqual(list(self.app.db.iterdump()),before);self.assertEqual(self.app.state()['height'],0)
    def test_commit_and_reopen_preserve_queued_change(self):
        self.step([self.raw]);s=self.app.state();self.app.close();self.app=self.open()
        self.assertEqual(self.app.state(),s);self.assertEqual(s['pending']['activation_height'],5)
    def test_finalize_retry_and_commit_retry_are_idempotent(self):
        r=self.app.finalize_block([self.raw],1,sha(b'1'))
        self.assertEqual(self.app.finalize_block([self.raw],1,sha(b'1')),r)
        self.app.commit();before=list(self.app.db.iterdump())
        self.assertEqual(self.app.finalize_block([self.raw],1,sha(b'1')),r)
        self.app.commit();self.assertEqual(list(self.app.db.iterdump()),before)
    def test_conflicting_pending_or_committed_block_refused(self):
        self.app.finalize_block([self.raw],1,sha(b'1'))
        with self.assertRaises(ValueError):self.app.finalize_block([],1,sha(b'1'))
        self.app.commit()
        with self.assertRaises(ValueError):self.app.finalize_block([self.raw],1,sha(b'other'))
    def test_restart_before_commit_discards_prepared_update(self):
        self.app.finalize_block([self.raw],1,sha(b'1'));self.app.close();self.app=self.open()
        self.assertEqual(self.app.state()['nonce'],0);self.assertIsNone(self.app.pending)
    def test_restart_after_emission_does_not_emit_again(self):
        self.step([self.raw]);self.step();r=self.step();self.assertTrue(r['validator_updates'])
        self.app.close();self.app=self.open();r=self.step()
        self.assertEqual(r['validator_updates'],[]);self.assertEqual(self.app.state()['epoch'],0)
        self.step();self.assertEqual(self.app.state()['epoch'],1)
    def test_field_three_update_wire_matches_computed_result(self):
        self.step([self.raw]);self.step()
        r=self.app.finalize_block([],3,sha(b'3'));wire=self.app.update_wire()
        parsed=FinalizeBlock.FromString(wire)
        self.assertEqual([{'public_key':v.pub_key.ed25519.hex(),'power':v.power} for v in parsed.validator_updates],r['validator_updates'])
    def test_rehashing_last_output_cannot_fake_update(self):
        self.step([self.raw]);self.step();self.step()
        last=json.loads(self.app.db.execute('SELECT last_block FROM checkpoint').fetchone()[0])
        last['result']['validator_updates']=[]
        self.app.db.execute('UPDATE checkpoint SET last_block=?',(encode(last),))
        with self.assertRaises(ValueError):self.app.state()
    def test_altered_state_with_recomputed_hash_is_refused(self):
        self.step([self.raw]);s=self.app.state();s['epoch']=1
        self.app.db.execute('UPDATE checkpoint SET state=?,app_hash=?',(encode(s),state_hash(s)))
        with self.assertRaises(ValueError):self.app.state()
    def test_read_only_store_refuses_finalize_commit_and_restore(self):
        self.step([self.raw]);s=self.app.state();self.app.close();self.app=self.open(read_only=True)
        with self.assertRaises(ValueError):self.app.finalize_block([],2,sha(b'2'))
        with self.assertRaises(ValueError):self.app.commit()
        with self.assertRaises(ValueError):self.app.install_snapshot(s,expected_app_hash=state_hash(s))
    def test_foreign_wallet_database_is_not_initialized_or_modified(self):
        p=self.root/'wallet.sqlite';d=sqlite3.connect(p);d.execute('CREATE TABLE decisions(id INTEGER)');d.commit();d.close();p.chmod(0o600)
        before=p.read_bytes()
        with self.assertRaises(ValueError):RegistryApplication(p,self.g)
        self.assertEqual(p.read_bytes(),before)
    def test_empty_existing_file_is_not_repaired(self):
        self.app.close();self.path.unlink();self.path.touch(mode=0o600)
        with self.assertRaises(ValueError):self.open()
        self.assertEqual(self.path.stat().st_size,0)
    def test_creation_cannot_overwrite_store(self):
        with self.assertRaises(FileExistsError):self.open(create=True)
    def test_missing_policy_does_not_reset_state(self):
        self.step([self.raw]);self.app.db.execute('DELETE FROM configuration')
        with self.assertRaises(ValueError):self.app.state()
    def test_wrong_genesis_refused_on_open(self):
        self.app.close();g=copy.deepcopy(self.g);g['chain_id']='another-chain'
        with self.assertRaises(ValueError):RegistryApplication(self.path,g)
    def test_sidecar_symlink_and_file_hardlink_refused(self):
        self.app.close();side=Path(str(self.path)+'-wal');side.unlink(missing_ok=True);side.symlink_to(self.path)
        with self.assertRaises(ValueError):self.open()
        side.unlink();os.link(self.path,self.root/'alias')
        with self.assertRaises(ValueError):self.open()
    def test_world_readable_store_refused(self):
        self.app.close();self.path.chmod(0o644)
        with self.assertRaises(ValueError):self.open()
    def test_failed_database_write_rolls_back_complete_block(self):
        self.app.finalize_block([self.raw],1,sha(b'1'));before=list(self.app.db.iterdump())
        self.app.db.set_authorizer(lambda code,*_:sqlite3.SQLITE_DENY if code==sqlite3.SQLITE_UPDATE else sqlite3.SQLITE_OK)
        with self.assertRaises(sqlite3.DatabaseError):self.app.commit()
        self.app.db.set_authorizer(None)
        self.assertEqual(list(self.app.db.iterdump()),before)
        self.app.commit();self.assertEqual(self.app.state()['nonce'],1)
    def test_concurrent_different_finalizations_cannot_overwrite(self):
        with self.open() as other:
            self.app.finalize_block([self.raw],1,sha(b'1'))
            other.finalize_block([],1,sha(b'other'))
            self.app.commit()
            with self.assertRaises(ValueError):other.commit()
        self.assertEqual(self.app.state()['nonce'],1)
    def test_identical_parallel_commits_converge(self):
        with self.open() as other:
            self.app.finalize_block([self.raw],1,sha(b'1'));other.finalize_block([self.raw],1,sha(b'1'))
            self.app.commit();self.assertEqual(other.commit()['status'],'already-committed')
    def test_mutating_returned_result_cannot_change_pending_state(self):
        result=self.app.finalize_block([self.raw],1,sha(b'1'));result['app_hash']='00'*32;result['tx_results'].clear()
        self.app.commit();self.assertEqual(self.app.state()['nonce'],1)
    def test_snapshot_at_each_boundary_preserves_future_timing(self):
        self.step([self.raw])
        for h in range(1,7):
            s=self.app.state();p=self.root/f'target-{h}.sqlite'
            with RegistryApplication(p,self.g,create=True) as target:
                report=target.install_snapshot(s,expected_app_hash=state_hash(s))
                self.assertFalse(report['consensus_verified_by_this_operation'])
                self.assertEqual(target.state(),s)
                a=self.app.finalize_block([],h+1,sha(str(h+1).encode()))
                b=target.finalize_block([],h+1,sha(str(h+1).encode()))
                self.assertEqual(a,b);target.commit();self.app.commit()
                self.assertEqual(target.state(),self.app.state())
    def test_restore_refuses_wrong_hash_or_nonempty_target(self):
        self.step([self.raw]);s=self.app.state()
        with RegistryApplication(self.root/'target.sqlite',self.g,create=True) as target:
            with self.assertRaises(ValueError):target.install_snapshot(s,expected_app_hash='00'*32)
            self.assertEqual(target.state()['height'],0)
            target.install_snapshot(s,expected_app_hash=state_hash(s))
            with self.assertRaises(ValueError):target.install_snapshot(s,expected_app_hash=state_hash(s))
    def test_snapshot_does_not_invent_executed_block_result(self):
        self.step([self.raw]);s=self.app.state()
        with RegistryApplication(self.root/'target.sqlite',self.g,create=True) as target:
            target.install_snapshot(s,expected_app_hash=state_hash(s))
            self.assertEqual(target.db.execute('SELECT last_block FROM checkpoint').fetchone()[0],b'null')
            with self.assertRaises(ValueError):target.finalize_block([self.raw],1,sha(b'1'))
    def test_no_pending_commit_is_not_activation(self):
        self.step([self.raw]);before=list(self.app.db.iterdump());self.app.commit()
        self.assertEqual(list(self.app.db.iterdump()),before)
    def test_bootstrap_marker_corruption_after_continuation_is_refused(self):
        self.step([self.raw]);s=self.app.state()
        with RegistryApplication(self.root/'target.sqlite',self.g,create=True) as target:
            target.install_snapshot(s,expected_app_hash=state_hash(s))
            target.finalize_block([],2,sha(b'2'));target.commit()
            target.db.execute('UPDATE bootstrap SET app_hash=?',('00'*32,))
            with self.assertRaises(ValueError):target.state()
    def test_snapshot_failure_rolls_back_marker_and_checkpoint(self):
        self.step([self.raw]);s=self.app.state()
        with RegistryApplication(self.root/'target.sqlite',self.g,create=True) as target:
            before=list(target.db.iterdump())
            target.db.set_authorizer(lambda code,*_:sqlite3.SQLITE_DENY if code==sqlite3.SQLITE_INSERT else sqlite3.SQLITE_OK)
            with self.assertRaises(sqlite3.DatabaseError):target.install_snapshot(s,expected_app_hash=state_hash(s))
            target.db.set_authorizer(None)
            self.assertEqual(list(target.db.iterdump()),before)
    def child(self,when):
        (self.root/'g.json').write_bytes(encode(self.g));(self.root/'command.json').write_bytes(self.raw)
        code='''import json,os,sys
from pathlib import Path
from registry_application import RegistryApplication
from registry_rules import sha
p=Path(sys.argv[1]);a=RegistryApplication(p/'registry.sqlite',json.loads((p/'g.json').read_bytes()))
a.finalize_block([(p/'command.json').read_bytes()],1,sha(b'1'))
if sys.argv[2]=='before':
 def kill(sql):
  if sql=='COMMIT':os._exit(41)
 a.db.set_trace_callback(kill)
a.commit()
os._exit(42)
'''
        r=subprocess.run([sys.executable,'-c',code,str(self.root),when],capture_output=True,timeout=10)
        self.assertEqual(r.returncode,41 if when=='before' else 42,r.stderr)
    def test_actual_exit_before_commit_preserves_old_state(self):
        self.child('before');self.assertEqual(self.app.state()['height'],0)
    def test_actual_exit_after_commit_preserves_new_state(self):
        self.child('after');self.assertEqual(self.app.state()['height'],1)
        self.assertEqual(self.app.state()['pending']['emission_height'],3)

if __name__=='__main__':unittest.main()
