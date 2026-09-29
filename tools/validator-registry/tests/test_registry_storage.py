import copy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from commit_verifier import encode
from registry_rules import RegistryRules
from registry_application import RegistryApplication,verify_snapshot,write_new
from registry_fixture import fixture,schedule,apply,advance


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.g,self.admins,self.vals,self.target=fixture();self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name);self.path=self.root/'registry.sqlite'
        self.app=RegistryApplication(self.path,self.g,create=True)
    def tearDown(self):self.app.close();self.tmp.cleanup()
    def queue(self):
        raw=schedule(self.app,self.admins,self.target);apply(self.app,[raw]);return raw
    def reopen(self):self.app.close();self.app=RegistryApplication(self.path,self.g)
    def clone(self,name='restored.sqlite',snapshot=None,**kw):
        snap=self.app.export_snapshot() if snapshot is None else snapshot
        return RegistryApplication.restore_new(self.root/name,self.g,snap,
                   expected_app_hash=kw.get('expected_app_hash',self.app.info()['app_hash']),
                   expected_height=kw.get('expected_height',self.app.info()['height']))
    def test_queued_emitted_active_restart_boundaries(self):
        self.queue()
        for h,phase,epoch in ((1,'queued',0),(4,'emitted',0),(5,'emitted',0),(6,None,1)):
            advance(self.app,h);old=self.app.state();self.reopen();self.assertEqual(self.app.state(),old)
            self.assertEqual(old['epoch'],epoch);self.assertEqual(None if old['pending'] is None else old['pending']['phase'],phase)
    def test_uncommitted_finalization_never_schedules(self):
        raw=schedule(self.app,self.admins,self.target)
        self.app.finalize_block([raw],1,b'a'*32);self.reopen()
        self.assertEqual(self.app.state()['height'],0);self.assertIsNone(self.app.state()['pending'])
    def test_uncommitted_emission_regenerated_once_after_reopen(self):
        self.queue();advance(self.app,3);r=self.app.finalize_block([],4,b'a'*32);self.assertTrue(r['validator_updates'])
        self.reopen();r2=self.app.finalize_block([],4,b'a'*32);self.assertEqual(r,r2);self.app.commit()
        self.assertEqual(self.app.committed_result(4),r)
        self.assertEqual(apply(self.app)['validator_updates'],[])
    def test_repeated_finalize_same_block_is_identical(self):
        raw=schedule(self.app,self.admins,self.target)
        r1=self.app.finalize_block([raw],1,b'a'*32);r2=self.app.finalize_block([raw],1,b'a'*32)
        self.assertEqual(r1,r2);self.assertEqual(self.app.state()['height'],0)
    def test_conflicting_finalize_does_not_replace_candidate(self):
        raw=schedule(self.app,self.admins,self.target);r=self.app.finalize_block([raw],1,b'a'*32)
        with self.assertRaises(ValueError):self.app.finalize_block([raw],1,b'b'*32)
        self.app.commit();self.assertEqual(self.app.committed_result(1),r)
    def test_commit_retry_and_status_do_not_reemit(self):
        self.queue();advance(self.app,4);before=list(self.app.db.iterdump());self.app.commit();self.app.info()
        self.assertEqual(before,list(self.app.db.iterdump()));self.assertEqual(apply(self.app)['validator_updates'],[])
    def test_failed_commit_rolls_back_queue_state_and_response(self):
        raw=schedule(self.app,self.admins,self.target);before=list(self.app.db.iterdump())
        with self.assertRaises(RuntimeError):apply(self.app,[raw],fault='before_commit')
        self.assertEqual(before,list(self.app.db.iterdump()));self.app.commit();self.assertEqual(self.app.state()['sequence'],1)
    def test_snapshot_with_queued_update_resumes_exactly(self):
        self.queue();target=self.clone()
        try:
            for _ in range(6):self.assertEqual(apply(self.app),apply(target))
        finally:target.close()
    def test_snapshot_after_emission_does_not_reemit(self):
        self.queue();advance(self.app,4);target=self.clone()
        try:
            r=apply(target);self.assertEqual(r['validator_updates'],[])
            self.assertEqual(target.state()['next_validators'],self.target);apply(target)
            self.assertEqual(target.state()['epoch'],1)
        finally:target.close()
    def test_snapshot_preserves_hplusone_before_activation(self):
        self.queue();advance(self.app,5);target=self.clone()
        try:
            self.assertEqual(target.state()['active_validators'],self.g['validators']);self.assertEqual(target.state()['next_validators'],self.target)
            self.assertEqual(apply(target),apply(self.app));self.assertEqual(target.state()['epoch'],1)
        finally:target.close()
    def test_snapshot_requires_external_hash_and_height(self):
        self.queue()
        for opts in ({'expected_app_hash':'f'*64},{'expected_height':2},{'expected_height':True}):
            with self.assertRaises(ValueError):self.clone(**opts)
            self.assertFalse((self.root/'restored.sqlite').exists())
    def test_snapshot_cannot_forge_authorization_with_rehashed_state(self):
        self.queue();snap=self.app.export_snapshot();packet=json.loads(__import__('base64').b64decode(snap['blocks'][0]['transactions'][0]))
        packet['approvals'][0]['signature']='00'*64;snap['blocks'][0]['transactions'][0]=__import__('base64').b64encode(encode(packet)).decode()
        with self.assertRaises(ValueError):self.clone(snapshot=snap)
        self.assertFalse((self.root/'restored.sqlite').exists())
    def test_snapshot_cannot_omit_history_but_keep_state(self):
        self.queue();snap=self.app.export_snapshot();snap['blocks']=[]
        with self.assertRaises(ValueError):self.clone(snapshot=snap)
    def test_snapshot_rejects_boolean_comparison_trick(self):
        self.queue();snap=self.app.export_snapshot();snap['state']['sequence']=True
        with self.assertRaises(ValueError):self.clone(snapshot=snap)
    def test_snapshot_never_replaces_existing_store(self):
        self.queue();before=list(self.app.db.iterdump())
        with self.assertRaises(FileExistsError):self.clone(name='registry.sqlite')
        self.assertEqual(before,list(self.app.db.iterdump()))
    def test_rehashed_checkpoint_cannot_skip_execution(self):
        self.queue();bad=self.app.state();bad['height']=2;raw=encode(bad)
        self.app.db.execute('UPDATE registry_checkpoint SET state=?,app_hash=?',(raw,self.app.rules.state_hash(bad)))
        with self.assertRaisesRegex(ValueError,'differs from replay'):self.app.state()
    def test_saved_response_cannot_omit_validator_updates(self):
        self.queue();advance(self.app,4);r=self.app.committed_result(4);r['validator_updates']=[]
        self.app.db.execute('UPDATE registry_blocks SET result=? WHERE height=4',(encode(r),))
        with self.assertRaisesRegex(ValueError,'execution differs'):self.reopen()
    def test_configuration_deletion_not_silently_repaired(self):
        self.app.db.execute('DELETE FROM registry_config')
        with self.assertRaises(ValueError):self.reopen()
    def test_wrong_genesis_refused_without_modifying_store(self):
        self.queue();self.app.close();raw=self.path.read_bytes();other=copy.deepcopy(self.g);other['chain_id']='other'
        with self.assertRaises(ValueError):RegistryApplication(self.path,other)
        self.assertEqual(self.path.read_bytes(),raw)
    def test_other_database_never_initialized(self):
        p=self.root/'wallet.sqlite';db=sqlite3.connect(p);db.execute('CREATE TABLE decisions(x)');db.commit();db.close();p.chmod(0o600);raw=p.read_bytes()
        with self.assertRaises(ValueError):RegistryApplication(p,self.g)
        self.assertEqual(raw,p.read_bytes())
    def test_empty_existing_database_refused_without_repair(self):
        p=self.root/'empty.sqlite';p.touch(mode=0o600)
        with self.assertRaises(ValueError):RegistryApplication(p,self.g)
        self.assertEqual(p.read_bytes(),b'')
    def test_symlink_and_hardlink_refused(self):
        for name,create in (('sym',lambda p:p.symlink_to(self.path)),('hard',lambda p:os.link(self.path,p))):
            p=self.root/name;create(p)
            with self.assertRaises(ValueError):RegistryApplication(p,self.g)
            p.unlink()
    def test_alias_sidecar_refused(self):
        self.app.close();p=Path(str(self.path)+'-wal');p.unlink(missing_ok=True);p.symlink_to(self.path)
        with self.assertRaises(ValueError):RegistryApplication(self.path,self.g)
    def test_read_only_cannot_finalize_or_commit(self):
        self.queue();self.app.close();self.app=RegistryApplication(self.path,self.g,read_only=True)
        self.assertEqual(self.app.state()['sequence'],1)
        with self.assertRaises(ValueError):self.app.finalize_block([],2,b'a'*32)
        with self.assertRaises(ValueError):self.app.commit()
    def test_two_connections_cannot_commit_incompatible_h1(self):
        other=RegistryApplication(self.path,self.g);raw=schedule(self.app,self.admins,self.target)
        try:
            self.app.finalize_block([raw],1,b'a'*32);other.finalize_block([],1,b'b'*32);self.app.commit()
            with self.assertRaisesRegex(ValueError,'advanced since'):other.commit()
            self.assertEqual(other.state(),self.app.state())
        finally:other.close()
    def test_storage_fault_is_not_normal_proposal_rejection(self):
        self.app.db.execute('DELETE FROM registry_config')
        with self.assertRaises(ValueError):self.app.process_proposal([],1)
    def test_capacity_refuses_instead_of_pruning(self):
        self.queue();old=self.app.export_snapshot()
        with patch('registry_application.MAX_BLOCKS',1):
            with self.assertRaises(ValueError):self.app.finalize_block([],2,b'a'*32)
        self.assertEqual(old,self.app.export_snapshot())
    def test_exports_are_exclusive(self):
        self.queue();p=self.root/'snap.json';write_new(p,encode(self.app.export_snapshot()));before=p.read_bytes()
        with self.assertRaises(FileExistsError):write_new(p,b'{}')
        self.assertEqual(p.read_bytes(),before)
    def test_real_exit_before_commit_preserves_queued_state(self):self.crash(3,'exit_before_commit',expected_height=3)
    def test_real_exit_after_emission_keeps_recoverable_response(self):self.crash(3,'exit_after_commit',expected_height=4)
    def test_real_exit_before_activation_preserves_pending_epoch(self):self.crash(5,'exit_before_commit',expected_height=5)
    def test_real_exit_after_activation_preserves_new_epoch(self):self.crash(5,'exit_after_commit',expected_height=6)
    def crash(self,height,fault,expected_height):
        self.queue();advance(self.app,height);self.app.close();(self.root/'genesis.json').write_bytes(encode(self.g))
        code='''import json,hashlib,sys
from pathlib import Path
from registry_application import RegistryApplication
p=Path(sys.argv[1]);a=RegistryApplication(p/'registry.sqlite',json.loads((p/'genesis.json').read_bytes()))
h=a.state()['height']+1
a.finalize_block([],h,hashlib.sha256(str(h).encode()).digest());a.commit(fault=sys.argv[2])
'''
        p=subprocess.run([sys.executable,'-c',code,str(self.root),fault],capture_output=True,timeout=10)
        self.assertEqual(p.returncode,81 if fault=='exit_before_commit' else 82,p.stderr)
        self.app=RegistryApplication(self.path,self.g);s=self.app.state();self.assertEqual(s['height'],expected_height)
        if expected_height==4:self.assertTrue(self.app.committed_result(4)['validator_updates'])
        self.assertEqual(s['epoch'],1 if expected_height>=6 else 0)
        advance(self.app,7);self.assertEqual(self.app.state()['epoch'],1)

if __name__=='__main__':unittest.main()
