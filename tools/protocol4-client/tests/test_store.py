"""Actual private SQLite persistence/process tests; no node network or live money."""
import copy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch

from block_application import encode
from commit_verifier import load_json
from p4_evidence import content_id, nanos, verify_evidence
from p4_read_store import P4ReadStore, write_new
from p4_fixture import build, bundle, rechain, sign_header
from validator_sets_core import ValidatorSet


class StoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.c = build()
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.path = self.root / 'read.sqlite'; self.now = self.c['now_ns']
        self.s = self.open(create=True)
    def tearDown(self): self.s.close(); self.temp.cleanup()
    def open(self, **args):
        return P4ReadStore(self.path, self.c['genesis'], self.c['policy'], clock=lambda:self.now, **args)
    def ingest(self, height=3, store=None, tip=None):
        return (self.s if store is None else store).import_evidence(bundle(self.c,height), expected_tip=tip)
    def all_rows(self): return list(self.s.db.iterdump())

    def test_new_store_is_unavailable_not_zero_funds(self):
        self.assertIsNone(self.s.current())
        with self.assertRaises(ValueError): self.s.account(self.c['payer'])
    def test_reopen_and_extend_through_queued_emitted_and_active_changes(self):
        tip=None
        for h, epoch in ((3,0),(5,0),(8,1),(16,2)):
            r=self.ingest(h,tip=tip); tip=r['evidence_id']
            self.s.close();self.s=self.open()
            view=self.s.current();self.assertEqual(view['registry_epoch'],epoch)
            self.assertEqual(view['state_height'],h)
        self.assertEqual(self.s.account(self.c['payer'])['account']['recorded_balance'],'874')
        self.assertEqual(self.s.db.execute('SELECT count(*) FROM observations').fetchone()[0],4)
    def test_exact_duplicate_keeps_original_records_and_identity(self):
        r=self.ingest();before=self.all_rows()
        again=self.ingest(tip=r['evidence_id'])
        self.assertEqual(again['status'],'already_recorded');self.assertEqual(again['evidence_id'],r['evidence_id'])
        self.assertEqual(self.all_rows(),before)
    def test_valid_alternative_quorum_keeps_existing_certificate(self):
        r=self.ingest();before=self.all_rows();e=bundle(self.c,3)
        for entry in e['headers']:
            entry['signed_header']=sign_header(entry['signed_header']['header'],ValidatorSet.parse(entry['validators']),self.c['keys'],[2,2,2,1])
        result=self.s.import_evidence(e,expected_tip=r['evidence_id'])
        self.assertEqual(result['status'],'already_recorded');self.assertEqual(self.all_rows(),before)
    def test_stale_expected_tip_cannot_advance_checkpoint(self):
        self.ingest();before=self.all_rows()
        with self.assertRaisesRegex(ValueError,'tip changed'):self.ingest(8)
        self.assertEqual(self.all_rows(),before)
    def test_unrelated_expected_tip_refused(self):
        r=self.ingest()
        with self.assertRaisesRegex(ValueError,'tip changed'):self.ingest(8,tip='0'*64)
        self.assertEqual(self.s.current()['evidence_id'],r['evidence_id'])
    def test_rollback_refused_without_erasing_evidence(self):
        r=self.ingest(16);before=self.all_rows()
        with self.assertRaisesRegex(ValueError,'rollback'):self.ingest(3,tip=r['evidence_id'])
        self.assertEqual(self.all_rows(),before)
    def test_same_height_valid_signed_fork_refused(self):
        r=self.ingest(8);e=bundle(self.c,8)
        e['headers'][4]['signed_header']['header']['consensus_hash']='EC'*32
        rechain(e,self.c['keys'])
        with self.assertRaisesRegex(ValueError,'block identity changed'):
            self.s.import_evidence(e,expected_tip=r['evidence_id'])
        self.assertEqual(self.s.current()['evidence_id'],r['evidence_id'])
    def test_later_valid_signed_fork_cannot_replace_prefix(self):
        r=self.ingest(3);e=bundle(self.c,16)
        e['headers'][1]['signed_header']['header']['consensus_hash']='DD'*32
        rechain(e,self.c['keys'])
        with self.assertRaisesRegex(ValueError,'block identity changed'):
            self.s.import_evidence(e,expected_tip=r['evidence_id'])
        self.assertEqual(self.s.current()['state_height'],3)
    def test_old_evidence_export_is_byte_identical_after_advancing(self):
        first=self.ingest();raw=encode(self.s.export(first['evidence_id']))
        self.ingest(16,tip=first['evidence_id'])
        self.assertEqual(encode(self.s.export(first['evidence_id'])),raw)
    def test_expired_policy_does_not_delete_records_or_reopen_authority(self):
        self.ingest();before=self.all_rows()
        self.now=nanos(self.c['policy']['anchor_time'])+3600*10**9
        with self.assertRaisesRegex(ValueError,'currently valid'):self.s.current()
        self.assertEqual(self.all_rows(),before)
    def test_clock_rollback_refused(self):
        self.ingest();self.now-=1
        with self.assertRaisesRegex(ValueError,'clock regressed'):self.s.current()
    def test_expiration_during_import_rolls_back_without_new_record(self):
        r=self.ingest();before=self.all_rows()
        expiry=nanos(self.c['policy']['anchor_time'])+3600*10**9
        values=iter([self.now,self.now,expiry])
        self.s.clock=lambda:next(values)
        with self.assertRaisesRegex(ValueError,'currently valid'):self.ingest(8,tip=r['evidence_id'])
        self.assertEqual(self.all_rows(),before)
    def test_expiration_during_noop_import_is_not_accepted(self):
        r=self.ingest();before=self.all_rows()
        expiry=nanos(self.c['policy']['anchor_time'])+3600*10**9
        values=iter([self.now,self.now,expiry]);self.s.clock=lambda:next(values)
        with self.assertRaisesRegex(ValueError,'currently valid'):self.ingest(3,tip=r['evidence_id'])
        self.assertEqual(self.all_rows(),before)
    def test_caller_mutation_after_check_does_not_change_persisted_evidence(self):
        e=bundle(self.c,3);expected=content_id(e)
        def verify_then_mutate(*a,**kw):
            result=verify_evidence(*a,**kw);e['state']['native']['accounts'][0][4]+=10000
            return result
        with patch('p4_read_store.verify_evidence',side_effect=verify_then_mutate):
            result=self.s.import_evidence(e,expected_tip=None)
        self.assertEqual(result['evidence_id'],expected)
        self.assertEqual(content_id(self.s.export(expected)),expected)
    def test_saved_evidence_rehashed_after_signature_tampering_is_rejected(self):
        self.ingest();e=bundle(self.c,3)
        e['headers'][1]['signed_header']['commit']['signatures'][0]['signature']='AA=='
        self.s.db.execute('UPDATE observations SET evidence_id=?,payload=?',(content_id(e),encode(e)))
        with self.assertRaises(ValueError):self.s.current()
    def test_saved_height_cannot_override_reverified_state(self):
        self.ingest();self.s.db.execute('UPDATE observations SET height=4')
        with self.assertRaisesRegex(ValueError,'metadata differs'):self.s.current()
    def test_broken_parent_digest_refused(self):
        r=self.ingest();self.ingest(8,tip=r['evidence_id'])
        self.s.db.execute('UPDATE observations SET parent_id=? WHERE seq=2',('0'*64,))
        with self.assertRaisesRegex(ValueError,'lineage'):self.s.current()
    def test_external_policy_cannot_be_changed_on_reopen(self):
        self.ingest();self.s.close()
        p={**self.c['policy'],'trust_period_seconds':7200}
        with self.assertRaisesRegex(ValueError,'policy differs'):
            P4ReadStore(self.path,self.c['genesis'],p,clock=lambda:self.now)
    def test_missing_config_cannot_be_silently_repaired(self):
        self.s.db.execute('DELETE FROM config');self.s.close()
        with self.assertRaisesRegex(ValueError,'policy differs'):self.open()
    def test_wallet_database_not_initialized_or_modified(self):
        path=self.root/'wallet.sqlite';db=sqlite3.connect(path);db.execute('CREATE TABLE decisions(secret TEXT)');db.close();path.chmod(0o600)
        before=path.read_bytes()
        with self.assertRaises(ValueError):P4ReadStore(path,self.c['genesis'],self.c['policy'])
        self.assertEqual(path.read_bytes(),before)
    def test_empty_file_not_repaired(self):
        path=self.root/'empty.sqlite';path.touch(mode=0o600)
        with self.assertRaises(ValueError):P4ReadStore(path,self.c['genesis'],self.c['policy'])
        self.assertEqual(path.read_bytes(),b'')
    def test_existing_store_not_overwritten_by_init(self):
        self.ingest();before=self.all_rows()
        with self.assertRaises(FileExistsError):self.open(create=True)
        self.assertEqual(self.all_rows(),before)
    def test_symlink_database_or_sidecar_refused(self):
        self.s.close();path=self.root/'link.sqlite';path.symlink_to(self.path)
        with self.assertRaises(ValueError):P4ReadStore(path,self.c['genesis'],self.c['policy'])
        sidecar=Path(str(self.path)+'-wal');sidecar.unlink(missing_ok=True);sidecar.symlink_to(self.path)
        with self.assertRaises(ValueError):self.open()
    def test_hardlink_or_group_readable_file_refused(self):
        self.s.close();alias=self.root/'alias.sqlite';os.link(self.path,alias)
        with self.assertRaises(ValueError):self.open()
        alias.unlink();self.path.chmod(0o640)
        with self.assertRaises(ValueError):self.open()
    def test_readonly_query_does_not_change_logical_records(self):
        self.ingest(16);before=self.all_rows()
        with self.open(read_only=True) as s:
            self.assertEqual(s.account(self.c['payer'])['account']['recorded_balance'],'874')
            self.assertEqual(s.receipt(self.c['wires']['after'],payer=self.c['payer'])['status'],'recorded')
            with self.assertRaises(ValueError):s.import_evidence(bundle(self.c,16),expected_tip=s.current()['evidence_id'])
        self.assertEqual(self.all_rows(),before)
    def test_capacity_refuses_without_eviction(self):
        r=self.ingest();before=self.all_rows()
        with patch('p4_read_store.MAX_RECORDS',1):
            with self.assertRaisesRegex(ValueError,'capacity reached'):self.ingest(8,tip=r['evidence_id'])
        self.assertEqual(self.all_rows(),before)
    def test_failed_sql_write_preserves_old_checkpoint(self):
        r=self.ingest();before=self.all_rows()
        self.s.db.set_authorizer(lambda action,*_: sqlite3.SQLITE_DENY if action==sqlite3.SQLITE_INSERT else sqlite3.SQLITE_OK)
        with self.assertRaises(sqlite3.DatabaseError):self.ingest(8,tip=r['evidence_id'])
        self.s.db.set_authorizer(None);self.assertEqual(self.all_rows(),before)
    def test_two_importers_cannot_both_replace_reviewed_tip(self):
        r=self.ingest()
        def work(_):
            with self.open() as store:
                try:return self.ingest(8,store=store,tip=r['evidence_id'])['status']
                except ValueError:return 'stale-tip-refused'
        with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(work,range(2)))
        self.assertEqual(sorted(results),['recorded','stale-tip-refused'])
        self.assertEqual(self.s.db.execute('SELECT count(*) FROM observations').fetchone()[0],2)
    def test_export_refuses_overwriting_without_discarding_evidence(self):
        r=self.ingest();output=self.root/'evidence.json';write_new(output,encode(self.s.export(r['evidence_id'])))
        original=output.read_bytes()
        with self.assertRaises(FileExistsError):write_new(output,b'{}')
        self.assertEqual(output.read_bytes(),original);self.assertEqual(self.s.current()['evidence_id'],r['evidence_id'])
    def test_unknown_receipt_is_not_permission_to_retry(self):
        self.ingest(3)
        result=self.s.receipt(self.c['wires']['after'],payer=self.c['payer'])
        self.assertEqual(result['status'],'unavailable');self.assertFalse(result['historical_absence_proven'])
        self.assertFalse(result['wallet_reservations_changed'])
    def crash(self, after):
        first=self.ingest();(self.root/'genesis.json').write_bytes(self.c['genesis'])
        (self.root/'policy.json').write_bytes(encode(self.c['policy']))
        (self.root/'evidence.json').write_bytes(encode(bundle(self.c,16)))
        code='''import json,os,sys
from pathlib import Path
from p4_read_store import P4ReadStore
p=Path(sys.argv[1]);s=P4ReadStore(p/'read.sqlite',(p/'genesis.json').read_bytes(),json.loads((p/'policy.json').read_bytes()),clock=lambda:int(sys.argv[3]))
if sys.argv[4]=='before':
 def stop(sql):
  if sql=='COMMIT':os._exit(41)
 s.db.set_trace_callback(stop)
s.import_evidence(json.loads((p/'evidence.json').read_bytes()),expected_tip=sys.argv[2])
os._exit(42)
'''
        result=subprocess.run([sys.executable,'-c',code,str(self.root),first['evidence_id'],str(self.now),'after' if after else 'before'],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,42 if after else 41,result.stderr)
    def test_actual_child_exit_before_commit_preserves_old_tip(self):
        self.crash(False);self.s.close();self.s=self.open();self.assertEqual(self.s.current()['state_height'],3)
        self.assertEqual(self.s.db.execute('SELECT count(*) FROM observations').fetchone()[0],1)
    def test_actual_child_exit_after_commit_preserves_complete_new_tip(self):
        self.crash(True);self.s.close();self.s=self.open();self.assertEqual(self.s.current()['state_height'],16)
        self.assertEqual(self.s.db.execute('SELECT count(*) FROM observations').fetchone()[0],2)


if __name__ == '__main__': unittest.main()
