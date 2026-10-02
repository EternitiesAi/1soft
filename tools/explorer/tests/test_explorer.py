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

from commit_verifier import encode,header_hash
from certificate_fixture import make_commit
from explorer_index import ExplorerIndex,ExplorerError,sha,MAX_INPUT
from explorer_web import render
from fixture_explorer import scenario,bundle,pin

ROOT=Path(__file__).resolve().parents[1]

class IndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.c=scenario()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.path=self.root/'index.sqlite'
        self.x=self.open(create=True)
    def tearDown(self):self.x.close();self.tmp.cleanup()
    def open(self,**args):return ExplorerIndex(self.path,self.c['genesis'],self.c['genesis_sha256'],**args)
    def start(self,at=12,bodies=True):return self.x.ingest(bundle(self.c,at,bodies=bodies),initial_header_hash=pin(self.c,at))
    def test_empty_index_is_unavailable_not_zero_balances(self):self.assertIsNone(self.x.current())
    def test_first_import_requires_external_anchor(self):
        with self.assertRaises(ValueError):self.x.ingest(bundle(self.c,12))
        self.assertIsNone(self.x.current())
    def test_wrong_pin_is_refused_without_new_index(self):
        with self.assertRaises(ValueError):self.x.ingest(bundle(self.c,12),initial_header_hash='0'*64)
        self.assertIsNone(self.x.current())
    def test_ingest_native_state_accounts_receipts_and_blocks(self):
        self.start(24);v=self.x.current()
        self.assertEqual((v['state_height'],v['anchor_height'],v['transaction_count'],v['indexed_body_count']),(24,25,24,24))
        self.assertEqual(v['supply_units'],'2500000');self.assertEqual(v['fee_pool_units'],'48')
        self.assertEqual(v['budgets'][0]['spent'],'483')
    def test_anchor_block_not_mislabeled_executed(self):
        self.start(12);v=self.x.current();self.assertEqual(max(b['height'] for b in v['blocks']),12)
        self.assertEqual(v['anchor_height'],13)
    def test_revoked_grant_is_retained_not_active(self):
        self.start(24);v=self.x.current();atlas=next(g for g in v['grants'] if g['label']=='atlas')
        self.assertTrue(atlas['revoked']);self.assertFalse(atlas['active_at_next_height'])
        self.assertEqual(atlas['spent'],'133')
    def test_pending_wallet_authority_not_claimed(self):
        self.start();v=self.x.current()
        self.assertFalse(v['wallet_pending_debits_included']);self.assertFalse(v['latest_state_guaranteed'])
        self.assertFalse(v['live_validator_status_established'])
        self.assertTrue(all(v['live_online_status'] is None for v in v['validators']))
    def test_reopen_extends_same_index(self):
        self.start();self.x.close();self.x=self.open();self.x.ingest(bundle(self.c,24,first=13))
        self.assertEqual(self.x.current()['transaction_count'],24)
    def test_identical_import_is_idempotent(self):
        self.start();old=list(self.x.db.iterdump());r=self.start()
        self.assertEqual(r['status'],'already_indexed');self.assertEqual(list(self.x.db.iterdump()),old)
    def test_rollback_refused_and_old_state_preserved(self):
        self.start(24);old=list(self.x.db.iterdump())
        with self.assertRaisesRegex(ValueError,'rollback'):self.start(12)
        self.assertEqual(list(self.x.db.iterdump()),old)
    def test_different_valid_signature_subset_for_same_block_is_not_a_fork(self):
        self.start();b=bundle(self.c,12)
        for i, old in enumerate(b['headers']):
            b['headers'][i]=make_commit(old['header'],self.c['trust'],self.c['validator_keys'],flags=[2,2,2,1])
        b['state_commit']=b['headers'][-1]
        result=self.x.ingest(b)
        self.assertEqual(result['status'],'already_indexed')
        self.assertEqual(self.x.current()['anchor_hash'],pin(self.c,12))
    def test_unverified_rpc_block_extras_not_materialized(self):
        b=bundle(self.c,12);b['blocks'][0]['block']['extra_unverified_field']='not-evidence'
        self.x.ingest(b,initial_header_hash=pin(self.c,12))
        self.assertNotIn('extra_unverified_field',self.x.evidence()['blocks'][0]['block'])
    def test_missing_continuation_refused(self):
        self.start()
        with self.assertRaises(ValueError):self.x.ingest(bundle(self.c,24,first=20))
        self.assertEqual(self.x.current()['state_height'],12)
    def test_same_height_conflict_refused(self):
        self.start();b=bundle(self.c,12)
        sh=b['state_commit'];h=sh['header'];h['consensus_hash']='ba'*32
        altered=make_commit(h,self.c['trust'],self.c['validator_keys']);b['headers'][-1]=altered;b['state_commit']=altered
        with self.assertRaisesRegex(ValueError,'conflict'):self.x.ingest(b)
        self.assertEqual(self.x.current()['anchor_hash'],pin(self.c,12))
    def test_wrong_supplied_pin_not_ignored_on_nonempty_index(self):
        self.start()
        with self.assertRaises(ValueError):self.x.ingest(bundle(self.c,24,first=13),initial_header_hash='0'*64)
        self.assertEqual(self.x.current()['state_height'],12)
    def test_forged_commit_refused(self):
        b=bundle(self.c,12);b['headers'][3]['commit']['signatures'][0]['signature']='AA=='
        with self.assertRaises(ValueError):self.x.ingest(b,initial_header_hash=pin(self.c,12))
        self.assertIsNone(self.x.current())
    def test_altered_state_refused(self):
        b=bundle(self.c,12);b['state']['native']['accounts'][0][4]+=1
        with self.assertRaises(ValueError):self.x.ingest(b,initial_header_hash=pin(self.c,12))
    def test_signed_but_broken_parent_link_refused(self):
        b=bundle(self.c,12);h=b['headers'][3]['header'];h['last_block_id']['parts']['hash']='ab'*32
        b['headers'][3]=make_commit(h,self.c['trust'],self.c['validator_keys'])
        with self.assertRaises(ValueError):self.x.ingest(b,initial_header_hash=pin(self.c,12))
    def test_changed_block_body_refused(self):
        b=bundle(self.c,12);b['blocks'][2]['block']['data']['txs']=[]
        with self.assertRaises(ValueError):self.x.ingest(b,initial_header_hash=pin(self.c,12))
    def test_duplicate_block_body_refused(self):
        b=bundle(self.c,12);b['blocks'].append(b['blocks'][0])
        with self.assertRaises(ValueError):self.x.ingest(b,initial_header_hash=pin(self.c,12))
    def test_missing_body_is_unknown_not_empty(self):
        self.start(bodies=False);v=self.x.current()
        self.assertEqual(v['indexed_body_count'],0)
        self.assertTrue(all(b['included_transaction_count'] is None for b in v['blocks']))
        self.assertTrue(all(not t['block_inclusion_verified'] for t in v['transactions']))
    def test_bodies_can_be_added_to_same_checkpoint(self):
        self.start(bodies=False);self.start(bodies=True)
        self.assertEqual(self.x.current()['indexed_body_count'],12)
    def test_rehashed_projection_corruption_does_not_change_displayed_balance(self):
        self.start();raw=self.x.db.execute('SELECT view FROM current').fetchone()[0];v=json.loads(raw)
        v['accounts'][0]['balance']='999999999';raw=encode(v)
        self.x.db.execute('UPDATE current SET view=?,view_hash=?',(raw,sha(raw)))
        with self.assertRaisesRegex(ValueError,'derived index'):self.x.current()
    def test_rehashed_evidence_corruption_is_reverified(self):
        self.start();e=self.x.evidence();e['state_commit']['commit']['signatures'][0]['signature']='AA=='
        raw=encode(e);self.x.db.execute('UPDATE current SET evidence=?,evidence_hash=?',(raw,sha(raw)))
        with self.assertRaises(ValueError):self.x.current()
    def test_unrecognized_existing_database_untouched(self):
        p=self.root/'wallet.sqlite';db=sqlite3.connect(p);db.execute('CREATE TABLE decisions(x TEXT)');db.close();p.chmod(0o600)
        before=p.read_bytes()
        with self.assertRaises(ValueError):ExplorerIndex(p,self.c['genesis'],self.c['genesis_sha256'])
        self.assertEqual(before,p.read_bytes())
    def test_empty_existing_file_not_repaired(self):
        self.x.close();self.path.unlink();self.path.touch(mode=0o600)
        with self.assertRaises(ValueError):self.open()
        self.assertEqual(self.path.read_bytes(),b'')
    def test_read_only_mode_cannot_ingest(self):
        self.start();self.x.close();self.x=self.open(read_only=True)
        with self.assertRaises(ValueError):self.x.ingest(bundle(self.c,24,first=13))
        self.assertEqual(self.x.current()['state_height'],12)
    def test_output_and_sidecars_must_be_private_regular_files(self):
        self.x.close();p=Path(str(self.path)+'-wal');p.unlink(missing_ok=True);p.symlink_to(self.path)
        with self.assertRaises(ValueError):self.open()
    def test_failed_commit_keeps_existing_checkpoint(self):
        self.start();old=list(self.x.db.iterdump())
        def deny(code,*_):return sqlite3.SQLITE_DENY if code==sqlite3.SQLITE_INSERT else sqlite3.SQLITE_OK
        self.x.db.set_authorizer(deny)
        with self.assertRaises(sqlite3.DatabaseError):self.x.ingest(bundle(self.c,24,first=13))
        self.x.db.set_authorizer(None);self.assertEqual(list(self.x.db.iterdump()),old)
    def test_two_importers_are_idempotent(self):
        self.start()
        def go(_):
            with self.open() as x:return x.ingest(bundle(self.c,24,first=13))['status']
        with ThreadPoolExecutor(max_workers=2) as pool:r=list(pool.map(go,range(2)))
        self.assertEqual(sorted(r),['already_indexed','indexed'])
    def test_config_corruption_does_not_reset_to_fresh_index(self):
        self.start();self.x.db.execute('DELETE FROM config')
        with self.assertRaises(ValueError):self.x.current()
    def test_wrong_genesis_refused_on_open(self):
        with self.assertRaises(ValueError):ExplorerIndex(self.path,self.c['genesis'],'0'*64)
    def test_large_amounts_preserved_as_decimal_strings(self):
        c=scenario(blocks=6,large_balance=True);p=self.root/'large.sqlite'
        with ExplorerIndex(p,c['genesis'],c['genesis_sha256'],create=True) as x:
            x.ingest(bundle(c),initial_header_hash=pin(c));v=x.current()
            self.assertEqual(v['supply_units'],str(2**53-1))
            self.assertTrue(all(type(a['balance']) is str for a in v['accounts']))
    def test_flat_protocol_one_and_two_supported_without_invented_budgets(self):
        for protocol in (1,2):
            c=scenario(blocks=6,protocol=protocol);p=self.root/f'p{protocol}.sqlite'
            with ExplorerIndex(p,c['genesis'],c['genesis_sha256'],create=True) as x:
                x.ingest(bundle(c),initial_header_hash=pin(c));v=x.current()
                self.assertEqual(v['state_commitment'],'legacy-flat-v1');self.assertEqual(v['budgets'],[])
    def test_index_capacity_refuses_without_erasing_old_history(self):
        self.start();old=list(self.x.db.iterdump())
        with patch('explorer_index.MAX_INDEX_HEADERS',13):
            with self.assertRaises(ValueError):self.x.ingest(bundle(self.c,24,first=13))
        self.assertEqual(list(self.x.db.iterdump()),old)
    def test_extra_fields_refused(self):
        b=bundle(self.c,12);b['paid']=True
        with self.assertRaises(ValueError):self.x.ingest(b,initial_header_hash=pin(self.c,12))
    def test_renderer_escapes_untrusted_data_and_has_no_remote_assets(self):
        self.start();v=self.x.current();v['chain_id']='</script><img src=x onerror=alert(1)>'
        html=render(v).decode();self.assertNotIn('<img src=x',html)
        self.assertIn('\\u003c/script',html);self.assertNotIn('src="https://',html)
    def test_index_does_not_call_network_or_load_wallet_keys(self):
        with patch('socket.socket',side_effect=AssertionError('network forbidden')),patch('certified_wallet._load_vault',side_effect=AssertionError('keys forbidden')):
            self.start();self.assertEqual(self.x.current()['transaction_count'],12)
    def test_existing_index_not_overwritten_by_init(self):
        self.start()
        with self.assertRaises(FileExistsError):self.open(create=True)
        self.assertEqual(self.x.current()['state_height'],12)
    def _crash(self,before):
        self.start();(self.root/'g.json').write_bytes(self.c['genesis']);(self.root/'b.json').write_bytes(encode(bundle(self.c,24,first=13)))
        code='''import json,os,sys
from pathlib import Path
from explorer_index import ExplorerIndex
p=Path(sys.argv[1]);x=ExplorerIndex(p/'index.sqlite',(p/'g.json').read_bytes(),sys.argv[2])
if sys.argv[3]=='before':
 def kill(sql):
  if sql=='COMMIT':os._exit(41)
 x.db.set_trace_callback(kill)
x.ingest(json.loads((p/'b.json').read_bytes()))
os._exit(42)
'''
        p=subprocess.run([sys.executable,'-c',code,str(self.root),self.c['genesis_sha256'],'before' if before else 'after'],capture_output=True,timeout=10)
        self.assertEqual(p.returncode,41 if before else 42,p.stderr)
    def test_actual_process_exit_before_commit_keeps_old_snapshot(self):
        self._crash(True);self.assertEqual(self.x.current()['state_height'],12)
    def test_actual_process_exit_after_commit_keeps_new_snapshot(self):
        self._crash(False);self.assertEqual(self.x.current()['state_height'],24)

if __name__=='__main__':unittest.main()
