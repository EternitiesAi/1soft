"""Native application/index integration; no consensus, banking or Resident data."""
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from block_application import BlockApplication, application_hash, encode, transaction_id
from native_core import NativeLedger, Reject, canonical, digest, public, sign
from state_tree import StateTree, ProofError, make_witness
from test_native_budgets import KEYS, IDS, genesis
from test_budget_integration import setup_transactions, payment
from certificate_fixture import validators, make_header, make_commit
from compact_verifier import verify_compact_witness

ROOT=Path(__file__).resolve().parents[1]


class IndexedApplicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.g={**genesis(),'state_commitment':'smt-v1'};self.path=self.root/'node.sqlite'
        self.app=BlockApplication(self.path,expected_genesis=self.g)
        self.app.init_chain(self.g['chain_id'],self.g)
    def tearDown(self):self.app.close();self.tmp.cleanup()
    def block(self,txs):
        h=self.app.height+1;r=self.app.finalize_block(txs,h,hashlib.sha256(str(h).encode()).digest())
        self.app.commit();return r
    def witness(self,q=None):return self.app.compact_witness(q or [('accounts',IDS[0])])
    def assert_reference(self,queries=None):
        q=queries or [('accounts',IDS[0]),('accounts','absent')]
        self.assertEqual(self.witness(q),make_witness(self.g,self.app.height,self.app.native,q))
    def test_coin_identity_is_1soft_without_changing_genesis(self):
        self.assertEqual(self.app.info()['name'],'1soft-native-dev')
        self.assertEqual(self.app.genesis,self.g)
    def test_genesis_installs_index_inside_same_database(self):
        self.assertIsNotNone(self.app.proof_index);self.assert_reference()
        cp=self.app.proof_index.checkpoint();self.assertEqual(cp['app_hash'],self.app.app_hash)
    def test_queries_do_not_rebuild_the_snapshot_tree(self):
        expected=self.witness()
        with patch('state_tree.StateTree',side_effect=AssertionError('must not rebuild')):
            self.assertEqual(self.witness(),expected)
    def test_queries_do_not_read_whole_committed_blob(self):
        sql=[];self.app.db.set_trace_callback(sql.append)
        try:self.witness()
        finally:self.app.db.set_trace_callback(None)
        self.assertTrue(sql);self.assertTrue(all('from committed' not in x.lower() for x in sql))
    def test_reference_and_indexed_nodes_execute_identically(self):
        reference=BlockApplication(self.root/'reference.sqlite',expected_genesis=self.g,proof_index=False)
        reference.init_chain(self.g['chain_id'],self.g)
        try:
            for txs in (setup_transactions(self.g),[payment(self.g,0,58)],[],[payment(self.g,1,39)],[payment(self.g,1,38)]):
                h=self.app.height+1;block_hash=hashlib.sha256(str(h).encode()).digest()
                left=self.app.finalize_block(txs,h,block_hash);right=reference.finalize_block(txs,h,block_hash)
                self.assertEqual(left,right);self.app.commit();reference.commit()
                self.assertEqual(self.app.native,reference.native)
                self.assertEqual(self.witness(),reference.compact_witness([('accounts',IDS[0])]))
        finally:reference.close()
    def test_budget_debit_and_receipt_share_index_checkpoint(self):
        self.block(setup_transactions(self.g));raw=payment(self.g,0,58);self.block([raw])
        q=[('budgets',IDS[0]+'::project'),('receipts',transaction_id(raw)),('accounts',IDS[0])]
        self.assert_reference(q);w=self.witness(q)
        self.assertEqual(w['entries'][0]['value'][4],60)
        self.assertEqual(w['entries'][1]['value'][0],transaction_id(raw))
    def test_rejected_transaction_does_not_advance_native_index_rows(self):
        self.block(setup_transactions(self.g));self.block([payment(self.g,0,58)])
        before=copy.deepcopy(self.app.native);oldroot=self.witness()['root']
        out=self.block([payment(self.g,1,39)])
        self.assertEqual(out['tx_results'][0]['code'],1);self.assertEqual(self.app.native,before)
        self.assertEqual(self.witness()['root'],oldroot);self.assertEqual(self.app.proof_index.work.writes,0)
    def test_prepared_and_processed_proposals_leave_index_untouched(self):
        old=self.witness();changes=self.app.db.total_changes
        txs=setup_transactions(self.g);self.app.prepare_proposal(txs,1,100000);self.app.process_proposal(txs,1)
        self.assertEqual(self.witness(),old);self.assertEqual(self.app.db.total_changes,changes)
    def test_finalized_not_committed_root_not_exposed(self):
        old=self.witness();self.app.finalize_block(setup_transactions(self.g),1,b'a'*32)
        self.assertEqual(self.witness(),old);self.assertEqual(self.app.proof_index.checkpoint()['height'],0)
        self.app.commit();self.assert_reference();self.assertEqual(self.app.proof_index.checkpoint()['height'],1)
    def test_exception_after_index_rolls_back_every_persistent_component(self):
        old=self.witness();self.app.finalize_block(setup_transactions(self.g),1,b'a'*32)
        with self.assertRaises(RuntimeError):self.app.commit(fault='after_index')
        self.assertEqual(self.witness(),old)
        self.assertEqual(self.app.db.execute('SELECT height FROM committed').fetchone()[0],0)
        self.assertEqual(self.app.db.execute('SELECT count(*) FROM blocks').fetchone()[0],0)
        self.app.commit();self.assertEqual(self.app.height,1);self.assert_reference()
    def test_application_and_index_checkpoint_commit_together(self):
        self.block(setup_transactions(self.g))
        persisted=self.app.db.execute('SELECT height,app_hash FROM committed WHERE id=1').fetchone()
        indexed=self.app.db.execute('SELECT height,app_hash FROM proof_checkpoint WHERE id=1').fetchone()
        self.assertEqual(persisted,indexed)

    def test_bad_incremental_root_prevents_application_commit(self):
        self.app.finalize_block(setup_transactions(self.g),1,b'a'*32)
        with patch('state_index.bind_root',return_value='00'*32),self.assertRaises(ProofError):self.app.commit()
        self.assertEqual(self.app.height,0);self.assertEqual(self.app.db.execute('SELECT height FROM committed').fetchone()[0],0)
        self.app.commit();self.assert_reference()
    def test_reopen_audits_persisted_nodes(self):
        self.block(setup_transactions(self.g));old=self.witness();self.app.close()
        self.app=BlockApplication(self.path,expected_genesis=self.g)
        self.assertEqual(self.witness(),old);self.assert_reference()
    def test_old_database_gets_one_time_derived_index_without_rewriting_history(self):
        p=self.root/'old.sqlite';old=BlockApplication(p,expected_genesis=self.g,proof_index=False)
        old.init_chain(self.g['chain_id'],self.g);old.finalize_block(setup_transactions(self.g),1,b'o'*32);old.commit()
        native=copy.deepcopy(old.native);app_hash=old.app_hash
        blocks=old.db.execute('SELECT * FROM blocks').fetchall();record=old.db.execute('SELECT * FROM committed').fetchall();old.close()
        fresh=BlockApplication(p,expected_genesis=self.g)
        try:
            self.assertEqual(fresh.native,native);self.assertEqual(fresh.app_hash,app_hash)
            self.assertEqual(fresh.db.execute('SELECT * FROM blocks').fetchall(),blocks)
            self.assertEqual(fresh.db.execute('SELECT * FROM committed').fetchall(),record)
            self.assertEqual(fresh.compact_witness([('accounts',IDS[0])]),make_witness(self.g,1,native,[('accounts',IDS[0])]))
        finally:fresh.close()
    def test_existing_index_cannot_be_silently_disabled(self):
        self.app.close()
        with self.assertRaisesRegex(Reject,'cannot disable'):BlockApplication(self.path,expected_genesis=self.g,proof_index=False)
    def test_corrupt_index_refused_not_auto_rebuilt_on_open(self):
        self.app.db.execute('UPDATE proof_nodes SET value=? WHERE depth=256',(b'[]',));self.app.close()
        with self.assertRaises(ProofError):BlockApplication(self.path,expected_genesis=self.g)
        db=sqlite3.connect(self.path)
        try:self.assertEqual(db.execute('SELECT count(*) FROM proof_nodes WHERE value=?',(b'[]',)).fetchone()[0],len(self.app.native['meta'])+len(self.app.native['accounts']))
        finally:db.close()
    def test_query_refuses_corrupt_index_instead_of_returning_bad_proof(self):
        self.app.db.execute('UPDATE proof_nodes SET root=?',(bytes(32),))
        path='/proof/accounts/'+IDS[0].encode().hex();result=self.app.query(path)
        self.assertEqual(result['code'],1);self.assertEqual(result['value'],b'')
    def test_orphaned_partial_index_not_reinitialized(self):
        self.app.db.execute('DELETE FROM proof_checkpoint');self.app.close()
        with self.assertRaisesRegex(ProofError,'orphaned'):BlockApplication(self.path,expected_genesis=self.g)
    def test_legacy_protocols_do_not_create_index_tables(self):
        for version in (1,2,3):
            g={**genesis(),'protocol_version':version};a=BlockApplication(':memory:',expected_genesis=g)
            try:
                a.init_chain(g['chain_id'],g)
                self.assertIsNone(a.proof_index)
                self.assertEqual(a.db.execute("SELECT count(*) FROM sqlite_master WHERE name='proof_nodes'").fetchone()[0],0)
            finally:a.close()
    def test_proof_still_verifies_under_unchanged_signed_header_verifier(self):
        self.block(setup_transactions(self.g));engine,trust,keys=validators(self.g)
        h=make_header(trust,self.app.height+1,self.app.app_hash,[]);h['version']['app']='3'
        h['last_block_id']={'hash':'12'*32,'parts':{'total':1,'hash':'13'*32}}
        cert=make_commit(h,trust,keys)
        result=verify_compact_witness(self.witness(),cert,trust,expected_queries=[('accounts',IDS[0])])
        self.assertEqual(result['state_height'],self.app.height)
    def crash(self,fault):
        (self.root/'genesis.json').write_bytes(encode(self.g));self.app.close()
        code='''import sys
from pathlib import Path
from block_application import BlockApplication
from test_budget_integration import setup_transactions
import json
g=json.loads(Path(sys.argv[2]).read_text())
a=BlockApplication(sys.argv[1],expected_genesis=g)
a.finalize_block(setup_transactions(g),1,b'x'*32)
a.commit(fault=sys.argv[3])
'''
        env=dict(os.environ,PYTHONPATH=str(ROOT/'src')+os.pathsep+str(ROOT/'tests'))
        result=subprocess.run([sys.executable,'-c',code,str(self.path),str(self.root/'genesis.json'),fault],env=env,capture_output=True,timeout=10)
        self.app=BlockApplication(self.path,expected_genesis=self.g)
        return result
    def test_process_exit_after_index_before_commit_recovers_old_root(self):
        old=self.witness();result=self.crash('exit_after_index')
        self.assertEqual(result.returncode,93,result.stderr);self.assertEqual(self.witness(),old)
        self.assertEqual(self.app.height,0);self.assert_reference()
    def test_process_exit_after_commit_recovers_new_root_and_balances(self):
        result=self.crash('exit_after_commit');self.assertEqual(result.returncode,92,result.stderr)
        self.assertEqual(self.app.height,1);self.assertIsNotNone(self.app.proof_index)
        self.assert_reference([('accounts',IDS[0]),('budgets',IDS[0]+'::project')])
    def test_rollback_then_retry_does_not_leak_orphan_nodes(self):
        self.app.finalize_block(setup_transactions(self.g),1,b'a'*32)
        for _ in range(3):
            with self.assertRaises(RuntimeError):self.app.commit(fault='after_index')
            self.app.proof_index.audit(digest(self.g),0,self.app.app_hash)
        self.app.commit();r=self.app.proof_index.audit(digest(self.g),1,self.app.app_hash)
        self.assertEqual(r['nodes'],2*r['records']-1)
    def test_missing_index_root_detected_during_commit(self):
        self.app.finalize_block(setup_transactions(self.g),1,b'a'*32)
        ref=self.app.proof_index.checkpoint()['root_ref'];self.app.db.execute('DELETE FROM proof_nodes WHERE location=?',(ref,))
        with self.assertRaises(ProofError):self.app.commit()
        self.assertEqual(self.app.db.execute('SELECT height FROM committed').fetchone()[0],0)


if __name__=='__main__':unittest.main()
