"""Execution-image isolation and lifecycle. Real SQLite, no validator claims."""
import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from native_core import NativeLedger, Reject, address, canonical, digest, public, sign, accept_account_key
from block_application import BlockApplication, application_hash, encode, snapshot, restore, MAX_BLOCK_BYTES
from execution_snapshot import ExecutionSnapshot, ExecutionSnapshotFault
from test_native_budgets import KEYS, IDS, genesis, budget_op, grant_op
from test_budget_integration import setup_transactions, payment

ROOT = Path(__file__).resolve().parents[1]


def raw(g, nonce=0, amount=5, *, key=KEYS[0], owner=IDS[0], op=None, until=1000):
    m = NativeLedger(':memory:', g)
    try:
        body = m.body(owner, nonce, op or {'type':'transfer','to':IDS[1],'units':amount}, valid_until=until)
        return canonical(sign(key, body))
    finally:
        m.close()


class ImageTests(unittest.TestCase):
    def setUp(self):
        self.g = genesis()
        self.ledger = NativeLedger(':memory:', self.g)
        self.hash = application_hash(self.g, 0, snapshot(self.ledger))
        self.image = ExecutionSnapshot.from_validated_ledger(self.ledger, 0, self.hash)
    def tearDown(self):
        self.image.close(); self.ledger.close()
    def fork(self):
        return self.image.fork(digest(self.g), 0, self.hash)
    def test_capture_is_independent_of_source_mutation(self):
        original = snapshot(self.ledger)
        self.ledger.apply(json.loads(raw(self.g)), height=1)
        trial = self.fork()
        try: self.assertEqual(snapshot(trial), original)
        finally: trial.close()
    def test_fork_matches_every_source_record(self):
        trial = self.fork()
        try: self.assertEqual(snapshot(trial), snapshot(self.ledger))
        finally: trial.close()
    def test_trial_payment_cannot_change_committed_image(self):
        first = self.fork(); second = self.fork()
        try:
            before = snapshot(second)
            first.apply(json.loads(raw(self.g)), height=1)
            self.assertEqual(snapshot(second), before)
            third = self.fork()
            try: self.assertEqual(snapshot(third), before)
            finally: third.close()
        finally: first.close(); second.close()
    def test_cached_source_denies_writes(self):
        for query in ('DELETE FROM receipts', 'UPDATE accounts SET balance=0',
                      'CREATE TABLE injected (x)', 'PRAGMA query_only=OFF'):
            with self.subTest(query=query), self.assertRaises(sqlite3.DatabaseError):
                self.image._db.execute(query)
    def test_old_checkpoint_is_not_accepted_as_new(self):
        for g,h,a in ((digest(self.g),1,self.hash),('0'*64,0,self.hash),(digest(self.g),0,'0'*64)):
            with self.subTest(height=h,genesis=g), self.assertRaises(ExecutionSnapshotFault):
                self.image.fork(g,h,a)
    def test_bad_height_and_digest_types_refused(self):
        for value in (True,-1,1.0,2**63):
            with self.subTest(height=value), self.assertRaises(ExecutionSnapshotFault):
                ExecutionSnapshot.from_validated_ledger(self.ledger,value,self.hash)
        with self.assertRaises(ExecutionSnapshotFault):
            ExecutionSnapshot.from_validated_ledger(self.ledger,0,'AA'*32)
    def test_capture_of_open_native_transaction_refused_without_hang(self):
        self.ledger.db.execute('BEGIN IMMEDIATE')
        try:
            with self.assertRaisesRegex(ExecutionSnapshotFault,'unfinished'):
                ExecutionSnapshot.from_validated_ledger(self.ledger,0,self.hash)
        finally: self.ledger.db.execute('ROLLBACK')
    def test_changed_genesis_refused(self):
        self.ledger.genesis['asset']='CHANGED'
        with self.assertRaisesRegex(ExecutionSnapshotFault,'genesis changed'):
            ExecutionSnapshot.from_validated_ledger(self.ledger,0,self.hash)
    def test_close_idempotent_and_fork_after_close_refused(self):
        self.image.close(); self.image.close()
        with self.assertRaises(ExecutionSnapshotFault): self.fork()
    def test_existing_trial_survives_image_close(self):
        trial = self.fork(); self.image.close()
        try:
            trial.apply(json.loads(raw(self.g)),height=1)
            self.assertEqual(trial.balance(IDS[1]),5)
        finally: trial.close()
    def test_cross_thread_forks_are_independent_native_connections(self):
        def execute(_):
            trial = self.fork()
            try:
                trial.apply(json.loads(raw(self.g)),height=1)
                return trial.balance(IDS[1]),snapshot(trial)
            finally: trial.close()
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(execute,range(8)))
        self.assertTrue(all(balance==5 and state==results[0][1] for balance,state in results))
        trial = self.fork()
        try: self.assertEqual(trial.balance(IDS[1]),0)
        finally: trial.close()
    def test_query_only_disabled_by_internal_tampering_is_detected(self):
        # Trusted-process defence-in-depth; not a hostile-OS security boundary.
        self.image._db.set_authorizer(None)
        self.image._db.execute('PRAGMA query_only=OFF')
        with self.assertRaises(ExecutionSnapshotFault): self.fork()
    def test_changed_source_counter_detected_even_after_readonly_restored(self):
        self.image._db.set_authorizer(None)
        self.image._db.execute('PRAGMA query_only=OFF')
        self.image._db.execute('UPDATE accounts SET nonce=nonce+1')
        self.image._db.execute('PRAGMA query_only=ON')
        with self.assertRaises(ExecutionSnapshotFault): self.fork()
    def test_memory_stat_is_sqlite_page_allocation(self):
        value = self.image.storage_bytes()
        self.assertGreater(value,0)
        self.assertEqual(value%4096,0)


class ExecutionApplicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.g={**genesis(),'state_commitment':'smt-v1'}
        self.path=self.root/'node.sqlite'
        self.app=BlockApplication(self.path,expected_genesis=self.g)
        self.app.init_chain(self.g['chain_id'],self.g)
    def tearDown(self): self.app.close();self.tmp.cleanup()
    def block(self, txs):
        h=self.app.height+1
        result=self.app.finalize_block(txs,h,hashlib.sha256(str(h).encode()).digest())
        self.app.commit();return result
    def reopen(self, **kwargs):
        self.app.close()
        self.app=BlockApplication(self.path,expected_genesis=self.g,**kwargs)
    def test_repeated_checks_do_not_reload_receipt_history(self):
        self.block([raw(self.g)])
        next_tx=raw(self.g,1)
        with patch('block_application.restore',side_effect=AssertionError('must not restore per request')), \
             patch.object(NativeLedger,'verify_receipts',side_effect=AssertionError('must not rescan old signatures')):
            for _ in range(4): self.assertEqual(self.app.check_tx(next_tx)['code'],0)
            self.assertTrue(self.app.process_proposal([next_tx],2))
            self.assertEqual(self.app.prepare_proposal([next_tx],2,MAX_BLOCK_BYTES),[next_tx])
            self.block([next_tx])
        self.assertEqual(self.app.height,2)
    def test_new_signature_still_checked_on_every_trial(self):
        env=json.loads(raw(self.g));env['signature']='00'*64
        for _ in range(4):
            self.assertEqual(self.app.check_tx(canonical(env))['code'],1)
        self.assertEqual(self.app.check_tx(raw(self.g))['code'],0)
    def test_startup_always_revalidates_disk_history(self):
        self.block([raw(self.g)]);self.app.close()
        original=NativeLedger.verify_receipts
        calls=[]
        def counted(ledger):
            calls.append(True);return original(ledger)
        with patch.object(NativeLedger,'verify_receipts',counted):
            self.app=BlockApplication(self.path,expected_genesis=self.g)
        self.assertEqual(len(calls),1)
    def test_corrupt_receipt_cannot_be_smuggled_through_recomputed_disk_root(self):
        # Legacy commitment keeps this test independent of proof-index corruption.
        path=self.root/'tampered.sqlite';g=genesis(2)
        app=BlockApplication(path,expected_genesis=g)
        app.init_chain(g['chain_id'],g);app.finalize_block([raw(g)],1,b'x'*32);app.commit();app.close()
        db=sqlite3.connect(path)
        saved=db.execute('SELECT state FROM committed WHERE id=1').fetchone()[0]
        state=json.loads(saved);receipt=state['receipts'][0];record=json.loads(receipt[3])
        record['envelope']['signature']='0'*128
        receipt[3]=canonical(record).decode();receipt[4]=digest(record)
        new_hash=application_hash(g,1,state)
        db.execute('UPDATE committed SET state=?,app_hash=?',(encode(state).decode(),new_hash))
        db.execute('UPDATE blocks SET app_hash=?',(new_hash,));db.commit();db.close()
        with self.assertRaises(Reject):BlockApplication(path,expected_genesis=g)
    def test_pending_image_never_used_for_checktx(self):
        tx=raw(self.g);next_tx=raw(self.g,1)
        old=self.app._execution
        self.app.finalize_block([tx],1,b'x'*32)
        self.assertIs(self.app._execution,old)
        self.assertEqual(self.app._pending_execution.checkpoint.height,1)
        self.assertEqual(self.app.check_tx(tx)['code'],0)
        self.assertEqual(self.app.check_tx(next_tx)['code'],1)
        self.assertEqual(self.app.query('/receipt/'+hashlib.sha256(b'bad').hexdigest())['code'],1)
    def test_commit_promotes_once_and_closes_old_image(self):
        old=self.app._execution
        self.app.finalize_block([raw(self.g)],1,b'x'*32)
        pending=self.app._pending_execution
        self.app.commit()
        self.assertIs(self.app._execution,pending);self.assertTrue(old.closed)
        self.assertIsNone(self.app._pending_execution)
        self.assertEqual(self.app.check_tx(raw(self.g,1))['code'],0)
        self.assertEqual(self.app.check_tx(raw(self.g))['code'],1)
        self.app.commit();self.assertIs(self.app._execution,pending)
    def test_commit_failures_keep_committed_image_and_allow_retry(self):
        for failure in ('after_state','after_index','before_commit'):
            with self.subTest(failure=failure):
                old=self.app._execution
                tx=raw(self.g,self.app.height)
                self.app.finalize_block([tx],self.app.height+1,b'x'*32)
                staged=self.app._pending_execution
                with self.assertRaises(RuntimeError):self.app.commit(fault=failure)
                self.assertIs(self.app._execution,old);self.assertFalse(old.closed)
                self.assertIs(self.app._pending_execution,staged)
                self.assertEqual(self.app.check_tx(tx)['code'],0)
                self.app.commit();self.assertIs(self.app._execution,staged)
    def test_capture_failure_does_not_stage_or_spend(self):
        before=self.app.query('/state')['value']
        with patch.object(ExecutionSnapshot,'from_validated_ledger',side_effect=RuntimeError('capture fault')):
            with self.assertRaises(RuntimeError):self.app.finalize_block([raw(self.g)],1,b'x'*32)
        self.assertIsNone(self.app.pending);self.assertIsNone(self.app._pending_execution)
        self.assertEqual(self.app.query('/state')['value'],before)
        self.block([raw(self.g)])
    def test_repeated_finalize_reuses_staged_image(self):
        result=self.app.finalize_block([raw(self.g)],1,b'x'*32)
        staged=self.app._pending_execution
        with patch.object(ExecutionSnapshot,'from_validated_ledger',side_effect=AssertionError('duplicate capture')):
            self.assertEqual(self.app.finalize_block([raw(self.g)],1,b'x'*32),result)
        self.assertIs(self.app._pending_execution,staged)
    def test_conflicting_finalize_cannot_replace_pending_image(self):
        self.app.finalize_block([raw(self.g)],1,b'x'*32)
        staged=self.app._pending_execution
        with self.assertRaises(Reject):self.app.finalize_block([],1,b'y'*32)
        self.assertIs(self.app._pending_execution,staged)
    def test_shared_budget_checks_advance_only_after_commit(self):
        self.block(setup_transactions(self.g))
        first=payment(self.g,0,58);excess=payment(self.g,1,39)
        self.assertEqual(self.app.check_tx(excess)['code'],0)
        self.app.finalize_block([first],2,b'x'*32)
        self.assertEqual(self.app.check_tx(excess)['code'],0)
        self.app.commit()
        self.assertEqual(self.app.check_tx(excess)['code'],1)
        self.assertEqual(self.app.check_tx(payment(self.g,1,38))['code'],0)
    def test_alternate_proposals_cannot_poison_other_trials(self):
        self.block(setup_transactions(self.g))
        first=payment(self.g,0,58);other=payment(self.g,1,39)
        for _ in range(3):
            self.assertEqual(self.app.prepare_proposal([first,other],2,MAX_BLOCK_BYTES),[first])
            self.assertTrue(self.app.process_proposal([other],2))
            self.assertFalse(self.app.process_proposal([first,other],2))
            self.assertEqual(self.app.check_tx(other)['code'],0)
    def test_key_rotation_and_grant_revocation_visible_to_new_trials(self):
        self.block(setup_transactions(self.g))
        maker=NativeLedger(':memory:',self.g)
        try:
            body=maker.body(IDS[0],3,{'type':'rotate_key','public_key':public(KEYS[5]),'acceptance':''})
            rotation=canonical(sign(KEYS[0],accept_account_key(KEYS[5],body)))
        finally:maker.close()
        self.block([rotation])
        self.assertEqual(self.app.check_tx(payment(self.g,0,10))['code'],1)
        self.assertEqual(self.app.check_tx(raw(self.g,4,key=KEYS[0]))['code'],1)
        self.assertEqual(self.app.check_tx(raw(self.g,4,key=KEYS[5]))['code'],0)
    def test_empty_blocks_expire_transaction_without_native_mutation(self):
        tx=raw(self.g,until=1)
        before=copy.deepcopy(self.app.native)
        self.assertEqual(self.app.check_tx(tx)['code'],0)
        self.block([])
        self.assertEqual(self.app.native,before)
        self.assertEqual(self.app._execution.checkpoint.height,1)
        self.assertEqual(self.app.check_tx(tx)['code'],1)
    def test_cached_and_reference_execution_equal_for_all_supported_genesis_modes(self):
        for version,smt in ((1,False),(2,False),(3,False),(3,True)):
            with self.subTest(version=version,smt=smt):
                g=genesis(version)
                if smt:g['state_commitment']='smt-v1'
                fast=BlockApplication(':memory:',execution_cache=True)
                reference=BlockApplication(':memory:',execution_cache=False)
                try:
                    fast.init_chain(g['chain_id'],g);reference.init_chain(g['chain_id'],g)
                    tx_sets=([raw(g,0)],[],[raw(g,1),raw(g,1,6)], [raw(g,2,key=KEYS[1])], [raw(g,2)])
                    for height,txs in enumerate(tx_sets,1):
                        for tx in txs:self.assertEqual(fast.check_tx(tx),reference.check_tx(tx))
                        self.assertEqual(fast.prepare_proposal(txs,height,MAX_BLOCK_BYTES),reference.prepare_proposal(txs,height,MAX_BLOCK_BYTES))
                        self.assertEqual(fast.process_proposal(txs,height),reference.process_proposal(txs,height))
                        self.assertEqual(fast.finalize_block(txs,height,b'x'*32),reference.finalize_block(txs,height,b'x'*32))
                        self.assertEqual(fast.commit(),reference.commit())
                        self.assertEqual(fast.query('/state'),reference.query('/state'))
                        if smt:self.assertEqual(fast.compact_witness([('accounts',IDS[0])]),reference.compact_witness([('accounts',IDS[0])]))
                finally:fast.close();reference.close()
    def test_missing_execution_image_is_internal_fault_not_transaction_rejection(self):
        old=self.app._execution;self.app._execution=None
        try:
            with self.assertRaises(ExecutionSnapshotFault):self.app.check_tx(raw(self.g))
        finally:self.app._execution=old
    def test_bad_staged_checkpoint_prevents_disk_commit(self):
        self.app.finalize_block([raw(self.g)],1,b'x'*32)
        staged=self.app._pending_execution
        self.app._pending_execution=self.app._execution
        try:
            with self.assertRaises(ExecutionSnapshotFault):self.app.commit()
            self.assertEqual(self.app.db.execute('SELECT height FROM committed').fetchone()[0],0)
        finally:self.app._pending_execution=staged
    def test_close_releases_pending_and_committed_images(self):
        self.app.finalize_block([raw(self.g)],1,b'x'*32)
        old,staged=self.app._execution,self.app._pending_execution
        self.app.close()
        self.assertTrue(old.closed);self.assertTrue(staged.closed)
    def test_reference_switch_is_explicit_and_restart_safe(self):
        self.block([raw(self.g)])
        state=self.app.query('/state')['value'];self.reopen(execution_cache=False)
        self.assertIsNone(self.app._execution)
        self.assertEqual(self.app.query('/state')['value'],state)
        self.assertEqual(self.app.check_tx(raw(self.g,1))['code'],0)
        self.reopen(execution_cache=True)
        self.assertEqual(self.app.query('/state')['value'],state)
    def test_invalid_cache_configuration_is_rejected(self):
        for value in (0,1,'yes',None):
            with self.subTest(value=value),self.assertRaises(Reject):BlockApplication(':memory:',execution_cache=value)
    def test_actual_cross_thread_application_checks(self):
        tx=raw(self.g)
        with ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(lambda _:self.app.check_tx(tx),range(12)))
        self.assertTrue(all(r['code']==0 for r in results));self.assertEqual(self.app.height,0)
    def test_process_exit_before_commit_rebuilds_old_validated_image(self):
        self._crash('exit_after_index',93,0)
    def test_process_exit_after_commit_rebuilds_new_validated_image(self):
        self._crash('exit_after_commit',92,1)
    def _crash(self,fault,code,height):
        tx=raw(self.g);self.app.close()
        code_text='''from block_application import BlockApplication
import sys
app=BlockApplication(sys.argv[1]);app.finalize_block([bytes.fromhex(sys.argv[2])],1,b'x'*32)
app.commit(fault=sys.argv[3])
'''
        proc=subprocess.run([sys.executable,'-c',code_text,str(self.path),tx.hex(),fault],
            capture_output=True,text=True,timeout=10)
        self.assertEqual(proc.returncode,code,proc.stderr)
        self.app=BlockApplication(self.path,expected_genesis=self.g)
        self.assertEqual(self.app.height,height);self.assertEqual(self.app._execution.checkpoint.height,height)
        self.assertEqual(self.app.check_tx(tx)['code'],height)
        self.assertEqual(self.app.check_tx(raw(self.g,1))['code'],1-height)


if __name__=='__main__':unittest.main()
