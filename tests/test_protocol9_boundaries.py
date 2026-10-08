"""Additional hostile-store/lifecycle cases; all use the labeled fake verifier."""
import copy
import os
import sqlite3
import unittest
from pathlib import Path
import test_protocol9_ledger as fixtures
import protocol8_transfer as n
import protocol9_consensus as p
from protocol9_application import Application
from protocol5_abci_wire import Request
tx,f=fixtures.tx,fixtures.f

class BoundaryTests(unittest.TestCase):
    setUp=fixtures.LedgerTests.setUp
    tearDown=fixtures.LedgerTests.tearDown
    block=fixtures.LedgerTests.block
    root=fixtures.LedgerTests.root
    reopen=fixtures.LedgerTests.reopen

    def test_full_initial_segment_rolls_and_keeps_old_root_authority(self):
        self.a.close();d=Path(self.tmp.name)/'full';d.mkdir(mode=0o700)
        g=copy.deepcopy(self.g);g['notes']=[{'kind':'p8-recipient-v1','commitment':f(100+i)} for i in range(16)]
        self.w.kat_statement[4]=self.w.root([row['commitment'] for row in g['notes']])
        self.raw=n.canonical(g);self.path=d/'state.sqlite';self.g=g
        self.a=Application(self.path,self.w,expected_genesis=self.raw)
        self.a.init_chain(g['chain_id'],self.raw,g['validators']);old=self.root()
        self.block([tx(g,old,0)])
        self.assertEqual(self.a.checkpoint['segment'],1)
        self.assertEqual(len(self.a.checkpoint['active_notes']),2)
        self.assertEqual(self.a.check_tx(tx(g,old,1))['code'],0)
        self.assertEqual(self.a.check_tx(tx(g,old,1,nullifier=f(1000)))['code'],5)
        self.reopen();self.assertEqual(self.a.checkpoint['notes_count'],18)

    def test_ordered_same_block_dependency_and_reversed_refusal(self):
        first=tx(self.g,self.root(),0)
        next_root=self.w.root(self.a.checkpoint['active_notes']+n.parse(first)[10:12])
        second=tx(self.g,next_root,1)
        self.assertFalse(self.a.process_proposal([second,first],1,bytes.fromhex(self.a.validators.hash)))
        self.assertEqual(self.a.prepare_proposal([second,first],1,10000),[first])
        self.assertTrue(self.a.process_proposal([first,second],1,bytes.fromhex(self.a.validators.hash)))
        self.assertEqual([r['code'] for r in self.block([first,second])['tx_results']],[0,0])
        self.reopen();self.assertEqual(self.a.checkpoint['accepted_count'],2)

    def test_recomputed_forged_checkpoint_hash_does_not_bypass_replay(self):
        self.block([tx(self.g,self.root(),0)])
        c=copy.deepcopy(self.a.checkpoint);c['fees']+=1
        self.a.db.execute('UPDATE p9_checkpoint SET checkpoint=?,app_hash=?',
                          (n.canonical(c),p.application_hash(self.g,c)))
        self.a.close()
        with self.assertRaises(n.Invalid):Application(self.path,self.w,expected_genesis=self.raw)

    def test_deleted_history_cannot_be_hidden_by_matching_checkpoint(self):
        self.block();self.block();self.a.db.execute('DELETE FROM p9_blocks WHERE height=1');self.a.close()
        with self.assertRaises(n.Invalid):Application(self.path,self.w,expected_genesis=self.raw)

    def test_global_nullifier_cannot_reset_when_anchor_changes(self):
        first=tx(self.g,self.root(),0);self.block([first])
        competing=tx(self.g,self.root(),1,nullifier=n.parse(first)[5])
        self.assertEqual(self.a.check_tx(competing)['code'],5)
        self.assertEqual(self.a.checkpoint['accepted_count'],1)

    def test_exact_request_projection_is_required_before_staging(self):
        q=Request().finalize_block;q.height=1;q.hash=b'x'*32
        q.next_validators_hash=bytes.fromhex(self.a.validators.hash)
        with self.assertRaises(n.Invalid):
            self.a.finalize_block([tx(self.g,self.root(),0)],1,b'x'*32,bytes(q.next_validators_hash),[],q.SerializeToString(deterministic=True))
        self.assertIsNone(self.a.pending)
        self.assertEqual(self.a.checkpoint['accepted_count'],0)

    def test_two_wire_container_and_height_bool_refuse(self):
        wire=tx(self.g,self.root(),0)
        self.assertFalse(self.a.process_proposal([wire]*3,1,bytes.fromhex(self.a.validators.hash)))
        self.assertFalse(self.a.process_proposal([],True,bytes.fromhex(self.a.validators.hash)))
        self.assertEqual(self.a.checkpoint['accepted_count'],0)

    def test_storage_hardlink_and_foreign_schema_refuse(self):
        self.a.close();link=Path(self.tmp.name)/'linked.sqlite';os.link(self.path,link)
        with self.assertRaises(n.Invalid):Application(link,self.w,expected_genesis=self.raw)
        foreign=Path(self.tmp.name)/'foreign.sqlite'
        db=sqlite3.connect(foreign);db.execute('CREATE TABLE p8_checkpoint(id INTEGER)');db.close();foreign.chmod(0o600)
        before=foreign.read_bytes()
        with self.assertRaises(n.Invalid):Application(foreign,self.w,expected_genesis=self.raw)
        self.assertEqual(foreign.read_bytes(),before)

if __name__=='__main__':unittest.main(verbosity=2)
