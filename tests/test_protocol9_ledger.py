"""Lifecycle tests with a labeled fake verifier, not cryptographic validation."""
import copy
import hashlib
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import protocol8_transfer as n
import protocol9_consensus as p
from protocol9_application import Application
from protocol5_abci_wire import Request
from protocol8_worker import Worker

def f(v): return v.to_bytes(32, 'little').hex()

class FakeWorker(Worker):
    """Deliberately fake proof/network/root operations for storage tests only."""
    sha256 = '12' * 32
    kat_sha256 = '34' * 32
    startup = {'fake_verifier': True}
    identity = {'sha256': sha256}
    def __init__(self): pass
    def guard(self): pass
    def network_domain(self, raw): return f(int.from_bytes(hashlib.sha256(raw).digest(), 'little') % n.MODULUS or 1)
    def root(self, notes): return f(int.from_bytes(hashlib.sha256(n.canonical(notes)).digest(), 'little') % n.MODULUS or 1)
    def verify(self, raw, network): return raw[-1] == 0 and n.parse(raw)[1] == network
    def audit(self): return {'fake_verifier': True}

def fixture():
    w = FakeWorker()
    g = {'format':p.GENESIS_FORMAT,'protocol_version':9,'chain_id':'p9-unit',
         'profile_sha256':n.PROFILE_SHA256,'worker_sha256':w.sha256,
         'kat_sha256':w.kat_sha256,'validators':[{'public_key':('%02x'%i)*32,'power':10} for i in range(1,5)],
         'pool_id':'56'*32,'network':f(1),'asset':f(2),'mission':f(3),'fee':1,
         'notes':[{'kind':'p8-recipient-v1','commitment':f(100)}]}
    g['network'] = w.network_domain(bytes.fromhex(p.bootstrap_digest(g)))
    w.kat_statement = [f(8),g['network'],g['asset'],g['mission'],w.root([f(100)]),f(101),f(102),f(1),f(10000),f(1),f(103),f(104),f(105)]
    return g,w

def tx(g,root,i,*,nullifier=None,request=None,outputs=None):
    fields=[f(8),g['network'],g['asset'],g['mission'],root,nullifier or f(1000+i),request or f(2000+i),f(1),f(10000),f(1),*(outputs or [f(3000+2*i),f(3001+2*i)]),f(4000+i)]
    return b'1SRCT008'+b''.join(n.field(v) for v in fields)+bytes(3136)

def finalize(app, txs, height):
    q=Request().finalize_block;q.height=height;q.hash=height.to_bytes(32,'big');q.next_validators_hash=bytes.fromhex(app.validators.hash);q.txs.extend(txs)
    votes=[]
    if height>1:
        for v in app.validators.validators:
            row={'address':v.address.hex(),'power':v.power,'block_id_flag':2};votes.append(row)
            x=q.decided_last_commit.votes.add();x.validator.address=v.address;x.validator.power=v.power;x.block_id_flag=2
    return app.finalize_block(txs,height,bytes(q.hash),bytes(q.next_validators_hash),votes,q.SerializeToString(deterministic=True))

class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();os.chmod(self.tmp.name,0o700)
        self.path=Path(self.tmp.name)/'state.sqlite';self.g,self.w=fixture()
        self.raw=n.canonical(self.g);self.a=Application(self.path,self.w,expected_genesis=self.raw)
        self.a.init_chain(self.g['chain_id'],self.raw,self.g['validators'])
    def tearDown(self):
        self.a.close();self.tmp.cleanup()
    def reopen(self):
        self.a.close();self.a=Application(self.path,self.w,expected_genesis=self.raw)
    def root(self): return self.w.root(self.a.checkpoint['active_notes'])
    def block(self,txs=None):
        value,_=finalize(self.a,txs or [],self.a.height+1);self.a.commit();return value
    def test_crosses_old_limits_with_global_old_root_replay_refusal(self):
        old=self.root();first=tx(self.g,old,0)
        for i in range(9):
            self.assertEqual(self.block([tx(self.g,self.root(),i)])['tx_results'][0]['code'],0)
        self.assertEqual(self.a.checkpoint['notes_count'],19)
        self.assertEqual(self.a.checkpoint['segment'],1)
        self.assertEqual(self.a.check_tx(tx(self.g,old,77,nullifier=n.parse(first)[5]))['code'],5)
        for _ in range(40):self.block([b'malformed'])
        while self.a.height<80:self.block()
        self.assertEqual(self.a.checkpoint['attempt_count'],49)
        self.assertLess(len(n.canonical(self.a.checkpoint)),4096)
        before=self.a.info();self.reopen();self.assertEqual(self.a.info(),before)
    def test_proposal_and_admission_do_not_reserve(self):
        wire=tx(self.g,self.root(),0);before=self.a.info()
        self.assertEqual(self.a.check_tx(wire)['code'],0)
        self.assertEqual(self.a.check_tx(wire)['code'],0)
        self.assertEqual(self.a.prepare_proposal([wire,wire],1,10000),[wire])
        self.assertFalse(self.a.process_proposal([wire,wire],1,bytes.fromhex(self.a.validators.hash)))
        self.assertEqual(self.a.info(),before)
        self.assertEqual(self.a.db.execute('SELECT COUNT(*) FROM p9_nullifiers').fetchone()[0],0)
    def test_commit_failure_rolls_back_all_indexes_and_checkpoint(self):
        before=self.a.info();finalize(self.a,[tx(self.g,self.root(),0)],1)
        self.a.db.execute("CREATE TEMP TRIGGER fail BEFORE INSERT ON p9_blocks BEGIN SELECT RAISE(ABORT,'injected'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.a.commit()
        self.assertEqual(self.a.info(),before)
        self.assertEqual(self.a.db.execute('SELECT COUNT(*) FROM p9_nullifiers').fetchone()[0],0)
        self.a.db.execute('DROP TRIGGER fail');self.a.commit();self.reopen()
        self.assertEqual(self.a.checkpoint['accepted_count'],1)
    def test_exact_finalize_recovery_and_conflict_refusal(self):
        wire=tx(self.g,self.root(),0);wanted=finalize(self.a,[wire],1)
        self.assertEqual(finalize(self.a,[wire],1),wanted);self.a.commit();self.reopen()
        self.assertEqual(finalize(self.a,[wire],1),wanted)
        with self.assertRaises(n.Invalid):finalize(self.a,[],1)
    def test_global_output_and_request_uniqueness(self):
        root=self.root();wire=tx(self.g,root,0);self.block([wire])
        self.assertEqual(self.a.check_tx(tx(self.g,root,1,request=n.parse(wire)[6]))['code'],5)
        self.assertEqual(self.a.check_tx(tx(self.g,root,1,outputs=[n.parse(wire)[10],f(8000)]))['code'],5)
    def test_corrupt_derived_index_refused_on_reopen(self):
        self.block([tx(self.g,self.root(),0)]);self.a.db.execute('DELETE FROM p9_nullifiers')
        self.a.close()
        with self.assertRaises(n.Invalid):Application(self.path,self.w,expected_genesis=self.raw)
    def test_corrupt_retained_request_refused_on_reopen(self):
        self.block();self.a.db.execute("UPDATE p9_blocks SET request_wire=?",(b'bad',));self.a.close()
        with self.assertRaises(n.Invalid):Application(self.path,self.w,expected_genesis=self.raw)
    def test_corrupt_retained_response_refused_on_reopen(self):
        self.block();self.a.db.execute("UPDATE p9_blocks SET response=?",(b'bad',));self.a.close()
        with self.assertRaises(n.Invalid):Application(self.path,self.w,expected_genesis=self.raw)
    def test_uncommitted_finalize_discarded(self):
        finalize(self.a,[tx(self.g,self.root(),0)],1);self.reopen()
        self.assertEqual(self.a.height,0);self.assertEqual(self.a.checkpoint['accepted_count'],0)
    def test_p8_genesis_and_unknown_profile_refused(self):
        other=copy.deepcopy(self.g);other['protocol_version']=8
        with self.assertRaises(n.Invalid):p.genesis_shape(n.canonical(other))
    def test_postcommit_refresh_failure_closes_and_reopens_durable_state(self):
        finalize(self.a,[tx(self.g,self.root(),0)],1)
        with patch.object(self.a,'_publish',side_effect=RuntimeError('post-commit injected')):
            with self.assertRaises(RuntimeError):self.a.commit()
        self.assertTrue(self.a.closed)
        self.reopen();self.assertEqual(self.a.height,1)
        self.assertEqual(self.a.checkpoint['accepted_count'],1)
    def test_unknown_root_badproof_window_and_context_refused(self):
        wire=tx(self.g,self.root(),0)
        self.assertEqual(self.a.check_tx(tx(self.g,f(9999),1))['code'],4)
        bad=bytearray(wire);bad[-1]=1;self.assertEqual(self.a.check_tx(bytes(bad))['code'],6)
        bad=bytearray(wire);bad[8+8*32:8+9*32]=n.field(f(1))
        self.assertEqual(self.a.check_tx(bytes(bad))['code'],1)
        other=copy.deepcopy(self.g);other['network']=f(9999)
        self.assertEqual(self.a.check_tx(tx(other,self.root(),2))['code'],2)
    def test_query_large_segment_and_snapshot_refuse(self):
        self.assertEqual(self.a.query('/segment/9999999999999999999')['code'],1)
        self.assertEqual(self.a.query('/state',prove=True)['code'],1)
        from protocol9_abci_server import dispatch
        q=Request();q.offer_snapshot.SetInParent()
        self.assertEqual(dispatch(self.a,q).offer_snapshot.result,3)
        other=copy.deepcopy(self.g);other['profile_sha256']='ff'*32
        with self.assertRaises(n.Invalid):p.genesis_shape(n.canonical(other))

if __name__=='__main__':unittest.main()
