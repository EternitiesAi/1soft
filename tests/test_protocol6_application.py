import os
import copy, importlib, json, os, sqlite3, subprocess, sys, tempfile, unittest
from pathlib import Path
from test_protocol6_treasury import FIX,fixture_genesis,worker
try:
    from protocol6_application import Application
except ModuleNotFoundError:Application=None
from protocol6_treasury import canonical

@unittest.skipUnless(os.environ.get('P6_WORKER') and os.environ.get('P6_WORKER_SHA256'),'unassessed: explicit P6 real-verifier inputs were not supplied')
class ApplicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w=worker();cls.g=canonical(fixture_genesis(cls.w.sha256));cls.a=(FIX/'a.tx').read_bytes()
    def setUp(self):
        self.assertIsNotNone(Application,'P6 durable validator lifecycle is missing')
        self.temp=tempfile.TemporaryDirectory();self.dir=Path(self.temp.name);self.dir.chmod(0o700)
        self.db=self.dir/'state.sqlite';self.app=Application(self.db,self.w,expected_genesis=self.g)
        g=json.loads(self.g)
        self.app.init_chain(g['chain_id'],self.g,g['validators'],1)
    def tearDown(self):
        if hasattr(self,'app'):self.app.close();self.temp.cleanup()
    def finalize(self,raw=None,h=1,wire=b'first',block=b'x'*32):
        votes=[] if h==1 else [{'address':v.address.hex(),'power':v.power,'block_id_flag':2} for v in self.app.validators.validators]
        return self.app.finalize_block([self.a] if raw is None else raw,h,block,bytes.fromhex(self.app.validators.hash),votes,wire)
    def test_admission_proposals_and_pending_state_are_not_committed(self):
        before=self.app.query('/state')['value']
        self.assertEqual(self.app.check_tx(self.a)['code'],0)
        self.assertEqual(self.app.prepare_proposal([self.a,(FIX/'b.tx').read_bytes()],1,10000),[self.a])
        self.assertFalse(self.app.process_proposal([self.a,(FIX/'b.tx').read_bytes()],1,bytes.fromhex(self.app.validators.hash)))
        self.finalize()
        self.assertEqual(self.app.query('/state')['value'],before)
        self.app.commit();s=json.loads(self.app.query('/state')['value'])
        self.assertEqual(s['height'],1);self.assertEqual(s['state']['treasury']['fees'],2)
        self.assertEqual(len(s['state']['receipts']),1)
    def test_replay_identity_and_restart_exact_response(self):
        retained,wire=self.finalize()
        self.assertEqual(self.finalize()[1],wire)
        with self.assertRaises(ValueError):self.finalize(wire=b'changed')
        self.app.commit();self.app.close();self.app=Application(self.db,self.w,expected_genesis=self.g)
        self.assertEqual(self.finalize()[1],wire)
        with self.assertRaises(ValueError):self.finalize(raw=[],wire=b'first')
    def test_commit_trigger_failure_preserves_entire_old_state(self):
        before=self.app.query('/state')['value'];self.finalize()
        self.app.db.execute("CREATE TEMP TRIGGER reject BEFORE INSERT ON blocks BEGIN SELECT RAISE(ABORT,'failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.app.commit()
        self.assertEqual(self.app.query('/state')['value'],before)
        self.app.close();self.app=Application(self.db,self.w,expected_genesis=self.g)
        self.assertEqual(self.app.height,0)
    def test_actual_process_death_before_and_after_commit(self):
        self.app.close();(self.dir/'genesis').write_bytes(self.g)
        program="""import os,sys
from pathlib import Path
from protocol6_application import Application
from test_protocol6_treasury import worker,FIX
d=Path(sys.argv[1]);a=Application(d/'state.sqlite',worker(),expected_genesis=(d/'genesis').read_bytes())
a.finalize_block([(FIX/'a.tx').read_bytes()],1,b'x'*32,bytes.fromhex(a.validators.hash),[],b'first')
if sys.argv[2]=='before':
 a.db.create_function('die',0,lambda:os._exit(71))
 a.db.execute('CREATE TEMP TRIGGER die BEFORE INSERT ON blocks BEGIN SELECT die(); END')
a.commit();os._exit(72)
"""
        for phase,exitcode,wanted in [('before',71,0),('after',72,1)]:
            p=subprocess.run([sys.executable,'-c',program,str(self.dir),phase],timeout=90,capture_output=True)
            self.assertEqual(p.returncode,exitcode,p.stderr.decode())
            self.app=Application(self.db,self.w,expected_genesis=self.g)
            self.assertEqual(self.app.height,wanted)
            self.assertEqual(len(self.app.state['receipts']),wanted)
            self.assertEqual(self.app.state['treasury']['fees'],2*wanted)
            self.app.close()
    def test_changed_genesis_schema_and_receipt_fail_closed(self):
        self.finalize();self.app.commit();self.app.close()
        g=json.loads(self.g);g['chain_id']='another-p6'
        with self.assertRaises(ValueError):Application(self.db,self.w,expected_genesis=canonical(g))
        c=sqlite3.connect(self.db);state=json.loads(c.execute('SELECT state FROM checkpoint').fetchone()[0]);state['receipts'][0]['fee']=999
        c.execute('UPDATE checkpoint SET state=?',(canonical(state),));c.commit();c.close()
        with self.assertRaises(ValueError):Application(self.db,self.w,expected_genesis=self.g)
    def test_immutable_validators_and_unsupported_interfaces(self):
        self.assertFalse(self.app.process_proposal([],1,b'z'*32))
        with self.assertRaises(ValueError):self.app.finalize_block([],1,b'x'*32,b'z'*32,[],b'wire')
        for p in ['/revoke','/snapshot','/unknown']:
            self.assertEqual(self.app.query(p)['code'],1)
        self.assertEqual(self.app.query('/state',prove=True)['code'],1)
        self.assertEqual(self.app.query('/state',height=True)['code'],1)
if __name__=='__main__':unittest.main()
