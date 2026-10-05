"""Actual-proof P7 owner/payment ordering, durable recovery and unavailable gates."""
import copy,hashlib,json,os,sqlite3,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from protocol7_application import Application
from protocol7_treasury import canonical,command,parse,ZERO,Unavailable
from protocol7_worker import Worker
@unittest.skipUnless(os.environ.get('P7_FIXTURES') and os.environ.get('P7_WORKER'),'unassessed: explicit real owner verifier/domain proof inputs not supplied')
class ApplicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d=Path(os.environ['P7_FIXTURES']);cls.g=(cls.d/'p7-genesis.json').read_bytes();cls.gdoc=json.loads(cls.g)
        cls.txs={p.stem:p.read_bytes() for p in cls.d.glob('*.tx')};cls.w=Worker(Path(os.environ['P7_WORKER']),os.environ['P7_WORKER_SHA256'],cls.txs['a'])
        cls.key=Ed25519PrivateKey.from_private_bytes(bytes([7])*32)
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.directory=Path(self.temp.name);self.directory.chmod(0o700);self.db=self.directory/'state.sqlite'
        self.app=Application(self.db,self.w,expected_genesis=self.g);self.app.init_chain(self.gdoc['chain_id'],self.g,self.gdoc['validators'])
    def tearDown(self):self.app.close();self.temp.cleanup()
    def cmd(self,kind='revoke',state=None,height=1):
        state=self.app.state if state is None else state;slot=state['treasury']['grants'][0]
        p=parse(self.txs['rotated_a']);c,k=(ZERO,slot['agent_key']) if kind=='revoke' else (p[8],p[29])
        return command(self.gdoc,state,kind=kind,grant_id=slot['id'],height=height,new_commitment=c,new_agent_key=k,key=self.key,worker=self.w)
    def finalize(self,txs,h=1,wire=b'first',block=b'x'*32):
        votes=[] if h==1 else [{'address':v.address.hex(),'power':v.power,'block_id_flag':2} for v in self.app.validators.validators]
        return self.app.finalize_block(txs,h,block,bytes.fromhex(self.app.validators.hash),votes,wire)
    def test_8192_transaction_and_two_payment_wire_bounds(self):
        self.assertEqual(len(self.txs['a']),4168)
        self.assertEqual(self.app.check_tx(self.txs['a'])['code'],0)
        self.assertEqual(self.app.check_tx(b'x'*8193)['code'],1)
        self.assertEqual(self.app.prepare_proposal([self.txs['a'],self.txs['after_a_b']],1,16400),[self.txs['a'],self.txs['after_a_b']])
        self.assertTrue(self.app.process_proposal([self.txs['a'],self.txs['after_a_b']],1,bytes.fromhex(self.app.validators.hash)))
        self.finalize([self.txs['a'],self.txs['after_a_b']]);self.app.commit();self.assertEqual(self.app.state['treasury']['fees'],4)
    def test_admission_and_prepared_owner_state_are_not_committed(self):
        before=self.app.query('/state')['value'];cmd=self.cmd()
        self.assertEqual(self.app.check_tx(cmd)['code'],0)
        self.assertEqual(self.app.check_tx(self.txs['a'])['code'],0)
        self.assertEqual(self.app.prepare_proposal([cmd,self.txs['a']],1,16400),[cmd])
        self.assertFalse(self.app.process_proposal([cmd,self.txs['a']],1,bytes.fromhex(self.app.validators.hash)))
        result,_=self.finalize([cmd,self.txs['a']]);self.assertEqual([x['code'] for x in result['tx_results']],[0,2])
        self.assertEqual(self.app.query('/state')['value'],before);self.app.commit()
        self.assertEqual(self.app.state['treasury']['owner_sequence'],1);self.assertEqual(self.app.state['treasury']['fees'],0)
        self.assertEqual(self.app.check_tx(self.txs['a'])['code'],2)
    def test_payment_first_stales_owner_then_fresh_revoke_and_actual_survivor(self):
        old=self.cmd();r,_=self.finalize([self.txs['a'],old]);self.assertEqual([x['code'] for x in r['tx_results']],[0,2]);self.app.commit()
        fresh=self.cmd(height=2);self.finalize([fresh],2,wire=b'second');self.app.commit()
        self.finalize([self.txs['after_a_revoke_b']],3,wire=b'third');self.app.commit()
        self.assertEqual([r['kind'] for r in self.app.state['receipts']],['payment','owner','payment'])
        self.assertEqual(self.app.state['treasury']['fees'],4);self.assertEqual(self.app.state['treasury']['owner_sequence'],1)
    def test_rotate_then_new_generation_actual_payment_reopen(self):
        oldnotes=copy.deepcopy(self.app.state['treasury']['notes']);self.finalize([self.cmd('rotate')]);self.app.commit()
        self.assertEqual(self.app.state['treasury']['notes'],oldnotes);self.assertEqual(self.app.check_tx(self.txs['a'])['code'],2)
        self.finalize([self.txs['rotated_a']],2,wire=b'second');self.app.commit()
        self.app.close();self.app=Application(self.db,self.w,expected_genesis=self.g)
        self.assertEqual(self.app.state['treasury']['grants'][0]['generation'],2);self.assertEqual(self.app.state['treasury']['fees'],2)
    def test_competing_commands_one_successor_and_exact_recovery_response(self):
        r,wire=self.finalize([self.cmd(),self.cmd('rotate')]);self.assertEqual([x['code'] for x in r['tx_results']],[0,2])
        self.assertEqual(self.finalize([self.cmd(),self.cmd('rotate')])[1],wire)
        self.app.commit();self.app.close();self.app=Application(self.db,self.w,expected_genesis=self.g)
        with self.assertRaises(ValueError):self.finalize([],wire=b'first')
        row=self.app.db.execute('SELECT response FROM blocks WHERE height=1').fetchone();self.assertEqual(bytes(row[0]),wire)
    def test_commit_trigger_failure_preserves_full_old_owner_and_money_state(self):
        before=self.app.query('/state')['value'];self.finalize([self.cmd('rotate')])
        self.app.db.execute("CREATE TEMP TRIGGER reject BEFORE INSERT ON blocks BEGIN SELECT RAISE(ABORT,'failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.app.commit()
        self.assertEqual(self.app.query('/state')['value'],before)
        self.app.close();self.app=Application(self.db,self.w,expected_genesis=self.g);self.assertEqual(self.app.height,0)
    def test_actual_process_death_before_and_after_owner_commit(self):
        self.app.close();(self.directory/'genesis').write_bytes(self.g)
        program="""import os,sys,json
from pathlib import Path
from protocol7_application import Application
from protocol7_worker import Worker
from protocol7_treasury import command,ZERO
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
d=Path(sys.argv[1]);g=(d/'genesis').read_bytes();gd=json.loads(g);fixtures=Path(os.environ['P7_FIXTURES'])
w=Worker(Path(os.environ['P7_WORKER']),os.environ['P7_WORKER_SHA256'],(fixtures/'a.tx').read_bytes());a=Application(d/'state.sqlite',w,expected_genesis=g)
slot=a.state['treasury']['grants'][0];raw=command(gd,a.state,kind='revoke',grant_id=slot['id'],height=1,new_commitment=ZERO,new_agent_key=slot['agent_key'],key=Ed25519PrivateKey.from_private_bytes(bytes([7])*32),worker=w)
a.finalize_block([raw],1,b'x'*32,bytes.fromhex(a.validators.hash),[],b'first')
if sys.argv[2]=='before':
 a.db.create_function('die',0,lambda:os._exit(71));a.db.execute('CREATE TEMP TRIGGER die BEFORE INSERT ON blocks BEGIN SELECT die(); END')
a.commit();os._exit(72)
"""
        for phase,code,wanted in [('before',71,0),('after',72,1)]:
            p=subprocess.run([sys.executable,'-c',program,str(self.directory),phase],timeout=90,capture_output=True)
            self.assertEqual(p.returncode,code,p.stderr.decode());self.app=Application(self.db,self.w,expected_genesis=self.g)
            self.assertEqual(self.app.height,wanted);self.assertEqual(self.app.state['treasury']['owner_sequence'],wanted);self.assertEqual(self.app.state['treasury']['fees'],0);self.app.close()
    def test_unavailable_proposals_and_finalize_abort_without_rejection_or_stage(self):
        cmd=self.cmd();before=self.app.query('/state')['value']
        for method in ('check','prepare','process','finalize'):
            with patch.object(self.w,'context_root',side_effect=Unavailable('actual operation unavailable')):
                with self.assertRaises(Unavailable):
                    if method=='check':self.app.check_tx(cmd)
                    elif method=='prepare':self.app.prepare_proposal([cmd],1,16400)
                    elif method=='process':self.app.process_proposal([cmd],1,bytes.fromhex(self.app.validators.hash))
                    else:self.finalize([cmd])
            self.assertEqual(self.app.query('/state')['value'],before);self.assertIsNone(self.app.pending)
    def test_cache_remeasures_real_binary_before_return(self):
        self.assertTrue(self.w.verify(self.txs['a']))
        with patch.object(self.w,'sha256','ab'*32),self.assertRaises(Unavailable):self.w.verify(self.txs['a'])
    def test_retained_request_result_command_state_and_receipt_tamper_refused(self):
        self.finalize([self.cmd()]);self.app.commit();self.app.close()
        db=sqlite3.connect(self.db);state=json.loads(db.execute('SELECT state FROM checkpoint').fetchone()[0]);state['receipts'][0]['body']['new_agent_key']=ZERO
        db.execute('UPDATE checkpoint SET state=?',(canonical(state),));db.commit();db.close()
        with self.assertRaises(ValueError):Application(self.db,self.w,expected_genesis=self.g)
    def test_exact_retained_finalize_wire_is_audited(self):
        self.finalize([self.cmd()]);self.app.commit();self.app.close()
        db=sqlite3.connect(self.db);db.execute('UPDATE blocks SET request_wire=?',(b'changed',));db.commit();db.close()
        with self.assertRaises(ValueError):Application(self.db,self.w,expected_genesis=self.g)
    def test_immutable_validators_and_unsupported_state_sync(self):
        self.assertFalse(self.app.process_proposal([],1,b'z'*32))
        with self.assertRaises(ValueError):self.finalize([],wire=b'x'*32769)
        for path in ('/snapshot','/rotate','/revoke','/unknown'):self.assertEqual(self.app.query(path)['code'],1)
        self.assertEqual(self.app.query('/state',prove=True)['code'],1);self.assertEqual(self.app.info()['version'],7)
if __name__=='__main__':unittest.main()
