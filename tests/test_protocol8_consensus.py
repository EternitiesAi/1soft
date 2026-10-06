"""Lifecycle and schema tests with a labeled fake worker; no native proof claim."""
import copy, hashlib, os, socket, sqlite3, sys, tempfile, threading, unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
import protocol8_transfer as n
import protocol8_consensus as p
from protocol8_application import Application
from protocol8_worker import Worker
from protocol8_certificate import verify_state
from protocol8_abci_server import dispatch
from protocol5_abci_wire import Request
from abci_server import Server
from abci_wire import read_frame, write_frame

def f(v): return v.to_bytes(32, 'little').hex()
def wire(fields): return b'1SRCT008' + b''.join(bytes.fromhex(v) for v in fields) + b'\0' * n.PROFILE['proof_bytes']
class FakeWorker(Worker):
    """Synthetic syntax/state mechanics only; deliberately not cryptography."""
    sha256 = 'ab' * 32
    identity = {'sha256': sha256, 'bytes': 1}
    startup = {'fake_worker': True, 'native_qualification': False}
    def __init__(self): pass
    def guard(self): pass
    def network_domain(self, raw): return f(1)
    def root(self, notes):
        for v in notes: n.field(v)
        n.need(1 <= len(notes) <= 16 and len(set(notes)) == len(notes), 'notes')
        return f(int.from_bytes(hashlib.sha256(b''.join(bytes.fromhex(v) for v in notes)).digest(), 'little') % n.MODULUS or 1)
    def verify(self, raw, network): return n.parse(raw)[1] == network and raw[-1] == 0
    def audit(self): return {'fake_worker': True}

class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.w = FakeWorker()
        self.fields = [f(v) for v in (8,1,2,3,1,5,6,1,32,1,10,11,12)]
        self.fields[4] = self.w.root([f(100)])
        self.first = wire(self.fields)
        self.w.kat_statement = n.parse(self.first); self.w.kat_sha256 = p.digest(self.first)
        self.g = {'format':p.GENESIS_FORMAT, 'protocol_version':8, 'chain_id':'p8-fake-test',
            'profile_sha256':p.PROFILE_SHA256, 'worker_sha256':self.w.sha256,
            'kat_sha256':self.w.kat_sha256, 'validators':[{'public_key':f(v), 'power':10} for v in range(1,5)],
            'pool_id':'cd'*32, 'asset':f(2), 'mission':f(3), 'fee':1, 'network':f(1),
            'notes':[{'kind':'p8-recipient-v1','commitment':f(100)}]}
        self.raw = p.canonical(self.g)
        self.temp = tempfile.TemporaryDirectory(); self.d = Path(self.temp.name); self.d.chmod(0o700)
        self.path = self.d/'state.sqlite'; self.app = Application(self.path,self.w,expected_genesis=self.raw)
        self.app.init_chain(self.g['chain_id'],self.raw,self.g['validators'])
        self.vh = bytes.fromhex(self.app.validators.hash)
        s,_ = p.execute_block(self.g,self.app.state,[self.first],1,self.w)
        fields = self.fields.copy(); fields[4] = s['ledger']['anchors'][-1]
        for i,v in ((5,15),(6,16),(10,20),(11,21)): fields[i] = f(v)
        self.second = wire(fields)
        fields = self.fields.copy()
        for i,v in ((6,26),(10,30),(11,31)): fields[i] = f(v)
        self.competing = wire(fields)
    def tearDown(self): self.app.close(); self.temp.cleanup()
    def finalize(self, txs, h=1, request=b'first'):
        votes = [] if h == 1 else [{'address':v.address.hex(),'power':v.power,'block_id_flag':2} for v in self.app.validators.validators]
        return self.app.finalize_block(txs,h,b'x'*32,self.vh,votes,request)
    def test_ordered_receive_respend_and_double_nullifier(self):
        before = self.app.query('/state')['value']
        self.assertEqual(self.app.check_tx(self.first)['code'],0)
        self.assertEqual(self.app.check_tx(self.competing)['code'],0)
        self.assertEqual(self.app.query('/state')['value'],before)
        self.assertEqual(self.app.prepare_proposal([self.first,self.second],1,8208),[self.first,self.second])
        self.assertTrue(self.app.process_proposal([self.first,self.second],1,self.vh))
        self.assertEqual(self.app.prepare_proposal([self.second,self.first],1,8208),[self.first])
        self.assertFalse(self.app.process_proposal([self.second,self.first],1,self.vh))
        self.assertEqual(self.app.prepare_proposal([self.first,self.competing],1,8208),[self.first])
        value,_ = self.finalize([self.first,self.competing]); self.assertEqual([r['code'] for r in value['tx_results']],[0,5])
        self.assertEqual(self.app.query('/state')['value'],before); self.app.commit()
        self.finalize([self.second],2,b'second'); self.app.commit()
        self.assertEqual(self.app.state['ledger']['fees'],2)
        self.assertEqual(len(self.app.state['ledger']['notes']),5)
        self.assertEqual(self.app.check_tx(self.competing)['code'],5)
    def test_atomic_commit_failure_keeps_old_checkpoint(self):
        before = self.app.query('/state')['value']; self.finalize([self.first])
        self.app.db.execute("CREATE TEMP TRIGGER fail BEFORE INSERT ON p8_blocks BEGIN SELECT RAISE(ABORT,'injected'); END")
        with self.assertRaises(sqlite3.IntegrityError): self.app.commit()
        self.assertEqual(self.app.query('/state')['value'],before)
        self.app.close(); self.app=Application(self.path,self.w,expected_genesis=self.raw)
        self.assertEqual(self.app.height,0); self.assertEqual(self.app.state['ledger']['fees'],0)
    def test_pending_committed_identity_and_same_store_recovery(self):
        value,response = self.finalize([self.first])
        self.assertEqual(self.finalize([self.first]),(value,response))
        with self.assertRaises(n.Invalid): self.finalize([self.first],request=b'changed')
        self.app.commit(); self.app.close(); self.app=Application(self.path,self.w,expected_genesis=self.raw)
        self.assertEqual(self.finalize([self.first]),(value,response))
        self.assertEqual(self.app.state['ledger']['fees'],1)
    def test_staged_uncommitted_state_is_discarded_on_reopen(self):
        self.finalize([self.first]); self.app.close(); self.app=Application(self.path,self.w,expected_genesis=self.raw)
        self.assertEqual(self.app.height,0); self.assertIsNone(self.app.pending)
    def test_retained_wire_and_state_tampering_refused(self):
        self.finalize([self.first]); self.app.commit(); self.app.close()
        db=sqlite3.connect(self.path); db.execute('UPDATE p8_blocks SET request_wire=?',(b'changed',)); db.commit(); db.close()
        with self.assertRaises(n.Invalid): Application(self.path,self.w,expected_genesis=self.raw)
    def test_genesis_roster_types_and_extra_fields_refused(self):
        for key,value in [('fee',True),('network',f(9)),('notes',[]),('validators',self.g['validators'][:3]),('extra',1)]:
            g=copy.deepcopy(self.g); g[key]=value
            with self.subTest(key=key),self.assertRaises(n.Invalid): p.genesis_document(p.canonical(g),self.w)
        other=copy.deepcopy(self.g);other['pool_id']='ef'*32
        self.assertNotEqual(p.bootstrap_digest(self.g),p.bootstrap_digest(other))
        self.assertNotEqual(p.application_hash(self.g,0,self.app.state),p.application_hash(other,0,self.app.state))
    def test_external_state_shape_and_history_result_tampering_refused(self):
        for value in (None,[],{}, {'blocks':[]}, {'format':p.STATE_FORMAT,'version':8,'ledger':{},'blocks':[{}]}):
            with self.subTest(value=value),self.assertRaises(n.Invalid): p.execute_block(self.g,value,[],1,self.w)
        s,_=p.execute_block(self.g,self.app.state,[self.first],1,self.w)
        s['blocks'][0]['results'][0]['code']=5
        with self.assertRaises(n.Invalid): p.replay(self.g,s,1,self.w)
    def test_fee_context_window_syntax_and_invalid_proof_codes(self):
        for i,v,code in ((1,9,2),(2,9,2),(3,9,2),(4,9,4),(7,2,3),(9,2,2)):
            fields=self.fields.copy();fields[i]=f(v)
            self.assertEqual(self.app.check_tx(wire(fields))['code'],code)
        self.assertEqual(self.app.check_tx(self.first+b'x')['code'],1)
        bad=bytearray(self.first);bad[-1]=1
        self.assertEqual(self.app.check_tx(bytes(bad))['code'],6)
        self.assertEqual(self.app.prepare_proposal([self.first],1,10),[])
        self.assertFalse(self.app.process_proposal([],1,b'z'*32))
    def test_worker_unavailable_quarantines_endpoint_without_commit(self):
        before=self.app.query('/state')['value']
        with patch.object(self.w,'guard',side_effect=n.Unavailable('injected')):
            with self.assertRaises(n.Unavailable): self.app.check_tx(self.first)
            endpoint=Server(str(self.d/'a.sock'),self.app,request_type=Request,dispatcher=dispatch)
            thread=threading.Thread(target=endpoint.serve_forever,daemon=True);thread.start()
            try:
                request=Request();request.check_tx.tx=self.first
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
                    connection.settimeout(5);connection.connect(str(self.d/'a.sock'))
                    with connection.makefile('rwb',buffering=0) as stream:
                        with self.assertLogs(level='ERROR'):
                            write_frame(stream,request);self.assertIsNone(read_frame(stream));thread.join(5)
                self.assertTrue(endpoint.failed.is_set());self.assertEqual(endpoint.metrics()['internal_faults'],1)
            finally:endpoint.shutdown();endpoint.server_close();thread.join(5)
        self.assertEqual(self.app.query('/state')['value'],before);self.assertIsNone(self.app.pending)
    def test_witness_mutation_refused_before_header_processing(self):
        witness={'genesis':self.g,'height':0,'app_hash':self.app.app_hash,'state':copy.deepcopy(self.app.state)}
        for key,value in [('height',True),('app_hash','ff'*32),('state',{}),('extra',1)]:
            bad=copy.deepcopy(witness);bad[key]=value
            with self.subTest(key=key),self.assertRaises(n.Invalid): verify_state(bad,{},self.raw,self.w)
    def test_unsupported_snapshot_and_query_contract(self):
        for method,expected in [('offer_snapshot',3),('apply_snapshot_chunk',2)]:
            request=Request();getattr(request,method).SetInParent()
            self.assertEqual(getattr(dispatch(self.app,request),method).result,expected)
        self.assertEqual(self.app.query('/snapshot')['code'],1)
        self.assertEqual(self.app.query('/state',prove=True)['code'],1)

if __name__=='__main__':unittest.main()
