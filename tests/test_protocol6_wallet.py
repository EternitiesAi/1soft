"""Real-proof/signed-state tests that detect premature release and duplicated delivery."""
import copy,hashlib,json,os,sqlite3,subprocess,sys,tempfile,threading,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from certificate_fixture import make_commit,make_header
from commit_verifier import sha
from protocol6_certificate import trust
from protocol6_treasury import canonical,initial_state,execute_block,application_hash,txid
from test_protocol6_treasury import FIX,fixture_genesis,worker
try:
    from protocol6_wallet import CertifiedTreasuryJournal
except ModuleNotFoundError:CertifiedTreasuryJournal=None

@unittest.skipUnless(os.environ.get('P6_WORKER') and os.environ.get('P6_WORKER_SHA256'),'unassessed: explicit P6 real-verifier inputs were not supplied')
class WalletTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if CertifiedTreasuryJournal is None:return
        cls.w=worker();cls.g=fixture_genesis(cls.w.sha256)
        cls.private=[Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(31,35)]
        cls.g['validators']=sorted([{'public_key':k.public_key().public_bytes_raw().hex(),'power':10} for k in cls.private],key=lambda r:r['public_key'])
        cls.raw=canonical(cls.g);cls.anchor=trust(cls.raw)
        byaddr={sha(k.public_key().public_bytes_raw())[:20]:k for k in cls.private}
        cls.keys=[byaddr[v.address] for v in cls.anchor.validators]
        cls.a=(FIX/'a.tx').read_bytes();cls.b=(FIX/'b.tx').read_bytes();cls.s0=initial_state(cls.g,cls.w)
        cls.sa,_=execute_block(cls.g,cls.s0,[cls.a],1,cls.w)
        cls.sb,_=execute_block(cls.g,cls.s0,[cls.b],1,cls.w)
    def setUp(self):
        self.assertIsNotNone(CertifiedTreasuryJournal,'P6 certified exact-obligation journal is missing')
        self.tmp=tempfile.TemporaryDirectory();self.dir=Path(self.tmp.name);self.db=self.dir/'wallet.sqlite'
        self.j=CertifiedTreasuryJournal(self.db,expected_genesis=self.raw,worker=self.w)
    def tearDown(self):
        if hasattr(self,'j'):self.j.close();self.tmp.cleanup()
    def signed(self,state,height,round_=0):
        witness={'genesis':copy.deepcopy(self.g),'height':height,'state':copy.deepcopy(state),'app_hash':application_hash(self.g,height,state)}
        previous={'hash':('ab'*32).upper(),'parts':{'total':1,'hash':('cd'*32).upper()}} if height else None
        signed=make_commit(make_header(self.anchor,height+1,witness['app_hash'],previous=previous),self.anchor,self.keys,round_=round_)
        return witness,signed
    def observe(self,state=None,height=1):return self.j.observe(*self.signed(self.sa if state is None else state,height))
    def reopen(self):
        self.j.close();self.j=CertifiedTreasuryJournal(self.db,expected_genesis=self.raw,worker=self.w)
    def test_known_conflict_refuses_first_claim_durably(self):
        ident=self.j.retain(self.b);self.observe();self.reopen()
        with self.assertRaises(ValueError):self.j.claim(ident)
        self.assertEqual(self.j.status(ident)['attempts'],0);self.assertEqual(self.j.export(ident),self.b)
    def test_known_elapsed_window_refuses_first_claim_without_release(self):
        ident=self.j.retain(self.a);state=copy.deepcopy(self.s0)
        for h in range(1,22):state,_=execute_block(self.g,state,[],h,self.w)
        self.observe(state,21);self.reopen()
        with self.assertRaises(ValueError):self.j.claim(ident)
        self.assertEqual(self.j.status(ident)['attempts'],0);self.assertEqual(self.j.status(ident)['hold_reason'],'unknown')
    def test_authenticated_unknown_before_claim_remains_eligible(self):
        ident=self.j.retain(self.a);self.observe(self.s0,0)
        self.assertEqual(self.j.claim(ident),self.a);self.assertEqual(self.j.status(ident)['attempts'],1)
    def test_cli_records_signed_state_using_explicit_external_pins(self):
        ident=self.j.retain(self.a);self.j.claim(ident);self.j.close()
        genesis=self.dir/'cli-genesis.json';genesis.write_bytes(self.raw)
        packet=self.dir/'cli-observation.json';packet.write_bytes(canonical(dict(zip(('witness','signed_header'),self.signed(self.sa,1)))))
        root=Path(__file__).resolve().parents[1]
        command=[sys.executable,str(root/'scripts/treasury_wallet.py'),'--journal',str(self.db),'--genesis',str(genesis),'--genesis-sha256',hashlib.sha256(self.raw).hexdigest(),'--worker',os.environ['P6_WORKER'],'--worker-sha256',self.w.sha256,'--kat',str(FIX/'a.tx'),'observe','--packet',str(packet)]
        done=subprocess.run(command,capture_output=True,timeout=120)
        self.assertEqual(done.returncode,0,done.stderr.decode()+done.stdout.decode())
        self.assertEqual(json.loads(done.stdout)['status'],'completed-local-command')
        self.reopen();self.assertEqual(self.j.status(ident)['status'],'recorded-certified')
        self.assertEqual(self.j.export(ident),self.a)
    def test_exact_completion_survives_reopen_and_preserves_original_bytes(self):
        ident=self.j.retain(self.a);self.assertEqual(self.j.claim(ident),self.a);self.observe();self.reopen()
        status=self.j.status(ident);self.assertEqual(status['status'],'recorded-certified')
        record=self.j.recorded_receipt(ident);self.assertEqual(bytes.fromhex(record['raw']),self.a)
        self.assertEqual(record['receipt']['height'],1);self.assertEqual(record['state_height'],1)
        self.assertEqual(self.j.export(ident),self.a)
        with self.assertRaises(ValueError):self.j.claim(ident)
    def test_lost_return_claims_before_io_and_never_retries(self):
        ident=self.j.retain(self.a);calls=[]
        def lost(raw):
            self.assertEqual(self.j.status(ident)['attempts'],1);calls.append(raw);raise TimeoutError('lost response')
        self.assertEqual(self.j.deliver_once(ident,lost)['outcome'],'unknown')
        with self.assertRaises(ValueError):self.j.deliver_once(ident,lost)
        self.assertEqual(calls,[self.a]);self.assertEqual(self.j.status(ident)['status'],'attempted-held')
        self.observe();self.assertEqual(self.j.status(ident)['status'],'recorded-certified')
    def test_transport_success_is_only_an_untrusted_hint(self):
        ident=self.j.retain(self.a)
        self.assertEqual(self.j.deliver_once(ident,lambda raw:{'code':0})['outcome'],'returned-untrusted')
        self.assertEqual(self.j.status(ident)['status'],'attempted-held')
        with self.assertRaises(ValueError):self.j.recorded_receipt(ident)
    def test_conflict_and_refreshed_replacement_keep_original_hold(self):
        ident=self.j.retain(self.b);self.j.claim(ident);self.observe()
        s=self.j.status(ident);self.assertEqual(s['status'],'observed-held');self.assertEqual(s['hold_reason'],'conflict')
        self.assertEqual(self.j.export(ident),self.b)
        with self.assertRaises(ValueError):self.j.retain((FIX/'after_a_b.tx').read_bytes())
        with self.assertRaises(ValueError):self.j.recorded_receipt(ident)
    def test_shared_parent_and_input_reservation_serializes_competing_proofs(self):
        self.j.retain(self.a)
        with self.assertRaises(ValueError):self.j.retain(self.b)
        with self.assertRaises(ValueError):self.j.retain(self.a)
    def test_absence_after_expiry_never_releases(self):
        ident=self.j.retain(self.a);state=copy.deepcopy(self.s0)
        for h in range(1,22):state,_=execute_block(self.g,state,[],h,self.w)
        self.observe(state,21);self.assertEqual(self.j.status(ident)['hold_reason'],'unknown')
        with self.assertRaises(ValueError):self.j.recorded_receipt(ident)
        with self.assertRaises(ValueError):self.j.retain(self.b)
    def test_older_or_same_height_conflicting_certificate_changes_nothing(self):
        ident=self.j.retain(self.a);self.observe();before=self.j.status(ident)
        for state,h in [(self.s0,0),(self.sb,1)]:
            with self.assertRaises(ValueError):self.observe(state,h)
            self.assertEqual(self.j.status(ident),before)
    def test_higher_valid_fork_cannot_replace_observed_history(self):
        ident=self.j.retain(self.a);self.observe();fork,_=execute_block(self.g,self.sb,[(FIX/'after_b_a.tx').read_bytes()],2,self.w)
        with self.assertRaises(ValueError):self.observe(fork,2)
        self.assertEqual(self.j.status(ident)['status'],'recorded-certified')
    def test_same_state_different_valid_round_is_idempotent(self):
        ident=self.j.retain(self.a);self.observe();record=self.j.recorded_receipt(ident)
        self.j.observe(*self.signed(self.sa,1,round_=1))
        self.assertEqual(self.j.recorded_receipt(ident),record)
    def test_even_quorum_signed_false_receipt_is_refused(self):
        ident=self.j.retain(self.a)
        for key,value in [('raw','00'),('txid','ab'*32),('raw_sha256','ab'*32),('fee',999),('height',20),('merchant_position',9),('change_position',9),('statement',['00'*32]*25),('authority_root_before','ab'*32),('note_root_before','ab'*32),('tx_index',9)]:
            changed=copy.deepcopy(self.sa);changed['receipts'][0][key]=value
            with self.assertRaises(ValueError):self.observe(changed)
            self.assertEqual(self.j.status(ident)['status'],'retained')
    def test_invalid_signature_and_wrong_genesis_leave_holds(self):
        ident=self.j.retain(self.a);w,h=self.signed(self.sa,1);h['commit']['signatures'][0]['signature']='AA=='
        with self.assertRaises(ValueError):self.j.observe(w,h)
        w,h=self.signed(self.sa,1);w['genesis']['chain_id']='other'
        with self.assertRaises(ValueError):self.j.observe(w,h)
        self.assertEqual(self.j.status(ident)['status'],'retained')
    def test_bad_proof_and_wrong_domain_cannot_create_obligation(self):
        bad=bytearray(self.a);bad[-1]^=1
        with self.assertRaises(ValueError):self.j.retain(bytes(bad))
        bad=bytearray(self.a);bad[40:72]=(999).to_bytes(32,'little')
        with self.assertRaises(ValueError):self.j.retain(bytes(bad))
    def test_tampered_retained_raw_and_schema_fail_reopen(self):
        self.j.retain(self.a);self.j.close()
        with sqlite3.connect(self.db) as c:c.execute("UPDATE obligations SET nf=?",('ab'*32,))
        with self.assertRaises(ValueError):CertifiedTreasuryJournal(self.db,expected_genesis=self.raw,worker=self.w)
        # Closing a transaction context is explicit in tests; no leaked test connection.
        c.close()
    def test_wrong_genesis_and_insecure_path_refused(self):
        changed=copy.deepcopy(self.g);changed['chain_id']='other';self.j.close()
        with self.assertRaises(ValueError):CertifiedTreasuryJournal(self.db,expected_genesis=canonical(changed),worker=self.w)
        self.dir.chmod(0o755)
        with self.assertRaises(ValueError):CertifiedTreasuryJournal(self.dir/'bad.sqlite',expected_genesis=self.raw,worker=self.w)
        self.dir.chmod(0o700)
    def test_sql_failure_preserves_old_observation_and_obligation(self):
        ident=self.j.retain(self.a);self.j.db.execute("CREATE TEMP TRIGGER reject BEFORE INSERT ON observations BEGIN SELECT RAISE(ABORT,'failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.observe()
        self.assertEqual(self.j.status(ident)['status'],'retained');self.reopen()
        self.assertEqual(self.j.status(ident)['status'],'retained')
    def test_concurrent_claim_allows_exactly_one_attempt(self):
        ident=self.j.retain(self.a);other=CertifiedTreasuryJournal(self.db,expected_genesis=self.raw,worker=self.w)
        outcomes=[];barrier=threading.Barrier(2)
        def claim(j):
            barrier.wait()
            try:j.claim(ident);outcomes.append('claimed')
            except ValueError:outcomes.append('refused')
        threads=[threading.Thread(target=claim,args=(j,)) for j in (self.j,other)]
        for t in threads:t.start()
        for t in threads:t.join(60);self.assertFalse(t.is_alive())
        other.close();self.assertEqual(sorted(outcomes),['claimed','refused'])
        self.reopen();self.assertEqual(self.j.status(ident)['attempts'],1)
    def test_process_death_before_and_after_observation_commit(self):
        ident=self.j.retain(self.a);self.j.claim(ident);self.j.close()
        (self.dir/'genesis.json').write_bytes(self.raw);(self.dir/'observation.json').write_bytes(canonical(dict(zip(('witness','signed_header'),self.signed(self.sa,1)))))
        program=r"""import json,os,sys
from pathlib import Path
from protocol6_wallet import CertifiedTreasuryJournal
from test_protocol6_treasury import worker
d=Path(sys.argv[1]);j=CertifiedTreasuryJournal(d/'wallet.sqlite',expected_genesis=(d/'genesis.json').read_bytes(),worker=worker())
o=json.loads((d/'observation.json').read_bytes())
if sys.argv[2]=='before':
 j.db.create_function('die',0,lambda:os._exit(71))
 j.db.execute('CREATE TEMP TRIGGER die BEFORE INSERT ON observations BEGIN SELECT die(); END')
j.observe(o['witness'],o['signed_header']);os._exit(72)
"""
        for phase,code,wanted in [('before',71,'attempted-held'),('after',72,'recorded-certified')]:
            p=subprocess.run([sys.executable,'-c',program,str(self.dir),phase],capture_output=True,timeout=120)
            self.assertEqual(p.returncode,code,p.stderr.decode());self.reopen()
            self.assertEqual(self.j.status(ident)['status'],wanted);self.assertEqual(self.j.export(ident),self.a);self.j.close()

if __name__=='__main__':unittest.main()
