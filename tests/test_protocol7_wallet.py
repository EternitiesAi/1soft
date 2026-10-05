"""Real P7 proofs/signatures and actual quorum receipt in finite client tests."""
import copy,json,os,sqlite3,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from protocol7_treasury import canonical,command,ZERO,Unavailable,initial_state
from protocol7_worker import Worker
@unittest.skipUnless(os.environ.get('P7_REPORT') and os.environ.get('P7_WORKER'),'unassessed: actual P7 quorum/proof receipt inputs not supplied')
class WalletTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path=Path(os.environ['P7_REPORT']);cls.report=json.loads(cls.path.read_bytes());cls.g=cls.report['genesis'];cls.rawg=canonical(cls.g)
        cls.d=cls.path.with_name(cls.path.name+'.artifacts');cls.a=(cls.d/'fixture-a.tx').read_bytes();cls.rotated=(cls.d/'fixture-rotated_a.tx').read_bytes()
        cls.w=Worker(Path(os.environ['P7_WORKER']),os.environ['P7_WORKER_SHA256'],cls.a);cls.owner=bytes.fromhex(cls.report['commands'][0]);cls.key=Ed25519PrivateKey.from_private_bytes(bytes([7])*32)
    def setUp(self):
        from protocol7_wallet import CertifiedTreasuryJournal
        self.temp=tempfile.TemporaryDirectory();self.directory=Path(self.temp.name);self.directory.chmod(0o700);self.pathdb=self.directory/'wallet.sqlite'
        self.wallet=CertifiedTreasuryJournal(self.pathdb,expected_genesis=self.rawg,worker=self.w)
    def tearDown(self):
        if hasattr(self,'wallet'):self.wallet.close();self.temp.cleanup()
    def reopen(self):
        from protocol7_wallet import CertifiedTreasuryJournal
        self.wallet.close();self.wallet=CertifiedTreasuryJournal(self.pathdb,expected_genesis=self.rawg,worker=self.w)
    def observe(self):return self.wallet.observe(self.report['state_witness'],self.report['signed_header'])
    def future(self,height):
        s=self.report['state_witness']['state'];slot=s['treasury']['grants'][1]
        return command(self.g,s,kind='revoke',grant_id=slot['id'],height=height,new_commitment=ZERO,new_agent_key=slot['agent_key'],key=self.key,worker=self.w)
    def test_payment_and_owner_exact_export_and_resource_holds(self):
        ident=self.wallet.retain(self.a);self.assertEqual(self.wallet.export(ident),self.a);self.assertEqual(self.wallet.status(ident)['attempts'],0)
        with self.assertRaises(ValueError):self.wallet.retain(self.owner)
        with self.assertRaises(ValueError):self.wallet.retain(self.a)
        with self.assertRaises(ValueError):self.wallet.retain(self.rotated)
        self.reopen();self.assertEqual(self.wallet.export(ident),self.a)
    def test_real_owner_one_attempt_is_committed_before_transport_and_unknown_is_held(self):
        ident=self.wallet.retain(self.owner);seen=[]
        def transport(raw):
            seen.append(raw);self.assertEqual(self.wallet.status(ident)['attempts'],1);raise OSError('lost reply')
        r=self.wallet.deliver_once(ident,transport);self.assertEqual(r['outcome'],'unknown');self.assertEqual(seen,[self.owner]);self.reopen()
        self.assertEqual(self.wallet.status(ident)['attempts'],1)
        with self.assertRaises(ValueError):self.wallet.claim(ident)
    def test_real_payment_claim_is_durable_before_transport(self):
        ident=self.wallet.retain(self.a)
        self.wallet.deliver_once(ident,lambda raw:self.assertEqual(self.wallet.status(ident)['attempts'],1));self.reopen()
        with self.assertRaises(ValueError):self.wallet.claim(ident)
        self.assertEqual(self.wallet.export(ident),self.a)
    def test_actual_owner_certificate_completes_only_exact_command(self):
        ident=self.wallet.retain(self.owner);self.observe();s=self.wallet.status(ident)
        self.assertEqual(s['status'],'recorded-certified');self.assertEqual(s['kind'],'owner');self.assertEqual(s['attempts'],0)
        r=self.wallet.recorded_receipt(ident);self.assertEqual(r['raw'],self.owner.hex());self.assertEqual(r['receipt']['kind'],'owner')
        self.reopen();self.assertEqual(self.wallet.recorded_receipt(ident),r);self.assertTrue(self.observe()['idempotent'])
        with self.assertRaises(ValueError):self.wallet.claim(ident)
    def test_actual_rotation_quarantines_unclaimed_old_payment(self):
        ident=self.wallet.retain(self.a);self.observe();s=self.wallet.status(ident)
        self.assertEqual(s['status'],'observed-held');self.assertEqual(s['hold_reason'],'rotated-grant');self.assertEqual(s['attempts'],0)
        with self.assertRaises(ValueError):self.wallet.claim(ident)
        with self.assertRaises(ValueError):self.wallet.recorded_receipt(ident)
        self.reopen();self.assertEqual(self.wallet.export(ident),self.a);self.assertEqual(self.wallet.status(ident)['attempts'],0)
    def test_committed_header_frontier_and_future_owner_window_are_exact(self):
        self.observe();h=self.report['state_witness']['height'];header=int(self.report['signed_header']['header']['height']);self.assertEqual(header,h+1)
        with self.assertRaises(ValueError):self.wallet.retain(self.future(header))
        with self.assertRaises(ValueError):self.wallet.retain(self.future(header+9))
        raw=self.future(header+1);ident=self.wallet.retain(raw);self.assertEqual(self.wallet.export(ident),raw)
        self.assertEqual(self.wallet.status(ident)['hold_reason'],'unknown');self.wallet.claim(ident);self.assertEqual(self.wallet.status(ident)['attempts'],1)
    def test_owner_sequence_lane_serializes_competing_prepared_commands(self):
        ident=self.wallet.retain(self.owner);packet=json.loads(self.owner[8:]);b=packet['body'];slot=initial_state(self.g,self.w)['treasury']['grants'][0]
        other=command(self.g,initial_state(self.g,self.w),kind='revoke',grant_id=slot['id'],height=b['height'],new_commitment=ZERO,new_agent_key=slot['agent_key'],key=self.key,worker=self.w)
        from protocol7_wallet import CertifiedTreasuryJournal
        with CertifiedTreasuryJournal(self.pathdb,expected_genesis=self.rawg,worker=self.w) as second:
            with self.assertRaises(ValueError):second.retain(other)
        self.assertEqual(self.wallet.status(ident)['attempts'],0)
    def test_wrong_header_preserves_exact_retained_and_observation_state(self):
        ident=self.wallet.retain(self.owner);bad=copy.deepcopy(self.report['signed_header']);bad['header']['app_hash']='ab'*32
        with self.assertRaises(ValueError):self.wallet.observe(self.report['state_witness'],bad)
        self.assertEqual(self.wallet.status(ident)['status'],'retained');self.assertEqual(self.wallet.status(ident)['attempts'],0)
    def test_unavailability_does_not_claim_or_mutate(self):
        ident=self.wallet.retain(self.owner)
        with patch.object(self.w,'context_root',side_effect=Unavailable('actual binary not available')),self.assertRaises(Unavailable):self.wallet.claim(ident)
        self.assertEqual(self.wallet.status(ident)['attempts'],0)
    def test_retained_projection_attempt_and_identity_tamper_refuse_reopen(self):
        ident=self.wallet.retain(self.owner);self.wallet.close();db=sqlite3.connect(self.pathdb);db.execute("UPDATE identity SET format='1soft/protocol6-certified-treasury-journal/v1'");db.commit();db.close()
        from protocol7_wallet import CertifiedTreasuryJournal
        with self.assertRaises(ValueError):CertifiedTreasuryJournal(self.pathdb,expected_genesis=self.rawg,worker=self.w)
if __name__=='__main__':unittest.main()
