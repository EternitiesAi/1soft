import os
import copy,importlib,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from certificate_fixture import make_commit,make_header
from commit_verifier import sha
from protocol6_treasury import canonical,initial_state,application_hash
from test_protocol6_treasury import worker,fixture_genesis
try:
    import protocol6_certificate as c6
except ModuleNotFoundError:c6=None
@unittest.skipUnless(os.environ.get('P6_WORKER') and os.environ.get('P6_WORKER_SHA256'),'unassessed: explicit P6 real-verifier inputs were not supplied')
class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.w=worker();cls.g=fixture_genesis(cls.w.sha256)
        cls.keys=[Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(31,35)]
        cls.g['validators']=sorted([{'public_key':k.public_key().public_bytes_raw().hex(),'power':10} for k in cls.keys],key=lambda r:r['public_key'])
        cls.raw=canonical(cls.g);s=initial_state(cls.g,cls.w)
        cls.witness={'genesis':cls.g,'height':0,'state':s,'app_hash':application_hash(cls.g,0,s)}
    def fixture(self):
        self.assertIsNotNone(c6,'P6 pinned static-validator state certificate is missing')
        t=c6.trust(self.raw);byaddr={sha(k.public_key().public_bytes_raw())[:20]:k for k in self.keys}
        return t,make_commit(make_header(t,1,self.witness['app_hash']),t,[byaddr[v.address] for v in t.validators])
    def test_signed_next_height_binds_exact_genesis_and_state(self):
        t,s=self.fixture();v=c6.verify_state(self.witness,s,self.raw)
        self.assertEqual(v['state_height'],0);self.assertEqual(v['header_height'],1)
    def test_wrong_height_genesis_state_and_signature_rejected(self):
        t,s=self.fixture()
        for what in ['height','genesis','state','signature']:
            w=copy.deepcopy(self.witness);h=copy.deepcopy(s)
            if what=='height':w['height']=1
            elif what=='genesis':w['genesis']['chain_id']='different'
            elif what=='state':w['state']['treasury']['fees']=999
            else:h['commit']['signatures'][0]['signature']='AA=='
            with self.assertRaises(ValueError):c6.verify_state(w,h,self.raw)
    def test_incomplete_quorum_cannot_authenticate(self):
        t,s=self.fixture();s['commit']['signatures']=s['commit']['signatures'][:2]
        with self.assertRaises(ValueError):c6.verify_state(self.witness,s,self.raw)
if __name__=='__main__':unittest.main()
