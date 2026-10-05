import os
import json,os,sqlite3,tempfile,unittest
from pathlib import Path
from protocol6_application import Application
from protocol6_treasury import canonical
from test_protocol6_treasury import FIX,fixture_genesis,worker
@unittest.skipUnless(os.environ.get('P6_WORKER') and os.environ.get('P6_WORKER_SHA256'),'unassessed: explicit P6 real-verifier inputs were not supplied')
class RecoveryIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.w=worker();cls.g=canonical(fixture_genesis(cls.w.sha256))
    def test_valid_looking_finalization_identity_tamper_fails_reopen(self):
        for column in ('block_hash','request_sha256'):
            with tempfile.TemporaryDirectory() as d:
                p=Path(d)/'state.sqlite';a=Application(p,self.w,expected_genesis=self.g)
                g=json.loads(self.g);a.init_chain(g['chain_id'],self.g,g['validators'],1)
                a.finalize_block([(FIX/'a.tx').read_bytes()],1,b'x'*32,bytes.fromhex(a.validators.hash),[],b'first');a.commit();a.close()
                with sqlite3.connect(p) as c:c.execute('UPDATE blocks SET '+column+'=?',('ab'*32,))
                with self.assertRaises(ValueError):
                    with Application(p,self.w,expected_genesis=self.g):pass
if __name__=='__main__':unittest.main()
