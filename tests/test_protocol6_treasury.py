import os
"""Actual-proof tests: disabling current-state or conservation caller guards must fail."""
import copy, hashlib, importlib, json, os, unittest
from pathlib import Path
try:
    p6=importlib.import_module('protocol6_treasury')
except ModuleNotFoundError:
    p6=None

FIX=Path(os.environ.get('P6_FIXTURES','/home/xnuonux/1soft-treasury-payment-evidence/treasury-qualified-04.fixtures'))

def fixture_genesis(worker_sha):
    treasury=json.loads((FIX/'genesis.json').read_bytes())
    return {'protocol_version':6,'chain_id':'one-p6-test','profile_sha256':'4e12c9a2eafd2d4f3e82106ba1128e1fc6301b24b871d30714eb0ca3b93115bd',
            'worker_sha256':worker_sha,'kat_sha256':hashlib.sha256((FIX/'a.tx').read_bytes()).hexdigest(),
            'validators':[{'public_key':f'{i:064x}','power':10} for i in range(1,5)],'treasury':treasury}

def worker():
    from protocol6_worker import Worker
    binary=Path(os.environ['P6_WORKER'])
    return Worker(binary,os.environ['P6_WORKER_SHA256'],(FIX/'a.tx').read_bytes())

@unittest.skipUnless(os.environ.get('P6_WORKER') and os.environ.get('P6_WORKER_SHA256'),'unassessed: explicit P6 real-verifier inputs were not supplied')
class TreasuryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if p6 is not None:cls.w=worker()
    def setUp(self):
        self.assertIsNotNone(p6,'P6 atomic validator state machine is missing')
        self.g=fixture_genesis(self.w.sha256)
        self.g=p6.genesis_document(p6.canonical(self.g));self.s=p6.initial_state(self.g,self.w)
    def tx(self,name):return (FIX/(name+'.tx')).read_bytes()
    def execute(self,s,txs,h):return p6.execute_block(self.g,s,txs,h,self.w)
    def test_ordered_current_authority_and_exact_aggregate_cap(self):
        a=self.tx('a');b=self.tx('b');after=self.tx('after_a_b')
        s,r=self.execute(self.s,[a,b],1)
        self.assertEqual([x['code'] for x in r],[0,2]);self.assertEqual(len(s['receipts']),1)
        self.assertEqual(self.s['treasury']['fees'],0)
        s,r=self.execute(s,[after],2)
        self.assertEqual(r[0]['code'],0);self.assertEqual(s['treasury']['fees'],4)
        self.assertEqual(len(s['treasury']['notes']),6);self.assertEqual(len(s['treasury']['nullifiers']),2)
        self.assertEqual(len(s['treasury']['authority_nullifiers']),4)
        self.assertEqual(len(s['receipts']),2)
        self.assertEqual(s['receipts'][0]['raw'],a.hex())
    def test_reverse_order_and_refresh(self):
        s,r=self.execute(self.s,[self.tx('b'),self.tx('a')],1)
        self.assertEqual([x['code'] for x in r],[0,2])
        s,r=self.execute(s,[self.tx('after_b_a')],2)
        self.assertEqual(r[0]['code'],0);self.assertEqual(s['treasury']['fees'],4)
    def test_duplicate_request_even_with_distinct_valid_proof(self):
        s,_=self.execute(self.s,[self.tx('a')],1)
        self.assertTrue(self.w.verify(self.tx('duplicate_request')))
        rejected,r=self.execute(s,[self.tx('duplicate_request')],2)
        self.assertEqual(r[0]['code'],5);self.assertEqual(rejected['treasury'],s['treasury'])
    def test_corrupt_proof_and_wire_fail_without_transition(self):
        a=self.tx('a');bad=bytearray(a);bad[-1]^=1
        for raw,code in [(bytes(bad),6),(a+b'x',1),(a[:-1],1)]:
            s,r=self.execute(self.s,[raw],1)
            self.assertEqual(r[0]['code'],code);self.assertEqual(s['treasury'],self.s['treasury'])
    def test_exclusive_expiry_and_wrong_domain(self):
        s=self.s
        for h in range(1,20):s,_=self.execute(s,[],h)
        s,r=self.execute(s,[self.tx('a')],20)
        self.assertEqual(r[0]['code'],3);self.assertEqual(s['treasury']['fees'],0)
        raw=bytearray(self.tx('a'));raw[40:72]=(999).to_bytes(32,'little')
        _,r=self.execute(self.s,[bytes(raw)],1);self.assertEqual(r[0]['code'],2)
    def test_genesis_closed_pins_and_old_protocol_refused(self):
        for key,value in [('protocol_version',5),('protocol_version',True),('profile_sha256','00'*32),('extra',1)]:
            g=copy.deepcopy(self.g);g[key]=value
            with self.assertRaises(ValueError):p6.genesis_document(p6.canonical(g))
    def test_replay_reconstructs_all_fields_and_detects_altered_receipt(self):
        s,_=self.execute(self.s,[self.tx('a')],1)
        self.assertEqual(p6.replay(self.g,s,1,self.w),s)
        altered=copy.deepcopy(s);altered['receipts'][0]['fee']=999
        with self.assertRaises(ValueError):p6.replay(self.g,altered,1,self.w)
    def test_height_history_and_block_bounds(self):
        for h,txs in [(0,[]),(2,[]),(True,[]),(1,[self.tx('a')]*3)]:
            with self.assertRaises(ValueError):self.execute(self.s,txs,h)

if __name__=='__main__':unittest.main()
