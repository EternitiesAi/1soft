import copy,json,os,unittest
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from protocol7_treasury import initial_state,command,execute_block,ZERO,Unavailable,canonical
from protocol7_worker import Worker
@unittest.skipUnless(os.environ.get('P7_FIXTURES') and os.environ.get('P7_WORKER'),'unassessed: explicit real P7 worker/proof inputs not supplied')
class AdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d=Path(os.environ['P7_FIXTURES']);cls.g=json.loads((cls.d/'p7-genesis.json').read_bytes());cls.w=Worker(Path(os.environ['P7_WORKER']),os.environ['P7_WORKER_SHA256'],(cls.d/'a.tx').read_bytes());cls.key=Ed25519PrivateKey.from_private_bytes(bytes([7])*32)
    def setUp(self):self.s=initial_state(self.g,self.w)
    def cmd(self,height):
        t=self.s['treasury'];slot=t['grants'][0];return command(self.g,self.s,kind='revoke',grant_id=slot['id'],height=height,new_commitment=ZERO,new_agent_key=slot['agent_key'],key=self.key,worker=self.w)
    def test_bounded_future_owner_admission_is_mutation_free(self):
        from protocol7_admission import preflight
        before=copy.deepcopy(self.s)
        for h in (1,2,8):self.assertEqual(preflight(self.g,self.s,self.cmd(h),1,self.w)['code'],0)
        self.assertEqual(preflight(self.g,self.s,self.cmd(9),1,self.w)['code'],3);self.assertEqual(self.s,before)
    def test_future_admission_never_weakens_exact_consensus_height(self):
        from protocol7_admission import preflight
        raw=self.cmd(2);self.assertEqual(preflight(self.g,self.s,raw,1,self.w)['code'],0)
        state,results=execute_block(self.g,self.s,[raw],1,self.w);self.assertEqual(results[0]['code'],2);self.assertEqual(state['treasury'],self.s['treasury'])
        state,_=execute_block(self.g,self.s,[],1,self.w);state,results=execute_block(self.g,state,[raw],2,self.w);self.assertEqual(results[0]['code'],0)
    def test_changed_context_stales_future_signed_command(self):
        from protocol7_admission import preflight
        later=self.cmd(2);state,_=execute_block(self.g,self.s,[self.cmd(1)],1,self.w)
        self.assertEqual(preflight(self.g,state,later,2,self.w)['code'],2)
    def test_unavailable_admission_is_not_a_rejected_transaction(self):
        from protocol7_admission import preflight
        raw=self.cmd(2)
        with patch.object(self.w,'context_root',side_effect=Unavailable('not available')),self.assertRaises(Unavailable):preflight(self.g,self.s,raw,1,self.w)
    def test_real_signature_and_malformed_owner_body_refuse_without_mutation(self):
        from protocol7_admission import preflight
        raw=self.cmd(2);p=json.loads(raw[8:]);p['signature']='00'*64
        self.assertEqual(preflight(self.g,self.s,raw[:8]+canonical(p),1,self.w)['code'],8)
        self.assertEqual(preflight(self.g,self.s,raw+b'x',1,self.w)['code'],1)
if __name__=='__main__':unittest.main()
