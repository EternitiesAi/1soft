"""Public kernel boundary tests with a labeled fake worker; no proof qualification."""
import copy,hashlib,unittest
from src import protocol8_transfer as p
def f(n):return n.to_bytes(32,'little').hex()
class FakeWorker:
    identity={'sha256':'ab'*32}
    def root(self,notes):
        p.need(type(notes)is list and 1<=len(notes)<=16,'notes')
        for n in notes:p.field(n);p.need(n!=p.ZERO,'zero')
        p.need(len(set(notes))==len(notes),'duplicate')
        return f(int.from_bytes(hashlib.sha256(b''.join(bytes.fromhex(n)for n in notes)).digest(),'little')%p.MODULUS or 1)
    def verify(self,raw,network):return True # Syntax/state tests only.
class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.w=FakeWorker()
        self.g=p.initial_state(network=f(1),asset=f(2),mission=f(3),fee=1,notes=[{'kind':'p8-recipient-v1','commitment':f(100)}],worker=self.w)
        self.public=[f(v)for v in (8,1,2,3,0,5,6,2,8,1,10,11,12)]
        self.public[4]=self.g['anchors'][0]
        self.raw=self.wire(self.public)
        self.state=p.apply(self.g,self.g,self.raw,2,self.w)
    def wire(self,fields):return b'1SRCT008'+b''.join(bytes.fromhex(v)for v in fields)+b'\0'*p.PROFILE['proof_bytes']
    def test_receive_replay_is_immutable(self):
        self.assertEqual(len(self.g['notes']),1);self.assertEqual(len(self.state['notes']),3)
        self.assertEqual(p.replay(self.g,self.state,self.w),self.state)
        self.assertEqual(self.state['fees'],1)
    def test_malformed_state_types_normalized(self):
        cases=[('receipts',None),('receipts','x'),('receipts',{}),('nullifiers',None),('requests',[{}]),('anchors',[[]]),('notes',[{'kind':'p7-merchant','commitment':f(1)}]),('fee',True),('fees',-1)]
        for key,value in cases:
            with self.subTest(key=key,value=value):
                s=copy.deepcopy(self.state);s[key]=value
                with self.assertRaises(p.Invalid):p.replay(self.g,s,self.w)
        for value in (None,[],{},'x'):
            s=copy.deepcopy(self.state);s['receipts'][0]=value
            with self.assertRaises(p.Invalid):p.replay(self.g,s,self.w)
    def test_forged_snapshot_and_receipt_refused(self):
        for key,value in [('notes',[{'kind':'p8-recipient-v1','commitment':f(101)}]),('anchors',[f(1),f(2)]),('fees',2),('network',f(2))]:
            s=copy.deepcopy(self.state);s[key]=value
            with self.assertRaises(p.Invalid):p.apply(self.g,s,self.raw,2,self.w)
        for key,value in [('txid','ef'*32),('raw',self.raw.hex().upper()),('height',True),('statement',[]),('note_root_after',f(1)),('unexpected',1)]:
            s=copy.deepcopy(self.state);s['receipts'][0][key]=value
            with self.assertRaises(p.Invalid):p.replay(self.g,s,self.w)
    def test_note_and_request_reuse_refused(self):
        with self.assertRaises(p.Invalid):p.apply(self.g,self.state,self.raw,2,self.w)
        for index in (5,6):
            fields=self.public.copy();fields[index]=f(90);fields[10]=f(91);fields[11]=f(92)
            with self.assertRaises(p.Invalid):p.apply(self.g,self.state,self.wire(fields),2,self.w)
    def test_context_height_fee_and_capacity(self):
        for index,value in [(1,9),(2,9),(3,9),(4,9),(9,2),(10,100)]:
            fields=self.public.copy();fields[index]=f(value)
            with self.assertRaises(p.Invalid):p.apply(self.g,self.g,self.wire(fields),2,self.w)
        for height in (1,8,True,-1):
            with self.assertRaises(p.Invalid):p.apply(self.g,self.g,self.raw,height,self.w)
        s=p.apply(self.g,self.g,self.raw,3,self.w)
        fields=self.public.copy();fields[5]=f(90);fields[6]=f(91);fields[10]=f(92);fields[11]=f(93)
        with self.assertRaises(p.Invalid):p.apply(self.g,s,self.wire(fields),2,self.w)
        g=p.initial_state(network=f(1),asset=f(2),mission=f(3),fee=1,notes=[{'kind':'p8-recipient-v1','commitment':f(v)}for v in range(100,115)],worker=self.w)
        fields=self.public.copy();fields[4]=g['anchors'][0]
        with self.assertRaises(p.Invalid):p.apply(g,g,self.wire(fields),2,self.w)
    def test_p7_and_noncanonical_wire_refused(self):
        for raw in (self.raw[:-1],self.raw+b'x',b'1SOFT007'+self.raw[8:],self.raw[:8]+p.MODULUS.to_bytes(32,'little')+self.raw[40:]):
            with self.assertRaises(p.Invalid):p.parse(raw)
    def test_duplicate_or_untyped_genesis_refused(self):
        for notes in ([{'kind':'p8-recipient-v1','commitment':f(1)}]*2,[{'kind':'p7-merchant','commitment':f(1)}],[{'kind':'p8-recipient-v1','commitment':p.ZERO}]):
            with self.assertRaises(p.Invalid):p.initial_state(network=f(1),asset=f(2),mission=f(3),fee=1,notes=notes,worker=self.w)
if __name__=='__main__':unittest.main()
