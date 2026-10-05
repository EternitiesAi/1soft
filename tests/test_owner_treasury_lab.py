"""Real Ed25519 commands and actual successor proofs in the native lab caller."""
import copy,hashlib,json,os,sys,unittest
from unittest.mock import patch
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools/owner-treasury-lab/scripts'))
try:import owner_ledger as lab
except ModuleNotFoundError:lab=None
@unittest.skipUnless(os.environ.get('OWNER_FIXTURES') and os.environ.get('OWNER_WORKER'),'unassessed: actual owner proof fixtures and pinned bridge not supplied')
class OwnerLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if lab is None:raise AssertionError('Authenticated owner treasury native caller is missing')
        cls.directory=Path(os.environ['OWNER_FIXTURES']);cls.t=json.loads((cls.directory/'genesis.json').read_bytes());cls.inactive=json.loads((cls.directory/'enroll-genesis.json').read_bytes())
        cls.txs={p.stem:p.read_bytes() for p in cls.directory.glob('*.tx')}
        cls.w=lab.Native(Path(os.environ['OWNER_WORKER']),os.environ['OWNER_WORKER_SHA256'],cls.txs['a'])
        cls.key=Ed25519PrivateKey.from_private_bytes(bytes([7])*32)
        assert cls.key.public_key().public_bytes_raw().hex()==cls.t['owner_key']
        cls.g=lab.genesis(cls.t,chain_id='owner-lab-local',worker=cls.w);cls.g0=lab.genesis(cls.inactive,chain_id='owner-lab-enroll',worker=cls.w)
    def setUp(self):self.s=lab.initial_state(self.g,self.w)
    def command(self,kind,s=None,g=None,slot=0,height=1,key=None):
        s=self.s if s is None else s;g=self.g if g is None else g
        target=s['treasury']['grants'][slot]
        if kind=='rotate':p=lab.parse(self.txs['rotated_a']);new_commit,new_key=p[8],p[29]
        elif kind=='enroll':p=lab.parse(self.txs['b']);new_commit,new_key=p[8],p[29]
        else:new_commit=lab.ZERO;new_key=target['agent_key']
        return lab.command(g,s,kind=kind,grant_id=target['id'],height=height,new_commitment=new_commit,new_agent_key=new_key,key=self.key if key is None else key,worker=self.w)
    def block(self,s,txs,height,g=None):return lab.execute_block(self.g if g is None else g,s,txs,height,self.w)
    def economic(self,s):return {k:v for k,v in s.items() if k!='blocks'}
    def resign(self,raw,change):
        packet=json.loads(raw[8:]);change(packet['body'])
        packet['signature']=self.key.sign(lab.COMMAND_DOMAIN+lab.canonical(packet['body'])).hex()
        return lab.COMMAND_MAGIC+lab.canonical(packet)
    def test_real_payment_and_exact_replay(self):
        s,r=self.block(self.s,[self.txs['a']],1);self.assertEqual(r[0]['code'],0)
        self.assertEqual(s['treasury']['owner_sequence'],0);self.assertEqual(s['treasury']['grants'][0]['generation'],1)
        self.assertEqual(s['treasury']['fees'],2);self.assertEqual(s['receipts'][0]['raw'],self.txs['a'].hex())
        self.assertEqual(lab.replay(self.g,s,1,self.w),s)
    def test_revoke_first_rejects_old_payment_without_value_change(self):
        command=self.command('revoke');s,r=self.block(self.s,[command,self.txs['a']],1)
        self.assertEqual([x['code'] for x in r],[0,2]);self.assertEqual(s['treasury']['grants'][0]['commitment'],lab.ZERO)
        self.assertEqual(s['treasury']['grants'][0]['generation'],1);self.assertEqual(s['treasury']['owner_sequence'],1)
        for k in ('parent','notes','fees','nullifiers','authority_nullifiers'):self.assertEqual(s['treasury'][k],self.s['treasury'][k])
        self.assertEqual(lab.replay(self.g,s,1,self.w),s)
    def test_payment_first_stales_prepared_command_and_fresh_command_can_revoke(self):
        command=self.command('revoke');s,r=self.block(self.s,[self.txs['a'],command],1)
        self.assertEqual([x['code'] for x in r],[0,2]);self.assertEqual(s['treasury']['owner_sequence'],0)
        fresh=self.command('revoke',s=s,height=2);s,r=self.block(s,[fresh],2);self.assertEqual(r[0]['code'],0)
        s,r=self.block(s,[self.txs['after_a_revoke_b']],3);self.assertEqual(r[0]['code'],0)
        self.assertEqual(s['treasury']['fees'],4);self.assertEqual(lab.replay(self.g,s,3,self.w),s)
    def test_unrelated_grant_note_unchanged_but_old_context_proof_stale(self):
        s,r=self.block(self.s,[self.command('revoke')],1)
        self.assertEqual(s['treasury']['grants'][1],self.s['treasury']['grants'][1]);self.assertEqual(s['treasury']['notes'],self.s['treasury']['notes'])
        s,r=self.block(s,[self.txs['b']],2);self.assertEqual(r[0]['code'],2)
        s,r=self.block(s,[self.txs['revoked_a_b']],3);self.assertEqual(r[0]['code'],0)
    def test_rotate_first_accepts_only_new_generation_key_and_preseeded_note(self):
        s,r=self.block(self.s,[self.command('rotate'),self.txs['a']],1);self.assertEqual([x['code'] for x in r],[0,2])
        self.assertEqual(s['treasury']['grants'][0]['generation'],2);self.assertEqual(s['treasury']['notes'],self.s['treasury']['notes'])
        s,r=self.block(s,[self.txs['rotated_a']],2);self.assertEqual(r[0]['code'],0)
        self.assertEqual(s['receipts'][-1]['statement'][26],lab.numfield(2));self.assertEqual(lab.replay(self.g,s,2,self.w),s)
    def test_reactivate_revoked_slot_keeps_old_notes_quarantined(self):
        s,_=self.block(self.s,[self.command('revoke')],1);s,r=self.block(s,[self.command('rotate',s=s,height=2)],2)
        self.assertEqual(r[0]['code'],0);self.assertEqual(s['treasury']['grants'][0]['generation'],2);self.assertEqual(s['treasury']['owner_sequence'],2)
        self.assertEqual(s['treasury']['notes'],self.s['treasury']['notes'])
        s,r=self.block(s,[self.txs['a']],3);self.assertEqual(r[0]['code'],2);self.assertEqual(lab.replay(self.g,s,3,self.w),s)
    def test_enrollment_once_from_generation_zero(self):
        base=lab.initial_state(self.g0,self.w);command=self.command('enroll',s=base,g=self.g0,slot=1)
        s,r=self.block(base,[command],1,g=self.g0);self.assertEqual(r[0]['code'],0)
        self.assertEqual(s['treasury']['grants'][1]['generation'],1);self.assertEqual(s['treasury']['grants'][0],base['treasury']['grants'][0])
        s,r=self.block(s,[self.txs['pre_enroll_a']],2,g=self.g0);self.assertEqual(r[0]['code'],2)
        s,r=self.block(s,[self.txs['after_enroll_b']],3,g=self.g0);self.assertEqual(r[0]['code'],0)
        with self.assertRaises(ValueError):self.command('enroll',s=s,g=self.g0,slot=1,height=4)
    def test_competing_owner_commands_only_one_advances(self):
        commands=[self.command('revoke'),self.command('rotate')]
        for order in (commands,commands[::-1]):
            s,r=self.block(self.s,order,1);self.assertEqual([x['code'] for x in r],[0,2]);self.assertEqual(s['treasury']['owner_sequence'],1)
            self.assertEqual(lab.replay(self.g,s,1,self.w),s)
    def test_signed_wrong_domain_sequence_generation_commitment_height_refused(self):
        original=self.command('revoke')
        for field,value in [('profile_sha256','ab'*32),('genesis_sha256','ab'*32),('chain_id','other-chain'),('owner_epoch',2),('next_sequence',2),('context_root',lab.numfield(99)),('generation',2),('old_commitment',lab.numfield(99)),('height',2),('new_agent_key',lab.ZERO)]:
            raw=self.resign(original,lambda b:b.__setitem__(field,value));s,r=self.block(self.s,[raw],1)
            self.assertNotEqual(r[0]['code'],0,field);self.assertEqual(self.economic(s),self.economic(self.s),field)
    def test_altered_signature_wrong_owner_and_duplicate_sequence_refused(self):
        raw=self.command('revoke');packet=json.loads(raw[8:]);packet['signature']='00'*64
        s,r=self.block(self.s,[lab.COMMAND_MAGIC+lab.canonical(packet)],1);self.assertNotEqual(r[0]['code'],0);self.assertEqual(self.economic(s),self.economic(self.s))
        wrong=Ed25519PrivateKey.from_private_bytes(bytes([8])*32)
        with self.assertRaises(ValueError):self.command('revoke',key=wrong)
        packet=json.loads(raw[8:]);packet['signature']=wrong.sign(lab.COMMAND_DOMAIN+lab.canonical(packet['body'])).hex()
        s,r=self.block(self.s,[lab.COMMAND_MAGIC+lab.canonical(packet)],1);self.assertNotEqual(r[0]['code'],0)
        s,_=self.block(self.s,[raw],1);again=self.resign(raw,lambda b:b.__setitem__('height',2));after,r=self.block(s,[again],2)
        self.assertNotEqual(r[0]['code'],0);self.assertEqual(self.economic(after),self.economic(s))
    def test_closed_canonical_commands_and_numeric_types(self):
        raw=self.command('revoke');packet=json.loads(raw[8:])
        variants=[lab.COMMAND_MAGIC+json.dumps(packet).encode(),lab.COMMAND_MAGIC+raw[8:-1]+b',"signature":"00"}',raw+b'\n']
        extra=copy.deepcopy(packet);extra['body']['extra']=0;variants.append(lab.COMMAND_MAGIC+lab.canonical(extra))
        for field,value in [('next_sequence',True),('generation',-1),('owner_epoch',2**64),('owner_key',self.t['owner_key'].upper()),('new_generation',2**64)]:
            variants.append(self.resign(raw,lambda b:b.__setitem__(field,value)))
        for bad in variants:
            s,r=self.block(self.s,[bad],1);self.assertNotEqual(r[0]['code'],0);self.assertEqual(self.economic(s),self.economic(self.s))
    def test_command_cannot_change_unmentioned_grant_parent_or_value(self):
        before=copy.deepcopy(self.s);raw=self.command('rotate');s,r=self.block(self.s,[raw],1)
        self.assertEqual(r[0]['code'],0);self.assertEqual(self.s,before)
        self.assertEqual(s['treasury']['grants'][1],self.s['treasury']['grants'][1])
        for k in ('parent','notes','fees','nullifiers','authority_nullifiers'):self.assertEqual(s['treasury'][k],self.s['treasury'][k])
    def test_u64_owner_and_generation_overflow_refused(self):
        for field in ('owner_sequence','generation'):
            s=copy.deepcopy(self.s)
            if field=='owner_sequence':s['treasury'][field]=2**64-1
            else:s['treasury']['grants'][0][field]=2**64-1
            with self.assertRaises(ValueError):self.command('rotate',s=s)
    def test_history_receipt_and_nullifier_tamper_refused(self):
        s,_=self.block(self.s,[self.txs['a']],1)
        for field in ('receipt','result','nullifier','sequence'):
            bad=copy.deepcopy(s)
            if field=='receipt':bad['receipts'][0]['raw_sha256']='ab'*32
            elif field=='result':bad['blocks'][0]['results'][0]['code']=2
            elif field=='nullifier':bad['treasury']['nullifiers']=[lab.numfield(99)]
            else:bad['treasury']['owner_sequence']=1
            with self.assertRaises(ValueError):lab.replay(self.g,bad,1,self.w)
    def test_real_worker_identity_and_corrupt_proof_fail_closed(self):
        self.assertTrue(self.w.verify(self.txs['a']));bad=bytearray(self.txs['a']);bad[-1]^=1;self.assertFalse(self.w.verify(bytes(bad)))
        with self.assertRaises(ValueError):lab.Native(Path(os.environ['OWNER_WORKER']),'ab'*32,self.txs['a'])
    def test_revoke_signed_successor_matches_retained_quarantine_metadata(self):
        raw=self.command('revoke');body=json.loads(raw[8:])['body'];s,r=self.block(self.s,[raw],1)
        self.assertEqual(r[0]['code'],0)
        self.assertEqual(body['new_agent_key'],s['treasury']['grants'][0]['agent_key'])
        self.assertEqual(body['new_agent_key'],self.s['treasury']['grants'][0]['agent_key'])
        self.assertEqual(body['new_commitment'],lab.ZERO)
        self.assertEqual(body['new_generation'],s['treasury']['grants'][0]['generation'])
    def test_bad_measured_binary_is_unavailable_not_stale_command(self):
        raw=self.command('revoke')
        with patch.object(self.w,'_open',side_effect=ValueError('owner native binary identity differs')):
            with self.assertRaises(lab.Unavailable):self.w.call('context-root',b'')
    def test_native_unavailability_never_records_a_rejection_or_mutates_state(self):
        raw=self.command('revoke');before=copy.deepcopy(self.s);call=self.w.call
        def unavailable(op,data):
            if op=='context-root':raise lab.Unavailable('actual verifier unavailable')
            return call(op,data)
        with patch.object(self.w,'call',side_effect=unavailable),self.assertRaises(lab.Unavailable):self.block(self.s,[raw],1)
        self.assertEqual(self.s,before)
if __name__=='__main__':unittest.main()
