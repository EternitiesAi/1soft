"""Mandatory real-Poseidon P7 network binding and bootstrap-cycle boundaries."""
import copy,hashlib,json,os,unittest
from pathlib import Path
from protocol7_treasury import canonical,genesis_document,genesis_shape,bootstrap_digest,PROFILE_SHA256
from protocol7_worker import Worker,Unavailable
@unittest.skipUnless(os.environ.get('P7_FIXTURES') and os.environ.get('P7_WORKER'),'unassessed: explicit real owner verifier/domain proof inputs not supplied')
class BootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d=Path(os.environ['P7_FIXTURES']);cls.g=json.loads((cls.d/'p7-genesis.json').read_bytes());cls.sha=os.environ['P7_WORKER_SHA256'];cls.binary=Path(os.environ['P7_WORKER'])
        cls.w=Worker(cls.binary,cls.sha,(cls.d/'a.tx').read_bytes())
    def test_fresh_exact_domain_and_profile_is_mandatory(self):
        self.assertEqual(genesis_document(canonical(self.g),self.w),self.g)
        for path,value in [('chain_id','other-network'),('protocol_version',6),('profile_sha256','ab'*32),('worker_sha256','ab'*32),('kat_sha256','ab'*32)]:
            g=copy.deepcopy(self.g);g[path]=value
            with self.assertRaises(ValueError,msg=path):genesis_document(canonical(g),self.w)
    def test_public_bootstrap_metadata_changes_exact_native_domain(self):
        original=self.w.network_domain(bytes.fromhex(bootstrap_digest(self.g)))
        for path in ('validator','owner_key','fee','grant_id','owner_epoch','asset','epoch','mission','parent_id'):
            g=copy.deepcopy(self.g)
            if path=='validator':g['validators'][0]['power']=11
            elif path=='grant_id':g['treasury']['grants'][0]['id']='ef'+'00'*31
            elif path=='owner_key':g['treasury'][path]='ef'*32
            elif type(g['treasury'][path]) is int:g['treasury'][path]+=1
            else:g['treasury'][path]='ef'+'00'*31
            self.assertNotEqual(self.w.network_domain(bytes.fromhex(bootstrap_digest(g))),original,path)
            with self.assertRaises(ValueError,msg=path):genesis_document(canonical(g),self.w)
    def test_dynamic_commitments_notes_and_kat_do_not_create_bootstrap_cycle(self):
        g=copy.deepcopy(self.g);g['treasury']['parent']='ef'+'00'*31;g['treasury']['notes'][0]='ee'+'00'*31;g['treasury']['grants'][0]['commitment']='ed'+'00'*31;g['kat_sha256']='ef'*32
        self.assertEqual(bootstrap_digest(g),bootstrap_digest(self.g))
        with self.assertRaises(ValueError):genesis_document(canonical(g),self.w)
    def test_valid_lab_kat_cannot_certify_different_network_domain(self):
        old=(self.d.parent/'owner-fixtures-01/a.tx').read_bytes();oldw=Worker(self.binary,self.sha,old)
        g=copy.deepcopy(self.g);g['kat_sha256']=hashlib.sha256(old).hexdigest()
        with self.assertRaises(ValueError):genesis_document(canonical(g),oldw)
    def test_closed_canonical_genesis_and_sorted_roster(self):
        for mutation in ('extra','bool','unsorted','sequence','zero'):
            g=copy.deepcopy(self.g)
            if mutation=='extra':g['extra']=0
            elif mutation=='bool':g['protocol_version']=True
            elif mutation=='unsorted':g['validators'].reverse()
            elif mutation=='sequence':g['treasury']['owner_sequence']=1
            else:g['treasury']['genesis']='00'*32
            with self.assertRaises(ValueError):genesis_document(canonical(g),self.w)
        with self.assertRaises(ValueError):genesis_shape(canonical(self.g)+b'\n')
    def test_verifier_cannot_prove_or_emit_fixtures(self):
        for op in ('prove','fixtures','fixtures-domain','ledger','sign'):
            with self.assertRaises(ValueError):self.w.call(op,b'')
if __name__=='__main__':unittest.main()
