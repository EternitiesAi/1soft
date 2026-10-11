"""Real envelope/storage/quorum mechanics, fake proof worker; no native claim."""
import copy,json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from certificate_fixture import make_header,make_commit
from commit_verifier import sha
from test_protocol9_ledger import fixture,finalize
import protocol8_transfer as n
import protocol9_consensus as p
from protocol9_certificate import export_history,trust
from protocol9_application import Application
from protocol9_notes import NoteController
from protocol9_wallet import RecipientWallet as V1
try: import protocol9_history_codec as codec
except ModuleNotFoundError:codec=None
try: import protocol9_history_wallet as v2
except ModuleNotFoundError:v2=None

def observation(height):
    blocks=[{'height':i,'transactions':[]} for i in range(1,height+1)]
    return {'witness':{'format':'1soft/protocol9-complete-history/v1','genesis':{'unit':'shape-only'},
        'height':height,'blocks':blocks,'app_hash':'11'*32,'checkpoint':{'height':height}},
        'signed_header':{},'certificate':{}}

class CodecTests(unittest.TestCase):
    def setUp(self):self.assertIsNotNone(codec,'history storage codec missing')
    def test_full_history_stored_once_and_exact_prefixes_reconstructed(self):
        obs=[observation(2),observation(5)];original=copy.deepcopy(obs)
        history,refs=codec.pack(obs,{'unit':'shape-only'})
        self.assertEqual(len(history['blocks']),5)
        self.assertEqual(n.canonical({'history':history,'observations':refs}).count(b'"blocks":'),1)
        self.assertEqual(codec.unpack(history,refs),obs);self.assertEqual(obs,original)
    def test_divergent_prefix_and_foreign_genesis_refused(self):
        for foreign in (False,True):
            obs=[observation(1),observation(2)]
            if foreign:obs[0]['witness']['genesis']={'unit':'foreign'}
            else:obs[0]['witness']['blocks'][0]['transactions']=['aa']
            with self.assertRaises(ValueError):codec.pack(obs,{'unit':'shape-only'})
    def test_closed_shapes_and_out_of_range_prefix_refused(self):
        history,refs=codec.pack([observation(2)],{'unit':'shape-only'})
        for kind in ('history-extra','ref-extra','height','blocks','sequence'):
            h=copy.deepcopy(history);o=copy.deepcopy(refs)
            if kind=='history-extra':h['trusted_index']={}
            elif kind=='ref-extra':o[0]['trusted_index']={}
            elif kind=='height':o[0]['height']=3
            elif kind=='blocks':h['blocks'].pop()
            else:h['blocks'][0]['height']=2
            with self.subTest(kind=kind),self.assertRaises(ValueError):codec.unpack(h,o)
    def test_unused_latest_replaced_without_touching_earlier_slots(self):
        obs=[observation(1),observation(2)];before=copy.deepcopy(obs)
        got=codec.retain(obs,[{'observation':0,'result':None}],observation(3))
        self.assertEqual([o['witness']['height'] for o in got],[1,3]);self.assertEqual(obs,before)
    def test_preparation_and_exact_result_each_pin_the_latest(self):
        obs=[observation(1),observation(2)]
        for row in ({'observation':1,'result':None},{'observation':0,'result':{'observation':1}}):
            got=codec.retain(obs,[row],observation(3))
            self.assertEqual([o['witness']['height'] for o in got],[1,2,3]);self.assertEqual(row['observation'],1 if row['result'] is None else 0)
    def test_all_required_slots_refuse_a_ninth_without_mutation(self):
        obs=[observation(i) for i in range(1,9)];old=copy.deepcopy(obs)
        with self.assertRaises(ValueError):codec.retain(obs,[{'observation':7,'result':None}],observation(9))
        self.assertEqual(obs,old)
    def test_malformed_dependency_cannot_drop_required_evidence(self):
        obs=[observation(1)]
        for row in ({'observation':True,'result':None},{'observation':1,'result':None},{'observation':0,'result':{'observation':-1}}):
            with self.assertRaises(ValueError):codec.retain(obs,[row],observation(2))

class WalletTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(v2,'versioned history wallet missing')
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.g,self.worker=fixture();self.keys=[Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(31,35)]
        self.g['validators']=sorted([{'public_key':k.public_key().public_bytes_raw().hex(),'power':10} for k in self.keys],key=lambda x:x['public_key'])
        self.g['network']=self.worker.network_domain(bytes.fromhex(p.bootstrap_digest(self.g)));self.worker.kat_statement[1]=self.g['network']
        self.app=Application(self.root/'ledger',self.worker,expected_genesis=n.canonical(self.g))
        self.app.init_chain(self.g['chain_id'],n.canonical(self.g),self.g['validators'])
        self.controller=object.__new__(NoteController);self.controller.g=self.g;self.controller.worker=self.worker;self.controller.sha256='12'*32
        self.keypatch=patch.object(NoteController,'key',return_value='15'*32);self.keypatch.start()
        self.args=dict(key=b'K'*32,wallet_id='16'*32,recipient_secret='17'*32,controller=self.controller)
        self.path=self.root/'wallet';self.wallet=v2.RecipientWallet(self.path,create=True,**self.args)
    def tearDown(self):self.app.close();self.keypatch.stop();self.tmp.cleanup()
    def packet(self):
        finalize(self.app,[],self.app.height+1);self.app.commit();w=export_history(self.root/'ledger');t=trust(n.canonical(self.g),self.worker)
        byaddr={sha(k.public_key().public_bytes_raw())[:20]:k for k in self.keys}
        h=make_header(t,w['height']+1,w['app_hash'],previous={'hash':'11'*32,'parts':{'total':1,'hash':'22'*32}})
        return w,make_commit(h,t,[byaddr[v.address] for v in t.validators])
    def physical(self):
        raw=json.loads(self.path.read_bytes());h=raw['header']
        return json.loads(AESGCM(b'K'*32).decrypt(bytes.fromhex(h['nonce']),bytes.fromhex(raw['ciphertext']),v2.AAD+n.canonical(h)))
    def corrupt(self,edit):
        raw=json.loads(self.path.read_bytes());p=self.physical();edit(p);h=raw['header']
        raw['ciphertext']=AESGCM(b'K'*32).encrypt(bytes.fromhex(h['nonce']),n.canonical(p),v2.AAD+n.canonical(h)).hex();self.path.write_bytes(n.canonical(raw))
    def test_twenty_signed_updates_keep_one_history_and_cold_reopen(self):
        for _ in range(20):self.wallet.observe(*self.packet())
        physical=self.physical();self.assertEqual(len(physical['history']['blocks']),20)
        self.assertEqual(len(physical['observations']),1)
        self.assertEqual(n.canonical(physical).count(b'"blocks":'),1)
        before=self.path.read_bytes();cold=v2.RecipientWallet(self.path,**self.args)
        self.assertEqual(cold.inventory()['as_of_height'],20);self.assertEqual(cold.inventory(),self.wallet.inventory());self.assertEqual(self.path.read_bytes(),before)
    def test_versions_refuse_cross_open_without_write(self):
        original=self.path.read_bytes()
        with self.assertRaises(ValueError):V1(self.path,**self.args)
        self.assertEqual(self.path.read_bytes(),original)
        path=self.root/'v1';V1(path,create=True,**self.args);old=path.read_bytes()
        with self.assertRaises(ValueError):v2.RecipientWallet(path,**self.args)
        self.assertEqual(path.read_bytes(),old)
    def test_tampered_history_cannot_be_authorized_by_ciphertext_key(self):
        self.wallet.observe(*self.packet());self.corrupt(lambda p:p['history']['blocks'][0].update(transactions=['aa']))
        with self.assertRaises(ValueError):self.wallet.inventory()
    def test_tampered_signed_checkpoint_and_metadata_refused(self):
        self.wallet.observe(*self.packet());original=self.path.read_bytes()
        for kind in ('checkpoint','signature','height','extra'):
            self.path.write_bytes(original)
            def edit(p):
                o=p['observations'][0]
                if kind=='checkpoint':o['checkpoint']['fees']=99
                elif kind=='signature':o['signed_header']['commit']['signatures'][0]['signature']='AA=='
                elif kind=='height':o['height']=0
                else:p['history']['trusted_nullifiers']=[]
            self.corrupt(edit)
            with self.subTest(kind=kind),self.assertRaises(ValueError):self.wallet.inventory()
        self.path.write_bytes(original)
    def test_rollback_and_fork_leave_wallet_unchanged(self):
        old=self.packet();self.wallet.observe(*old);self.wallet.observe(*self.packet());raw=self.path.read_bytes()
        with self.assertRaises(ValueError):self.wallet.observe(*old)
        self.assertEqual(self.path.read_bytes(),raw)
        bad,header=self.packet();bad['blocks'][0]['transactions']=['aa']
        with self.assertRaises(ValueError):self.wallet.observe(bad,header)
        self.assertEqual(self.path.read_bytes(),raw)
    def test_revision_and_byte_capacity_preserve_original(self):
        self.wallet.observe(*self.packet());next_packet=self.packet();before=self.path.read_bytes()
        for bound,value in (('MAX_REVISIONS',1),('MAX_PLAIN',16)):
            with patch.object(v2,bound,value),self.assertRaises(ValueError):self.wallet.observe(*next_packet)
            self.assertEqual(self.path.read_bytes(),before)
    def test_nonce_reuse_identity_and_owner_refused(self):
        before=self.path.read_bytes();nonce=bytes.fromhex(json.loads(before)['header']['nonce'])
        with patch('protocol9_history_wallet.os.urandom',return_value=nonce),self.assertRaises(n.Unavailable):self.wallet.observe(*self.packet())
        self.assertEqual(self.path.read_bytes(),before)
        with self.assertRaises(ValueError):v2.RecipientWallet(self.path,**{**self.args,'key':b'X'*32})
        self.path.chmod(0o644)
        with self.assertRaises(ValueError):self.wallet.inventory()

if __name__=='__main__':unittest.main()
