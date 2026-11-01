"""Real quorum signatures and storage mechanics; deliberately fake proof worker.

The separate native engine journey qualifies cryptographic execution.
"""
import copy, os, tempfile, unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from certificate_fixture import make_commit, make_header
from commit_verifier import sha
from test_protocol9_ledger import fixture, tx, finalize, f
from protocol9_application import Application
import protocol9_consensus as p
import protocol8_transfer as n
try: import protocol9_certificate as c
except ModuleNotFoundError: c=None

class HistoryCertificateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();os.chmod(self.tmp.name,0o700)
        self.g,self.worker=fixture()
        self.keys=[Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(31,35)]
        self.g['validators']=sorted([{'public_key':k.public_key().public_bytes_raw().hex(),'power':10} for k in self.keys],key=lambda r:r['public_key'])
        self.g['network']=self.worker.network_domain(bytes.fromhex(p.bootstrap_digest(self.g)))
        self.worker.kat_statement[1]=self.g['network'];self.raw=n.canonical(self.g)
        self.path=Path(self.tmp.name)/'ledger'
        self.app=Application(self.path,self.worker,expected_genesis=self.raw)
        self.app.init_chain(self.g['chain_id'],self.raw,self.g['validators'])
        wire=tx(self.g,self.worker.root([f(100)]),0);self.wire=wire
        for height,attempts in enumerate(([wire],[b'malformed'],[]),1):
            finalize(self.app,attempts,height);self.app.commit()
    def tearDown(self):self.app.close();self.tmp.cleanup()
    def packet(self):
        self.assertIsNotNone(c,'P9 complete-history authentication is missing')
        witness=c.export_history(self.path)
        trust=c.trust(self.raw,self.worker)
        byaddr={sha(k.public_key().public_bytes_raw())[:20]:k for k in self.keys}
        previous={'hash':'11'*32,'parts':{'total':1,'hash':'22'*32}}
        signed=make_commit(make_header(trust,witness['height']+1,witness['app_hash'],previous=previous),trust,[byaddr[v.address] for v in trust.validators])
        return witness,signed
    def test_exact_history_derives_receipt_and_global_indexes(self):
        witness,signed=self.packet();cert,ledger=c.verify_history(witness,signed,self.raw,self.worker)
        self.assertEqual(cert['state_height'],3);self.assertEqual(cert['header_height'],4)
        self.assertEqual(len(ledger['notes']),3);self.assertEqual(ledger['notes'][2]['segment'],0)
        self.assertEqual(ledger['receipts'][0]['raw'],self.wire.hex())
        self.assertEqual(ledger['receipts'][0]['height'],1)
        self.assertIn(n.parse(self.wire)[5],ledger['nullifiers'])
        self.assertEqual(witness['checkpoint']['attempt_count'],2)
    def test_omitted_changed_reordered_attempts_cannot_authenticate(self):
        witness,signed=self.packet()
        for kind in ('omit','change-refusal','reorder','extra','wrong-height','wrong-checkpoint','foreign-genesis','index'):
            bad=copy.deepcopy(witness)
            if kind=='omit':bad['blocks'].pop(1)
            elif kind=='change-refusal':bad['blocks'][1]['transactions']=['aa']
            elif kind=='reorder':bad['blocks'].reverse()
            elif kind=='extra':bad['blocks'][0]['extra']=True
            elif kind=='wrong-height':bad['height']=2
            elif kind=='wrong-checkpoint':bad['checkpoint']['fees']=2
            elif kind=='foreign-genesis':bad['genesis']['pool_id']='78'*32
            else:bad['ledger']={'receipts':[]}
            with self.subTest(kind=kind),self.assertRaises(ValueError):c.verify_history(bad,signed,self.raw,self.worker)
    def test_quorum_signature_height_and_apphash_refused(self):
        witness,signed=self.packet()
        for kind in ('signature','height','quorum','apphash'):
            bad=copy.deepcopy(signed)
            if kind=='signature':bad['commit']['signatures'][0]['signature']='AA=='
            elif kind=='height':bad['header']['height']='5'
            elif kind=='quorum':bad['commit']['signatures']=bad['commit']['signatures'][:2]
            else:bad['header']['app_hash']='00'*32
            with self.subTest(kind=kind),self.assertRaises(ValueError):c.verify_history(witness,bad,self.raw,self.worker)
    def test_unsigned_history_does_not_run_proof_verification(self):
        witness,signed=self.packet();signed['commit']['signatures']=[]
        def forbidden(*args):raise AssertionError('unsigned history reached proof verifier')
        self.worker.verify=forbidden
        with self.assertRaises(ValueError):c.verify_history(witness,signed,self.raw,self.worker)
    def test_export_refuses_symlink_and_large_history_before_allocation(self):
        self.packet();alias=Path(self.tmp.name)/'alias';alias.symlink_to(self.path)
        with self.assertRaises(ValueError):c.export_history(alias)
        self.app.db.execute('UPDATE p9_checkpoint SET checkpoint=?',(n.canonical({'height':c.MAX_HISTORY_HEIGHT+1}),))
        with self.assertRaises(ValueError):c.export_history(self.path)
    def test_empty_blocks_are_rebuilt_not_carried(self):
        witness,signed=self.packet()
        self.assertEqual(witness['height'],3);self.assertEqual([b['height'] for b in witness['blocks']],[1,2])
        cert,_=c.verify_history(witness,signed,self.raw,self.worker);self.assertEqual(cert['state_height'],3)
        for kind in ('listed-empty','moved-later','moved-past-height','short-height'):
            bad=copy.deepcopy(witness)
            if kind=='listed-empty':bad['blocks'].append({'height':3,'transactions':[]})
            elif kind=='moved-later':bad['blocks'][1]['height']=3
            elif kind=='moved-past-height':bad['blocks'][1]['height']=4
            else:bad['height']=2
            with self.subTest(kind=kind),self.assertRaises(ValueError):c.verify_history(bad,signed,self.raw,self.worker)
    def test_an_idle_ledger_outlives_the_old_block_cap(self):
        # v1 listed every block and refused past 4096; an idle engine makes ~1.2 a second, so a house lasted an hour.
        for height in range(4,4101):finalize(self.app,[],height);self.app.commit()
        witness,signed=self.packet()
        self.assertEqual(witness['height'],4100);self.assertEqual(len(witness['blocks']),2)
        cert,ledger=c.verify_history(witness,signed,self.raw,self.worker)
        self.assertEqual(cert['state_height'],4100);self.assertEqual(ledger['receipts'][0]['raw'],self.wire.hex())
        bad=copy.deepcopy(witness);bad['height']=4099
        with self.assertRaises(ValueError):c.verify_history(bad,signed,self.raw,self.worker)
    def test_skip_empty_is_the_empty_advance(self):
        import sqlite3
        from protocol9_store import Store, schema
        db=sqlite3.connect(':memory:');schema(db,create=True);store=Store(db,self.g,self.worker)
        a=store.initial();a,_,_=store.advance(a,[self.wire],1)
        b=a
        for h in range(2,40):b,_,_=store.advance(b,[],h)
        self.assertEqual(store.skip_empty(a,39),b);self.assertEqual(store.skip_empty(b,39),b)
        with self.assertRaises(ValueError):store.skip_empty(b,38)
        db.close()

if __name__=='__main__':unittest.main()
