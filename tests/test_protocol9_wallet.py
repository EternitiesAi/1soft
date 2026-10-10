"""Adversarial envelope/worker unit mechanics, no native proof or consensus claim."""
import copy, json, os, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import protocol8_transfer as n
from protocol9_notes import NoteController
from protocol8_notes import PrivateProcess
from test_protocol9_ledger import fixture
try: from protocol9_wallet import RecipientWallet
except ModuleNotFoundError: RecipientWallet=None

class EnvelopeMechanics(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.path=self.root/'wallet';self.controller=object.__new__(NoteController)
        self.assertIsNotNone(RecipientWallet,'P9 protected wallet is missing')
        self.controller.g,self.controller.worker=fixture()
        self.controller.sha256='12'*32
        self.keypatch=patch.object(NoteController,'key',return_value='15'*32);self.keypatch.start()
        self.args=dict(key=b'K'*32,wallet_id='16'*32,recipient_secret='17'*32,controller=self.controller)
        self.wallet=RecipientWallet(self.path,create=True,**self.args)
    def tearDown(self):self.keypatch.stop();self.temp.cleanup()
    def test_cold_open_idempotent_no_plaintext_sidecars(self):
        old=self.path.read_bytes();self.assertEqual(RecipientWallet(self.path,**self.args).inventory(),self.wallet.inventory())
        self.assertEqual(self.path.read_bytes(),old);self.assertEqual(set(p.name for p in self.root.iterdir()),{'wallet','wallet.lock'})
        self.assertNotIn(b'"notes":',old);self.assertNotIn(b'K'*32,old)
    def test_wrong_key_and_identity_refused_without_write(self):
        old=self.path.read_bytes()
        for change in ({'key':b'X'*32},{'wallet_id':'18'*32}):
            with self.assertRaises(n.Invalid):RecipientWallet(self.path,**{**self.args,**change})
            self.assertEqual(self.path.read_bytes(),old)
    def test_ciphertext_and_header_authentication(self):
        old=self.path.read_bytes();v=json.loads(old)
        for mutate in ('ciphertext','revision','extra'):
            bad=copy.deepcopy(v)
            if mutate=='ciphertext':bad['ciphertext']=('00' if bad['ciphertext'][:2]!='00' else 'ff')+bad['ciphertext'][2:]
            elif mutate=='revision':bad['header']['revision']=1
            else:bad['header']['extra']='forged'
            self.path.write_bytes(n.canonical(bad))
            with self.assertRaises(n.Invalid):self.wallet.inventory()
        self.path.write_bytes(old)
    def test_nonce_reuse_failure_preserves_original(self):
        old=self.path.read_bytes();nonce=bytes.fromhex(json.loads(old)['header']['nonce'])
        with self.wallet._locked():
            p=self.wallet._read();p['revision']+=1
            with patch('protocol9_wallet.os.urandom',return_value=nonce):
                with self.assertRaises(n.Unavailable):self.wallet._write(p)
        self.assertEqual(self.path.read_bytes(),old)
    def test_permissions_hardlinks_and_sidecars_refused(self):
        self.path.chmod(0o644)
        with self.assertRaises(n.Invalid):self.wallet.inventory()
        self.path.chmod(0o600);os.link(self.path,self.root/'alias')
        with self.assertRaises(n.Invalid):self.wallet.inventory()
        (self.root/'alias').unlink();(self.root/'wallet-wal').touch()
        with self.assertRaises(n.Invalid):self.wallet.inventory()
    def test_symlink_and_existing_creation_refused(self):
        old=self.path.read_bytes()
        with self.assertRaises(n.Invalid):RecipientWallet(self.path,create=True,**self.args)
        self.assertEqual(self.path.read_bytes(),old)
        alias=self.root/'link';alias.symlink_to(self.path)
        with self.assertRaises(n.Invalid):RecipientWallet(alias,**self.args)
    def test_private_worker_identity_and_malformed_output_reaped(self):
        executable=self.root/'bad-worker';executable.write_bytes(b'#!/bin/sh\nprintf x\n');executable.chmod(0o700)
        worker=PrivateProcess(executable,n.sha(executable.read_bytes()))
        with self.assertRaises(n.Unavailable):worker.call('key',bytes(32),32)
        self.assertTrue(worker.runs[-1]['process_reaped']);self.assertEqual(worker.runs[-1]['output_bytes'],1)
        executable.write_bytes(b'#!/bin/sh\nprintf y\n')
        with self.assertRaises(n.Unavailable):worker.call('key',bytes(32),32)
        self.assertEqual(len(worker.runs),1)
    def test_segment_selection_handles_global_history_over16(self):
        ledger={'notes':[{'commitment':str(i),'segment':i//16,'position':i%16} for i in range(37)]}
        self.assertEqual(self.wallet._segment(ledger,'3'),[str(i) for i in range(16)])
        self.assertEqual(self.wallet._segment(ledger,'36'),[str(i) for i in range(32,37)])
        with self.assertRaises(n.Invalid):self.wallet._segment(ledger,'unknown')
    def test_import_refuses_another_commitment_in_the_same_segment(self):
        # Fake private inspection isolates the explicit caller identity check.
        # Authentication/native ownership are exercised in the actual gate.
        from test_protocol9_ledger import f
        from contextlib import nullcontext
        o={'origin':f(1),'value':10,'expiry':100,'note_secret':f(2),'blind':f(3)}
        p={'observations':[{}],'notes':[],'obligations':[],'revision':0}
        ledger={'notes':[{'commitment':f(100),'segment':0,'position':0},{'commitment':f(101),'segment':0,'position':1}]}
        with patch.object(self.wallet,'_locked',return_value=nullcontext()),patch.object(self.wallet,'_read',return_value=p),patch.object(self.wallet,'_ledger',return_value=ledger),patch.object(self.controller,'inspect',return_value={'commitment':f(101)}):
            with patch.object(self.wallet,'_origin'),patch.object(self.wallet,'_write',side_effect=AssertionError('mismatched import wrote wallet')):
                with self.assertRaises(n.Invalid):self.wallet.import_note(f(100),o,genesis=True)
if __name__=='__main__':unittest.main()
