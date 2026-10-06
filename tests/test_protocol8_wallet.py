"""Adversarial envelope/worker unit mechanics, no native proof or consensus claim."""
import copy, json, os, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import protocol8_transfer as n
from protocol8_notes import NoteController,PrivateProcess
from protocol8_wallet import RecipientWallet

class EnvelopeMechanics(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.path=self.root/'wallet';self.controller=object.__new__(NoteController)
        self.controller.g={k:'11'*32 for k in ('profile_sha256','worker_sha256','pool_id','asset','mission')}
        self.controller.g.update(protocol_version=8,chain_id='fake-envelope-test',validators=[],fee=1)
        self.controller.sha256='12'*32
        self.controller.worker=type('FakeIdentity',(),{'sha256':'13'*32,'kat_sha256':'14'*32})()
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
            with patch('protocol8_wallet.os.urandom',return_value=nonce):
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
if __name__=='__main__':unittest.main()
