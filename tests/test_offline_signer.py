"""Disposable keys only. These tests establish neither custody nor consensus."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import NativeLedger, Reject, address, canonical, public, sign
from offline_signer import create_vault, review_intent, approve_intent, _load_vault

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = b'disposable-test-password-not-a-real-secret'


class SignerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / 'owner.pem'
        self.pk = create_vault(self.path, PASSWORD)
        self.merchant = Ed25519PrivateKey.generate()
        self.to = address(public(self.merchant))
        self.owner = address(self.pk)
        self.g = {'chain_id': '1soft-offline-dev', 'asset': 'DEV', 'fee': 2, 'protocol_version': 2,
            'allocations': [{'public_key': self.pk, 'units': 1000},
                            {'public_key': public(self.merchant), 'units': 0}]}
        self.db = NativeLedger(':memory:', self.g)
        self.body = self.db.body(self.owner, 0, {'type': 'transfer', 'to': self.to, 'units': 20})
    def tearDown(self):
        self.db.close(); self.temp.cleanup()
    def review(self, body=None, pk=None, mode='sign'):
        return review_intent(self.g, self.body if body is None else body, pk or self.pk, mode=mode)
    def approved(self, body=None, path=None, pk=None, mode='sign'):
        body = self.body if body is None else body
        pk = pk or self.pk
        return approve_intent(path or self.path, PASSWORD, self.g, body, pk,
                              self.review(body, pk, mode)['confirmation'], mode=mode)
    def test_only_encrypted_pem_on_disk(self):
        data = self.path.read_bytes()
        self.assertTrue(data.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
    def test_correct_key_unlocks(self):
        self.assertEqual(public(_load_vault(self.path, PASSWORD)), self.pk)
    def test_wrong_password_rejected(self):
        with self.assertRaises(Reject): _load_vault(self.path, b'wrong-password-long-enough')
    def test_short_password_rejected(self):
        with self.assertRaises(Reject): create_vault(self.root/'short.pem', b'short')
    def test_oversized_password_rejected(self):
        with self.assertRaises(Reject): create_vault(self.root/'long.pem', b'x'*1025)
    def test_nonbytes_password_rejected(self):
        with self.assertRaises(Reject): create_vault(self.root/'text.pem', 'long-enough-password')
    def test_existing_vault_never_overwritten(self):
        before = self.path.read_bytes()
        with self.assertRaises(FileExistsError): create_vault(self.path, PASSWORD)
        self.assertEqual(self.path.read_bytes(), before)
    def test_world_readable_key_refused(self):
        self.path.chmod(0o644)
        with self.assertRaises(Reject): _load_vault(self.path, PASSWORD)
    def test_world_readable_directory_refused(self):
        self.root.chmod(0o755)
        with self.assertRaises(Reject): _load_vault(self.path, PASSWORD)
    def test_key_symlink_refused(self):
        link = self.root/'link.pem'; link.symlink_to(self.path)
        with self.assertRaises(OSError): _load_vault(link, PASSWORD)
    def test_parent_symlink_refused(self):
        real = self.root/'real'; real.mkdir(mode=0o700)
        alias = self.root/'alias'; alias.symlink_to(real, target_is_directory=True)
        with self.assertRaises(OSError): create_vault(alias/'key.pem', PASSWORD)
    def test_hardlink_refused(self):
        os.link(self.path, self.root/'linked.pem')
        with self.assertRaises(Reject): _load_vault(self.path, PASSWORD)
    def test_fifo_refused_without_blocking(self):
        fifo = self.root/'fifo'; os.mkfifo(fifo, mode=0o600)
        with self.assertRaises(Reject): _load_vault(fifo, PASSWORD)
    def test_directory_as_key_refused(self):
        folder = self.root/'directory'; folder.mkdir(mode=0o700)
        with self.assertRaises((Reject, OSError)): _load_vault(folder, PASSWORD)
    def test_unencrypted_key_refused(self):
        key = Ed25519PrivateKey.generate()
        self.path.write_bytes(key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
        with self.assertRaises(Reject): _load_vault(self.path, PASSWORD)
    def test_wrong_key_type_refused(self):
        key = ec.generate_private_key(ec.SECP256R1())
        self.path.write_bytes(key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.BestAvailableEncryption(PASSWORD)))
        with self.assertRaises(Reject): _load_vault(self.path, PASSWORD)
    def test_oversized_key_refused(self):
        self.path.write_bytes(b'x'*8193)
        with self.assertRaises(Reject): _load_vault(self.path, PASSWORD)
    def test_appended_second_pem_refused(self):
        self.path.write_bytes(self.path.read_bytes()*2)
        with self.assertRaises(Reject): _load_vault(self.path, PASSWORD)
    def test_corrupt_pem_refused(self):
        self.path.write_bytes(b'-----BEGIN ENCRYPTED PRIVATE KEY-----\nxyz\n-----END ENCRYPTED PRIVATE KEY-----\n')
        with self.assertRaises(Reject): _load_vault(self.path, PASSWORD)
    def test_review_no_unlock(self):
        with patch('offline_signer._load_vault', side_effect=AssertionError('must not unlock')):
            self.assertEqual(self.review()['proposed_account_debit_units'], 22)
    def test_transfer_round_trip(self):
        self.db.apply(self.approved(), height=1)
        self.assertEqual(self.db.balance(self.to), 20)
        self.assertEqual(self.db.balance(self.owner), 978)
    def test_review_marks_unverified_authority(self):
        self.assertFalse(self.review()['current_authority_verified'])
    def test_input_not_mutated(self):
        original = copy.deepcopy(self.body)
        self.approved()
        self.assertEqual(self.body, original)
    def test_bad_confirmation_before_key_access(self):
        with patch('offline_signer._load_vault', side_effect=AssertionError('must not unlock')):
            with self.assertRaises(Reject): approve_intent(self.path, PASSWORD, self.g, self.body, self.pk, '0'*64)
    def test_changed_amount_rejected(self):
        reviewed = self.review()['confirmation']; self.body['op']['units'] = 21
        with self.assertRaises(Reject): approve_intent(self.path, PASSWORD, self.g, self.body, self.pk, reviewed)
    def test_all_intention_dimensions_bound(self):
        original = self.review()['confirmation']
        changes = [('nonce',1), ('valid_until',999), ('max_fee',3), ('grant_id','worker')]
        for field, value in changes:
            changed = copy.deepcopy(self.body); changed[field] = value
            self.assertNotEqual(original, self.review(changed)['confirmation'], field)
    def test_other_reviewed_signer_not_unlock_same_key(self):
        other = public(self.merchant)
        with self.assertRaises(Reject): self.approved(pk=other)
    def test_recipient_change_changes_digest(self):
        changed = copy.deepcopy(self.body); changed['op']['to'] = 'other-account'
        self.assertNotEqual(self.review()['confirmation'], self.review(changed)['confirmation'])
    def test_wrong_network_refused(self):
        self.body['chain_id'] = 'other'
        with self.assertRaises(Reject): self.review()
    def test_wrong_genesis_refused(self):
        self.body['genesis_hash'] = '0'*64
        with self.assertRaises(Reject): self.review()
    def test_wrong_protocol_refused(self):
        self.body['version'] = 1
        with self.assertRaises(Reject): self.review()
    def test_boolean_amount_refused(self):
        self.body['op']['units'] = True
        with self.assertRaises(Reject): self.review()
    def test_unknown_body_field_refused(self):
        self.body['memo'] = 'hide something'
        with self.assertRaises(Reject): self.review()
    def test_unknown_operation_field_refused(self):
        self.body['op']['memo'] = 'hide something'
        with self.assertRaises(Reject): self.review()
    def test_fee_beyond_consent_refused(self):
        self.body['max_fee'] = 1
        with self.assertRaises(Reject): self.review()
    def test_accept_transfer_refused(self):
        with self.assertRaises(Reject): self.review(mode='accept')
    def test_empty_grant_allowlist_refused(self):
        body = self.db.body(self.owner,0, {'type':'grant','id':'raven','public_key':public(self.merchant),
            'cap':100,'expires':100,'recipients':[]})
        with self.assertRaises(Reject): self.review(body)
    def test_agent_cannot_review_admin_as_spend(self):
        body = self.db.body(self.owner,0,{'type':'fence'},grant_id='worker')
        with self.assertRaises(Reject): self.review(body)
    def test_delegated_payment_works(self):
        path = self.root/'agent.pem'; pk = create_vault(path,PASSWORD)
        grant = self.db.body(self.owner,0,{'type':'grant','id':'worker','public_key':pk,
            'cap':30,'expires':100,'recipients':[self.to]})
        self.db.apply(self.approved(grant),height=1)
        spend = self.db.body(self.owner,0,{'type':'transfer','to':self.to,'units':20},grant_id='worker')
        self.db.apply(self.approved(spend,path,pk),height=2)
        self.assertEqual(self.db.balance(self.to),20)
    def test_onboarding_two_vaults(self):
        path = self.root/'new.pem'; pk = create_vault(path,PASSWORD)
        body = self.db.body(self.owner,0,{'type':'open_account','public_key':pk,'units':100,'acceptance':''})
        accepted = self.approved(body,path,pk,mode='accept')
        self.db.apply(self.approved(accepted),height=1)
        self.assertEqual(self.db.balance(address(pk)),100)
    def test_sponsor_cannot_skip_incoming_acceptance(self):
        body = self.db.body(self.owner,0,{'type':'open_account','public_key':public(self.merchant),'units':100,'acceptance':''})
        with self.assertRaises(Reject): self.approved(body)
    def test_funding_change_invalidates_acceptance(self):
        path=self.root/'new.pem';pk=create_vault(path,PASSWORD)
        body=self.db.body(self.owner,0,{'type':'open_account','public_key':pk,'units':100,'acceptance':''})
        accepted=self.approved(body,path,pk,mode='accept');accepted['op']['units']=101
        with self.assertRaises(Reject): self.approved(accepted)
    def test_key_rotation_preserves_id(self):
        path=self.root/'replacement.pem';pk=create_vault(path,PASSWORD)
        body=self.db.body(self.owner,0,{'type':'rotate_key','public_key':pk,'acceptance':''})
        accepted=self.approved(body,path,pk,mode='accept')
        self.db.apply(self.approved(accepted),height=1)
        spend=self.db.body(self.owner,1,{'type':'transfer','to':self.to,'units':20})
        self.db.apply(self.approved(spend,path,pk),height=2)
        self.assertEqual(self.db._account(self.owner)['public_key'],pk)
        self.assertEqual(self.db.balance(self.owner),976)
    def test_revocation_can_be_signed(self):
        grant=self.db.body(self.owner,0,{'type':'grant','id':'worker','public_key':public(self.merchant),
            'cap':30,'expires':100,'recipients':[self.to]})
        self.db.apply(self.approved(grant),height=1)
        self.db.apply(self.approved(self.db.body(self.owner,1,{'type':'revoke','id':'worker'})),height=2)
        self.assertEqual(self.db.state()['grants'][0]['revoked'],1)
    def test_fence_can_be_signed(self):
        self.db.apply(self.approved(self.db.body(self.owner,0,{'type':'fence'})),height=1)
        self.assertEqual(self.db._account(self.owner)['epoch'],1)
    def test_replay_is_ledger_responsibility(self):
        result=self.approved(); self.db.apply(result,height=1);self.db.apply(result,height=2)
        self.assertEqual(self.db.balance(self.to),20)
    def test_review_cli_needs_no_secret(self):
        g=self.root/'genesis.json';g.write_bytes(canonical(self.g))
        b=self.root/'body.json';b.write_bytes(canonical(self.body))
        p=subprocess.run([sys.executable,str(ROOT/'scripts/wallet.py'),'review','--genesis',str(g),
            '--body',str(b),'--signer-public-key',self.pk],capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(json.loads(p.stdout)['confirmation'],self.review()['confirmation'])
    def test_noninteractive_key_creation_refused(self):
        p=subprocess.run([sys.executable,str(ROOT/'scripts/wallet.py'),'create-key','--vault',str(self.root/'no.pem')],
            input='',capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,2);self.assertFalse((self.root/'no.pem').exists())
    def test_noninteractive_sign_refused(self):
        g=self.root/'genesis.json';g.write_bytes(canonical(self.g))
        b=self.root/'body.json';b.write_bytes(canonical(self.body));out=self.root/'out.json'
        p=subprocess.run([sys.executable,str(ROOT/'scripts/wallet.py'),'sign','--genesis',str(g),
            '--body',str(b),'--signer-public-key',self.pk,'--vault',str(self.path),'--output',str(out)],
            input='',capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,2);self.assertFalse(out.exists())
    def test_duplicate_json_keys_cli_refused(self):
        g=self.root/'genesis.json';g.write_bytes(canonical(self.g));b=self.root/'body.json'
        b.write_bytes(b'{"op":{},"op":{}}')
        p=subprocess.run([sys.executable,str(ROOT/'scripts/wallet.py'),'review','--genesis',str(g),
            '--body',str(b),'--signer-public-key',self.pk],capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,2)



    def test_nonascii_confirmation_refused(self):
        with self.assertRaises(Reject):
            approve_intent(self.path,PASSWORD,self.g,self.body,self.pk,'é'*64)

    def tty_command(self, command, responses):
        import pty, select, time
        master, slave = pty.openpty()
        proc = subprocess.Popen(command,stdin=slave,stdout=slave,stderr=slave,close_fds=True,start_new_session=True)
        os.close(slave); output=bytearray(); position=0
        try:
            for prompt,answer in responses:
                end=time.monotonic()+12
                while prompt not in output[position:]:
                    if time.monotonic()>end: self.fail('TTY prompt not reached: '+repr(bytes(output)))
                    ready,_,_=select.select([master],[],[],0.1)
                    if ready:
                        try: chunk=os.read(master,65536)
                        except OSError: chunk=b''
                        if not chunk:self.fail('TTY closed before prompt')
                        output.extend(chunk)
                position=len(output)
                os.write(master,answer+b'\n')
            deadline=time.monotonic()+12
            while proc.poll() is None:
                if time.monotonic()>deadline:self.fail('TTY command did not exit')
                ready,_,_=select.select([master],[],[],0.1)
                if ready:
                    try:output.extend(os.read(master,65536))
                    except OSError:break
            proc.wait(timeout=12)
            while select.select([master],[],[],0)[0]:
                try:
                    data=os.read(master,65536)
                    if not data:break
                    output.extend(data)
                except OSError:break
            return proc.returncode,bytes(output)
        finally:
            if proc.poll() is None:proc.kill();proc.wait()
            os.close(master)

    def test_real_terminal_creates_encrypted_key_without_echoing_password(self):
        path=self.root/'tty.pem'
        code,output=self.tty_command([sys.executable,str(ROOT/'scripts/wallet.py'),'create-key','--vault',str(path)],
            [(b'Vault passphrase:',PASSWORD),(b'Repeat passphrase:',PASSWORD)])
        self.assertEqual(code,0,output);self.assertNotIn(PASSWORD,output)
        self.assertTrue(path.read_bytes().startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'))

    def test_real_terminal_signs_and_ledger_accepts(self):
        g=self.root/'genesis.json';g.write_bytes(canonical(self.g));b=self.root/'body.json';b.write_bytes(canonical(self.body))
        out=self.root/'signed.json'
        command=[sys.executable,str(ROOT/'scripts/wallet.py'),'sign','--genesis',str(g),'--body',str(b),
            '--signer-public-key',self.pk,'--vault',str(self.path),'--output',str(out)]
        code,output=self.tty_command(command,[(b'Type the full confirmation digest shown above to approve:',self.review()['confirmation'].encode()),
            (b'Vault passphrase:',PASSWORD)])
        self.assertEqual(code,0,output);self.assertNotIn(PASSWORD,output)
        self.db.apply(json.loads(out.read_text()),height=1)
        self.assertEqual(self.db.balance(self.to),20)

    def test_real_terminal_rejects_wrong_confirmation_before_unlock(self):
        g=self.root/'genesis.json';g.write_bytes(canonical(self.g));b=self.root/'body.json';b.write_bytes(canonical(self.body));out=self.root/'no.json'
        command=[sys.executable,str(ROOT/'scripts/wallet.py'),'sign','--genesis',str(g),'--body',str(b),
            '--signer-public-key',self.pk,'--vault',str(self.path),'--output',str(out)]
        code,output=self.tty_command(command,[(b'Type the full confirmation digest shown above to approve:',b'0'*64)])
        self.assertEqual(code,2);self.assertNotIn(b'Vault passphrase:',output);self.assertFalse(out.exists())

    def test_real_terminal_does_not_overwrite_existing_output(self):
        g=self.root/'genesis.json';g.write_bytes(canonical(self.g));b=self.root/'body.json';b.write_bytes(canonical(self.body));out=self.root/'old.json';out.write_bytes(b'old')
        command=[sys.executable,str(ROOT/'scripts/wallet.py'),'sign','--genesis',str(g),'--body',str(b),
            '--signer-public-key',self.pk,'--vault',str(self.path),'--output',str(out)]
        code,output=self.tty_command(command,[(b'Type the full confirmation digest shown above to approve:',self.review()['confirmation'].encode()),
            (b'Vault passphrase:',PASSWORD)])
        self.assertEqual(code,2);self.assertEqual(out.read_bytes(),b'old')

if __name__=='__main__':unittest.main()
