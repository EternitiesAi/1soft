"""Real subprocess/terminal interaction over synthetic attested state, not a network."""
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import time
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import public,address
from offline_signer import create_vault
from commit_verifier import encode
from wallet_state_fixture import StateFixture

ROOT=Path(__file__).resolve().parents[1]
PASS=b'disposable-tty-state-wallet-password'

class StateWalletCLI(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.vault=self.root/'owner.pem';self.pk=create_vault(self.vault,PASS);self.owner=address(self.pk)
        recipient=Ed25519PrivateKey.generate();self.to=address(public(recipient))
        g={'chain_id':'1soft-cli-state-dev','asset':'DEV','fee':2,'protocol_version':2,
           'allocations':[{'public_key':self.pk,'units':1000},{'public_key':public(recipient),'units':0}]}
        self.fixture=StateFixture(g);self.packet=self.fixture.packet(stamp=datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
        self.genesis=self.root/'genesis.json';self.genesis.write_bytes(self.fixture.raw)
        self.packetfile=self.root/'state.json';self.packetfile.write_bytes(encode(self.packet))
        self.base=[sys.executable,str(ROOT/'scripts/state_wallet.py'),'--genesis',str(self.genesis),
            '--genesis-sha256',self.fixture.pin,'--workspace',str(self.root/'state.sqlite')]
        p=self.call('sync','--packet',str(self.packetfile));self.assertEqual(p.returncode,0,p.stderr)
    def tearDown(self):self.fixture.close();self.tmp.cleanup()
    def call(self,*args):return subprocess.run([*self.base,*args],input='',capture_output=True,text=True,timeout=12)
    def prepare(self):
        path=self.root/'review.json'
        p=self.call('prepare','--account',self.owner,'--recipient',self.to,'--units','20','--valid-until','20','--output',str(path))
        self.assertEqual(p.returncode,0,p.stderr);return path,json.loads(path.read_text())
    def tty(self,command,responses):
        master,slave=pty.openpty();p=subprocess.Popen(command,stdin=slave,stdout=slave,stderr=slave,start_new_session=True);os.close(slave)
        data=bytearray();position=0
        try:
            for prompt,answer in responses:
                until=time.monotonic()+12
                while prompt not in data[position:]:
                    if time.monotonic()>until:self.fail('terminal prompt timeout')
                    if select.select([master],[],[],.1)[0]:
                        try:chunk=os.read(master,65536)
                        except OSError:chunk=b''
                        if not chunk:self.fail('terminal closed early: '+repr(data))
                        data.extend(chunk)
                position=len(data);os.write(master,answer+b'\n')
            until=time.monotonic()+12
            while p.poll() is None:
                if time.monotonic()>until:self.fail('terminal exit timeout')
                if select.select([master],[],[],.1)[0]:
                    try:data.extend(os.read(master,65536))
                    except OSError:break
            p.wait(timeout=5);return p.returncode,bytes(data)
        finally:
            if p.poll() is None:p.kill();p.wait()
            os.close(master)
    def sign_tty(self,path,review,out):
        return self.tty([*self.base,'sign','--review',str(path),'--vault',str(self.vault),'--output',str(out)],
            [(b'Type the full certified review digest to approve:',review['confirmation'].encode()),(b'Vault passphrase:',PASS)])
    def test_prepare_displays_asof_height_and_unbroadcast_status(self):
        _,r=self.prepare();self.assertFalse(r['broadcast']);self.assertFalse(r['latest_network_state_established'])
    def test_noninteractive_signing_refused(self):
        path,_=self.prepare();out=self.root/'no.json'
        p=self.call('sign','--review',str(path),'--vault',str(self.vault),'--output',str(out))
        self.assertEqual(p.returncode,2);self.assertFalse(out.exists())
    def test_real_terminal_sign_export_and_native_execution(self):
        path,r=self.prepare();out=self.root/'signed.json';code,display=self.sign_tty(path,r,out)
        self.assertEqual(code,0,display);self.assertNotIn(PASS,display)
        env=json.loads(out.read_text());self.fixture.ledger.apply(env,height=2)
        self.assertEqual(self.fixture.ledger.balance(self.to),20)
        self.assertEqual(json.loads(self.call('pending').stdout)['intentions'][0]['status'],'signed')
        exported=self.root/'recovered.json';p=self.call('export','--txid',r['native_txid'],'--output',str(exported))
        self.assertEqual(p.returncode,0);self.assertEqual(exported.read_bytes(),out.read_bytes())
    def test_wrong_confirmation_no_password_prompt(self):
        path,r=self.prepare();out=self.root/'no.json'
        code,display=self.tty([*self.base,'sign','--review',str(path),'--vault',str(self.vault),'--output',str(out)],
            [(b'Type the full certified review digest to approve:',b'0'*64)])
        self.assertEqual(code,2);self.assertNotIn(b'Vault passphrase:',display);self.assertFalse(out.exists())
    def test_failed_output_preserves_signature_and_hold(self):
        path,r=self.prepare();out=self.root/'old.json';out.write_bytes(b'old')
        code,display=self.sign_tty(path,r,out);self.assertEqual(code,2,display);self.assertEqual(out.read_bytes(),b'old')
        self.assertEqual(len(json.loads(self.call('pending').stdout)['intentions']),1)
        recovered=self.root/'recovered.json';p=self.call('export','--txid',r['native_txid'],'--output',str(recovered))
        self.assertEqual(p.returncode,0);self.fixture.ledger.apply(json.loads(recovered.read_text()),height=2)
    def test_prepare_never_overwrites_review(self):
        path,_=self.prepare();old=path.read_bytes()
        p=self.call('prepare','--account',self.owner,'--recipient',self.to,'--units','21','--valid-until','20','--output',str(path))
        self.assertEqual(p.returncode,2);self.assertEqual(path.read_bytes(),old)
    def test_wrong_pin_refused(self):
        command=list(self.base);command[command.index('--genesis-sha256')+1]='0'*64
        p=subprocess.run([*command,'pending'],capture_output=True,text=True,timeout=10);self.assertEqual(p.returncode,2)
    def test_malformed_state_file_refused(self):
        self.packetfile.write_text('{"state":{},"state":{}}')
        self.assertEqual(self.call('sync','--packet',str(self.packetfile)).returncode,2)

if __name__=='__main__':unittest.main()
