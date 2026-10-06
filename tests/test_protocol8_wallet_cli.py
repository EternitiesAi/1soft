"""Labeled fake-native CLI mechanics; real AES envelope, no native/consensus claim."""
import copy,fcntl,json,os,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from test_protocol8_consensus import FakeWorker,f,wire
import protocol8_consensus as p
import protocol8_wallet_cli as c
from protocol8_notes import NoteController

class WalletCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.data=self.root/'data';self.data.mkdir(mode=0o700)
        self.workspace=self.root/'config';self.blob=self.data/'wallet'
        self.binaries={}
        for name in ('worker','helper','prover'):
            path=self.root/name;path.write_bytes(('fake-'+name).encode());path.chmod(0o700);self.binaries[name]=path
        self.w=FakeWorker();self.w.sha256=c.sha(self.binaries['worker'].read_bytes())
        fields=[f(v) for v in (8,1,2,3,1,5,6,1,32,1,10,11,12)];fields[4]=self.w.root([f(100)])
        self.tx=wire(fields);self.w.kat_statement=fields;self.w.kat_sha256=c.sha(self.tx)
        self.w.audit=lambda:{'fake_worker':True,'call_count':0,'reaped_count':0,'timeout_count':0,'calls':[],'retained_count':0,'retention_limit':512}
        self.g={'format':p.GENESIS_FORMAT,'protocol_version':8,'chain_id':'cli-fake',
            'profile_sha256':p.PROFILE_SHA256,'worker_sha256':self.w.sha256,'kat_sha256':self.w.kat_sha256,
            'validators':[{'public_key':f(v),'power':10} for v in range(1,5)],'pool_id':'cd'*32,
            'asset':f(2),'mission':f(3),'fee':1,'network':f(1),'notes':[{'kind':'p8-recipient-v1','commitment':f(100)}]}
        self.genesis=self.root/'genesis';self.genesis.write_bytes(p.canonical(self.g))
        self.kat=self.root/'kat';self.kat.write_bytes(self.tx);self.genesis_pin=c.sha(self.genesis.read_bytes())
        self.cred=self.root/'credentials';self.secret={'key':'4b'*32,'wallet_id':f(77),'recipient_secret':f(78)}
        self.cred.write_bytes(p.canonical(self.secret));self.cred.chmod(0o600)
        self.patches=[patch.object(c,'Worker',return_value=self.w),patch.object(NoteController,'key',return_value=f(79))]
        for x in self.patches:x.start()
    def tearDown(self):
        for x in reversed(self.patches):x.stop()
        self.tmp.cleanup()
    def args(self,command,**kw):
        return SimpleNamespace(command=command,workspace=self.workspace,genesis_sha256=self.genesis_pin,credentials=self.cred,
            **({'genesis':self.genesis,'kat':self.kat,'worker':self.binaries['worker'],'helper':self.binaries['helper'],
                'helper_sha256':c.sha(self.binaries['helper'].read_bytes()),'prover':self.binaries['prover'],
                'prover_sha256':c.sha(self.binaries['prover'].read_bytes()),'wallet':self.blob} if command=='init' else {}),**kw)
    def call(self,command,**kw):return c.execute(self.args(command,**kw))
    def init(self):
        result,code=self.call('init');self.assertEqual(code,0,result);return result
    def test_creation_encrypts_without_printing_credentials(self):
        result=self.init();self.assertEqual(set(x.name for x in self.workspace.iterdir()),c.MEMBERS)
        self.assertEqual(set(x.name for x in self.data.iterdir()),{'wallet','wallet.lock'})
        for path in (*self.workspace.iterdir(),*self.data.iterdir()):self.assertEqual(path.stat().st_mode&0o777,0o600)
        raw=p.canonical(result)+self.blob.read_bytes()+(self.workspace/'wallet-cli.json').read_bytes()
        for name in ('key','recipient_secret'):self.assertNotIn(self.secret[name].encode(),raw)
    def test_doctor_no_native_or_wallet_write(self):
        self.init();before=self.blob.read_bytes()
        with patch.object(c,'Worker',side_effect=AssertionError('native doctor')):
            result,code=self.call('doctor')
        self.assertEqual(code,0);self.assertFalse(result['native_executed']);self.assertFalse(result['encrypted_store_authenticated'])
        self.assertEqual(result['native_audits'],{});self.assertEqual(self.blob.read_bytes(),before)
    def test_native_cold_inventory_byte_stable(self):
        self.init();old=self.blob.read_bytes();a,code=self.call('inventory');b,code2=self.call('inventory')
        self.assertEqual((code,code2),(0,0));self.assertEqual(a['inventory'],b['inventory']);self.assertEqual(self.blob.read_bytes(),old)
    def test_wrong_pin_before_creation(self):
        args=self.args('init');args.genesis_sha256='ef'*32
        with patch.object(c,'Worker',side_effect=AssertionError('native before pins')):r,code=c.execute(args)
        self.assertEqual(code,1);self.assertFalse(self.workspace.exists());self.assertFalse(self.blob.exists());self.assertEqual(r['native_audits'],{})
    def test_existing_targets_preserved(self):
        self.init();before=self.blob.read_bytes();r,code=self.call('init')
        self.assertEqual(code,1);self.assertEqual(before,self.blob.read_bytes())
    def test_credential_change_refuses_before_native(self):
        self.init();before=self.blob.read_bytes();self.cred.write_bytes(p.canonical({**self.secret,'key':'58'*32}))
        with patch.object(c,'Worker',side_effect=AssertionError('native before pins')):r,code=self.call('inventory')
        self.assertEqual(code,1);self.assertEqual(before,self.blob.read_bytes());self.assertEqual(r['native_audits'],{})
    def test_ciphertext_authentication_refuses_preserves_corruption(self):
        self.init();v=json.loads(self.blob.read_bytes());v['ciphertext']=('00' if v['ciphertext'][:2]!='00' else 'ff')+v['ciphertext'][2:]
        self.blob.write_bytes(p.canonical(v));bad=self.blob.read_bytes();r,code=self.call('inventory')
        self.assertEqual(code,1);self.assertEqual(bad,self.blob.read_bytes());self.assertEqual(r['status'],'refused')
    def test_duplicate_config_owner_refused(self):
        self.init();before=self.blob.read_bytes();fd=os.open(self.workspace/'wallet-cli.lock',os.O_RDONLY)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);r,code=self.call('doctor')
        finally:os.close(fd)
        self.assertEqual(code,1);self.assertEqual(before,self.blob.read_bytes());self.assertEqual(r['native_audits'],{})
    def test_permission_hardlink_sidecar_refusals(self):
        self.init();before=self.blob.read_bytes();self.cred.chmod(0o644);self.assertEqual(self.call('doctor')[1],1)
        self.cred.chmod(0o600);os.link(self.cred,self.root/'alias');self.assertEqual(self.call('doctor')[1],1)
        (self.root/'alias').unlink();(self.data/'wallet-wal').touch();self.assertEqual(self.call('inventory')[1],1)
        self.assertEqual(self.blob.read_bytes(),before)
    def test_changed_manifest_and_runtime_refused(self):
        self.init();path=self.workspace/'wallet-cli.json';old=path.read_bytes();v=json.loads(old);v['runtime_files']={};path.write_bytes(p.canonical(v))
        self.assertEqual(self.call('doctor')[1],1);path.write_bytes(old)
        with patch.object(c,'runtime_files',return_value={}):self.assertEqual(self.call('doctor')[1],1)
    def test_private_output_is_atomic_nonoverwriting_and_link_safe(self):
        target=self.data/'delivered';r=c.private_output(target,b'private-opening');self.assertEqual(target.read_bytes(),b'private-opening')
        self.assertEqual(target.stat().st_mode&0o777,0o600);self.assertEqual(target.stat().st_nlink,1)
        with self.assertRaises(ValueError):c.private_output(target,b'changed')
        link=self.data/'link';link.symlink_to(target)
        with self.assertRaises(ValueError):c.private_output(link,b'changed')
        self.assertNotIn(b'private-opening',p.canonical(r));self.assertFalse(list(self.data.glob('*.stage-*')))
    def test_exception_never_echoes_private_payload(self):
        secret='never-print-this-private-payload'
        with patch.object(c,'operate',side_effect=ValueError(secret)):r,code=self.call('inventory')
        self.assertEqual(code,1);self.assertNotIn(secret,p.canonical(r).decode());self.assertEqual(r['broadcast_calls'],0)

if __name__=='__main__':unittest.main()
