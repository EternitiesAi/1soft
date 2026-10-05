"""Supplied actual P7 origin, encrypted custody and deliberate fault boundaries."""
import copy,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from protocol7_treasury import canonical,digest,integer,numfield,parse,ZERO,Unavailable
from protocol7_worker import Worker
from protocol7_prover import Prover
from protocol7_notes import NoteController
from protocol7_wallet import CertifiedTreasuryJournal
from protocol7_vault import ChangeVault,VaultError

INPUTS=('P7_VAULT_ORIGIN','P7_VAULT_WORKER','P7_VAULT_PROVER','P7_NOTE_CONTROLLER','P7_REQUEST_FIXTURE')
@unittest.skipUnless(all(os.environ.get(k) for k in INPUTS),'unassessed: actual certified P7 origin/binaries not supplied')
class VaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report_path=Path(os.environ['P7_VAULT_ORIGIN']);cls.report=json.loads(cls.report_path.read_bytes())
        cls.g=cls.report['genesis'];cls.rawg=canonical(cls.g);cls.first=bytes.fromhex(cls.report['prepared_wire'])
        cls.worker=Worker(os.environ['P7_VAULT_WORKER'],cls.g['worker_sha256'],
                          Path(str(cls.report_path)+'.artifacts/fixture-a.tx').read_bytes())
        cls.prover=Prover(os.environ['P7_VAULT_PROVER'],digest(Path(os.environ['P7_VAULT_PROVER']).read_bytes()),
                          expected_genesis=cls.rawg,worker=cls.worker)
        cls.controller=NoteController(os.environ['P7_NOTE_CONTROLLER'],digest(Path(os.environ['P7_NOTE_CONTROLLER']).read_bytes()),
                                      expected_genesis=cls.rawg,worker=cls.worker)
        request=subprocess.check_output([os.environ['P7_REQUEST_FIXTURE']],input=bytes.fromhex(cls.report['bootstrap_sha256']),timeout=30)
        cls.w=[request[1096+i*32:1128+i*32].hex() for i in range(31)]
        cls.opening={'agent_secret':cls.w[11],'value':integer(cls.w[24]),'expiry':integer(cls.w[26]),'note_secret':cls.w[27],'blind':cls.w[28]}
        debit=integer(cls.w[13])+integer(parse(cls.first)[17])
        cls.authority={'parent':[cls.w[0],numfield(integer(cls.w[1])+debit),numfield(integer(cls.w[2])+1),cls.w[4]],
                       'grant':[cls.w[5],numfield(integer(cls.w[6])+debit),numfield(integer(cls.w[7])+1),cls.w[9],cls.w[10],cls.w[12]]}
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='1soft-p7-vault-test-');self.directory=Path(self.temp.name)
        self.key=os.urandom(32);self.vid=os.urandom(32).hex();self.path=self.directory/'vault.json'
        self.journal=CertifiedTreasuryJournal(self.directory/'journal.sqlite',expected_genesis=self.rawg,worker=self.worker)
        self.ident=self.journal.retain(self.first)
        r=self.report['record'];self.journal.observe(r['witness'],r['signed_header'])
        self.vault=ChangeVault(self.path,key=self.key,expected_vault_id=self.vid,controller=self.controller,create=True)
        self.commitment=parse(self.first)[23]
    def tearDown(self):self.journal.close();self.temp.cleanup()
    def import_note(self):return self.vault.import_change(self.journal,self.ident,self.opening)
    def reopen(self,key=None,vid=None):return ChangeVault(self.path,key=key or self.key,expected_vault_id=vid or self.vid,controller=self.controller)
    def prepare(self,vault=None,**kw):
        args={'authority':self.authority,'amount':1,'valid_until':20,'request':numfield(9019)};args.update(kw)
        return (vault or self.vault).prepare_payment(self.journal,self.prover,self.commitment,**args)
    def test_authenticated_import_encryption_reopen_and_duplicate(self):
        self.assertTrue(self.import_note()==self.commitment)
        raw=self.path.read_bytes()
        for secret in (self.key,self.key.hex().encode(),bytes.fromhex(self.opening['note_secret']),self.opening['note_secret'].encode()):
            self.assertFalse(secret in raw,'runtime private material persisted in plaintext')
        self.assertTrue(self.reopen().inventory()==self.vault.inventory())
        self.assertEqual(self.path.stat().st_mode&0o777,0o600)
        with self.assertRaises(VaultError):self.import_note()
        self.assertTrue(self.path.read_bytes()==raw,'duplicate changed encrypted store')
    def test_wrong_key_id_ciphertext_and_header_refused(self):
        self.import_note();raw=self.path.read_bytes()
        with self.assertRaises(VaultError):self.reopen(key=os.urandom(32))
        with self.assertRaises(VaultError):self.reopen(vid=os.urandom(32).hex())
        for where in ('ciphertext','nonce','revision','profile'):
            value=json.loads(raw)
            if where=='ciphertext':value[where]=bytes([int(value[where][:2],16)^1]).hex()+value[where][2:]
            elif where=='nonce':value['header']['nonce']='00'*12
            elif where=='revision':value['header']['revision']+=1
            else:value['header']['profile_sha256']='00'*32
            self.path.write_bytes(canonical(value))
            with self.assertRaises((ValueError,RuntimeError)):self.reopen()
            self.path.write_bytes(raw)
        self.assertTrue(self.reopen().inventory()['notes']==[self.commitment])
    def test_unsafe_paths_modes_hardlinks_and_sidecars_refused(self):
        raw=self.path.read_bytes();alias=self.directory/'alias';os.link(self.path,alias)
        with self.assertRaises(VaultError):self.reopen()
        alias.unlink();self.path.chmod(0o644)
        with self.assertRaises(VaultError):self.reopen()
        self.path.chmod(0o600);self.path.unlink();self.path.symlink_to(self.directory/'other')
        with self.assertRaises(VaultError):self.reopen()
        self.path.unlink();self.path.write_bytes(raw);self.path.chmod(0o600)
        side=Path(str(self.path)+'-wal');side.write_bytes(b'')
        with self.assertRaises(VaultError):self.reopen()
        side.unlink();self.assertTrue(self.reopen().inventory()['revision']==0)
    def test_altered_openings_and_forged_origin_leave_store_unchanged(self):
        raw=self.path.read_bytes()
        for field in ('agent_secret','value','expiry','note_secret','blind','extra'):
            bad=copy.deepcopy(self.opening)
            bad[field]=True if field in ('value','expiry') else (numfield(321) if field!='extra' else 'unsupported')
            with self.assertRaises((ValueError,RuntimeError)):self.vault.import_change(self.journal,self.ident,bad)
            self.assertTrue(self.path.read_bytes()==raw,'refused import changed store')
        original=self.journal.recorded_receipt
        for field in ('raw','profile_sha256','genesis_sha256','certificate'):
            bad=copy.deepcopy(original(self.ident))
            if field=='raw':bad[field]=bad[field][:-2]+'ff'
            elif field=='certificate':bad[field]={}
            else:bad[field]='ab'*32
            with patch.object(self.journal,'recorded_receipt',return_value=bad):
                with self.assertRaises((ValueError,RuntimeError)):self.import_note()
            self.assertTrue(self.path.read_bytes()==raw)
    def test_nonce_reuse_and_publish_failure_preserve_original(self):
        raw=self.path.read_bytes();nonce=bytes.fromhex(json.loads(raw)['header']['nonce'])
        with patch('protocol7_vault.os.urandom',return_value=nonce):
            with self.assertRaises(VaultError):self.import_note()
        self.assertTrue(self.path.read_bytes()==raw)
        with patch('protocol7_vault.os.replace',side_effect=OSError('injected publication refusal')):
            with self.assertRaises(OSError):self.import_note()
        self.assertTrue(self.path.read_bytes()==raw)
        self.assertFalse(any(p.name.startswith('.vault.json.stage-') for p in self.directory.iterdir()))
        self.assertTrue(self.import_note()==self.commitment)
    def test_real_prove_retains_same_input_once_and_recovers_after_reopen(self):
        self.import_note();ident=self.prepare();wire=self.journal.export(ident)
        self.assertTrue(self.worker.verify(wire));self.assertEqual(integer(parse(wire)[17]),2)
        self.assertTrue(parse(wire)[20]==self.worker.note_root(self.report['record']['witness']['state']['treasury']['notes']))
        self.assertTrue(self.reopen().recover_prepared(self.journal,self.commitment)==ident)
        with self.assertRaises(VaultError):self.prepare(request=numfield(9020))
        with self.assertRaises(ValueError):self.vault.import_prepared_change(self.journal,ident)
        self.assertEqual(self.journal.status(ident)['attempts'],0)
    def test_durable_stage_unavailable_prover_and_explicit_later_commit(self):
        self.import_note();produce=self.prover.produce
        with patch.object(self.prover,'produce',side_effect=Unavailable('injected unavailable prover')):
            with self.assertRaises(Unavailable):self.prepare()
        vault=self.reopen();self.assertEqual(len(vault.inventory()['retained_preparations']),1)
        with self.assertRaises(VaultError):vault.recover_prepared(self.journal,self.commitment)
        with self.assertRaises(VaultError):self.prepare(vault=vault)
        with vault._locked():item=vault._read()['pending'][0]
        # Explicit caller re-evaluation of the original staged request only; the
        # vault recovery method itself never proves, retries or dispatches.
        ident=self.journal.prepare(self.prover,item['public'],item['witness'])
        self.assertTrue(vault.recover_prepared(self.journal,self.commitment)==ident)
        self.assertEqual(self.journal.status(ident)['attempts'],0)
    def test_local_return_lost_after_actual_journal_commit(self):
        self.import_note();prepare=self.journal.prepare
        def discard(*args):prepare(*args);raise TimeoutError('intentional local return loss')
        with patch.object(self.journal,'prepare',side_effect=discard):
            with self.assertRaises(TimeoutError):self.prepare()
        ident=self.reopen().recover_prepared(self.journal,self.commitment);wire=self.journal.export(ident)
        self.journal.close();self.journal=CertifiedTreasuryJournal(self.directory/'journal.sqlite',expected_genesis=self.rawg,worker=self.worker)
        self.assertTrue(self.reopen().recover_prepared(self.journal,self.commitment)==ident)
        self.assertTrue(self.journal.export(ident)==wire)
        with self.assertRaises(VaultError):self.prepare()
    def test_current_generation_epoch_spent_and_sequence_fault_boundaries(self):
        self.import_note();audit=self.journal._audit
        for field in ('generation','owner_epoch','nullifiers'):
            def changed():
                obs,rows=audit();obs=copy.deepcopy(obs);t=obs[-1]['witness']['state']['treasury']
                if field=='generation':t['grants'][0]['generation']+=1
                elif field=='owner_epoch':t['owner_epoch']+=1
                else:
                    record=self.vault._record(self.vault._read(),self.commitment)
                    p=parse(bytes.fromhex(record['origin']['raw']));d=self.controller.derive(p,self.opening,t['notes'],t['notes'].index(self.commitment));t['nullifiers'].append(d['nullifier'])
                return obs,rows
            # Explicit audited-state fault double, not a new quorum certificate.
            with patch.object(self.journal,'_audit',side_effect=changed):
                with self.assertRaises(VaultError):self.prepare()
        record=None
        with self.vault._locked():record=self.vault._record(self.vault._read(),self.commitment)
        def sequence_changed():
            obs,rows=audit();obs=copy.deepcopy(obs);obs[-1]['witness']['state']['treasury']['owner_sequence']+=1;return obs,rows
        with patch.object(self.journal,'_audit',side_effect=sequence_changed):
            with self.journal.atomic(False):
                _,t,_,_,_=self.vault._live(self.journal,record);self.assertEqual(t['owner_sequence'],1)
    def test_process_exit_after_encrypted_stage_before_journal_prepare(self):
        self.import_note()
        code='''import json,os,sys
from pathlib import Path
from protocol7_treasury import canonical,digest,numfield
from protocol7_worker import Worker
from protocol7_prover import Prover
from protocol7_notes import NoteController
from protocol7_vault import ChangeVault
from protocol7_wallet import CertifiedTreasuryJournal
v=json.loads(sys.stdin.buffer.read());r=json.loads(Path(v['report']).read_bytes());g=canonical(r['genesis'])
w=Worker(v['worker'],r['genesis']['worker_sha256'],Path(v['report']+'.artifacts/fixture-a.tx').read_bytes())
p=Prover(v['prover'],digest(Path(v['prover']).read_bytes()),expected_genesis=g,worker=w)
c=NoteController(v['controller'],digest(Path(v['controller']).read_bytes()),expected_genesis=g,worker=w)
j=CertifiedTreasuryJournal(v['journal'],expected_genesis=g,worker=w)
vault=ChangeVault(v['vault'],key=bytes.fromhex(v['key']),expected_vault_id=v['id'],controller=c)
j.prepare=lambda *args:os._exit(37)
vault.prepare_payment(j,p,v['commitment'],authority=v['authority'],amount=1,valid_until=20,request=numfield(9031))
'''
        payload={'report':str(self.report_path),'worker':os.environ['P7_VAULT_WORKER'],'prover':os.environ['P7_VAULT_PROVER'],
                 'controller':os.environ['P7_NOTE_CONTROLLER'],'journal':str(self.directory/'journal.sqlite'),'vault':str(self.path),
                 'key':self.key.hex(),'id':self.vid,'commitment':self.commitment,'authority':self.authority}
        r=subprocess.run([sys.executable,'-c',code],input=canonical(payload),stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                         env={'PYTHONPATH':str(Path(__file__).resolve().parents[1]/'src')},timeout=120)
        self.assertEqual(r.returncode,37,'stage-boundary child did not exit at expected boundary')
        self.assertFalse(r.stdout or r.stderr,'stage-boundary child emitted diagnostics')
        self.assertEqual(len(self.reopen().inventory()['retained_preparations']),1)
        with self.assertRaises(VaultError):self.reopen().recover_prepared(self.journal,self.commitment)

if __name__=='__main__':unittest.main()
