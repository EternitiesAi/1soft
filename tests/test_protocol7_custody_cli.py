"""One-shot command privacy/refusal tests, and supplied actual-origin caller composition."""
import importlib.util,json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from protocol7_treasury import canonical,digest,numfield,Unavailable
ROOT=Path(os.environ.get('P7_CUSTODY_SOURCE_ROOT',Path(__file__).resolve().parents[1]))
CLI=Path(os.environ.get('P7_CUSTODY_CLI',ROOT/'scripts/owner_treasury_custody.py'))
BASE=['--journal','/missing/journal','--vault','/missing/vault','--genesis','/missing/genesis',
      '--worker','/missing/worker','--kat','/missing/kat','--controller','/missing/controller',
      '--genesis-sha256','ab'*32,'--worker-sha256','ab'*32,'--controller-sha256','ab'*32,'--vault-id','ab'*32]
KEY='13'*32 # explicit public nonproduction parsing/fault fixture

class InputPrivacyTests(unittest.TestCase):
    def run_cli(self,args,raw):
        return subprocess.run([sys.executable,'-B',str(CLI),*args],input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
              env={'PYTHONPATH':str(ROOT/'src')+':'+str(ROOT/'scripts')},timeout=30)
    def test_actual_closed_input_size_canonical_keys_and_argument_refusals_without_echo(self):
        requests=[b'private diagnostic sentinel',b'x'*8193,b'{"key":"'+KEY.encode()+b'","key":"'+KEY.encode()+b'"}',
                  json.dumps({'key':KEY}).encode(),canonical({'key':KEY,'unexpected':'private diagnostic sentinel'}),
                  canonical({'key':False}),canonical({'key':KEY})]
        for raw in requests:
            with self.subTest(case=len(raw)):
                r=self.run_cli([*BASE,'inventory'],raw);self.assertEqual(r.returncode,1)
                self.assertFalse(r.stderr,'private CLI failure emitted stderr')
                response=json.loads(r.stdout);self.assertTrue(response['status']=='command-refused')
                self.assertFalse(KEY.encode() in r.stdout or b'private diagnostic sentinel' in r.stdout,'private input echoed')
        r=self.run_cli([*BASE,'inventory','--key','private diagnostic sentinel'],canonical({'key':KEY}))
        self.assertEqual(r.returncode,1);self.assertFalse(r.stderr or b'private diagnostic sentinel' in r.stdout)

    def test_wrapper_post_entry_fault_is_unknown_and_static(self):
        spec=importlib.util.spec_from_file_location('custody_cli_fault',CLI);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        class Args:
            execution_receipt=False
            operation='prepare';prover=Path('/public/prover');prover_sha256='ab'*32
            journal=Path('/public/journal');vault=Path('/public/vault');genesis=Path('/public/genesis')
            worker=Path('/public/worker');kat=Path('/public/kat');controller=Path('/public/controller')
            genesis_sha256='ab'*32;worker_sha256='ab'*32;controller_sha256='ab'*32;vault_id='ab'*32
        class Journal:
            def __enter__(self):return self
            def __exit__(self,*_):pass
        class Vault:
            def prepare_payment(self,*_,**kw):raise OSError('private diagnostic sentinel '+KEY)
        from io import BytesIO
        class Stream:
            def __init__(self,raw=b''):self.buffer=BytesIO(raw)
            def isatty(self):return False
        private=canonical({'key':KEY,'commitment':numfield(5),'authority':{},'amount':1,'valid_until':20,'request':numfield(9019)})
        output=Stream();fake_stat=type('S',(),{'st_mode':0o100600,'st_uid':os.geteuid(),'st_nlink':1})()
        # Explicit wrapper fault doubles. Actual persistence/lost-return/process
        # boundaries are exercised by the supplied-origin vault tests.
        with patch.object(m,'arguments',return_value=Args()),patch.object(m.sys,'stdin',Stream(private)),patch.object(m.sys,'stdout',output),\
             patch.object(m,'read_input',return_value=b'public'),patch.object(m,'digest',return_value='ab'*32),\
             patch.object(m,'genesis_shape',return_value={'worker_sha256':'ab'*32}),patch.object(Path,'lstat',return_value=fake_stat),\
             patch.object(m,'Worker'),patch.object(m,'NoteController'),patch.object(m,'CertifiedTreasuryJournal',return_value=Journal()),\
             patch.object(m,'ChangeVault',return_value=Vault()),patch.object(m,'Prover'):
            code=m.main([])
        self.assertEqual(code,1);raw=output.buffer.getvalue();v=json.loads(raw)
        self.assertTrue(v['status']=='prepare-not-returned' and v['failure_class']=='unknown' and v['reconcile_required'] is True)
        self.assertFalse(KEY.encode() in raw or b'private diagnostic sentinel' in raw,'fault diagnostic exposed private content')

    def test_actual_sigterm_during_private_input_is_static_unavailable(self):
        p=subprocess.Popen([sys.executable,'-B',str(CLI),*BASE,'inventory'],stdin=subprocess.PIPE,
             stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PYTHONPATH':str(ROOT/'src')+':'+str(ROOT/'scripts')})
        try:
            p.stdin.write(b'{"key":"'+KEY.encode());p.stdin.flush()
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                channel=Path('/proc/'+str(p.pid)+'/wchan')
                if channel.exists() and 'pipe_read' in channel.read_text():break
                time.sleep(.05)
            else:self.fail('actual CLI did not reach protected input read')
            p.terminate();out,err=p.communicate(timeout=10)
            self.assertEqual(p.returncode,1);self.assertFalse(err or KEY.encode() in out)
            v=json.loads(out);self.assertTrue(v['failure_class']=='unavailable' and v['reconcile_required'] is False)
        finally:
            if p.poll() is None:p.kill();p.communicate()

@unittest.skipUnless(all(os.environ.get(k) for k in ('P7_VAULT_ORIGIN','P7_VAULT_WORKER','P7_VAULT_PROVER','P7_NOTE_CONTROLLER','P7_REQUEST_FIXTURE')),
                     'unassessed: actual certified origin/binaries not supplied')
class ActualCallerTests(unittest.TestCase):
    def test_actual_create_import_inventory_prepare_recover_and_uncertified_import_refusal(self):
        from test_protocol7_vault import VaultTests
        from protocol7_wallet import CertifiedTreasuryJournal
        VaultTests.setUpClass();v=VaultTests
        with tempfile.TemporaryDirectory(prefix='1soft-p7-cli-') as td:
            directory=Path(td);genesis=directory/'genesis.json';genesis.write_bytes(v.rawg)
            kat=directory/'kat.tx';kat.write_bytes(Path(str(v.report_path)+'.artifacts/fixture-a.tx').read_bytes())
            journal=directory/'journal.sqlite';vault=directory/'vault.json';key=os.urandom(32).hex();vid=os.urandom(32).hex()
            with CertifiedTreasuryJournal(journal,expected_genesis=v.rawg,worker=v.worker) as j:
                ident=j.retain(v.first);r=v.report['record'];j.observe(r['witness'],r['signed_header'])
            common=['--journal',str(journal),'--vault',str(vault),'--genesis',str(genesis),'--worker',os.environ['P7_VAULT_WORKER'],
                    '--kat',str(kat),'--controller',os.environ['P7_NOTE_CONTROLLER'],'--genesis-sha256',digest(v.rawg),
                    '--worker-sha256',v.g['worker_sha256'],'--controller-sha256',v.controller.sha256,'--vault-id',vid]
            def call(op,data,success=True):
                flags=[*common]
                if op=='prepare':flags+=['--prover',os.environ['P7_VAULT_PROVER'],'--prover-sha256',v.prover.sha256]
                p=subprocess.run([sys.executable,'-B',str(CLI),*flags,op],input=canonical({'key':key,**data}),
                   stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PYTHONPATH':str(ROOT/'src')+':'+str(ROOT/'scripts')},timeout=180)
                self.assertEqual(p.returncode,0 if success else 1,'actual custody CLI returned unexpected status')
                self.assertFalse(p.stderr,'actual custody CLI emitted diagnostics')
                self.assertFalse(key.encode() in p.stdout or v.opening['note_secret'].encode() in p.stdout,'actual private material echoed')
                return json.loads(p.stdout)
            created=call('create',{});self.assertEqual(created['result']['revision'],0)
            imported=call('import-change',{'txid':ident,'opening':v.opening});commitment=imported['result']['commitment']
            inventory=call('inventory',{});self.assertTrue(inventory['result']['notes']==[commitment])
            prepared=call('prepare',{'commitment':commitment,'authority':v.authority,'amount':1,'valid_until':20,'request':numfield(9037)})
            second=prepared['result']['txid'];self.assertEqual(prepared['result']['attempts'],0)
            recovered=call('recover-prepared',{'commitment':commitment});self.assertTrue(recovered['result']['txid']==second)
            self.assertTrue(recovered['result']['raw_sha256']==prepared['result']['raw_sha256'])
            failed=call('import-prepared',{'txid':second},False);self.assertTrue(failed['status']=='command-refused')
            with CertifiedTreasuryJournal(journal,expected_genesis=v.rawg,worker=v.worker) as j:
                self.assertEqual(j.status(second)['attempts'],0);self.assertTrue(v.worker.verify(j.export(second)))

if __name__=='__main__':unittest.main()
