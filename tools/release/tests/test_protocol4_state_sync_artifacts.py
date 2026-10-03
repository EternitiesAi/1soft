"""Original private artifact membership, permissions and byte validation."""
from pathlib import Path
import tempfile
import unittest
from check_protocol4_state_sync import artifact_manifest,verify_private_artifacts

class Protocol4PrivateArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o700)
        self.log=self.root/'engine.log';self.log.write_bytes(b'original engine stdout\n');self.log.chmod(0o600)
    def tearDown(self):self.tmp.cleanup()
    def test_manifest_records_original_file_and_private_mode(self):
        record=artifact_manifest(self.root)
        self.assertEqual([r['path'] for r in record],['engine.log'])
        self.assertEqual(record[0]['mode'],'0600')
        self.assertEqual(record[0]['bytes'],23)
    def test_changed_original_bytes_refused(self):
        value={'artifacts':artifact_manifest(self.root),'logs':[]}
        self.log.write_bytes(b'changed')
        with self.assertRaises(ValueError):verify_private_artifacts(value,self.root)
    def test_extra_original_file_refused(self):
        value={'artifacts':artifact_manifest(self.root),'logs':[]}
        extra=self.root/'extra';extra.write_text('unlisted');extra.chmod(0o600)
        with self.assertRaises(ValueError):verify_private_artifacts(value,self.root)
    def test_symlink_or_public_private_fixture_refused(self):
        self.log.chmod(0o644)
        with self.assertRaises(ValueError):artifact_manifest(self.root)
        self.log.chmod(0o600);(self.root/'alias').symlink_to(self.log)
        with self.assertRaises(ValueError):artifact_manifest(self.root)

class Protocol4RetainedProofBindingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_protocol4_state_sync_gate import Protocol4GateSemanticTests
        Protocol4GateSemanticTests.setUpClass()
    def setUp(self):
        import copy,hashlib
        from test_protocol4_state_sync_gate import Protocol4GateSemanticTests
        from commit_verifier import encode
        case=Protocol4GateSemanticTests();case.setUp();self.value=copy.deepcopy(case.value)
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o700)
        def save(name,value):
            p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            p.write_bytes(encode(value));p.chmod(0o600)
        self.save=save
        v=self.value
        for i,node in enumerate(v['nodes']):
            home=self.root/'nodes'/('node'+str(i));(home/'config').mkdir(parents=True,mode=0o700)
            for filename in ('node_key.json','priv_validator_key.json'):
                p=home/'config'/filename;p.write_bytes(b'disposable fixture bytes');p.chmod(0o600)
            meta=home.stat()
            node.update(home_path=str(home),home_device=meta.st_dev,home_inode=meta.st_ino,
                node_key_sha256=hashlib.sha256((home/'config/node_key.json').read_bytes()).hexdigest(),
                validator_key_sha256=hashlib.sha256((home/'config/priv_validator_key.json').read_bytes()).hexdigest())
            save('node-'+str(i)+'-initial.json',node)
        restart=v['target_restart'];restart.update(identity_before=copy.deepcopy(v['nodes'][4]),
            identity_after=copy.deepcopy(v['nodes'][4]),home_before=v['nodes'][4]['home_path'],
            home_after=v['nodes'][4]['home_path'],database_before=str(self.root/'app4/state.sqlite'),
            database_after=str(self.root/'app4/state.sqlite'))
        (self.root/'app4').mkdir(mode=0o700);(self.root/'app4/state.sqlite').write_bytes(b'fixture DB inode')
        (self.root/'app4/state.sqlite').chmod(0o600);meta=(self.root/'app4/state.sqlite').stat()
        restart.update(database_device_before=meta.st_dev,database_device_after=meta.st_dev,
            database_inode_before=meta.st_ino,database_inode_after=meta.st_ino)
        save('node-4-ordinary-before.json',restart['identity_before'])
        save('node-4-ordinary-after.json',restart['identity_after'])
        for row in v['processes']:
            name=row['name'];i=int(name[6] if name.startswith('engine') else name[3])
            row['argv']=['/pinned/engine','start','--home',v['nodes'][i]['home_path']] if name.startswith('engine') else [
                '/python','/wrapper','--database',str(self.root/('app'+str(i))/'state.sqlite'),
                '--genesis',str(self.root/'protocol4-genesis.json')]
            row['spawned_at_ns']=v['trust_pin']['target_started_at_ns'] if name=='app4' else v['trust_pin']['pinned_at_ns']-1
            save('process-'+name+'-started.json',{k:row[k] for k in ('name','pid','birth','role','argv','spawned_at_ns')})
            save('process-'+name+'-exit.json',row)
        v['logs']=[{'name':r['name']+'.log'} for r in v['processes']]
        save('trust-pin.json',{k:x for k,x in v['trust_pin'].items() if k!='target_started_at_ns'})
        save('pre-target-evidence.json',v['trust_pin']['pre_target']['evidence'])
        save('read-policy.json',v['trust_pin']['policy'])
        save('control4/checkpoint-normal.json',v['install'])
        raw=(self.root/'control4/checkpoint-normal.json').read_bytes()
        save('control4/installed.json',{'record_file':'checkpoint-normal.json','record_sha256':hashlib.sha256(raw).hexdigest()})
    def tearDown(self):self.tmp.cleanup()
    def validate(self):
        from check_protocol4_state_sync import verify_retained_proofs
        return verify_retained_proofs(self.value,self.root)
    def test_original_process_and_filesystem_receipts_are_bound(self):
        self.assertTrue(self.validate())
    def test_report_pid_substitution_cannot_hide_behind_unchanged_manifest(self):
        self.value['processes'][0]['pid']=555
        with self.assertRaises(ValueError):self.validate()
    def test_rewritten_retained_exit_cannot_substitute_actual_outcome(self):
        import copy
        row=copy.deepcopy(self.value['processes'][0]);row['returncode']=7
        self.save('process-engine0-exit.json',row)
        with self.assertRaises(ValueError):self.validate()
    def test_source_engine_home_command_substitution_refused(self):
        row=self.value['processes'][0];row['argv'][-1]=self.value['nodes'][1]['home_path']
        self.save('process-engine0-started.json',{k:row[k] for k in ('name','pid','birth','role','argv','spawned_at_ns')})
        self.save('process-engine0-exit.json',row)
        with self.assertRaises(ValueError):self.validate()
    def test_changed_key_bytes_or_replaced_database_inode_refused(self):
        (self.root/'nodes/node4/config/node_key.json').write_bytes(b'changed key bytes')
        with self.assertRaises(ValueError):self.validate()
    def test_actual_target_start_cannot_be_relabelled_after_launch(self):
        self.value['trust_pin']['target_started_at_ns']+=1
        with self.assertRaises(ValueError):self.validate()
