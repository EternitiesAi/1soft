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
        from serve_abci_state_sync_crash import write_event
        write_event(self.root/'control4','installed.json',{'record_file':'checkpoint-normal.json',
                    'record_sha256':hashlib.sha256(raw).hexdigest()})
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

    def real_installed_event(self):
        from commit_verifier import load_json
        from serve_abci_state_sync_crash import write_event
        control=self.root/'control4';path=control/'installed.json'
        item=load_json(path.read_bytes());path.unlink()
        write_event(control,'installed.json',item)
        return path
    def test_actual_shared_event_writer_bytes_verify_through_retained_checker(self):
        path=self.real_installed_event()
        self.assertTrue(path.read_bytes().endswith(b'\n'))
        self.assertTrue(self.validate())
    def test_event_without_writer_final_newline_is_refused(self):
        path=self.real_installed_event();path.write_bytes(path.read_bytes()[:-1])
        with self.assertRaises(ValueError):self.validate()
    def test_event_optional_whitespace_and_altered_values_are_refused(self):
        import json
        for mutation in ('extra-newline','leading-space','pretty','altered-checkpoint'):
            self.tearDown();self.setUp();path=self.real_installed_event();raw=path.read_bytes()
            if mutation=='extra-newline':path.write_bytes(raw+b'\n')
            elif mutation=='leading-space':path.write_bytes(b' '+raw)
            elif mutation=='pretty':path.write_bytes(json.dumps(json.loads(raw),indent=2).encode()+b'\n')
            else:
                item=json.loads(raw);item['record_sha256']='0'*64
                path.write_bytes(json.dumps(item,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n')
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.validate()
    def test_financial_and_checkpoint_json_do_not_accept_event_newline_codec(self):
        for filename in ('trust-pin.json','pre-target-evidence.json','process-engine0-started.json','control4/checkpoint-normal.json'):
            self.tearDown();self.setUp();path=self.root/filename;path.write_bytes(path.read_bytes()+b'\n')
            if filename.startswith('control4'):
                # Rebind the event digest to the changed bytes; strict financial
                # codec must still refuse, rather than just detect hash tampering.
                import hashlib,json
                from serve_abci_state_sync_crash import write_event
                event=self.root/'control4/installed.json';item=json.loads(event.read_bytes());event.unlink()
                item['record_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
                write_event(event.parent,event.name,item)
            with self.subTest(filename=filename),self.assertRaisesRegex(ValueError,'noncanonical original receipt: '+filename):self.validate()

class Protocol4OriginalCodecTests(unittest.TestCase):
    def test_all_identified_event_receipts_use_exact_actual_writer_bytes(self):
        from serve_abci_state_sync_crash import write_event
        from check_protocol4_state_sync import EVENT_RECEIPTS,retained_json
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);root.chmod(0o700);(root/'control4').mkdir(mode=0o700)
            for name in sorted(EVENT_RECEIPTS):
                value={'schema':1,'pid':123,'birth':'456','run_id':'a'*32}
                if 'ready' in name:
                    value.update(device=1,inode=12,database='/private/state.sqlite',socket='/private/a.sock')
                elif 'exit' in name or 'killed' in name:
                    value.update(returncode=-9 if 'killed' in name else 0,stop_requested=True,
                        termination_signal=9 if 'killed' in name else 15,rescue_used=False,cleanup_error=None)
                else:value.update(record_file='checkpoint-normal.json',record_sha256='b'*64)
                write_event(root/'control4',Path(name).name,value)
                self.assertEqual(retained_json(root,name),value)
    def test_unknown_event_location_is_not_given_newline_exception(self):
        from serve_abci_state_sync_crash import write_event
        from check_protocol4_state_sync import retained_json
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);root.chmod(0o700);(root/'control3').mkdir(mode=0o700)
            write_event(root/'control3','installed.json',{'schema':1})
            with self.assertRaises(ValueError):retained_json(root,'control3/installed.json')
    def test_event_duplicate_json_fields_do_not_become_canonical(self):
        from check_protocol4_state_sync import retained_json
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'control4').mkdir()
            (root/'control4/installed.json').write_bytes(b'{"pid":1,"pid":1}\n')
            with self.assertRaises(ValueError):retained_json(root,'control4/installed.json')

    def test_unknown_event_name_keeps_generic_canonical_codec(self):
        from serve_abci_state_sync_crash import write_event
        from check_protocol4_state_sync import retained_json
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);root.chmod(0o700);(root/'control4').mkdir(mode=0o700)
            write_event(root/'control4','unexpected.json',{'schema':1})
            with self.assertRaises(ValueError):retained_json(root,'control4/unexpected.json')
    def test_nonobject_and_oversized_event_bytes_are_refused(self):
        from serve_abci_state_sync_crash import write_event
        from check_protocol4_state_sync import retained_json
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);root.chmod(0o700);control=root/'control4';control.mkdir(mode=0o700)
            write_event(control,'installed.json',['not-an-object'])
            with self.assertRaises(ValueError):retained_json(root,'control4/installed.json')
            write_event(control,'recovered.json',{'schema':1})
            path=control/'recovered.json';path.write_bytes(path.read_bytes()+b' '*4096)
            with self.assertRaises(ValueError):retained_json(root,'control4/recovered.json')
    def test_reordered_compact_event_body_is_refused(self):
        import json
        from serve_abci_state_sync_crash import write_event
        from check_protocol4_state_sync import retained_json
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);root.chmod(0o700);control=root/'control4';control.mkdir(mode=0o700)
            write_event(control,'installed.json',{'schema':1,'pid':123})
            (control/'installed.json').write_bytes(json.dumps({'schema':1,'pid':123},
                separators=(',',':'),sort_keys=False).encode()+b'\n')
            with self.assertRaises(ValueError):retained_json(root,'control4/installed.json')


class Protocol4RetainedControlledExitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_protocol4_state_sync_gate import Protocol4ControlledExitSemanticTests
        Protocol4ControlledExitSemanticTests.setUpClass()
    def setUp(self):
        import copy,hashlib
        from commit_verifier import encode
        from test_protocol4_state_sync_gate import Protocol4ControlledExitSemanticTests
        from serve_abci_state_sync_crash import write_event
        case=Protocol4ControlledExitSemanticTests();case.setUp()
        self.row=case.controlled();self.value=case.value
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o700)
        control=self.root/'control4';control.mkdir(mode=0o700)
        # Real shared writer, with the kill's original install-event metadata.
        installed={'record_file':'checkpoint-pause.json','record_sha256':'c'*64}
        write_event(control,'installed.json',installed)
        killed=copy.deepcopy(self.value['crash']['killed']);killed['install']=installed
        write_event(control,'killed.json',killed)
        self.row['causal_exit']['event_sha256']=hashlib.sha256((control/'killed.json').read_bytes()).hexdigest()
        raw=self.value['engine_sync']['original_logs']['engine4'].encode()
        (self.root/'engine4.log').write_bytes(raw);(self.root/'engine4.log').chmod(0o600)
    def tearDown(self):self.tmp.cleanup()
    def validate(self):
        from check_protocol4_state_sync import verify_retained_controlled_engine_exit
        return verify_retained_controlled_engine_exit(self.value,self.row,self.root)
    def rewrite_kill(self,mutation):
        import hashlib,json
        from serve_abci_state_sync_crash import write_event
        path=self.root/'control4/killed.json';item=json.loads(path.read_bytes());path.unlink()
        mutation(item);write_event(path.parent,path.name,item)
        self.row['causal_exit']['event_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
    def test_actual_event_writer_and_original_log_bind_to_cause(self):
        self.assertTrue(self.validate())
    def test_rebound_original_kill_cannot_substitute_child_identity(self):
        self.rewrite_kill(lambda item:item.update(pid=999))
        with self.assertRaises(ValueError):self.validate()
    def test_kill_install_metadata_must_equal_original_install_event(self):
        self.rewrite_kill(lambda item:item['install'].update(record_sha256='d'*64))
        with self.assertRaises(ValueError):self.validate()
    def test_kill_codec_remains_exact_even_after_cause_digest_rebound(self):
        import hashlib
        path=self.root/'control4/killed.json';path.write_bytes(path.read_bytes().rstrip(b'\n'))
        self.row['causal_exit']['event_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):self.validate()
    def test_rebound_original_log_cannot_replace_reported_engine_diagnostic(self):
        import hashlib
        path=self.root/'engine4.log';path.write_bytes(b'unrelated engine stdout\n')
        self.row['causal_exit']['log_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):self.validate()
