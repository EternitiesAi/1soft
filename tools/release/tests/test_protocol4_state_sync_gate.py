"""Refusal behavior for the P4 gate; no engine or network substitutes."""
import copy
import json
import unittest
from check_protocol4_state_sync import CHECK_IDS, validate_envelope

def envelope():
    source = {'commit': 'a'*40, 'tree': 'b'*40, 'source_id': 'c'*64,
              'files': [{'path': 'scripts/run_protocol4_state_sync.py',
                         'mode': '100644', 'sha256': 'd'*64}]}
    process = {'returncode':0,'timed_out':False,'log_truncated':False,'cleanup_complete':True,
               'rescue_actions':[],'cleanup_errors':[],'owned_survivors':[],'owned_survivor_count':0,
               'pid':999,'birth':'999','alive_after':False}
    value = {'schema': '1soft-protocol4-state-sync-v1', 'status': 'completed-awaiting-external-validation',
             'profile': 'basic', 'source': copy.deepcopy(source),
             'source_dirty_before': False, 'source_dirty_after': False,
             'engine_version': '0.38.25', 'engine_sha256': 'e'*64,
             'public_network': False, 'real_funds': False,
             'checks': [{'id': x, 'passed': True} for x in CHECK_IDS],
             'snapshot_evidence': {}, 'final_evidence': {}, 'snapshot_transfer': {},
             'payments': {}, 'target_restart': {}, 'install': {}, 'trust_pin': {},
             'processes': [], 'logs': []}
    return value, source, process

class Protocol4GateEnvelopeTests(unittest.TestCase):
    def validate(self, value, source, process):
        return validate_envelope(value, 'basic', source, 'e'*64, process)

    def test_complete_envelope_reaches_semantic_validation(self):
        value, source, process = envelope()
        self.assertEqual(self.validate(value, source, process), list(CHECK_IDS))

    def test_zero_or_missing_checks_refused(self):
        for checks in ([], None):
            value, source, process = envelope(); value['checks'] = checks
            with self.subTest(checks=checks), self.assertRaises(ValueError):
                self.validate(value, source, process)

    def test_missing_duplicate_or_extra_check_id_refused(self):
        for mutation in ('missing', 'duplicate', 'extra'):
            value, source, process = envelope()
            if mutation == 'missing': value['checks'].pop()
            elif mutation == 'duplicate': value['checks'].append(copy.deepcopy(value['checks'][0]))
            else: value['checks'].append({'id':'invented-success', 'passed':True})
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.validate(value, source, process)

    def test_false_skipped_or_truthy_check_refused(self):
        for passed in (False, 'true', 1, None):
            value, source, process = envelope(); value['checks'][0]['passed'] = passed
            with self.subTest(passed=passed), self.assertRaises(ValueError):
                self.validate(value, source, process)

    def test_runtime_failure_timeout_or_truncation_refused(self):
        for key, replacement in (('returncode',1),('returncode',False),
                                 ('timed_out',True),('log_truncated',True)):
            value, source, process = envelope(); process[key] = replacement
            with self.subTest(key=key,replacement=replacement), self.assertRaises(ValueError):
                self.validate(value, source, process)

    def test_failed_unassessed_or_partial_report_refused(self):
        for status in ('failed','unassessed','partial'):
            value, source, process = envelope(); value['status'] = status
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.validate(value, source, process)

    def test_dirty_changed_or_missing_source_refused(self):
        for mutation in ('before','after','tree','mode','missing'):
            value, source, process = envelope()
            if mutation in ('before','after'): value['source_dirty_'+mutation] = True
            elif mutation == 'tree': value['source']['tree'] = '0'*40
            elif mutation == 'mode': value['source']['files'][0]['mode'] = '100755'
            else: value.pop('source')
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.validate(value, source, process)

    def test_missing_original_private_evidence_refused(self):
        for name in ('snapshot_evidence','final_evidence','snapshot_transfer','payments',
                     'target_restart','install','trust_pin','processes','logs'):
            value, source, process = envelope(); value.pop(name)
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.validate(value, source, process)

    def test_wrong_engine_or_unsafe_scope_refused(self):
        for key, replacement in (('engine_sha256','0'*64),('engine_version','0.38.24'),
                                 ('public_network',True),('real_funds',True),('profile','legacy')):
            value, source, process = envelope(); value[key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(value, source, process)

    def test_outer_cleanup_rescue_survivors_missing_or_bad_types_refused(self):
        for key,replacement in (('cleanup_complete',False),('rescue_actions',[{'signal':9}]),
                ('cleanup_errors',['disk fault']),('owned_survivors',[1]),('owned_survivor_count',True),
                ('alive_after',True),('pid',True),('birth','')):
            value,source,process=envelope();process[key]=replacement
            with self.subTest(key=key),self.assertRaises(ValueError):self.validate(value,source,process)
        value,source,process=envelope();process.pop('cleanup_complete')
        with self.assertRaises(ValueError):self.validate(value,source,process)



class Protocol4GateSemanticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from p4_fixture import build, bundle
        cls.case = build(8)
        cls.case['now_ns'] -= 500*10**9
        cls.bundle = staticmethod(bundle)

    def setUp(self):
        import base64
        import hashlib
        from commit_verifier import encode
        from protocol4_state_sync import _hash, _metadata
        from p4_evidence import verify_evidence
        self.value, self.source, self.process = envelope()
        c = self.case; snapshot = self.bundle(c,4); final = self.bundle(c,8)
        s = snapshot['state']; composite = {'native':s['native'],'registry':s['registry']}
        raw = encode({'schema':2,'domain':'1soft/protocol4/composite-state-sync/v1',
            'genesis':s['genesis'],'height':4,'app_hash':s['app_hash'],
            'state':composite,'history':snapshot['history']})
        self.value.update(snapshot_evidence=snapshot,final_evidence=final,
            source_final_state=copy.deepcopy(final['state']),target_final_state=copy.deepcopy(final['state']),
            source_final_history=copy.deepcopy(final['history']),target_final_history=copy.deepcopy(final['history']),
            first_target_block=5,snapshot_response_code=1,final_marker=None,
            payments={k:base64.b64encode(c['wires'][w]).decode() for k,w in [('pre','before'),('post','after')]},
            trust_pin={'policy':copy.deepcopy(c['policy']),
                'engine_genesis_sha256':hashlib.sha256(c['genesis']).hexdigest(),
                'native_genesis_sha256':hashlib.sha256(encode(c['g'])).hexdigest(),
                'pinned_at_ns':1,'target_started_at_ns':2,'target_never_started':True},
            snapshot_transfer={'format':2,'height':4,'offered_app_hash':s['app_hash'],
                'hash':_hash(raw).hex(),'metadata':base64.b64encode(_metadata(c['g'],4,s['app_hash'],len(raw),1)).decode(),
                'chunks':[base64.b64encode(raw).decode()],
                'methods':['list_snapshots','offer_snapshot','load_snapshot_chunk','apply_snapshot_chunk']},
            install={'height':4,'app_hash':s['app_hash'],'state':composite,
                     'history':snapshot['history'],'marker':{'height':4,'app_hash':s['app_hash']},
                     'block_rows':0,'transaction_active':False},
            target_restart={'database_before':'/private/a.db','database_after':'/private/a.db',
                'home_before':'/private/home','home_after':'/private/home',
                'before':copy.deepcopy(final['state']),'after':copy.deepcopy(final['state']),
                'old_pid':10,'new_pid':11,'evidence':copy.deepcopy(final)},
            processes=[{'pid':i,'birth':str(i),'alive_after':False,'returncode':0} for i in range(1,11)],
            logs=[{'bytes':100,'truncated':False,'sha256':'a'*64,'complete':True,'closed':True,'fsynced':True,'capture_error':None}])
        # Real ABCI dispatcher traffic supplies the test's transfer trace.
        from protocol4_application import Protocol4Application
        from protocol4_abci_wire import Request
        from protocol4_abci_server import dispatch
        source = Protocol4Application(':memory:',expected_genesis=c['g'])
        target = Protocol4Application(':memory:',expected_genesis=c['g'])
        source.genesis=c['g'];source.state=composite;source.height=4;source.app_hash=s['app_hash']
        for row in snapshot['history']:
            source.db.execute('INSERT INTO history VALUES (?,?)',(row['height'],encode(row['txs']).decode()))
        trace=[]
        def call(app,req):
            ans=dispatch(app,req)
            trace.append({'request':base64.b64encode(req.SerializeToString(deterministic=True)).decode(),
                          'response':base64.b64encode(ans.SerializeToString(deterministic=True)).decode()})
            return ans
        try:
            req=Request();req.list_snapshots.SetInParent();desc=call(source,req).list_snapshots.snapshots[0]
            req=Request();req.offer_snapshot.snapshot.CopyFrom(desc);req.offer_snapshot.app_hash=bytes.fromhex(s['app_hash'])
            call(target,req)
            req=Request();req.load_snapshot_chunk.height=4;req.load_snapshot_chunk.format=2;req.load_snapshot_chunk.chunk=0
            chunk=call(source,req).load_snapshot_chunk.chunk
            req=Request();req.apply_snapshot_chunk.index=0;req.apply_snapshot_chunk.chunk=chunk;req.apply_snapshot_chunk.sender='unit'
            call(target,req)
        finally:source.close();target.close()
        self.value['snapshot_transfer']['trace']=trace
        self.value['unavailable_responses']=[{'height':h,'code':1,'log':'protocol-4 response unavailable'}
                                             for h in range(1,5)]
        self.value['evidence_origin']={'state':'target-ABCI-query',
            'headers':'source-engine-RPC','history':'source-blocks-with-target-durable-equality'}
        self.value['engine_sync']={'original_log':'Snapshot restored\nVerified ABCI app\n'}
        gengine=json.loads(c['genesis'])
        nodes=[]
        for i in range(5):
            pk=base64.b64decode(gengine['validators'][i]['pub_key']['value']).hex() if i<4 else 'f'*64
            nodes.append({'index':i,'node_id':format(i+1,'040x'),'validator_public_key':pk,
                'home_path':'/private/nodes/node'+str(i),'home_device':1,'home_inode':84+i,
                'node_key_sha256':format(i+1,'064x'),'validator_key_sha256':format(i+6,'064x')})
        self.value['nodes']=nodes
        names=['engine'+str(i) for i in range(5)]+['app'+str(i) for i in range(5)]+['app4-restart','engine4-restart']
        self.value['processes']=[{'name':name,'role':'engine' if name.startswith('engine') else 'app',
            'pid':i+1,'birth':str(i+1),'returncode':0,'alive_after':False,
            'stop_requested':True,'termination_signal':15,'rescue_used':False,'cleanup_error':None}
            for i,name in enumerate(names)]
        self.value['service_cleanup']={'complete':True,'rescue_actions':[],'errors':[],'owned_survivors':[]}
        trust=self.value['trust_pin']
        trust.update(pinned_at_ns=c['now_ns']-1,target_started_at_ns=c['now_ns'],
            source_pids=[1,2,3,4],sources=[{'index':i,'engine_pid':i+1,'engine_birth':str(i+1),
                'app_pid':i+6,'app_birth':str(i+6),'observed_height':3} for i in range(4)],
            pre_target={'evidence':self.bundle(c,2),'checked_at_ns':c['now_ns']-2},
            target_initial_inventory=['config/config.toml','config/genesis.json','config/node_key.json',
                                      'config/priv_validator_key.json','data/priv_validator_state.json'])
        restart=self.value['target_restart'];restart.update(old_birth='10',new_birth='11',
            identity_before=copy.deepcopy(nodes[4]),identity_after=copy.deepcopy(nodes[4]),
            database_device_before=1,database_device_after=1,database_inode_before=99,database_inode_after=99,
            database_before='/private/app4/state.sqlite',database_after='/private/app4/state.sqlite',
            home_before=nodes[4]['home_path'],home_after=nodes[4]['home_path'])



    def validate(self):
        from check_protocol4_state_sync import validate_result
        return validate_result(self.value,'basic',self.source,'e'*64,self.process,
                               self.case['genesis'],self.case['policy'],now_ns=self.case['now_ns'])

    def test_original_quorum_signed_execution_and_actual_abci_trace_verify(self):
        report=self.validate()
        self.assertEqual(report['snapshot_height'],4);self.assertEqual(report['final_height'],8)
        self.assertEqual(report['signed_payments'],2)

    def test_method_names_without_original_abci_wire_refused(self):
        self.value['snapshot_transfer'].pop('trace')
        with self.assertRaises(ValueError):self.validate()

    def test_final_apply_reply_corruption_refused(self):
        from protocol4_abci_wire import Response
        import base64
        reply=Response();reply.apply_snapshot_chunk.result=4
        self.value['snapshot_transfer']['trace'][-1]['response']=base64.b64encode(reply.SerializeToString()).decode()
        with self.assertRaises(ValueError):self.validate()

    def test_forged_final_header_signature_refused(self):
        self.value['final_evidence']['headers'][-1]['signed_header']['commit']['signatures'][0]['signature']='AA=='
        with self.assertRaises(ValueError):self.validate()

    def test_changed_native_balance_despite_passed_checks_refused(self):
        self.value['final_evidence']['state']['native']['accounts'][0][4]+=1
        with self.assertRaises(ValueError):self.validate()

    def test_changed_snapshot_history_despite_matching_claims_refused(self):
        self.value['snapshot_evidence']['history'][0]['txs'].pop()
        with self.assertRaises(ValueError):self.validate()

    def test_reusing_presnapshot_signed_wire_as_post_payment_refused(self):
        self.value['payments']['post']=self.value['payments']['pre']
        with self.assertRaises(ValueError):self.validate()

    def test_fake_snapshot_height_block_response_refused(self):
        self.value['snapshot_response_code']=0
        with self.assertRaises(ValueError):self.validate()

    def test_target_history_substitution_refused(self):
        self.value['target_final_history'][0]['txs']=[]
        with self.assertRaises(ValueError):self.validate()

    def test_target_launch_before_trust_pin_refused(self):
        self.value['trust_pin']['target_started_at_ns']=0
        with self.assertRaises(ValueError):self.validate()


    def test_same_restart_checkpoint_then_later_current_state_is_authenticated(self):
        restart_state=copy.deepcopy(self.case['states'][7])
        self.value['target_restart']['before']=restart_state
        self.value['target_restart']['after']=copy.deepcopy(restart_state)
        self.value['target_restart']['evidence']=self.bundle(self.case,7)
        try: report=self.validate()
        except ValueError as exc:self.fail('later authenticated state must preserve the restart checkpoint: '+str(exc))
        self.assertEqual(report['final_height'],8)


    def test_generic_query_error_does_not_prove_unavailable_snapshot_history(self):
        self.value['unavailable_responses'][0]['log']='unknown protocol-4 query path'
        with self.assertRaises(ValueError):self.validate()

    def test_partial_unavailable_history_refused(self):
        self.value['unavailable_responses'].pop()
        with self.assertRaises(ValueError):self.validate()

    def test_missing_mixed_evidence_origin_refused(self):
        self.value.pop('evidence_origin')
        with self.assertRaises(ValueError):self.validate()

    def test_stale_current_checkpoint_under_still_valid_trust_refused(self):
        from check_protocol4_state_sync import validate_result
        with self.assertRaises(ValueError):
            validate_result(self.value,'basic',self.source,'e'*64,self.process,
                self.case['genesis'],self.case['policy'],now_ns=self.case['now_ns']+400*10**9)

    def test_offer_alone_without_successful_engine_verification_refused(self):
        self.value['engine_sync']['original_log']='Received snapshot; starting restore'
        with self.assertRaises(ValueError):self.validate()


    def test_unexpected_nonzero_engine_exit_refused(self):
        self.value['processes'][0]['returncode']=1
        with self.assertRaises(ValueError):self.validate()
    def test_service_rescue_sigkill_refused(self):
        self.value['processes'][0].update(returncode=-9,rescue_used=True)
        with self.assertRaises(ValueError):self.validate()
    def test_any_log_or_cleanup_failure_refused(self):
        self.value['service_cleanup']['errors']=['capture-fsync']
        with self.assertRaises(ValueError):self.validate()
    def test_changed_source_pid_or_validator_identity_refused(self):
        for field in ('pid','pubkey'):
            with self.subTest(field=field):
                original=copy.deepcopy(self.value)
                if field=='pid':self.value['trust_pin']['sources'][0]['engine_pid']=777
                else:self.value['nodes'][0]['validator_public_key']='e'*64
                with self.assertRaises(ValueError):self.validate()
                self.value=original
    def test_changed_database_home_node_id_or_key_hash_refused(self):
        for field in ('database_inode_after','home_inode','node_id','node_key_sha256'):
            with self.subTest(field=field):
                original=copy.deepcopy(self.value)
                if field=='database_inode_after':self.value['target_restart'][field]=100
                else:self.value['target_restart']['identity_after'][field]=123 if field=='home_inode' else 'e'*40
                with self.assertRaises(ValueError):self.validate()
                self.value=original
    def test_unverified_or_postlaunch_pre_target_checkpoint_refused(self):
        for field in ('signature','time'):
            with self.subTest(field=field):
                original=copy.deepcopy(self.value)
                if field=='signature':self.value['trust_pin']['pre_target']['evidence']['headers'][0]['signed_header']['commit']['signatures'][0]['signature']='AA=='
                else:self.value['trust_pin']['pre_target']['checked_at_ns']=self.case['now_ns']+1
                with self.assertRaises(ValueError):self.validate()
                self.value=original

    def test_stdout_incomplete_read_write_fsync_or_close_refused(self):
        for key,replacement in (('complete',False),('closed',False),('fsynced',False),('capture_error','read fault')):
            self.setUp();self.value['logs'][0][key]=replacement
            with self.subTest(key=key),self.assertRaises(ValueError):self.validate()

class Protocol4CrashSemanticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Protocol4GateSemanticTests.setUpClass.__func__(cls)
    def setUp(self):
        Protocol4GateSemanticTests.setUp(self)
    def crash_value(self,newer=False):
        import base64
        from commit_verifier import encode
        from check_protocol4_state_sync import CRASH_IDS
        from protocol4_state_sync import _hash,_metadata
        from protocol4_application import Protocol4Application
        from protocol4_abci_wire import Request
        from protocol4_abci_server import dispatch
        v=self.value;initial=copy.deepcopy(v['install'])
        initial.update(pid=201,birth='10',run_id='f'*32,database_device=1,database_inode=99,
                       socket_device=1,socket_inode=77,checkpoint_recovery=False)
        initial_trace=copy.deepcopy(v['snapshot_transfer']);initial_trace['trace'][-1]['response']=None
        if newer:
            evidence=self.bundle(self.case,6);state=evidence['state']
            composite={'native':state['native'],'registry':state['registry']}
            raw=encode({'schema':2,'domain':'1soft/protocol4/composite-state-sync/v1',
                'genesis':state['genesis'],'height':6,'app_hash':state['app_hash'],
                'state':composite,'history':evidence['history']})
            source=Protocol4Application(':memory:',expected_genesis=self.case['g'])
            target=Protocol4Application(':memory:',expected_genesis=self.case['g'])
            source.genesis=self.case['g'];source.state=composite;source.height=6;source.app_hash=state['app_hash']
            for row in evidence['history']:
                source.db.execute('INSERT INTO history VALUES (?,?)',(row['height'],encode(row['txs']).decode()))
            trace=[]
            def call(app,req):
                ans=dispatch(app,req);trace.append({'request':base64.b64encode(req.SerializeToString()).decode(),
                    'response':base64.b64encode(ans.SerializeToString()).decode()});return ans
            try:
                req=Request();req.list_snapshots.SetInParent();desc=call(source,req).list_snapshots.snapshots[0]
                req=Request();req.offer_snapshot.snapshot.CopyFrom(desc);req.offer_snapshot.app_hash=bytes.fromhex(state['app_hash']);call(target,req)
                req=Request();req.load_snapshot_chunk.height=6;req.load_snapshot_chunk.format=2
                chunk=call(source,req).load_snapshot_chunk.chunk
                req=Request();req.apply_snapshot_chunk.chunk=chunk;req.apply_snapshot_chunk.sender='unit';call(target,req)
            finally:source.close();target.close()
            v['snapshot_evidence']=evidence
            v['snapshot_transfer']={'format':2,'height':6,'offered_app_hash':state['app_hash'],
                'hash':_hash(raw).hex(),'metadata':base64.b64encode(_metadata(self.case['g'],6,state['app_hash'],len(raw),1)).decode(),
                'chunks':[base64.b64encode(raw).decode()],
                'methods':['list_snapshots','offer_snapshot','load_snapshot_chunk','apply_snapshot_chunk'],'trace':trace}
            v['install']={'height':6,'app_hash':state['app_hash'],'state':composite,'history':evidence['history'],
                'marker':{'height':6,'app_hash':state['app_hash']},'block_rows':0,'transaction_active':False}
            v['first_target_block']=7
            v['unavailable_responses']=[{'height':h,'code':1,'log':'protocol-4 response unavailable'} for h in range(1,7)]
        v['install'].update(pid=202,birth='20',run_id='f'*32,database_device=1,database_inode=99,
                           socket_device=1,socket_inode=78,checkpoint_recovery=True)
        reopened=copy.deepcopy(initial);reopened['pid']=202
        v['crash']={'initial_install':initial,'initial_evidence':self.bundle(self.case,4),
            'initial_transfer':initial_trace,'killed':{'pid':201,'birth':'10','run_id':'f'*32,
                'returncode':-9,'signal':'SIGKILL','install':initial},
            'ready':{'pid':201,'birth':'10','run_id':'f'*32,'device':1,'inode':77},
            'recovered':copy.deepcopy(v['install']),'restart_checkpoint':reopened,
            'rollback_after':copy.deepcopy(reopened),'rollback_offer_result':3,
            'recovery_kind':'newer' if newer else 'same','home_device':1,'home_inode':88}
        v['profile']='final-apply-crash';v['checks'] += [{'id':x,'passed':True} for x in CRASH_IDS]
        v['processes'][9]['role']='crash-supervisor'
        v['processes'] += [
            {'name':'engine4-recovery','role':'engine','pid':13,'birth':'13','alive_after':False,
             'returncode':0,'stop_requested':True,'termination_signal':15,'rescue_used':False,'cleanup_error':None},
            {'name':'pause-ready.json','role':'final-apply-pause-child','pid':201,'birth':'10',
             'returncode':-9,'alive_after':False,'stop_requested':True,'termination_signal':9,
             'rescue_used':False,'cleanup_error':None},
            {'name':'recovery-ready.json','role':'recovery-child','pid':202,'birth':'20',
             'returncode':0,'alive_after':False,'stop_requested':True,'termination_signal':15,
             'rescue_used':False,'cleanup_error':None}]
        v['crash']['identity_before']=copy.deepcopy(v['nodes'][4])
        v['crash']['identity_after']=copy.deepcopy(v['nodes'][4])
        from run_protocol4_state_sync import canonical_older_offer
        from protocol4_abci_wire import Request
        from protocol4_abci_server import dispatch
        from protocol4_application import Protocol4Application
        from commit_verifier import load_json
        older=self.bundle(self.case,3)
        request,chunks=canonical_older_offer(older,self.case['genesis'],self.case['policy'],now_ns=self.case['now_ns'])
        with Protocol4Application(':memory:',expected_genesis=self.case['g']) as target:
            target.state_sync._install(load_json(base64.b64decode(initial_trace['chunks'][0])),False)
            answer=dispatch(target,request)
        self.assertEqual(answer.offer_snapshot.result,3)
        v['crash']['rollback_probe']={'kind':'manual-direct-ABCI-coherent-older-checkpoint','evidence':older,
            'request':base64.b64encode(request.SerializeToString(deterministic=True)).decode(),
            'response':base64.b64encode(answer.SerializeToString(deterministic=True)).decode(),
            'chunks':[base64.b64encode(x).decode() for x in chunks]}

        return v
    def validate(self):
        from check_protocol4_state_sync import validate_result
        return validate_result(self.value,'final-apply-crash',self.source,'e'*64,self.process,
            self.case['genesis'],self.case['policy'],now_ns=self.case['now_ns'])
    def test_same_checkpoint_sigkill_reoffer_verifies(self):
        self.crash_value()
        try:report=self.validate()
        except ValueError as exc:self.fail('same checkpoint recovery should verify: '+str(exc))
        self.assertEqual(report['snapshot_height'],4)
    def test_newer_checkpoint_recovery_is_explicit_and_signed(self):
        self.crash_value(True)
        try:report=self.validate()
        except ValueError as exc:self.fail('newer checkpoint recovery should verify: '+str(exc))
        self.assertEqual(report['snapshot_height'],6)
    def test_false_newer_as_same_label_refused(self):
        self.crash_value(True);self.value['crash']['recovery_kind']='same'
        with self.assertRaises(ValueError):self.validate()
    def test_final_apply_reply_before_claimed_kill_refused(self):
        self.crash_value();self.value['crash']['initial_transfer']['trace'][-1]['response']=self.value['snapshot_transfer']['trace'][-1]['response']
        with self.assertRaises(ValueError):self.validate()
    def test_changed_database_inode_on_recovery_refused(self):
        self.crash_value();self.value['crash']['restart_checkpoint']['database_inode']=100
        with self.assertRaises(ValueError):self.validate()
    def test_wrong_owned_child_identity_refused(self):
        self.crash_value();self.value['crash']['killed']['birth']='11'
        with self.assertRaises(ValueError):self.validate()

    def test_malformed_older_descriptor_is_not_a_rollback_qualification(self):
        import base64
        from protocol4_abci_wire import Request
        self.crash_value()
        probe=self.value['crash']['rollback_probe']
        request=Request.FromString(base64.b64decode(probe['request']))
        request.offer_snapshot.snapshot.height-=1
        probe['request']=base64.b64encode(request.SerializeToString()).decode()
        with self.assertRaises(ValueError):self.validate()
    def test_missing_or_unsigned_older_proof_or_engine_label_refused(self):
        for mutation in ('missing','signature','label','chunk'):
            self.setUp();self.crash_value()
            probe=self.value['crash']['rollback_probe']
            if mutation=='missing':self.value['crash'].pop('rollback_probe')
            elif mutation=='signature':probe['evidence']['headers'][0]['signed_header']['commit']['signatures'][0]['signature']='AA=='
            elif mutation=='label':probe['kind']='actual-engine-rollback-offer'
            else:probe['chunks'][0]='AA=='
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):self.validate()


class Protocol4ControlledExitSemanticTests(unittest.TestCase):
    setUpClass=classmethod(Protocol4CrashSemanticTests.setUpClass.__func__)
    setUp=Protocol4CrashSemanticTests.setUp
    crash_value=Protocol4CrashSemanticTests.crash_value
    validate=Protocol4CrashSemanticTests.validate
    def controlled(self):
        import hashlib
        self.crash_value();v=self.value;v['run_id']='f'*32
        row=next(x for x in v['processes'] if x['name']=='engine4')
        row.update(stop_requested=False,termination_signal=None,spawned_at_ns=10)
        before={k:row[k] for k in ('name','pid','birth','spawned_at_ns')}
        before.update(alive=True,observed_at_ns=20)
        killed=v['crash']['killed'];killed.update(stop_requested=True,termination_signal=9,
            rescue_used=False,cleanup_error=None,engine_before_kill=before,
            kill_requested_at_ns=30,reaped_at_ns=40)
        log='consensus connection terminated. Did the application crash? Please restart CometBFT err="read message: EOF"\n'
        row['causal_exit']={'kind':'controlled-final-apply-application-kill','run_id':'f'*32,
            'event_file':'control4/killed.json','event_sha256':'a'*64,'child_pid':201,'child_birth':'10',
            'engine_before_kill':copy.deepcopy(before),'kill_requested_at_ns':30,'reaped_at_ns':40,
            'observed_at_ns':50,'log_name':'engine4.log','log_sha256':hashlib.sha256(log.encode()).hexdigest()}
        v['engine_sync']['original_logs']={'engine4':log}
        return row
    def test_controlled_target_selfexit_reaches_all_eighteen_semantic_checks(self):
        from check_protocol4_state_sync import CHECK_IDS,CRASH_IDS
        self.controlled()
        self.assertEqual(self.validate()['check_ids'],list(CHECK_IDS+CRASH_IDS))
    def test_controlled_cause_cannot_authorize_other_role_or_nonzero(self):
        for mutation in ('source','recovery','nonzero','supervisor'):
            with self.subTest(mutation=mutation):
                self.setUp();row=self.controlled()
                if mutation=='nonzero':row['returncode']=2
                else:
                    name={'source':'engine0','recovery':'engine4-recovery','supervisor':'app4'}[mutation]
                    other=next(x for x in self.value['processes'] if x['name']==name)
                    other.update(causal_exit=row.pop('causal_exit'),stop_requested=False,termination_signal=None)
                    row.update(stop_requested=True,termination_signal=15)
                with self.assertRaises(ValueError):self.validate()
    def test_coherent_missing_empty_or_malformed_run_ids_are_refused(self):
        # Alter every identity together, retaining all equality relationships.
        # Shape validation must independently reject these complete substitutions.
        for replacement in ('missing',None,'',False,123,'f'*31,'f'*33,'A'*32,'g'*32):
            with self.subTest(replacement=replacement):
                self.setUp();row=self.controlled();v=self.value;c=v['crash']
                objects=(v,row['causal_exit'],c['killed'],c['initial_install'],
                         c['ready'],c['recovered'],v['install'])
                for item in objects:
                    if replacement=='missing':item.pop('run_id',None)
                    else:item['run_id']=replacement
                with self.assertRaises(ValueError):self.validate()
    def test_missing_substituted_or_unbounded_cause_is_refused(self):
        for mutation in ('missing','child','birth','run','window','before','signal','diagnostic','hash','extra'):
            with self.subTest(mutation=mutation):
                self.setUp();row=self.controlled();cause=row['causal_exit']
                if mutation=='missing':row.pop('causal_exit')
                elif mutation=='child':cause['child_pid']=999
                elif mutation=='birth':cause['engine_before_kill']['birth']='999'
                elif mutation=='run':cause['run_id']='a'*32
                elif mutation=='window':cause['observed_at_ns']=40+11*10**9
                elif mutation=='before':cause['engine_before_kill']['alive']=False
                elif mutation=='signal':row['termination_signal']=15
                elif mutation=='diagnostic':self.value['engine_sync']['original_logs']['engine4']='unrelated EOF'
                elif mutation=='hash':cause['log_sha256']='b'*64
                else:cause['invented']=True
                with self.assertRaises(ValueError):self.validate()
