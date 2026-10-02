"""Refusal behavior for the P4 gate; no engine or network substitutes."""
import copy
import unittest
from check_protocol4_state_sync import CHECK_IDS, validate_envelope

def envelope():
    source = {'commit': 'a'*40, 'tree': 'b'*40, 'source_id': 'c'*64,
              'files': [{'path': 'scripts/run_protocol4_state_sync.py',
                         'mode': '100644', 'sha256': 'd'*64}]}
    process = {'returncode': 0, 'timed_out': False, 'log_truncated': False}
    value = {'schema': '1soft-protocol4-state-sync-v1', 'status': 'passed',
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
                'old_pid':101,'new_pid':102,'evidence':copy.deepcopy(final)},
            processes=[{'pid':i,'birth':str(i),'alive_after':False,'returncode':0} for i in range(1,11)],
            logs=[{'bytes':100,'truncated':False,'sha256':'a'*64}])
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
