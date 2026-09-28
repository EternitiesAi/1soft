"""Matrix report/pin controls; synthetic reports here are never engine evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_network as matrix

SOURCE={'commit':'a'*40,'tree':'b'*40,'source_id':'c'*64,'files':[
    {'path':'scripts/run_devnet.py','sha256':'d'*64},
    {'path':'scripts/run_state_sync.py','sha256':'e'*64},
    {'path':'SOURCE_MANIFEST.json','sha256':'f'*64}]}
PROCESS={'returncode':0,'timed_out':False,'log_truncated':False}
ENGINE='1'*64
TXIDS=('a'*64,'b'*64)
WIRES=('c'*64,'d'*64)
NAMES=('first worker payment','second worker boundary payment')
NATIVE_CORE_CHECKS=(
    'four actual CometBFT processes',
    'fresh chain producing blocks',
    'native transfer independently signature/inclusion verified',
    '3 of 4 continue',
    '2 of 4 do not advance during measured interval',
    'quorum restoration resumes progress',
    'stale validator rejoins',
    'four applications agree at common height',
    'native test supply conserved',
    'all intended native operations recorded',
    'native receipts independently certified against genesis',
    'read-only client collected and verified actual RPC receipt',
    'four committed block records agree',
    'block record matches signed next-header state commitment',
)
P1_CHECKS=(
    'owner grant independently signature/inclusion verified',
    'agent transfer independently signature/inclusion verified',
    'owner fence independently signature/inclusion verified',
    'old authority rejected by node admission',
)
P2_CHECKS=(
    'onboard signed native account independently signature/inclusion verified',
    'rotate continuing account key independently signature/inclusion verified',
    'replacement key payment independently signature/inclusion verified',
    'retired account key rejected',
    'pre-rotation grant rejected',
    'duplicate onboarding cannot reset identity',
    'rotated account retains stable identity and expected balance',
    'same-named grants remain owner-scoped',
)
P3_CHECKS=(
    'shared budget creation independently signature/inclusion verified',
    'first worker payment signed by certified wallet against real validator state',
    'second worker overcommit refused before vault unlock',
    'second worker boundary payment signed by certified wallet against real validator state',
    'older first receipt is already recorded after cold reopen',
    'revisiting receipt preserves wallet transport and RPC counts',
)
SMT_CHECKS=(
    'compact accounts query accepted',
    'compact accounts proof independently verified',
    'compact receipts query accepted',
    'compact receipts proof independently verified',
    'compact receipt binds exact original transfer',
)
SYNC_CORE_CHECKS=(
    'four source validators are producing blocks',
    'pre-snapshot native transfer committed',
    'state-sync trust height/hash captured from running source chain',
    'fresh non-validator application was installed through state sync',
    'restored marker AppHash matches source block at that exact height',
    'restored application did not invent source block metadata at snapshot height',
    'post-snapshot transfer committed on source chain',
    'source chain head is stable after quorum loss',
    'state-synced node continued through ordinary block sync',
    'source and state-synced applications agree at frozen head',
    'post-snapshot transaction exists in target native receipt history',
    'state-sync provenance marker survives later block execution',
    'target block metadata starts strictly after restored snapshot',
    'target durable application checkpoint equals source checkpoint',
)

def history(height):
    return {'scope':'local_application_block_results','application_height':height,
        'availability':{'bootstrap_height':0,'keep_blocks':2,'pruned_through':height-2,
                        'retained_count':2,'retained_from':height-1,'retained_through':height,
                        'within_configured_window':True},
        'cometbft_retain_height':0,'engine_history_pruning_requested':False,
        'historical_transaction_absence_proven':False,'total_storage_bounded':False,
        'native_receipt_count':4,'native_receipts_pruned':False}

def fixture(name='native-p1'):
    _,script,args=matrix.expected_profile(name)
    r={'status':'passed','checks':[{'name':'synthetic control','passed':True}],
       'engine_sha256':ENGINE,'engine_version':'0.38.25',
       'public_network':False,'real_funds':False,
       'native_protocol_version':int(args[args.index('--protocol-version')+1]),
       'state_commitment':'smt-v1' if '--state-commitment' in args else 'legacy-flat-v1',
       'run_provenance':{'source_commit':SOURCE['commit'],'source_tree':SOURCE['tree'],
         'tracked_worktree_dirty':False,'runner_relative_path':script,
         'runner_sha256':next(f['sha256'] for f in SOURCE['files'] if f['path']==script),
         'source_manifest_sha256':'f'*64}}
    required=SYNC_CORE_CHECKS if script.endswith('run_state_sync.py') else NATIVE_CORE_CHECKS
    r['checks'].extend({'name':check,'passed':True} for check in required)
    if script.endswith('run_devnet.py'):
        specific=P1_CHECKS if name in ('native-p1','retained-p1') else P1_CHECKS+P2_CHECKS if name=='native-p2' else P3_CHECKS
        r['checks'].extend({'name':check,'passed':True} for check in specific)
        if name in ('native-p3-smt','product-p3-smt'):
            r['checks'].extend({'name':check,'passed':True} for check in SMT_CHECKS)
    if name=='state-sync-p3-smt':
        r['checks'].append({'name':'state-synced SMT node serves a verified compact account proof after continuation','passed':True})
    if '--decision-delivery' in args:
        delivery_payments=[{'name':name,'decision_id':str(i+2)*64,'native_txid':TXIDS[i],
                            'wire_sha256':WIRES[i],'submission_attempts':1}
                           for i,name in enumerate(NAMES)]
        transport_payments=[{'name':name,'wire_sha256':WIRES[i],'upstream_http_status':200,
                             'upstream_check_tx_code':0,'upstream_tx_hash_matches':True,
                             'downstream_reply_dropped':i==0,
                             'downstream_reply_forwarded':i==1}
                            for i,name in enumerate(NAMES)]
        r.update(wallet_integration_verified=True,decision_delivery={'enabled':True,'status':'passed',
            'payments':delivery_payments,
            'transport':{'endpoint_scope':'loopback-only','forwarded_payment_submissions':2,
                'read_only_rpc_requests':18,'http_methods_seen':['POST']*18,
                'unexpected_http_methods':[],'unexpected_requests':[],
                'payments':transport_payments},
            'receipt_convergence':{'reconciliation_outcome':'already_recorded',
                'native_txid':TXIDS[0],'wire_sha256':WIRES[0],
                'submission_attempts':1,'network_requested':False,
                'wallet_sync_performed':False,'signing_performed':False}})
        r['checks'].append({'name':'two exact worker payments were forwarded once with no unexpected HTTP methods or RPC requests','passed':True})
    if '--block-history-keep' in args:
        before,after=history(12),history(14)
        nodes=[history(h) for h in (15,15,15,14)]
        r['final_state']={'native':{'receipts':[{'txid':str(i)*64} for i in range(4)]}}
        r['local_history']={'enabled':True,'status':'passed','keep_blocks':2,
                            'application_restart_verified':True,'before_restart':before,
                            'after_restart':after,'nodes':nodes}
        r['checks'].extend([
            {'name':'retention survives actual application and engine restart without a repeated flag',
             'passed':True,'details':{'before':before,'after':after}},
            {'name':'all four applications retain the bounded local window without pruning native receipts',
             'passed':True,'details':nodes}])
    if '--product-journey' in args:
        labels=('both-signed','raven-before-reconcile','raven-reconciled',
                'atlas-before-reconcile','atlas-reconciled')
        pairs=((100,0),(100,60),(40,60),(40,100),(0,100))
        payments=[{'label':label,'txid':TXIDS[i],'wire_sha256':WIRES[i],
                   'receipt_sha256':str(i+4)*64,'inclusion_height':9+i*3,
                   'header_hash':str(i+6)*64,'evidence_id':str(i+8)*64,
                   'proof_kind':'smt-v1' if name.endswith('smt') else 'legacy-full-state-v1'}
                  for i,label in enumerate(('raven','atlas'))]
        r['product_journey']={'enabled':True,'status':'passed','payments':payments,
            'stages':[{'stage':label,'wallet_pending_units':pair[0],
                       'explorer_spent_units':pair[1],
                       'wallet_pending_debits_included':False,
                       'wallet_state_height':12,'explorer_state_height':12,
                       'explorer_anchor_hash':'e'*64,'view_sha256':'f'*64}
                      for label,pair in zip(labels,pairs)],
            'observations':[{'file':'000-initial-wallet-anchor.json','sha256':'e'*64}],
            'source_node_mutations_by_product_clients':False,
            'wallet_mutations_by_product_clients':False,
            'public_network':False,'real_funds':False,
            'final_state_height':15,'final_app_hash':'e'*64,
            'verification_after_local_pruning':[
                {'native_txid':payment['txid'],'pruned_block':payment['inclusion_height'],
                 'exact_archived_receipt_verified':True,'index_retains_verified_inclusion':True}
                for payment in payments]}
        for label in ('raven','atlas'):
            r['checks'].extend([
                {'name':label+': explorer and archive bind the exact live receipt without releasing a hold',
                 'passed':True},
                {'name':label+': reopened derived stores preserve both indexed and archived payment',
                 'passed':True}])
        r['checks'].extend([
            {'name':'integrated product stages match signed obligations and recorded spending','passed':True},
            {'name':'old local payment metadata pruned while exact explorer and archive evidence remain','passed':True}])
    if script.endswith('run_state_sync.py'):
        r.update(state_sync_verified=True,continued_execution_verified=True)
    return r

class NetworkMatrixTests(unittest.TestCase):
    def validate(self,r,name='native-p1',process=None):
        return matrix.validate_result(r,name,SOURCE,ENGINE,process or PROCESS)
    def test_exact_profile_can_pass_structural_checks_only(self):
        report=fixture()
        self.assertEqual(self.validate(report),len(report['checks']))
    def test_all_nine_profiles_are_unique(self):
        self.assertEqual(len(matrix.PROFILES),9);self.assertEqual(len({p[0] for p in matrix.PROFILES}),9)
    def test_product_profiles_explicitly_enable_retention_and_delivery(self):
        for name in ('product-p3-flat','product-p3-smt'):
            args=matrix.expected_profile(name)[2]
            self.assertIn('--decision-delivery',args);self.assertIn('--receipt-convergence',args)
            self.assertEqual(args[args.index('--block-history-keep')+1],'2')
            report=fixture(name)
            self.assertEqual(self.validate(report,name),len(report['checks']))
    def test_missing_checks_cannot_be_hidden_under_pass(self):
        r=fixture();r['checks']=[]
        with self.assertRaises(ValueError):self.validate(r)
    def test_failed_check_cannot_be_hidden_under_pass(self):
        r=fixture();r['checks'][0]['passed']=False
        with self.assertRaises(ValueError):self.validate(r)
    def test_boolean_like_check_is_not_pass(self):
        r=fixture();r['checks'][0]['passed']=1
        with self.assertRaises(ValueError):self.validate(r)
    def test_ancestor_revision_is_not_current_candidate(self):
        r=fixture();r['run_provenance']['source_commit']='0'*40
        with self.assertRaises(ValueError):self.validate(r)
    def test_dirty_runner_refused(self):
        r=fixture();r['run_provenance']['tracked_worktree_dirty']=True
        with self.assertRaises(ValueError):self.validate(r)
    def test_mismatched_binary_refused(self):
        r=fixture();r['engine_sha256']='0'*64
        with self.assertRaises(ValueError):self.validate(r)
    def test_mismatched_runner_bytes_refused(self):
        r=fixture();r['run_provenance']['runner_sha256']='0'*64
        with self.assertRaises(ValueError):self.validate(r)
    def test_wrong_protocol_and_commitment_refused(self):
        for key,value in (('native_protocol_version',3),('state_commitment','smt-v1')):
            r=fixture();r[key]=value
            with self.assertRaises(ValueError):self.validate(r)
    def test_timeout_and_truncated_log_refused(self):
        for key in ('timed_out','log_truncated'):
            with self.assertRaises(ValueError):self.validate(fixture(),process={**PROCESS,key:True})
    def test_source_inventory_mismatch_refused(self):
        r=fixture();r['run_provenance']['source_manifest_sha256']='0'*64
        with self.assertRaises(ValueError):self.validate(r)
    def test_missing_application_restart_refused(self):
        r=fixture('retained-p1');r['local_history']['application_restart_verified']=False
        with self.assertRaises(ValueError):self.validate(r,'retained-p1')
    def test_delivery_transport_cannot_be_placeholder_or_mismatch(self):
        for mutation in ('empty_rows','different_wire','missing_named_check'):
            with self.subTest(mutation=mutation):
                r=fixture('native-p3-flat')
                if mutation=='empty_rows':r['decision_delivery']['transport']['payments']=[{},{}]
                elif mutation=='different_wire':
                    r['decision_delivery']['transport']['payments'][0]['wire_sha256']='0'*64
                else:r['checks']=[{'name':'synthetic control','passed':True}]
                with self.assertRaises(ValueError):self.validate(r,'native-p3-flat')
    def test_retention_requires_before_after_and_four_valid_windows(self):
        for mutation in ('missing_before','three_nodes','bad_window'):
            with self.subTest(mutation=mutation):
                r=fixture('retained-p1')
                if mutation=='missing_before':r['local_history'].pop('before_restart')
                elif mutation=='three_nodes':r['local_history']['nodes'].pop()
                else:r['local_history']['nodes'][0]['availability']['retained_count']=0
                with self.assertRaises(ValueError):self.validate(r,'retained-p1')
    def test_product_payment_must_match_delivery_identity(self):
        for field in ('txid','wire_sha256'):
            with self.subTest(field=field):
                r=fixture('product-p3-flat');r['product_journey']['payments'][0][field]='0'*64
                with self.assertRaises(ValueError):self.validate(r,'product-p3-flat')
    def test_product_pruning_requires_exact_verified_receipts(self):
        for mutation in ('empty','wrong_txid','false_archive'):
            with self.subTest(mutation=mutation):
                r=fixture('product-p3-flat')
                row=r['product_journey']['verification_after_local_pruning'][0]
                if mutation=='empty':r['product_journey']['verification_after_local_pruning']=[{},{}]
                elif mutation=='wrong_txid':row['native_txid']='0'*64
                else:row['exact_archived_receipt_verified']=False
                with self.assertRaises(ValueError):self.validate(r,'product-p3-flat')
    def test_product_semantic_checks_cannot_be_replaced_by_generic_pass(self):
        r=fixture('product-p3-flat')
        r['checks']=[{'name':'synthetic control','passed':True}]
        with self.assertRaises(ValueError):self.validate(r,'product-p3-flat')
    def test_native_semantic_checks_cannot_be_replaced_by_generic_pass(self):
        for name in ('native-p1','native-p2','native-p3-flat','native-p3-smt','retained-p1'):
            with self.subTest(name=name):
                r=fixture(name)
                r['checks']=[{'name':'synthetic control','passed':True}]
                with self.assertRaises(ValueError):self.validate(r,name)
    def test_state_sync_semantic_checks_cannot_be_replaced_by_generic_pass(self):
        for name in ('state-sync-p1','state-sync-p3-smt'):
            with self.subTest(name=name):
                r=fixture(name)
                r['checks']=[{'name':'synthetic control','passed':True}]
                with self.assertRaises(ValueError):self.validate(r,name)
    def test_profile_specific_semantic_checks_are_required(self):
        for name,missing in (
            ('native-p1','owner fence independently signature/inclusion verified'),
            ('native-p2','owner grant independently signature/inclusion verified'),
            ('native-p2','retired account key rejected'),
            ('native-p3-flat','second worker overcommit refused before vault unlock'),
            ('native-p3-smt','compact receipts proof independently verified'),
            ('state-sync-p1','target block metadata starts strictly after restored snapshot'),
            ('state-sync-p3-smt','state-synced SMT node serves a verified compact account proof after continuation')):
            with self.subTest(name=name):
                r=fixture(name)
                r['checks']=[check for check in r['checks'] if check['name']!=missing]
                with self.assertRaises(ValueError):self.validate(r,name)
    def test_boolean_values_cannot_impersonate_numeric_engine_evidence(self):
        mutations=(
            ('native-p1', lambda r: r.__setitem__('native_protocol_version',True)),
            ('native-p3-flat', lambda r: r['decision_delivery']['payments'][0].__setitem__('submission_attempts',True)),
            ('native-p3-flat', lambda r: r['decision_delivery']['transport']['payments'][0].__setitem__('upstream_check_tx_code',False)),
            ('retained-p1', lambda r: r['local_history']['before_restart']['availability'].__setitem__('bootstrap_height',False)),
            ('product-p3-flat', lambda r: r['product_journey']['stages'][4].__setitem__('wallet_pending_units',False)),
            ('product-p3-flat', lambda r: (r['product_journey']['payments'][0].__setitem__('inclusion_height',1),
                                          r['product_journey']['verification_after_local_pruning'][0].__setitem__('pruned_block',True))),
        )
        for name,mutate in mutations:
            with self.subTest(name=name,mutation=mutate.__code__.co_firstlineno):
                r=fixture(name);mutate(r)
                with self.assertRaises(ValueError):self.validate(r,name)
    def test_product_not_allowed_to_release_hold_before_reconciliation(self):
        r=fixture('product-p3-flat');r['product_journey']['stages'][1]['wallet_pending_units']=40
        with self.assertRaises(ValueError):self.validate(r,'product-p3-flat')
    def test_missing_pruned_receipt_verification_refused(self):
        r=fixture('product-p3-flat');r['product_journey']['verification_after_local_pruning']=[]
        with self.assertRaises(ValueError):self.validate(r,'product-p3-flat')
    def test_state_sync_requires_continued_execution(self):
        r=fixture('state-sync-p1');r['continued_execution_verified']=False
        with self.assertRaises(ValueError):self.validate(r,'state-sync-p1')
    def test_missing_engine_does_not_execute_any_scenario_or_go_probe(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'source';source.mkdir();output=root/'evidence'
            with patch.object(matrix,'ROOT',source),patch.object(matrix,'source_identity',return_value=SOURCE),\
                 patch.object(matrix,'checked_manifests',return_value=[]),\
                 patch.object(matrix,'run_process',side_effect=AssertionError('must not launch')):
                result=matrix.run(str(root/'missing'),ENGINE,output)
            self.assertEqual(result,2)
            report=json.loads((output/'result.json').read_bytes())
            self.assertEqual(report['status'],'unassessed');self.assertEqual(report['scenarios'],[])
            self.assertNotIn('wire',report);self.assertEqual(report['release_status'],'blocked')
    def test_old_output_directory_never_reused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);source=root/'source';source.mkdir();output=root/'evidence';output.mkdir()
            (output/'prior.log').write_text('preserve')
            with patch.object(matrix,'ROOT',source),patch.object(matrix,'source_identity',return_value=SOURCE),\
                 patch.object(matrix,'checked_manifests',return_value=[]):
                with self.assertRaises(FileExistsError):matrix.run(str(root/'missing'),ENGINE,output)
            self.assertEqual((output/'prior.log').read_text(),'preserve')

if __name__=='__main__':unittest.main()
