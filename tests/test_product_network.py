"""Test the opt-in validator gate with explicit local fixtures, not fake consensus."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for p in ('scripts', 'src', 'tests', 'tools/wallet-delivery/src', 'tools/wallet-delivery/tests', 'tools/wallet-account/src'):
    sys.path.insert(0, str(ROOT/p))
import run_devnet as runner
from product_network_case import ProductNetworkCase, check_retention
from block_application import BlockApplication
from commit_verifier import encode
from certified_wallet import CertifiedWallet
from decision_delivery import DecisionDelivery
from delivery_fixture import Scenario, IDS
from native_core import canonical


class ProductFlagTests(unittest.TestCase):
    def test_application_window_flag_is_explicit(self):
        args = runner.application_command(Path('/private/app'), Path('/private/genesis.json'), 2)
        self.assertEqual(args[-2:], ['--block-history-keep','2'])
    def test_reopen_command_omits_window_to_test_persisted_policy(self):
        args = runner.application_command(Path('/private/app'), Path('/private/genesis.json'))
        self.assertNotIn('--block-history-keep', args)
    def test_window_bounds_refuse_before_launching(self):
        for value in (0, 1, True, '2', 2.0, 17):
            with self.subTest(value=value),self.assertRaises(ValueError):
                runner.application_command(Path('/private'),Path('/private/g.json'),value)
    def test_product_requires_exact_profile_before_engine_lookup(self):
        with tempfile.TemporaryDirectory() as d:
            base=dict(protocol_version=3,decision_delivery=True,receipt_convergence=True,block_history_keep=2,product_journey=True)
            for field, value in (('protocol_version',1),('decision_delivery',False),('receipt_convergence',False),('block_history_keep',None),('block_history_keep',3),('product_journey',1)):
                with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                    runner.run('/missing',Path(d)/'out.json',**{**base,field:value})
            self.assertFalse((Path(d)/'out.json').exists())
    def test_product_missing_engine_has_zero_checks(self):
        with tempfile.TemporaryDirectory() as d:
            r=runner.run('/missing-cometbft-1soft',Path(d)/'out.json',3,decision_delivery=True,
                         receipt_convergence=True,block_history_keep=2,product_journey=True)
            self.assertEqual(r['status'],'unassessed');self.assertEqual(r['checks'],[])
            self.assertEqual(r['product_journey']['status'],'unassessed')
            self.assertEqual(r['local_history']['status'],'unassessed')
            self.assertFalse(r['local_history']['application_restart_verified'])
            self.assertFalse((Path(d)/'product-evidence').exists())
    def test_history_missing_engine_does_not_report_restart(self):
        with tempfile.TemporaryDirectory() as d:
            r=runner.run('/missing-cometbft-1soft',Path(d)/'out.json',1,block_history_keep=4)
            self.assertEqual(r['status'],'unassessed');self.assertFalse(r['local_history']['application_restart_verified'])
    def test_default_has_no_product_or_pruning_result(self):
        with tempfile.TemporaryDirectory() as d:
            r=runner.run('/missing-cometbft-1soft',Path(d)/'out.json')
            self.assertNotIn('local_history',r);self.assertNotIn('product_journey',r)


class RetentionAssertions(unittest.TestCase):
    def setUp(self):
        self.h={'scope':'local_application_block_results','application_height':10,
            'availability':{'keep_blocks':2,'retained_count':2,'retained_from':9,'retained_through':10,
                'pruned_through':8,'bootstrap_height':0,'within_configured_window':True},
            'native_receipts_pruned':False,'cometbft_retain_height':0,'engine_history_pruning_requested':False,
            'historical_transaction_absence_proven':False,'total_storage_bounded':False}
    def test_valid_metadata_is_not_consensus_qualification(self):
        self.assertEqual(check_retention(self.h,2)['retained_count'],2)
    def test_unpruned_window_cannot_pass(self):
        self.h['availability']['retained_count']=10
        with self.assertRaises(AssertionError):check_retention(self.h,2)
    def test_wrong_height_boundary_cannot_pass(self):
        self.h['availability']['pruned_through']=7
        with self.assertRaises(AssertionError):check_retention(self.h,2)
    def test_native_pruning_claim_cannot_pass(self):
        self.h['native_receipts_pruned']=True
        with self.assertRaises(AssertionError):check_retention(self.h,2)
    def test_engine_retain_height_must_stay_zero(self):
        self.h['cometbft_retain_height']=1
        with self.assertRaises(AssertionError):check_retention(self.h,2)
    def test_missing_metadata_is_not_pruning_success(self):
        with self.assertRaises(AssertionError):check_retention(None,2)


class ProductJourneyTests(unittest.TestCase):
    def run_case(self,compact):
        c=Scenario(compact=compact);product=None
        checks=[]
        def checked(name,condition,details=None):
            checks.append({'name':name,'passed':bool(condition),'details':details})
            self.assertTrue(condition,name)
        def read_rpc(method,params):
            # Explicit fixture callback for ancillary commit/availability reads;
            # the ProductNetworkCase explorer itself uses actual loopback HTTP.
            if method=='commit':return {'signed_header':c.headers[int(params['height'])]}
            response=c.app.query(params['path'])
            return {'response':{**response,'value':base64.b64encode(response['value']).decode()}}
        try:
            c.app.close();c.app=BlockApplication(c.root/'app.sqlite',expected_genesis=c.genesis,block_history_keep=2)
            raven=c.sign();atlas=c.sign(who=3,units=38)
            for file in c.root.glob('*.pem'):file.unlink()
            with c.rpc() as url,patch('certified_wallet._load_vault',side_effect=AssertionError('unexpected unlock')):
                product=ProductNetworkCase(c.root/'products',c.root/'proofs',c.raw,url,read_rpc,checked,
                                           next(iter(c.wallet.pending()['pending_budget_units'])),clock=lambda:c.clock)
                product.start(c.wallet,c.exposed)
                for i,(label,signed) in enumerate((('raven',raven),('atlas',atlas))):
                    with DecisionDelivery(c.wallet_path,c.delivery_path,c.raw,c.policy,url,create=i==0,clock=lambda:c.clock) as d:
                        q=d.queue(signed['decision_id'],account=IDS[0],grant_id=label)
                        sent=d.send(signed['decision_id'],q['delivery_confirmation'],account=IDS[0],grant_id=label)
                        self.assertEqual(sent['transport_status'],'unresolved' if i==0 else 'endpoint_admitted')
                    c.wallet.close();c.wallet=CertifiedWallet(c.wallet_path,c.raw,c.policy,clock=lambda:c.clock)
                    with DecisionDelivery(c.wallet_path,c.delivery_path,c.raw,c.policy,url,clock=lambda:c.clock) as d:
                        received=d.refresh(signed['decision_id'],account=IDS[0],grant_id=label)
                        self.assertTrue(received['exact_transport_receipt_verified'])
                        packet=json.loads(d.export_receipt(signed['decision_id'],account=IDS[0],grant_id=label))
                        product.receipt(label,c.wallet,canonical(signed['result']),packet,
                                        expected_pending=100 if i==0 else 40,expected_spent=60 if i==0 else 100)
                        d.reconcile(signed['decision_id'],account=IDS[0],grant_id=label,continuation=c.continuation())
                        product.reconciled(label,c.wallet,40 if i==0 else 0,60 if i==0 else 100)
                    c.mode='return_after_execution'
                for _ in range(4):c.block([])
                c.exposed=c.witness(c.app.height-1)
                result=product.finish(c.wallet)
            self.assertEqual(result['status'],'passed');self.assertEqual(len(c.seen),2)
            self.assertEqual(c.seen,[canonical(raven['result']),canonical(atlas['result'])])
            self.assertEqual([(s['wallet_pending_units'],s['explorer_spent_units']) for s in result['stages']],
                             [(100,0),(100,60),(40,60),(40,100),(0,100)])
            self.assertEqual(len(result['verification_after_local_pruning']),2)
            self.assertTrue((c.root/'proofs/explorer-final.html').exists())
            self.assertEqual(json.loads((c.root/'proofs/product-result.json').read_bytes())['status'],'passed')
            # Stored capsules and view carry native public evidence, never test keys.
            self.assertFalse(list((c.root/'proofs').glob('*.pem')))
            self.assertTrue(all(q['method'] in ('abci_query','commit','block','broadcast_tx_sync') for q in c.requests))
            return checks
        finally:
            if product is not None:product.close()
            c.close()
    def test_flat_gate_helpers_complete_actual_component_journey(self):self.run_case(False)
    def test_smt_gate_helpers_complete_actual_component_journey(self):self.run_case(True)
    def test_failed_refresh_observation_saved_before_propagating(self):
        c=Scenario();product=None
        try:
            with c.rpc() as url:
                product=ProductNetworkCase(c.root/'p',c.root/'out',c.raw,url,lambda *_:None,
                    lambda *_:None,'unused',clock=lambda:c.clock)
                with patch('product_network_case.refresh',side_effect=ValueError('untrusted detail')):
                    with self.assertRaises(ValueError):product._refresh('test')
                r=json.loads((c.root/'out/product-result.json').read_bytes())
                self.assertEqual(r['status'],'running')
                obs=json.loads((c.root/'out'/r['observations'][0]['file']).read_bytes())
                self.assertEqual(obs,{'status':'raised','error_type':'ValueError'})
                self.assertNotIn('untrusted detail',json.dumps(r))
        finally:
            if product is not None:product.close()
            c.close()

if __name__=='__main__':unittest.main()
