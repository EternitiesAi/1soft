"""Semantic acceptance checks; all positive reports here are SYNTHETIC fixtures."""
import base64
import copy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from block_application import encode
from native_core import digest
from protocol4_application import Protocol4Application
from protocol4_abci_server import dispatch
from protocol4_abci_wire import Request
from commit_verifier import header_hash
from validator_witness import nanos
from recovery_checks import checkpoint,fingerprint,verify_replayed_anchor
from recovery_fixture import model
from acceptance import validate,PROFILES
import run_engine

SOURCE={'commit':'1'*40,'tree':'2'*40,'source_id':'3'*64}
ENGINE='4'*64


def crash_report():
    c=model();g=c['genesis']
    with tempfile.TemporaryDirectory() as name:
        p=Path(name)/'a.sqlite';a=Protocol4Application(p,expected_genesis=g)
        a.init_chain(g['chain_id'],g,g['validator_registry']['validators']);saved=None
        for i,q in enumerate(c['requests'],1):
            dispatch(a,Request.FromString(q));a.commit()
            if i==4:saved=checkpoint(p,g)
        final=checkpoint(p,g);a.close()
    now=nanos(c['headers'][-1]['header']['time'])+10**9;initial=header_hash(c['headers'][0]['header']).hex()
    obs={'schema':1,'run_id':'a'*32,'pid':123,'height':4,'phase':'committed-before-reply',
         'genesis_sha256':digest(g),'checkpoint':fingerprint(saved)}
    evidence={'genesis':g,'emitted_height':4,'final_checkpoint':final,'target_checkpoint':copy.deepcopy(final),
              'payment_wires':[base64.b64encode(w).decode() for w in (c['first'],c['second'])],
              'signed_headers':c['headers'],
              'verified_anchor':verify_replayed_anchor(g,final['history'],final['state'],c['headers'],initial,now),
              'crash':{'observation':obs,'checkpoint':saved,'pid':123,'returncode':-9,'restarted_pid':456,
              'same_database_inode':True,'same_engine_identity':True,
              'saved_response_after_recovery':saved['latest_block']['response_sha256'],'emission_heights':[4]}}
    names=('ordered-payments','dynamic-signed-anchor','matching-source-and-target','post-transition-payment',
           'durable-commit-before-lost-reply','same-store-restart','no-duplicate-emission')
    return {'schema':1,'status':'passed','profile':PROFILES[1],'source':SOURCE,'engine_sha256':ENGINE,
            'engine_version':'0.38.25','public_network':False,'real_funds':False,'independent_operators':False,
            'release_status':'blocked','genesis_sha256':digest(g),'run_id':'a'*32,'initial_header_hash':initial,
            'observed_at_ns':now,'checks':[{'name':n,'passed':True} for n in names],'evidence':evidence}

class AcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.base=crash_report()
    def test_exact_developer_fixture_validates_without_claiming_network(self):
        r=validate(self.base,source=SOURCE,engine_hash=ENGINE);self.assertEqual(r['receipt_count'],2)
        self.assertEqual(r['release_status'],'blocked')
    def assert_bad(self,change):
        r=copy.deepcopy(self.base);change(r)
        with self.assertRaises((ValueError,KeyError,TypeError)):validate(r,source=SOURCE,engine_hash=ENGINE)
    def test_different_source_refused(self):self.assert_bad(lambda r:r['source'].update(commit='9'*40))
    def test_different_engine_refused(self):self.assert_bad(lambda r:r.update(engine_sha256='9'*64))
    def test_boolean_schema_refused(self):self.assert_bad(lambda r:r.update(schema=True))
    def test_placeholder_pass_refused(self):self.assert_bad(lambda r:r.update(checks=[{'name':'passed','passed':True}]))
    def test_truthy_integer_check_refused(self):self.assert_bad(lambda r:r['checks'][0].update(passed=1))
    def test_duplicate_check_refused(self):self.assert_bad(lambda r:r['checks'].append(r['checks'][0]))
    def test_recovered_pid_cannot_be_old_pid(self):self.assert_bad(lambda r:r['evidence']['crash'].update(restarted_pid=123))
    def test_boolean_new_pid_refused(self):self.assert_bad(lambda r:r['evidence']['crash'].update(restarted_pid=True))
    def test_snapshot_reset_does_not_count_as_same_store(self):self.assert_bad(lambda r:r['evidence']['crash'].update(same_database_inode=False))
    def test_new_engine_identity_refused(self):self.assert_bad(lambda r:r['evidence']['crash'].update(same_engine_identity=False))
    def test_saved_response_changed_refused(self):self.assert_bad(lambda r:r['evidence']['crash'].update(saved_response_after_recovery='9'*64))
    def test_duplicate_emission_refused(self):self.assert_bad(lambda r:r['evidence']['crash'].update(emission_heights=[4,5]))
    def test_missing_original_signed_payment_refused(self):self.assert_bad(lambda r:r['evidence']['payment_wires'].pop())
    def test_boolean_crash_receipt_counter_refused(self):self.assert_bad(lambda r:r['evidence']['crash']['observation']['checkpoint'].update(native_receipt_count=True))
    def test_missing_final_signed_commit_refused(self):self.assert_bad(lambda r:r['evidence']['signed_headers'].pop())
    def test_public_readiness_cannot_be_asserted(self):self.assert_bad(lambda r:r.update(release_status='approved'))
    def test_crash_must_be_at_emission_not_other_height(self):self.assert_bad(lambda r:r['evidence'].update(emitted_height=5))

class DriverTests(unittest.TestCase):
    def test_absent_engine_is_unassessed_and_starts_nothing(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);code=root/'src';code.mkdir();out=root/'evidence'
            with patch.object(run_engine,'ROOT',code),patch.object(run_engine,'source_identity',return_value=SOURCE),\
                 patch.object(run_engine,'Child',side_effect=AssertionError('no child allowed')):
                r=run_engine.run(root/'absent-cometbft',ENGINE,out,PROFILES[0])
            self.assertEqual(r['status'],'unassessed');self.assertFalse(r['consensus_executed']);self.assertEqual(r['checks'],[])
            self.assertEqual(json.loads((out/'result.json').read_bytes())['status'],'unassessed')
    def test_old_evidence_directory_not_reused(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);code=root/'src';code.mkdir();out=root/'evidence';out.mkdir()
            with patch.object(run_engine,'ROOT',code),patch.object(run_engine,'source_identity',return_value=SOURCE):
                with self.assertRaises(FileExistsError):run_engine.run(root/'absent',ENGINE,out,PROFILES[0])
    def test_wrong_binary_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);code=root/'src';code.mkdir();binary=root/'binary';binary.write_bytes(b'not an engine')
            with patch.object(run_engine,'ROOT',code),patch.object(run_engine,'source_identity',return_value=SOURCE),\
                 patch.object(run_engine,'Child',side_effect=AssertionError('no process')):
                r=run_engine.run(binary,ENGINE,root/'evidence',PROFILES[1])
            self.assertEqual(r['status'],'failed');self.assertFalse(r['consensus_executed'])
    def test_unknown_profile_refused(self):
        with self.assertRaises(ValueError):run_engine.run(Path('none'),ENGINE,Path('/irrelevant'),'unknown')
    def test_source_directory_cannot_hold_test_outputs(self):
        with self.assertRaises(ValueError):run_engine.run(Path('none'),ENGINE,run_engine.ROOT/'new-output',PROFILES[0])



def bootstrap_report():
    c=model(third=True);g=c['genesis']
    with tempfile.TemporaryDirectory() as name:
        p=Path(name);source=Protocol4Application(p/'source.sqlite',expected_genesis=g)
        source.init_chain(g['chain_id'],g,g['validator_registry']['validators'])
        for raw in c['requests'][:7]:dispatch(source,Request.FromString(raw));source.commit()
        target=Protocol4Application(p/'target.sqlite',expected_genesis=g);desc=source.list_snapshots()[0]
        assert target.offer_snapshot(desc,bytes.fromhex(source.app_hash))==1
        for i in range(desc['chunks']):assert target.apply_snapshot_chunk(i,source.load_snapshot_chunk(7,2,i),'fixture')['result']==1
        boot=checkpoint(p/'target.sqlite',g)
        for raw in c['requests'][7:]:
            dispatch(source,Request.FromString(raw));source.commit();dispatch(target,Request.FromString(raw));target.commit()
        final=checkpoint(p/'source.sqlite',g);other=checkpoint(p/'target.sqlite',g);source.close();target.close()
    initial=header_hash(c['headers'][0]['header']).hex();now=nanos(c['headers'][-1]['header']['time'])+10**9
    names=('ordered-payments','dynamic-signed-anchor','matching-source-and-target','post-transition-payment',
           'untouched-format2-bootstrap','no-imported-block-evidence','post-snapshot-payment')
    return {'schema':1,'status':'passed','profile':PROFILES[0],'source':SOURCE,'engine_sha256':ENGINE,
       'engine_version':'0.38.25','public_network':False,'real_funds':False,'independent_operators':False,
       'release_status':'blocked','genesis_sha256':digest(g),'run_id':'a'*32,'initial_header_hash':initial,
       'observed_at_ns':now,'checks':[{'name':n,'passed':True} for n in names],
       'evidence':{'genesis':g,'emitted_height':4,'final_checkpoint':final,'target_checkpoint':other,
        'signed_headers':c['headers'],'verified_anchor':verify_replayed_anchor(g,c['history'],final['state'],c['headers'],initial,now),
        'payment_wires':[base64.b64encode(c[k]).decode() for k in ('first','second','third')],
        'bootstrap_checkpoint':boot,'bootstrap_observation':{'schema':1,'run_id':'a'*32,'pid':123,
        'phase':'snapshot-installed-before-reply','checkpoint':fingerprint(boot)},'unavailable_blocks':list(range(1,8)),
        'unavailable_block_responses':[{'height':h,'code':1,'log':'protocol-4 response unavailable','value':''} for h in range(1,8)]}}

class BootstrapReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.base=bootstrap_report()
    def test_bootstrap_fixture_matches_signed_replay_and_post_snapshot_payment(self):
        self.assertEqual(validate(self.base,source=SOURCE,engine_hash=ENGINE)['receipt_count'],3)
    def bad(self,change):
        r=copy.deepcopy(self.base);change(r)
        with self.assertRaises((ValueError,KeyError,TypeError)):validate(r,source=SOURCE,engine_hash=ENGINE)
    def test_boolean_local_block_count_refused(self):self.bad(lambda r:r['evidence']['bootstrap_checkpoint'].update(local_block_count=False))
    def test_fabricated_bootstrap_block_metadata_refused(self):self.bad(lambda r:r['evidence']['bootstrap_checkpoint'].update(latest_block={'claimed':True}))
    def test_partial_unavailable_history_inspection_refused(self):self.bad(lambda r:r['evidence']['unavailable_blocks'].pop())
    def test_old_observation_run_refused(self):self.bad(lambda r:r['evidence']['bootstrap_observation'].update(run_id='b'*32))
    def test_missing_post_snapshot_payment_refused(self):self.bad(lambda r:r['evidence']['payment_wires'].pop())

if __name__=='__main__':unittest.main()
