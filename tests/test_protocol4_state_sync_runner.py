"""Bounded runner boundary tests; real engine scenarios are separate gates."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from run_protocol4_state_sync import engine_preflight, output_paths, public_projection

class Protocol4StateSyncRunnerTests(unittest.TestCase):
    def test_missing_engine_is_unassessed_without_launch(self):
        with tempfile.TemporaryDirectory() as d:
            report=engine_preflight(Path(d)/'absent','a'*64)
            self.assertEqual(report['status'],'unassessed')
            self.assertEqual(report['reason'],'pinned engine absent')
    def test_changed_engine_bytes_fail_before_execution(self):
        with tempfile.TemporaryDirectory() as d:
            engine=Path(d)/'engine';engine.write_text('must never be executed')
            report=engine_preflight(engine,'a'*64)
            self.assertEqual(report['status'],'failed')
            self.assertEqual(report['engine_sha256'],hashlib.sha256(engine.read_bytes()).hexdigest())
    def test_existing_output_is_preserved_and_refused(self):
        with tempfile.TemporaryDirectory() as d:
            old=Path(d)/'existing';old.mkdir();(old/'valuable').write_text('preserve')
            with self.assertRaises(ValueError):output_paths(old,Path(d)/'public')
            self.assertEqual((old/'valuable').read_text(),'preserve')
    def test_checkout_output_or_aliased_private_parent_refused(self):
        from run_protocol4_state_sync import ROOT
        with self.assertRaises(ValueError):output_paths(ROOT/'generated',Path('/tmp/public-new'))
        with tempfile.TemporaryDirectory() as d:
            parent=Path(d)/'original';parent.mkdir();link=Path(d)/'alias';link.symlink_to(parent,target_is_directory=True)
            with self.assertRaises(ValueError):output_paths(link/'private',Path(d)/'public')
    def test_public_projection_does_not_copy_full_private_proofs_or_paths(self):
        result={'schema':'1soft-protocol4-state-sync-v1','status':'failed','profile':'basic',
                'source':{'commit':'a'*40,'tree':'b'*40,'source_id':'c'*64},
                'engine_sha256':'d'*64,'checks':[],'private_key':'NEVER EXPORT',
                'reason':'private /home/fixture and signing wire','payments':{'pre':'SECRET'},
                'final_evidence':{'native':'SECRET'},'private_output':'/private/path'}
        public=public_projection(result)
        self.assertEqual(public['status'],'failed');self.assertEqual(public['qualified_check_ids'],[])
        self.assertNotIn('SECRET',str(public));self.assertNotIn('NEVER EXPORT',str(public))
        self.assertNotIn('/private',str(public));self.assertNotIn('/home',str(public))


    def test_written_comet38_state_sync_config_meets_discovery_floor_and_exact_trust(self):
        import tomllib
        from run_devnet import patch_toml
        from run_protocol4_state_sync import state_sync_configuration
        raw='[statesync]\nenable=false\nrpc_servers=""\ntrust_height=0\ntrust_hash=""\ntrust_period="168h0m0s"\ndiscovery_time="15s"\nchunk_request_timeout="10s"\nchunk_fetchers=4\nmax_snapshot_chunks=64\n'
        config=tomllib.loads(patch_toml(raw,state_sync_configuration(
            {'anchor_height':11,'anchor_hash':'ab'*32},[1111,2222])))['statesync']
        # Official pinned Config.ValidateBasic rejects every nonzero duration below 5s.
        self.assertGreaterEqual(int(config['discovery_time'][:-1]),5)
        self.assertEqual(config['trust_height'],11)
        self.assertEqual(config['trust_hash'],'AB'*32)
        self.assertEqual(config['rpc_servers'],'http://127.0.0.1:1111,http://127.0.0.1:2222')
