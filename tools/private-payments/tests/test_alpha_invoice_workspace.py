"""Explicit fresh alpha invoice capability; engine initialization is a filesystem fixture."""
import hashlib
import inspect
from pathlib import Path
import unittest
from unittest.mock import patch
from block_application import encode
from commit_verifier import load_json
import local_devnet as devnet
import merchant_devnet
from merchant_browser import ready_for_browser
import test_merchant_devnet as fixture
from wallet_fixture import PASSWORD

class AlphaInvoiceWorkspaceTests(unittest.TestCase):
    setUp=fixture.MerchantWorkspaceTests.setUp
    def initialized(self, enabled=True, profile='durable-private-alpha-v1'):
        self.assertIn('invoice_commitments',inspect.signature(devnet.initialize).parameters,
                      'explicit fresh alpha invoice initialization is missing')
        with patch.object(devnet,'verify_engine',return_value=Path('/fixture-engine')), \
             patch.object(devnet.subprocess,'run',side_effect=fixture.fake_testnet), \
             patch.object(devnet.subprocess,'check_output',side_effect=[(str(i)*40+'\n').encode() for i in range(4)]), \
             patch.object(devnet,'free_ports',return_value=list(range(24000,24008))):
            return devnet.initialize(self.root,'/fixture-engine',password=PASSWORD,profile=profile,invoice_commitments=enabled)
    def test_fresh_explicit_capability_selects_alpha_network_without_legacy_fallback(self):
        q=self.initialized()
        self.assertEqual(q['format'],'1soft/local-alpha-invoice-workspace/v1')
        g=load_json((self.root/'app-genesis.json').read_bytes())
        self.assertEqual(g['invoice_commitment_version'],1)
        self.assertEqual(g['development_profile'],'durable-private-alpha-v1')
        self.assertEqual(devnet.load_configuration(self.root),q)
        with patch.object(devnet,'verify_engine',return_value=Path('/fixture-engine')):
            n=merchant_devnet.network_for_workspace(self.root,'/fixture-engine')
        self.assertIs(type(n),devnet.LocalNetwork);self.assertTrue(n.alpha)
    def test_alpha_invoice_ready_marker_is_original_pinned_and_key_free(self):
        q=self.initialized()
        policy=dict(schema=2,format='1soft/protocol4-read-policy/v2',genesis_sha256=q['genesis_sha256'],
            anchor_height=1,anchor_hash='a'*64,anchor_time='2026-10-03T17:00:00Z',trust_period_seconds=3600,
            max_clock_drift_seconds=5,expected_block_version=11,checkpoint_progression=True,
            absolute_not_after_ns=1791133200000000000)
        devnet.private_new(self.root/'policy.json',encode(policy))
        marker=dict(schema=1,format='1soft/local-alpha-invoice-ready/v1',
            workspace_sha256=hashlib.sha256((self.root/'workspace.json').read_bytes()).hexdigest(),
            policy_sha256=hashlib.sha256(encode(policy)).hexdigest())
        devnet.private_new(self.root/'READY.json',encode(marker))
        with patch.object(devnet,'verify_engine',return_value=Path('/fixture-engine')):
            n=merchant_devnet.network_for_workspace(self.root,'/fixture-engine')
        with patch('offline_signer._load_vault',side_effect=AssertionError('must not unlock')):
            self.assertTrue(ready_for_browser(n))
        marker['policy_sha256']='0'*64;(self.root/'READY.json').write_bytes(encode(marker))
        with self.assertRaises(ValueError):ready_for_browser(n)
    def test_invoice_option_requires_explicit_alpha_before_any_workspace_creation(self):
        self.assertIn('invoice_commitments',inspect.signature(devnet.initialize).parameters)
        for enabled,profile in [(True,None),(1,'durable-private-alpha-v1'),('true','durable-private-alpha-v1')]:
            with patch.object(devnet,'verify_engine',side_effect=AssertionError('engine reached')):
                with self.assertRaises(ValueError):devnet.initialize(self.root,'/not-run',password=PASSWORD,
                    profile=profile,invoice_commitments=enabled)
            self.assertFalse(self.root.exists())
    def test_original_alpha_without_capability_cannot_open_invoice_browser(self):
        self.initialized(False)
        with patch.object(devnet,'verify_engine',return_value=Path('/fixture-engine')):
            n=merchant_devnet.network_for_workspace(self.root,'/fixture-engine')
        with self.assertRaises(ValueError):ready_for_browser(n)
    def test_relabelled_invoice_config_cannot_downgrade_to_generic_workspace(self):
        self.initialized();q=load_json((self.root/'workspace.json').read_bytes())
        q['format']='1soft/local-development-workspace/v1';(self.root/'workspace.json').write_bytes(encode(q))
        with self.assertRaises(ValueError):devnet.load_configuration(self.root)

if __name__=='__main__':unittest.main()
