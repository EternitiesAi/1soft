"""Fresh capability workspaces; upstream initialization is a filesystem fixture."""
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch
from block_application import encode
from commit_verifier import load_json
import merchant_devnet as devnet
import local_devnet
import test_merchant_devnet as fixture
from wallet_fixture import PASSWORD

class InvoiceWorkspaceTests(unittest.TestCase):
    setUp=fixture.MerchantWorkspaceTests.setUp
    config=fixture.MerchantWorkspaceTests.config
    write_config=fixture.MerchantWorkspaceTests.write_config
    network=fixture.MerchantWorkspaceTests.network

    def initialized(self,enabled=True):
        with patch.object(devnet,'verify_engine',return_value=Path('/fixture-engine')), \
             patch.object(devnet.subprocess,'run',side_effect=fixture.fake_testnet), \
             patch.object(devnet.subprocess,'check_output',side_effect=[(str(i)*40+'\n').encode() for i in range(4)]), \
             patch.object(devnet,'free_ports',return_value=list(range(24000,24008))):
            return devnet.initialize(self.root,'/fixture-engine',password=PASSWORD,
                recipient_count=3,invoice_commitments=enabled)

    def repin_capability(self,capability):
        q=self.config();g=load_json((self.root/'app-genesis.json').read_bytes())
        if capability is None:g.pop('invoice_commitment_version',None)
        else:g['invoice_commitment_version']=capability
        engine=load_json((self.root/'engine-genesis.json').read_bytes());engine['app_state']=g
        full=encode(engine);native=encode(g)
        (self.root/'app-genesis.json').write_bytes(native);(self.root/'engine-genesis.json').write_bytes(full)
        q['native_sha256']=hashlib.sha256(native).hexdigest();q['genesis_sha256']=hashlib.sha256(full).hexdigest()
        q['files']['app-genesis.json']=q['native_sha256'];q['files']['engine-genesis.json']=q['genesis_sha256']
        for i in range(4):
            name=f'nodes/node{i}/config/genesis.json';(self.root/name).write_bytes(full)
            q['files'][name]=q['genesis_sha256']
        self.write_config(q)

    def test_explicit_fresh_v3_capability_and_exact_dispatch(self):
        q=self.initialized();self.assertEqual(q['schema'],3)
        self.assertEqual(q['format'],'1soft/local-development-workspace/v3')
        g=load_json((self.root/'app-genesis.json').read_bytes())
        self.assertEqual(g['invoice_commitment_version'],1)
        self.assertEqual(q,devnet.load_configuration(self.root))
        with patch.object(devnet,'verify_engine',return_value=Path('/fixture-engine')):
            self.assertIsInstance(devnet.network_for_workspace(self.root,'/fixture-engine'),devnet.MerchantNetwork)
        with self.assertRaises(ValueError):local_devnet.load_configuration(self.root)

    def test_default_v2_is_unchanged_and_has_no_capability(self):
        q=self.initialized(False);self.assertEqual(q['schema'],2)
        self.assertEqual(q['format'],devnet.FORMAT)
        self.assertNotIn('invoice_commitment_version',load_json((self.root/'app-genesis.json').read_bytes()))

    def test_non_boolean_option_refused_before_engine_or_files(self):
        for enabled in (1,'1',None,[]):
            with self.subTest(enabled=enabled),patch.object(devnet,'verify_engine',side_effect=AssertionError('engine reached')):
                with self.assertRaises(ValueError):
                    devnet.initialize(self.root,'/not-run',password=PASSWORD,invoice_commitments=enabled)
            self.assertFalse(self.root.exists())

    def test_v2_repin_cannot_enable_native_capability(self):
        self.initialized(False);self.repin_capability(1)
        with self.assertRaisesRegex(ValueError,'capability'):devnet.load_configuration(self.root)

    def test_v3_repin_cannot_remove_native_capability(self):
        self.initialized();self.repin_capability(None)
        with self.assertRaisesRegex(ValueError,'capability'):devnet.load_configuration(self.root)

    def test_cli_capability_is_explicit_and_only_on_init(self):
        import test_merchant_network_cli as cli_fixture
        cli=cli_fixture.CLI
        args=cli.parser().parse_args(['init','--workspace',str(self.root),'--engine','/fixture-engine','--invoice-commitments'])
        q={'genesis_sha256':'a'*64,'endpoint':'http://127.0.0.1:24004/','merchant_recipients':['b'*64,'c'*64]}
        with patch.object(cli,'password',return_value=PASSWORD),patch.object(cli,'initialize',return_value=q) as initialize:
            cli.execute(args)
        initialize.assert_called_once_with(self.root,Path('/fixture-engine'),password=PASSWORD,recipient_count=3,invoice_commitments=True)
        with self.assertRaises(SystemExit):
            cli.parser().parse_args(['run','--workspace',str(self.root),'--engine','/fixture-engine','--invoice-commitments'])

if __name__=='__main__':unittest.main()
