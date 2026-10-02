"""Fresh-only merchant workspace safety; engine calls are explicit filesystem fixtures.

Encrypted development vaults and the native P4 ledger are real. Testnet/RPC and
checkpoint collection are substituted; none of these tests claim consensus.
"""
import base64
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from block_application import encode, snapshot
from commit_verifier import load_json
import local_devnet
from native_core import NativeLedger, address, canonical, public, sign
from offline_signer import _load_vault
from wallet_fixture import PASSWORD

try:
    import merchant_devnet as devnet
except ImportError:
    devnet = None

CONFIG = """proxy_app = ""
abci = "socket"
[rpc]
laddr = ""
unsafe = false
[p2p]
laddr = ""
persistent_peers = ""
addr_book_strict = true
allow_duplicate_ip = false
pex = true
[consensus]
timeout_commit = "1s"
[mempool]
max_tx_bytes = 1
"""


def fake_testnet(args, **kwargs):
    """Create only a fresh upstream config fixture, never launch an engine."""
    if args[1] != 'testnet':
        raise AssertionError('unexpected engine execution')
    assert args[2:6] == ['--v', '4', '--n', '0']
    nodes = Path(args[-1])
    validators = []
    for i in range(4):
        pk = bytes.fromhex(public(Ed25519PrivateKey.from_private_bytes(bytes([71+i])*32)))
        validators.append({'address': hashlib.sha256(pk).digest()[:20].hex().upper(),
            'pub_key': {'type': 'tendermint/PubKeyEd25519', 'value': base64.b64encode(pk).decode()},
            'power': '1', 'name': 'FIXTURE'})
    raw = encode({'validators': validators, 'consensus_params': {'block': {}}})
    for i in range(4):
        config = nodes / f'node{i}/config'
        config.mkdir(parents=True)
        for name, value in (('genesis.json', raw), ('config.toml', CONFIG.encode()),
                            ('node_key.json', b'{"fixture":"node"}'),
                            ('priv_validator_key.json', b'{"fixture":"validator"}')):
            (config / name).write_bytes(value)
    return None


class MerchantWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(devnet, 'fresh merchant devnet is missing')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.parent = Path(self.tmp.name); self.parent.chmod(0o700)
        self.root = self.parent / 'workspace'

    def initialized(self, count=3):
        with patch.object(devnet, 'verify_engine', return_value=Path('/fixture-engine')), \
             patch.object(devnet.subprocess, 'run', side_effect=fake_testnet), \
             patch.object(devnet.subprocess, 'check_output', side_effect=[(str(i)*40+'\n').encode() for i in range(4)]), \
             patch.object(devnet, 'free_ports', return_value=list(range(24000, 24008))):
            return devnet.initialize(self.root, '/fixture-engine', password=PASSWORD, recipient_count=count)

    def config(self): return load_json(local_devnet.read_private(self.root/'workspace.json'))
    def write_config(self, q): (self.root/'workspace.json').write_bytes(encode(q))
    def repin(self, q, name):
        q['files'][name] = hashlib.sha256(local_devnet.read_private(self.root/name)).hexdigest()
        self.write_config(q)

    def network(self):
        with patch.object(devnet, 'verify_engine', return_value=Path('/fixture-engine')):
            return devnet.MerchantNetwork(self.root, '/fixture-engine')

    def prepared_bootstrap(self):
        config = self.initialized()
        net = self.network(); net.lock = object()
        native = load_json(local_devnet.read_private(self.root/'app-genesis.json'))
        ledger = NativeLedger(':memory:', native); self.addCleanup(ledger.close)
        policy = {'schema': 1, 'format': '1soft/protocol4-read-policy/v1',
            'genesis_sha256': config['genesis_sha256'], 'anchor_height': 1,
            'anchor_hash': 'a'*64, 'anchor_time': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'trust_period_seconds': 3600, 'max_clock_drift_seconds': 5, 'expected_block_version': 11}
        local_devnet.private_new(self.root/'policy.json', encode(policy))
        submissions = {}
        def rpc(port, method, params):
            if method == 'broadcast_tx_sync':
                wire = base64.b64decode(params['tx'], validate=True)
                ledger.apply(load_json(wire), height=1)
                submissions[hashlib.sha256(wire).digest()] = wire
                return {'code': 0}
            if method == 'tx':
                wire = submissions[base64.b64decode(params['hash'], validate=True)]
                return {'tx_result': {'code': 0}, 'tx': base64.b64encode(wire).decode()}
            raise AssertionError('unexpected RPC')
        class Service:
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def import_checkpoint(self, proof, *, expected_tip): pass
            def sync(self, *, expected_revision): pass
        return net, ledger, submissions, rpc, Service()

    def test_fresh_pool_has_existing_zero_accounts_separate_protected_keys_and_supply(self):
        q = self.initialized()
        self.assertEqual(2, q['schema']); self.assertEqual(devnet.FORMAT, q['format'])
        self.assertEqual(3, len(set(q['merchant_recipients'])))
        self.assertEqual(q['merchant_recipients'][0], q['merchant'])
        self.assertEqual(q, devnet.load_configuration(self.root))
        g = load_json(local_devnet.read_private(self.root/'app-genesis.json'))
        self.assertEqual([1000, 0, 0, 0], [a['units'] for a in g['allocations']])
        ledger = NativeLedger(':memory:', g)
        try:
            for recipient in q['merchant_recipients']: self.assertEqual(0, ledger.balance(recipient))
            self.assertEqual(1000, sum(a['balance'] for a in ledger.state()['accounts']))
        finally: ledger.close()

    def test_recipient_vaults_match_genesis_and_no_unencrypted_key_is_written(self):
        q = self.initialized(2)
        keys = load_json(local_devnet.read_private(self.root/'development-keys.json'))
        self.assertEqual({'owner', 'raven', 'atlas', 'admin0', 'admin1', 'admin2', 'admin3',
                          'merchant0', 'merchant1'}, set(keys))
        for i, recipient in enumerate(q['merchant_recipients']):
            vault = self.root/f'merchant{i}.pem'
            self.assertEqual(0o600, vault.stat().st_mode & 0o777)
            self.assertTrue(vault.read_bytes().startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----'))
            self.assertEqual(keys[f'merchant{i}'], public(_load_vault(vault, PASSWORD)))
            self.assertEqual(recipient, address(keys[f'merchant{i}']))

    def test_pool_bound_and_boolean_count_refused_before_files_or_engine(self):
        for count in (1, 17, True, '3', 3.0):
            with self.subTest(count=count), patch.object(devnet, 'verify_engine', side_effect=AssertionError('engine reached')):
                with self.assertRaises(ValueError):
                    devnet.initialize(self.root, '/not-run', password=PASSWORD, recipient_count=count)
            self.assertFalse(self.root.exists())

    def test_existing_workspace_and_bad_password_never_change_valuable_bytes(self):
        self.root.mkdir(mode=0o700); local_devnet.private_new(self.root/'valuable', b'retained')
        with patch.object(devnet, 'verify_engine', return_value=Path('/fixture-engine')):
            with self.assertRaises(ValueError): devnet.initialize(self.root, '/fixture-engine', password=PASSWORD)
        self.assertEqual(b'retained', (self.root/'valuable').read_bytes())
        fresh = self.parent/'bad-password'
        with patch.object(devnet, 'verify_engine', side_effect=AssertionError('engine reached')):
            with self.assertRaises(ValueError): devnet.initialize(fresh, '/not-run', password=b'short')
        self.assertFalse(fresh.exists())

    def test_partial_engine_initialization_is_retained_and_cannot_be_reinitialized(self):
        with patch.object(devnet, 'verify_engine', return_value=Path('/fixture-engine')), \
             patch.object(devnet.subprocess, 'run', side_effect=RuntimeError('fixture failure')):
            with self.assertRaises(RuntimeError): devnet.initialize(self.root, '/fixture-engine', password=PASSWORD)
        saved = (self.root/'owner.pem').read_bytes()
        self.assertFalse((self.root/'workspace.json').exists())
        with self.assertRaises((ValueError, OSError)): devnet.load_configuration(self.root)
        with patch.object(devnet, 'verify_engine', return_value=Path('/fixture-engine')):
            with self.assertRaises(ValueError): devnet.initialize(self.root, '/fixture-engine', password=PASSWORD)
        self.assertEqual(saved, (self.root/'owner.pem').read_bytes())

    def test_v1_loader_refuses_v2_without_mutating_files(self):
        self.initialized(); original = (self.root/'workspace.json').read_bytes()
        with self.assertRaises(ValueError): local_devnet.load_configuration(self.root)
        self.assertEqual(original, (self.root/'workspace.json').read_bytes())

    def test_long_lived_network_refuses_repin_before_ready_policy_service_or_start(self):
        self.initialized(); net = self.network()
        config = self.config(); config['ports'] = list(range(25000, 25008))
        config['endpoint'] = 'http://127.0.0.1:25004/'
        self.write_config(config)
        for method in ('ready', 'policy', 'service', 'start'):
            with self.subTest(method=method), patch.object(local_devnet.subprocess, 'Popen', side_effect=AssertionError('process reached')):
                with self.assertRaises(ValueError): getattr(net, method)()

    def test_long_lived_network_refuses_changed_pinned_file_before_key_access(self):
        self.initialized(); net = self.network(); net.lock = object()
        (self.root/'merchant0.pem').write_bytes(b'changed encrypted key fixture')
        with patch.object(devnet, '_load_vault', side_effect=AssertionError('key reached')):
            with self.assertRaises(ValueError): net.bootstrap(password=PASSWORD)

    def test_engine_pin_is_reverified_before_any_owned_start(self):
        self.initialized(); net = self.network()
        with patch.object(devnet, 'verify_engine', side_effect=ValueError('engine changed after construction')) as verify, \
             patch.object(local_devnet.subprocess, 'Popen', side_effect=AssertionError('process reached')):
            with self.assertRaises(ValueError): net.start()
        verify.assert_called_once_with(net.binary)

    def test_in_memory_config_mutation_and_valid_new_genesis_repin_refuse(self):
        self.initialized(); net = self.network()
        net.config['merchant'] = net.config['merchant_recipients'][1]
        with self.assertRaises(ValueError): net.ready()
        net.config = self.config()
        q = self.config(); g = load_json((self.root/'app-genesis.json').read_bytes())
        g['chain_id'] = '1soft-dev-repinned'; g['validator_registry']['chain_id'] = g['chain_id']
        engine = load_json((self.root/'engine-genesis.json').read_bytes())
        engine['chain_id'] = g['chain_id']; engine['app_state'] = g; full = encode(engine)
        (self.root/'app-genesis.json').write_bytes(encode(g)); (self.root/'engine-genesis.json').write_bytes(full)
        q['chain_id'] = g['chain_id']; q['native_sha256'] = hashlib.sha256(encode(g)).hexdigest()
        q['genesis_sha256'] = hashlib.sha256(full).hexdigest()
        q['files']['app-genesis.json'] = q['native_sha256']; q['files']['engine-genesis.json'] = q['genesis_sha256']
        for i in range(4):
            name = f'nodes/node{i}/config/genesis.json'; (self.root/name).write_bytes(full)
            q['files'][name] = q['genesis_sha256']
        self.write_config(q)
        self.assertEqual(q, devnet.load_configuration(self.root))
        with self.assertRaises(ValueError): net.ready()

    def test_long_lived_network_refuses_policy_and_ready_repin_without_trust_renewal(self):
        net, ledger, submissions, rpc, svc = self.prepared_bootstrap()
        with patch.object(devnet, 'rpc', side_effect=rpc), \
             patch.object(devnet, 'genesis_native', side_effect=lambda _: snapshot(ledger)), \
             patch.object(devnet, 'collect_evidence', return_value={'evidence': {}}), patch.object(net, 'service', return_value=svc):
            net.bootstrap(password=PASSWORD)
        policy = load_json((self.root/'policy.json').read_bytes()); policy['max_clock_drift_seconds'] = 4
        (self.root/'policy.json').write_bytes(encode(policy))
        ready = load_json((self.root/'READY.json').read_bytes())
        ready['policy_sha256'] = hashlib.sha256(encode(policy)).hexdigest()
        (self.root/'READY.json').write_bytes(encode(ready))
        net.lock = None
        with patch.object(local_devnet, 'PlatformService', return_value=object()), \
             patch.object(local_devnet.subprocess, 'Popen', side_effect=AssertionError('process reached')):
            for method in ('ready', 'policy', 'service', 'start'):
                with self.subTest(method=method):
                    with self.assertRaises(ValueError): getattr(net, method)()

    def test_manifest_membership_file_bytes_and_public_key_identity_are_strict(self):
        self.initialized(); original = self.config()
        vault = (self.root/'merchant0.pem').read_bytes()
        inventory = (self.root/'development-keys.json').read_bytes()
        for mode in ('removed-pin', 'extra-pin', 'changed-vault', 'changed-public-key'):
            with self.subTest(mode=mode):
                q = load_json(encode(original))
                if mode == 'removed-pin': del q['files']['merchant0.pem']
                elif mode == 'extra-pin': q['files']['unexpected'] = 'a'*64
                elif mode == 'changed-vault':
                    (self.root/'merchant0.pem').write_bytes(b'wrong fixture')
                else:
                    keys = load_json(local_devnet.read_private(self.root/'development-keys.json'))
                    keys['merchant0'] = keys['merchant1']
                    (self.root/'development-keys.json').write_bytes(encode(keys))
                    q['files']['development-keys.json'] = hashlib.sha256((self.root/'development-keys.json').read_bytes()).hexdigest()
                self.write_config(q)
                with self.assertRaises(ValueError): devnet.load_configuration(self.root)
                (self.root/'merchant0.pem').write_bytes(vault)
                (self.root/'development-keys.json').write_bytes(inventory)

    def test_duplicate_reordered_unknown_pool_and_noncanonical_configuration_refused(self):
        self.initialized(); original = self.config()
        for pool in ([original['merchant']]*3, list(reversed(original['merchant_recipients'])),
                     ['lab_'+'a'*64, *original['merchant_recipients'][1:]]):
            q = load_json(encode(original)); q['merchant_recipients'] = pool; self.write_config(q)
            with self.assertRaises(ValueError): devnet.load_configuration(self.root)
        (self.root/'workspace.json').write_bytes(encode(original)+b'\n')
        with self.assertRaises(ValueError): devnet.load_configuration(self.root)

    def test_nonzero_pool_allocation_or_extra_genesis_account_refused_even_when_repinned(self):
        self.initialized(); q = self.config()
        g = load_json(local_devnet.read_private(self.root/'app-genesis.json'))
        g['allocations'][1]['units'] = 1
        engine = load_json(local_devnet.read_private(self.root/'engine-genesis.json')); engine['app_state'] = g
        (self.root/'app-genesis.json').write_bytes(encode(g)); (self.root/'engine-genesis.json').write_bytes(encode(engine))
        q['native_sha256'] = hashlib.sha256(encode(g)).hexdigest()
        q['genesis_sha256'] = hashlib.sha256(encode(engine)).hexdigest()
        q['files']['app-genesis.json'] = q['native_sha256']; q['files']['engine-genesis.json'] = q['genesis_sha256']
        self.write_config(q)
        with self.assertRaises(ValueError): devnet.load_configuration(self.root)

    def test_public_rpc_or_changed_node_genesis_refused_even_when_repinned(self):
        self.initialized(); q = self.config()
        name = 'nodes/node0/config/config.toml'; conf = self.root/name
        conf.write_bytes(conf.read_bytes().replace(b'127.0.0.1:24004', b'0.0.0.0:24004'))
        self.repin(q, name)
        with self.assertRaises(ValueError): devnet.load_configuration(self.root)

    def test_dispatch_uses_exact_format_and_never_falls_back_after_v2_failure(self):
        self.initialized()
        with patch.object(devnet, 'verify_engine', return_value=Path('/fixture-engine')):
            self.assertIsInstance(devnet.network_for_workspace(self.root, '/fixture-engine'), devnet.MerchantNetwork)
        with patch.object(devnet, 'MerchantNetwork', side_effect=ValueError('bad v2')), \
             patch.object(devnet, 'LocalNetwork', side_effect=AssertionError('v1 fallback')):
            with self.assertRaises(ValueError): devnet.network_for_workspace(self.root, '/fixture-engine')
        q = self.config(); q['format'] = local_devnet.FORMAT; q['schema'] = 1
        self.write_config(q)
        marker = object()
        with patch.object(devnet, 'LocalNetwork', return_value=marker):
            self.assertIs(marker, devnet.network_for_workspace(self.root, '/fixture-engine'))

    def test_unknown_or_duplicate_format_refused_before_network_creation(self):
        self.root.mkdir(mode=0o700)
        for raw in (b'{"schema":2,"format":"unsupported"}',
                    b'{"format":"1soft/local-development-workspace/v1","format":"1soft/local-development-workspace/v2"}'):
            (self.root/'workspace.json').write_bytes(raw); (self.root/'workspace.json').chmod(0o600)
            with patch.object(devnet, 'LocalNetwork', side_effect=AssertionError('network reached')), \
                 patch.object(devnet, 'MerchantNetwork', side_effect=AssertionError('network reached')):
                with self.assertRaises(ValueError): devnet.network_for_workspace(self.root, '/not-run')

    def test_three_native_setup_ops_authorize_full_pool_and_preserve_conservation(self):
        net, ledger, submissions, rpc, svc = self.prepared_bootstrap()
        with patch.object(devnet, 'rpc', side_effect=rpc), \
             patch.object(devnet, 'genesis_native', side_effect=lambda _: snapshot(ledger)), \
             patch.object(devnet, 'collect_evidence', return_value={'evidence': {}}), \
             patch.object(net, 'service', return_value=svc):
            result = net.bootstrap(password=PASSWORD)
        self.assertEqual(3, len(submissions)); self.assertTrue(net.ready())
        packets = [load_json((self.root/f'setup-{i}.json').read_bytes()) for i in range(3)]
        self.assertEqual(['budget_create', 'grant', 'grant'], [p['body']['op']['type'] for p in packets])
        self.assertEqual([0, 1, 2], [p['body']['nonce'] for p in packets])
        for packet in packets: self.assertEqual(net.config['merchant_recipients'], packet['body']['op']['recipients'])
        self.assertEqual(994, ledger.balance(net.config['roles']['owner']['payer']))
        self.assertEqual(1000, sum(a['balance'] for a in ledger.state()['accounts']))
        self.assertFalse(result['trust_renewed'])

    def test_ready_restart_is_key_free_and_does_not_renew_policy_resign_or_resend(self):
        net, ledger, submissions, rpc, svc = self.prepared_bootstrap()
        with patch.object(devnet, 'rpc', side_effect=rpc), \
             patch.object(devnet, 'genesis_native', side_effect=lambda _: snapshot(ledger)), \
             patch.object(devnet, 'collect_evidence', return_value={'evidence': {}}), patch.object(net, 'service', return_value=svc):
            net.bootstrap(password=PASSWORD)
        policy = (self.root/'policy.json').read_bytes()
        with patch.object(devnet, '_load_vault', side_effect=AssertionError('unlock reached')), \
             patch.object(devnet, 'sign', side_effect=AssertionError('sign reached')), \
             patch.object(devnet, 'rpc', side_effect=AssertionError('RPC reached')):
            self.assertFalse(net.bootstrap(password=None)['trust_renewed'])
        self.assertEqual(policy, (self.root/'policy.json').read_bytes())

    def test_saved_claims_recover_by_exact_observation_without_unlock_sign_or_broadcast(self):
        net, ledger, submissions, rpc, svc = self.prepared_bootstrap()
        with patch.object(devnet, 'rpc', side_effect=rpc), \
             patch.object(devnet, 'genesis_native', side_effect=lambda _: snapshot(ledger)), \
             patch.object(devnet, 'collect_evidence', return_value={'evidence': {}}), \
             patch.object(net, 'service', side_effect=RuntimeError('stop before journal creation')):
            with self.assertRaises(RuntimeError): net.bootstrap(password=PASSWORD)
        self.assertEqual(3, len(submissions)); saved = {i: (self.root/f'setup-{i}.json').read_bytes() for i in range(3)}
        def observation(port, method, params):
            self.assertEqual('tx', method); return rpc(port, method, params)
        with patch.object(devnet, 'rpc', side_effect=observation), \
             patch.object(devnet, '_load_vault', side_effect=AssertionError('unlock reached')), \
             patch.object(devnet, 'sign', side_effect=AssertionError('sign reached')), \
             patch.object(devnet, 'collect_evidence', return_value={'evidence': {}}), patch.object(net, 'service', return_value=svc):
            net.bootstrap(password=PASSWORD)
        self.assertEqual(saved, {i: (self.root/f'setup-{i}.json').read_bytes() for i in range(3)})

    def test_claim_without_wire_and_partial_journal_sidecar_are_retained_fail_closed(self):
        self.initialized(); net = self.network(); net.lock = object()
        local_devnet.private_new(self.root/'setup-0.claim', b'a'*64)
        with patch.object(devnet, '_load_vault', side_effect=AssertionError('unlock reached')), \
             patch.object(devnet, 'rpc', side_effect=AssertionError('RPC reached')):
            with self.assertRaises(ValueError): net.bootstrap(password=PASSWORD)
        self.assertFalse((self.root/'setup-0.json').exists())
        local_devnet.private_new(self.root/'wallet.sqlite-wal', b'retained sidecar')
        with patch.object(devnet, '_load_vault', side_effect=AssertionError('unlock reached')):
            with self.assertRaises(ValueError): net.bootstrap(password=PASSWORD)
        self.assertEqual(b'retained sidecar', (self.root/'wallet.sqlite-wal').read_bytes())

    def test_unknown_setup_claim_is_not_rebroadcast_and_does_not_create_journals(self):
        self.initialized(); net = self.network(); net.lock = object()
        native = load_json((self.root/'app-genesis.json').read_bytes())
        ledger = NativeLedger(':memory:', native); self.addCleanup(ledger.close)
        calls = []
        def rpc(port, method, params):
            calls.append(method)
            if method == 'broadcast_tx_sync': return {'code': 0}
            raise ValueError('unavailable')
        with patch.object(devnet, 'rpc', side_effect=rpc), \
             patch.object(devnet, 'genesis_native', return_value=snapshot(ledger)), \
             patch.object(devnet, 'wait', side_effect=lambda predicate, seconds: predicate()):
            with self.assertRaises(ValueError): net.bootstrap(password=PASSWORD)
        wire = (self.root/'setup-0.json').read_bytes()
        with patch.object(devnet, 'rpc', side_effect=rpc), \
             patch.object(devnet, 'sign', side_effect=AssertionError('sign reached')), \
             patch.object(devnet, 'wait', side_effect=lambda predicate, seconds: predicate()):
            with self.assertRaises(ValueError): net.bootstrap(password=PASSWORD)
        self.assertEqual(1, calls.count('broadcast_tx_sync'))
        self.assertEqual(wire, (self.root/'setup-0.json').read_bytes())
        self.assertFalse((self.root/'wallet.sqlite').exists()); self.assertFalse((self.root/'READY.json').exists())

    def test_saved_signature_context_or_claim_tampering_never_unlocks_resigns_or_sends(self):
        self.initialized(); net = self.network(); net.lock = object()
        g = load_json((self.root/'app-genesis.json').read_bytes())
        ledger = NativeLedger(':memory:', g); self.addCleanup(ledger.close)
        owner = _load_vault(self.root/'owner.pem', PASSWORD)
        op = {'type': 'budget_create', 'id': 'studio', 'cap': 100, 'expires': 500,
              'recipients': net.config['merchant_recipients']}
        packet = sign(owner, ledger.body(net.config['roles']['owner']['payer'], 0, op, valid_until=100))
        original = canonical(packet)
        for mode in ('signature', 'genesis', 'claim'):
            with self.subTest(mode=mode):
                changed = load_json(original)
                if mode == 'signature': changed['signature'] = ('0' if changed['signature'][0] != '0' else '1')+changed['signature'][1:]
                elif mode == 'genesis':
                    changed['body']['genesis_hash'] = '0'*64; changed = sign(owner, changed['body'])
                wire = canonical(changed)
                (self.root/'setup-0.json').write_bytes(wire); (self.root/'setup-0.json').chmod(0o600)
                claim = ('0'*64 if mode == 'claim' else hashlib.sha256(wire).hexdigest()).encode()
                (self.root/'setup-0.claim').write_bytes(claim); (self.root/'setup-0.claim').chmod(0o600)
                with patch.object(devnet, '_load_vault', side_effect=AssertionError('unlock reached')), \
                     patch.object(devnet, 'sign', side_effect=AssertionError('sign reached')), \
                     patch.object(devnet, 'rpc', side_effect=AssertionError('send reached')):
                    with self.assertRaises(ValueError): net.bootstrap(password=PASSWORD)
                self.assertEqual(wire, (self.root/'setup-0.json').read_bytes())
                self.assertEqual(claim, (self.root/'setup-0.claim').read_bytes())
        self.assertFalse((self.root/'wallet.sqlite').exists())

    def test_maximum_pool_is_valid_and_fixed_policy_expiry_refuses_without_recreation(self):
        q = self.initialized(16)
        self.assertEqual(16, len(q['merchant_recipients']))
        self.assertEqual(q, devnet.load_configuration(self.root))
        net = self.network(); now = datetime.now(timezone.utc)
        policy = {'schema': 1, 'format': '1soft/protocol4-read-policy/v1',
            'genesis_sha256': q['genesis_sha256'], 'anchor_height': 1, 'anchor_hash': 'a'*64,
            'anchor_time': now.isoformat().replace('+00:00', 'Z'), 'trust_period_seconds': 1,
            'max_clock_drift_seconds': 5, 'expected_block_version': 11}
        local_devnet.private_new(self.root/'policy.json', encode(policy))
        local_devnet.private_new(self.root/'READY.json', encode({'schema': 2, 'format': devnet.READY_FORMAT,
            'workspace_sha256': hashlib.sha256((self.root/'workspace.json').read_bytes()).hexdigest(),
            'policy_sha256': hashlib.sha256(encode(policy)).hexdigest()}))
        net.clock = lambda: int(now.timestamp()*10**9)+2*10**9
        net.lock = object(); original = (self.root/'policy.json').read_bytes()
        with patch.object(devnet, '_load_vault', side_effect=AssertionError('unlock reached')):
            with self.assertRaises(ValueError): net.bootstrap(password=PASSWORD)
        self.assertEqual(original, (self.root/'policy.json').read_bytes())


if __name__ == '__main__': unittest.main()
