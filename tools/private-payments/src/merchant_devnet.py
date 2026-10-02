"""Fresh private P4 devnet with a finite genesis recipient pool.

This separately versioned initializer reuses local_devnet's pinned-engine,
private-file and owned-process primitives. It never rewrites a v1 workspace.
All keys are disposable development keys; encrypted PKCS8 is software custody,
with no hostile-host protection, memory zeroization or production recovery claim.
"""
import base64
import hashlib
import os
from pathlib import Path
import re
import subprocess
import time
import tomllib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from block_application import encode, restore
from commit_verifier import header_hash, load_json
from local_devnet import (LocalNetwork, ROOT, PIN_SHA, private_new, read_private,
                          verify_engine, rpc, wait, genesis_native)
from native_core import BODY_FIELDS, DOMAIN, address, canonical, digest, public, pubkey, sign
from offline_signer import create_vault, _load_vault, _password
from p4_delivery import collect_evidence
from p4_evidence import check_clock, hash_text, integer, need, p4_genesis, policy_checked
from p4_read_store import private_path
from registry_rules_core import GENESIS_FORMAT
from run_devnet import free_ports, patch_toml
from validator_sets_core import canonical_roster

FORMAT = '1soft/local-development-workspace/v2'
READY_FORMAT = '1soft/local-development-ready/v2'
INVOICE_FORMAT = '1soft/local-development-workspace/v3'
INVOICE_READY_FORMAT = '1soft/local-development-ready/v3'
MIN_RECIPIENTS = 2
MAX_RECIPIENTS = 16
PUBLIC_KEYS_FILE = 'development-keys.json'
FINANCIAL_JOURNALS = ('wallet', 'delivery', 'ledger', 'requests', 'receipts')


def _count(value):
    return integer(value, MIN_RECIPIENTS, MAX_RECIPIENTS)


def _key_names(count):
    _count(count)
    return ('owner', 'raven', 'atlas', 'admin0', 'admin1', 'admin2', 'admin3',
            *(f'merchant{i}' for i in range(count)))


def immutable_names(recipient_count):
    names = {'app-genesis.json', 'engine-genesis.json', PUBLIC_KEYS_FILE,
             *(name+'.pem' for name in _key_names(recipient_count))}
    for i in range(4):
        names.update(f'nodes/node{i}/config/'+name for name in
                     ('config.toml', 'genesis.json', 'node_key.json', 'priv_validator_key.json'))
    return names


def _public_keys(root, count):
    raw = read_private(root/PUBLIC_KEYS_FILE, 4096)
    keys = load_json(raw, max_bytes=4096)
    need(type(keys) is dict and set(keys) == set(_key_names(count)) and encode(keys) == raw,
         'development public key inventory differs')
    for key in keys.values(): pubkey(key)
    need(len(set(keys.values())) == len(keys), 'development keys must be distinct')
    return keys


def initialize(workspace, engine, *, password, recipient_count=3, invoice_commitments=False):
    """Create a new private dev workspace only; partial output is never repaired."""
    need(type(invoice_commitments) is bool, 'explicit boolean invoice capability required')
    count = _count(recipient_count); _password(password)
    root = Path(workspace).absolute()
    need(not root.is_relative_to(ROOT), 'development workspace must be outside source')
    need(os.name == 'posix' and len(os.fsencode(root/'app0/a.sock')) < 100,
         'private POSIX workspace path required, at most 85 bytes')
    need(not root.exists() and not root.is_symlink(), 'workspace exists; no overwrite or reset')
    binary = verify_engine(engine)
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    private_path(root/'owner.lock'); private_new(root/'owner.lock', b'')
    keys = {name: create_vault(root/(name+'.pem'), password) for name in _key_names(count)}
    need(len(set(keys.values())) == len(keys), 'development keys must be distinct')
    private_new(root/PUBLIC_KEYS_FILE, encode(keys))
    nodes = root/'nodes'
    subprocess.run([str(binary), 'testnet', '--v', '4', '--n', '0', '--o', str(nodes)],
                   check=True, capture_output=True, timeout=40, umask=0o077)
    nodes.chmod(0o700)
    for p in nodes.rglob('*'): p.chmod(0o700 if p.is_dir() else 0o600)
    engine_genesis = load_json(read_private(nodes/'node0/config/genesis.json'))
    initial = engine_genesis['validators']
    need(type(initial) is list and len(initial) == 4, 'exactly four initial validators required')
    for row in initial: row['power'] = '10'
    roster = canonical_roster([{'public_key': base64.b64decode(row['pub_key']['value'], validate=True).hex(),
                               'power': 10} for row in initial])
    chain = '1soft-dev-'+os.urandom(6).hex(); payer = address(keys['owner'])
    recipients = [address(keys[f'merchant{i}']) for i in range(count)]
    registry = {'schema': 1, 'format': GENESIS_FORMAT, 'mode': 'development-only', 'chain_id': chain,
        'validators': roster, 'administrators': {'format': 'threshold-ed25519-v1',
        'public_keys': sorted(keys[f'admin{i}'] for i in range(4)), 'threshold': 3},
        'minimum_delay_blocks': 2, 'cooldown_blocks': 1, 'minimum_validators': 4, 'maximum_power_bps': 3333}
    genesis = {'chain_id': chain, 'asset': 'DEV', 'fee': 2, 'protocol_version': 4,
        'allocations': [{'public_key': keys['owner'], 'units': 1000},
                       *({'public_key': keys[f'merchant{i}'], 'units': 0} for i in range(count))],
        'validator_registry': registry}
    if invoice_commitments: genesis['invoice_commitment_version'] = 1
    private_new(root/'app-genesis.json', encode(genesis))
    engine_genesis.update(chain_id=chain, initial_height='1', app_state=genesis, validators=initial)
    engine_genesis['consensus_params']['block'].update(max_bytes='1048576', max_gas='-1')
    full = encode(engine_genesis); private_new(root/'engine-genesis.json', full)
    ports = free_ports(8); p2p = ports[:4]; http = ports[4:]
    ids = [subprocess.check_output([str(binary), 'show-node-id', '--home', str(nodes/f'node{i}')],
            timeout=10).decode('ascii').strip() for i in range(4)]
    need(all(re.fullmatch('[0-9a-f]{40}', value) for value in ids) and len(set(ids)) == 4,
         'distinct development node identities required')
    for i in range(4):
        app = root/f'app{i}'; app.mkdir(mode=0o700); sock = app/'a.sock'; home = nodes/f'node{i}'
        (home/'config/genesis.json').write_bytes(full)
        conf = home/'config/config.toml'
        conf.write_text(patch_toml(read_private(conf).decode('utf-8'), {
            'proxy_app': f'unix://{sock}', 'abci': 'socket', 'rpc.laddr': f'tcp://127.0.0.1:{http[i]}',
            'rpc.unsafe': False, 'p2p.laddr': f'tcp://127.0.0.1:{p2p[i]}',
            'p2p.persistent_peers': ','.join(f'{ids[j]}@127.0.0.1:{p2p[j]}' for j in range(4) if j != i),
            'p2p.addr_book_strict': False, 'p2p.allow_duplicate_ip': True, 'p2p.pex': False,
            'consensus.timeout_commit': '4s', 'mempool.max_tx_bytes': 65536}), encoding='utf-8')
    roles = {name: dict(payer=payer, grant_id='' if name == 'owner' else name, vault=name+'.pem')
             for name in ('owner', 'raven', 'atlas')}
    config = {'schema': 3 if invoice_commitments else 2,
        'format': INVOICE_FORMAT if invoice_commitments else FORMAT, 'chain_id': chain,
        'genesis_sha256': hashlib.sha256(full).hexdigest(),
        'native_sha256': hashlib.sha256(encode(genesis)).hexdigest(), 'engine_sha256': PIN_SHA,
        'ports': ports, 'endpoint': f'http://127.0.0.1:{http[0]}/', 'roles': roles,
        'merchant': recipients[0], 'merchant_recipients': recipients,
        'files': {name: hashlib.sha256(read_private(root/name)).hexdigest()
                  for name in sorted(immutable_names(count))}}
    private_new(root/'workspace.json', encode(config))
    return load_configuration(root)


def _node_configuration(root, q, full):
    """Pins do not permit a re-pinned public listener or a divergent node genesis."""
    identities = {}
    for i in range(4):
        home = root/f'nodes/node{i}/config'
        need(read_private(home/'genesis.json') == full, 'node genesis differs')
        conf = tomllib.loads(read_private(home/'config.toml').decode('utf-8'))
        need(conf.get('proxy_app') == f'unix://{root}/app{i}/a.sock' and conf.get('abci') == 'socket' and
             conf.get('rpc', {}).get('laddr') == f'tcp://127.0.0.1:{q["ports"][4+i]}' and
             conf.get('rpc', {}).get('unsafe') is False and
             conf.get('p2p', {}).get('laddr') == f'tcp://127.0.0.1:{q["ports"][i]}' and
             conf.get('p2p', {}).get('pex') is False and
             conf.get('p2p', {}).get('addr_book_strict') is False and
             conf.get('p2p', {}).get('allow_duplicate_ip') is True and
             conf.get('consensus', {}).get('timeout_commit') == '4s' and
             type(conf.get('mempool', {}).get('max_tx_bytes')) is int and
             conf['mempool']['max_tx_bytes'] == 65536, 'private node configuration differs')
        peers = conf['p2p'].get('persistent_peers')
        need(type(peers) is str, 'fixed loopback peer roster required')
        rows = peers.split(','); need(len(rows) == 3, 'fixed loopback peer roster required')
        observed = {}
        for row in rows:
            match = re.fullmatch('([0-9a-f]{40})@127[.]0[.]0[.]1:([0-9]{1,5})', row)
            need(match is not None, 'non-loopback development peer refused')
            port = integer(int(match[2]), 1, 65535)
            need(port not in observed, 'duplicate development peer')
            observed[port] = match[1]
            need(port not in identities or identities[port] == match[1], 'development peer identity differs')
            identities[port] = match[1]
        need(set(observed) == set(q['ports'][:4])-{q['ports'][i]}, 'fixed loopback peer ports differ')
    need(len(identities) == 4 and len(set(identities.values())) == 4, 'development peer identities differ')


def load_configuration(workspace):
    root = Path(workspace).absolute(); raw = read_private(root/'workspace.json')
    q = load_json(raw)
    need(type(q) is dict and set(q) == {'schema', 'format', 'chain_id', 'genesis_sha256', 'native_sha256',
         'engine_sha256', 'ports', 'endpoint', 'roles', 'merchant', 'merchant_recipients', 'files'} and
         type(q['schema']) is int and (q['schema'], q['format']) in
         ((2, FORMAT), (3, INVOICE_FORMAT)) and encode(q) == raw,
         'merchant workspace configuration differs')
    pool = q['merchant_recipients']; need(type(pool) is list, 'bounded ordered recipient pool required')
    count = _count(len(pool))
    need(q['engine_sha256'] == PIN_SHA and type(q['ports']) is list and len(q['ports']) == 8,
         'workspace engine/ports differ')
    for port in q['ports']: integer(port, 1, 65535)
    need(len(set(q['ports'])) == 8 and q['endpoint'] == f'http://127.0.0.1:{q["ports"][4]}/',
         'workspace loopback endpoint/ports differ')
    need(type(q['files']) is dict and set(q['files']) == immutable_names(count),
         'workspace immutable file list differs')
    for name, value in q['files'].items():
        hash_text(value)
        need(hashlib.sha256(read_private(root/name)).hexdigest() == value, 'workspace immutable file changed')
    keys = _public_keys(root, count)
    full = read_private(root/'engine-genesis.json')
    g, _ = p4_genesis(full, q['genesis_sha256'])
    need(encode(load_json(full)) == full and g['asset'] == 'DEV' and g['chain_id'] == q['chain_id'] and
         g['fee'] == 2 and g['protocol_version'] == 4, 'development genesis required')
    need((q['schema'] == 2 and 'invoice_commitment_version' not in g) or
         (q['schema'] == 3 and type(g.get('invoice_commitment_version')) is int and
          g['invoice_commitment_version'] == 1), 'workspace/native invoice capability differs')
    need(read_private(root/'app-genesis.json') == encode(g) and
         hashlib.sha256(encode(g)).hexdigest() == q['native_sha256'], 'native genesis differs')
    expected_allocations = [{'public_key': keys['owner'], 'units': 1000},
        *({'public_key': keys[f'merchant{i}'], 'units': 0} for i in range(count))]
    need(g['allocations'] == expected_allocations and
         g['validator_registry']['administrators']['public_keys'] == sorted(keys[f'admin{i}'] for i in range(4)),
         'fixed development allocations/administrators differ')
    expected_pool = [address(keys[f'merchant{i}']) for i in range(count)]
    expected_payer = address(keys['owner'])
    need(pool == expected_pool and q['merchant'] == expected_pool[0] and
         q['roles'] == {name: dict(payer=expected_payer, grant_id='' if name == 'owner' else name, vault=name+'.pem')
                       for name in ('owner', 'raven', 'atlas')}, 'fixed development account roles/pool differ')
    need(not set(keys.values()) & {row['public_key'] for row in g['validator_registry']['validators']},
         'development account and validator keys overlap')
    _node_configuration(root, q, full)
    return q


class MerchantNetwork(LocalNetwork):
    def __init__(self, workspace, engine, *, clock=time.time_ns):
        self.root = Path(workspace).absolute(); self.config = load_configuration(self.root)
        self._configuration_bytes = encode(self.config)
        self._policy_bytes = read_private(self.root/'policy.json') if (self.root/'policy.json').exists() else None
        self._ready_bytes = read_private(self.root/'READY.json') if (self.root/'READY.json').exists() else None
        self.binary = verify_engine(engine); self.clock = clock
        self._engine_path = self.binary
        self.lock = None; self.apps = []; self.engines = []; self.handles = []; self.stopped = False

    def _check_config(self):
        need(encode(self.config) == self._configuration_bytes and
             encode(load_configuration(self.root)) == self._configuration_bytes,
             'original workspace configuration changed; no repin or repair')
        if self._policy_bytes is not None:
            need(read_private(self.root/'policy.json') == self._policy_bytes,
                 'original trust policy changed; no repin or renewal')
        if self._ready_bytes is not None:
            need(read_private(self.root/'READY.json') == self._ready_bytes,
                 'original readiness marker changed; no repin or repair')

    def start(self):
        self._check_config()
        need(self.binary == self._engine_path and verify_engine(self.binary) == self._engine_path,
             'original pinned engine changed before startup')
        if (self.root/'READY.json').exists() or (self.root/'READY.json').is_symlink():
            self.ready()
        elif (self.root/'policy.json').exists() or (self.root/'policy.json').is_symlink():
            check_clock(self.policy(), self.clock())
        return super().start()

    def policy(self):
        self._check_config()
        policy = super().policy()
        raw = read_private(self.root/'policy.json')
        need(encode(policy) == raw, 'canonical original trust policy required')
        if self._policy_bytes is None: self._policy_bytes = raw
        need(raw == self._policy_bytes, 'original trust policy changed; no repin or renewal')
        return policy

    def service(self, **kwargs):
        self._check_config()
        return super().service(**kwargs)

    def ready(self):
        self._check_config()
        p = self.root/'READY.json'
        need(not p.is_symlink(), 'workspace readiness file is linked')
        if not p.exists(): return False
        raw = read_private(p); q = load_json(raw)
        expected = {'schema': self.config['schema'],
            'format': INVOICE_READY_FORMAT if self.config['schema'] == 3 else READY_FORMAT,
            'workspace_sha256': hashlib.sha256(read_private(self.root/'workspace.json')).hexdigest(),
            'policy_sha256': hashlib.sha256(read_private(self.root/'policy.json')).hexdigest()}
        need(q == expected and type(q.get('schema')) is int and encode(q) == raw,
             'workspace readiness pins differ')
        check_clock(self.policy(), self.clock())
        if self._ready_bytes is None: self._ready_bytes = raw
        need(raw == self._ready_bytes, 'original readiness marker changed; no repin or repair')
        return True

    def _operations(self):
        keys = _public_keys(self.root, len(self.config['merchant_recipients']))
        recipients = list(self.config['merchant_recipients'])
        ops = [{'type': 'budget_create', 'id': 'studio', 'cap': 100, 'expires': 500, 'recipients': recipients}]
        for name in ('raven', 'atlas'):
            ops.append({'type': 'grant', 'id': name, 'public_key': keys[name], 'cap': 100, 'expires': 500,
                        'recipients': list(recipients), 'budget_id': 'studio'})
        return keys, ops

    def _owner_key(self, password, expected):
        self._check_config()
        if (self.root/'policy.json').exists() or (self.root/'policy.json').is_symlink():
            check_clock(self.policy(), self.clock())
        _password(password); owner = None
        for name, pk in expected.items():
            key = _load_vault(self.root/(name+'.pem'), password)
            need(public(key) == pk, 'original development vault differs')
            if name == 'owner': owner = key
            key = None
        return owner

    def bootstrap(self, *, password):
        need(self.lock is not None and not self.stopped, 'network is not owned')
        if self.ready(): return {'status': 'original_workspace_retained', 'trust_renewed': False}
        journal_paths = [self.root/(name+'.sqlite'+suffix) for name in FINANCIAL_JOURNALS
                         for suffix in ('', '-wal', '-shm', '-journal')]
        need(not any(p.exists() or p.is_symlink() for p in journal_paths),
             'partially initialized journals retained; no repair or recreation')
        genesis = load_json(read_private(self.root/'app-genesis.json'))
        keys, ops = self._operations(); owner = None; port = self.config['ports'][4]
        payer = self.config['roles']['owner']['payer']
        try:
            for nonce, op in enumerate(ops):
                wire_path = self.root/f'setup-{nonce}.json'; claim = self.root/f'setup-{nonce}.claim'
                wire_exists = wire_path.exists() or wire_path.is_symlink()
                claim_exists = claim.exists() or claim.is_symlink()
                need(wire_exists or not claim_exists, 'setup claim has no original wire; no reconstruction')
                expected = {'version': 4, 'chain_id': genesis['chain_id'], 'genesis_hash': digest(genesis),
                    'sender': payer, 'nonce': nonce, 'op': op, 'grant_id': '', 'valid_until': 100, 'max_fee': 2}
                if wire_exists:
                    wire = read_private(wire_path, 32768)
                else:
                    if owner is None: owner = self._owner_key(password, keys)
                    ledger = restore(genesis, genesis_native(port))
                    try:
                        need(ledger._account(payer)['nonce'] == nonce, 'development setup nonce differs')
                        body = ledger.body(payer, nonce, op, valid_until=100)
                        need(body == expected, 'development setup body differs')
                        wire = canonical(sign(owner, body))
                    finally: ledger.close()
                    private_new(wire_path, wire)
                packet = load_json(wire, max_bytes=32768)
                need(type(packet) is dict and set(packet) == {'body', 'signature'} and
                     type(packet['body']) is dict and set(packet['body']) == BODY_FIELDS and
                     packet['body'] == expected and canonical(packet) == wire, 'saved setup wire differs')
                for name in ('version', 'nonce', 'valid_until', 'max_fee'):
                    integer(packet['body'][name])
                signature = packet['signature']
                need(type(signature) is str and re.fullmatch('[0-9a-f]{128}', signature) is not None,
                     'saved setup signature differs')
                try:
                    Ed25519PublicKey.from_public_bytes(bytes.fromhex(keys['owner'])).verify(
                        bytes.fromhex(signature), DOMAIN+canonical(packet['body']))
                except (InvalidSignature, ValueError):
                    raise ValueError('saved setup signature differs') from None
                wire_hash = hashlib.sha256(wire).hexdigest()
                if not claim_exists:
                    private_new(claim, wire_hash.encode('ascii'))
                    admission = rpc(port, 'broadcast_tx_sync', {'tx': base64.b64encode(wire).decode('ascii')})
                    need(type(admission['code']) is int and admission['code'] == 0,
                         'development setup admission refused')
                else:
                    need(read_private(claim, 64) == wire_hash.encode('ascii'), 'saved setup claim differs')
                result = wait(lambda: rpc(port, 'tx', {'hash': base64.b64encode(hashlib.sha256(wire).digest()).decode('ascii')}), 30)
                need(type(result['tx_result']['code']) is int and result['tx_result']['code'] == 0 and
                     base64.b64decode(result['tx'], validate=True) == wire, 'exact development setup execution unavailable')
        finally: owner = None
        policy_path = self.root/'policy.json'
        if not policy_path.exists() and not policy_path.is_symlink():
            first = rpc(port, 'commit', {'height': '1'})['signed_header']['header']
            policy = {'schema': 1, 'format': '1soft/protocol4-read-policy/v1',
                'genesis_sha256': self.config['genesis_sha256'], 'anchor_height': 1,
                'anchor_hash': header_hash(first).hex(), 'anchor_time': first['time'],
                'trust_period_seconds': 3600, 'max_clock_drift_seconds': 5, 'expected_block_version': 11}
            private_new(policy_path, encode(policy_checked(policy)))
        proof = collect_evidence(self.config['endpoint'], read_private(self.root/'engine-genesis.json'),
                                 self.policy(), self.clock())['evidence']
        with self.service(create=True) as svc:
            svc.import_checkpoint(proof, expected_tip=None); svc.sync(expected_revision=None)
        ready = encode({'schema': self.config['schema'],
            'format': INVOICE_READY_FORMAT if self.config['schema'] == 3 else READY_FORMAT,
            'workspace_sha256': hashlib.sha256(read_private(self.root/'workspace.json')).hexdigest(),
            'policy_sha256': hashlib.sha256(read_private(policy_path)).hexdigest()})
        private_new(self.root/'READY.json', ready)
        self._ready_bytes = ready
        return {'status': 'development_workspace_ready', 'validator_count': 4,
                'merchant_recipient_count': len(self.config['merchant_recipients']), 'trust_renewed': False}


def network_for_workspace(workspace, engine, *, clock=time.time_ns):
    """Exact format dispatch; a selected loader failure never falls back."""
    raw = read_private(Path(workspace).absolute()/'workspace.json')
    q = load_json(raw)
    need(type(q) is dict and encode(q) == raw, 'canonical workspace configuration required')
    selected = q.get('format')
    if selected == '1soft/local-development-workspace/v1':
        return LocalNetwork(workspace, engine, clock=clock)
    if selected in (FORMAT, INVOICE_FORMAT):
        return MerchantNetwork(workspace, engine, clock=clock)
    raise ValueError('unsupported development workspace format')
