"""Versioned development validator-control state machine, not a money protocol.

Separate, genesis-pinned administrative keys authorize delayed roster changes.
Consensus signing keys never become administrative keys. No old node imports this
module and this profile cannot move coins or activate an existing chain upgrade.
"""
from __future__ import annotations

import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from commit_verifier import encode, load_json, exact
from validator_sets import ValidatorSet, validator_updates, hex_text, chain_name

GENESIS_FORMAT = '1soft/validator-registry-genesis/v1'
TX_FORMAT = '1soft/validator-registry-action/v1'
STATE_FORMAT = '1soft/validator-registry-state/v1'
APP_VERSION = 4001  # Experimental registry ONLY. Not native protocol 4 payments.
SIGN_DOMAIN = b'1soft/validator-registry/authorization/v1\x00'
STATE_DOMAIN = b'1soft/validator-registry/state/v1\x00'
RECEIPT_DOMAIN = b'1soft/validator-registry/receipt/v1\x00'
MAX_HEIGHT = 2**53 - 1
MAX_TX_BYTES = 65536
MAX_BLOCK_TXS = 8
MAX_BLOCK_BYTES = MAX_TX_BYTES * MAX_BLOCK_TXS
MAX_VALIDITY_BLOCKS = 1024
MAX_SCHEDULE_AHEAD = 1024
MAX_ACTIONS = 512
ZERO = '0' * 64


class RegistryReject(ValueError):
    """Deterministic invalid administrative operation; no authority acquired."""


def require(condition, message):
    if not condition:
        raise RegistryReject(message)


def integer(value, low=0, high=MAX_HEIGHT):
    require(type(value) is int and low <= value <= high, 'invalid exact integer')
    return value


def frozen(value, maximum=8*1024*1024):
    raw = encode(value)
    require(len(raw) <= maximum, 'registry document exceeds bound')
    return load_json(raw, max_bytes=maximum)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_genesis(value):
    g = frozen(value, 131072)
    exact(g, {'schema','format','mode','chain_id','validators','administrators',
              'minimum_delay_blocks','cooldown_blocks','minimum_validators','maximum_power_bps'},
          'registry genesis')
    integer(g['schema'], 1, 1)
    require(g['format'] == GENESIS_FORMAT and g['mode'] == 'development-only',
            'unsupported registry genesis or mode')
    chain_name(g['chain_id'])
    integer(g['minimum_delay_blocks'], 2, 128)
    integer(g['cooldown_blocks'], 1, 128)
    integer(g['minimum_validators'], 4, 256)
    integer(g['maximum_power_bps'], 1, 3333)
    a = g['administrators']
    exact(a, {'format','public_keys','threshold'}, 'registry administrator policy')
    require(a['format'] == 'threshold-ed25519-v1', 'unknown administrative policy')
    keys = a['public_keys']
    require(type(keys) is list and 3 <= len(keys) <= 16, 'invalid administrator count')
    for key in keys: hex_text(key)
    require(keys == sorted(set(keys)), 'administrator keys must be unique and sorted')
    integer(a['threshold'], 1, len(keys))
    require(a['threshold'] * 3 > len(keys) * 2, 'administrative threshold must exceed two thirds')
    validate_roster(g['validators'], g)
    return g


def validate_roster(rows, genesis):
    roster = ValidatorSet.parse(rows)
    require(len(roster.validators) >= genesis['minimum_validators'], 'too few validators')
    admins = set(genesis['administrators']['public_keys'])
    require(not admins.intersection(v.public_key.hex() for v in roster.validators),
            'consensus and administrator keys must be disjoint')
    require(all(v.power * 10000 <= roster.total_power * genesis['maximum_power_bps']
                for v in roster.validators), 'individual voting power exceeds policy')
    return roster


class RegistryRules:
    """Pure deterministic execution from an explicit versioned genesis."""
    def __init__(self, genesis):
        self._genesis_bytes = encode(validate_genesis(genesis))
        self.genesis_hash = digest(self._genesis_bytes)
        self.policy_hash = digest(encode(self.genesis['administrators']))

    @property
    def genesis(self):
        return load_json(self._genesis_bytes, max_bytes=131072)

    def initial_state(self):
        roster = self.genesis['validators']; root = ValidatorSet.parse(roster).hash
        return {'schema':1, 'format':STATE_FORMAT, 'genesis_sha256':self.genesis_hash,
                'policy_sha256':self.policy_hash, 'height':0, 'sequence':0, 'epoch':0,
                'active_validators':roster, 'active_hash':root,
                'next_validators':roster, 'next_hash':root, 'pending':None,
                'last_activation_height':0, 'receipt_count':0, 'receipt_head':ZERO}

    def state_hash(self, state):
        self.audit_state(state)
        return digest(STATE_DOMAIN + encode(state))

    def audit_state(self, state):
        exact(state, {'schema','format','genesis_sha256','policy_sha256','height','sequence','epoch',
                      'active_validators','active_hash','next_validators','next_hash','pending',
                      'last_activation_height','receipt_count','receipt_head'}, 'registry state')
        integer(state['schema'],1,1)
        require(state['format'] == STATE_FORMAT and state['genesis_sha256'] == self.genesis_hash
                and state['policy_sha256'] == self.policy_hash, 'registry state identity differs')
        height = integer(state['height'],0,MAX_HEIGHT-3)
        integer(state['epoch'],0,MAX_ACTIONS)
        integer(state['sequence'],0,MAX_ACTIONS); integer(state['receipt_count'],0,MAX_ACTIONS)
        require(state['sequence'] == state['receipt_count'], 'action sequence/count mismatch')
        hex_text(state['receipt_head'])
        require((state['sequence'] == 0) == (state['receipt_head'] == ZERO), 'receipt history marker differs')
        integer(state['last_activation_height'],0,height)
        current = validate_roster(state['active_validators'],self.genesis)
        following = validate_roster(state['next_validators'],self.genesis)
        require(state['active_hash'] == current.hash and state['next_hash'] == following.hash,
                'roster commitment mismatch')
        p = state['pending']
        expected = current
        if p is not None:
            exact(p, {'id','authorized_wire_sha256','scheduled_height','emitted_height','activation_height',
                      'from_epoch','to_epoch','from_hash','target_hash','target_validators','phase'}, 'pending transition')
            hex_text(p['id']); hex_text(p['authorized_wire_sha256'])
            integer(p['scheduled_height'],1,height)
            integer(p['emitted_height'],p['scheduled_height']+self.genesis['minimum_delay_blocks'],MAX_HEIGHT-3)
            require(p['emitted_height'] <= p['scheduled_height']+MAX_SCHEDULE_AHEAD, 'schedule exceeds bound')
            integer(p['activation_height'],p['emitted_height']+2,p['emitted_height']+2)
            integer(p['from_epoch'],0,MAX_ACTIONS); integer(p['to_epoch'],1,MAX_ACTIONS)
            require(p['from_epoch'] == state['epoch'] and p['to_epoch'] == state['epoch']+1 and
                    p['from_hash'] == current.hash, 'pending transition base differs')
            target = validate_roster(p['target_validators'],self.genesis)
            require(target.hash == p['target_hash'] and target.hash != current.hash, 'pending target differs or no-op')
            if p['phase'] == 'queued': require(height < p['emitted_height'], 'queued transition passed emission')
            elif p['phase'] == 'emitted':
                require(p['emitted_height'] <= height < p['activation_height'], 'emitted transition outside window')
                if height+1 == p['activation_height']: expected = target
            else: raise RegistryReject('unknown transition phase')
        require(following.hash == expected.hash, 'next roster inconsistent with activation height')

    def body(self, state, operation, *, valid_from, valid_until):
        """Draft only: no private keys, implicit approval or chain submission."""
        self.audit_state(state)
        return frozen({'schema':1, 'format':TX_FORMAT, 'chain_id':self.genesis['chain_id'],
                       'genesis_sha256':self.genesis_hash, 'policy_sha256':self.policy_hash,
                       'sequence':state['sequence'], 'expected_epoch':state['epoch'],
                       'expected_active_hash':state['active_hash'], 'valid_from':valid_from,
                       'valid_until':valid_until, 'operation':operation}, MAX_TX_BYTES)

    def signing_bytes(self, body):
        self.validate_body(body)
        return SIGN_DOMAIN + encode(body)

    def validate_body(self, body):
        exact(body, {'schema','format','chain_id','genesis_sha256','policy_sha256','sequence','expected_epoch',
                     'expected_active_hash','valid_from','valid_until','operation'}, 'registry action')
        integer(body['schema'],1,1)
        require(body['format'] == TX_FORMAT and body['chain_id'] == self.genesis['chain_id'] and
                body['genesis_sha256'] == self.genesis_hash and body['policy_sha256'] == self.policy_hash,
                'action domain or pinned policy differs')
        integer(body['sequence'],0,MAX_ACTIONS-1); integer(body['expected_epoch'],0,MAX_ACTIONS)
        hex_text(body['expected_active_hash'])
        start=integer(body['valid_from'],1,MAX_HEIGHT-3)
        end=integer(body['valid_until'],start,MAX_HEIGHT-3)
        require(end-start <= MAX_VALIDITY_BLOCKS, 'action validity exceeds bound')
        op=body['operation']; require(type(op) is dict, 'invalid operation')
        if op.get('kind') == 'schedule':
            exact(op,{'kind','emitted_height','target_validators'},'schedule operation')
            integer(op['emitted_height'],1,MAX_HEIGHT-3)
            validate_roster(op['target_validators'],self.genesis)
        elif op.get('kind') == 'cancel':
            exact(op,{'kind','proposal_id'},'cancel operation');hex_text(op['proposal_id'])
        else: raise RegistryReject('unsupported registry operation')

    def authorize(self, raw):
        require(type(raw) is bytes and len(raw) <= MAX_TX_BYTES, 'registry action bytes exceed bound')
        packet = load_json(raw, max_bytes=MAX_TX_BYTES)
        exact(packet,{'body','approvals'},'authorized registry action')
        require(encode(packet) == raw, 'registry action is not canonical')
        body=packet['body']; material=self.signing_bytes(body)
        approvals=packet['approvals']; policy=self.genesis['administrators']
        require(type(approvals) is list and policy['threshold'] <= len(approvals) <= len(policy['public_keys']),
                'administrative approval threshold not met')
        seen=[]
        for approval in approvals:
            exact(approval,{'public_key','signature'},'administrative approval')
            key=hex_text(approval['public_key']); sig=hex_text(approval['signature'],64)
            require(key in policy['public_keys'] and key not in seen, 'unknown or repeated administrative signer')
            try: Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(bytes.fromhex(sig),material)
            except (InvalidSignature,ValueError) as exc: raise RegistryReject('invalid administrative signature') from exc
            seen.append(key)
        require(seen == sorted(seen), 'noncanonical approval ordering')
        return body,digest(material),digest(raw)

    def _apply(self, state, raw, height):
        body,txid,wire_hash=self.authorize(raw)
        require(body['valid_from'] <= height <= body['valid_until'], 'administrative action outside validity')
        require(body['sequence'] == state['sequence'], 'administrative sequence mismatch')
        require(body['expected_epoch'] == state['epoch'] and body['expected_active_hash'] == state['active_hash'],
                'administrative base epoch or roster changed')
        op=body['operation']; pending=state['pending']
        if op['kind']=='schedule':
            require(pending is None, 'another transition is pending')
            require(state['last_activation_height']==0 or height >= state['last_activation_height']+self.genesis['cooldown_blocks'], 'activation cooldown')
            emit=op['emitted_height']
            require(height+self.genesis['minimum_delay_blocks'] <= emit <= height+MAX_SCHEDULE_AHEAD,
                    'emission delay outside permitted range')
            target=validate_roster(op['target_validators'],self.genesis)
            require(target.hash != state['active_hash'], 'unchanged roster is not a transition')
            replacement={'id':txid,'authorized_wire_sha256':wire_hash,'scheduled_height':height,
                         'emitted_height':emit,'activation_height':emit+2,
                         'from_epoch':state['epoch'],'to_epoch':state['epoch']+1,
                         'from_hash':state['active_hash'],'target_hash':target.hash,
                         'target_validators':target.json(),'phase':'queued'}
            affected=txid
        else:
            require(pending is not None and pending['id']==op['proposal_id'], 'cancellation does not name pending proposal')
            require(pending['phase']=='queued' and height < pending['emitted_height'], 'emitted transition cannot be cancelled')
            replacement=None; affected=op['proposal_id']
        require(state['sequence'] < MAX_ACTIONS, 'registry action history full')
        receipt={'sequence':state['sequence'],'height':height,'action':op['kind'],'id':txid,
                 'wire_sha256':wire_hash,'proposal_id':affected,'previous':state['receipt_head']}
        state['receipt_head']=digest(RECEIPT_DOMAIN+encode(receipt))
        state['sequence']+=1;state['receipt_count']+=1;state['pending']=replacement
        return {'code':0,'log':'','data':txid,'receipt':receipt,'receipt_hash':state['receipt_head']}

    def transition(self, before, txs, height):
        self.audit_state(before)
        integer(height,1,MAX_HEIGHT-3)
        require(height==before['height']+1, 'registry blocks must be consecutive')
        require(type(txs) is list and len(txs)<=MAX_BLOCK_TXS and
                all(type(raw) is bytes and len(raw)<=MAX_TX_BYTES for raw in txs) and
                sum(map(len,txs))<=MAX_BLOCK_BYTES,'registry block exceeds bound')
        state=frozen(before); events=[]; updates=[]; previous_active=state['active_hash']
        pending=state['pending']
        # Height-driven effects happen before transactions: cancellation AT emission
        # is too late. Effects are still speculative until the caller's Commit.
        if pending and pending['phase']=='emitted' and height==pending['activation_height']:
            state['active_validators']=pending['target_validators'];state['active_hash']=pending['target_hash']
            state['epoch']=pending['to_epoch'];state['last_activation_height']=height;state['pending']=None
            events.append({'kind':'activated','height':height,'proposal_id':pending['id'],'epoch':state['epoch']})
        elif pending and pending['phase']=='queued' and height==pending['emitted_height']:
            updates=validator_updates(ValidatorSet.parse(state['active_validators']),ValidatorSet.parse(pending['target_validators']))
            pending['phase']='emitted'
            events.append({'kind':'emitted','height':height,'proposal_id':pending['id'],'activation_height':height+2})
        results=[]
        for raw in txs:
            candidate=frozen(state)
            try: result=self._apply(candidate,raw,height)
            except ValueError:
                # A uniform rejection avoids exception-text/platform-dependent consensus results.
                result={'code':1,'log':'registry action rejected','data':''}
            else: state=candidate
            results.append(result)
        state['height']=height;state['next_validators']=state['active_validators'];state['next_hash']=state['active_hash']
        p=state['pending']
        if p and p['phase']=='emitted' and p['activation_height']==height+1:
            state['next_validators']=p['target_validators'];state['next_hash']=p['target_hash']
        app_hash=self.state_hash(state)
        result={'height':height,'app_hash':app_hash,'tx_results':results,'validator_updates':updates,'events':events,
                'validators_hash':state['active_hash'],'next_validators_hash':state['next_hash'],
                'last_commit_validators_hash':previous_active,'epoch':state['epoch']}
        return state,frozen(result)
