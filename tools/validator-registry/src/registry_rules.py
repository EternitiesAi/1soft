"""Experimental validator-control state machine; not an activated 1soft protocol.

A separately pinned threshold administrative policy authorizes delayed registry
changes. No consensus key is implicitly an administrator. All inputs, state and
outputs are deterministic; the existing monetary P1/P2/P3 implementations are not
imported or modified. This module has no signer, network or filesystem operation.
"""
from __future__ import annotations

import hashlib
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from commit_verifier import encode, exact, load_json
from validator_sets import (ValidatorSet, chain_name, freeze, hex_text, integer,
                            validator_updates, MAX_HEIGHT, MAX_VALIDATORS)

PROFILE = '1soft/validator-registry-experiment/v1'
GENESIS_FORMAT = '1soft/validator-registry-genesis/v1'
COMMAND_FORMAT = '1soft/validator-registry-command/v1'
SIGN_DOMAIN = b'1soft/validator-registry-authorization/v1\x00'
STATE_DOMAIN = b'1soft/validator-registry-state/v1\x00'
MAX_COMMAND_BYTES = 65536
MAX_STATE_BYTES = 16 * 1024 * 1024
MAX_COMMANDS_PER_BLOCK = 8
MAX_BLOCK_BYTES = 256 * 1024
MAX_RECEIPTS = 256
ZERO = '0' * 64


class RegistryError(ValueError):
    """A candidate operation is invalid; not a finding about real funds."""


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise RegistryError(reason)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical_copy(value, limit=MAX_STATE_BYTES):
    return freeze(value, limit)


def genesis_id(genesis: dict) -> str:
    return sha(encode(genesis))


def validate_roster(genesis: dict, rows: list) -> ValidatorSet:
    roster = ValidatorSet.parse(rows)
    rules = genesis['rules']
    need(len(roster.validators) >= rules['minimum_validators'], 'minimum validator count')
    admins = set(genesis['administrators']['public_keys'])
    need(not admins.intersection(v.public_key.hex() for v in roster.validators),
         'administrative and consensus keys must be separate')
    need(all(v.power * 10000 <= rules['maximum_key_power_bps'] * roster.total_power
             for v in roster.validators), 'per-key power concentration exceeds pinned rule')
    return roster


def validate_genesis(value: dict) -> dict:
    g = canonical_copy(value, 256 * 1024)
    exact(g, {'schema', 'format', 'profile', 'chain_id', 'administrators', 'rules', 'validators'}, 'registry genesis')
    need(type(g['schema']) is int and g['schema'] == 1 and g['format'] == GENESIS_FORMAT
         and g['profile'] == PROFILE, 'not the explicit registry experiment')
    chain_name(g['chain_id'])
    a = g['administrators']
    exact(a, {'public_keys', 'threshold'}, 'registry authority')
    keys = a['public_keys']
    need(type(keys) is list and 3 <= len(keys) <= 16, 'administrative key count')
    for k in keys:
        hex_text(k)
    need(keys == sorted(set(keys)), 'administrative keys must be unique and ordered')
    integer(a['threshold'], 2, len(keys))
    rules = g['rules']
    exact(rules, {'delay_blocks', 'maximum_future_blocks', 'minimum_validators',
                  'maximum_key_power_bps'}, 'registry rules')
    integer(rules['delay_blocks'], 2, 10000)
    integer(rules['maximum_future_blocks'], rules['delay_blocks'], 100000)
    integer(rules['minimum_validators'], 4, MAX_VALIDATORS)
    integer(rules['maximum_key_power_bps'], 2500, 3333)
    validate_roster(g, g['validators'])
    return g


def initial_state(genesis: dict) -> dict:
    g = validate_genesis(genesis)
    return {'schema': 1, 'profile': PROFILE, 'genesis_sha256': genesis_id(g),
            'height': 0, 'epoch': 0, 'nonce': 0, 'active_set': g['validators'],
            'pending': None, 'last_activation_height': 0, 'receipts': []}


def state_hash(state: dict) -> str:
    raw = encode(state)
    need(len(raw) <= MAX_STATE_BYTES, 'registry state capacity reached')
    return sha(STATE_DOMAIN + raw)


def sign_bytes(body: dict) -> bytes:
    """Canonical signing preimage only; no key loading or signing function."""
    raw = encode(body)
    need(len(raw) <= MAX_COMMAND_BYTES, 'command body exceeds bound')
    return SIGN_DOMAIN + raw


def command_id(body: dict) -> str:
    return sha(sign_bytes(body))


def decode_command(raw: bytes, genesis: dict) -> dict:
    need(type(raw) is bytes and 0 < len(raw) <= MAX_COMMAND_BYTES, 'command byte bound')
    envelope = load_json(raw, max_bytes=MAX_COMMAND_BYTES)
    exact(envelope, {'body', 'approvals'}, 'registry command')
    need(encode(envelope) == raw, 'command encoding must be canonical')
    b = envelope['body']
    exact(b, {'schema', 'format', 'chain_id', 'genesis_sha256', 'authority_epoch',
              'nonce', 'base_epoch', 'base_set_hash', 'valid_from', 'valid_until', 'operation'}, 'command body')
    need(type(b['schema']) is int and b['schema'] == 1 and b['format'] == COMMAND_FORMAT,
         'unsupported command version')
    need(b['chain_id'] == genesis['chain_id'] and b['genesis_sha256'] == genesis_id(genesis),
         'command belongs to a different pinned experiment')
    integer(b['authority_epoch'], 0, 0)  # This profile deliberately has no authority rotation.
    integer(b['nonce'], 0, MAX_HEIGHT)
    integer(b['base_epoch'], 0, MAX_HEIGHT)
    hex_text(b['base_set_hash'])
    integer(b['valid_from'], 1, MAX_HEIGHT - 4)
    integer(b['valid_until'], b['valid_from'], MAX_HEIGHT - 4)
    need(b['valid_until'] - b['valid_from'] <= genesis['rules']['maximum_future_blocks'],
         'command validity window too large')
    op = b['operation']
    need(type(op) is dict and op.get('type') in ('schedule', 'cancel'), 'unknown registry operation')
    if op['type'] == 'schedule':
        exact(op, {'type', 'emission_height', 'validators'}, 'schedule operation')
        integer(op['emission_height'], 1, MAX_HEIGHT - 3)
        validate_roster(genesis, op['validators'])
    else:
        exact(op, {'type', 'proposal_id'}, 'cancel operation')
        hex_text(op['proposal_id'])
    approvals = envelope['approvals']
    policy = genesis['administrators']
    need(type(approvals) is list and policy['threshold'] <= len(approvals) <= len(policy['public_keys']),
         'administrative signature threshold not met')
    previous = ''
    for approval in approvals:
        exact(approval, {'public_key', 'signature'}, 'administrative approval')
        key = hex_text(approval['public_key']); signature = hex_text(approval['signature'], 64)
        need(key > previous and key in policy['public_keys'], 'unknown duplicate or unordered administrator')
        previous = key
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(bytes.fromhex(signature), sign_bytes(b))
        except InvalidSignature as exc:
            raise RegistryError('invalid administrative signature') from exc
    return envelope


def advance_clock(state: dict, height: int) -> tuple[list, dict | None]:
    """Advance an already-validated private state copy, including empty heights.

    Used with consecutive heights during execution and event jumps during audit.
    Only the normal consecutive call's returned update may become a block output.
    """
    integer(height, state['height'], MAX_HEIGHT - 3)
    update = []; activated = None
    p = state['pending']
    if p is not None:
        if state['height'] < p['emission_height'] <= height:
            update = validator_updates(ValidatorSet.parse(state['active_set']), ValidatorSet.parse(p['validators']))
            p['emitted'] = True
        if p['activation_height'] <= height:
            state['active_set'] = p['validators']
            state['epoch'] += 1
            state['last_activation_height'] = p['activation_height']
            activated = {'proposal_id': p['proposal_id'], 'epoch': state['epoch'],
                         'height': p['activation_height']}
            state['pending'] = None
    state['height'] = height
    return update, activated


def accept(state: dict, envelope: dict, genesis: dict) -> dict:
    """All preconditions are checked before the private candidate is changed."""
    b = envelope['body']; op = b['operation']; h = state['height']
    need(b['valid_from'] <= h <= b['valid_until'], 'command is not valid at this height')
    need(b['nonce'] == state['nonce'], 'stale or future administrative nonce')
    need(b['base_epoch'] == state['epoch'] and
         b['base_set_hash'] == ValidatorSet.parse(state['active_set']).hash, 'registry epoch or base roster changed')
    need(len(state['receipts']) < MAX_RECEIPTS, 'registry history capacity reached; no eviction')
    proposal = command_id(b)
    if op['type'] == 'schedule':
        need(state['pending'] is None, 'one validator transition is already pending')
        need(h > state['last_activation_height'], 'activation-height cooldown')
        e = op['emission_height']; rules = genesis['rules']
        need(h + rules['delay_blocks'] <= e <= h + rules['maximum_future_blocks'],
             'emission is outside the pinned delay window')
        target = validate_roster(genesis, op['validators'])
        need(target.hash != b['base_set_hash'], 'unchanged roster is not a transition')
        pending = {'proposal_id': proposal, 'accepted_height': h, 'base_epoch': state['epoch'],
                   'emission_height': e, 'activation_height': e + 2,
                   'validators': target.json(), 'emitted': False}
    else:
        pending = state['pending']
        need(pending is not None and pending['proposal_id'] == op['proposal_id'], 'cancellation selects no pending proposal')
        need(h < pending['emission_height'] and not pending['emitted'], 'emitted transition cannot be cancelled')
        pending = None
    receipt = {'sequence': len(state['receipts']) + 1, 'height': h, 'command_id': proposal,
               'previous': state['receipts'][-1]['sha256'] if state['receipts'] else ZERO,
               'envelope': envelope}
    receipt['sha256'] = sha(encode(receipt))
    state['nonce'] += 1
    state['pending'] = pending
    state['receipts'].append(receipt)
    state_hash(state)  # Bounded candidate; caller discards it if this refuses.
    return receipt


def restore_state(genesis: dict, value: dict, expected_hash: str | None = None) -> dict:
    """Rebuild all registry authority/epochs from signed accepted-command history.

    Snapshot metadata cannot grant authority. This replay does NOT authenticate the
    checkpoint's external consensus or prove that no alternate history exists.
    """
    g = validate_genesis(genesis)
    s = canonical_copy(value)
    exact(s, set(initial_state(g)), 'registry snapshot')
    integer(s['height'], 0, MAX_HEIGHT - 3)
    need(type(s['receipts']) is list and len(s['receipts']) <= MAX_RECEIPTS, 'receipt history bound')
    replay = initial_state(g)
    for receipt in s['receipts']:
        exact(receipt, {'sequence', 'height', 'command_id', 'previous', 'envelope', 'sha256'}, 'registry receipt')
        integer(receipt['height'], max(1, replay['height']), s['height'])
        advance_clock(replay, receipt['height'])
        envelope = decode_command(encode(receipt['envelope']), g)
        generated = accept(replay, envelope, g)
        need(encode(generated) == encode(receipt), 'receipt differs from authorized deterministic execution')
    advance_clock(replay, s['height'])
    need(encode(replay) == encode(s), 'registry snapshot differs from signed command replay')
    h = state_hash(replay)
    if expected_hash is not None:
        need(h == hex_text(expected_hash), 'registry snapshot commitment mismatch')
    return replay


def block_transition(genesis: dict, state: dict, height: int, block_hash: str, transactions: list[bytes]):
    g = validate_genesis(genesis)
    old = restore_state(g, state)
    integer(height, old['height'] + 1, old['height'] + 1)
    hex_text(block_hash)
    need(type(transactions) is list and len(transactions) <= MAX_COMMANDS_PER_BLOCK,
         'registry block command count exceeded')
    need(all(type(raw) is bytes and len(raw) <= MAX_COMMAND_BYTES for raw in transactions)
         and sum(map(len, transactions)) <= MAX_BLOCK_BYTES, 'registry block bytes exceeded')
    next_state = canonical_copy(old)
    updates, activation = advance_clock(next_state, height)
    results = []
    for raw in transactions:
        try:
            envelope = decode_command(raw, g)
            candidate = canonical_copy(next_state)
            receipt = accept(candidate, envelope, g)
        except (ValueError, KeyError, TypeError, OverflowError):
            results.append({'code': 1, 'command_id': None})
        else:
            next_state = candidate
            results.append({'code': 0, 'command_id': receipt['command_id']})
    future = canonical_copy(next_state)
    advance_clock(future, height + 1)
    result = {'schema': 1, 'profile': PROFILE, 'height': height, 'block_hash': block_hash,
              'app_hash': state_hash(next_state), 'tx_results': results,
              'validator_updates': updates, 'active_epoch': next_state['epoch'],
              'active_set_hash': ValidatorSet.parse(next_state['active_set']).hash,
              'next_height_set_hash': ValidatorSet.parse(future['active_set']).hash,
              'activation': activation}
    return next_state, result


def draft(genesis: dict, state: dict, operation: dict, *, valid_from: int, valid_until: int) -> dict:
    g = validate_genesis(genesis); s = restore_state(g, state)
    integer(valid_from, s['height'] + 1, MAX_HEIGHT - 4)
    integer(valid_until, valid_from, MAX_HEIGHT - 4)
    return canonical_copy({'schema': 1, 'format': COMMAND_FORMAT, 'chain_id': g['chain_id'],
        'genesis_sha256': genesis_id(g), 'authority_epoch': 0, 'nonce': s['nonce'],
        'base_epoch': s['epoch'], 'base_set_hash': ValidatorSet.parse(s['active_set']).hash,
        'valid_from': valid_from, 'valid_until': valid_until, 'operation': operation}, MAX_COMMAND_BYTES)
