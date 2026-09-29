"""Bounded adjacent-header verification for changing Ed25519 validator sets.

Research/development module; NOT wired into P1/P2/P3 wallets or ABCI execution.
Uses the existing CometBFT serialization and Ed25519 primitives, not a new
signature algorithm. Caller-pinned genesis/checkpoint/policy are external trust.
No skipping, governance authorization, transaction execution or RPC discovery.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from commit_verifier import (MAX_POWER, MAX_VALIDATORS, Validator, b64, block_id,
    encode, exact, header_hash, hexbytes, load_json, merkle_root, number,
    pinned_genesis, sha, timestamp, vote_sign_bytes)

FORMAT = '1soft-validator-step/v1'
MAX_STEP_BYTES = 512 * 1024
MAX_BATCH = 64
MAX_BATCH_BYTES = 8 * 1024 * 1024
MAX_HEIGHT = 2**53 - 4


class TransitionError(ValueError):
    """Invalid or unavailable continuation; no financial outcome follows."""


def need(condition, message):
    if not condition:
        raise TransitionError(message)


def integer(value, low=0, high=2**63-1):
    need(type(value) is int and low <= value <= high, 'invalid exact integer')
    return value


def hex32(value):
    need(type(value) is str and len(value) == 64 and
         all(c in '0123456789abcdef' for c in value), 'lowercase 32-byte hex required')
    return bytes.fromhex(value)


def nanos(text):
    t = timestamp(text)
    return t.seconds * 10**9 + t.nanos


def freeze(value, limit=MAX_STEP_BYTES):
    raw = encode(value)
    need(len(raw) <= limit, 'validator evidence exceeds bound')
    return load_json(raw, max_bytes=limit)


def canonical_set(values):
    """Canonical public key/power list. No list supplied by a peer is trusted."""
    need(type(values) is list and 1 <= len(values) <= MAX_VALIDATORS, 'invalid validator count')
    seen = set(); rows = []
    for row in values:
        exact(row, {'public_key', 'power'}, 'validator')
        key = hex32(row['public_key']); power = integer(row['power'], 1, MAX_POWER)
        addr = sha(key)[:20]
        need(addr not in seen, 'duplicate validator identity')
        seen.add(addr); rows.append((addr, key, power))
    need(sum(p for _, _, p in rows) <= MAX_POWER, 'total voting power exceeds bound')
    rows.sort(key=lambda row: (-row[2], row[0]))
    return [{'public_key': key.hex(), 'power': p} for _, key, p in rows]


def parse_set(values):
    ordered = canonical_set(values)
    need(values == ordered, 'validator list is not in canonical power/address order')
    return tuple(Validator(sha(bytes.fromhex(v['public_key']))[:20],
                           bytes.fromhex(v['public_key']), v['power']) for v in ordered)


def set_hash(values):
    return merkle_root([v.encoded() for v in parse_set(values)]).hex()


def policy_for(genesis_bytes, genesis_sha256, *, initial_height, initial_header_hash,
               trust_period_seconds, max_clock_drift_seconds=30):
    """Explicit operator choice; not a recommended production trust period."""
    hex32(genesis_sha256); hex32(initial_header_hash)
    trust = pinned_genesis(genesis_bytes, genesis_sha256)
    engine = load_json(genesis_bytes, max_bytes=1024*1024)
    version = engine['app_state'].get('protocol_version', 1)
    integer(version, 1, 3)
    return {'schema': 1, 'genesis_sha256': genesis_sha256, 'chain_id': trust.chain_id,
            'initial_height': integer(initial_height, 1, MAX_HEIGHT),
            'initial_header_hash': initial_header_hash, 'block_version': 11,
            'app_version': version,
            'trust_period_seconds': integer(trust_period_seconds, 1, 7*86400),
            'max_clock_drift_seconds': integer(max_clock_drift_seconds, 0, 300)}


def validate_policy(policy, genesis_bytes):
    exact(policy, {'schema','genesis_sha256','chain_id','initial_height','initial_header_hash',
                  'block_version','app_version','trust_period_seconds','max_clock_drift_seconds'}, 'policy')
    need(type(policy['schema']) is int and policy['schema'] == 1, 'unsupported policy version')
    rebuilt = policy_for(genesis_bytes, policy['genesis_sha256'], initial_height=policy['initial_height'],
        initial_header_hash=policy['initial_header_hash'], trust_period_seconds=policy['trust_period_seconds'],
        max_clock_drift_seconds=policy['max_clock_drift_seconds'])
    need(encode(policy) == encode(rebuilt), 'policy conflicts with pinned genesis or supported versions')
    return rebuilt


def verify_step(value, policy):
    """Verify signatures/sets internally. Establishes NO ancestry or external trust alone."""
    v = freeze(value)
    exact(v, {'format','signed_header','validators','next_validators'}, 'validator step')
    need(v['format'] == FORMAT, 'unknown validator-step format')
    signed = v['signed_header']; exact(signed, {'header','commit'}, 'signed header')
    header = signed['header']; digest = header_hash(header)
    height = number(header['height'], minimum=1, maximum=MAX_HEIGHT)
    need(header['chain_id'] == policy['chain_id'], 'wrong chain')
    need(number(header['version']['block']) == policy['block_version'] and
         number(header['version']['app']) == policy['app_version'], 'unapproved block/application version')
    vals = parse_set(v['validators']); next_vals = parse_set(v['next_validators'])
    vh = merkle_root([x.encoded() for x in vals]); nh = merkle_root([x.encoded() for x in next_vals])
    need(hexbytes(header['validators_hash'], 32) == vh, 'current validator root mismatch')
    need(hexbytes(header['next_validators_hash'], 32) == nh, 'next validator root mismatch')
    need(hexbytes(header['proposer_address'], 20) in {x.address for x in vals}, 'unknown proposer')
    commit = signed['commit']; exact(commit, {'height','round','block_id','signatures'}, 'commit')
    need(number(commit['height'], minimum=1) == height, 'commit height mismatch')
    round_ = number(commit['round'], maximum=2**31-1)
    need(block_id(commit['block_id']).hash == digest, 'commit/header hash mismatch')
    slots = commit['signatures']
    need(type(slots) is list and len(slots) == len(vals), 'wrong number of validator slots')
    committed = 0
    for validator, slot in zip(vals, slots):
        exact(slot, {'block_id_flag','validator_address','timestamp','signature'}, 'commit signature')
        flag = number(slot['block_id_flag'], minimum=1, maximum=3)
        if flag == 1:
            need(slot['validator_address'] == '' and slot['signature'] in ('', None), 'nonempty absent vote')
            need(nanos(slot['timestamp']) == -62135596800 * 10**9, 'nonzero absent timestamp')
            continue
        need(hexbytes(slot['validator_address'], 20) == validator.address, 'signature/address order mismatch')
        signature = b64(slot['signature'], 64, max_size=64)
        payload = vote_sign_bytes(policy['chain_id'], height, round_,
                                 commit['block_id'] if flag == 2 else None, slot['timestamp'])
        try:
            Ed25519PublicKey.from_public_bytes(validator.public_key).verify(signature, payload)
        except InvalidSignature as exc:
            raise TransitionError('invalid validator signature') from exc
        if flag == 2:
            committed += validator.power
    total = sum(x.power for x in vals)
    need(committed * 3 > total * 2, 'strictly more than two-thirds voting power required')
    return {'height': height, 'header_hash': digest.hex(), 'time_ns': nanos(header['time']),
            'validators_hash': vh.hex(), 'next_validators_hash': nh.hex(),
            'validator_count': len(vals), 'next_validator_count': len(next_vals),
            'signed_power': committed, 'total_power': total}


def verify_link(previous, following, policy):
    old = verify_step(previous, policy)
    new = verify_step(following, policy)
    need(new['height'] == old['height'] + 1, 'every intermediate header is required')
    need(new['time_ns'] > old['time_ns'], 'header time must increase strictly')
    need(block_id(following['signed_header']['header']['last_block_id']).SerializeToString() ==
         block_id(previous['signed_header']['commit']['block_id']).SerializeToString(), 'previous block identity mismatch')
    need(new['validators_hash'] == old['next_validators_hash'], 'successor validator set was not committed by predecessor')
    return new


def check_time(info, policy, now_ns):
    integer(now_ns)
    need(now_ns < info['time_ns'] + policy['trust_period_seconds'] * 10**9, 'trusted checkpoint expired')
    need(info['time_ns'] < now_ns + policy['max_clock_drift_seconds'] * 10**9, 'header exceeds allowed clock drift')


def verify_anchor(value, policy, genesis_bytes, now_ns):
    validate_policy(policy, genesis_bytes)
    info = verify_step(value, policy)
    need(info['height'] == policy['initial_height'] and info['header_hash'] == policy['initial_header_hash'],
         'initial header differs from external checkpoint pin')
    if info['height'] == 1:
        trust = pinned_genesis(genesis_bytes, policy['genesis_sha256'])
        need(info['validators_hash'] == trust.validators_hash.hex() and
             info['next_validators_hash'] == trust.validators_hash.hex(),
             'this profile requires the unmodified genesis set for the first two heights')
    check_time(info, policy, now_ns)
    return info


def preview_update(next_validators, changes, finalized_height):
    """Pure H/H+1/H+2 model. Does NOT authorize, enqueue or execute an update.

    Input set is the validators already scheduled for H+1, not necessarily those
    signing H. Zero power removes; all changes apply atomically to that base set.
    """
    h = integer(finalized_height, 1, MAX_HEIGHT)
    base = canonical_set(next_validators)
    need(type(changes) is list and 1 <= len(changes) <= MAX_VALIDATORS, 'empty/oversized update')
    result = {v['public_key']: v['power'] for v in base}; seen = set(); updates = []
    for item in changes:
        exact(item, {'public_key','power'}, 'validator change')
        key = hex32(item['public_key']); p = integer(item['power'], 0, MAX_POWER)
        need(key not in seen, 'duplicate validator change'); seen.add(key)
        if p == 0:
            need(key.hex() in result, 'cannot remove a missing validator'); del result[key.hex()]
        else:
            result[key.hex()] = p
        updates.append({'public_key':key.hex(), 'power':p})
    new = canonical_set([{'public_key':k,'power':v} for k,v in result.items()])
    updates.sort(key=lambda v: sha(bytes.fromhex(v['public_key']))[:20])
    return {'schema':1, 'status':'preview-only', 'finalize_height':h,
            'next_hash_header_height':h+1, 'active_validator_height':h+2,
            'changed_last_commit_height':h+3, 'before_hash':set_hash(base),
            'after_hash':set_hash(new), 'next_validators':new, 'updates':updates,
            'governance_authorization_checked':False, 'activation_scheduled':False,
            'chain_mutated':False}
