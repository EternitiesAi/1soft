"""Sequential dynamic-validator header evidence, separate from the legacy wallet.

Every next roster must be committed by the prior verified header. An endpoint's
roster or a draft plan is never trust. Checkpoint pins and a fixed trust period are
external inputs. No skipping, fork choice, trust renewal, signing or balances.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from commit_verifier import (exact, encode, load_json, pinned_genesis, header_hash,
    block_id, hexbytes, number, b64, vote_sign_bytes, timestamp)
from validator_sets import (ValidatorSet, need, integer, hex_text, freeze,
    document_id, MAX_HEIGHT, validate_draft)

FORMAT = '1soft/validator-witness/v1'
MAX_BATCH_HEADERS = 64
MAX_STORED_HEADERS = 256
MAX_TRUST_SECONDS = 31 * 86400  # a development bound, NOT a safe unbonding-period choice


def nanos(text):
    value = timestamp(text)
    return value.seconds * 10**9 + value.nanos


def validate_policy(value):
    p = freeze(value, 4096)
    exact(p, {'schema','format','genesis_sha256','anchor_height','anchor_hash',
              'anchor_time','trust_period_seconds','max_clock_drift_seconds',
              'expected_block_version','expected_app_version'}, 'external transition policy')
    integer(p['schema'], 1, 1)
    need(p['format'] == '1soft/validator-policy/v1', 'unsupported transition policy')
    hex_text(p['genesis_sha256']); hex_text(p['anchor_hash'])
    integer(p['anchor_height'], 1); nanos(p['anchor_time'])
    integer(p['trust_period_seconds'], 1, MAX_TRUST_SECONDS)
    integer(p['max_clock_drift_seconds'], 0, 60)
    integer(p['expected_block_version'], 1); integer(p['expected_app_version'], 1)
    return p


def _clock(p, now_ns):
    integer(now_ns, 0, 2**63 - 1)
    start = nanos(p['anchor_time']); expiry = start + p['trust_period_seconds'] * 10**9
    need(start <= now_ns < expiry, 'fixed anchor trust period is not currently valid')
    return expiry


def verify_header(entry, chain_id, policy, now_ns):
    """Verify ORIGINAL bytes/fields. Never patch NextValidatorsHash to evade legacy checks."""
    exact(entry, {'signed_header','validators','next_validators'}, 'validator header evidence')
    current = ValidatorSet.parse(entry['validators']); following = ValidatorSet.parse(entry['next_validators'])
    sh = entry['signed_header']; exact(sh, {'header','commit'}, 'signed header')
    h = sh['header']; digest = header_hash(h)
    height = number(h['height'], minimum=1, maximum=MAX_HEIGHT)
    need(h['chain_id'] == chain_id, 'header belongs to another chain')
    need(number(h['version']['block']) == policy['expected_block_version'] and
         number(h['version']['app']) == policy['expected_app_version'],
         'protocol version changed; a separate upgrade contract is required')
    need(hexbytes(h['validators_hash'],32).hex() == current.hash, 'current roster not committed by header')
    need(hexbytes(h['next_validators_hash'],32).hex() == following.hash, 'next roster not committed by header')
    need(hexbytes(h['proposer_address'],20) in {v.address for v in current.validators}, 'unknown proposer')
    stamp = nanos(h['time'])
    need(stamp <= now_ns + policy['max_clock_drift_seconds'] * 10**9, 'header is too far in the future')
    c = sh['commit']; exact(c, {'height','round','block_id','signatures'}, 'commit')
    need(number(c['height'], minimum=1) == height, 'commit/header height differs')
    round_ = number(c['round'], maximum=2**31 - 1)
    need(block_id(c['block_id']).hash == digest, 'commit does not bind original header')
    sigs = c['signatures']
    need(type(sigs) is list and len(sigs) == len(current.validators), 'wrong signature slot count')
    power = 0
    for v, sig in zip(current.validators, sigs):
        exact(sig, {'block_id_flag','validator_address','timestamp','signature'}, 'validator signature')
        flag = number(sig['block_id_flag'], minimum=1, maximum=3)
        if flag == 1:
            need(sig['validator_address'] == '' and sig['signature'] in (None, ''), 'nonempty absent slot')
            need(nanos(sig['timestamp']) == -62135596800 * 10**9, 'nonzero absent timestamp')
            continue
        need(hexbytes(sig['validator_address'],20) == v.address, 'signature/address slot differs')
        wire = vote_sign_bytes(chain_id, height, round_, c['block_id'] if flag == 2 else None, sig['timestamp'])
        try:
            Ed25519PublicKey.from_public_bytes(v.public_key).verify(b64(sig['signature'],64,max_size=64), wire)
        except InvalidSignature as exc:
            raise ValueError('invalid validator signature') from exc
        if flag == 2:
            power += v.power
    need(power * 3 > current.total_power * 2, 'insufficient current-set committing power')
    return {'height':height, 'block_hash':digest.hex(), 'app_hash':h['app_hash'].lower(),
            'time_ns':stamp, 'validators_hash':current.hash, 'next_validators_hash':following.hash,
            'signed_power':power, 'total_power':current.total_power}


def _verify_entries(entries, genesis, p, now_ns):
    need(type(entries) is list and 1 <= len(entries) <= MAX_STORED_HEADERS, 'invalid stored header count')
    trust = pinned_genesis(genesis, p['genesis_sha256'])
    result = []; previous_entry = previous = None
    for entry in entries:
        info = verify_header(entry, trust.chain_id, p, now_ns)
        if previous is None:
            need(info['height'] == p['anchor_height'] and info['block_hash'] == p['anchor_hash'] and
                 info['time_ns'] == nanos(p['anchor_time']), 'initial header differs from external anchor')
            if info['height'] == 1:
                need(info['validators_hash'] == trust.validators_hash.hex(), 'height-one set differs from genesis')
        else:
            need(info['height'] == previous['height'] + 1, 'nonadjacent header; no skip verification')
            need(info['validators_hash'] == previous['next_validators_hash'], 'new set was not announced by prior quorum')
            need(block_id(entry['signed_header']['header']['last_block_id']).SerializeToString() ==
                 block_id(previous_entry['signed_header']['commit']['block_id']).SerializeToString(),
                 'full preceding block identity differs')
            need(info['time_ns'] > previous['time_ns'], 'header time did not advance')
        result.append(info); previous_entry = entry; previous = info
    return result


def verify_witness(value, genesis, policy, *, now_ns):
    p = validate_policy(policy); expiry = _clock(p, now_ns)
    w = freeze(value)
    exact(w, {'schema','format','policy_sha256','entries','last_observed_clock_ns'}, 'validator witness')
    integer(w['schema'], 1, 1)
    need(w['format'] == FORMAT and w['policy_sha256'] == document_id(p), 'witness policy differs')
    integer(w['last_observed_clock_ns'], 0, 2**63 - 1)
    need(nanos(p['anchor_time']) <= w['last_observed_clock_ns'] <= now_ns,
         'local clock regressed or stored observation time invalid')
    summaries = _verify_entries(w['entries'], genesis, p, now_ns)
    need(summaries[-1]['time_ns'] <= w['last_observed_clock_ns'] + p['max_clock_drift_seconds'] * 10**9,
         'stored observation predates its final header')
    changes = [{'height':s['height'], 'from_hash':summaries[i-1]['validators_hash'],
                'to_hash':s['validators_hash']} for i,s in enumerate(summaries)
               if i and s['validators_hash'] != summaries[i-1]['validators_hash']]
    return {'schema':1,'status':'verified-sequential-validator-history',
            'witness_sha256':document_id(w), 'policy_sha256':document_id(p),
            'anchor_height':summaries[0]['height'], 'final_height':summaries[-1]['height'],
            'final_header_hash':summaries[-1]['block_hash'], 'final_app_hash':summaries[-1]['app_hash'],
            'headers_verified':len(summaries),'validator_changes':changes,
            'trust_expires_ns':expiry, 'checked_at_ns':now_ns, 'latest_state_guaranteed':False,
            'governance_authorization_established':False,'native_state_verified':False,
            'wallet_authority_changed':False, 'public_network_ready':False}


def start_witness(entry, genesis, policy, *, now_ns):
    p = validate_policy(policy)
    w = {'schema':1, 'format':FORMAT, 'policy_sha256':document_id(p),
         'entries':[freeze(entry)],'last_observed_clock_ns':now_ns}
    verify_witness(w, genesis, p, now_ns=now_ns)
    return w


def extend_witness(previous, entries, genesis, policy, *, expected_parent_sha256, now_ns):
    """Return a NEW witness; caller's old proof remains unchanged even on failure."""
    old = freeze(previous); batch = freeze(entries)
    need(document_id(old) == hex_text(expected_parent_sha256), 'wrong parent witness')
    verify_witness(old, genesis, policy, now_ns=now_ns)
    need(type(batch) is list and 1 <= len(batch) <= MAX_BATCH_HEADERS, 'invalid append batch')
    new = {**old, 'entries':old['entries'] + batch, 'last_observed_clock_ns':now_ns}
    verify_witness(new, genesis, policy, now_ns=now_ns)
    return new


def audit_transition(draft, witness, genesis, policy, *, now_ns):
    """Observe the H/H+1/H+2/H+3 roster timeline, NOT approval or transaction execution."""
    p = validate_draft(draft); checked = verify_witness(witness, genesis, policy, now_ns=now_ns)
    trust = pinned_genesis(genesis, policy['genesis_sha256'])
    need(p['chain_id'] == trust.chain_id and p['native_genesis_hash'] == trust.native_genesis_hash,
         'plan belongs to a different native chain')
    entries = freeze(witness)['entries']
    byheight = {number(e['signed_header']['header']['height']):e for e in entries}
    h = p['emitted_height']; old = p['old_set_hash']; new = p['new_set_hash']
    expected = [(h,old,old),(h+1,old,new),(h+2,new,new),(h+3,new,new)]
    observed = []
    for height, current, following in expected:
        need(height in byheight, 'transition audit lacks complete H through H+3 coverage')
        header = byheight[height]['signed_header']['header']
        need(hexbytes(header['validators_hash'],32).hex() == current and
             hexbytes(header['next_validators_hash'],32).hex() == following, 'transition activation timeline differs')
        observed.append({'height':height,'validators_hash':current,'next_validators_hash':following})
    return {'schema':1,'status':'planned-roster-timeline-observed', 'plan_sha256':document_id(p),
            'witness_sha256':checked['witness_sha256'], 'timeline':observed,
            'governance_authorization_established':False, 'abci_emission_observed':False,
            'last_commit_payload_verified':False, 'node_upgrade_performed':False,
            'wallet_authority_changed':False, 'public_network_ready':False}
