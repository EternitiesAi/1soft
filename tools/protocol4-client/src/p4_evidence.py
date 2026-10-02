"""P4 verified read-side evidence; no signer, dispatch, wallet or node mutation.

Signed header ancestry, exact transaction inclusion and a replay of BOTH native
payment and administrative state are required. Snapshot replay inputs alone do not
establish block identity. This is a bounded full-history verifier, not a light
client with skip verification, nor a new consensus implementation.
"""
from __future__ import annotations

import hashlib
from typing import Any

from block_application import encode
from commit_verifier import (b64, block_id, exact, hexbytes, load_json, merkle_root,
                             number, sha)
from native_core import canonical, digest, FEE_ACCOUNT
from protocol4_application import Protocol4Application, MAX_HEIGHT, MAX_TX_BYTES
from validator_sets_core import ValidatorSet
from validator_witness import verify_header, nanos

FORMAT = '1soft/protocol4-read-evidence/v1'
POLICY_FORMAT = '1soft/protocol4-read-policy/v1'
MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
MAX_GENESIS_BYTES = 1024 * 1024
MAX_TRUST_SECONDS = 31 * 86400  # Development limit, NOT an economic security recommendation.


class EvidenceError(ValueError):
    """Unavailable or rejected evidence does not mean an unpaid transaction."""


def need(value, message):
    if not value:
        raise EvidenceError(message)


def integer(value, low=0, high=2**63-1):
    need(type(value) is int and low <= value <= high, 'invalid exact integer')
    return value


def hash_text(value):
    need(type(value) is str and len(value) == 64 and
         all(c in '0123456789abcdef' for c in value), 'expected lowercase SHA-256')
    return value


def content_id(value):
    return hashlib.sha256(encode(value)).hexdigest()


def freeze(value, maximum=MAX_EVIDENCE_BYTES):
    raw = encode(value)
    need(len(raw) <= maximum, 'evidence exceeds bounded input size')
    return load_json(raw, max_bytes=maximum)


def policy_checked(value):
    p = freeze(value, 4096)
    exact(p, {'schema', 'format', 'genesis_sha256', 'anchor_height', 'anchor_hash',
              'anchor_time', 'trust_period_seconds', 'max_clock_drift_seconds',
              'expected_block_version'}, 'external P4 read policy')
    integer(p['schema'], 1, 1)
    need(p['format'] == POLICY_FORMAT, 'unsupported P4 read policy')
    hash_text(p['genesis_sha256']); hash_text(p['anchor_hash'])
    integer(p['anchor_height'], 1, MAX_HEIGHT+1)
    nanos(p['anchor_time'])
    integer(p['trust_period_seconds'], 1, MAX_TRUST_SECONDS)
    integer(p['max_clock_drift_seconds'], 0, 60)
    integer(p['expected_block_version'], 11, 11)
    return p


def check_clock(policy, now_ns, previous_ns=None):
    integer(now_ns)
    start = nanos(policy['anchor_time'])
    expiry = start + policy['trust_period_seconds'] * 10**9
    need(start <= now_ns < expiry, 'fixed external trust policy is not currently valid')
    if previous_ns is not None:
        integer(previous_ns)
        need(start <= previous_ns <= now_ns, 'stored observation or local clock regressed')
    return expiry


def p4_genesis(raw, expected_digest):
    """Distinct P4 genesis path; the legacy static TrustAnchor stays unchanged."""
    need(type(raw) is bytes and 0 < len(raw) <= MAX_GENESIS_BYTES, 'bounded genesis bytes required')
    need(hashlib.sha256(raw).hexdigest() == hash_text(expected_digest), 'external genesis pin differs')
    engine = load_json(raw, max_bytes=MAX_GENESIS_BYTES)
    need(type(engine) is dict and number(engine.get('initial_height', '1'), minimum=1) == 1,
         'unsupported engine genesis or initial height')
    g = engine.get('app_state')
    need(type(g) is dict and type(g.get('protocol_version')) is int and g['protocol_version'] == 4,
         'this read path accepts only fresh-genesis P4')
    need(engine.get('chain_id') == g.get('chain_id'), 'engine/native chain identity differs')
    Protocol4Application._validate_genesis(g)
    roster = ValidatorSet.parse(g['validator_registry']['validators'])
    rows = engine.get('validators')
    need(type(rows) is list and len(rows) == len(roster.validators), 'engine initial roster differs')
    observed = {}
    for row in rows:
        need(type(row) is dict, 'invalid genesis validator')
        pk = row.get('pub_key'); exact(pk, {'type', 'value'}, 'genesis validator key')
        need(pk['type'] == 'tendermint/PubKeyEd25519', 'unsupported validator key')
        raw_key = b64(pk['value'], 32, max_size=32)
        address = sha(raw_key)[:20]
        need(hexbytes(row.get('address'), 20) == address and raw_key not in observed,
             'genesis key/address mismatch or duplicate')
        observed[raw_key] = number(row.get('power'), minimum=1)
    need(observed == {v.public_key: v.power for v in roster.validators},
         'engine initial powers differ from committed registry')
    return g, roster


def _header_identity(entry):
    sh = entry['signed_header']
    return {'header': sh['header'], 'block_id': sh['commit']['block_id']}


def extends(previous, incoming):
    """Check exact already accepted history, ignoring only valid signature subsets."""
    need(incoming['state']['height'] >= previous['state']['height'], 'P4 read checkpoint rollback')
    old_history = previous['history']; old_headers = previous['headers']
    need(encode(incoming['history'][:len(old_history)]) == encode(old_history),
         'previously accepted transaction history changed')
    for left, right in zip(old_headers, incoming['headers']):
        need(encode(_header_identity(left)) == encode(_header_identity(right)),
             'previously accepted signed block identity changed')
    if incoming['state']['height'] == previous['state']['height']:
        need(encode(previous['state']) == encode(incoming['state']), 'same-height composite state conflict')


def verify_evidence(value, genesis_bytes, policy, *, now_ns):
    """Return independently reconstructed read data under explicit fixed trust pins.

    No packet field can choose the policy. All H transaction lists match signed
    header DataHash values; signed header H+1 commits the final state H. We do not
    claim to have observed actual ABCI request/response packets or validator hosts.
    Re-execution deliberately reuses the pinned node implementation.
    """
    p = policy_checked(policy); expiry = check_clock(p, now_ns)
    g, initial_roster = p4_genesis(genesis_bytes, p['genesis_sha256'])
    e = freeze(value)
    exact(e, {'schema', 'format', 'state', 'history', 'headers'}, 'P4 evidence')
    integer(e['schema'], 1, 1)
    need(e['format'] == FORMAT, 'unsupported P4 evidence format')
    state = e['state']; exact(state, {'genesis', 'height', 'app_hash', 'native', 'registry'}, 'P4 state')
    h = integer(state['height'], 0, MAX_HEIGHT)
    hash_text(state['app_hash'])
    need(encode(state['genesis']) == encode(g), 'evidence changes the pinned full native genesis')
    need(type(e['history']) is list and len(e['history']) == h, 'complete ordered P4 history required')
    need(type(e['headers']) is list and len(e['headers']) == h+1, 'signed history from height 1 through H+1 required')
    need(p['anchor_height'] <= h+1, 'external anchor not reached')
    header_policy = {'expected_app_version': 4, 'expected_block_version': p['expected_block_version'],
                     'max_clock_drift_seconds': p['max_clock_drift_seconds']}
    summaries = []; previous = None; exact_anchor_seen = False
    # Verify signatures/ancestry before running any supplied transaction inputs.
    for expected_height, entry in enumerate(e['headers'], 1):
        info = verify_header(entry, g['chain_id'], header_policy, now_ns)
        need(info['height'] == expected_height, 'nonconsecutive P4 header history')
        if previous is None:
            need(info['validators_hash'] == initial_roster.hash, 'first header roster differs from genesis')
            first_parent = block_id(entry['signed_header']['header']['last_block_id'], allow_empty=True)
            need(not first_parent.hash and first_parent.part_set_header.total == 0 and
                 not first_parent.part_set_header.hash, 'height-one header invents an earlier block')
        else:
            prior = e['headers'][expected_height-2]['signed_header']
            need(info['validators_hash'] == previous['next_validators_hash'], 'unannounced validator roster')
            need(block_id(entry['signed_header']['header']['last_block_id']).SerializeToString() ==
                 block_id(prior['commit']['block_id']).SerializeToString(), 'complete previous block ID differs')
            need(info['time_ns'] > previous['time_ns'], 'header timestamp failed to advance')
        if expected_height == p['anchor_height']:
            need(info['block_hash'] == p['anchor_hash'] and info['time_ns'] == nanos(p['anchor_time']),
                 'independent checkpoint hash or timestamp differs')
            exact_anchor_seen = True
        previous = info; summaries.append(info)
    need(exact_anchor_seen, 'independent checkpoint missing')
    attempts = []; updates = []; transitions = []
    with Protocol4Application(':memory:', expected_genesis=g) as app:
        app.init_chain(g['chain_id'], g, g['validator_registry']['validators'])
        for height in range(1, h+1):
            row = e['history'][height-1]; exact(row, {'height', 'txs'}, 'P4 replay block')
            integer(row['height'], height, height)
            need(type(row['txs']) is list, 'transaction list required')
            # Check the encoded size before decoding and enforce the node bounds.
            need(len(row['txs']) <= 64 and all(type(t) is str and len(t) <= (MAX_TX_BYTES+2)//3*4
                                              for t in row['txs']), 'bounded transaction encodings required')
            txs = [Protocol4Application._wire_from_b64(t) for t in row['txs']]
            Protocol4Application._bounds(txs)
            header = e['headers'][height-1]['signed_header']['header']
            need(merkle_root([sha(raw) for raw in txs]) == hexbytes(header['data_hash'], 32, empty=True),
                 'replay transaction list is not the signed block data')
            need(summaries[height-1]['app_hash'] == app.app_hash, 'header does not commit prior composite state')
            before_epoch = app.state['registry']['epoch']
            after, result = app._execute(txs, height)
            need(result['validators_hash'] == summaries[height-1]['validators_hash'] and
                 result['next_validators_hash'] == summaries[height-1]['next_validators_hash'],
                 'signed roster schedule differs from authorized registry execution')
            need(summaries[height]['app_hash'] == result['app_hash'],
                 'signed H+1 hash differs from composite execution')
            for index, (raw, outcome) in enumerate(zip(txs, result['tx_results'])):
                kind = 'administrative' if 'receipt' in outcome else ('payment' if outcome['code'] == 0 else 'rejected')
                attempts.append({'height': height, 'index': index, 'wire_sha256': hashlib.sha256(raw).hexdigest(),
                                 'code': outcome['code'], 'kind': kind, 'id': outcome['data']})
            if result['validator_updates']:
                updates.append({'emitted_height': height, 'active_height': height+2,
                                'updates': result['validator_updates']})
            if after['registry']['epoch'] != before_epoch:
                transitions.append({'height': height, 'epoch': after['registry']['epoch'],
                                    'active_hash': after['registry']['active_hash']})
            app.state, app.height, app.app_hash = after, height, result['app_hash']
        # The anchor's roster is height-driven. A new action at H+1 cannot change
        # H+1/H+2 rosters under the pinned minimum scheduling delay. Do NOT execute
        # H+1 money, invent its body, or call its unknown transfers completed.
        _, lookahead = app.rules.transition(app.state['registry'], [], h+1)
        need(lookahead['validators_hash'] == summaries[-1]['validators_hash'] and
             lookahead['next_validators_hash'] == summaries[-1]['next_validators_hash'],
             'anchor roster differs from queued registry schedule')
        need(encode(app.state) == encode({'native': state['native'], 'registry': state['registry']}) and
             app.app_hash == state['app_hash'] == summaries[-1]['app_hash'],
             'replayed composite state differs from supplied checkpoint')
        app._audit_state(g, app.state, h, app.app_hash)
    receipts = []
    for row in state['native']['receipts']:
        record = load_json(row[3].encode(), max_bytes=32768)
        raw = canonical(record['envelope']); wire = hashlib.sha256(raw).hexdigest()
        executed = [a for a in attempts if a['height'] == record['height'] and
                    a['wire_sha256'] == wire and a['code'] == 0 and a['id'] == row[0] and a['kind'] == 'payment']
        need(len(executed) == 1, 'receipt does not name one successful included payment')
        receipts.append({'native_txid': row[0], 'receipt_sha256': row[4], 'wire_sha256': wire,
                         'height': record['height'], 'index': executed[0]['index'], 'record': record})
    accounts = [{'id': r[0], 'public_key': r[1], 'nonce': r[2], 'epoch': r[3], 'recorded_balance': str(r[4])}
                for r in state['native']['accounts']]
    return {'schema': 1, 'status': 'verified-p4-historical-state', 'evidence_id': content_id(e),
            'policy_id': content_id(p), 'genesis_sha256': p['genesis_sha256'],
            'state_height': h, 'app_hash': state['app_hash'], 'header_height': h+1,
            'header_hash': summaries[-1]['block_hash'], 'verified_headers': len(summaries),
            'registry_epoch': state['registry']['epoch'], 'registry': state['registry'],
            'accounts': accounts, 'receipts': receipts, 'attempts': attempts,
            'validator_updates': updates, 'validator_transitions': transitions,
            'grants': state['native']['grants'], 'budgets': state['native']['budgets'],
            'grant_budgets': state['native']['grant_budgets'],
            'recorded_supply_units': str(sum(int(a['recorded_balance']) for a in accounts)),
            'trust_expires_ns': expiry, 'checked_at_ns': now_ns,
            'native_execution_replayed': True, 'registry_authorization_replayed': True,
            'signed_block_inclusion_verified': True, 'actual_abci_responses_observed': False,
            'latest_state_guaranteed': False, 'pending_wallet_debits_included': False,
            'spending_authority': False, 'independent_validator_hosts_verified': False}


def _account_from_verified_report(report, account_id):
    rows = [row for row in report['accounts'] if row['id'] == account_id]
    return {'status': 'recorded' if rows else 'unavailable', 'state_height': report['state_height'],
            'account': rows[0] if rows else None, 'pending_wallet_debits_included': False,
            'spending_authority': False}


def _receipt_from_verified_report(report, exact_transaction, payer):
    need(type(exact_transaction) is bytes and len(exact_transaction) <= 16384, 'exact signed payment bytes required')
    packet = load_json(exact_transaction, max_bytes=16384)
    exact(packet, {'body', 'signature'}, 'requested P4 payment')
    need(canonical(packet) == exact_transaction and type(packet['body']) is dict and
         type(packet['body'].get('version')) is int and packet['body']['version'] == 4 and
         packet['body'].get('sender') == payer, 'requested payment version or payer differs')
    rows = [r for r in report['receipts'] if r['wire_sha256'] == hashlib.sha256(exact_transaction).hexdigest()
            and canonical(r['record']['envelope']) == exact_transaction]
    need(len(rows) <= 1, 'ambiguous recorded payment')
    return {'status': 'recorded' if rows else 'unavailable', 'receipt': rows[0] if rows else None,
            'state_height': report['state_height'], 'header_hash': report['header_hash'],
            'historical_absence_proven': False, 'wallet_reservations_changed': False,
            'external_settlement_verified': False}


def verify_account(value, genesis_bytes, policy, account_id, *, now_ns):
    """Derive an account only AFTER verifying evidence, never from a supplied view."""
    return _account_from_verified_report(
        verify_evidence(value, genesis_bytes, policy, now_ns=now_ns), account_id)


def verify_receipt(value, genesis_bytes, policy, exact_transaction, *, payer, now_ns):
    """Positive receipt evidence only. A miss is unavailable, not nonexecution."""
    return _receipt_from_verified_report(
        verify_evidence(value, genesis_bytes, policy, now_ns=now_ns), exact_transaction, payer)
