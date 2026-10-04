"""Reconcile this wallet's signed decisions against one authenticated FULL state.

No network calls, signing, cancellation, custody or cross-wallet guarantee. The
caller verifies/locks the witness and owns the same SQLite transaction that will
record a new signature. Immutable decisions are the authority for local holds;
status labels are derived, never accepted as an endpoint's assertion.
"""
from __future__ import annotations

import hashlib
import json
from collections import defaultdict

from commit_verifier import encode, ensure, load_json, verify_native_signatures
from native_core import (DOMAIN, canonical, pubkey, require, verify_account_key_acceptance)
from offline_signer import review_intent

REVIEW_DOMAIN = b'1soft/certified-review/v1\x00'
MAX_DECISIONS = 10000
MAX_REVIEW_BYTES = 65536


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def lane(body: dict, mode: str, signer: str) -> tuple:
    """Native owner counters never reset; grant labels are immutable per owner.

    Consent signatures are not debits and use a separate conflict domain.
    Native genesis is already fixed by the enclosing journal's pinned policy.
    """
    if mode == 'accept':
        return (body['sender'], 'incoming-consent', signer, body['nonce'])
    return (body['sender'], 'grant' if body['grant_id'] else 'owner',
            body['grant_id'], body['nonce'])


def checked_decision(row, genesis: dict, policy_id: str) -> dict:
    """Verify the exact signed bytes and immutable local review before using it.

    Existing certificate-wallet journals are read without replacing signatures.
    No pre-existing decision is assumed paid merely because it predates this code.
    The journal remains a trusted-local store, not hostile-OS tamper protection.
    """
    decision_id, slot, review_json, result_json, result_hash = row
    require(all(type(s) is str for s in row), 'invalid stored decision types')
    require(len(review_json.encode()) <= MAX_REVIEW_BYTES and len(result_json.encode()) <= 16384,
            'stored signing decision exceeds bound')
    review = load_json(review_json.encode(), max_bytes=MAX_REVIEW_BYTES)
    result = load_json(result_json.encode(), max_bytes=16384)
    require(type(review) is dict and review.get('confirmation') == decision_id,
            'stored review identifier mismatch')
    material = {k: v for k, v in review.items() if k != 'confirmation'}
    require(sha(REVIEW_DOMAIN + encode(material)) == decision_id,
            'stored review commitment mismatch')
    require(review.get('trust_policy_sha256') == policy_id, 'decision trust policy differs')
    require(canonical(result).decode() == result_json and sha(result_json.encode()) == result_hash,
            'stored decision integrity mismatch')
    mode, signer, body = review.get('mode'), review.get('signer_public_key'), review.get('body')
    require(mode in ('sign', 'accept'), 'invalid stored signing mode')
    base = review_intent(genesis, body, signer, mode=mode)
    require(review.get('proposed_account_debit_units') == base['proposed_account_debit_units'],
            'stored debit differs from signed intention')
    require(type(review.get('state_height')) is int and review['state_height'] >= 0,
            'invalid signing checkpoint')
    if mode == 'sign':
        require(result.get('body') == body, 'stored signature belongs to another intention')
        verify_native_signatures(result, signer, protocol_version=genesis.get('protocol_version', 1))
        txid = sha(DOMAIN + canonical(body))
    else:
        require(type(result) is dict and type(result.get('op')) is dict,
                'invalid stored incoming-key consent')
        verify_account_key_acceptance(result)
        without_acceptance = json.loads(canonical(result))
        without_acceptance['op']['acceptance'] = ''
        require(without_acceptance == body and signer == result['op']['public_key'],
                'stored consent belongs to another intention')
        txid = None
    return {'decision_id': decision_id, 'review': review, 'result': result,
            'body': body, 'mode': mode, 'signer': signer, 'native_txid': txid,
            'lane': lane(body, mode, signer), 'debit': 0 if mode == 'accept' else base['proposed_account_debit_units']}


def classify_authenticated_receipt(row: list | tuple | None, *,
                                   local_envelope: dict, expected_signer: str,
                                   state_height: int,
                                   minimum_receipt_height: int = 1) -> str:
    """Classify one receipt from state the caller has already authenticated.

    This pure function performs no proof verification, signing or journal writes.
    The caller must separately bind the state to its trusted genesis/checkpoint and
    verify the local envelope's signatures. A wallet can use its signing checkpoint
    plus one as minimum_receipt_height, within the transaction that owns its holds.
    """
    pubkey(expected_signer)
    ensure(type(state_height) is int and state_height >= 0,
           'invalid authenticated state height')
    ensure(type(minimum_receipt_height) is int and minimum_receipt_height >= 1,
           'invalid minimum receipt height')
    ensure(type(local_envelope) is dict and set(local_envelope) == {'body', 'signature'} and
           type(local_envelope['body']) is dict, 'invalid local native envelope')
    body = local_envelope['body']
    valid_until = body.get('valid_until')
    ensure(type(valid_until) is int and valid_until >= 0, 'invalid signed validity height')
    if row is None:
        return 'absent_after_expiry' if state_height > valid_until else 'pending'

    txid = sha(DOMAIN + canonical(body))
    ensure(type(row) in (list, tuple) and len(row) == 5 and row[0] == txid and
           type(row[1]) is int and row[1] >= 1 and
           all(type(row[index]) is str for index in (2, 3, 4)),
           'invalid authenticated receipt row')
    record = load_json(row[3].encode(), max_bytes=32768)
    ensure(type(record) is dict, 'invalid authenticated receipt record')
    ensure(record.get('txid') == txid and
           canonical(record.get('envelope')) == canonical(local_envelope) and
           record.get('signer_public_key') == expected_signer,
           'authenticated receipt differs from local wire')
    ensure(type(record.get('sequence')) is int and record['sequence'] == row[1],
           'authenticated receipt sequence differs from row')
    ensure(record.get('previous') == row[2], 'authenticated receipt previous digest differs from row')
    ensure(type(record.get('height')) is int and
           minimum_receipt_height <= record['height'] <= valid_until and
           record['height'] <= state_height,
           'receipt height outside signed validity or checkpoint')
    ensure(sha(encode(record)) == row[4], 'receipt record digest mismatch')
    return 'included'


def inventory(db, policy_id: str, ledger, state_height: int) -> dict:
    """Derive holds from signed decisions, not from manual or provider status.

    Retirement requires an exact receipt in this attested, semantically checked
    unpruned state, or absence after the signed validity height has passed. Until
    then even revocation, nonce advancement or a timeout keeps the conservative
    hold. Incoming-key consent cannot spend and therefore creates no balance hold.
    """
    rows = db.execute('SELECT id,slot,review,result,result_hash FROM decisions ORDER BY id').fetchall()
    require(len(rows) <= MAX_DECISIONS, 'development decision-count limit exceeded')
    accounts, grants, budgets = defaultdict(int), defaultdict(int), defaultdict(int)
    entries, pending_lanes = [], set()
    for row in rows:
        item = checked_decision(row, ledger.genesis, policy_id)
        body = item['body']
        require(state_height >= item['review']['state_height'], 'witness predates an existing decision')
        budget_id = None
        if item['mode'] == 'accept':
            # Never charges the sponsor; only its separate native signature can.
            status = 'consent_only'
        else:
            receipt = ledger.db.execute(
                'SELECT txid,sequence,previous,record,hash FROM receipts WHERE txid=?',
                (item['native_txid'],)).fetchone()
            classification = classify_authenticated_receipt(
                None if receipt is None else tuple(receipt),
                local_envelope=item['result'], expected_signer=item['signer'],
                state_height=state_height,
                minimum_receipt_height=item['review']['state_height'] + 1)
            status = {'included': 'recorded', 'absent_after_expiry': 'expired_absent',
                      'pending': 'pending'}[classification]
            if body['grant_id'] and ledger.protocol_version == 3:
                grant_key = ledger.grant_storage_id(body['sender'], body['grant_id'])
                link = ledger.db.execute('SELECT budget_id FROM grant_budgets WHERE grant_id=?',
                                         (grant_key,)).fetchone()
                require(link is not None, 'signed grant lost its immutable budget binding')
                budget_id = link[0]
                require(item['review'].get('shared_budget_id') == budget_id,
                        'signed decision budget differs from authenticated binding')
            if status == 'pending':
                require(item['lane'] not in pending_lanes, 'multiple pending decisions occupy one native nonce')
                pending_lanes.add(item['lane'])
                accounts[body['sender']] += item['debit']
                if body['grant_id']:
                    grant_key = ledger.grant_storage_id(body['sender'], body['grant_id'])
                    grants[grant_key] += item['debit']
                if budget_id is not None:
                    budgets[budget_id] += item['debit']
        entries.append({'decision_id': item['decision_id'], 'native_txid': item['native_txid'],
                        'mode': item['mode'], 'status': status, 'account': body['sender'],
                        'grant_id': body['grant_id'], 'budget_id': budget_id, 'nonce': body['nonce'],
                        'valid_until': body['valid_until'], 'debit_units': item['debit'],
                        'lane': list(item['lane'])})
    # The full inventory is included by digest so another process's signing or
    # retirement invalidates a review displayed before that change.
    material = {'entries': entries, 'accounts': dict(accounts), 'grants': dict(grants),
                'budgets': dict(budgets)}
    return {**material, 'digest': sha(encode(material)), 'decisions': len(rows)}


def constrain(view: dict, summary: dict, ledger, body: dict, mode: str, signer: str) -> dict:
    """Add local reservations to the already-verified native state constraints."""
    candidate_lane = list(lane(body, mode, signer))
    # Identical signatures are always recovered, never newly signed. Consent
    # decisions remain one-use locally even after their timing window closes.
    target = sha(DOMAIN + canonical(body)) if mode == 'sign' else None
    for entry in summary['entries']:
        if mode == 'sign' and entry['native_txid'] == target:
            require(False, 'this intention already has a local signing decision; export it instead')
        if entry['lane'] == candidate_lane and entry['status'] in ('pending', 'consent_only'):
            require(False, 'this authority nonce already has a local signing decision; export or reconcile it instead')
    require(summary['decisions'] < MAX_DECISIONS, 'development decision-count limit reached')
    held_balance = summary['accounts'].get(body['sender'], 0)
    grant_key = ledger.grant_storage_id(body['sender'], body['grant_id']) if body['grant_id'] else None
    held_grant = summary['grants'].get(grant_key, 0) if grant_key else 0
    budget_key = view.get('shared_budget_id')
    held_budget = summary['budgets'].get(budget_key, 0) if budget_key else 0
    debit = view['proposed_account_debit_units'] if mode == 'sign' else 0
    if mode == 'sign':
        require(debit + held_balance <= view['account_balance_units'],
                'balance insufficient after pending signed obligations')
        if grant_key:
            require(debit + held_grant <= view['grant_remaining_units'],
                    'grant insufficient after pending signed obligations')
        if budget_key:
            require(debit + held_budget <= view['shared_budget_remaining_units'],
                    'shared budget insufficient after pending signed obligations')
    return {'reservation_schema': 1, 'local_obligations_digest': summary['digest'],
            'pending_account_debit_units': held_balance,
            'account_available_after_pending_units': max(0, view['account_balance_units'] - held_balance),
            'pending_grant_debit_units': held_grant,
            'grant_available_after_pending_units': None if not grant_key else max(0, view['grant_remaining_units'] - held_grant),
            'pending_shared_budget_debit_units': held_budget,
            'shared_budget_available_after_pending_units': None if not budget_key else max(0, view['shared_budget_remaining_units'] - held_budget),
            'reservation_scope': 'signed obligations in this journal only; not a chain-wide balance lock'}
