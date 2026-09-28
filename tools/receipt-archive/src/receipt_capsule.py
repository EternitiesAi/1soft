"""Portable historical receipt evidence; never current balance or spend authority.

The caller independently pins BOTH genesis bytes and the final header hash. The
capsule supplies neither trust nor a new signature algorithm. Legacy flat chains
retain a full state witness; SMT chains carry one existing authenticated proof.
No receipt absence result, wallet mutation, network access or pruning API exists.
"""
from __future__ import annotations

import hashlib

from block_application import restore
from commit_verifier import (b64, block_id, encode, exact, load_json, pinned_genesis,
    timestamp, verify_packet, verify_signed_header)
from compact_verifier import verify_compact_receipt
from native_core import DOMAIN, canonical
from offline_signer import review_intent
from state_tree import make_witness

FORMAT = '1soft-receipt-capsule-v1'
MAX_BYTES = 16 * 1024 * 1024
MAX_LINKS = 64
FIELDS = {'schema', 'format', 'genesis_sha256', 'transaction', 'state_commit',
          'inclusion', 'continuation', 'proof_kind', 'witness'}
RECORD_FIELDS = {'txid','sequence','previous','height','state_hash','fee_units',
                 'signer_public_key','envelope'}

class ArchiveError(ValueError):
    """Missing or inconsistent evidence; never means that payment failed."""


def need(condition, message):
    if not condition:
        raise ArchiveError(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def hash_text(value):
    need(type(value) is str and len(value) == 64 and
         all(c in '0123456789abcdef' for c in value), 'expected lowercase SHA-256')
    return value


def frozen(value):
    raw = encode(value)
    need(len(raw) <= MAX_BYTES, 'receipt capsule exceeds byte limit')
    return load_json(raw, max_bytes=MAX_BYTES)


def transaction_identity(raw):
    need(type(raw) is bytes, 'exact signed transaction bytes required')
    env = load_json(raw, max_bytes=16384)
    exact(env, {'body', 'signature'}, 'requested transaction')
    need(canonical(env) == raw, 'noncanonical signed transaction')
    return sha(DOMAIN + canonical(env['body'])), sha(raw), env


def _ns(text):
    value = timestamp(text)
    return value.seconds * 1_000_000_000 + value.nanos


def _ancestry(inclusion, final, links, trust):
    need(type(links) is list and len(links) <= MAX_LINKS, 'bounded signed ancestry required')
    prior = verify_signed_header(inclusion, trust)
    target = verify_signed_header(final, trust)
    need(target['height'] > prior['height'] and
         len(links) == target['height'] - prior['height'] - 1,
         'exact intervening signed headers required')
    previous = inclusion
    for following in [*links, final]:
        info = verify_signed_header(following, trust, expected_height=prior['height'] + 1)
        need(block_id(following['header']['last_block_id']).SerializeToString() ==
             block_id(previous['commit']['block_id']).SerializeToString(),
             'receipt inclusion does not extend to pinned state header')
        need(_ns(following['header']['time']) >= _ns(previous['header']['time']),
             'historical header time regressed')
        previous, prior = following, info
    return target


def _record(row, envelope, txid, genesis, state_height):
    need(type(row) is list and len(row) == 5, 'receipt row missing')
    record = load_json(row[3].encode(), max_bytes=16384)
    exact(record, RECORD_FIELDS, 'execution receipt')
    need(encode(record).decode() == row[3] and sha(encode(record)) == row[4],
         'noncanonical or changed receipt record')
    need(row[0] == record['txid'] == txid and row[2] == record['previous'],
         'receipt identity/link differs')
    need(type(row[1]) is int and type(record['sequence']) is int and
         1 <= row[1] == record['sequence'] <= 2**53-1, 'receipt sequence differs')
    for key in ('txid', 'previous', 'state_hash', 'signer_public_key'):
        hash_text(record[key])
    need(record['envelope'] == envelope, 'receipt differs from exact signed payment')
    need(type(record['height']) is int and 1 <= record['height'] <= state_height and
         record['height'] <= envelope['body']['valid_until'], 'receipt execution height invalid')
    need(type(record['fee_units']) is int and record['fee_units'] == genesis['fee'],
         'receipt fee differs from native genesis')
    review_intent(genesis, envelope['body'], record['signer_public_key'])
    return record


def verify_capsule(capsule, genesis_bytes, expected_genesis_sha256, *,
                   expected_transaction, expected_header_hash):
    """Reverify portable evidence under EXTERNAL exact-transaction/checkpoint pins.

    History has no live-clock expiry check. A valid old receipt is not a current
    account statement, a refreshed trust policy, or permission to release a hold.
    """
    hash_text(expected_genesis_sha256)
    hash_text(expected_header_hash)
    trust = pinned_genesis(genesis_bytes, expected_genesis_sha256)
    c = frozen(capsule)
    exact(c, FIELDS, 'receipt capsule')
    need(type(c['schema']) is int and c['schema'] == 1 and c['format'] == FORMAT,
         'unsupported receipt capsule version')
    need(c['genesis_sha256'] == expected_genesis_sha256, 'capsule genesis file differs')
    txid, wire_hash, env = transaction_identity(expected_transaction)
    need(b64(c['transaction']) == expected_transaction, 'capsule selects a different signed payment')
    exact(c['inclusion'], {'block', 'commit'}, 'inclusion evidence')
    header = _ancestry(c['inclusion']['commit'], c['state_commit'], c['continuation'], trust)
    need(header['block_hash'].lower() == expected_header_hash, 'state header differs from external pin')
    if c['proof_kind'] == 'smt-v1':
        verified = verify_compact_receipt(c['witness'], c['state_commit'], trust,
            expected_transaction=expected_transaction, **c['inclusion'])
        row = c['witness']['entries'][0]['value']
        genesis = c['witness']['genesis']
        height = verified['state_height']
    elif c['proof_kind'] == 'legacy-full-state-v1':
        genesis = c['witness']['genesis']
        need('state_commitment' not in genesis, 'SMT capsule must use selected receipt proof')
        packet = {'schema': 1, 'state': c['witness'], 'state_commit': c['state_commit'],
            'transactions': [{'tx': c['transaction'], **c['inclusion']}]}
        verified = verify_packet(packet, trust, expected_txids=[txid])
        rows = [r for r in c['witness']['native']['receipts'] if r[0] == txid]
        need(len(rows) == 1, 'exact receipt missing')
        row, height = rows[0], verified['state']['state_height']
    else:
        raise ArchiveError('unsupported receipt evidence type')
    record = _record(row, env, txid, genesis, height)
    need(record['height'] == int(c['inclusion']['commit']['header']['height']),
         'execution receipt differs from included block height')
    return {'schema': 1, 'status': 'verified-historical-receipt',
        'evidence_id': sha(encode(c)), 'native_txid': txid, 'wire_sha256': wire_hash,
        'receipt_sha256': sha(encode(record)), 'receipt': record,
        'genesis_sha256': expected_genesis_sha256,
        'state_header_hash': expected_header_hash, 'state_header_height': header['height'],
        'state_height': height, 'proof_kind': c['proof_kind'],
        'inclusion_to_state_ancestry_verified': True, 'latest_state_guaranteed': False,
        'wallet_reservations_changed': False, 'historical_absence_proven': False,
        'external_settlement_verified': False, 'live_network_provenance_established': False}


def pack_receipt(packet, genesis_bytes, expected_genesis_sha256, *,
                 expected_transaction, expected_header_hash, continuation=None):
    """Convert an existing saved certificate to a portable receipt capsule.

    The full-state input is validated once. SMT output drops unrelated state and
    receipts but keeps transaction-block inclusion and exact signed ancestry.
    Flat commitment output must keep the full witness: no fictitious compression.
    """
    p = frozen(packet)
    exact(p, {'schema', 'state', 'state_commit', 'transactions'}, 'source certificate')
    need(type(p['schema']) is int and p['schema'] == 1, 'unsupported source certificate')
    need(type(p['transactions']) is list and len(p['transactions']) <= 64,
         'source transaction witness bound exceeded')
    matches = []
    for item in p['transactions']:
        exact(item, {'tx', 'block', 'commit'}, 'source inclusion')
        if b64(item['tx']) == expected_transaction:
            matches.append(item)
    need(len(matches) == 1, 'exact selected transaction must occur once')
    trust = pinned_genesis(genesis_bytes, expected_genesis_sha256)
    txid, _, _ = transaction_identity(expected_transaction)
    selected = {**p, 'transactions': matches}
    verify_packet(selected, trust, expected_txids=[txid])
    # Check native receipt/invariant consistency before deriving a new proof.
    ledger = restore(p['state']['genesis'], p['state']['native'])
    ledger.close()
    state, item = p['state'], matches[0]
    smt = state['genesis'].get('state_commitment') == 'smt-v1'
    witness = (make_witness(state['genesis'], state['height'], state['native'], [('receipts', txid)])
               if smt else state)
    capsule = {'schema': 1, 'format': FORMAT, 'genesis_sha256': expected_genesis_sha256,
        'transaction': item['tx'], 'state_commit': p['state_commit'],
        'inclusion': {'block': item['block'], 'commit': item['commit']},
        'continuation': [] if continuation is None else continuation,
        'proof_kind': 'smt-v1' if smt else 'legacy-full-state-v1', 'witness': witness}
    capsule = frozen(capsule)  # Detach caller-owned continuation before verification.
    verify_capsule(capsule, genesis_bytes, expected_genesis_sha256,
        expected_transaction=expected_transaction, expected_header_hash=expected_header_hash)
    return capsule
