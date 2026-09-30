"""Portable positive P4 transfer receipts; trust is always supplied by the caller.

This wraps complete signed replay evidence rather than inventing a compact proof.
It cannot sign, send, reconcile a wallet, renew a policy, or prove absence.
"""
from __future__ import annotations

import base64
import hashlib

from commit_verifier import b64, encode, exact, load_json
from native_core import canonical
from p4_evidence import (MAX_EVIDENCE_BYTES, content_id, freeze, hash_text,
                         integer, need, policy_checked, verify_evidence,
                         verify_receipt)

FORMAT = '1soft/protocol4-payment-capsule/v1'
MAX_WIRE_BYTES = 16384
MAX_CAPSULE_BYTES = MAX_EVIDENCE_BYTES + 32768
MAX_DEPTH = 64
CAPSULE_FIELDS = {'schema', 'format', 'genesis_sha256', 'policy_id', 'payer',
                  'wire', 'binding', 'evidence'}
BINDING_FIELDS = {'native_txid', 'receipt_sha256', 'wire_sha256', 'height',
                  'index', 'signer_public_key'}


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def _depth_checked(raw):
    # Reject deep JSON before handing it to a recursive decoder. Strings do not
    # count as structure; malformed syntax still goes to the strict decoder.
    depth = 0
    quoted = escaped = False
    for ch in raw:
        if quoted:
            if escaped:
                escaped = False
            elif ch == 92:
                escaped = True
            elif ch == 34:
                quoted = False
        elif ch == 34:
            quoted = True
        elif ch in (91, 123):
            depth += 1
            need(depth <= MAX_DEPTH, 'capsule JSON nesting exceeds bound')
        elif ch in (93, 125):
            depth -= 1
            need(depth >= 0, 'invalid capsule JSON nesting')


def parse_capsule(value):
    """Freeze a dict or parse exact canonical bytes with bounded strict JSON."""
    if type(value) is bytes:
        raw = value
    else:
        need(type(value) is dict, 'capsule dict or bytes required')
        raw = encode(value)
    need(0 < len(raw) <= MAX_CAPSULE_BYTES, 'capsule exceeds byte bound')
    _depth_checked(raw)
    c = load_json(raw, max_bytes=MAX_CAPSULE_BYTES)
    need(encode(c) == raw, 'capsule bytes must use canonical JSON')
    exact(c, CAPSULE_FIELDS, 'P4 payment capsule')
    integer(c['schema'], 1, 1)
    need(c['format'] == FORMAT, 'unsupported P4 payment capsule')
    hash_text(c['genesis_sha256']); hash_text(c['policy_id'])
    need(type(c['payer']) is str and len(c['payer']) == 68 and
         c['payer'].startswith('lab_'), 'exact native payer required')
    hash_text(c['payer'][4:])
    exact(c['binding'], BINDING_FIELDS, 'P4 capsule receipt binding')
    for field in ('native_txid', 'receipt_sha256', 'wire_sha256', 'signer_public_key'):
        hash_text(c['binding'][field])
    integer(c['binding']['height'], 1, 512)
    integer(c['binding']['index'], 0, 63)
    _transaction(b64(c['wire'], max_size=MAX_WIRE_BYTES), c['payer'])
    freeze(c['evidence'], MAX_EVIDENCE_BYTES)
    return c


def encode_capsule(capsule):
    """Canonical transport bytes; structural validation is not verification."""
    return encode(parse_capsule(capsule))


def _transaction(raw, payer):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_WIRE_BYTES,
         'exact signed P4 payment bytes required')
    packet = load_json(raw, max_bytes=MAX_WIRE_BYTES)
    exact(packet, {'body', 'signature'}, 'P4 capsule payment')
    body = packet['body']
    need(canonical(packet) == raw and type(body) is dict and
         type(body.get('version')) is int and body['version'] == 4 and
         body.get('sender') == payer, 'canonical payment version or payer differs')
    op = body.get('op')
    need(type(op) is dict and op.get('type') == 'transfer',
         'capsule requires a transfer payment, not a native management receipt')
    return packet


def _recomputed(evidence, genesis_bytes, policy, raw, payer, now_ns):
    # Both unchanged public APIs are deliberately used. Their full replays
    # establish trust and exact positive receipt identity independently of any
    # display/binding fields. No static-validator verifier receives P4.
    report = verify_evidence(evidence, genesis_bytes, policy, now_ns=now_ns)
    positive = verify_receipt(evidence, genesis_bytes, policy, raw,
                              payer=payer, now_ns=now_ns)
    need(positive['status'] == 'recorded' and positive['receipt'] is not None,
         'exact payment receipt unavailable; outcome unknown')
    receipt = positive['receipt']
    need(canonical(receipt['record']['envelope']) == raw,
         'recorded payment wire differs')
    binding = {k: receipt[k] for k in ('native_txid', 'receipt_sha256',
                                      'wire_sha256', 'height', 'index')}
    binding['signer_public_key'] = receipt['record']['signer_public_key']
    return report, positive, binding


def make_capsule(evidence, genesis_bytes, policy, exact_transaction, *, payer, now_ns):
    """Export one positive transfer, with caller-selected external trust inputs."""
    p = policy_checked(policy)
    e = freeze(evidence, MAX_EVIDENCE_BYTES)
    _transaction(exact_transaction, payer)
    _, _, binding = _recomputed(e, genesis_bytes, p, exact_transaction, payer, now_ns)
    return parse_capsule({'schema': 1, 'format': FORMAT,
        'genesis_sha256': p['genesis_sha256'], 'policy_id': content_id(p),
        'payer': payer, 'wire': base64.b64encode(exact_transaction).decode('ascii'),
        'binding': binding, 'evidence': e})


def verify_capsule(capsule, genesis_bytes, policy, *, now_ns,
                   expected_payer=None, expected_wire_sha256=None):
    """Recompute a positive report; packet metadata can never select trust/time.

    Without expected payer/wire, this proves only the payment carried by the
    capsule. Invoice or intended-payment callers must compare their own identity.
    """
    c = parse_capsule(capsule)
    p = policy_checked(policy)
    need(c['genesis_sha256'] == p['genesis_sha256'] and
         c['policy_id'] == content_id(p), 'capsule external trust references differ')
    if expected_payer is not None:
        need(c['payer'] == expected_payer, 'capsule payer differs from caller selection')
    raw = b64(c['wire'], max_size=MAX_WIRE_BYTES)
    wire_hash = sha256(raw)
    if expected_wire_sha256 is not None:
        need(wire_hash == hash_text(expected_wire_sha256),
             'capsule wire differs from caller selection')
    packet = _transaction(raw, c['payer'])
    report, positive, binding = _recomputed(c['evidence'], genesis_bytes, p,
                                            raw, c['payer'], now_ns)
    need(encode(binding) == encode(c['binding']), 'capsule binding differs from verified receipt')
    body = packet['body']; op = body['op']; record = positive['receipt']['record']
    return {'schema': 1, 'status': 'verified-p4-payment-receipt',
        'capsule_id': sha256(encode(c)), 'evidence_id': report['evidence_id'],
        'genesis_sha256': report['genesis_sha256'], 'policy_id': report['policy_id'],
        'asset': c['evidence']['state']['genesis']['asset'],
        'unit': 'native-atomic-units', 'amount_units': str(op['units']),
        'fee_units': str(record['fee_units']),
        'total_debit_units': str(op['units'] + record['fee_units']),
        'payer': c['payer'], 'recipient': op['to'], 'grant_id': body['grant_id'],
        'nonce': body['nonce'], 'transaction': packet, 'receipt': positive['receipt'],
        'binding': binding, 'state_height': report['state_height'],
        'app_hash': report['app_hash'], 'header_height': report['header_height'],
        'header_hash': report['header_hash'], 'registry_epoch': report['registry_epoch'],
        'receipt_height': binding['height'], 'checked_at_ns': now_ns,
        'trust_expires_ns': report['trust_expires_ns'],
        'native_execution_replayed': True, 'registry_authorization_replayed': True,
        'signed_block_inclusion_verified': True,
        'latest_network_state_established': False, 'latest_state_guaranteed': False,
        'spending_authority': False, 'pending_wallet_debits_included': False,
        'wallet_reservations_changed': False, 'historical_absence_proven': False,
        'external_settlement_verified': False, 'automatic_resend': False,
        'actual_abci_responses_observed': False,
        'independent_validator_hosts_verified': False}
