"""Portable public committed-invoice evidence, with external caller trust.

Preserves original bytes using canonical base64; no archive extraction, key,
database, network, wallet mutation or service callback. A response declaration
and an exporter do not authenticate a merchant or prove external delivery.
"""
import base64

from commit_verifier import b64, encode, exact, load_json
from native_core import canonical
from p4_evidence import integer, need
from p4_receipt_capsule import MAX_CAPSULE_BYTES, MAX_WIRE_BYTES
from payment_x402 import (MAX_REQUIRED_HEADER, MAX_SIGNATURE_HEADER, MAX_RESPONSE_HEADER,
    TrustedMerchantAssignment, _depth, _sha, parse_payment_required, verify_merchant_payment)

FORMAT = '1soft/merchant-proof/v1'
MAX_TERMS_BYTES = 8192
MAX_RESOURCE_BYTES = 64 * 1024
MAX_PROOF_BYTES = 4 * ((MAX_CAPSULE_BYTES + MAX_WIRE_BYTES + MAX_RESOURCE_BYTES + MAX_TERMS_BYTES + 8)//3) + 64 * 1024
FIELDS = {'schema', 'format', 'required_header', 'invoice_terms_b64', 'wire_b64',
          'capsule_b64', 'signature_header', 'response_header', 'resource_b64'}


def parse_merchant_proof(raw):
    """Only bounded transport validation; this does not establish payment."""
    need(type(raw) is bytes and 0 < len(raw) <= MAX_PROOF_BYTES, 'merchant proof byte bound exceeded')
    _depth(raw)
    value = load_json(raw, max_bytes=MAX_PROOF_BYTES)
    exact(value, FIELDS, 'merchant proof')
    integer(value['schema'], 1, 1)
    need(value['format'] == FORMAT and encode(value) == raw, 'canonical merchant proof format required')
    for field, limit in (('required_header',MAX_REQUIRED_HEADER), ('signature_header',MAX_SIGNATURE_HEADER),
                         ('response_header',MAX_RESPONSE_HEADER)):
        text = value[field]
        need(type(text) is str and 0 < len(text) <= limit and text.isascii(), 'bounded original header required')
    parts = {}
    for name, limit in (('invoice_terms',MAX_TERMS_BYTES), ('wire',MAX_WIRE_BYTES),
                        ('capsule',MAX_CAPSULE_BYTES), ('resource',MAX_RESOURCE_BYTES)):
        parts[name] = b64(value[name+'_b64'], max_size=limit)
        need(len(parts[name]) > 0, 'nonempty original merchant proof bytes required')
    return value, parts


def verify_merchant_proof(raw, *, genesis_bytes, policy, expectation, assignment, now_ns):
    """Replay against separately authenticated trust, intent and AS-OF time.

    Do not derive expectation/assignment/genesis/policy/time from the bundle.
    An externally chosen historical time proves AS-OF evidence only, never
    current authority. No bundle field selects a verification time or trust pin.
    This cannot prove store durability, uniqueness, merchant identity, receipt
    of the resource by a buyer or arbitrary external service completion.
    """
    need(type(assignment) is TrustedMerchantAssignment, 'independent merchant assignment required')
    value, parts = parse_merchant_proof(raw)
    quote = parse_payment_required(value['required_header'], expectation, now_ns=now_ns)
    terms = quote.get('invoice_terms')
    need(terms is not None, 'committed v2 invoice required for merchant proof')
    need(parts['invoice_terms'] == canonical(terms), 'original invoice preimage differs from quote')
    need(_sha(parts['resource']) == terms['resource_sha256'], 'resource bytes differ from invoice commitment')
    # Assignment is mandatory and type-checked by the existing verifier. Never
    # manufacture one using untrusted fields from this transport.
    proof = verify_merchant_payment(signature_header=value['signature_header'],
        required_header=value['required_header'], expectation=expectation, assignment=assignment,
        exact_wire=parts['wire'], capsule=parts['capsule'], genesis_bytes=genesis_bytes,
        policy=policy, payer=assignment.payer, now_ns=now_ns)
    need(value['response_header'] == proof['payment_response_header'],
         'response declaration differs from independently replayed payment')
    receipt = proof['receipt_report']
    return {'schema':1, 'status':'verified-committed-merchant-payment',
        'proof_sha256':_sha(raw), 'quote_sha256':quote['quote_sha256'], 'request_id':quote['request_id'],
        'invoice_terms_sha256':_sha(parts['invoice_terms']), 'resource_sha256':terms['resource_sha256'],
        'wire_sha256':proof['wire_sha256'], 'capsule_sha256':_sha(parts['capsule']),
        'native_txid':proof['native_txid'], 'genesis_sha256':receipt['genesis_sha256'],
        'policy_id':receipt['policy_id'], 'payer':receipt['payer'], 'recipient':receipt['recipient'],
        'amount_units':receipt['amount_units'], 'fee_units':receipt['fee_units'],
        'total_debit_units':receipt['total_debit_units'], 'receipt_height':receipt['receipt_height'],
        'checked_at_ns':now_ns, 'verification_scope':'historical-as-of-caller-selected-time',
        'delivery_time_verified':False, 'native_execution_replayed':True,
        'registry_authorization_replayed':True, 'signed_block_inclusion_verified':True,
        'native_signature_authenticates_resource':True, 'resource_bytes_match_commitment':True,
        'response_declaration_consistent':True, 'merchant_identity_authenticated':False,
        'merchant_consumption_proven':False, 'external_service_delivery_verified':False,
        'external_settlement_verified':False, 'latest_network_state_established':False,
        'spending_authority':False, 'wallet_reservations_changed':False, 'onchain_privacy':False,
        'full_public_ledger_disclosed':True, 'independent_validator_hosts_verified':False}


def make_merchant_proof(*, required_header, exact_wire, capsule, signature_header,
                        response_header, resource, genesis_bytes, policy, expectation,
                        assignment, now_ns):
    """Freeze and fully verify a bundle before export; original bytes only."""
    quote = parse_payment_required(required_header, expectation, now_ns=now_ns)
    need(quote.get('invoice_terms') is not None, 'committed v2 invoice required')
    for raw, limit in ((exact_wire,MAX_WIRE_BYTES),(capsule,MAX_CAPSULE_BYTES),(resource,MAX_RESOURCE_BYTES)):
        need(type(raw) is bytes and 0 < len(raw) <= limit, 'bounded original proof bytes required')
    value = {'schema':1,'format':FORMAT,'required_header':required_header,
             'signature_header':signature_header,'response_header':response_header}
    for name, raw in (('wire',exact_wire),('capsule',capsule),('resource',resource),
                      ('invoice_terms',canonical(quote['invoice_terms']))):
        value[name+'_b64'] = base64.b64encode(raw).decode('ascii')
    raw = encode(value)
    verify_merchant_proof(raw, genesis_bytes=genesis_bytes, policy=policy,
                          expectation=expectation, assignment=assignment, now_ns=now_ns)
    return raw
