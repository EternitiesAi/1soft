"""Bounded x402-v2 HTTP envelopes for an experimental native P4 scheme.

Original implementation; interface references: x402 Foundation, Apache-2.0,
c8c71f244c0d45a6a4fd990a96c69aa34781cd05 (specs and core payment types).
No acquired SDK code is imported. Operator-provided expectations/assignments are
trust inputs, never values inferred from the HTTP offer. No signing, dispatch,
network requests, hold retirement, or merchant consumption occurs here.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import re
from urllib.parse import unquote_to_bytes, urlsplit

from commit_verifier import b64, encode, exact, load_json
from native_core import BODY_FIELDS, MAX_UNITS, canonical, identifier
from p4_evidence import hash_text, integer, need
from p4_receipt_capsule import encode_capsule, parse_capsule, verify_capsule
from payment_requests import MAX_LIFETIME_NS, RequestBook, new_request, request_id

SCHEME = '1soft-p4'
ASSET = '1soft:DEV'
OFFER_FORMAT = '1soft/x402-native-offer/v1'
PAYLOAD_FORMAT = '1soft/x402-native-payment/v1'
MAX_REQUIRED_HEADER = 8192
MAX_SIGNATURE_HEADER = 32768
MAX_RESPONSE_HEADER = 8192
MAX_HEADER_COUNT = 64
HEADER_LIMITS = {'PAYMENT-REQUIRED': MAX_REQUIRED_HEADER,
                 'PAYMENT-SIGNATURE': MAX_SIGNATURE_HEADER,
                 'PAYMENT-RESPONSE': MAX_RESPONSE_HEADER}
REQUIREMENT_FIELDS = {'scheme', 'network', 'asset', 'amount', 'payTo',
                      'maxTimeoutSeconds', 'extra'}
EXTRA_FIELDS = {'format', 'genesisSha256', 'merchantOrigin', 'nativeAsset',
                'createdNs', 'expiresNs', 'quoteNonce', 'assetTransferMethod', 'paymentFlow'}
PAYLOAD_FIELDS = {'format', 'quoteSha256', 'requestId', 'payer', 'wire',
                  'wireSha256', 'capsuleSha256'}
RESPONSE_BINDINGS = {'quoteSha256', 'wireSha256', 'capsuleSha256',
                     'genesisSha256', 'resourceUrl'}


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _text(value, maximum, *, empty=False):
    need(type(value) is str and (empty or len(value) > 0) and len(value) <= maximum and
         value.isascii() and all(32 <= ord(c) < 127 for c in value), 'invalid bounded text')
    return value


def _account(value):
    need(type(value) is str and re.fullmatch(r'lab_[0-9a-f]{64}', value) is not None,
         'exact native account required')
    return value


def _units(value):
    need(type(value) is str and len(value) <= 19 and
         re.fullmatch(r'[1-9][0-9]*', value) is not None, 'exact positive atomic amount required')
    integer(int(value), 1, MAX_UNITS)
    return value


def _url(value, *, origin=False):
    _text(value, 2048)
    need(all(ord(c) > 32 for c in value) and '\\' not in value and '#' not in value and
         re.search(r'%(?![0-9a-fA-F]{2})', value) is None, 'ambiguous resource URL')
    decoded = unquote_to_bytes(value)
    need(all(32 < c < 127 for c in decoded) and b'\\' not in decoded,
         'encoded controls or ambiguous URL bytes')
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError('invalid URL authority') from exc
    need(parsed.scheme in ('http', 'https') and parsed.hostname is not None and
         parsed.username is None and parsed.password is None and not parsed.fragment,
         'explicit HTTP resource URL required')
    host = parsed.hostname
    need(re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?', host) is not None and
         '..' not in host and (port is None or 1 <= port <= 65535), 'invalid URL host or port')
    need(parsed.scheme == 'https' or host == '127.0.0.1',
         'remote resources require HTTPS; development HTTP is literal loopback only')
    need(port != (443 if parsed.scheme == 'https' else 80), 'explicit default port is ambiguous')
    authority = host + (':' + str(port) if port is not None else '')
    expected_origin = parsed.scheme + '://' + authority
    need(parsed.netloc == authority and value.startswith(expected_origin),
         'URL authority must use exact lowercase canonical spelling')
    path = unquote_to_bytes(parsed.path)
    need(not parsed.path.startswith('//') and all(piece not in (b'.', b'..')
         for piece in path.split(b'/')), 'ambiguous URL path')
    if origin:
        need(value == expected_origin and not parsed.path and not parsed.query,
             'merchant origin must be an exact authority without path')
    else:
        need(parsed.path.startswith('/'), 'resource requires an absolute path')
    return expected_origin


@dataclass(frozen=True)
class NativePaymentExpectation:
    """Authenticated operator-selected pins; do not construct from the offer.

    The network namespace is grammar-valid CAIP-2 but explicitly unregistered.
    This profile supports only valueless native DEV, never a stablecoin route.
    """
    merchant_origin: str
    resource_url: str
    network: str
    asset: str
    genesis_sha256: str
    recipient: str
    amount_units: str

    def __post_init__(self):
        need(_url(self.merchant_origin, origin=True) == _url(self.resource_url),
             'resource is not at the pinned merchant origin')
        need(type(self.network) is str and
             re.fullmatch(r'1soft:[a-z0-9][a-z0-9-]{0,31}', self.network) is not None,
             'explicit operator-pinned experimental native network required')
        need(self.asset == ASSET, 'unsupported native asset')
        hash_text(self.genesis_sha256); _account(self.recipient); _units(self.amount_units)


@dataclass(frozen=True)
class TrustedMerchantAssignment:
    """Pins from an independently trusted immutable merchant invoice store.

    That store MUST assign a never-reused recipient to exactly one quote and
    retain the intended payer/original wire. This record cannot prove the store's
    uniqueness or durability. It MUST NOT be constructed from client payloads.
    """
    quote_sha256: str
    request_id: str
    recipient: str
    payer: str
    wire_sha256: str

    def __post_init__(self):
        hash_text(self.quote_sha256); hash_text(self.request_id); hash_text(self.wire_sha256)
        _account(self.recipient); _account(self.payer)


def _expectation(value):
    need(type(value) is NativePaymentExpectation, 'independent trusted expectation required')
    value.__post_init__()
    return value


def _depth(raw):
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped: escaped = False
            elif byte == 92: escaped = True
            elif byte == 34: quoted = False
        elif byte == 34: quoted = True
        elif byte in (91, 123):
            depth += 1
            need(depth <= 16, 'payment header JSON nesting exceeds bound')
        elif byte in (93, 125):
            depth -= 1
            need(depth >= 0, 'invalid payment header JSON nesting')


def _decode(value, maximum):
    need(type(value) is str and 0 < len(value) <= maximum and value.isascii(),
         'payment header exceeds bounded input')
    raw = b64(value, max_size=maximum * 3 // 4)
    _depth(raw)
    parsed = load_json(raw, max_bytes=maximum * 3 // 4)
    need(type(parsed) is dict and encode(parsed) == raw, 'canonical payment header JSON required')
    return parsed, raw


def _header(value, maximum):
    encoded = base64.b64encode(encode(value)).decode('ascii')
    _decode(encoded, maximum)
    return encoded


def payment_header(headers, name):
    """Read one header from raw pairs; reject case-insensitive duplicates.

    Do not pass a dictionary made after duplicate headers have been collapsed.
    This does not fetch or interpret any other HTTP field or response status.
    """
    need(type(name) is str and name in HEADER_LIMITS, 'unsupported payment header name')
    need(type(headers) in (list, tuple) and len(headers) <= MAX_HEADER_COUNT,
         'bounded raw header pairs required')
    found = []
    for row in headers:
        need(type(row) in (list, tuple) and len(row) == 2, 'invalid HTTP header pair')
        key, value = row
        need(type(key) is str and re.fullmatch(r'[!#$%&\x27*+.^_`|~0-9A-Za-z-]{1,128}', key)
             is not None, 'invalid HTTP header name')
        need(type(value) is str and len(value) <= MAX_SIGNATURE_HEADER and
             value.isascii() and all(32 <= ord(c) < 127 for c in value),
             'invalid bounded HTTP header value')
        if key.upper() == name: found.append(value)
    need(len(found) == 1, 'exactly one payment header required; duplicates refused')
    _decode(found[0], HEADER_LIMITS[name])
    return found[0]


def _resource(value, expectation):
    need(type(value) is dict and {'url'} <= set(value) <= {'url', 'description', 'mimeType'},
         'unsupported resource fields')
    need(value['url'] == expectation.resource_url, 'resource differs from authenticated expectation')
    _url(value['url'])
    if 'description' in value: _text(value['description'], 400, empty=True)
    if 'mimeType' in value:
        need(type(value['mimeType']) is str and len(value['mimeType']) <= 100 and
             re.fullmatch(r'[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+', value['mimeType']) is not None,
             'invalid resource MIME type')


def _offer(value, expectation, now_ns):
    need(type(value) is dict and {'x402Version', 'resource', 'accepts'} <= set(value) <=
         {'x402Version', 'resource', 'accepts', 'error', 'extensions'}, 'unsupported PaymentRequired fields')
    integer(value['x402Version'], 2, 2)
    if 'error' in value: _text(value['error'], 200, empty=True)
    if 'extensions' in value: need(type(value['extensions']) is dict and not value['extensions'],
                                   'unsupported payment extensions')
    _resource(value['resource'], expectation)
    need(type(value['accepts']) is list and len(value['accepts']) == 1,
         'exactly one supported payment method required')
    terms = value['accepts'][0]; exact(terms, REQUIREMENT_FIELDS, 'native PaymentRequirements')
    need(terms['scheme'] == SCHEME and terms['network'] == expectation.network and
         terms['asset'] == expectation.asset, 'unsupported scheme, network or asset')
    need(_units(terms['amount']) == expectation.amount_units and
         _account(terms['payTo']) == expectation.recipient, 'quoted recipient or amount differs')
    extra = terms['extra']; exact(extra, EXTRA_FIELDS, 'native quote extra')
    need(extra['format'] == OFFER_FORMAT and extra['nativeAsset'] == 'DEV' and
         extra['assetTransferMethod'] == 'p4-capsule' and extra['paymentFlow'] == 'upfront',
         'unsupported experimental native mechanism or payment flow')
    need(hash_text(extra['genesisSha256']) == expectation.genesis_sha256 and
         extra['merchantOrigin'] == expectation.merchant_origin, 'quoted trust or merchant pin differs')
    hash_text(extra['quoteNonce'])
    start = integer(extra['createdNs'], 1); end = integer(extra['expiresNs'], start + 1)
    need(end - start <= MAX_LIFETIME_NS, 'quote lifetime exceeds development bound')
    integer(now_ns, 1)
    need(start <= now_ns < end, 'quote is not currently open')
    integer(terms['maxTimeoutSeconds'], 1, 86400)
    need(terms['maxTimeoutSeconds'] == (end - start + 10**9 - 1) // 10**9,
         'quote timeout differs from exact lifetime')


def make_payment_required(expectation, *, created_ns, expires_ns, quote_nonce,
                          description='', mime_type='application/octet-stream'):
    """Create canonical v2 PaymentRequired; an offer never authorizes spending."""
    e = _expectation(expectation)
    start = integer(created_ns, 1); end = integer(expires_ns, start + 1)
    value = {'x402Version': 2, 'resource': {'url': e.resource_url,
             'description': description, 'mimeType': mime_type}, 'accepts': [{
        'scheme': SCHEME, 'network': e.network, 'asset': e.asset, 'amount': e.amount_units,
        'payTo': e.recipient, 'maxTimeoutSeconds': (end - start + 10**9 - 1) // 10**9,
        'extra': {'format': OFFER_FORMAT, 'genesisSha256': e.genesis_sha256,
                  'merchantOrigin': e.merchant_origin, 'nativeAsset': 'DEV',
                  'createdNs': start, 'expiresNs': end, 'quoteNonce': quote_nonce,
                  'assetTransferMethod': 'p4-capsule', 'paymentFlow': 'upfront'}}]}
    _offer(value, e, start)
    return _header(value, MAX_REQUIRED_HEADER)


def parse_payment_required(required_header, expectation, *, now_ns):
    """Check exact pins and map to the existing canonical unsigned request."""
    e = _expectation(expectation)
    offer, raw = _decode(required_header, MAX_REQUIRED_HEADER)
    _offer(offer, e, now_ns)
    extra = offer['accepts'][0]['extra']; quote_id = _sha(raw)
    request = new_request(e.genesis_sha256, e.recipient, e.amount_units,
        created_ns=extra['createdNs'], expires_ns=extra['expiresNs'], note='x402 quote ' + quote_id)
    return {'offer': offer, 'quote_sha256': quote_id, 'request': request,
            'request_id': request_id(request), 'spending_authority': False}


def retain_payment_request(book, required_header, expectation, *, now_ns):
    """Recheck then append unsigned intent; no signer or wallet is accessed."""
    q = parse_payment_required(required_header, expectation, now_ns=now_ns)
    need(type(book) is RequestBook and book.genesis == expectation.genesis_sha256,
         'canonical request book for exact genesis required')
    return book.add(q['request'])


def _wire(raw, expectation, payer):
    _account(payer)
    need(type(raw) is bytes and 0 < len(raw) <= 16384, 'bounded original native wire required')
    packet = load_json(raw, max_bytes=16384); exact(packet, {'body', 'signature'}, 'native payment')
    need(canonical(packet) == raw, 'original wire must be canonical')
    body = packet['body']; exact(body, BODY_FIELDS, 'native payment body')
    integer(body['version'], 4, 4)
    need(body['sender'] == payer, 'original payer differs')
    identifier(body['chain_id']); hash_text(body['genesis_hash'])
    integer(body['nonce'], 0, MAX_UNITS); integer(body['valid_until'], 0, MAX_UNITS)
    integer(body['max_fee'], 0, MAX_UNITS)
    need(type(body['grant_id']) is str, 'explicit grant lane required')
    if body['grant_id']: identifier(body['grant_id'])
    need(type(packet['signature']) is str and
         re.fullmatch(r'[0-9a-f]{128}', packet['signature']) is not None, 'native signature encoding required')
    op = body['op']; exact(op, {'type', 'to', 'units'}, 'native transfer')
    need(op['type'] == 'transfer' and op['to'] == expectation.recipient and
         str(integer(op['units'], 1, MAX_UNITS)) == expectation.amount_units,
         'original wire changes quoted transfer')
    return packet


def _capsule_bytes(value, expectation, exact_wire, payer):
    capsule = parse_capsule(value); raw = encode_capsule(capsule)
    need(capsule['genesis_sha256'] == expectation.genesis_sha256 and capsule['payer'] == payer and
         b64(capsule['wire'], max_size=16384) == exact_wire, 'capsule differs from exact payment selection')
    return capsule, raw


def make_payment_signature(*, required_header, expectation, exact_wire, capsule, payer, now_ns):
    """Wrap original payment material; structural binding is NOT paid proof.

    The full capsule goes in a separately bounded local fixture body. Its digest
    binds the original bytes here. The native signature does not sign this quote
    or resource: immutable unique-recipient assignment is separately required.
    """
    q = parse_payment_required(required_header, expectation, now_ns=now_ns)
    _wire(exact_wire, expectation, payer)
    _, capsule_raw = _capsule_bytes(capsule, expectation, exact_wire, payer)
    value = {'x402Version': 2, 'resource': q['offer']['resource'],
             'accepted': q['offer']['accepts'][0], 'payload': {
        'format': PAYLOAD_FORMAT, 'quoteSha256': q['quote_sha256'], 'requestId': q['request_id'],
        'payer': payer, 'wire': base64.b64encode(exact_wire).decode('ascii'),
        'wireSha256': _sha(exact_wire), 'capsuleSha256': _sha(capsule_raw)}}
    return _header(value, MAX_SIGNATURE_HEADER)


def verify_merchant_payment(*, signature_header, required_header, expectation, assignment,
                             exact_wire, capsule, genesis_bytes, policy, payer, now_ns):
    """Reverify exact positive execution; merchant consumption remains required.

    No remote field supplies assignment, genesis, policy, time or original wire.
    The caller must durably consume native_txid AND wire_sha256 in its merchant
    store before delivering a resource. This verifier is stateless and repeatable.
    """
    q = parse_payment_required(required_header, expectation, now_ns=now_ns)
    need(type(assignment) is TrustedMerchantAssignment, 'independent merchant assignment required')
    assignment.__post_init__()
    wire_hash = _sha(exact_wire) if type(exact_wire) is bytes else None
    need((assignment.quote_sha256, assignment.request_id, assignment.recipient,
          assignment.payer, assignment.wire_sha256) ==
         (q['quote_sha256'], q['request_id'], expectation.recipient, payer, wire_hash),
         'immutable merchant assignment differs from exact quote/payment')
    _wire(exact_wire, expectation, payer)
    checked_capsule, capsule_raw = _capsule_bytes(capsule, expectation, exact_wire, payer)
    value, _ = _decode(signature_header, MAX_SIGNATURE_HEADER)
    exact(value, {'x402Version', 'resource', 'accepted', 'payload'}, 'native PaymentPayload')
    integer(value['x402Version'], 2, 2)
    need(encode(value['resource']) == encode(q['offer']['resource']) and
         encode(value['accepted']) == encode(q['offer']['accepts'][0]), 'payment changes exact quoted terms')
    payload = value['payload']; exact(payload, PAYLOAD_FIELDS, 'native payment payload')
    need(payload == {'format': PAYLOAD_FORMAT, 'quoteSha256': q['quote_sha256'],
        'requestId': q['request_id'], 'payer': payer,
        'wire': base64.b64encode(exact_wire).decode('ascii'),
        'wireSha256': wire_hash, 'capsuleSha256': _sha(capsule_raw)},
        'payment payload changes original wire, capsule or quote binding')
    # This is the existing full replay, not admission, a new signature check,
    # a client-supplied success flag, or a substitute static-validator verifier.
    proof = verify_capsule(checked_capsule, genesis_bytes, policy, now_ns=now_ns,
                           expected_payer=payer, expected_wire_sha256=wire_hash)
    need(proof['genesis_sha256'] == expectation.genesis_sha256 and proof['asset'] == 'DEV' and
         proof['recipient'] == expectation.recipient and proof['amount_units'] == expectation.amount_units and
         proof['payer'] == payer, 'verified native receipt differs from authenticated quote')
    response = {'success': True, 'transaction': proof['binding']['native_txid'],
        'network': expectation.network, 'payer': payer, 'amount': expectation.amount_units,
        'extensions': {SCHEME: {'quoteSha256': q['quote_sha256'], 'wireSha256': wire_hash,
            'capsuleSha256': _sha(capsule_raw), 'genesisSha256': expectation.genesis_sha256,
            'resourceUrl': expectation.resource_url}}}
    return {'status': 'verified-native-execution-awaiting-merchant-consumption',
        'quote_sha256': q['quote_sha256'], 'request_id': q['request_id'],
        'wire_sha256': wire_hash, 'native_txid': proof['binding']['native_txid'],
        'receipt_report': proof, 'payment_response_header': _header(response, MAX_RESPONSE_HEADER),
        'merchant_consumption_required': True, 'merchant_replay_checked': False,
        'resource_delivery_authorized': False, 'wallet_reservations_changed': False,
        'external_settlement_verified': False, 'native_signature_authenticates_resource': False,
        'full_public_ledger_disclosed': True}


def parse_payment_response(response_header, expectation, *, payer, quote_sha256,
                           wire_sha256, capsule_sha256):
    """Parse a bound server declaration; even success=True proves no execution."""
    e = _expectation(expectation); _account(payer)
    for digest in (quote_sha256, wire_sha256, capsule_sha256): hash_text(digest)
    value, _ = _decode(response_header, MAX_RESPONSE_HEADER)
    exact(value, {'success', 'transaction', 'network', 'payer', 'amount', 'extensions'},
          'native payment response')
    need(type(value['success']) is bool and value['success'] is True, 'only positive native declarations supported')
    hash_text(value['transaction'])
    need(value['network'] == e.network and value['payer'] == payer and _units(value['amount']) == e.amount_units,
         'response changes authenticated native payment')
    exact(value['extensions'], {SCHEME}, 'native response extensions')
    binding = value['extensions'][SCHEME]; exact(binding, RESPONSE_BINDINGS, 'native response binding')
    need(binding == {'quoteSha256': quote_sha256, 'wireSha256': wire_sha256,
        'capsuleSha256': capsule_sha256, 'genesisSha256': e.genesis_sha256,
        'resourceUrl': e.resource_url}, 'response changes selected quote or evidence')
    return {'response': value, 'execution_proven': False, 'wallet_reservations_changed': False,
            'resource_delivery_authorized': False, 'merchant_replay_checked': False}
