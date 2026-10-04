"""Minimal transparent-alpha delivery receipt.

This is a deliberately reduced projection for a resource download.  It is not
a shielded proof, a payment receipt, or an anonymity mechanism.  The full
public merchant proof remains the separate, explicit export format.
"""
import json
import re
from urllib.parse import urlsplit

FORMAT = '1soft/minimal-delivery-receipt/v1'
_FIELDS = {'schema', 'format', 'resource_sha256', 'merchant_origin',
           'resource_path', 'quote_commitment', 'execution_status',
           'verifier_anchor'}
_HEX = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)
_PATH_SEGMENT = re.compile(r'[A-Za-z0-9._~-]+\Z', re.ASCII)
_STATUSES = {'fulfilled'}


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')


def _hex(value, label):
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise ValueError('invalid minimal delivery receipt ' + label)
    return value


def _origin(value):
    if type(value) is not str or len(value) > 256 or not value.isascii():
        raise ValueError('invalid minimal delivery receipt origin')
    parsed = urlsplit(value)
    if (parsed.scheme, parsed.hostname, parsed.path, parsed.query, parsed.fragment) != ('http', '127.0.0.1', '', '', ''):
        raise ValueError('minimal delivery receipt requires literal loopback origin')
    try:
        port = parsed.port
    except ValueError:
        port = None
    if (not (1 <= (port or 0) <= 65535) or parsed.username is not None or
            parsed.password is not None or value != f'http://127.0.0.1:{port}'):
        raise ValueError('invalid minimal delivery receipt origin port')
    return value


def _path(value):
    parts = value.split('/')[1:] if type(value) is str else []
    if (type(value) is not str or not value or len(value) > 2048 or
            not value.isascii() or not value.startswith('/') or
            any(part in ('.', '..') or _PATH_SEGMENT.fullmatch(part) is None
                for part in parts)):
        raise ValueError('invalid minimal delivery receipt resource path')
    return value


def create(*, resource_sha256, merchant_origin, resource_path,
           quote_commitment, execution_status, verifier_anchor):
    """Create canonical minimal metadata for one fulfilled public resource."""
    value = {
        'schema': 1,
        'format': FORMAT,
        'resource_sha256': _hex(resource_sha256, 'resource digest'),
        'merchant_origin': _origin(merchant_origin),
        'resource_path': _path(resource_path),
        'quote_commitment': _hex(quote_commitment, 'quote commitment'),
        'execution_status': execution_status,
        'verifier_anchor': _hex(verifier_anchor, 'verifier anchor'),
    }
    if execution_status not in _STATUSES:
        raise ValueError('unsupported minimal delivery receipt execution status')
    return _canonical(value)


def parse(raw):
    """Validate exact canonical receipt shape and return its metadata."""
    if type(raw) is not bytes or not 0 < len(raw) <= 4096:
        raise ValueError('invalid minimal delivery receipt')
    try:
        value = json.loads(raw.decode('utf-8'))
    except (UnicodeError, ValueError, RecursionError):
        raise ValueError('invalid minimal delivery receipt') from None
    if (type(value) is not dict or set(value) != _FIELDS or
            _canonical(value) != raw or type(value.get('schema')) is not int or
            value['schema'] != 1 or
            value.get('format') != FORMAT):
        raise ValueError('invalid minimal delivery receipt')
    create(resource_sha256=value['resource_sha256'], merchant_origin=value['merchant_origin'],
           resource_path=value['resource_path'], quote_commitment=value['quote_commitment'],
           execution_status=value['execution_status'], verifier_anchor=value['verifier_anchor'])
    return value
