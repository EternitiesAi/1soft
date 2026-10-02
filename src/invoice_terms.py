"""Public invoice preimage; no key access, ledger writes or delivery claims."""
import hashlib
import json
import re
from urllib.parse import unquote_to_bytes,urlsplit
from native_core import MAX_UNITS,canonical,fields,identifier,require

DOMAIN=b'1soft/invoice-terms/v1'+bytes([0])
FORMAT='1soft/invoice-terms/v1'
FIELDS={'schema','format','quote_sha256','genesis_sha256','merchant_origin',
        'resource_url','resource_sha256','network','asset','recipient',
        'amount_units','created_ns','expires_ns'}

def _hash(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None,
            'invalid invoice digest')

def _url(value,origin=False):
    require(type(value) is str and 0<len(value)<=2048 and value.isascii() and
            all(32<ord(c)<127 for c in value) and chr(92) not in value and '#' not in value and
            re.search(r'%(?![0-9a-fA-F]{2})',value) is None,'invalid invoice URL')
    decoded=unquote_to_bytes(value)
    require(all(32<c<127 for c in decoded) and bytes([92]) not in decoded,'ambiguous invoice URL')
    try:p=urlsplit(value);port=p.port
    except ValueError as exc:raise ValueError('invalid invoice URL authority') from exc
    host=p.hostname
    require(p.scheme in ('http','https') and type(host) is str and
            re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',host) is not None and
            '..' not in host and p.username is None and p.password is None and
            (p.scheme=='https' or host=='127.0.0.1') and
            (port is None or 1<=port<=65535) and port!=(443 if p.scheme=='https' else 80),
            'invalid invoice URL authority')
    authority=host+(':'+str(port) if port is not None else '')
    base=p.scheme+'://'+authority
    require(p.netloc==authority and value.startswith(base),'noncanonical invoice URL authority')
    path=unquote_to_bytes(p.path)
    require(not p.path.startswith('//') and all(part not in (b'.',b'..') for part in path.split(b'/')),
            'ambiguous invoice URL path')
    require((value==base and not p.path and not p.query) if origin else p.path.startswith('/'),
            'invalid invoice origin or resource path')
    return base

def terms_checked(value,genesis_sha256=None,recipient=None,units=None,now_ns=None):
    fields(value,FIELDS)
    require(type(value['schema']) is int and value['schema']==1 and value['format']==FORMAT,
            'unsupported invoice terms format')
    for name in ('quote_sha256','genesis_sha256','resource_sha256'):_hash(value[name])
    require(_url(value['merchant_origin'],True)==_url(value['resource_url']),
            'invoice resource changes merchant origin')
    require(type(value['network']) is str and
            re.fullmatch(r'1soft:[a-z0-9][a-z0-9-]{0,31}',value['network']) is not None and
            value['asset']=='1soft:DEV','unsupported invoice network or asset')
    recipient_value=value['recipient']
    require(type(recipient_value) is str and re.fullmatch('lab_[0-9a-f]{64}',recipient_value) is not None,
            'exact native invoice recipient required')
    amount=value['amount_units']
    require(type(amount) is str and re.fullmatch('[1-9][0-9]{0,18}',amount) is not None and
            int(amount)<=MAX_UNITS,'invalid invoice amount')
    start,end=value['created_ns'],value['expires_ns']
    require(type(start) is int and type(end) is int and
            1<=start<end<2**63 and end-start<=86400*10**9,'invalid invoice lifetime')
    if genesis_sha256 is not None:require(value['genesis_sha256']==genesis_sha256,'invoice genesis differs')
    if recipient is not None:require(recipient_value==recipient,'invoice recipient differs')
    if units is not None:require(type(units) is int and int(amount)==units,'invoice amount differs')
    if now_ns is not None:
        require(type(now_ns) is int and start<=now_ns<end,'invoice is not currently open')
    return json.loads(canonical(value))

def terms_commitment(value):
    return hashlib.sha256(DOMAIN+canonical(terms_checked(value))).hexdigest()
