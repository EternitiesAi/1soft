"""Small, deliberately nonstandard credential protocol for isolated development.

No DID/VC conformance, real residency admission, KYC, human identity, subjective
continuity, unique embodiment, bank custody or payment authority is asserted.
Ed25519 and SHA-256/HMAC are standard primitives supplied by their libraries.
Verification requires locally pinned issuer policy; nothing is fetched from a card.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import unicodedata
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MAX_WIRE = 262144
MAX_STATUS_RECORDS = 512
CARD_DOMAIN = b'1soft/resident-pass/card/v1\x00'
STATUS_DOMAIN = b'1soft/resident-pass/status/v1\x00'
PRESENT_DOMAIN = b'1soft/resident-pass/presentation/v1\x00'
LINK_DOMAIN = b'1soft/resident-pass/native-association/v1\x00'
KINDS = ('resident', 'external-agent', 'human-member')
PURPOSES = ('introduce', 'link-native-account')
TOKEN = re.compile(r'[a-z0-9][a-z0-9._:-]{0,127}\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')
CARD_FIELDS = {'schema','issuer','credential_id','subject_id','kind','audience',
               'display_name','holder_key','epoch','issued_at','expires_at'}
STATUS_FIELDS = {'schema','issuer','sequence','issued_at','expires_at','entries'}
ENTRY_FIELDS = {'credential_id','subject_id','holder_key','epoch','status'}
CHALLENGE_FIELDS = {'schema','nonce','audience','purpose','card_digest','context_digest',
                    'issued_at','expires_at'}

class Refused(ValueError):
    """Invalid input or evidence; no authority is inferred."""

def require(condition, message):
    if not condition: raise Refused(message)

def fields(value, names):
    require(type(value) is dict and set(value) == names, 'unexpected or missing fields')

def number(value, *, low=0, high=2**53-1):
    require(type(value) is int and low <= value <= high, 'invalid integer')
    return value

def token(value):
    require(type(value) is str and TOKEN.fullmatch(value) is not None, 'invalid identifier')
    return value

def hex64(value):
    require(type(value) is str and HEX.fullmatch(value) is not None, 'invalid digest or public key')
    return value

def canonical(value):
    try:
        data = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                          separators=(',',':')).encode('ascii')
    except (TypeError, ValueError, RecursionError) as exc: raise Refused('invalid JSON value') from exc
    require(len(data) <= MAX_WIRE, 'message too large')
    return data

def decode(raw):
    require(type(raw) is bytes and len(raw) <= MAX_WIRE, 'invalid input size')
    def pairs(items):
        out={}
        for key,value in items:
            require(key not in out, 'duplicate JSON field'); out[key]=value
        return out
    def bad(_): raise Refused('non-integer JSON number')
    try: return json.loads(raw, object_pairs_hook=pairs, parse_float=bad, parse_constant=bad)
    except (ValueError, UnicodeError, RecursionError) as exc: raise Refused('invalid JSON input') from exc

def digest(value): return hashlib.sha256(canonical(value)).hexdigest()
def public(key): return key.public_key().public_bytes_raw().hex()

def verify_signature(key, signature, domain, body):
    hex64(key)
    require(type(signature) is str and re.fullmatch('[0-9a-f]{128}', signature) is not None,
            'invalid signature encoding')
    try: Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(bytes.fromhex(signature), domain+canonical(body))
    except (ValueError, InvalidSignature) as exc: raise Refused('invalid signature') from exc

def sign_document(key, domain, body):
    """Test/development signing primitive; not a protected signer or consent UI."""
    body=decode(canonical(body))
    return {'body':body,'signature':key.sign(domain+canonical(body)).hex()}

def pairwise_subject(secret, issuer, audience):
    """Opaque per-issuer/per-audience alias; no memories or wallet address input.

    Issuer and secret-holder can correlate their own mappings. Identical display
    names, keys, or wallet addresses can still correlate presentations. Not ZK.
    """
    require(type(secret) is bytes and len(secret)==32, '32-byte alias seed required')
    token(issuer); token(audience)
    return 'sub_'+hmac.new(secret,b'1soft/resident-pass/alias/v1\x00'+canonical([issuer,audience]),hashlib.sha256).hexdigest()

def card_body(body):
    fields(body,CARD_FIELDS); number(body['schema'],low=1,high=1)
    for k in ('issuer','credential_id','subject_id','audience'): token(body[k])
    require(body['kind'] in KINDS and type(body['kind']) is str,'unsupported subject kind')
    name=body['display_name']
    require(type(name) is str and name==name.strip() and 1<=len(name)<=64 and
            unicodedata.normalize('NFC',name)==name and
            not any(unicodedata.category(c).startswith('C') for c in name), 'invalid display name')
    hex64(body['holder_key']); number(body['epoch'])
    number(body['issued_at']); number(body['expires_at'])
    require(0<body['expires_at']-body['issued_at']<=31*86400, 'invalid card validity period')
    return body

def issue_card(key, body):
    card_body(body);return sign_document(key,CARD_DOMAIN,body)

def status_body(body):
    fields(body,STATUS_FIELDS); number(body['schema'],low=1,high=1);token(body['issuer'])
    number(body['sequence'],low=1);number(body['issued_at']);number(body['expires_at'])
    require(0<body['expires_at']-body['issued_at']<=300,'invalid status validity period')
    entries=body['entries'];require(type(entries) is list and len(entries)<=MAX_STATUS_RECORDS,'invalid status entries')
    seen=set();active=set()
    for entry in entries:
        fields(entry,ENTRY_FIELDS)
        for k in ('credential_id','subject_id'):token(entry[k])
        hex64(entry['holder_key']);number(entry['epoch'])
        require(entry['status'] in ('active','revoked') and type(entry['status']) is str,'invalid credential status')
        require(entry['credential_id'] not in seen,'duplicate status entry');seen.add(entry['credential_id'])
        if entry['status']=='active':
            require(entry['subject_id'] not in active,'two active cards for the same subject alias')
            active.add(entry['subject_id'])
    return body

def issue_status(key, body):
    status_body(body);return sign_document(key,STATUS_DOMAIN,body)

def challenge_body(body):
    fields(body,CHALLENGE_FIELDS);number(body['schema'],low=1,high=1)
    for k in ('nonce','card_digest','context_digest'):hex64(body[k])
    token(body['audience']);require(body['purpose'] in PURPOSES,'unsupported challenge purpose')
    number(body['issued_at']);number(body['expires_at'])
    require(0<body['expires_at']-body['issued_at']<=120,'invalid challenge validity')
    return body

def present(key, challenge):
    challenge_body(challenge)
    return sign_document(key,PRESENT_DOMAIN,challenge)

@dataclass(frozen=True)
class IssuerRule:
    issuer: str
    public_key: str
    kinds: tuple[str,...]
    def __post_init__(self):
        token(self.issuer);hex64(self.public_key)
        require(type(self.kinds) is tuple and 1<=len(self.kinds)<=len(KINDS) and
                len(set(self.kinds))==len(self.kinds) and all(k in KINDS for k in self.kinds), 'invalid issuer scope')
