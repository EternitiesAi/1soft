"""Version-1 application-data confidentiality; no ledger privacy or spending rights.

The trusted caller supplies a separate 256-bit invoice-data key and the exact
canonical unsigned payment-request SHA256. Persist returned bytes unchanged.
This module has no storage, custody, signing, network or browser key route.

The caller owns key distribution, rotation, recovery and access. Lost keys lose
invoice content; compromised keys expose their encrypted content. Decryption
necessarily creates plaintext in Python memory; secure erasure is not promised.
AES-GCM nonce reuse under a key is unsafe. Production uses fresh OS-backed secure
randomness only, without a configurable nonce or a cross-process nonce registry.
"""

import base64
import binascii
import json
import re
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT = "1soft/private-invoice/v1"
ALGORITHM = "AES-256-GCM"
MAX_PLAINTEXT_BYTES = 10000
MAX_ENVELOPE_BYTES = 14000
_FIELD_BYTES = {"description": 1024, "contact": 512, "content": 8192}
_CONTEXT_FIELDS = {"schema", "format", "algorithm", "genesis_sha256", "request_sha256"}
_ENVELOPE_FIELDS = _CONTEXT_FIELDS | {"nonce_b64", "ciphertext_b64"}
_SHA256 = re.compile(r"[0-9a-f]{64}", flags=re.ASCII)


class InvoicePrivacyError(ValueError):
    """Generic refusal without exposing caller secrets or invoice plaintext."""


def _require(condition):
    if not condition:
        raise InvoicePrivacyError("invalid encrypted invoice")


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def _pairs(pairs):
    result = {}
    for name, value in pairs:
        _require(name not in result)
        result[name] = value
    return result


def _reject_constant(_):
    raise InvoicePrivacyError("invalid encrypted invoice")


def _parse(raw, limit):
    _require(type(raw) is bytes and 0 < len(raw) <= limit)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=_reject_constant)
        _require(_canonical(value) == raw)
        return value
    except (UnicodeError, ValueError, RecursionError, OverflowError):
        raise InvoicePrivacyError("invalid encrypted invoice") from None


def _key(key):
    _require(type(key) is bytes and len(key) == 32)
    return key


def _context(genesis_sha256, request_sha256):
    for value in (genesis_sha256, request_sha256):
        _require(type(value) is str and _SHA256.fullmatch(value) is not None)
    return {"schema": 1, "format": FORMAT, "algorithm": ALGORITHM,
            "genesis_sha256": genesis_sha256, "request_sha256": request_sha256}


def _plaintext(content):
    _require(type(content) is dict and set(content) == set(_FIELD_BYTES))
    try:
        for name, limit in _FIELD_BYTES.items():
            value = content[name]
            _require(type(value) is str and len(value) <= limit)
            _require(len(value.encode("utf-8")) <= limit)
            _require(all((ord(char) >= 32 and not 127 <= ord(char) <= 159) or
                         (name == "content" and char in "\n\t") for char in value))
        raw = _canonical(content)
        _require(len(raw) <= MAX_PLAINTEXT_BYTES)
        return raw
    except UnicodeError:
        raise InvoicePrivacyError("invalid encrypted invoice") from None


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _unb64(value, low, high):
    _require(type(value) is str and 0 < len(value) <= 4 * ((high + 2) // 3))
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeError, ValueError, binascii.Error):
        raise InvoicePrivacyError("invalid encrypted invoice") from None
    _require(low <= len(raw) <= high and _b64(raw) == value)
    return raw


def encrypt_invoice(content, *, key, genesis_sha256, request_sha256):
    """Encrypt three bounded string fields and return canonical envelope bytes.

    The caller must derive request_sha256 from the exact canonical unsigned
    request (payment_requests.request_id), verify its genesis independently, and
    leave recipient and atomic units explicit for payment consent. This function
    authenticates the supplied context; it does not validate a payment request,
    prove merchant identity, authenticate who created the invoice, or authorize
    spending. The encryption key must be separate from every payment key.
    """
    trusted_key = _key(key)
    context = _context(genesis_sha256, request_sha256)
    plaintext = _plaintext(content)
    nonce = secrets.token_bytes(12)
    _require(type(nonce) is bytes and len(nonce) == 12)
    ciphertext = AESGCM(trusted_key).encrypt(nonce, plaintext, _canonical(context))
    envelope = _canonical({**context, "nonce_b64": _b64(nonce),
                           "ciphertext_b64": _b64(ciphertext)})
    _require(len(envelope) <= MAX_ENVELOPE_BYTES)
    return envelope


def _checked_envelope(envelope, expected):
    value = _parse(envelope, MAX_ENVELOPE_BYTES)
    _require(type(value) is dict and set(value) == _ENVELOPE_FIELDS)
    _require(type(value["schema"]) is int)
    _require(all(value[name] == expected[name] for name in _CONTEXT_FIELDS))
    nonce = _unb64(value["nonce_b64"], 12, 12)
    ciphertext = _unb64(value["ciphertext_b64"], 16, MAX_PLAINTEXT_BYTES + 16)
    return nonce, ciphertext


def validate_envelope(envelope: bytes, *, genesis_sha256: str, request_sha256: str) -> bytes:
    """Check exact bounded envelope structure/context without a key.

    Return the original canonical bytes unchanged. This does not authenticate
    ciphertext, verify an AES-GCM tag, validate the hidden plaintext or prove
    payment. Anyone can construct a well-shaped envelope. Use decrypt_invoice
    with a trusted key to authenticate data before returning any plaintext.
    """
    expected = _context(genesis_sha256, request_sha256)
    _checked_envelope(envelope, expected)
    return envelope


def decrypt_invoice(envelope, *, key, genesis_sha256, request_sha256):
    """Authenticate exact bounded bytes against trusted context, then return data.

    Anyone holding the invoice key can create valid ciphertext. Neither this
    data nor a successful decryption is evidence of payment or non-repudiation.
    No content is returned until the complete AES-GCM tag and shape validate.
    """
    trusted_key = _key(key)
    expected = _context(genesis_sha256, request_sha256)
    nonce, ciphertext = _checked_envelope(envelope, expected)
    try:
        plaintext = AESGCM(trusted_key).decrypt(nonce, ciphertext, _canonical(expected))
    except InvalidTag:
        raise InvoicePrivacyError("invalid encrypted invoice") from None
    content = _parse(plaintext, MAX_PLAINTEXT_BYTES)
    _plaintext(content)
    return content
