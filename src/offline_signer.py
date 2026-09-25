"""Local-only native-coin signing laboratory. No network or broadcast function.

Encrypted PKCS8 keys use cryptography's implementation. The review digest binds
exact bytes/roles, not a person's identity. Anyone with the password can sign.
No hardware custody, hostile-OS protection, memory zeroization or recovery claim.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from pathlib import Path
import stat

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import (NativeLedger, Reject, BODY_FIELDS, FEE_ACCOUNT, canonical,
    digest, fields, integer, identifier, pubkey, public, require, sign,
    accept_account_key, verify_account_key_acceptance)

REVIEW_DOMAIN = b'1soft/offline-review/v1\x00'
KEY_LIMIT = 8192


def _password(value: bytes) -> bytes:
    require(type(value) is bytes and 16 <= len(value) <= 1024,
            'use a long unique passphrase (16-1024 UTF-8 bytes)')
    return value


def _parent(path: Path) -> tuple[int, str]:
    """Pin each directory using no-follow descriptor-relative opens (POSIX)."""
    require(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'), 'vault requires Linux/WSL or POSIX')
    path = Path(os.path.abspath(path))
    require(path.name not in ('', '.', '..'), 'invalid vault path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for component in path.parent.parts[1:]:
            nxt = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = nxt
        info = os.fstat(fd)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) & 0o077 == 0,
                'vault parent must be owned by you and private (0700)')
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


def create_vault(path: Path, password: bytes) -> str:
    """Create a new encrypted Ed25519 key; never overwrite or export its seed."""
    _password(password)
    parent, name = _parent(path)
    try:
        key = Ed25519PrivateKey.generate()
        encrypted = key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8,
                                      ser.BestAvailableEncryption(password))
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, 'wb') as out:
            out.write(encrypted)
            out.flush()
            os.fsync(out.fileno())
        os.fsync(parent)
        return public(key)
    finally:
        os.close(parent)


def _load_vault(path: Path, password: bytes) -> Ed25519PrivateKey:
    _password(password)
    parent, name = _parent(path)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                    and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) & 0o077 == 0,
                    'vault must be a private, owned regular file with no hard links')
            require(0 < info.st_size <= KEY_LIMIT, 'invalid vault size')
            data = source.read(KEY_LIMIT + 1)
            require(len(data) <= KEY_LIMIT, 'vault grew past size limit')
    finally:
        os.close(parent)
    require(data.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----\n') and
            data.rstrip().endswith(b'-----END ENCRYPTED PRIVATE KEY-----') and
            data.count(b'-----BEGIN ') == 1, 'only encrypted PKCS8 keys are accepted')
    try:
        key = ser.load_pem_private_key(data, password)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise Reject('unable to unlock vault') from exc
    require(isinstance(key, Ed25519PrivateKey), 'vault key must be Ed25519')
    return key


def review_intent(genesis: dict, body: dict, signer_public_key: str, *, mode: str = 'sign') -> dict:
    """Static review only: no claim of current balance, nonce or authority proof."""
    pubkey(signer_public_key)
    require(mode in ('sign', 'accept'), 'unsupported signing role')
    body = json.loads(canonical(body))
    ledger = NativeLedger(':memory:', genesis)
    try:
        genesis = ledger.genesis
        version = ledger.protocol_version
    finally:
        ledger.close()
    fields(body, BODY_FIELDS)
    require(type(body['version']) is int and body['version'] == version, 'wrong protocol')
    require(body['chain_id'] == genesis['chain_id'] and body['genesis_hash'] == digest(genesis),
            'wrong trusted chain or genesis')
    identifier(body['sender'])
    require(body['sender'] != FEE_ACCOUNT, 'system account cannot sign')
    integer(body['nonce']); integer(body['valid_until']); integer(body['max_fee'])
    require(genesis['fee'] <= body['max_fee'], 'fee exceeds consent')
    require(type(body['grant_id']) is str, 'invalid grant label')
    if body['grant_id']:
        identifier(body['grant_id'])
    op = body['op']
    require(type(op) is dict and type(op.get('type')) is str, 'invalid operation')
    kind = op['type']
    require(not body['grant_id'] or kind == 'transfer', 'agent cannot administer accounts')
    debit = genesis['fee']
    if kind == 'transfer':
        fields(op, {'type', 'to', 'units'})
        identifier(op['to']); integer(op['units'], minimum=1)
        require(op['to'] not in (body['sender'], FEE_ACCOUNT), 'invalid recipient')
        debit += op['units']
    elif kind == 'grant':
        fields(op, {'type', 'id', 'public_key', 'cap', 'expires', 'recipients'} |
               ({'budget_id'} if version == 3 else set()))
        if version == 3: identifier(op['budget_id'])
        identifier(op['id']); pubkey(op['public_key']); integer(op['cap'], minimum=1); integer(op['expires'])
        items = op['recipients']
        require(type(items) is list and 1 <= len(items) <= 64, 'explicit recipients required')
        for recipient in items:
            identifier(recipient)
            require(recipient not in (body['sender'], FEE_ACCOUNT), 'invalid recipient')
        require(len(set(items)) == len(items), 'duplicate recipient')
    elif version == 3 and kind == 'budget_create':
        fields(op, {'type', 'id', 'cap', 'expires', 'recipients'})
        identifier(op['id']); integer(op['cap'], minimum=1); integer(op['expires'])
        items = op['recipients']
        require(type(items) is list and 1 <= len(items) <= 64, 'explicit budget recipients required')
        for recipient in items:
            identifier(recipient)
            require(recipient not in (body['sender'], FEE_ACCOUNT), 'invalid budget recipient')
        require(len(set(items)) == len(items), 'duplicate budget recipient')
    elif kind == 'revoke' or (version == 3 and kind == 'budget_revoke'):
        fields(op, {'type', 'id'}); identifier(op['id'])
    elif kind == 'fence':
        fields(op, {'type'})
    elif kind in ('open_account', 'rotate_key') and version in (2, 3):
        fields(op, {'type', 'public_key', 'acceptance'} | ({'units'} if kind == 'open_account' else set()))
        pubkey(op['public_key'])
        if kind == 'open_account':
            integer(op['units'], minimum=1); debit += op['units']
        if mode == 'accept':
            require(signer_public_key == op['public_key'] and op['acceptance'] == '',
                    'incoming key must accept an unsigned key-consent intention')
        else:
            verify_account_key_acceptance(body)
    else:
        raise Reject('unsupported operation')
    require(mode != 'accept' or kind in ('open_account', 'rotate_key'), 'not an incoming-key operation')
    integer(debit)
    signed_view = {'genesis_hash': digest(genesis), 'body': body, 'mode': mode,
                   'signer_public_key': signer_public_key}
    confirmation = hashlib.sha256(REVIEW_DOMAIN + canonical(signed_view)).hexdigest()
    return {'schema': 1, 'development_only': True, 'current_authority_verified': False,
            'network': genesis['chain_id'], 'asset': genesis['asset'], 'units': 'atomic integer units',
            'role': 'incoming-key consent' if mode == 'accept' else ('agent grant' if body['grant_id'] else 'account key'),
            'signer_public_key': signer_public_key, 'body': body, 'mode': mode,
            'native_fee_units': genesis['fee'], 'proposed_account_debit_units': debit,
            'confirmation': confirmation,
            'warning': 'No current balance, nonce, authority or settlement proof. No broadcast. Development keys only.'}


def approve_intent(path: Path, password: bytes, genesis: dict, body: dict,
                   signer_public_key: str, confirmation: str, *, mode: str = 'sign') -> dict:
    review = review_intent(genesis, body, signer_public_key, mode=mode)
    require(type(confirmation) is str and re.fullmatch('[0-9a-f]{64}', confirmation) is not None
            and hmac.compare_digest(review['confirmation'], confirmation),
            'intention changed or confirmation does not match')
    key = _load_vault(path, password)
    require(public(key) == signer_public_key, 'vault is not the reviewed signer')
    if mode == 'accept':
        return accept_account_key(key, review['body'])
    return sign(key, review['body'])
