"""Bounded CometBFT validator-set mathematics, not a governance authority.

No production node imports this module. Positive power is required in full rosters;
zero power exists only in the deterministic removal delta. Uses the existing
v0.38 Ed25519/protobuf/Merkle primitives without changing the legacy verifier.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Any
from commit_verifier import (MAX_POWER, MAX_VALIDATORS, Validator, exact, encode,
                             merkle_root, load_json)

MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
MAX_HEIGHT = 2**53 - 1


class TransitionError(ValueError):
    """Evidence or proposed transition refused; never financial authorization."""


def need(value: bool, message: str) -> None:
    if not value:
        raise TransitionError(message)


def integer(value: Any, low=0, high=MAX_HEIGHT) -> int:
    need(type(value) is int and low <= value <= high, 'invalid exact integer')
    return value


def hex_text(value: Any, size=32) -> str:
    need(type(value) is str and len(value) == 2 * size and
         all(c in '0123456789abcdef' for c in value), 'noncanonical hash or public key')
    return value


def chain_name(value: Any) -> str:
    need(type(value) is str and 0 < len(value.encode('utf8')) <= 50, 'invalid chain identity')
    return value


def freeze(value: Any, limit=MAX_DOCUMENT_BYTES) -> Any:
    raw = encode(value)
    need(len(raw) <= limit, 'document exceeds byte bound')
    return load_json(raw, max_bytes=limit)


def document_id(value: Any) -> str:
    return hashlib.sha256(encode(value)).hexdigest()


@dataclass(frozen=True)
class ValidatorSet:
    validators: tuple[Validator, ...]

    def __post_init__(self):
        need(type(self.validators) is tuple and 1 <= len(self.validators) <= MAX_VALIDATORS,
             'invalid immutable validator tuple')
        for v in self.validators:
            need(type(v) is Validator and type(v.public_key) is bytes and len(v.public_key) == 32
                 and type(v.address) is bytes and v.address == hashlib.sha256(v.public_key).digest()[:20],
                 'invalid validator object')
            integer(v.power, 1, MAX_POWER)
        need(len({v.address for v in self.validators}) == len(self.validators), 'duplicate validator')
        need(list(self.validators) == sorted(self.validators, key=lambda v: (-v.power, v.address)),
             'noncanonical validator ordering')
        need(sum(v.power for v in self.validators) <= MAX_POWER, 'total voting power overflow')

    @classmethod
    def parse(cls, rows: Any) -> 'ValidatorSet':
        need(type(rows) is list and 1 <= len(rows) <= MAX_VALIDATORS, 'invalid roster size')
        seen = set(); vals = []
        for row in rows:
            exact(row, {'public_key', 'power'}, 'validator roster row')
            key = bytes.fromhex(hex_text(row['public_key']))
            power = integer(row['power'], 1, MAX_POWER)
            address = hashlib.sha256(key).digest()[:20]
            need(address not in seen, 'duplicate validator key/address')
            seen.add(address); vals.append(Validator(address, key, power))
        need(sum(v.power for v in vals) <= MAX_POWER, 'validator voting power overflow')
        ordered = sorted(vals, key=lambda v: (-v.power, v.address))
        # Wire order is a contract; do not silently normalize untrusted proofs.
        need(vals == ordered, 'roster must use voting-power/address order')
        return cls(tuple(vals))

    @property
    def hash(self) -> str:
        return merkle_root([v.encoded() for v in self.validators]).hex()

    @property
    def total_power(self) -> int:
        return sum(v.power for v in self.validators)

    def json(self) -> list[dict]:
        return [{'public_key': v.public_key.hex(), 'power': v.power} for v in self.validators]


def canonical_roster(rows: Any) -> list[dict]:
    """Authoring helper only. The evidence parser itself never sorts its input."""
    copy = freeze(rows, 128 * 1024)
    need(type(copy) is list and 1 <= len(copy) <= MAX_VALIDATORS, 'invalid roster size')
    for row in copy:
        exact(row, {'public_key', 'power'}, 'proposed validator')
        hex_text(row['public_key']); integer(row['power'], 1, MAX_POWER)
    copy.sort(key=lambda r: (-r['power'], hashlib.sha256(bytes.fromhex(r['public_key'])).digest()[:20]))
    return ValidatorSet.parse(copy).json()


def validator_updates(current: ValidatorSet, target: ValidatorSet) -> list[dict]:
    before = {v.public_key.hex(): v.power for v in current.validators}
    after = {v.public_key.hex(): v.power for v in target.validators}
    changed = [k for k in before.keys() | after.keys() if before.get(k) != after.get(k)]
    changed.sort(key=lambda k: hashlib.sha256(bytes.fromhex(k)).digest()[:20])
    return [{'public_key': k, 'power': after.get(k, 0)} for k in changed]


def draft_transition(current_rows, target_rows, *, chain_id, native_genesis_hash,
                     expected_current_hash, emitted_height) -> dict:
    """An unsigned, non-authorizing draft; never a ready-to-broadcast transaction.

    The upstream delay is H (emit), H+1 (announce next set), H+2 (active set),
    H+3 (last-commit information uses the changed set). This does not schedule or
    install an upgrade, decide who may change validators, or emit a live ABCI reply.
    """
    old = ValidatorSet.parse(freeze(current_rows)); new = ValidatorSet.parse(freeze(target_rows))
    chain_name(chain_id); hex_text(native_genesis_hash); hex_text(expected_current_hash)
    h = integer(emitted_height, 1, MAX_HEIGHT - 3)
    need(old.hash == expected_current_hash, 'draft base roster differs from expected hash')
    updates = validator_updates(old, new)
    need(updates, 'unchanged validator roster is not a transition')
    return {'schema': 1, 'format': '1soft/validator-transition-draft/v1',
            'chain_id': chain_id, 'native_genesis_hash': native_genesis_hash,
            'old_set': old.json(), 'new_set': new.json(),
            'old_set_hash': old.hash, 'new_set_hash': new.hash,
            'emitted_height': h, 'announcement_height': h + 1,
            'activation_height': h + 2, 'last_commit_height': h + 3,
            'validator_updates': updates, 'authorization': 'not-established',
            'activation_performed': False, 'protocol_upgrade_required': True}


def validate_draft(value: Any) -> dict:
    p = freeze(value)
    expected = {'schema','format','chain_id','native_genesis_hash','old_set','new_set',
                'old_set_hash','new_set_hash','emitted_height','announcement_height',
                'activation_height','last_commit_height','validator_updates',
                'authorization','activation_performed','protocol_upgrade_required'}
    exact(p, expected, 'validator transition draft')
    reproduced = draft_transition(p['old_set'], p['new_set'], chain_id=p['chain_id'],
        native_genesis_hash=p['native_genesis_hash'], expected_current_hash=p['old_set_hash'],
        emitted_height=p['emitted_height'])
    need(encode(reproduced) == encode(p), 'draft differs from deterministic transition')
    return p
