"""Disposable protocol-4 monetary and validator identities for local tests only."""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from native_core import public
from registry_rules_core import GENESIS_FORMAT
from validator_sets_core import canonical_roster


def key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def fixture():
    payers = [key(1), key(2)]
    validators = [key(i) for i in range(41, 46)]
    admins = [key(i) for i in range(171, 175)]
    initial = canonical_roster([{'public_key': public(k), 'power': 10} for k in validators[:4]])
    replacement = canonical_roster([
        {'public_key': public(validators[1]), 'power': 12},
        {'public_key': public(validators[2]), 'power': 10},
        {'public_key': public(validators[3]), 'power': 10},
        {'public_key': public(validators[4]), 'power': 9},
    ])
    registry = {'schema': 1, 'format': GENESIS_FORMAT, 'mode': 'development-only',
                'chain_id': 'one-p4-dev', 'validators': initial,
                'administrators': {'format': 'threshold-ed25519-v1',
                                   'public_keys': sorted(public(k) for k in admins), 'threshold': 3},
                'minimum_delay_blocks': 2, 'cooldown_blocks': 1,
                'minimum_validators': 4, 'maximum_power_bps': 3333}
    genesis = {'chain_id': 'one-p4-dev', 'asset': 'ONE', 'fee': 1,
               'allocations': [{'public_key': public(k), 'units': 100_000} for k in payers],
               'protocol_version': 4, 'validator_registry': registry}
    return genesis, payers, admins, validators, replacement
