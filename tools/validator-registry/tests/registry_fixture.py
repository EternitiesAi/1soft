"""Public deterministic test keys only; never for a deployed network or funds."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from commit_verifier import encode
from validator_sets import canonical_roster
from registry_rules import (GENESIS_FORMAT, PROFILE, draft, sign_bytes, initial_state,
                            block_transition, sha)


def pub(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def fixture():
    admins = [Ed25519PrivateKey.from_private_bytes(bytes([i]) * 32) for i in (31, 32, 33)]
    validators = [Ed25519PrivateKey.from_private_bytes(bytes([i]) * 32) for i in range(41, 49)]
    roster = canonical_roster([{'public_key': pub(k), 'power': 10} for k in validators[:4]])
    g = {'schema': 1, 'format': GENESIS_FORMAT, 'profile': PROFILE, 'chain_id': '1soft-registry-lab',
         'administrators': {'public_keys': sorted(pub(k) for k in admins), 'threshold': 2},
         'rules': {'delay_blocks': 2, 'maximum_future_blocks': 100,
                   'minimum_validators': 4, 'maximum_key_power_bps': 3333},
         'validators': roster}
    target = canonical_roster([{'public_key': pub(k), 'power': 10} for k in validators[:5]])
    return g, admins, validators, target


def approve(body, keys):
    a = [{'public_key': pub(k), 'signature': k.sign(sign_bytes(body)).hex()} for k in keys]
    return encode({'body': body, 'approvals': sorted(a, key=lambda x: x['public_key'])})


def schedule(g, state, keys, target, emission=3, start=None, until=None):
    start = start or state['height'] + 1
    body = draft(g, state, {'type': 'schedule', 'emission_height': emission, 'validators': target},
                 valid_from=start, valid_until=until or start+20)
    return approve(body, keys)


def cancel(g, state, keys, proposal_id=None, start=None):
    start = start or state['height'] + 1
    body = draft(g, state, {'type': 'cancel', 'proposal_id': proposal_id or state['pending']['proposal_id']},
                 valid_from=start, valid_until=start+20)
    return approve(body, keys)


def block(g, state, txs=()):
    h = state['height'] + 1
    return block_transition(g, state, h, sha(str(h).encode()), list(txs))
