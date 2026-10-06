"""AS-OF P8 full-state authentication under an externally pinned static quorum."""
import hashlib
from commit_verifier import TrustAnchor, Validator, merkle_root, verify_signed_header
from protocol8_consensus import (canonical, digest, genesis_document, replay,
                                 application_hash, need, MAX_HEIGHT, MAX_STATE_BYTES)

def trust(raw_genesis, worker):
    g = genesis_document(raw_genesis, worker)
    vals = [Validator(hashlib.sha256(bytes.fromhex(r['public_key'])).digest()[:20],
                      bytes.fromhex(r['public_key']), r['power']) for r in g['validators']]
    vals.sort(key=lambda v: (-v.power, v.address))
    frozen = tuple(vals)
    return TrustAnchor(g['chain_id'], frozen, merkle_root([v.encoded() for v in frozen]),
                       digest(raw_genesis), sum(v.power for v in frozen))

def verify_state(witness, signed_header, raw_genesis, worker):
    need(type(witness) is dict and set(witness) == {'genesis', 'height', 'app_hash', 'state'},
         'closed P8 full-state witness')
    need(len(canonical(witness)) <= MAX_STATE_BYTES + 16384, 'P8 witness byte bound')
    g = genesis_document(raw_genesis, worker)
    need(canonical(witness['genesis']) == raw_genesis, 'P8 witness external genesis differs')
    h = witness['height']
    need(type(h) is int and 0 <= h <= MAX_HEIGHT, 'P8 witness height')
    replay(g, witness['state'], h, worker)
    computed = application_hash(g, h, witness['state'])
    need(witness['app_hash'] == computed, 'P8 replayed AppHash differs')
    cert = verify_signed_header(signed_header, trust(raw_genesis, worker), expected_height=h+1)
    need(cert['app_hash'] == computed, 'P8 state not bound by signed next header')
    return {**cert, 'state_height':h, 'header_height':h+1,
            'genesis_sha256':digest(raw_genesis), 'profile_sha256':g['profile_sha256'],
            'claim':'AS-OF P8 full state under an externally pinned static quorum; native history replayed; no freshness'}
