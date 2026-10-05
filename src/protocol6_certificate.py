"""AS-OF P6 full-state authentication under an externally pinned static quorum."""
from commit_verifier import TrustAnchor,Validator,merkle_root,verify_signed_header,VerificationError
from protocol6_treasury import canonical,genesis_document,digest,application_hash,need
import hashlib
def trust(raw_genesis):
    g=genesis_document(raw_genesis)
    vals=[Validator(hashlib.sha256(bytes.fromhex(r['public_key'])).digest()[:20],bytes.fromhex(r['public_key']),r['power']) for r in g['validators']]
    vals.sort(key=lambda v:(-v.power,v.address));frozen=tuple(vals)
    return TrustAnchor(g['chain_id'],frozen,merkle_root([v.encoded() for v in frozen]),digest(raw_genesis),sum(v.power for v in frozen))
def verify_state(witness,signed_header,raw_genesis):
    g=genesis_document(raw_genesis);anchor=trust(raw_genesis)
    need(type(witness) is dict and set(witness)=={'genesis','height','app_hash','state'},'closed P6 state witness required')
    need(canonical(witness['genesis'])==raw_genesis,'P6 witness genesis differs from external pin')
    h=witness['height'];need(type(h) is int and 0<=h<=64,'P6 witness height')
    state=witness['state'];need(type(state) is dict and set(state)=={'version','treasury','receipts','blocks'} and state['version']==6 and type(state['blocks']) is list and len(state['blocks'])==h,'P6 witness state shape')
    computed=application_hash(g,h,state);need(witness['app_hash']==computed,'P6 witness AppHash differs')
    cert=verify_signed_header(signed_header,anchor,expected_height=h+1)
    need(cert['app_hash']==computed,'P6 state not bound by signed next header')
    return {**cert,'state_height':h,'header_height':h+1,'genesis_sha256':digest(raw_genesis),'profile_sha256':g['profile_sha256'],
        'claim':'AS-OF P6 full state authenticated by a pinned static quorum; no freshness or independent rule replay'}
