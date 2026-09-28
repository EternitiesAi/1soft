"""Actual local ledger transitions; publicly known disposable test key seeds.
Committee headers/signatures are synthetic, not validator-network execution.
"""
import base64
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from block_application import BlockApplication
from certificate_fixture import validators, make_header, make_commit
from commit_verifier import encode, header_hash
from native_core import NativeLedger, address, public, canonical, sign
from receipt_capsule import pack_receipt, sha


def case(smt=True, count=6, selected=1, keep=2, amount=10, prune_after=0, protocol=3):
    key = Ed25519PrivateKey.from_private_bytes(bytes([210])*32)
    other = Ed25519PrivateKey.from_private_bytes(bytes([211])*32)
    g = {'chain_id': '1soft-receipt-archive-test', 'asset': 'DEV', 'fee': 2,
         'protocol_version': protocol, 'allocations': [
             {'public_key': public(key), 'units': 1000000},
             {'public_key': public(other), 'units': 0}]}
    if protocol == 1: g.pop('protocol_version')
    if smt: g['state_commitment'] = 'smt-v1'
    engine, trust, keys = validators(g)
    engine_raw = encode(engine)
    app = BlockApplication(':memory:', expected_genesis=g, block_history_keep=keep)
    app.init_chain(g['chain_id'], g)
    model = NativeLedger(':memory:', g)
    commits, items = [], []
    try:
        for h in range(1, count+1):
            raw = canonical(sign(key, model.body(address(public(key)), h-1,
                {'type':'transfer','to':address(public(other)), 'units': amount}, valid_until=10000)))
            previous = commits[-1]['commit']['block_id'] if commits else None
            head = make_header(trust, h, app.app_hash, [raw], previous)
            head['version']['app'] = str(protocol)
            signed = make_commit(head, trust, keys)
            result = app.finalize_block([raw], h, header_hash(head)); app.commit()
            assert result['tx_results'][0]['code'] == 0
            commits.append(signed)
            items.append({'tx':base64.b64encode(raw).decode(),
                'block': {'block_id':signed['commit']['block_id'],
                          'block':{'header':head,'data':{'txs':[base64.b64encode(raw).decode()]}}},
                'commit': signed})
        state = json.loads(app.query('/state')['value'])
        head = make_header(trust, count+1, app.app_hash, previous=commits[-1]['commit']['block_id'])
        head['version']['app'] = str(protocol)
        signed_state = make_commit(head, trust, keys)
        packet = {'schema':1, 'state':state, 'state_commit':signed_state, 'transactions':[items[selected-1]]}
        raw = base64.b64decode(items[selected-1]['tx'])
        # commits[0] is header1. The inclusion header is selected, so the
        # intermediate headers begin at selected+1 (zero-based index selected).
        links = commits[selected:]
        pin = header_hash(head).hex()
        capsule = pack_receipt(packet, engine_raw, sha(engine_raw), expected_transaction=raw,
                               expected_header_hash=pin, continuation=links)
        for h in range(count+1, count+prune_after+1):
            app.finalize_block([],h,bytes.fromhex(sha(str(h).encode())));app.commit()
        return {'packet':packet,'capsule':capsule,'genesis':engine_raw,'genesis_sha256':sha(engine_raw),
                'raw':raw,'pin':pin,'links':links,'keys':keys,'trust':trust,
                'old_block_code':app.query('/block/'+str(selected))['code'],
                'app_hash':app.app_hash,'later_height':app.height,'state':state,'commits':commits,'items':items}
    finally:
        model.close(); app.close()
