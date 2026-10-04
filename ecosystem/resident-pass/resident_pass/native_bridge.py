"""Optional bridge to the local 1soft v0.13 compact-account verifier.

A dual-key, audience-specific association is NOT a spend grant. Native account
state, credential status, and possession of two distinct keys are checked
separately. The caller supplies its independently pinned native genesis trust.
Nothing is broadcast or added to native consensus, balances or grants.
"""
from __future__ import annotations
from .protocol import (LINK_DOMAIN,canonical,decode,digest,fields,number,require,card_body,
                       verify_signature)


def association_for(card,witness,signed_header,trust,account):
    from compact_verifier import verify_compact_witness
    from native_core import pubkey,integer
    from state_tree import COLUMNS
    body=card_body(card['body'])
    result=verify_compact_witness(witness,signed_header,trust,expected_queries=[('accounts',account)])
    value=result['records'][0]['row'];require(value is not None,'native account absent at snapshot')
    row=dict(zip(COLUMNS['accounts'],value))
    pubkey(row['public_key']);integer(row['epoch']);integer(row['balance']);integer(row['nonce'])
    require(row['public_key']!=body['holder_key'],'identity and financial keys must be separate')
    return {'schema':1,'purpose':'native-account-association','issuer':body['issuer'],
        'subject_id':body['subject_id'],'card_digest':digest(card),'audience':body['audience'],
        'native_genesis_hash':trust.native_genesis_hash,'chain_id':trust.chain_id,
        'account_id':account,'wallet_public_key':row['public_key'],'wallet_epoch':row['epoch'],
        'state_height':result['state_height'],'state_app_hash':result['state_app_hash'],
        'state_header_hash':result['header_hash']}


def sign_association(wallet_key,association,challenge):
    from .protocol import public,challenge_body
    challenge_body(challenge)
    require(challenge['purpose']=='link-native-account' and challenge['context_digest']==digest(association),
            'association does not match the reviewed challenge')
    require(public(wallet_key)==association['wallet_public_key'],'wrong financial key')
    return wallet_key.sign(LINK_DOMAIN+canonical({'association':association,'challenge':challenge})).hex()


def accept_association(verifier,card,presentation,association,wallet_signature,witness,signed_header,trust):
    """Reverify all evidence, then consume one local challenge atomically.

    Freshness is bounded locally, not a guarantee that no later block changed the
    account. Hosted issuers, consensus correctness and operator independence are
    NOT verified here. Synthetic committee fixtures remain synthetic.
    """
    from commit_verifier import timestamp
    card=decode(canonical(card));presentation=decode(canonical(presentation));association=decode(canonical(association))
    require(type(association) is dict and type(association.get('account_id')) is str,'invalid association')
    expected=association_for(card,witness,signed_header,trust,association['account_id'])
    require(association==expected,'association differs from authenticated account state')
    fields(presentation,{'body','signature'})
    verify_signature(expected['wallet_public_key'],wallet_signature,LINK_DOMAIN,
                     {'association':association,'challenge':presentation['body']})
    stamp=timestamp(signed_header['header']['time'])
    with verifier.atomic():
        now=verifier.now()
        require(stamp.seconds<=now and now-stamp.seconds<=120,'native account evidence outside freshness window')
        body,challenge=verifier._check(card,presentation,now,purpose='link-native-account',context_digest=digest(association))
        old=verifier.db.execute('SELECT height,hash FROM native_checkpoints WHERE chain=?',(trust.native_genesis_hash,)).fetchone()
        if old:
            require(expected['state_height']>=old['height'],'native checkpoint rollback')
            if expected['state_height']==old['height']:
                require(expected['state_app_hash']==old['hash'],'conflicting native checkpoint')
        verifier.db.execute('INSERT OR REPLACE INTO native_checkpoints VALUES (?,?,?)',
            (trust.native_genesis_hash,expected['state_height'],expected['state_app_hash']))
        return verifier._finish(body,challenge,{'native_account_association':expected,
            'wallet_key_at_snapshot_verified':True,'identity_and_money_keys_distinct':True,
            'latest_native_state_guaranteed':False,'native_mutation_performed':False,
            'live_network_provenance_established':False})
