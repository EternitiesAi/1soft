"""Combine administrative replay with the existing dynamic header witness.

This authenticates a bounded registry-only history under explicit development
trust. It is not a wallet, node upgrade, independent-operator attestation or proof
that actual CometBFT processes emitted the reconstructed response bytes.
"""
from commit_verifier import (encode,load_json,pinned_genesis,header_hash,merkle_root,sha,hexbytes)
from validator_sets import ValidatorSet
from validator_witness import verify_witness,validate_policy
from registry_rules import RegistryRules,APP_VERSION,require,frozen
from registry_application import verify_snapshot,decode_txs,MAX_STORE_BYTES


def verify_registry_history(snapshot,witness,engine_genesis,policy,*,now_ns):
    snapshot=frozen(snapshot,MAX_STORE_BYTES);witness=frozen(witness)
    p=validate_policy(policy)
    require(p['expected_app_version']==APP_VERSION and p['anchor_height']==1,
            'registry evidence requires registry version and height-one external anchor')
    trusted=pinned_genesis(engine_genesis,p['genesis_sha256'])
    engine=load_json(engine_genesis,max_bytes=1024*1024)
    rules=RegistryRules(engine['app_state'])
    require(ValidatorSet.parse(rules.genesis['validators']).hash==trusted.validators_hash.hex(),
            'registry initial set differs from engine genesis')
    checked=verify_witness(witness,engine_genesis,p,now_ns=now_ns)
    snap,state=verify_snapshot(snapshot,rules.genesis,expected_height=checked['final_height']-1,
                                expected_app_hash=checked['final_app_hash'])
    entries=witness['entries']
    require(len(entries)==snap['height']+1,'registry needs complete signed header coverage')
    before=rules.initial_state()
    for record,entry in zip(snap['blocks'],entries):
        h=entry['signed_header']['header'];raws=decode_txs(record['transactions'])
        require(header_hash(h).hex()==record['block_hash'],'registry record not bound to its signed block')
        require(hexbytes(h['data_hash'],32,empty=True)==merkle_root([sha(r) for r in raws]),
                'administrative wires differ from signed block data')
        require(h['app_hash'].lower()==rules.state_hash(before),'preceding registry AppHash differs')
        after,result=rules.transition(before,raws,record['height'])
        require(h['validators_hash'].lower()==result['validators_hash'] and
                h['next_validators_hash'].lower()==result['next_validators_hash'],
                'signed validator schedule differs from authorized registry execution')
        before=after
    # Final header has not itself been executed by the snapshot. Its rosters are
    # determined by already committed queue metadata, never by its unknown txs.
    _,expected=rules.transition(before,[],before['height']+1)
    final=entries[-1]['signed_header']['header']
    require(final['validators_hash'].lower()==expected['validators_hash'] and
            final['next_validators_hash'].lower()==expected['next_validators_hash'],
            'final header roster differs from committed registry queue')
    return {'schema':1,'status':'verified-development-registry-history','height':state['height'],
            'app_hash':rules.state_hash(state),'epoch':state['epoch'],'accepted_actions':state['sequence'],
            'registry_administrative_authorization_verified':True,'signed_block_inclusion_verified':True,
            'activation_schedule_verified':True,'abci_emission_observed':False,
            'native_payment_state_verified':False,'wallet_authority_changed':False,
            'validator_history':checked,'consensus_executed':False,'release_status':'blocked'}
