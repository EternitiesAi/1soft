"""Public native-v3 transactions for the actual-engine acceptance runner.

No validator, signing custody, consensus claim or generated secret leaves this
fixture builder. Its output is also applied to the real local state machine.
"""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import NativeLedger, address, public, sign, canonical


def build_budget_case(chain, *, state_commitment=None):
    owner, merchant, raven, atlas = (Ed25519PrivateKey.generate() for _ in range(4))
    a, b = address(public(owner)), address(public(merchant))
    g = {'chain_id':chain,'asset':'DEV','fee':2,'protocol_version':3,
         'allocations':[{'public_key':public(owner),'units':100_000_000},{'public_key':public(merchant),'units':0}]}
    if state_commitment is not None:
        if state_commitment != 'smt-v1': raise ValueError('unsupported commitment mode')
        g['state_commitment'] = state_commitment
    m = NativeLedger(':memory:',g)
    def tx(key,nonce,op,grant=''):
        return canonical(sign(key,m.body(a,nonce,op,grant_id=grant,valid_until=10000)))
    def grant(label,key):
        return {'type':'grant','id':label,'budget_id':'project','public_key':public(key),'cap':100,
                'expires':10000,'recipients':[b]}
    def pay(amount):return {'type':'transfer','to':b,'units':amount}
    accepted = [
        ('native transfer',tx(owner,0,pay(1000))),
        ('shared budget creation',tx(owner,1,{'type':'budget_create','id':'project','cap':100,'expires':10000,'recipients':[b]})),
        ('raven budget membership',tx(owner,2,grant('raven',raven))),
        ('atlas budget membership',tx(owner,3,grant('atlas',atlas))),
        ('first worker payment',tx(raven,0,pay(58),'raven')),
        ('second worker boundary payment',tx(atlas,0,pay(38),'atlas')),
        ('revoke whole budget',tx(owner,4,{'type':'budget_revoke','id':'project'}))]
    result = {'genesis':g,'protocol_version':3,'accepted':accepted,
              'rejections_before':{'second worker boundary payment':[
                  ('aggregate cap refuses individually affordable payment',tx(atlas,0,pay(39),'atlas'))]},
              'rejected':[
                  ('revoked budget refuses existing worker',tx(raven,1,pay(1),'raven')),
                  ('budget name cannot reset spent history',tx(owner,5,{'type':'budget_create','id':'project','cap':100,'expires':10000,'recipients':[b]}))],
              'budget_id':m.grant_storage_id(a,'project')}
    m.close()
    return result
