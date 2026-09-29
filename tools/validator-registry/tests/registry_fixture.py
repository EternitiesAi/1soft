"""Public disposable deterministic seeds, never user or production keys."""
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from native_core import public
from validator_sets import canonical_roster
from registry_rules import RegistryRules,GENESIS_FORMAT
from commit_verifier import encode
import hashlib


def fixture():
    admins=[Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(171,175)]
    validators=[Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(181,193)]
    genesis={'schema':1,'format':GENESIS_FORMAT,'mode':'development-only','chain_id':'1soft-registry-dev-test',
             'validators':canonical_roster([{'public_key':public(k),'power':10} for k in validators[:4]]),
             'administrators':{'format':'threshold-ed25519-v1','public_keys':sorted(public(k) for k in admins),'threshold':3},
             'minimum_delay_blocks':2,'cooldown_blocks':1,'minimum_validators':4,'maximum_power_bps':3333}
    target=canonical_roster([{'public_key':public(k),'power':p} for k,p in zip(validators[1:5],(10,12,10,9))])
    return genesis,admins,validators,target


def authorize(rules,body,keys):
    signing=rules.signing_bytes(body)
    approvals=sorted([{'public_key':public(k),'signature':k.sign(signing).hex()} for k in keys],key=lambda r:r['public_key'])
    return encode({'body':body,'approvals':approvals})


def schedule(app,admins,target,*,emitted=4,valid_from=1,valid_until=20):
    body=app.rules.body(app.state(),{'kind':'schedule','emitted_height':emitted,'target_validators':target},
                        valid_from=valid_from,valid_until=valid_until)
    return authorize(app.rules,body,admins[:3])


def apply(app,txs=None,*,fault=''):
    h=app.state()['height']+1
    result=app.finalize_block(txs or [],h,hashlib.sha256(str(h).encode()).digest())
    app.commit(fault=fault)
    return result


def advance(app,until):
    while app.state()['height']<until:apply(app)
