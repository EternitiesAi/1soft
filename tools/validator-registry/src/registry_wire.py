"""Experimental registry FinalizeBlock codec; never imported by the native server.

Field numbers follow the pinned CometBFT v0.38.25 ABI. A local encode/decode check
is not official-Go interoperability or execution by a changing-validator engine.
"""
from google.protobuf import descriptor_pb2,descriptor_pool,message_factory
from commit_verifier import exact
from registry_rules import require,integer,MAX_BLOCK_TXS
from validator_sets import hex_text,MAX_POWER,MAX_VALIDATORS
import hashlib

D=descriptor_pb2.FieldDescriptorProto
fd=descriptor_pb2.FileDescriptorProto(name='1soft_registry038.proto',package='one.registry038',syntax='proto3')
for name,fields in {
    'PublicKey':[('ed25519',1,D.TYPE_BYTES,False)],
    'ValidatorUpdate':[('pub_key',1,'PublicKey',False),('power',2,D.TYPE_INT64,False)],
    'ExecTxResult':[('code',1,D.TYPE_UINT32,False),('data',2,D.TYPE_BYTES,False),('log',3,D.TYPE_STRING,False)],
    'ResponseFinalizeBlock':[('tx_results',2,'ExecTxResult',True),('validator_updates',3,'ValidatorUpdate',True),('app_hash',5,D.TYPE_BYTES,False)],
}.items():
    m=fd.message_type.add(name=name)
    for key,num,kind,repeated in fields:
        f=m.field.add(name=key,number=num,label=D.LABEL_REPEATED if repeated else D.LABEL_OPTIONAL)
        if type(kind) is str:f.type=D.TYPE_MESSAGE;f.type_name='.one.registry038.'+kind
        else:f.type=kind
pool=descriptor_pool.DescriptorPool();pool.Add(fd)
ResponseFinalizeBlock=message_factory.GetMessageClass(pool.FindMessageTypeByName('one.registry038.ResponseFinalizeBlock'))


def encode_finalize(result):
    """Only a RegistryApplication result belongs here, not an unsigned proposal."""
    exact(result,{'height','app_hash','tx_results','validator_updates','events','validators_hash',
                  'next_validators_hash','last_commit_validators_hash','epoch'},'registry finalization')
    integer(result['height'],1);hex_text(result['app_hash'])
    require(type(result['tx_results']) is list and len(result['tx_results'])<=MAX_BLOCK_TXS,'too many execution results')
    response=ResponseFinalizeBlock(app_hash=bytes.fromhex(result['app_hash']))
    for r in result['tx_results']:
        integer(r['code'],0,1)
        require(type(r['log']) is str and type(r['data']) is str,'invalid registry result')
        if r['code']==0:hex_text(r['data'])
        else:require(r['data']=='' and r['log']=='registry action rejected','invalid rejection result')
        response.tx_results.add(code=r['code'],data=r['data'].encode('ascii'),log=r['log'])
    rows=result['validator_updates'];require(type(rows) is list and len(rows)<=2*MAX_VALIDATORS,'too many updates')
    addresses=[]
    for r in rows:
        exact(r,{'public_key','power'},'registry validator update');key=bytes.fromhex(hex_text(r['public_key']))
        integer(r['power'],0,MAX_POWER);addresses.append(hashlib.sha256(key).digest()[:20])
        update=response.validator_updates.add(power=r['power']);update.pub_key.ed25519=key
    require(addresses==sorted(set(addresses)),'duplicate or noncanonical updates')
    return response.SerializeToString(deterministic=True)
