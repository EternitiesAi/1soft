"""Only the proposed validator_updates part of a FinalizeBlock protobuf.

This is a compatibility probe, not an ABCI server response or permission to emit it.
All existing application wire schemas remain unchanged.
"""
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from validator_sets import need, integer, hex_text, MAX_POWER, MAX_VALIDATORS
from commit_verifier import exact, sha
D=descriptor_pb2.FieldDescriptorProto
fd=descriptor_pb2.FileDescriptorProto(name='1soft_transition_probe.proto',package='one.transition',syntax='proto3')
for name,fields in {
    'PublicKey':[('ed25519',1,D.TYPE_BYTES,False)],
    'ValidatorUpdate':[('pub_key',1,'PublicKey',False),('power',2,D.TYPE_INT64,False)],
    'FinalizeBlock':[('validator_updates',3,'ValidatorUpdate',True)],
}.items():
    msg=fd.message_type.add(name=name)
    for field,tag,kind,repeated in fields:
        f=msg.field.add(name=field,number=tag,label=D.LABEL_REPEATED if repeated else D.LABEL_OPTIONAL)
        if type(kind) is str:f.type=D.TYPE_MESSAGE;f.type_name='.one.transition.'+kind
        else:f.type=kind
pool=descriptor_pool.DescriptorPool();pool.Add(fd)
FinalizeBlock=message_factory.GetMessageClass(pool.FindMessageTypeByName('one.transition.FinalizeBlock'))


def encode_update_response(rows):
    need(type(rows) is list and 1 <= len(rows) <= 2*MAX_VALIDATORS,'invalid update count')
    seen=set();addresses=[];response=FinalizeBlock()
    for row in rows:
        exact(row,{'public_key','power'},'validator update')
        key=bytes.fromhex(hex_text(row['public_key']));integer(row['power'],0,MAX_POWER)
        need(key not in seen,'duplicate validator update');seen.add(key);addresses.append(sha(key)[:20])
        v=response.validator_updates.add(power=row['power']);v.pub_key.ed25519=key
    need(addresses==sorted(addresses),'noncanonical update order')
    return response.SerializeToString(deterministic=True)
