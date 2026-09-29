"""Test-only CometBFT v0.38.25 ABCI descriptors for the isolated registry.

The existing native ABCI descriptor and server deliberately stay unchanged. This
subset adds only the fields needed to check real validator-set transitions.
"""
from __future__ import annotations

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from abci_wire import D, SCHEMA as NATIVE_SCHEMA, REQUESTS, RESPONSES, read_frame, write_frame

B, I, MSG = D.TYPE_BYTES, D.TYPE_INT64, D.TYPE_MESSAGE
SCHEMA = {name: list(fields) for name, fields in NATIVE_SCHEMA.items()}
SCHEMA.update({
    'PublicKey': [('ed25519', 1, B)],
    'ValidatorUpdate': [('pub_key', 1, 'PublicKey'), ('power', 2, I)],
    'Validator': [('address', 1, B), ('power', 3, I)],
    'VoteInfo': [('validator', 1, 'Validator'), ('block_id_flag', 3, D.TYPE_INT32)],
    'CommitInfo': [('round', 1, D.TYPE_INT32), ('votes', 2, 'VoteInfo', True)],
})
SCHEMA['RequestInitChain'].append(('validators', 4, 'ValidatorUpdate', True))
SCHEMA['ResponseInitChain'].append(('validators', 2, 'ValidatorUpdate', True))
SCHEMA['RequestFinalizeBlock'].extend((
    ('decided_last_commit', 2, 'CommitInfo'),
    ('next_validators_hash', 7, B),
))
SCHEMA['ResponseFinalizeBlock'].append(('validator_updates', 3, 'ValidatorUpdate', True))

fd = descriptor_pb2.FileDescriptorProto(
    name='one_registry_abci038_subset.proto', package='one.registryabci038', syntax='proto3')
for name, fields in {**SCHEMA, 'Request': REQUESTS, 'Response': RESPONSES}.items():
    message = fd.message_type.add(name=name)
    if name in ('Request', 'Response'):
        message.oneof_decl.add(name='value')
    for entry in fields:
        field_name, number, kind, *repeat = entry
        field = message.field.add(
            name=field_name, number=number,
            label=D.LABEL_REPEATED if repeat and repeat[0] else D.LABEL_OPTIONAL)
        if isinstance(kind, str):
            field.type = MSG
            field.type_name = '.one.registryabci038.' + kind
        else:
            field.type = kind
        if name in ('Request', 'Response'):
            field.oneof_index = 0
pool = descriptor_pool.DescriptorPool()
pool.Add(fd)
Request = message_factory.GetMessageClass(pool.FindMessageTypeByName('one.registryabci038.Request'))
Response = message_factory.GetMessageClass(pool.FindMessageTypeByName('one.registryabci038.Response'))