"""CometBFT v0.38.25 ABCI++ fields required by fresh-genesis protocol 5.

The P1/P2/P3 descriptor remains unchanged. This is an explicit versioned codec.
"""
from __future__ import annotations

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

from abci_wire import D, SCHEMA as LEGACY_SCHEMA, REQUESTS, RESPONSES, read_frame, write_frame, MAX_FRAME

B, I, MSG = D.TYPE_BYTES, D.TYPE_INT64, D.TYPE_MESSAGE
SCHEMA = {name: list(fields) for name, fields in LEGACY_SCHEMA.items()}
SCHEMA.update({
    'PublicKey': [('ed25519', 1, B)],
    'ValidatorUpdate': [('pub_key', 1, 'PublicKey'), ('power', 2, I)],
    'Validator': [('address', 1, B), ('power', 3, I)],
    'VoteInfo': [('validator', 1, 'Validator'), ('block_id_flag', 3, D.TYPE_INT32)],
    'CommitInfo': [('round', 1, D.TYPE_INT32), ('votes', 2, 'VoteInfo', True)],
})
SCHEMA['RequestInitChain'].append(('validators', 4, 'ValidatorUpdate', True))
SCHEMA['ResponseInitChain'].append(('validators', 2, 'ValidatorUpdate', True))
SCHEMA['RequestProcessProposal'].append(('next_validators_hash', 7, B))
SCHEMA['RequestFinalizeBlock'].extend((
    ('decided_last_commit', 2, 'CommitInfo'),
    ('next_validators_hash', 7, B),
))
SCHEMA['ResponseFinalizeBlock'].append(('validator_updates', 3, 'ValidatorUpdate', True))

fd = descriptor_pb2.FileDescriptorProto(
    name='one_protocol5_abci038_subset.proto', package='one.protocol5abci038', syntax='proto3')
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
            field.type_name = '.one.protocol5abci038.' + kind
        else:
            field.type = kind
        if name in ('Request', 'Response'):
            field.oneof_index = 0
pool = descriptor_pool.DescriptorPool()
pool.Add(fd)
Request = message_factory.GetMessageClass(pool.FindMessageTypeByName('one.protocol5abci038.Request'))
Response = message_factory.GetMessageClass(pool.FindMessageTypeByName('one.protocol5abci038.Response'))


def encode_finalization(result: dict) -> bytes:
    response = Response()
    out = response.finalize_block
    out.SetInParent()
    out.app_hash = bytes.fromhex(result['app_hash'])
    for row in result['tx_results']:
        tx = out.tx_results.add(code=row['code'], data=row['data'].encode('ascii'), log=row['log'])
        if tx.code:
            tx.codespace = 'one-shielded-development'
    for row in result['validator_updates']:
        update = out.validator_updates.add()
        update.pub_key.ed25519 = bytes.fromhex(row['public_key'])
        update.power = row['power']
    return out.SerializeToString(deterministic=True)
