"""Wire-compatible subset of CometBFT v0.38.25 ABCI protobuf messages.

Uses Google's protobuf runtime, not a custom protobuf parser. Field numbers were
checked against upstream proto/tendermint/abci/types.proto at v0.38.25. Unused
request fields (timestamps, commit information) remain protobuf unknown fields;
this native application does not use them. Real upstream interoperability is a
separate, mandatory test gate, not implied by local serialization tests.
"""
from __future__ import annotations

import io
import socket
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf.message import DecodeError

MAX_FRAME = 2_097_152
D = descriptor_pb2.FieldDescriptorProto
B, S, I, U, BOOL, MSG = D.TYPE_BYTES, D.TYPE_STRING, D.TYPE_INT64, D.TYPE_UINT64, D.TYPE_BOOL, D.TYPE_MESSAGE
SCHEMA = {
 'RequestEcho': [('message',1,S)], 'RequestFlush': [],
 'RequestInfo': [('version',1,S),('block_version',2,U),('p2p_version',3,U),('abci_version',4,S)],
 'RequestInitChain': [('chain_id',2,S),('app_state_bytes',5,B),('initial_height',6,I)],
 'RequestQuery': [('data',1,B),('path',2,S),('height',3,I),('prove',4,BOOL)],
 'RequestCheckTx': [('tx',1,B),('type',2,D.TYPE_INT32)], 'RequestCommit': [],
 'RequestListSnapshots': [], 'RequestOfferSnapshot': [], 'RequestLoadSnapshotChunk': [], 'RequestApplySnapshotChunk': [],
 'RequestPrepareProposal': [('max_tx_bytes',1,I),('txs',2,B,True),('height',5,I)],
 'RequestProcessProposal': [('txs',1,B,True),('hash',4,B),('height',5,I)],
 'RequestExtendVote': [], 'RequestVerifyVoteExtension': [('vote_extension',4,B)],
 'RequestFinalizeBlock': [('txs',1,B,True),('hash',4,B),('height',5,I)],
 'ResponseException': [('error',1,S)], 'ResponseEcho': [('message',1,S)], 'ResponseFlush': [],
 'ResponseInfo': [('data',1,S),('version',2,S),('app_version',3,U),('last_block_height',4,I),('last_block_app_hash',5,B)],
 'ResponseInitChain': [('app_hash',3,B)],
 'ResponseQuery': [('code',1,D.TYPE_UINT32),('log',3,S),('info',4,S),('index',5,I),('key',6,B),('value',7,B),('height',9,I),('codespace',10,S)],
 'ResponseCheckTx': [('code',1,D.TYPE_UINT32),('data',2,B),('log',3,S),('gas_wanted',5,I),('gas_used',6,I),('codespace',8,S)],
 'ResponseCommit': [('retain_height',3,I)], 'ResponseListSnapshots': [],
 'ResponseOfferSnapshot': [('result',1,D.TYPE_INT32)], 'ResponseLoadSnapshotChunk': [],
 'ResponseApplySnapshotChunk': [('result',1,D.TYPE_INT32)],
 'ResponsePrepareProposal': [('txs',1,B,True)],
 'ResponseProcessProposal': [('status',1,D.TYPE_INT32)],
 'ResponseExtendVote': [('vote_extension',1,B)],
 'ResponseVerifyVoteExtension': [('status',1,D.TYPE_INT32)],
 'ExecTxResult': [('code',1,D.TYPE_UINT32),('data',2,B),('log',3,S),('gas_wanted',5,I),('gas_used',6,I),('codespace',8,S)],
 'ResponseFinalizeBlock': [('tx_results',2,'ExecTxResult',True),('app_hash',5,B)],
}
REQUESTS = [('echo',1,'RequestEcho'),('flush',2,'RequestFlush'),('info',3,'RequestInfo'),
 ('init_chain',5,'RequestInitChain'),('query',6,'RequestQuery'),('check_tx',8,'RequestCheckTx'),
 ('commit',11,'RequestCommit'),('list_snapshots',12,'RequestListSnapshots'),('offer_snapshot',13,'RequestOfferSnapshot'),
 ('load_snapshot_chunk',14,'RequestLoadSnapshotChunk'),('apply_snapshot_chunk',15,'RequestApplySnapshotChunk'),
 ('prepare_proposal',16,'RequestPrepareProposal'),('process_proposal',17,'RequestProcessProposal'),
 ('extend_vote',18,'RequestExtendVote'),('verify_vote_extension',19,'RequestVerifyVoteExtension'),
 ('finalize_block',20,'RequestFinalizeBlock')]
RESPONSES = [('exception',1,'ResponseException')] + [(name, num+1, 'Response'+kind[len('Request'):]) for name,num,kind in REQUESTS]

fd = descriptor_pb2.FileDescriptorProto(name='eternities_abci038_subset.proto', package='eternities.abci038', syntax='proto3')
for name, fields in {**SCHEMA, 'Request': REQUESTS, 'Response': RESPONSES}.items():
    message = fd.message_type.add(name=name)
    oneof = name in ('Request','Response')
    if oneof: message.oneof_decl.add(name='value')
    for entry in fields:
        fname, number, kind, *repeat = entry
        f = message.field.add(name=fname, number=number,
            label=D.LABEL_REPEATED if repeat and repeat[0] else D.LABEL_OPTIONAL)
        if isinstance(kind, str):
            f.type=MSG; f.type_name='.eternities.abci038.'+kind
        else: f.type=kind
        if oneof: f.oneof_index=0
pool = descriptor_pool.DescriptorPool(); pool.Add(fd)
Request = message_factory.GetMessageClass(pool.FindMessageTypeByName('eternities.abci038.Request'))
Response = message_factory.GetMessageClass(pool.FindMessageTypeByName('eternities.abci038.Response'))


def uvarint(value: int) -> bytes:
    if type(value) is not int or not 0 <= value <= MAX_FRAME: raise ValueError('invalid frame size')
    out = bytearray()
    while value >= 128: out.append((value & 127) | 128); value >>= 7
    out.append(value)
    return bytes(out)


def read_frame(stream) -> bytes | None:
    length = 0
    for index in range(10):
        b = stream.read(1)
        if not b:
            if index == 0: return None
            raise ValueError('truncated length')
        byte = b[0]
        if index == 9 and byte > 1: raise ValueError('varint overflow')
        length |= (byte & 127) << (7*index)
        if not byte & 128: break
    else: raise ValueError('varint overflow')
    if length > MAX_FRAME: raise ValueError('frame too large')
    # Canonical length delimiter only; lengths from CometBFT's writer are canonical.
    if len(uvarint(length)) != index+1: raise ValueError('noncanonical length')
    payload = bytearray()
    while len(payload) < length:
        chunk = stream.read(length-len(payload))
        if not chunk: raise ValueError('truncated message')
        payload.extend(chunk)
    return bytes(payload)


def write_frame(stream, message):
    wire = message.SerializeToString(deterministic=True)
    stream.write(uvarint(len(wire))); stream.write(wire); stream.flush()


class Client:
    """Local ABCI test client. Sends application requests, NOT consensus votes."""
    def __init__(self, path: str, timeout: float = 5):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(timeout)
        self.socket.connect(path)
        self.stream = self.socket.makefile('rwb', buffering=0)

    def call(self, method: str, **kwargs):
        request = Request()
        target = getattr(request, method); target.SetInParent()
        for k,v in kwargs.items():
            field = target.DESCRIPTOR.fields_by_name[k]
            if field.is_repeated: getattr(target,k).extend(v)
            else: setattr(target,k,v)
        write_frame(self.stream, request)
        data = read_frame(self.stream)
        if data is None: raise ConnectionError('ABCI connection closed')
        response = Response.FromString(data)
        if response.WhichOneof('value') == 'exception': raise RuntimeError(response.exception.error)
        if response.WhichOneof('value') != method: raise RuntimeError('unexpected ABCI response')
        return getattr(response, method)

    def close(self):
        self.stream.close(); self.socket.close()

    def __enter__(self): return self
    def __exit__(self,*args): self.close()
