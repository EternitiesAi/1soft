"""Independent, static-validator-set CometBFT v0.38 development verifier.

Verifies signed headers, full transaction-list inclusion, and full-state witnesses.
NOT consensus, NOT a general light client, NOT proof of freshness or independence.
Trust comes from a separately pinned genesis file, never validators in an RPC reply.
Only Ed25519 and an unchanged genesis validator set are supported. All signature
slots are checked, including nil votes and signatures beyond the quorum threshold.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory, timestamp_pb2

MAX_PACKET_BYTES = 16 * 1024 * 1024
MAX_VALIDATORS = 256  # intentional development bound, not an upstream protocol limit
MAX_POWER = (2**63 - 1) // 8
MAX_TXS = 64
MAX_TX_BYTES = 16_384
ZERO_TIME = '0001-01-01T00:00:00Z'
HEX = re.compile(r'[0-9A-Fa-f]*\Z')
DECIMAL = re.compile(r'(?:0|[1-9][0-9]*)\Z')
TIME = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z\Z')
HEADER_FIELDS = {'version','chain_id','height','time','last_block_id','last_commit_hash',
    'data_hash','validators_hash','next_validators_hash','consensus_hash','app_hash',
    'last_results_hash','evidence_hash','proposer_address'}


class VerificationError(ValueError):
    pass


def ensure(condition: bool, message: str):
    if not condition:
        raise VerificationError(message)


def exact(value: Any, keys: set[str], label: str):
    ensure(type(value) is dict and set(value) == keys, 'invalid '+label+' fields')


def number(value: Any, *, maximum: int = 2**63-1, minimum: int = 0) -> int:
    if type(value) is str:
        ensure(len(value) <= 20 and DECIMAL.fullmatch(value) is not None, 'invalid decimal integer')
        value = int(value)
    ensure(type(value) is int and minimum <= value <= maximum, 'integer out of bounds')
    return value


def hexbytes(value: Any, size: int, *, empty: bool = False) -> bytes:
    ensure(type(value) is str and HEX.fullmatch(value) is not None, 'invalid hex')
    ensure(len(value) == 2*size or (empty and value == ''), 'invalid hex length')
    return bytes.fromhex(value)


def b64(value: Any, size: int | None = None, *, max_size: int = MAX_TX_BYTES) -> bytes:
    ensure(type(value) is str and len(value) <= 4*((max_size+2)//3), 'invalid base64 size')
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise VerificationError('invalid base64') from exc
    ensure(base64.b64encode(raw).decode() == value, 'noncanonical base64')
    ensure(len(raw) <= max_size and (size is None or len(raw) == size), 'invalid decoded length')
    return raw


def encode(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                          allow_nan=False).encode('ascii')
    except (ValueError, TypeError, RecursionError) as exc:
        raise VerificationError('invalid JSON value') from exc


def load_json(raw: bytes, *, max_bytes: int = MAX_PACKET_BYTES) -> Any:
    ensure(type(raw) is bytes and len(raw) <= max_bytes, 'JSON exceeds verification bound')
    def pairs(items):
        out = {}
        for k,v in items:
            ensure(k not in out, 'duplicate JSON key')
            out[k] = v
        return out
    def no_float(_):
        raise VerificationError('non-integer JSON number')
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_float=no_float, parse_constant=no_float)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise VerificationError('invalid verification JSON') from exc


def sha(raw: bytes) -> bytes:
    return hashlib.sha256(raw).digest()


def merkle_root(leaves: list[bytes]) -> bytes:
    """CometBFT HashFromByteSlices: RFC-6962 domain separation and split rule."""
    if not leaves:
        return sha(b'')
    if len(leaves) == 1:
        return sha(b'\x00'+leaves[0])
    split = 1 << ((len(leaves)-1).bit_length()-1)
    return sha(b'\x01'+merkle_root(leaves[:split])+merkle_root(leaves[split:]))


# Independent schema, not the application-side ABCI schema. Google's protobuf
# implementation serializes the fields; cryptography verifies Ed25519 signatures.
D = descriptor_pb2.FieldDescriptorProto
fd = descriptor_pb2.FileDescriptorProto(name='etn_commit_verifier.proto', package='etn.verify', syntax='proto3')
fd.dependency.append('google/protobuf/timestamp.proto')
schema = {
    'PartSet': [('total',1,D.TYPE_UINT32), ('hash',2,D.TYPE_BYTES)],
    'BlockID': [('hash',1,D.TYPE_BYTES), ('part_set_header',2,'PartSet')],
    'Vote': [('type',1,D.TYPE_INT32), ('height',2,D.TYPE_SFIXED64), ('round',3,D.TYPE_SFIXED64),
             ('block_id',4,'BlockID'), ('timestamp',5,'.google.protobuf.Timestamp'), ('chain_id',6,D.TYPE_STRING)],
    'Version': [('block',1,D.TYPE_UINT64), ('app',2,D.TYPE_UINT64)],
    'PublicKey': [('ed25519',1,D.TYPE_BYTES)],
    'SimpleValidator': [('pub_key',1,'PublicKey'), ('voting_power',2,D.TYPE_INT64)],
    'StringValue': [('value',1,D.TYPE_STRING)],
    'Int64Value': [('value',1,D.TYPE_INT64)],
    'BytesValue': [('value',1,D.TYPE_BYTES)],
}
for name, fields in schema.items():
    msg = fd.message_type.add(name=name)
    for name_, num, kind in fields:
        f = msg.field.add(name=name_,number=num,label=D.LABEL_OPTIONAL)
        if isinstance(kind,str):
            f.type = D.TYPE_MESSAGE; f.type_name = kind if kind.startswith('.') else '.etn.verify.'+kind
        else:
            f.type = kind
pool = descriptor_pool.DescriptorPool()
pool.AddSerializedFile(timestamp_pb2.DESCRIPTOR.serialized_pb);pool.Add(fd)
MESSAGES = {n:message_factory.GetMessageClass(pool.FindMessageTypeByName('etn.verify.'+n)) for n in schema}


def timestamp(value: Any):
    ensure(type(value) is str and TIME.fullmatch(value) is not None, 'timestamp must be UTC RFC3339 with <=9 fractional digits')
    stamp = timestamp_pb2.Timestamp()
    try:
        stamp.FromJsonString(value)
    except (ValueError, OverflowError) as exc:
        raise VerificationError('invalid timestamp') from exc
    return stamp


def block_id(value: Any, *, allow_empty: bool = False):
    exact(value, {'hash','parts'}, 'block ID')
    exact(value['parts'], {'total','hash'}, 'part-set')
    h = hexbytes(value['hash'],32,empty=allow_empty)
    count = number(value['parts']['total'],maximum=2**32-1)
    part_hash = hexbytes(value['parts']['hash'],32,empty=allow_empty)
    ensure((bool(h) and count > 0 and bool(part_hash)) or
           (allow_empty and not h and count == 0 and not part_hash), 'inconsistent block ID')
    msg = MESSAGES['BlockID'](hash=h)
    # gogoproto's non-nullable part_set_header is emitted even when empty.
    msg.part_set_header.SetInParent()
    msg.part_set_header.total = count; msg.part_set_header.hash = part_hash
    return msg


def delimiter(length: int) -> bytes:
    out = bytearray()
    while length >= 128:
        out.append((length & 127) | 128); length >>= 7
    return bytes(out)+bytes([length])


def vote_sign_bytes(chain_id: str, height: int, round_: int, block: dict | None,
                    time: str, *, vote_type: int = 2) -> bytes:
    """Canonical, length-delimited vote. Other vote types only support golden tests."""
    ensure(type(chain_id) is str and len(chain_id.encode('utf8')) <= 50, 'invalid chain ID')
    ensure(type(vote_type) is int and vote_type in (0,1,2), 'invalid vote type')
    msg = MESSAGES['Vote'](type=vote_type, height=number(height),
                           round=number(round_,maximum=2**31-1), chain_id=chain_id)
    t = timestamp(time);msg.timestamp.seconds=t.seconds;msg.timestamp.nanos=t.nanos
    msg.timestamp.SetInParent()  # required for time.Unix(0,0), too
    if block is not None:
        msg.block_id.CopyFrom(block_id(block))
    raw = msg.SerializeToString(deterministic=True)
    return delimiter(len(raw))+raw


def header_hash(header: Any) -> bytes:
    exact(header,HEADER_FIELDS,'header')
    exact(header['version'],{'block','app'},'header version')
    ensure(type(header['chain_id']) is str and 0 < len(header['chain_id'].encode()) <= 50, 'invalid header chain')
    h = number(header['height'], minimum=1)
    v = MESSAGES['Version'](block=number(header['version']['block'],maximum=2**64-1),
                            app=number(header['version']['app'],maximum=2**64-1))
    last = block_id(header['last_block_id'],allow_empty=(h==1))
    if h == 1:
        ensure(not last.hash,'first header has a previous block')
    leaves = [v.SerializeToString(),
        MESSAGES['StringValue'](value=header['chain_id']).SerializeToString(),
        MESSAGES['Int64Value'](value=h).SerializeToString(),
        timestamp(header['time']).SerializeToString(),last.SerializeToString()]
    for key in ('last_commit_hash','data_hash','validators_hash','next_validators_hash',
                'consensus_hash','app_hash','last_results_hash','evidence_hash','proposer_address'):
        size = 20 if key == 'proposer_address' else 32
        # This verifier intentionally only supports our 32-byte application hashes.
        raw = hexbytes(header[key],size,empty=key in ('last_commit_hash','data_hash','last_results_hash','evidence_hash'))
        leaves.append(MESSAGES['BytesValue'](value=raw).SerializeToString())
    return merkle_root(leaves)


@dataclass(frozen=True)
class Validator:
    address: bytes
    public_key: bytes
    power: int

    def encoded(self) -> bytes:
        msg = MESSAGES['SimpleValidator'](voting_power=self.power)
        msg.pub_key.ed25519 = self.public_key
        return msg.SerializeToString()


@dataclass(frozen=True)
class TrustAnchor:
    chain_id: str
    validators: tuple[Validator, ...]
    validators_hash: bytes
    native_genesis_hash: str
    total_power: int


def trust_from_genesis(genesis: Any) -> TrustAnchor:
    ensure(type(genesis) is dict,'invalid engine genesis')
    ensure(number(genesis.get('initial_height','1'),minimum=1)==1,'only initial height 1 supported')
    chain = genesis.get('chain_id')
    ensure(type(chain) is str and 0<len(chain.encode())<=50,'invalid genesis chain')
    vals = genesis.get('validators');native=genesis.get('app_state')
    ensure(type(vals) is list and 0<len(vals)<=MAX_VALIDATORS,'invalid validator count')
    ensure(type(native) is dict and native.get('chain_id')==chain,'application/engine genesis mismatch')
    version = native.get('protocol_version', 1)
    ensure(type(version) is int and version in (1, 2, 3),
           'static trust anchor refuses dynamic protocol')
    seen = set();ordered=[]
    for val in vals:
        ensure(type(val) is dict,'invalid validator')
        pk = val.get('pub_key');exact(pk,{'type','value'},'public key')
        ensure(pk['type']=='tendermint/PubKeyEd25519','unsupported validator key type')
        raw=b64(pk['value'],32,max_size=32);addr=sha(raw)[:20]
        ensure(val.get('address') is not None and hexbytes(val['address'],20)==addr,'validator address/key mismatch')
        ensure(addr not in seen,'duplicate validator');seen.add(addr)
        ordered.append(Validator(addr,raw,number(val.get('power'),minimum=1,maximum=MAX_POWER)))
    ordered.sort(key=lambda v:(-v.power,v.address))
    total=sum(v.power for v in ordered);ensure(total<=MAX_POWER,'total voting power overflow')
    return TrustAnchor(chain,tuple(ordered),merkle_root([v.encoded() for v in ordered]),sha(encode(native)).hex(),total)


def pinned_genesis(raw: bytes, expected_sha256: str) -> TrustAnchor:
    expected=hexbytes(expected_sha256,32)
    ensure(sha(raw)==expected,'trusted genesis file digest mismatch')
    return trust_from_genesis(load_json(raw,max_bytes=1024*1024))


def verify_signed_header(value: Any, trust: TrustAnchor, *, expected_height: int | None = None) -> dict:
    exact(value,{'header','commit'},'signed header')
    header=value['header'];computed=header_hash(header)
    height=number(header['height'],minimum=1)
    ensure(header['chain_id']==trust.chain_id,'wrong chain')
    if expected_height is not None:
        ensure(height==number(expected_height,minimum=1),'unexpected certificate height')
    ensure(hexbytes(header['validators_hash'],32)==trust.validators_hash,'untrusted validator set')
    ensure(hexbytes(header['next_validators_hash'],32)==trust.validators_hash,'validator changes unsupported')
    ensure(hexbytes(header['proposer_address'],20) in {v.address for v in trust.validators},'unknown proposer')
    commit=value['commit'];exact(commit,{'height','round','block_id','signatures'},'commit')
    ensure(number(commit['height'],minimum=1)==height,'commit/header height mismatch')
    r=number(commit['round'],maximum=2**31-1);bid=block_id(commit['block_id'])
    ensure(bid.hash==computed,'header/commit hash mismatch')
    sigs=commit['signatures'];ensure(type(sigs) is list and len(sigs)==len(trust.validators),'wrong signature slot count')
    signed=0;signers=[]
    for val, sig in zip(trust.validators,sigs):
        exact(sig,{'block_id_flag','validator_address','timestamp','signature'},'commit signature')
        flag=number(sig['block_id_flag'],minimum=1,maximum=3)
        if flag == 1:  # absent
            ensure(sig['validator_address']=='' and sig['signature'] in ('',None),'nonempty absent signature')
            t=timestamp(sig['timestamp'])
            ensure(t.seconds==-62135596800 and t.nanos==0,'nonzero absent timestamp')
            continue
        ensure(hexbytes(sig['validator_address'],20)==val.address,'signature slot/address mismatch')
        raw=b64(sig['signature'],64,max_size=64)
        signed_bytes=vote_sign_bytes(trust.chain_id,height,r,commit['block_id'] if flag==2 else None,sig['timestamp'])
        try:
            Ed25519PublicKey.from_public_bytes(val.public_key).verify(raw,signed_bytes)
        except InvalidSignature as exc:
            raise VerificationError('invalid validator signature') from exc
        if flag == 2:
            signed+=val.power;signers.append(val.address.hex().upper())
    ensure(signed*3>trust.total_power*2,'insufficient committing voting power')
    return {'height':height,'block_hash':computed.hex().upper(),
            'app_hash':header['app_hash'].lower(),'signed_power':signed,'total_power':trust.total_power,
            'signers':signers,'freshness':'not established','validator_mode':'static genesis Ed25519'}


def verify_block_transactions(block_result: Any, signed_header: Any, trust: TrustAnchor,
                              *, expected_tx: bytes | None = None) -> dict:
    cert=verify_signed_header(signed_header,trust)
    ensure(type(block_result) is dict and type(block_result.get('block')) is dict,'invalid block response')
    block=block_result['block']
    ensure(header_hash(block.get('header')).hex().upper()==cert['block_hash'],'block/header mismatch')
    ensure(block_id(block_result.get('block_id')).SerializeToString()==
           block_id(signed_header['commit']['block_id']).SerializeToString(),'block ID mismatch')
    data=block.get('data');exact(data,{'txs'},'block data')
    txs=data['txs'];txs=[] if txs is None else txs
    ensure(type(txs) is list and len(txs)<=MAX_TXS,'transaction-list bound exceeded')
    decoded=[b64(tx,max_size=MAX_TX_BYTES) for tx in txs]
    ensure(merkle_root([sha(tx) for tx in decoded])==hexbytes(block['header']['data_hash'],32),'transaction data hash mismatch')
    if expected_tx is not None:
        ensure(type(expected_tx) is bytes and decoded.count(expected_tx)==1,'expected transaction not included exactly once')
    return {**cert,'transaction_count':len(decoded),
            'transaction_hashes':[sha(tx).hex().upper() for tx in decoded],
            'claim':'transaction inclusion; not execution success by itself'}


def verify_state_witness(state: Any, signed_header: Any, trust: TrustAnchor) -> dict:
    """ABCI result at h is anchored by the signed header at h+1, not h."""
    exact(state,{'genesis','height','app_hash','native'},'state witness')
    height=number(state['height']);ensure(type(state['height']) is int,'state height must be a JSON integer')
    cert=verify_signed_header(signed_header,trust,expected_height=height+1)
    genesis_hash=sha(encode(state['genesis'])).hex()
    ensure(genesis_hash==trust.native_genesis_hash,'state genesis mismatch')
    version = state['genesis'].get('protocol_version', 1)
    ensure(type(version) is int and version in (1, 2, 3), 'unsupported native snapshot version')
    tables = {'meta','accounts','grants','receipts'} | ({'budgets','grant_budgets'} if version == 3 else set())
    native=state['native'];exact(native,tables,'native snapshot')
    from state_tree import enabled, StateTree, bind_root
    if enabled(state['genesis']):
        computed=bind_root(genesis_hash,height,StateTree(native).root)
    else:
        material={'domain':'ETERNITIES/ABCI-STATE/v1','genesis':genesis_hash,'height':height,'native':native}
        computed=sha(encode(material)).hex()
    ensure(hexbytes(state['app_hash'],32).hex()==computed,'state witness hash mismatch')
    ensure(cert['app_hash']==computed,'state not committed by this header')
    return {**cert,'state_height':height,'state_app_hash':computed,
            'claim':'full-state commitment under pinned static validator trust; not a balance Merkle proof'}


def verify_native_signatures(envelope: Any, signer_public_key: Any, *, protocol_version: int) -> bool:
    """Independently check transaction signatures and v2 incoming-key consent.

    Does not reexecute balances, nonces or delegation history. Those remain
    claims of the quorum-attested state. Returns whether a second key consent
    signature was required and verified.
    """
    exact(envelope, {'body', 'signature'}, 'native envelope')
    body = envelope['body']
    ensure(type(body) is dict, 'invalid native body')
    ensure(type(protocol_version) is int and protocol_version in (1, 2, 3), 'unsupported native protocol')
    ensure(type(body.get('version')) is int and body['version'] == protocol_version,
           'receipt protocol/genesis mismatch')
    try:
        Ed25519PublicKey.from_public_bytes(hexbytes(signer_public_key, 32)).verify(
            hexbytes(envelope['signature'], 64), b'ETERNITIES/NATIVE-LAB/v1\x00' + encode(body))
    except InvalidSignature as exc:
        raise VerificationError('invalid native receipt signature') from exc
    op = body.get('op')
    ensure(type(op) is dict, 'invalid native operation')
    if protocol_version not in (2, 3) or op.get('type') not in ('open_account', 'rotate_key'):
        return False
    exact(body, {'version','chain_id','genesis_hash','sender','nonce','op',
                 'grant_id','valid_until','max_fee'}, 'account-key body')
    ensure(body['grant_id'] == '', 'delegated key change forbidden')
    fields = {'type','public_key','acceptance'}
    if op['type'] == 'open_account':
        fields.add('units')
        ensure(type(op.get('units')) is int and 1 <= op['units'] <= 2**53-1,
               'invalid account funding')
    exact(op, fields, 'account-key operation')
    payload = dict(body); payload['op'] = {k:v for k,v in op.items() if k != 'acceptance'}
    try:
        Ed25519PublicKey.from_public_bytes(hexbytes(op['public_key'], 32)).verify(
            hexbytes(op['acceptance'], 64), b'ETERNITIES/ACCOUNT-KEY-CONSENT/v2\x00' + encode(payload))
    except InvalidSignature as exc:
        raise VerificationError('invalid incoming-key consent signature') from exc
    return True


def verify_packet(packet: Any, trust: TrustAnchor, *, expected_txids: list[str] | None = None) -> dict:
    exact(packet,{'schema','state','state_commit','transactions'},'certificate packet')
    ensure(type(packet['schema']) is int and packet['schema']==1,'unsupported packet version')
    state_cert=verify_state_witness(packet['state'],packet['state_commit'],trust)
    transactions=packet['transactions'];ensure(type(transactions) is list and len(transactions)<=64,'too many transaction witnesses')
    receipts=packet['state']['native']['receipts'];ensure(type(receipts) is list,'invalid receipts')
    receipt_index={}
    for row in receipts:
        ensure(type(row) is list and len(row)==5 and type(row[0]) is str and row[0] not in receipt_index,'invalid receipt index')
        receipt_index[row[0]]=row
    proofs=[];seen=set()
    for item in transactions:
        exact(item,{'tx','block','commit'},'transaction witness')
        raw=b64(item['tx']);result=verify_block_transactions(item['block'],item['commit'],trust,expected_tx=raw)
        ensure(result['height']<=state_cert['state_height'],'transaction later than witnessed state')
        env=load_json(raw,max_bytes=MAX_TX_BYTES)
        exact(env,{'body','signature'},'native envelope')
        ensure(encode(env)==raw and type(env['body']) is dict,'noncanonical native transaction')
        txid=sha(b'ETERNITIES/NATIVE-LAB/v1\x00'+encode(env['body'])).hex()
        ensure(txid not in seen,'duplicate transaction witness');seen.add(txid)
        ensure(txid in receipt_index,'transaction not recorded as executed in witnessed state')
        row=receipt_index[txid]
        ensure(type(row[3]) is str and type(row[4]) is str,'invalid receipt storage types')
        record=load_json(row[3].encode(),max_bytes=MAX_TX_BYTES)
        ensure(type(record) is dict and record.get('txid')==txid and record.get('envelope')==env,'receipt/envelope mismatch')
        ensure(type(record.get('height')) is int and record['height']==result['height'],'receipt/block height mismatch')
        ensure(sha(encode(record)).hex()==row[4],'receipt digest mismatch')
        incoming_consent = verify_native_signatures(env, record.get('signer_public_key'),
            protocol_version=packet['state']['genesis'].get('protocol_version', 1))
        proofs.append({'native_txid':txid,'block_height':result['height'],'block_hash':result['block_hash'],
                       'incoming_key_consent_verified':incoming_consent,
                       'claim':'included and recorded as executed in the quorum-committed state'})
    if expected_txids is not None:
        ensure(type(expected_txids) is list and 0 < len(expected_txids) <= 64,'invalid requested transaction list')
        requested=[hexbytes(txid,32).hex() for txid in expected_txids]
        ensure(len(set(requested))==len(requested),'duplicate requested transaction')
        ensure(set(requested)==seen,'certificate does not match the requested transactions')
    return {'status':'verified','chain_id':trust.chain_id,'state':state_cert,'transactions':proofs,
            'requested_transactions_bound':expected_txids is not None,
            'scope':'static-set development certificate verification, not a general light client',
            'not_established':['live network execution provenance','freshness','independent validator operation',
                               'dynamic validator changes','public-network security','external settlement']}
