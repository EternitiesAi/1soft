"""Explicit v3 encrypted transport for the unchanged complete v2 row stream.

Independent bounded zlib chunks save backup bytes. Raw fallback preserves
incompressible inputs. Decoded bytes retain the original v2 manifest/snapshot
identity and recovery-only archive; no source journal or authority changes.
"""
import hashlib
import secrets
import struct
import zlib

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from block_application import encode
from commit_verifier import exact, load_json
from offline_signer import _password
from p4_evidence import integer, need
from p4_custody import KDF
import p4_custody_stream as stream

MAGIC = b'1SOFTP4B3\n'
FORMAT = '1soft/p4-recovery-backup/v3'
CHUNK_BYTES = stream.CHUNK_BYTES
HEADER_BYTES = stream.HEADER_BYTES
MAX_CHUNKS = stream.MAX_CHUNKS
MAX_STREAM_BYTES = stream.MAX_STREAM_BYTES
# Codec and original length add five bytes to each data/final frame. Neither
# the admitted source bytes nor the reconstructed stream/archive cap increases.
MAX_BACKUP_BYTES = stream.MAX_BACKUP_BYTES+5*(MAX_CHUNKS+1)
RAW = 0
ZLIB = 1
LEVEL = 6
WINDOW_BITS = 15


def encode_chunk(raw):
    need(type(raw) is bytes and 0<len(raw)<=CHUNK_BYTES, 'invalid plaintext chunk')
    encoded = zlib.compress(raw, level=LEVEL, wbits=WINDOW_BITS)
    return (ZLIB, encoded) if len(encoded)<len(raw) else (RAW, raw)


def decode_chunk(codec, encoded, size):
    integer(size, 1, CHUNK_BYTES)
    need(type(codec) is int and codec in (RAW,ZLIB), 'unsupported chunk codec')
    need(type(encoded) is bytes and 0<len(encoded)<=size, 'encoded chunk length differs')
    if codec == RAW:
        need(len(encoded)==size, 'raw chunk length differs')
        return encoded
    need(len(encoded)<size, 'compressed chunk is not smaller')
    # Only ordinary 32KiB-window zlib-wrapped DEFLATE; no preset dictionaries.
    need(len(encoded)>=2 and encoded[0]==0x78 and not encoded[1]&0x20 and
         int.from_bytes(encoded[:2],'big')%31==0, 'unsupported compressed stream header')
    try:
        decoder = zlib.decompressobj(wbits=WINDOW_BITS)
        raw = decoder.decompress(encoded, max_length=size+1)
    except zlib.error as exc:
        raise ValueError('unable to decompress bounded chunk') from exc
    need(len(raw)==size, 'decompressed output length differs')
    need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
         'compressed stream EOF or tail differs')
    return raw


def _aad(header, kind, index, codec, size, encoded_size):
    return MAGIC+header+kind+struct.pack('>IBII',index,codec,size,encoded_size)


def sealed_parts(pair,password,result):
    _password(password)
    salt = secrets.token_bytes(32); prefix = secrets.token_bytes(8)
    h = {'schema':3,'format':FORMAT,'kdf':KDF.copy(),'cipher':'aes-256-gcm',
         'salt':salt.hex(),'nonce_prefix':prefix.hex(),'chunk_bytes':CHUNK_BYTES,
         'codec':'zlib','compression_level':LEVEL,'window_bits':WINDOW_BITS}
    header = encode(h); need(len(header)<=HEADER_BYTES,'backup header exceeds bound')
    key = Scrypt(salt=salt,length=32,n=32768,r=8,p=1).derive(password)
    cipher = AESGCM(key)
    yield MAGIC+struct.pack('>I',len(header))+header
    digest = hashlib.sha256(); total = 0; index = 0; counts = {}
    for raw in stream.plain_chunks(pair,counts):
        need(index<MAX_CHUNKS,'backup chunk count exceeds bound')
        digest.update(raw); total += len(raw)
        need(total<=MAX_STREAM_BYTES,'backup stream exceeds bound')
        codec, encoded = encode_chunk(raw)
        ct = cipher.encrypt(prefix+struct.pack('>I',index),encoded,
                            _aad(header,b'D',index,codec,len(raw),len(encoded)))
        yield struct.pack('>cBII',b'D',codec,len(raw),len(ct))+ct
        index += 1
    manifest = {'schema':2,'chunks':index,'stream_bytes':total,
                'stream_sha256':digest.hexdigest(),**counts}
    raw = encode(manifest); need(len(raw)<=HEADER_BYTES,'backup manifest exceeds bound')
    ct = cipher.encrypt(prefix+struct.pack('>I',index),raw,
                        _aad(header,b'F',index,RAW,len(raw),len(raw)))
    yield struct.pack('>cBII',b'F',RAW,len(raw),len(ct))+ct
    result['snapshot_id'] = stream.snapshot_id(manifest)
    result['manifest'] = manifest


def unseal(source,password):
    _password(password); encrypted_bytes = 0
    def read(n):
        nonlocal encrypted_bytes
        need(0<n<=CHUNK_BYTES+16,'encrypted read exceeds frame bound')
        encrypted_bytes += n
        need(encrypted_bytes<=MAX_BACKUP_BYTES,'encrypted backup exceeds bound')
        raw = source.read(n); need(len(raw)==n,'truncated encrypted backup')
        return raw
    need(read(len(MAGIC))==MAGIC,'unsupported backup format')
    n = struct.unpack('>I',read(4))[0]
    need(0<n<=HEADER_BYTES,'backup header exceeds bound')
    header = read(n); h = load_json(header,max_bytes=HEADER_BYTES)
    exact(h,{'schema','format','kdf','cipher','salt','nonce_prefix','chunk_bytes',
             'codec','compression_level','window_bits'},'backup v3 header')
    need(encode(h)==header and type(h['schema']) is int and h['schema']==3 and
         h['format']==FORMAT and h['cipher']=='aes-256-gcm' and
         encode(h['kdf'])==encode(KDF) and h['codec']=='zlib' and
         type(h['chunk_bytes']) is int and h['chunk_bytes']==CHUNK_BYTES and
         type(h['compression_level']) is int and h['compression_level']==LEVEL and
         type(h['window_bits']) is int and h['window_bits']==WINDOW_BITS,
         'unsupported backup parameters')
    for field,size in (('salt',32),('nonce_prefix',8)):
        value = h[field]
        need(type(value) is str and len(value)==2*size,'invalid encryption metadata')
        try: raw = bytes.fromhex(value)
        except ValueError as exc: raise ValueError('invalid encryption metadata') from exc
        need(raw.hex()==value,'noncanonical encryption metadata')
    key = Scrypt(salt=bytes.fromhex(h['salt']),length=32,n=32768,r=8,p=1).derive(password)
    cipher = AESGCM(key); prefix = bytes.fromhex(h['nonce_prefix'])
    chunks = []; total = 0; digest = hashlib.sha256()
    while True:
        kind,codec,size,n = struct.unpack('>cBII',read(10))
        need(kind in (b'D',b'F'),'invalid backup frame')
        limit = CHUNK_BYTES if kind==b'D' else HEADER_BYTES
        need(0<size<=limit and 16<n<=size+16,'backup frame length exceeds bound')
        need(codec in (RAW,ZLIB) and (kind!=b'F' or codec==RAW),'unsupported frame codec')
        need(n-16==size if codec==RAW else n-16<size,'encoded frame length differs')
        index = len(chunks)
        if kind==b'D':
            need(index<MAX_CHUNKS and total+size<=MAX_STREAM_BYTES,'backup stream exceeds bound')
            need(not chunks or len(chunks[-1])==CHUNK_BYTES,'nonfinal chunk length differs')
        try:
            encoded = cipher.decrypt(prefix+struct.pack('>I',index),read(n),
                                     _aad(header,kind,index,codec,size,n-16))
        except InvalidTag as exc: raise ValueError('unable to authenticate backup') from exc
        if kind==b'F':
            need(len(encoded)==size,'final manifest length differs')
            manifest = load_json(encoded,max_bytes=HEADER_BYTES)
            exact(manifest,{'schema','chunks','stream_bytes','stream_sha256','row_counts','blob_bytes'},
                  'backup manifest')
            need(encode(manifest)==encoded and not source.read(1),'backup manifest encoding or EOF differs')
            break
        raw = decode_chunk(codec,encoded,size)
        chunks.append(raw); total += len(raw); digest.update(raw)
    need(type(manifest['schema']) is int and manifest['schema']==2 and
         type(manifest['chunks']) is int and manifest['chunks']==len(chunks) and
         type(manifest['stream_bytes']) is int and manifest['stream_bytes']==total and
         manifest['stream_sha256']==digest.hexdigest(),'backup final commitment differs')
    with stream.stream_pair(chunks) as pair:
        need(encode({k:manifest[k] for k in ('row_counts','blob_bytes')})==encode(pair[3]),
             'backup row manifest differs')
    return tuple(chunks),manifest
