"""Protocol-faithful worker transport fixture.

This process never verifies Halo2 and is not cryptographic acceptance evidence.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import struct

from protocol5_encoding import PROFILE_MAGIC

KAT_DOMAIN = b"1soft/shielded-kat/v1\0"

def kat_bytes(fields, proof=b"GGGG"):
    return (
        b"1SFTKAT1" + struct.pack("<H", 1) + b"".join(fields)
        + struct.pack("<I", len(proof)) + proof + b"\0"
        + struct.pack("<I", 0) + b"\1"
    )

def profile_bytes(kat, proof_length=4):
    hashes = [bytes([i]) * 32 for i in range(1, 10)]
    hashes[6] = hashlib.sha256(KAT_DOMAIN + kat).digest()
    circuit = b"1soft/shielded-consensus/halo2-pasta/v1"
    return (
        PROFILE_MAGIC + struct.pack(
            "<HHIHHHIH", 1, 1, 1, 13, 4, 14, proof_length, len(circuit))
        + circuit + b"".join(hashes)
    )

def worker_source(profile, mode="normal"):
    encoded = base64.b64encode(profile).decode("ascii")
    return f'''#!/usr/bin/env python3
import base64, hashlib, struct, sys, time
MOD=int("40000000000000000000000000000000224698fc094cf91b992d30ed00000001",16)
PROFILE=base64.b64decode("{encoded}")
MODE="{mode}"
def exact(n):
    out=b""
    while len(out)<n:
        piece=sys.stdin.buffer.read(n-len(out))
        if not piece: raise EOFError
        out+=piece
    return out
def field(data):
    return (int.from_bytes(hashlib.sha256(data).digest(),"little")%MOD).to_bytes(32,"little")
handled=0
while True:
    if MODE=="stall_after_startup" and handled==3:
        time.sleep(3600)
    try: size=struct.unpack("<I",exact(4))[0]
    except EOFError: break
    request=exact(size)
    magic=request[:8]
    version,opcode,rid=struct.unpack_from("<HHQ",request,8)
    pid=request[20:52]
    plen=struct.unpack_from("<I",request,52)[0]
    payload=request[56:]
    status=0; response=b""
    if magic!=b"1SFTVRQ1" or plen!=len(payload): status=65535
    elif opcode==1: response=PROFILE
    elif opcode==2:
        count=struct.unpack_from("<H",payload,0)[0]
        response=field(b"tree"+payload[:2+count*32])
    elif opcode==4:
        proof_len=struct.unpack_from("<I",payload,448)[0]
        proof=payload[452:]
        status=0 if proof_len==len(proof) and proof and proof==b"G"*len(proof) else 2
    elif opcode==3:
        count=struct.unpack_from("<H",payload,0)[0]
        off=2+count*32
        proof_len=struct.unpack_from("<I",payload,off+448)[0]
        proof=payload[off+452:]
        if proof_len!=len(proof) or not proof or proof!=b"G"*len(proof): status=2
        else:
            before=field(b"tree"+payload[:2+count*32])
            commitments=payload[2:2+count*32]+payload[off+10*32:off+12*32]
            after=field(b"tree"+struct.pack("<H",count+2)+commitments)
            response=before+after+struct.pack("<HH",count,count+1)
    else: status=65535
    if MODE=="wrong_id": rid+=1
    if MODE=="internal": status=65535
    body=b"1SFTVRS1"+struct.pack("<HHQ",1,opcode,rid)+pid+struct.pack("<HI",status,len(response))+response
    sys.stdout.buffer.write(struct.pack("<I",len(body))+body); sys.stdout.buffer.flush()
    handled+=1
'''

def write_worker(path: Path, profile: bytes, mode="normal") -> None:
    path.write_text(worker_source(profile, mode), encoding="ascii")
    path.chmod(0o700)
