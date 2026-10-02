"""Version-2 bounded row stream. It never creates an active on-disk journal.

Encryption buffers one chunk; the unchanged historical auditors still retain
bounded journal/proof data in memory. This is not a constant-RAM audit claim.
"""
from contextlib import contextmanager, closing
import hashlib
import secrets
import sqlite3
import struct
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from block_application import encode
from commit_verifier import exact, load_json
from offline_signer import _password
from p4_evidence import MAX_GENESIS_BYTES, MAX_EVIDENCE_BYTES, integer, need, policy_checked
from p4_wallet import MAX_PAYLOAD, MAX_DECISIONS, pending
from p4_delivery import MAX_ATTEMPTS, MAX_RECEIPT_BYTES
from p4_custody import (WALLET_SCHEMA, DELIVERY_SCHEMA, WALLET_ID, DELIVERY_ID,
                       ARCHIVE_ID, KDF, _WalletAudit, _DeliveryAudit)

MAGIC = b'1SOFTP4B2\n'
FORMAT = '1soft/p4-recovery-backup/v2'
SNAPSHOT_FORMAT = '1soft/p4-journal-snapshot/v2'
CHUNK_BYTES = 1024*1024
HEADER_BYTES = 4096
META_BYTES = 8192
ROW_META_BYTES = 4096
TABLES = tuple((0, name, columns, limit) for name,(columns,limit) in WALLET_SCHEMA.items()) + tuple(
    (1, name, columns, limit) for name,(columns,limit) in DELIVERY_SCHEMA.items())
CELL_LIMITS = (4096, MAX_EVIDENCE_BYTES, 32768, 0, 16384, 4096, MAX_EVIDENCE_BYTES+4096)
TABLE_BYTE_LIMITS = (4096, MAX_PAYLOAD, min(MAX_PAYLOAD,MAX_DECISIONS*32768), 0,
                     MAX_ATTEMPTS*16384, MAX_ATTEMPTS*4096, MAX_RECEIPT_BYTES)
MAX_PAIR_BYTES = sum(TABLE_BYTE_LIMITS)
MAX_ROWS = sum(t[3] for t in TABLES)
MAX_STREAM_BYTES = MAX_PAIR_BYTES+MAX_GENESIS_BYTES+META_BYTES+MAX_ROWS*(ROW_META_BYTES+4)+len(TABLES)*9+32
MAX_CHUNKS = (MAX_STREAM_BYTES+CHUNK_BYTES-1)//CHUNK_BYTES
MAX_BACKUP_BYTES = len(MAGIC)+4+HEADER_BYTES+MAX_STREAM_BYTES+MAX_CHUNKS*21+HEADER_BYTES+21
# The writer fixes SQLite pages at4096. Allow up to two extra pages per chunk
# plus16 pages for the fixed schema/manifest, rather than a source admission cap.
MAX_ARCHIVE_BYTES = MAX_STREAM_BYTES+MAX_CHUNKS*8192+65536


def _create(schema, app_id):
    db = sqlite3.connect(':memory:', isolation_level=None)
    db.execute(f'PRAGMA application_id={app_id}')
    for name,(columns,_) in schema.items(): db.execute(f'CREATE TABLE {name}({columns})')
    return db


def blob_size(delivery):
    return sum(delivery.wallet.db.execute(f'SELECT coalesce(sum(length({col})),0) FROM {table}').fetchone()[0]
               if source==0 else delivery.db.execute(f'SELECT coalesce(sum(length({col})),0) FROM {table}').fetchone()[0]
               for source,table,col in ((0,'config','policy'),(0,'observations','payload'),
                    (0,'decisions','payload'),(1,'attempts','review'),(1,'responses','payload'),(1,'receipts','payload')))


@contextmanager
def capture_pair(delivery):
    wdb,ddb = _create(WALLET_SCHEMA,WALLET_ID),_create(DELIVERY_SCHEMA,DELIVERY_ID)
    try:
        wallet = delivery.wallet
        with wallet.atomic():
            with delivery.atomic():
                _,_,_,decisions,_ = wallet._load(historical=True)
                delivery._audit(decisions)
                for source,table,columns,limit in TABLES:
                    original = wallet.db if source==0 else delivery.db
                    target = wdb if source==0 else ddb
                    count = 0
                    for row in original.execute(f'SELECT * FROM {table} ORDER BY 1'):
                        count += 1; need(count<=limit,'journal row bound exceeded')
                        target.execute(f'INSERT INTO {table} VALUES ({",".join("?" for _ in row)})',row)
                meta = {'schema':2,'format':SNAPSHOT_FORMAT,'captured_ns':time.time_ns(),
                        'policy':wallet.policy,'genesis':wallet.genesis}
        # Capture releases original locks before encryption and publication.
        audit_pair(wdb,ddb,meta,wallet.genesis,wallet.policy,wallet.path)
        yield wdb,ddb,meta
    finally: wdb.close(); ddb.close()


def audit_pair(wdb,ddb,meta,genesis,policy,path):
    policy = policy_checked(policy)
    need(meta['genesis']==bytes(genesis) and encode(meta['policy'])==encode(policy),
         'externally selected genesis or policy differs')
    need(hashlib.sha256(bytes(genesis)).hexdigest()==policy['genesis_sha256'],'external genesis pin differs')
    wallet = _WalletAudit(wdb,path,genesis,policy)
    wid,evidence,report,decisions,last = wallet.load()
    delivery = _DeliveryAudit(ddb,wallet,wid)
    attempts,responses,receipts,dlast = delivery.audit(decisions)
    return dict(wallet_id=wid,delivery_id=delivery.config[2],policy_id=wallet.policy_id,
                report=report,decisions=decisions,held=pending(report,decisions),
                attempts=attempts,responses=responses,receipts=receipts,last_ns=max(last,dlast))


def _segments(wdb,ddb,meta,counts):
    public = {k:v for k,v in meta.items() if k!='genesis'}
    raw = encode(public); need(len(raw)<=META_BYTES,'snapshot metadata exceeds bound')
    genesis = meta['genesis']; need(0<len(genesis)<=MAX_GENESIS_BYTES,'genesis exceeds bound')
    yield struct.pack('>I',len(raw)); yield raw
    yield struct.pack('>I',len(genesis)); yield genesis
    counts.update(row_counts=[],blob_bytes=[])
    for index,(source,table,columns,limit) in enumerate(TABLES):
        db = wdb if source==0 else ddb
        count = db.execute(f'SELECT count(*) FROM {table}').fetchone()[0]
        need(count<=limit,'journal row bound exceeded')
        counts['row_counts'].append(count)
        yield b'T'+struct.pack('>II',index,count)
        total = 0
        for row in db.execute(f'SELECT * FROM {table} ORDER BY 1'):
            cells = []
            for v in row:
                need(type(v) in (int,str,bytes),'unsupported journal cell')
                if type(v) is bytes:
                    need(len(v)<=CELL_LIMITS[index],'journal BLOB exceeds cell bound')
                    total += len(v); need(total<=TABLE_BYTE_LIMITS[index],'journal BLOB table bound exceeded')
                    cells.append({'blob':len(v)})
                else: cells.append(v)
            raw = encode(cells); need(len(raw)<=ROW_META_BYTES,'journal row metadata exceeds bound')
            yield struct.pack('>I',len(raw)); yield raw
            for v in row:
                if type(v) is bytes: yield v
        counts['blob_bytes'].append(total)
    yield b'E'


def plain_chunks(pair,counts=None):
    buffer = bytearray(); total = 0
    for segment in _segments(*pair,{} if counts is None else counts):
        total += len(segment); need(total<=MAX_STREAM_BYTES,'complete row stream exceeds bound')
        part = memoryview(segment)
        while part:
            n = min(CHUNK_BYTES-len(buffer),len(part)); buffer.extend(part[:n]); part=part[n:]
            if len(buffer)==CHUNK_BYTES:
                yield bytes(buffer); buffer.clear()
    if buffer: yield bytes(buffer)


class _Reader:
    def __init__(self,chunks): self.chunks=iter(chunks); self.part=memoryview(b''); self.total=0
    def read(self,n):
        result=bytearray()
        while len(result)<n:
            if not self.part:
                try:
                    raw=next(self.chunks)
                    need(type(raw) is bytes and 0<len(raw)<=CHUNK_BYTES,'invalid snapshot chunk')
                    self.total+=len(raw);need(self.total<=MAX_STREAM_BYTES,'snapshot stream exceeds bound')
                    self.part=memoryview(raw)
                except StopIteration: break
            k=min(n-len(result),len(self.part));result.extend(self.part[:k]);self.part=self.part[k:]
        return bytes(result)
    def exact(self,n):
        raw=self.read(n);need(len(raw)==n,'truncated row stream');return raw
    def uint(self): return struct.unpack('>I',self.exact(4))[0]
    def json(self,limit):
        n=self.uint();need(0<n<=limit,'row metadata exceeds bound')
        raw=self.exact(n);v=load_json(raw,max_bytes=limit);need(encode(v)==raw,'row metadata encoding differs');return v


@contextmanager
def stream_pair(chunks):
    wdb,ddb=_create(WALLET_SCHEMA,WALLET_ID),_create(DELIVERY_SCHEMA,DELIVERY_ID)
    try:
        r=_Reader(chunks);meta=r.json(META_BYTES)
        exact(meta,{'schema','format','captured_ns','policy'},'stream snapshot metadata')
        need(type(meta['schema']) is int and meta['schema']==2 and meta['format']==SNAPSHOT_FORMAT,
             'unsupported snapshot stream version')
        integer(meta['captured_ns']);policy_checked(meta['policy'])
        size=r.uint();need(0<size<=MAX_GENESIS_BYTES,'genesis exceeds bound');meta['genesis']=r.exact(size)
        counts=[];sizes=[]
        for index,(source,table,columns,limit) in enumerate(TABLES):
            need(r.exact(1)==b'T' and r.uint()==index,'snapshot table order differs')
            count=r.uint();need(count<=limit,'journal row bound exceeded');counts.append(count)
            db=wdb if source==0 else ddb
            width=len(db.execute(f'PRAGMA table_info({table})').fetchall());total=0
            for _ in range(count):
                row=r.json(ROW_META_BYTES);need(type(row) is list and len(row)==width,'journal row shape differs')
                cells=[]
                for cell in row:
                    if type(cell) is dict:
                        exact(cell,{'blob'},'journal BLOB marker');n=integer(cell['blob'],0,CELL_LIMITS[index])
                        total+=n;need(total<=TABLE_BYTE_LIMITS[index],'journal BLOB table bound exceeded')
                        cells.append(r.exact(n))
                    else:
                        need(type(cell) in (int,str),'invalid journal cell type')
                        if type(cell) is int: integer(cell)
                        else: need(len(cell)<=4096,'journal text exceeds bound')
                        cells.append(cell)
                db.execute(f'INSERT INTO {table} VALUES ({",".join("?" for _ in cells)})',cells)
            sizes.append(total)
        need(r.exact(1)==b'E' and not r.read(1),'snapshot stream has trailing data')
        yield wdb,ddb,meta,{'row_counts':counts,'blob_bytes':sizes}
    except sqlite3.Error as exc: raise ValueError('invalid retained journal row stream') from exc
    finally:wdb.close();ddb.close()


def _manifest(chunks):
    digest=hashlib.sha256();n=0;total=0
    for raw in chunks: digest.update(raw);n+=1;total+=len(raw)
    return {'schema':2,'chunks':n,'stream_bytes':total,'stream_sha256':digest.hexdigest()}


def snapshot_id(manifest):
    return hashlib.sha256(b'1soft/p4-journal-snapshot/v2\0'+bytes.fromhex(manifest['stream_sha256'])).hexdigest()


def sealed_parts(pair,password,result):
    _password(password);salt=secrets.token_bytes(32);prefix=secrets.token_bytes(8)
    h={'schema':2,'format':FORMAT,'kdf':KDF.copy(),'cipher':'aes-256-gcm',
       'salt':salt.hex(),'nonce_prefix':prefix.hex(),'chunk_bytes':CHUNK_BYTES}
    header=encode(h);need(len(header)<=HEADER_BYTES,'backup header exceeds bound')
    key=Scrypt(salt=salt,length=32,n=32768,r=8,p=1).derive(password);cipher=AESGCM(key)
    yield MAGIC+struct.pack('>I',len(header))+header
    digest=hashlib.sha256();total=0;index=0
    counts={}
    for raw in plain_chunks(pair,counts):
        digest.update(raw);total+=len(raw)
        aad=MAGIC+header+b'D'+struct.pack('>II',index,len(raw))
        ct=cipher.encrypt(prefix+struct.pack('>I',index),raw,aad)
        yield b'D'+struct.pack('>I',len(ct))+ct
        index+=1;need(index<=MAX_CHUNKS,'backup chunk count exceeds bound')
    manifest={'schema':2,'chunks':index,'stream_bytes':total,'stream_sha256':digest.hexdigest(),**counts}
    raw=encode(manifest);need(len(raw)<=HEADER_BYTES,'backup manifest exceeds bound')
    aad=MAGIC+header+b'F'+struct.pack('>II',index,len(raw))
    ct=cipher.encrypt(prefix+struct.pack('>I',index),raw,aad)
    yield b'F'+struct.pack('>I',len(ct))+ct
    result['snapshot_id']=snapshot_id(manifest);result['manifest']=manifest


def unseal(source,password):
    _password(password)
    def read(n):
        raw=source.read(n);need(len(raw)==n,'truncated encrypted backup');return raw
    need(read(len(MAGIC))==MAGIC,'unsupported backup format')
    n=struct.unpack('>I',read(4))[0];need(0<n<=HEADER_BYTES,'backup header exceeds bound')
    header=read(n);h=load_json(header,max_bytes=HEADER_BYTES)
    exact(h,{'schema','format','kdf','cipher','salt','nonce_prefix','chunk_bytes'},'backup v2 header')
    need(encode(h)==header and type(h['schema']) is int and h['schema']==2 and h['format']==FORMAT
         and h['cipher']=='aes-256-gcm' and encode(h['kdf'])==encode(KDF)
         and type(h['chunk_bytes']) is int and h['chunk_bytes']==CHUNK_BYTES,'unsupported backup parameters')
    for field,size in (('salt',32),('nonce_prefix',8)):
        value=h[field];need(type(value) is str and len(value)==2*size,'invalid encryption metadata')
        try: raw=bytes.fromhex(value)
        except ValueError as exc:raise ValueError('invalid encryption metadata') from exc
        need(raw.hex()==value,'noncanonical encryption metadata')
    key=Scrypt(salt=bytes.fromhex(h['salt']),length=32,n=32768,r=8,p=1).derive(password)
    cipher=AESGCM(key);chunks=[];total=0;digest=hashlib.sha256()
    while True:
        kind=read(1);need(kind in (b'D',b'F'),'invalid backup frame')
        n=struct.unpack('>I',read(4))[0]
        limit=CHUNK_BYTES if kind==b'D' else HEADER_BYTES
        need(16<n<=limit+16,'backup frame exceeds bound')
        index=len(chunks);need(index<=MAX_CHUNKS,'backup chunk count exceeds bound')
        aad=MAGIC+header+kind+struct.pack('>II',index,n-16)
        try:raw=cipher.decrypt(bytes.fromhex(h['nonce_prefix'])+struct.pack('>I',index),read(n),aad)
        except InvalidTag as exc:raise ValueError('unable to authenticate backup') from exc
        if kind==b'F':
            manifest=load_json(raw,max_bytes=HEADER_BYTES)
            exact(manifest,{'schema','chunks','stream_bytes','stream_sha256','row_counts','blob_bytes'},'backup manifest')
            need(encode(manifest)==raw and not source.read(1),'backup manifest encoding or EOF differs')
            break
        need(not chunks or len(chunks[-1])==CHUNK_BYTES,'nonfinal chunk length differs')
        chunks.append(raw);total+=len(raw);digest.update(raw)
        need(len(chunks)<=MAX_CHUNKS and total<=MAX_STREAM_BYTES,'backup stream exceeds bound')
    need(type(manifest['schema']) is int and manifest['schema']==2 and
         type(manifest['chunks']) is int and manifest['chunks']==len(chunks) and
         type(manifest['stream_bytes']) is int and manifest['stream_bytes']==total and
         manifest['stream_sha256']==digest.hexdigest(),'backup final commitment differs')
    with stream_pair(chunks) as pair:
        need(encode({k:manifest[k] for k in ('row_counts','blob_bytes')})==encode(pair[3]),
             'backup row manifest differs')
    return tuple(chunks),manifest


def make_archive(chunks,manifest):
    with closing(sqlite3.connect(':memory:')) as db:
        db.execute('PRAGMA page_size=4096');db.execute(f'PRAGMA application_id={ARCHIVE_ID}')
        db.execute('CREATE TABLE recovery(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,snapshot_id TEXT NOT NULL,manifest BLOB NOT NULL)')
        db.execute('CREATE TABLE chunks(seq INTEGER PRIMARY KEY,payload BLOB NOT NULL)')
        db.execute('INSERT INTO recovery VALUES (1,2,?,?)',(snapshot_id(manifest),encode(manifest)))
        db.executemany('INSERT INTO chunks VALUES (?,?)',enumerate(chunks,1));db.commit()
        raw=db.serialize();need(len(raw)<=MAX_ARCHIVE_BYTES,'recovery archive exceeds bound');return raw


def archive_chunks(raw):
    with closing(sqlite3.connect(':memory:')) as db:
        db.deserialize(raw)
        need(db.execute('PRAGMA application_id').fetchone()[0]==ARCHIVE_ID,'not a recovery-only archive')
        objects=set(db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
        if objects=={('table','recovery')}:return None
        need(objects=={('table','recovery'),('table','chunks')} and db.execute('PRAGMA page_size').fetchone()[0]==4096,
             'unsupported recovery archive schema')
        for table,names in (('recovery',('id','version','snapshot_id','manifest')),('chunks',('seq','payload'))):
            need(tuple(r[1] for r in db.execute(f'PRAGMA table_info({table})'))==names,'recovery columns differ')
        rows=db.execute('SELECT * FROM recovery').fetchall()
        need(len(rows)==1 and rows[0][:2]==(1,2) and type(rows[0][3]) is bytes,'unsupported recovery archive version')
        manifest=load_json(rows[0][3],max_bytes=HEADER_BYTES)
        need(encode(manifest)==rows[0][3],'recovery manifest encoding differs')
        exact(manifest,{'schema','chunks','stream_bytes','stream_sha256','row_counts','blob_bytes'},'archive manifest')
        chunks=[];total=0
        for index,(seq,payload) in enumerate(db.execute('SELECT * FROM chunks ORDER BY seq'),1):
            need(type(seq) is int and seq==index and index<=MAX_CHUNKS and type(payload) is bytes
                 and 0<len(payload)<=CHUNK_BYTES,'invalid recovery chunk')
            need(not chunks or len(chunks[-1])==CHUNK_BYTES,'nonfinal chunk length differs')
            chunks.append(payload);total+=len(payload);need(total<=MAX_STREAM_BYTES,'recovery stream exceeds bound')
        actual=_manifest(chunks)
        need(all(type(manifest[k]) is type(v) and manifest[k]==v for k,v in actual.items())
             and rows[0][2]==snapshot_id(manifest),'recovery content changed')
        with stream_pair(chunks) as pair:
            need(encode(pair[3])==encode({k:manifest[k] for k in pair[3]}),'recovery row manifest differs')
        return tuple(chunks),rows[0][2]


def audit_chunks(chunks,genesis,policy,path):
    with stream_pair(chunks) as pair:return audit_pair(*pair[:3],genesis,policy,path)
