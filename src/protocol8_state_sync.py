"""Bounded P8 snapshots authenticated by the trusted engine's Offer AppHash.

Descriptor hashes detect corruption; they never provide consensus authority.
Full genesis and native replay are mandatory before atomic installation.
"""
from __future__ import annotations
from collections import OrderedDict
import hashlib
from protocol8_consensus import (canonical, closed_json, need, digest, hex32,
    bootstrap_digest, replay, application_hash, MAX_HEIGHT, MAX_STATE_BYTES, StateError)
from state_sync import (OFFER_ABORT, OFFER_ACCEPT, OFFER_REJECT, OFFER_REJECT_FORMAT,
    APPLY_ABORT, APPLY_ACCEPT, APPLY_REJECT_SNAPSHOT, APPLY_RETRY)

FORMAT = 8
DOMAIN = '1soft/protocol8-recipient-recovery/snapshot/v1'
HASH_DOMAIN = DOMAIN.encode()+b'\0'
CHUNK_BYTES = 4096
MAX_PAYLOAD_BYTES = MAX_STATE_BYTES+16384+4096
MAX_CHUNKS = (MAX_PAYLOAD_BYTES+CHUNK_BYTES-1)//CHUNK_BYTES
MAX_METADATA_BYTES = 4096
PAYLOAD_KEYS = {'genesis','height','app_hash','state'}
IDENTITY_KEYS = {'genesis_sha256','bootstrap_sha256','profile_sha256','worker_sha256','kat_sha256'}
METADATA_KEYS = IDENTITY_KEYS|{'domain','format','height','app_hash','payload_bytes','chunk_bytes','chunks','payload_sha256'}

def payload_hash(raw): return hashlib.sha256(HASH_DOMAIN+raw).digest()
def identities(app):
    return {'genesis_sha256':digest(app.expected), 'bootstrap_sha256':bootstrap_digest(app.g),
            **{k:app.g[k] for k in ('profile_sha256','worker_sha256','kat_sha256')}}

def validate_payload(raw, app, height, app_hash):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_PAYLOAD_BYTES, 'P8 snapshot payload bound')
    p = closed_json(raw, MAX_PAYLOAD_BYTES)
    need(type(p) is dict and set(p) == PAYLOAD_KEYS and type(p['height']) is int and
         1 <= p['height'] <= MAX_HEIGHT and p['height'] == height and
         p['app_hash'] == app_hash and canonical(p['genesis']) == app.expected,
         'P8 full snapshot genesis/checkpoint differs')
    hex32(app_hash)
    replay(app.g,p['state'],height,app.worker)
    need(application_hash(app.g,height,p['state']) == app_hash, 'P8 replayed snapshot AppHash differs')
    return p

def metadata(app, height, app_hash, raw):
    return canonical({**identities(app), 'domain':DOMAIN, 'format':FORMAT,
        'height':height,'app_hash':app_hash,'payload_bytes':len(raw),
        'chunk_bytes':CHUNK_BYTES,'chunks':(len(raw)+CHUNK_BYTES-1)//CHUNK_BYTES,
        'payload_sha256':payload_hash(raw).hex()})

def parse_metadata(raw, app):
    m = closed_json(raw,MAX_METADATA_BYTES)
    need(type(m) is dict and set(m) == METADATA_KEYS and m['domain'] == DOMAIN and
         type(m['format']) is int and m['format'] == FORMAT and
         {k:m[k] for k in IDENTITY_KEYS} == identities(app), 'P8 snapshot metadata identity differs')
    hex32(m['app_hash']); hex32(m['payload_sha256'])
    need(type(m['height']) is int and 1 <= m['height'] <= MAX_HEIGHT and
         type(m['payload_bytes']) is int and 0 < m['payload_bytes'] <= MAX_PAYLOAD_BYTES and
         type(m['chunk_bytes']) is int and m['chunk_bytes'] == CHUNK_BYTES and
         type(m['chunks']) is int and 1 <= m['chunks'] <= MAX_CHUNKS and
         (m['payload_bytes']+CHUNK_BYTES-1)//CHUNK_BYTES == m['chunks'], 'P8 snapshot geometry differs')
    return m

class StateSync:
    def __init__(self, app):
        self.app=app; self.served=OrderedDict(); self.offer_state=None; self.completed=None

    def checkpoint_only(self):
        a=self.app
        if a.closed or a.state is None or a.pending is not None or a.height <= 0: return False
        r=a.db.execute('SELECT height,app_hash,payload_sha256,payload FROM p8_snapshot_origin WHERE id=1').fetchone()
        c=a.db.execute('SELECT genesis,height,app_hash,state FROM p8_checkpoint WHERE id=1').fetchone()
        if r is None or c is None: return False
        raw=bytes(r[3])
        return (r[:2] == (a.height,a.app_hash) and r[2] == payload_hash(raw).hex() and
                bytes(c[0]) == a.expected and c[1:3] == (a.height,a.app_hash) and
                bytes(c[3]) == canonical(a.state) and
                raw == canonical({'genesis':a.g,'height':a.height,'app_hash':a.app_hash,'state':a.state}) and
                a.db.execute('SELECT 1 FROM p8_blocks LIMIT 1').fetchone() is None)

    def list(self):
        a=self.app
        with a.lock:
            need(not a.closed, 'P8 recovery application closed')
            if a.state is None or a.height <= 0: return []
            raw=canonical({'genesis':a.g,'height':a.height,'app_hash':a.app_hash,'state':a.state})
            if len(raw)>MAX_PAYLOAD_BYTES: return []
            m=metadata(a,a.height,a.app_hash,raw)
            d={'height':a.height,'format':FORMAT,'chunks':(len(raw)+CHUNK_BYTES-1)//CHUNK_BYTES,
               'hash':payload_hash(raw),'metadata':m}
            self.served[a.height]=(d,raw);self.served.move_to_end(a.height)
            while len(self.served)>2:self.served.popitem(last=False)
            return [dict(d)]

    def load(self,height,format_,index):
        a=self.app
        with a.lock:
            need(not a.closed, 'P8 recovery application closed')
            if not (type(height) is int and 1<=height<=MAX_HEIGHT and type(format_) is int and
                    format_==FORMAT and type(index) is int and 0<=index<MAX_CHUNKS):return b''
            if height not in self.served and a.height==height:self.list()
            found=self.served.get(height)
            if found is None or index>=found[0]['chunks']:return b''
            return found[1][index*CHUNK_BYTES:(index+1)*CHUNK_BYTES]

    def offer(self,snapshot,trusted_app_hash):
        a=self.app
        with a.lock:
            self.offer_state=None;self.completed=None
            if a.closed or a.pending is not None:return OFFER_ABORT
            checkpoint=self.checkpoint_only()
            if a.state is not None and not checkpoint:return OFFER_ABORT
            if type(snapshot) is not dict or set(snapshot)!={'height','format','chunks','hash','metadata'}:return OFFER_REJECT
            if type(snapshot['format']) is not int or snapshot['format']!=FORMAT:return OFFER_REJECT_FORMAT
            try:
                m=parse_metadata(snapshot['metadata'],a)
                need(type(snapshot['height']) is int and snapshot['height']==m['height'] and
                     type(snapshot['chunks']) is int and snapshot['chunks']==m['chunks'] and
                     type(snapshot['hash']) is bytes and len(snapshot['hash'])==32 and
                     snapshot['hash'].hex()==m['payload_sha256'] and type(trusted_app_hash) is bytes and
                     len(trusted_app_hash)==32 and trusted_app_hash.hex()==m['app_hash'], 'P8 snapshot trusted offer differs')
                if checkpoint:
                    need(m['height']>=a.height,'P8 snapshot rollback refused')
                    if m['height']==a.height:
                        row=a.db.execute('SELECT payload_sha256 FROM p8_snapshot_origin WHERE id=1').fetchone()
                        need(m['app_hash']==a.app_hash and row[0]==m['payload_sha256'],'P8 same-height snapshot differs')
                self.offer_state={'metadata':m,'parts':[],'bytes':0,'checkpoint':checkpoint}
                return OFFER_ACCEPT
            except (StateError,TypeError,UnicodeError,RecursionError):return OFFER_REJECT

    def install(self,p,raw,checkpoint):
        a=self.app; a.db.execute('BEGIN IMMEDIATE')
        try:
            if checkpoint:
                need(self.checkpoint_only() and p['height']>=a.height,'P8 checkpoint changed during import')
                need(p['state']['blocks'][:a.height] == a.state['blocks'],
                     'P8 newer snapshot does not extend authenticated origin')
                a.db.execute('DELETE FROM p8_checkpoint');a.db.execute('DELETE FROM p8_snapshot_origin')
            else:
                need(not a.closed and a.pending is None and a.state is None and
                     a.db.execute('SELECT 1 FROM p8_checkpoint').fetchone() is None and
                     a.db.execute('SELECT 1 FROM p8_blocks').fetchone() is None and
                     a.db.execute('SELECT 1 FROM p8_snapshot_origin').fetchone() is None,'P8 initialized during import')
            a.db.execute('INSERT INTO p8_checkpoint VALUES (1,?,?,?,?)',(a.expected,p['height'],p['app_hash'],canonical(p['state'])))
            a.db.execute('INSERT INTO p8_snapshot_origin VALUES (1,?,?,?,?)',(p['height'],p['app_hash'],payload_hash(raw).hex(),raw))
            a.db.execute('COMMIT')
        except BaseException:
            if a.db.in_transaction:a.db.execute('ROLLBACK')
            raise
        try:a._after_snapshot_commit()
        except BaseException:
            # A durable write followed by a failed refresh may only recover by
            # reopening, never by serving the stale in-memory checkpoint.
            a.close();raise
        a.state=p['state'];a.height=p['height'];a.app_hash=p['app_hash'];a.pending=None

    def apply(self,index,chunk,sender):
        a=self.app
        def reply(code,refetch=None):return {'result':code,'refetch_chunks':refetch or [],'reject_senders':[]}
        with a.lock:
            if a.closed:return reply(APPLY_ABORT)
            if self.offer_state is None:
                c=self.completed
                if c is not None and self.checkpoint_only() and type(index) is int and index==c['index'] and type(chunk) is bytes:
                    return reply(APPLY_ACCEPT if chunk==c['chunk'] else APPLY_REJECT_SNAPSHOT)
                return reply(APPLY_ABORT)
            o=self.offer_state;m=o['metadata']
            try:
                need(type(index) is int and 0<=index<m['chunks'] and type(chunk) is bytes and
                     0<len(chunk)<=CHUNK_BYTES and type(sender) is str and
                     len(sender.encode('utf8'))<=256,'P8 snapshot chunk bounds')
                expected=len(o['parts'])
                if index<expected:
                    if o['parts'][index]==chunk:return reply(APPLY_ACCEPT)
                    self.offer_state=None;return reply(APPLY_REJECT_SNAPSHOT)
                if index>expected:return reply(APPLY_RETRY,[expected])
                want=CHUNK_BYTES if index<m['chunks']-1 else m['payload_bytes']-index*CHUNK_BYTES
                need(len(chunk)==want and o['bytes']+len(chunk)<=m['payload_bytes'],'P8 snapshot chunk geometry')
                o['parts'].append(chunk);o['bytes']+=len(chunk)
                if len(o['parts'])<m['chunks']:return reply(APPLY_ACCEPT)
                raw=b''.join(o['parts'])
                need(len(raw)==m['payload_bytes'] and payload_hash(raw).hex()==m['payload_sha256'],'P8 snapshot payload hash differs')
                p=validate_payload(raw,a,m['height'],m['app_hash'])
                self.install(p,raw,o['checkpoint'])
                self.offer_state=None;self.completed={'index':index,'chunk':chunk}
                return reply(APPLY_ACCEPT)
            except (StateError,TypeError,UnicodeError,RecursionError):
                self.offer_state=None;return reply(APPLY_REJECT_SNAPSHOT)
