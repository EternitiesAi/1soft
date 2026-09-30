"""Unsigned requests and local decision correlation; never a funds journal."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import sqlite3
import time

from block_application import encode
from commit_verifier import load_json
from native_core import identifier, MAX_UNITS
from p4_evidence import freeze, hash_text, integer, need, content_id
from p4_read_store import private_path

FORMAT = '1soft/payment-request/v1'
FIELDS = {'schema','format','genesis_sha256','recipient','units','created_ns','expires_ns','note'}
MAX_REQUEST_BYTES = 4096
MAX_REQUESTS = 64
MAX_LIFETIME_NS = 86_400 * 10**9
APPLICATION_ID = 0x31504C42


def _shape(value):
    need(type(value) is dict and set(value) == FIELDS, 'invalid payment request fields')
    integer(value['schema'],1,1)
    need(value['format'] == FORMAT,'unsupported payment request format')
    hash_text(value['genesis_sha256']); identifier(value['recipient'])
    units = value['units']
    need(type(units) is str and units.isascii() and units.isdecimal() and
         1 <= len(units) <= 19 and units[0] != '0', 'exact positive atomic units required')
    integer(int(units),1,MAX_UNITS)
    start=integer(value['created_ns'],1); end=integer(value['expires_ns'],start+1)
    need(end-start <= MAX_LIFETIME_NS,'request lifetime exceeds development bound')
    note=value['note']
    need(type(note) is str and len(note)<=400 and all(ord(c)>=32 for c in note), 'invalid request note')
    raw=encode(value);need(len(raw)<=MAX_REQUEST_BYTES,'request exceeds byte bound')
    return load_json(raw,max_bytes=MAX_REQUEST_BYTES)


def new_request(genesis_sha256,recipient,units,*,created_ns,expires_ns,note=''):
    return _shape(dict(schema=1,format=FORMAT,genesis_sha256=genesis_sha256,
                       recipient=recipient,units=units,created_ns=created_ns,expires_ns=expires_ns,note=note))


def encode_request(value):
    return encode(_shape(value))


def request_id(value):
    return hashlib.sha256(encode_request(value)).hexdigest()


def parse_request(value,genesis_sha256,*,now_ns,historical=False):
    hash_text(genesis_sha256);integer(now_ns,1)
    need(type(historical) is bool,'invalid request display mode')
    if type(value) is bytes:
        need(len(value)<=MAX_REQUEST_BYTES,'request exceeds byte bound')
        parsed=_shape(load_json(value,max_bytes=MAX_REQUEST_BYTES))
        need(encode(parsed)==value,'request bytes must be canonical')
    else:
        parsed=_shape(value)
    need(parsed['genesis_sha256']==genesis_sha256,'request belongs to another genesis')
    if not historical:
        need(parsed['created_ns']<=now_ns<parsed['expires_ns'],'request is not currently open')
    return parsed


def _review(value,request):
    value=freeze(value,32768)
    need(value.get('schema')==1 and type(value.get('schema')) is int and
         value.get('format')=='1soft/p4-transfer-review/v1','transfer review required')
    hash_text(value['wallet_id']);hash_text(value['policy_id'])
    op=value['body']['op']
    need(type(op) is dict and set(op)=={'type','to','units'} and op['type']=='transfer', 'transfer operation required')
    integer(op['units'],1,MAX_UNITS)
    need(op['to']==request['recipient'] and op['units']==int(request['units']),'review changes requested payment')
    return value


class RequestBook:
    """Append-only request/review bindings. A binding is NOT signature or payment proof."""
    def __init__(self,path,genesis_sha256,*,create=False,clock=time.time_ns):
        hash_text(genesis_sha256);need(type(create) is bool,'invalid creation mode')
        self.path=private_path(path);self.genesis=genesis_sha256;self.clock=clock;self.db=None
        for file in (self.path,Path(str(self.path)+'-wal'),Path(str(self.path)+'-shm')):
            if file.exists():need(file.stat().st_size<=8*1024*1024,'request storage exceeds development bound')
        if create:
            fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        else:need(self.path.is_file(),'request book is not initialized')
        try:
            self.db=sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,isolation_level=None,timeout=5)
            if create:
                self.db.execute('PRAGMA journal_mode=WAL')
                self.db.execute('PRAGMA synchronous=FULL')
                with self.atomic():
                    self.db.execute(f'PRAGMA application_id={APPLICATION_ID}')
                    self.db.execute('CREATE TABLE config(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,genesis TEXT NOT NULL,last_ns INTEGER NOT NULL)')
                    self.db.execute('CREATE TABLE requests(id TEXT PRIMARY KEY,payload BLOB NOT NULL)')
                    self.db.execute('CREATE TABLE bindings(request_id TEXT PRIMARY KEY,decision_id TEXT UNIQUE NOT NULL,review BLOB NOT NULL)')
                    self.db.execute('INSERT INTO config VALUES(1,1,?,?)',(self.genesis,integer(self.clock(),1)))
                parent=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(parent)
                finally:os.close(parent)
            need(self.db.execute('PRAGMA application_id').fetchone()[0]==APPLICATION_ID,'unknown request book')
            need(self.db.execute('PRAGMA journal_mode').fetchone()[0]=='wal','request journal mode differs')
            self.db.execute('PRAGMA synchronous=FULL');self._catalog()
        except BaseException:self.close();raise

    def close(self):
        if self.db is not None:self.db.close();self.db=None
    def __enter__(self):return self
    def __exit__(self,*_):self.close()

    @contextmanager
    def atomic(self,write=True):
        self.db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK');raise

    def _catalog(self):
        private_path(self.path)
        need({r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}=={'config','requests','bindings'},'request schema differs')
        config=self.db.execute('SELECT * FROM config').fetchall()
        need(len(config)==1 and config[0][:3]==(1,1,self.genesis),'request configuration differs')
        integer(config[0][3],1)
        now=integer(self.clock(),1);rows=self.db.execute('SELECT id,payload FROM requests ORDER BY rowid').fetchall()
        need(len(rows)<=MAX_REQUESTS,'request record capacity exceeded')
        entries={}
        for rid,raw in rows:
            hash_text(rid);request=parse_request(raw,self.genesis,now_ns=now,historical=True)
            need(request_id(request)==rid,'request identity differs')
            entries[rid]={'request_id':rid,'request':request,'decision_id':None,'review':None,'execution_proven':False}
        bindings=self.db.execute('SELECT request_id,decision_id,review FROM bindings').fetchall()
        need(len(bindings)<=len(entries),'invalid request binding count')
        for rid,did,raw in bindings:
            need(rid in entries,'binding request unavailable');hash_text(did)
            value=load_json(raw,max_bytes=32768);need(encode(value)==raw,'review bytes changed')
            checked=_review(value,entries[rid]['request']);need(content_id(checked)==did,'decision identity differs')
            entries[rid].update(decision_id=did,review=checked)
        return config[0][3],entries

    def _now(self,last):
        now=integer(self.clock(),last);self.db.execute('UPDATE config SET last_ns=? WHERE id=1',(now,));return now

    def add(self,value):
        with self.atomic():
            last,entries=self._catalog();now=self._now(last)
            request=parse_request(value,self.genesis,now_ns=now);rid=request_id(request)
            if rid in entries:return {'status':'already_retained','request_id':rid,'execution_proven':False}
            need(len(entries)<MAX_REQUESTS,'request capacity reached; no eviction')
            self.db.execute('INSERT INTO requests VALUES(?,?)',(rid,encode_request(request)))
        return {'status':'request_retained','request_id':rid,'execution_proven':False}

    def bind_review(self,rid,review):
        hash_text(rid)
        with self.atomic():
            last,entries=self._catalog();now=self._now(last);need(rid in entries,'request unavailable')
            entry=entries[rid];request=parse_request(entry['request'],self.genesis,now_ns=now)
            value=_review(review,request);did=content_id(value)
            if entry['decision_id'] is not None:
                need(entry['decision_id']==did and entry['review']==value,'request already has another review')
                return {'request_id':rid,'decision_id':did,'execution_proven':False}
            need(not any(e['decision_id']==did for e in entries.values()),'decision already bound to another request')
            self.db.execute('INSERT INTO bindings VALUES(?,?,?)',(rid,did,encode(value)))
        return {'request_id':rid,'decision_id':did,'execution_proven':False}

    def entries(self):
        with self.atomic(write=False):return list(self._catalog()[1].values())

    def selected(self,rid):
        hash_text(rid)
        with self.atomic(write=False):
            _,entries=self._catalog();need(rid in entries,'request unavailable');return entries[rid]
