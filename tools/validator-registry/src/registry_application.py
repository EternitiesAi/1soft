"""Durable, isolated registry application with replay-audited local state.

One transaction commits the height, queue/epoch state, exact action wires and ABCI
result. All history is retained with finite development bounds. This is NOT the
existing monetary BlockApplication, a network or an authenticated wallet snapshot.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import os
from pathlib import Path
import sqlite3
import stat
import threading

from commit_verifier import encode, load_json, exact
from registry_rules import (RegistryRules, RegistryReject, require, integer, frozen,
                            digest, APP_VERSION, MAX_BLOCK_TXS, MAX_BLOCK_BYTES, MAX_TX_BYTES)

APP_ID=0x31565247
MAX_BLOCKS=512
MAX_STORE_BYTES=8*1024*1024
SNAPSHOT_FORMAT='1soft/validator-registry-snapshot/v1'
COLUMNS={
    'registry_config':('id','genesis','genesis_hash'),
    'registry_checkpoint':('id','state','app_hash'),
    'registry_blocks':('height','block_hash','transactions','result','app_hash'),
}


def private_path(path):
    require(os.name=='posix','registry store requires POSIX')
    p=Path(os.path.abspath(path))
    for a in (p.parent,*p.parent.parents):require(not a.is_symlink(),'symlink ancestor refused')
    m=p.parent.stat()
    require(stat.S_ISDIR(m.st_mode) and m.st_uid==os.geteuid() and m.st_mode&0o077==0,
            'private owned registry directory required')
    for f in (p,*(Path(str(p)+suffix) for suffix in ('-wal','-shm','-journal'))):
        if f.exists() or f.is_symlink():
            s=f.lstat()
            require(stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1
                    and s.st_mode&0o077==0,'unsafe registry file or sidecar')
    return p


def write_new(path, raw):
    require(type(raw) is bytes and len(raw)<=MAX_STORE_BYTES,'output exceeds registry limit')
    p=private_path(path)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    fd=os.open(p.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def encode_txs(txs):
    return [base64.b64encode(t).decode('ascii') for t in txs]


def decode_txs(values):
    require(type(values) is list and len(values)<=MAX_BLOCK_TXS,'invalid saved transaction list')
    decoded=[]
    for value in values:
        require(type(value) is str and len(value)<=4*((MAX_TX_BYTES+2)//3),'saved transaction exceeds bound')
        try:raw=base64.b64decode(value,validate=True)
        except (ValueError,TypeError) as exc:raise RegistryReject('invalid saved transaction encoding') from exc
        require(len(raw)<=MAX_TX_BYTES and base64.b64encode(raw).decode('ascii')==value,'noncanonical transaction encoding')
        decoded.append(raw)
    require(sum(map(len,decoded))<=MAX_BLOCK_BYTES,'saved block exceeds bound')
    return decoded


def replay(genesis, records):
    """Authenticate all administrative operations again; no peer state is trusted."""
    rules=RegistryRules(genesis);state=rules.initial_state()
    require(type(records) is list and len(records)<=MAX_BLOCKS,'registry block history limit')
    raw=encode(records);require(len(raw)<=MAX_STORE_BYTES,'registry history size limit')
    for record in records:
        exact(record,{'height','block_hash','transactions','result','app_hash'},'registry block record')
        from validator_sets import hex_text
        hex_text(record['block_hash'])
        integer(record['height'],1,MAX_BLOCKS)
        state,result=rules.transition(state,decode_txs(record['transactions']),record['height'])
        require(encode(result)==encode(record['result']) and result['app_hash']==record['app_hash'],
                'saved execution differs from authenticated replay')
    return state


def verify_snapshot(value, genesis, *, expected_app_hash, expected_height):
    """External hash/height are required, not taken from the snapshot itself.

    No light-client verification occurs here. The embedding caller must establish
    those pins independently. Existing node state-sync never accepts this format.
    """
    from validator_sets import hex_text
    hex_text(expected_app_hash);integer(expected_height,0,MAX_BLOCKS)
    snap=frozen(value,MAX_STORE_BYTES)
    exact(snap,{'schema','format','genesis','blocks','height','app_hash','state'},'registry snapshot')
    integer(snap['schema'],1,1);integer(snap['height'],0,MAX_BLOCKS)
    require(snap['format']==SNAPSHOT_FORMAT and encode(snap['genesis'])==encode(genesis),
            'registry snapshot format/genesis differs')
    rules=RegistryRules(genesis);state=replay(genesis,snap['blocks'])
    require(state['height']==expected_height==snap['height'] and
            rules.state_hash(state)==expected_app_hash==snap['app_hash'] and
            encode(state)==encode(snap['state']),'snapshot state/checkpoint differs from replay and pins')
    return snap,state


class RegistryApplication:
    def __init__(self,path,genesis,*,create=False,read_only=False):
        require(type(create) is bool and type(read_only) is bool and not(create and read_only),'invalid registry mode')
        self.rules=RegistryRules(genesis);self.path=private_path(path);self.read_only=read_only
        self.db=None;self._pending=None;self.lock=threading.RLock()
        if create:
            fd=os.open(self.path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);os.close(fd)
        else:require(self.path.is_file(),'registry database not initialized')
        try:
            self.db=sqlite3.connect(self.path.as_uri()+('?mode=ro' if read_only else '?mode=rw'),uri=True,
                                   isolation_level=None,timeout=5,check_same_thread=False)
            if create:
                self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
                with self.atomic():
                    self.db.execute(f'PRAGMA application_id={APP_ID}')
                    self.db.execute('CREATE TABLE registry_config(id INTEGER PRIMARY KEY CHECK(id=1),genesis BLOB NOT NULL,genesis_hash TEXT NOT NULL)')
                    self.db.execute('CREATE TABLE registry_checkpoint(id INTEGER PRIMARY KEY CHECK(id=1),state BLOB NOT NULL,app_hash TEXT NOT NULL)')
                    self.db.execute('CREATE TABLE registry_blocks(height INTEGER PRIMARY KEY,block_hash TEXT NOT NULL,transactions BLOB NOT NULL,result BLOB NOT NULL,app_hash TEXT NOT NULL)')
                    state=self.rules.initial_state()
                    self.db.execute('INSERT INTO registry_config VALUES(1,?,?)',(encode(self.rules.genesis),self.rules.genesis_hash))
                    self.db.execute('INSERT INTO registry_checkpoint VALUES(1,?,?)',(encode(state),self.rules.state_hash(state)))
                fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(fd)
                finally:os.close(fd)
            with self.atomic(write=False):self._state=self._audit()
            if not read_only:
                require(self.db.execute('PRAGMA journal_mode').fetchone()[0]=='wal','registry journal mode changed')
                self.db.execute('PRAGMA synchronous=FULL')
        except BaseException:
            self.close();raise

    @contextmanager
    def atomic(self,write=True):
        require(not self.db.in_transaction and not(write and self.read_only),'registry transaction/mode conflict')
        self.db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        try:yield;self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise

    def _schema(self):
        require(self.db.execute('PRAGMA application_id').fetchone()[0]==APP_ID,'not a registry database')
        objects=set(self.db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
        require(objects=={('table',k) for k in COLUMNS},'registry schema differs; no repair')
        for table,columns in COLUMNS.items():
            require(tuple(r[1] for r in self.db.execute('PRAGMA table_info('+table+')'))==columns,'registry columns differ')
        rows=self.db.execute('SELECT * FROM registry_config').fetchall()
        require(len(rows)==1 and rows[0]==(1,encode(self.rules.genesis),self.rules.genesis_hash),
                'registry genesis or administrative policy differs')
        n,size=self.db.execute('SELECT count(*),coalesce(sum(length(transactions)+length(result)),0) FROM registry_blocks').fetchone()
        require(n<=MAX_BLOCKS and size<=MAX_STORE_BYTES,'registry history capacity exceeded')
        row=self.db.execute('SELECT id,length(state) FROM registry_checkpoint').fetchall()
        require(len(row)==1 and row[0][0]==1 and row[0][1]<=MAX_STORE_BYTES,'invalid registry checkpoint size')

    def _records(self):
        result=[]
        for h,b,txs,r,a in self.db.execute('SELECT * FROM registry_blocks ORDER BY height'):
            require(type(txs) is bytes and type(r) is bytes,'saved record encoding differs')
            values=load_json(txs,max_bytes=MAX_STORE_BYTES);response=load_json(r,max_bytes=MAX_STORE_BYTES)
            require(encode(values)==txs and encode(response)==r,'noncanonical saved record')
            result.append({'height':h,'block_hash':b,'transactions':values,'result':response,'app_hash':a})
        return result

    def _audit(self):
        self._schema();records=self._records();state=replay(self.rules.genesis,records)
        row=self.db.execute('SELECT * FROM registry_checkpoint').fetchone()
        require(row==(1,encode(state),self.rules.state_hash(state)), 'durable registry checkpoint differs from replay')
        return state

    def state(self):
        with self.lock,self.atomic(write=False):return frozen(self._audit())

    def info(self):
        state=self.state()
        return {'name':'1soft-validator-registry-development','app_version':APP_VERSION,'height':state['height'],
                'app_hash':self.rules.state_hash(state),'epoch':state['epoch'],
                'native_payments_supported':False,'release_status':'blocked'}

    def check_tx(self,raw):
        state=self.state()
        _,result=self.rules.transition(state,[raw],state['height']+1)
        return result['tx_results'][0]

    def process_proposal(self,txs,height):
        state=self.state()  # Storage faults are not ordinary proposal rejections.
        try:
            _,result=self.rules.transition(state,txs,height)
            return all(r['code']==0 for r in result['tx_results'])
        except ValueError:return False

    def finalize_block(self,txs,height,block_hash):
        with self.lock:
            require(not self.read_only,'read-only registry')
            require(type(block_hash) is bytes and len(block_hash)==32,'invalid block identity')
            state=self.state()
            frozen_txs=list(txs) if type(txs) is list else txs
            candidate,result=self.rules.transition(state,frozen_txs,height)
            record={'height':height,'block_hash':block_hash.hex(),'transactions':encode_txs(frozen_txs),
                    'result':result,'app_hash':result['app_hash']}
            identity=digest(encode(record))
            if self._pending is not None:
                require(self._pending['identity']==identity,'different block already finalized')
                return frozen(self._pending['record']['result'])
            require(height<=MAX_BLOCKS,'registry development height limit')
            self._pending={'before':state,'state':candidate,'record':record,'identity':identity}
            return frozen(result)

    def commit(self,*,fault=''):
        """Fault strings are local test inputs, never transaction fields."""
        with self.lock:
            require(not self.read_only,'read-only registry')
            require(fault in ('','before_commit','exit_before_commit','exit_after_commit'),'unknown test fault')
            if self._pending is None:return self.info()
            p=self._pending;r=p['record']
            with self.atomic():
                observed=self._audit()
                require(encode(observed)==encode(p['before']),'registry advanced since finalization')
                self.db.execute('INSERT INTO registry_blocks VALUES(?,?,?,?,?)',
                                (r['height'],r['block_hash'],encode(r['transactions']),encode(r['result']),r['app_hash']))
                self.db.execute('UPDATE registry_checkpoint SET state=?,app_hash=? WHERE id=1',(encode(p['state']),r['app_hash']))
                # Audit both the exact emission response and state before commit.
                require(encode(self._audit())==encode(p['state']),'registry commit replay mismatch')
                if fault=='before_commit':raise RuntimeError('injected registry commit failure')
                if fault=='exit_before_commit':os._exit(81)
            if fault=='exit_after_commit':os._exit(82)
            self._state=p['state'];self._pending=None
            return self.info()

    def discard_pending(self):
        with self.lock:self._pending=None

    def committed_result(self,height):
        integer(height,1,MAX_BLOCKS)
        with self.lock,self.atomic(write=False):
            self._audit();row=self.db.execute('SELECT result FROM registry_blocks WHERE height=?',(height,)).fetchone()
            require(row is not None,'committed registry response unavailable')
            return load_json(row[0],max_bytes=MAX_STORE_BYTES)

    def export_snapshot(self):
        with self.lock,self.atomic(write=False):
            state=self._audit()
            snap={'schema':1,'format':SNAPSHOT_FORMAT,'genesis':self.rules.genesis,
                  'blocks':self._records(),'height':state['height'],'app_hash':self.rules.state_hash(state),'state':state}
            return frozen(snap,MAX_STORE_BYTES)

    @classmethod
    def restore_new(cls,path,genesis,snapshot,*,expected_app_hash,expected_height):
        snap,state=verify_snapshot(snapshot,genesis,expected_app_hash=expected_app_hash,expected_height=expected_height)
        # Invalid/unknown snapshots never create a database. An I/O error after
        # creation may leave an empty initialized dev store, never a partial restore.
        app=cls(path,genesis,create=True)
        try:
            with app.atomic():
                for r in snap['blocks']:
                    app.db.execute('INSERT INTO registry_blocks VALUES(?,?,?,?,?)',
                        (r['height'],r['block_hash'],encode(r['transactions']),encode(r['result']),r['app_hash']))
                app.db.execute('UPDATE registry_checkpoint SET state=?,app_hash=? WHERE id=1',(encode(state),expected_app_hash))
                require(encode(app._audit())==encode(state),'restored registry history differs')
            app._state=state
            return app
        except BaseException:app.close();raise

    def close(self):
        if self.db is not None:self.db.close();self.db=None
        self._pending=None

    def __enter__(self):return self
    def __exit__(self,*_):self.close()
