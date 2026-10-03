"""Private append-only shared P4 history, distinct from every monetary journal."""
from __future__ import annotations

import base64
from collections import OrderedDict
from contextlib import contextmanager
import copy
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import time

from block_application import encode
from commit_verifier import exact, load_json
from p4_evidence import (content_id,hash_text,integer,need,
    _account_from_verified_report,_receipt_from_verified_report)
from p4_read_store import private_path
from p4_incremental_evidence import (CHECKPOINT_FORMAT,MAX_SEGMENT_BYTES,
    VerifiedCursor,check_clock,checked_segment,identity,policy_v2_checked)

APPLICATION_ID=0x31503449
ARCHIVE_FORMAT='1soft/protocol4-incremental-history-archive/v1'
DEFAULT_LIMITS={'max_blocks':4096,'max_checkpoints':4096,
    'max_bytes':256*1024*1024,'max_physical_bytes':512*1024*1024,
    'max_item_bytes':16*1024*1024,'max_context_bytes':64*1024*1024,
    'max_contexts':257}
CHECKPOINT_KEYS={'schema','format','parent_id','height','app_hash','lookahead_height',
    'lookahead_hash','lookahead_time_ns','lookahead_digest','policy_id','history_id',
    'checked_ns','state_sha256','store_id','id'}


class P4IncrementalStore:
    def __init__(self,path,genesis_bytes,policy,*,create=False,read_only=False,
                 clock=time.time_ns,limits=None):
        need(type(create) is bool and type(read_only) is bool and not(create and read_only),
             'invalid incremental store mode')
        self.policy=policy_v2_checked(policy);self.policy_id=content_id(self.policy)
        self.genesis=bytes(genesis_bytes);self.clock=clock;self.read_only=read_only
        self.limits=dict(DEFAULT_LIMITS)
        if limits is not None:
            need(type(limits) is dict and set(limits)==set(DEFAULT_LIMITS),'exact resource limits required')
            for key,value in limits.items():integer(value,1,DEFAULT_LIMITS[key])
            self.limits.update(limits)
        self.path=private_path(path);self.db=None;self._cursor=None;self._token=None
        self._views=OrderedDict();self._cache_bytes=0;self._descriptors=[]
        # Verify original genesis/profile independently of any serialized cache.
        candidate=VerifiedCursor(self.genesis,self.policy);candidate.close()
        if create:
            check_clock(self.policy,self.clock())
            fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        else:need(self.path.is_file(),'incremental store not initialized; no implicit repair')
        st=self.path.stat();self._path_identity=(st.st_dev,st.st_ino)
        try:
            self.db=sqlite3.connect(self.path.as_uri()+('?mode=ro' if read_only else '?mode=rw'),
                                   uri=True,isolation_level=None,timeout=5)
            if create:
                self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
                with self.atomic():
                    self.db.execute(f'PRAGMA application_id={APPLICATION_ID}')
                    self.db.execute('CREATE TABLE config(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, store_id TEXT NOT NULL, genesis_sha256 TEXT NOT NULL, policy_id TEXT NOT NULL, policy BLOB NOT NULL)')
                    self.db.execute('CREATE TABLE headers(height INTEGER PRIMARY KEY, digest TEXT NOT NULL, payload BLOB NOT NULL)')
                    self.db.execute('CREATE TABLE blocks(height INTEGER PRIMARY KEY, digest TEXT NOT NULL, payload BLOB NOT NULL)')
                    self.db.execute('CREATE TABLE checkpoints(seq INTEGER PRIMARY KEY, checkpoint_id TEXT UNIQUE NOT NULL, height INTEGER NOT NULL, checked_ns INTEGER NOT NULL, payload BLOB NOT NULL)')
                    self.db.execute('INSERT INTO config VALUES(1,1,?,?,?,?)',
                        (secrets.token_hex(32),self.policy['genesis_sha256'],self.policy_id,encode(self.policy)))
                parent=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(parent)
                finally:os.close(parent)
            if not read_only:
                need(self.db.execute('PRAGMA journal_mode').fetchone()[0]=='wal','unexpected journal mode; no repair')
                self.db.execute('PRAGMA synchronous=FULL')
            with self.atomic(write=False):self._catalog()
        except BaseException:self.close();raise

    @property
    def history_id(self):return self.store_id

    def close(self):
        self._discard()
        if self.db is not None:self.db.close();self.db=None
    def __enter__(self):return self
    def __exit__(self,*_):self.close()

    def _discard(self):
        if self._cursor is not None:self._cursor.close()
        self._cursor=None;self._token=None;self._views.clear();self._cache_bytes=0;self._descriptors=[]

    @contextmanager
    def atomic(self,write=True):
        need(self.db is not None and not self.db.in_transaction and not(write and self.read_only),
             'incremental transaction or mode conflict')
        self.db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        self._write_trust_checkpoint=None
        self._write_latest_ns=self.clock() if write else None
        try:
            yield
            if write:
                # Nothing that constructs/deep-copies a returned view runs after this guard.
                final=self.clock()
                check_clock(self.policy,final,self._write_latest_ns,
                            checkpoint=self._write_trust_checkpoint)
                if self._cursor is not None and self._cursor.summary is not None:
                    need(final-self._cursor.summary['time_ns']<=300*10**9,
                         'checkpoint became stale before commit')
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            self._discard()
            raise

    def _fingerprint(self):
        private_path(self.path)
        current=self.path.stat()
        need((current.st_dev,current.st_ino)==self._path_identity,'incremental database path identity changed')
        files=[]
        for suffix in ('','-wal'):
            p=Path(str(self.path)+suffix)
            if p.exists():
                s=p.stat();files.append((suffix,s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns))
        return (tuple(files),self.db.execute('PRAGMA data_version').fetchone()[0],
                self.db.total_changes,self.db.execute('PRAGMA schema_version').fetchone()[0])

    def _catalog(self):
        private_path(self.path)
        current=self.path.stat()
        need((current.st_dev,current.st_ino)==self._path_identity,'incremental database path identity changed')
        need(self.db.execute('PRAGMA application_id').fetchone()[0]==APPLICATION_ID,
             'not incremental history; no repair')
        objects=set(self.db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
        columns={'config':('id','version','store_id','genesis_sha256','policy_id','policy'),
                 'headers':('height','digest','payload'),'blocks':('height','digest','payload'),
                 'checkpoints':('seq','checkpoint_id','height','checked_ns','payload')}
        need(objects=={('table',k) for k in columns},'unrecognized incremental schema')
        for table,names in columns.items():
            need(tuple(r[1] for r in self.db.execute(f'PRAGMA table_info({table})'))==names,
                 'incremental columns differ')
        config=self.db.execute('SELECT * FROM config').fetchall()
        need(len(config)==1 and config[0][:2]==(1,1) and
             config[0][3:]==(self.policy['genesis_sha256'],self.policy_id,encode(self.policy)),
             'original external genesis or policy differs')
        self.store_id=hash_text(config[0][2])
        total=0
        for table,limit in (('blocks',self.limits['max_blocks']),
                            ('headers',self.limits['max_blocks']+1),
                            ('checkpoints',self.limits['max_checkpoints'])):
            count,size,maxsize=self.db.execute(f'SELECT count(*),coalesce(sum(length(payload)),0),coalesce(max(length(payload)),0) FROM {table}').fetchone()
            integer(count,0,limit);integer(size,0,self.limits['max_bytes'])
            integer(maxsize,0,self.limits['max_item_bytes'])
            total+=size
            # Descriptor type/length checks precede every retained body BLOB read.
            bad=self.db.execute(f"SELECT count(*) FROM {table} WHERE typeof(payload)!='blob' OR length(payload)=0").fetchone()[0]
            need(bad==0,'invalid retained payload descriptor')
        need(total<=self.limits['max_bytes'],'history byte quota exceeded; no eviction')
        physical=sum(Path(str(self.path)+s).stat().st_size for s in ('','-wal')
                     if Path(str(self.path)+s).exists())
        need(physical<=self.limits['max_physical_bytes'],'physical history quota exceeded; no eviction')
        rows=self.db.execute('SELECT seq,checkpoint_id,height,checked_ns,length(payload) FROM checkpoints ORDER BY seq').fetchall()
        prior_h=0;prior_ns=None
        for expected,(seq,cid,height,checked,size) in enumerate(rows,1):
            integer(seq,expected,expected);hash_text(cid)
            integer(height,prior_h+1,min(prior_h+64,4096));integer(checked)
            if prior_ns is not None:need(checked>=prior_ns,'admission clock regressed')
            prior_h=height;prior_ns=checked
        for table,wanted in (('blocks',prior_h),('headers',prior_h+1 if rows else 0)):
            count,lo,hi=self.db.execute(f'SELECT count(*),min(height),max(height) FROM {table}').fetchone()
            need(count==wanted and (wanted==0 or (lo==1 and hi==wanted)),
                 'retained consecutive history incomplete')
        return rows

    def _decode_row(self,table,height):
        row=self.db.execute(f'SELECT digest,payload FROM {table} WHERE height=?',(height,)).fetchone()
        need(row is not None,'retained history row missing')
        digest,raw=row;hash_text(digest)
        need(type(raw) is bytes and 0<len(raw)<=self.limits['max_item_bytes'] and
             hashlib.sha256(raw).hexdigest()==digest,'retained history digest differs')
        value=load_json(raw,max_bytes=self.limits['max_item_bytes'])
        need(encode(value)==raw,'noncanonical retained history')
        return value

    def _checkpoint(self,seq):
        cid,height,checked,raw=self.db.execute('SELECT checkpoint_id,height,checked_ns,payload FROM checkpoints WHERE seq=?',(seq,)).fetchone()
        value=load_json(raw,max_bytes=4096)
        exact(value,CHECKPOINT_KEYS,'immutable checkpoint')
        need(encode(value)==raw and content_id({k:v for k,v in value.items() if k!='id'})==cid==value['id'],
             'checkpoint descriptor digest differs')
        integer(value['schema'],1,1)
        need(value['format']==CHECKPOINT_FORMAT and value['store_id']==self.store_id and
             value['policy_id']==self.policy_id,'checkpoint original identity differs')
        integer(value['height'],height,height);integer(value['checked_ns'],checked,checked)
        integer(value['lookahead_height'],height+1,height+1);integer(value['lookahead_time_ns'])
        for key in ('app_hash','lookahead_hash','lookahead_digest','history_id','state_sha256'):hash_text(value[key])
        if value['parent_id'] is not None:hash_text(value['parent_id'])
        return value

    def _remember(self,view):
        cid=view['checkpoint']['id'];rawsize=len(encode(view))
        need(rawsize<=self.limits['max_context_bytes'],'derived context byte quota exceeded')
        if cid in self._views:
            old=self._views.pop(cid);self._cache_bytes-=len(encode(old))
        while self._views and (len(self._views)>=self.limits['max_contexts'] or
                               self._cache_bytes+rawsize>self.limits['max_context_bytes']):
            _,old=self._views.popitem(last=False);self._cache_bytes-=len(encode(old))
        self._views[cid]=view;self._cache_bytes+=rawsize

    def _authenticate(self,rows,wanted):
        cursor=VerifiedCursor(self.genesis,self.policy)
        descriptors=[];captured={}
        prior=None
        try:
            for seq,_,height,checked,_ in rows:
                cp=self._checkpoint(seq)
                need(cp['parent_id']==(None if prior is None else prior['id']),
                     'checkpoint parent lineage differs')
                check_clock(self.policy,checked,None if prior is None else prior['checked_ns'],checkpoint=prior)
                start=cursor.app.height
                history=[self._decode_row('blocks',h) for h in range(start+1,height+1)]
                headers=[self._decode_row('headers',h) for h in range(start+1,height+2)]
                state=cursor.advance(history,headers,now_ns=checked)
                need(cp['history_id']==cursor.history_id and cp['state_sha256']==content_id(state) and
                     cp['app_hash']==cursor.app.app_hash and cp['lookahead_hash']==cursor.summary['block_hash'] and
                     cp['lookahead_time_ns']==cursor.summary['time_ns'] and
                     cp['lookahead_digest']==content_id(cursor.lookahead),
                     'checkpoint metadata differs from authenticated history')
                need(cursor.summary['time_ns']<=checked+self.policy['max_clock_drift_seconds']*10**9 and
                     checked-cursor.summary['time_ns']<=300*10**9,'original admission freshness differs')
                descriptors.append(cp)
                if cp['id'] in wanted or (seq==len(rows) and not wanted):
                    captured[cp['id']]=cursor.view(cp,now_ns=checked,current_authority=False)
                    need(sum(len(encode(v)) for v in captured.values())<=self.limits['max_context_bytes'],
                         'checkpoint context batch byte quota exceeded')
                prior=cp
            return cursor,descriptors,captured
        except BaseException:cursor.close();raise

    def _ensure(self,wanted=()):
        token=self._fingerprint();rows=None
        wanted=set(wanted)
        if self._cursor is None or token!=self._token:
            rows=self._catalog()
            self._discard()
            cursor,descriptors,views=self._authenticate(rows,wanted)
            self._cursor=cursor;self._descriptors=descriptors
            for view in views.values():self._remember(view)
            self._token=self._fingerprint()
        for cid in wanted & set(self._views):self._views.move_to_end(cid)
        missing=wanted-set(self._views)
        if missing:
            valid={cp['id'] for cp in self._descriptors}
            need(missing<=valid,'unknown retained checkpoint')
            if rows is None:rows=self._catalog()
            cursor,_,views=self._authenticate(rows,missing)
            cursor.close()
            for view in views.values():self._remember(view)
        return self._descriptors[-1] if self._descriptors else None

    def _now(self,now):
        actual=integer(self.clock())
        if now is not None:
            integer(now)
            need(0<=actual-now<=10**9,'explicit time differs from current host clock')
        return actual

    def current(self,now=None,checkpoint_id=None,historical=False):
        need(type(historical) is bool,'typed historical selector required')
        requested=() if checkpoint_id is None else (hash_text(checkpoint_id),)
        with self.atomic(write=False):
            tip=self._ensure(requested)
            if tip is None:return None
            cp=tip if checkpoint_id is None else next((v for v in self._descriptors if v['id']==checkpoint_id),None)
            need(cp is not None,'unknown retained checkpoint')
            if cp['id'] not in self._views:self._ensure((cp['id'],))
            result=copy.deepcopy(self._views[cp['id']])
            if historical:
                result['context']['current_authority']=False
                result['report']['historical_context']=True
                return result
            observed=self._now(now)
            check_clock(self.policy,observed,tip['checked_ns'],checkpoint=tip)
            need(cp['id']==tip['id'],'historical checkpoint is not current authority')
            # Native state and lookahead remain bound to the in-process verified cursor.
            result=self._cursor.view(cp,now_ns=observed,current_authority=True)
            check_clock(self.policy,self.clock(),observed,checkpoint=tip)
            return result

    def checkpoint_at(self,checkpoint_id,historical=True):
        return self.current(checkpoint_id=checkpoint_id,historical=historical)

    def checkpoint_batch(self,ids,historical=True):
        need(type(ids) in (list,tuple,set) and type(historical) is bool,'bounded checkpoint IDs required')
        wanted=set(hash_text(cid) for cid in ids)
        need(len(wanted)<=self.limits['max_contexts'],'checkpoint context count quota exceeded')
        with self.atomic(write=False):
            tip=self._ensure(wanted)
            need(wanted<={cp['id'] for cp in self._descriptors},'unknown retained checkpoint')
            if not historical:
                now=self._now(None);check_clock(self.policy,now,tip['checked_ns'],checkpoint=tip)
                need(wanted<={tip['id']},'historical checkpoint is not current authority')
            result={cid:copy.deepcopy(self._views[cid]) for cid in wanted}
            need(sum(len(encode(v)) for v in result.values())<=self.limits['max_context_bytes'],
                 'checkpoint context batch byte quota exceeded')
            for view in result.values():
                view['context']['current_authority']=not historical
                view['report']['historical_context']=historical
            return result

    def checkpoint_descriptors(self):
        with self.atomic(write=False):
            self._ensure()
            return {cp['id']:copy.deepcopy(cp) for cp in self._descriptors}

    def check_current(self,checkpoint_id,now=None,previous_ns=None):
        view=self.current(now=now)
        need(view is not None and view['checkpoint']['id']==hash_text(checkpoint_id),
             'reviewed checkpoint tip changed')
        check_clock(self.policy,self.clock(),previous_ns,checkpoint=view['checkpoint'])
        return view['checkpoint']

    def import_segment(self,segment,*,now=None,expected_tip=None):
        s=checked_segment(segment)
        try:
            with self.atomic():
                previous=self._ensure()
                self._write_trust_checkpoint=previous
                actual_tip=None if previous is None else previous['id']
                need(expected_tip==actual_tip and s['parent_checkpoint']==actual_tip,
                     'reviewed incremental tip changed')
                start=0 if previous is None else previous['height']
                need(s['from_height']==start,'segment skips original history or rolls back')
                observed=self._now(now)
                check_clock(self.policy,observed,None if previous is None else previous['checked_ns'],checkpoint=previous)
                need(len(self._descriptors)<self.limits['max_checkpoints'] and
                     s['state']['height']<=self.limits['max_blocks'],
                     'history capacity reached; no eviction')
                state=self._cursor.advance(s['history'],s['headers'],now_ns=observed,expected_state=s['state'])
                need(observed-self._cursor.summary['time_ns']<=300*10**9,
                     'new checkpoint freshness bound exceeded')
                checked=self.clock()
                self._write_latest_ns=max(self._write_latest_ns,checked)
                check_clock(self.policy,checked,observed,checkpoint=previous)
                cp={'schema':1,'format':CHECKPOINT_FORMAT,'parent_id':actual_tip,
                    'height':self._cursor.app.height,'app_hash':self._cursor.app.app_hash,
                    'lookahead_height':self._cursor.app.height+1,
                    'lookahead_hash':self._cursor.summary['block_hash'],
                    'lookahead_time_ns':self._cursor.summary['time_ns'],
                    'lookahead_digest':content_id(self._cursor.lookahead),'policy_id':self.policy_id,
                    'history_id':self._cursor.history_id,'checked_ns':checked,
                    'state_sha256':content_id(state),'store_id':self.store_id}
                cp['id']=content_id(cp)
                for table,values in (('blocks',s['history']),('headers',s['headers'])):
                    for value in values:
                        height=value['height'] if table=='blocks' else integer(int(value['signed_header']['header']['height']))
                        if table=='headers' and previous is not None and height==start+1:
                            retained=self._decode_row('headers',height)
                            need(encode(identity(retained))==encode(identity(value)),
                                 'retained boundary identity changed')
                            continue
                        raw=encode(value);need(len(raw)<=self.limits['max_item_bytes'],'retained item quota exceeded')
                        self.db.execute(f'INSERT INTO {table} VALUES(?,?,?)',(height,hashlib.sha256(raw).hexdigest(),raw))
                raw=encode(cp)
                self.db.execute('INSERT INTO checkpoints VALUES(?,?,?,?,?)',
                    (len(self._descriptors)+1,cp['id'],cp['height'],checked,raw))
                self._catalog()
                # Final CURRENT wall-clock check occurs after all processing, immediately before COMMIT.
                final=self.clock();check_clock(self.policy,final,checked,checkpoint=previous)
                need(final-self._cursor.summary['time_ns']<=300*10**9,
                     'checkpoint became stale before commit')
                view=self._cursor.view(cp,now_ns=final,current_authority=True)
            self._descriptors.append(cp);self._remember(self._cursor.view(cp,now_ns=checked,current_authority=False))
            self._token=self._fingerprint()
            return {**view,'status':'checkpoint_recorded','wallet_reservations_changed':False}
        except BaseException:self._discard();raise

    def collect(self,endpoint,*,now=None,expected_tip=None):
        from p4_incremental_rpc import collect_segment
        view=self.current(now=now)
        actual=None if view is None else view['checkpoint']['id']
        need(actual==expected_tip,'reviewed incremental tip changed')
        observed=self._now(now)
        candidate=collect_segment(endpoint,self.genesis,self.policy,observed,view=view)
        result=self.import_segment(candidate['segment'],expected_tip=expected_tip)
        return {**result,'rpc_requests':candidate['rpc_requests'],'signed':False,
                'broadcast':False,'captured_source_height':candidate['captured_source_height']}

    def account(self,account_id):
        view=self.current();need(view is not None,'authenticated checkpoint unavailable')
        return _account_from_verified_report(view['report'],account_id)

    def receipt(self,wire,*,payer):
        view=self.current();need(view is not None,'authenticated checkpoint unavailable')
        return _receipt_from_verified_report(view['report'],wire,payer)

    def export_history(self):
        with self.atomic(write=False):
            self._ensure()
            value={'schema':1,'format':ARCHIVE_FORMAT,'store_id':self.store_id,
                'genesis_b64':base64.b64encode(self.genesis).decode(),'policy':self.policy,
                'headers':[self._decode_row('headers',h) for h in range(1,self._cursor.app.height+2)] if self._descriptors else [],
                'history':[self._decode_row('blocks',h) for h in range(1,self._cursor.app.height+1)],
                'checkpoints':self._descriptors}
            raw=encode(value);need(len(raw)<=self.limits['max_bytes'],'archive logical quota exceeded')
            return raw
