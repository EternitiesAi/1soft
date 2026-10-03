"""Finite prospective alpha monetary journal referencing original authenticated history.

This is a new journal, never a migration or second signer over an existing wallet.
The retained history is required to audit exact origins. Historical recovery is
inert; copied workspaces and hostile host rollback are not fenced.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3
import time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from block_application import encode, restore
from commit_verifier import exact, load_json
from development_profile import max_height_for, DURABLE_PROFILE
from native_core import DOMAIN, canonical
from p4_evidence import content_id, hash_text, integer, need, p4_genesis
from p4_incremental_evidence import policy_v2_checked, check_clock, CONTEXT_FORMAT
from p4_read_store import private_path
from p4_wallet import (P4Wallet, MAX_DECISIONS, MAX_AGE_SECONDS, matched_receipt,
                       transfer_review, rotation_review, decision_review, ZERO)
from validator_witness import nanos

APPLICATION_ID = 0x31504157
MAX_OBSERVATIONS = 4096
MAX_REFERENCE_BYTES = 2048
MAX_PAYLOAD = 16*1024*1024
REFERENCE_FORMAT = '1soft/p4-alpha-wallet-checkpoint-reference/v1'

class P4AlphaWallet(P4Wallet):
    def __init__(self,path,genesis_bytes,policy,store,*,create=False,clock=time.time_ns):
        need(type(create) is bool,'explicit alpha wallet creation mode required')
        self._policy_bytes=encode(policy_v2_checked(policy));self.policy_id=content_id(self.policy)
        self.genesis=bytes(genesis_bytes);g,_=p4_genesis(self.genesis,self.policy['genesis_sha256'])
        need(g.get('development_profile')==DURABLE_PROFILE,'alpha wallet requires explicit fresh alpha genesis')
        self.height_limit=max_height_for(g);self.store=store;self.store_id=hash_text(store.store_id)
        need(bytes(store.genesis)==self.genesis and encode(store.policy)==self._policy_bytes,
             'wallet history genesis or immutable policy differs')
        self.clock=clock;self.db=None;self.path=private_path(path);self._active_checkpoint=None
        if create:
            now=self.clock();check_clock(self.policy,now)
            fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        else:need(self.path.is_file(),'alpha wallet is not initialized; no implicit creation')
        try:
            self.db=sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,isolation_level=None,timeout=5)
            if create:
                self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
                with self.atomic():
                    self.db.execute(f'PRAGMA application_id={APPLICATION_ID}')
                    self.db.execute('CREATE TABLE config(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL,wallet_id TEXT NOT NULL,policy BLOB NOT NULL,created_ns INTEGER NOT NULL,store_id TEXT NOT NULL)')
                    self.db.execute('CREATE TABLE observations(seq INTEGER PRIMARY KEY,evidence_id TEXT UNIQUE NOT NULL,parent_id TEXT NOT NULL,checked_ns INTEGER NOT NULL,payload BLOB NOT NULL)')
                    self.db.execute('CREATE TABLE decisions(seq INTEGER PRIMARY KEY,decision_id TEXT UNIQUE NOT NULL,signed_ns INTEGER NOT NULL,payload BLOB NOT NULL)')
                    self.db.execute('INSERT INTO config VALUES (1,2,?,?,?,?)',(secrets.token_hex(32),self._policy_bytes,now,self.store_id))
                fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(fd)
                finally:os.close(fd)
            self._catalog();need(self.db.execute('PRAGMA journal_mode').fetchone()[0]=='wal','alpha wallet journal mode differs')
            self.db.execute('PRAGMA synchronous=FULL')
        except BaseException:self.close();raise

    def _catalog(self):
        private_path(self.path)
        need(self.db.execute('PRAGMA application_id').fetchone()[0]==APPLICATION_ID,'not an alpha wallet; no migration or repair')
        objects=set(self.db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
        need(objects=={('table','config'),('table','observations'),('table','decisions')},'unexpected alpha wallet schema')
        columns={'config':('id','version','wallet_id','policy','created_ns','store_id'),
                 'observations':('seq','evidence_id','parent_id','checked_ns','payload'),
                 'decisions':('seq','decision_id','signed_ns','payload')}
        for table,names in columns.items():
            need(tuple(x[1] for x in self.db.execute(f'PRAGMA table_info({table})'))==names,'alpha wallet columns differ')
        rows=self.db.execute('SELECT * FROM config').fetchall()
        need(len(rows)==1 and rows[0][:2]==(1,2) and rows[0][3]==self._policy_bytes
             and rows[0][5]==self.store_id,'alpha wallet immutable configuration differs')
        wallet_id,created=hash_text(rows[0][2]),integer(rows[0][4])
        for table,limit in [('observations',MAX_OBSERVATIONS),('decisions',MAX_DECISIONS)]:
            count,size=self.db.execute(f'SELECT count(*),coalesce(sum(length(payload)),0) FROM {table}').fetchone()
            need(count<=limit and size<=MAX_PAYLOAD,'alpha wallet storage quota exceeded')
        for suffix in ('','-wal','-shm'):
            p=Path(str(self.path)+suffix)
            if p.exists():need(p.stat().st_size<=64*1024*1024,'alpha wallet physical quota exceeded')
        obs=self.db.execute('SELECT * FROM observations ORDER BY seq').fetchall()
        previous,prior_ns,prior_h=ZERO,created,-1
        for n,(seq,eid,parent,checked,raw) in enumerate(obs,1):
            integer(seq,n,n);hash_text(eid);integer(checked,prior_ns)
            need(parent==previous and type(raw) is bytes and 0<len(raw)<=MAX_REFERENCE_BYTES,'alpha reference lineage or size differs')
            ref=load_json(raw,max_bytes=MAX_REFERENCE_BYTES)
            exact(ref,{'schema','format','checkpoint_id','store_id','height'},'wallet checkpoint reference')
            integer(ref['schema'],1,1);integer(ref['height'],0,self.height_limit)
            need(encode(ref)==raw and ref['format']==REFERENCE_FORMAT and ref['checkpoint_id']==eid
                 and ref['store_id']==self.store_id and ref['height']>prior_h,'alpha wallet reference changed')
            previous,prior_ns,prior_h=eid,checked,ref['height']
        decisions=[];prior_ns=created
        for n,(seq,did,signed,raw) in enumerate(self.db.execute('SELECT * FROM decisions ORDER BY seq'),1):
            integer(seq,n,n);integer(signed,prior_ns);hash_text(did)
            need(type(raw) is bytes and 0<len(raw)<=32768,'invalid original decision bytes')
            d=load_json(raw,max_bytes=32768);exact(d,{'id','review','wire_hex','signed_ns'},'original alpha signing decision')
            need(encode(d)==raw and d['id']==did==content_id(d['review']) and type(d['signed_ns']) is int
                 and d['signed_ns']==signed,'alpha original decision identity changed')
            need(type(d['wire_hex']) is str and len(d['wire_hex'])<=32768 and bytes.fromhex(d['wire_hex']).hex()==d['wire_hex'],'invalid original signed wire')
            decisions.append(d);prior_ns=signed
        latest=max([created]+[x[3] for x in obs]+[d['signed_ns'] for d in decisions])
        return wallet_id,obs,decisions,latest

    def _origin_fresh(self,context,checkpoint,now,previous_ns=None):
        need(context['format']==CONTEXT_FORMAT and context['checkpoint_id']==checkpoint['id']
             and context['store_id']==self.store_id and context['policy_id']==self.policy_id,
             'authenticated monetary context binding differs')
        check_clock(self.policy,now,previous_ns,checkpoint=checkpoint)
        tip=nanos(context['lookahead']['signed_header']['header']['time'])
        need(tip==checkpoint['lookahead_time_ns'] and now-MAX_AGE_SECONDS*10**9<=tip
             <=now+self.policy['max_clock_drift_seconds']*10**9,'signing requires a recent authenticated checkpoint')
        need(context['state']['height']<self.height_limit,'explicit alpha height ceiling reached')

    def _fresh(self,context,now,previous_ns=None):
        view=self.store.checkpoint_at(context['checkpoint_id'],historical=True)
        need(encode(view['context']['state'])==encode(context['state'])
             and encode(view['context']['lookahead'])==encode(context['lookahead']),
             'monetary context differs from retained original execution')
        self.store.check_current(context['checkpoint_id'],now=now,previous_ns=previous_ns)
        self._origin_fresh(context,view['checkpoint'],now,previous_ns)

    def _check_clock(self,now,previous_ns=None):
        if self._active_checkpoint is None:return check_clock(self.policy,now,previous_ns)
        return self.store.check_current(self._active_checkpoint,now=now,previous_ns=previous_ns)

    def _transfer_review(self,*args,**kwargs):return transfer_review(*args,**kwargs,height_limit=self.height_limit)
    def _rotation_review(self,*args,**kwargs):return rotation_review(*args,**kwargs,height_limit=self.height_limit)
    def _decision_review(self,*args,**kwargs):return decision_review(*args,**kwargs,height_limit=self.height_limit)

    def _load(self,*,historical=False):
        wallet_id,obs,decisions,latest=self._catalog();need(obs,'no authenticated alpha wallet checkpoint')
        descriptors=self.store.checkpoint_descriptors();byid={x[1]:x for x in obs}
        for row in obs:
            need(row[1] in descriptors,'wallet origin checkpoint is missing')
            cp=descriptors[row[1]];ref=load_json(row[4],max_bytes=MAX_REFERENCE_BYTES)
            need(cp['height']==ref['height'] and cp['store_id']==self.store_id and cp['policy_id']==self.policy_id,
                 'wallet reference differs from original checkpoint')
            integer(row[3],cp['checked_ns'])
        ids=[d['review']['evidence_id'] for d in decisions]+[obs[-1][1]]
        views=self.store.checkpoint_batch(ids,historical=True);last_seq=0
        for n,d in enumerate(decisions):
            review=d['review'];eid=review['evidence_id'];need(eid in byid,'original signing context is missing')
            row=byid[eid];integer(d['signed_ns'],row[3]);need(row[0]>=last_seq,'signing context moved backwards');last_seq=row[0]
            v=views[eid];e,r=v['context'],v['report']
            self._origin_fresh(e,v['checkpoint'],d['signed_ns'],row[3])
            expected=self._decision_review(e,r,decisions[:n],wallet_id,self.policy_id,review,self.policy['genesis_sha256'],d['signed_ns'])
            need(encode(expected)==encode(review),'original review differs from authenticated signing context')
            raw=bytes.fromhex(d['wire_hex']);packet=load_json(raw,max_bytes=16384)
            exact(packet,{'body','signature'},'original signed alpha decision')
            need(canonical(packet)==raw and packet['body']==review['body'],'original signed wire differs from review')
            try:Ed25519PublicKey.from_public_bytes(bytes.fromhex(review['signer_public_key'])).verify(bytes.fromhex(packet['signature']),DOMAIN+canonical(packet['body']))
            except (InvalidSignature,ValueError) as exc:raise ValueError('original alpha signature is invalid') from exc
            ledger=restore(e['state']['genesis'],e['state']['native'])
            try:ledger.apply(packet,height=r['state_height']+1)
            finally:ledger.close()
        latest_view=views[obs[-1][1]];e,r=latest_view['context'],latest_view['report'];self._active_checkpoint=obs[-1][1]
        for d in decisions:matched_receipt(r,d)
        if not historical:
            now=self.clock();check_clock(self.policy,now,latest,checkpoint=latest_view['checkpoint'])
            # Current display can retain a valid older checkpoint; signing additionally requires freshness.
            r=dict(r,checked_at_ns=now,historical_context=False)
            check_clock(self.policy,self.clock(),now,checkpoint=latest_view['checkpoint'])
        return wallet_id,e,r,decisions,latest

    def sync(self,checkpoint_id,*,expected_revision):
        hash_text(checkpoint_id)
        with self.atomic():
            wid,obs,ds,latest=self._catalog();now=self.clock()
            if obs:
                wid,oldctx,old,ds,latest=self._load(historical=True)
                need(expected_revision==self._revision(wid,old,ds),'reviewed wallet revision changed')
            else:need(not ds and expected_revision is None,'initial alpha revision must be empty')
            self.store.check_current(checkpoint_id,now=now,previous_ns=latest)
            v=self.store.current(now=now,checkpoint_id=checkpoint_id);r,cp=v['report'],v['checkpoint']
            if obs:
                need(cp['height']>=old['state_height'],'wallet checkpoint moved backward')
                if cp['id']==old['evidence_id']:
                    self.store.check_current(checkpoint_id,now=self.clock(),previous_ns=now)
                    return {'status':'already_recorded','revision':self._revision(wid,old,ds)}
                need(cp['height']>old['state_height'],'different same-height wallet checkpoint refused')
            for d in ds:matched_receipt(r,d)
            need(len(obs)<MAX_OBSERVATIONS,'alpha wallet observation capacity reached; no eviction')
            ref=encode({'schema':1,'format':REFERENCE_FORMAT,'checkpoint_id':cp['id'],'store_id':self.store_id,'height':cp['height']})
            checked=self.clock();self.store.check_current(checkpoint_id,now=checked,previous_ns=max(now,latest))
            self.db.execute('INSERT INTO observations VALUES (?,?,?,?,?)',(len(obs)+1,cp['id'],obs[-1][1] if obs else ZERO,checked,ref))
            self._active_checkpoint=cp['id']
        return {'status':'checkpoint_recorded','revision':self._revision(wid,r,ds),'state_height':cp['height'],'signing_performed':False}

    def rotation_status(self,decision_id,*,payer,evidence):
        # The old full-proof interface cannot authorize the new reference profile.
        raise ValueError('alpha rotation status uses authenticated wallet status and retained receipts; legacy full evidence refused')
