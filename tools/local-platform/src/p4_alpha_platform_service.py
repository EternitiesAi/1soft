"""Explicit finite alpha composition, with one original financial journal.

Read-history advancement is separate from wallet assimilation and authority.
Historical wallet balances retain obligations; they do not authorize spending.
"""
import hashlib
import hmac
import os
import sqlite3
import tempfile
from contextlib import contextmanager
from pathlib import Path
import time
from block_application import encode
from commit_verifier import load_json,exact
from p4_evidence import content_id,hash_text,integer,need
from p4_incremental_evidence import policy_v2_checked
from p4_incremental_store import P4IncrementalStore
from p4_alpha_wallet import P4AlphaWallet
from p4_alpha_delivery import P4AlphaDelivery
from p4_read_store import private_path
from p4_explorer import project_report
from payment_rpc import endpoint_port
from payment_requests import RequestBook
from platform_service import PlatformService,checked_roles,HISTORY_BLOCK_BYTES
from offline_signer import _password

RECEIPT_CATALOG_ID=0x31504143
MAX_CAPSULES=256

class AlphaReceiptCatalog:
    """Small inert references; exact original delivery history remains authority."""
    def __init__(self,path,*,create=False):
        self.path=private_path(path);self.db=None
        if create:
            fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        else:need(self.path.is_file(),'alpha receipt catalog is not initialized')
        try:
            self.db=sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,isolation_level=None)
            if create:
                self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
                self.db.execute('BEGIN IMMEDIATE')
                self.db.execute(f'PRAGMA application_id={RECEIPT_CATALOG_ID}')
                self.db.execute('CREATE TABLE references_v1(capsule_id TEXT PRIMARY KEY,payload BLOB NOT NULL)')
                self.db.execute('COMMIT')
                fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(fd)
                finally:os.close(fd)
            self.entries()
        except BaseException:self.close();raise
    def close(self):
        if self.db is not None:self.db.close();self.db=None
    def entries(self):
        private_path(self.path)
        need(self.db.execute('PRAGMA application_id').fetchone()[0]==RECEIPT_CATALOG_ID,'alpha reference catalog identity differs')
        need(set(self.db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))=={('table','references_v1')},'alpha reference catalog schema differs')
        need(tuple(r[1] for r in self.db.execute('PRAGMA table_info(references_v1)'))==('capsule_id','payload'),'alpha reference catalog columns differ')
        for suffix in ('','-wal','-shm'):
            p=Path(str(self.path)+suffix)
            if p.exists():need(p.stat().st_size<=4*1024*1024,'alpha reference catalog physical quota exceeded')
        rows=self.db.execute('SELECT * FROM references_v1 ORDER BY capsule_id').fetchmany(MAX_CAPSULES+1)
        need(len(rows)<=MAX_CAPSULES,'alpha reference catalog capacity exceeded')
        result={}
        for cid,raw in rows:
            need(type(raw) is bytes and 0<len(raw)<=4096,'bounded alpha reference required')
            ref=load_json(raw,max_bytes=4096)
            exact(ref,{'schema','format','genesis_sha256','policy_id','store_id','checkpoint_id','wire_sha256','payer','decision_id'},'alpha receipt reference')
            integer(ref['schema'],1,1);need(ref['format']=='1soft/p4-alpha-receipt-reference/v1','alpha reference format differs')
            for name in ('genesis_sha256','policy_id','store_id','checkpoint_id','wire_sha256','decision_id'):hash_text(ref[name])
            need(encode(ref)==raw and cid==content_id(ref),'alpha reference identity differs')
            result[cid]=ref
        return result
    def put(self,ref):
        cid=content_id(ref);raw=encode(ref);need(len(raw)<=4096,'bounded alpha reference required')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            rows=self.entries()
            if cid not in rows:
                need(len(rows)<MAX_CAPSULES,'alpha reference catalog capacity reached; no eviction')
                self.db.execute('INSERT INTO references_v1 VALUES(?,?)',(cid,raw))
            else:need(encode(rows[cid])==raw,'retained alpha reference changed')
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise
        return {'status':'historical_receipt_reference_retained','capsule_id':cid,'wallet_reservations_changed':False}

class AlphaPlatformService(PlatformService):
    def __init__(self,workspace,genesis_bytes,policy,endpoint,roles,*,create=False,clock=time.time_ns,store=None):
        need(type(create) is bool,'explicit alpha creation mode required')
        self.root=Path(workspace).absolute();self.clock=clock
        self.genesis=bytes(genesis_bytes);self.policy=policy_v2_checked(policy)
        endpoint_port(endpoint);self.endpoint=endpoint;self.roles=checked_roles(roles,self.root)
        self.wallet=self.delivery=self.store=self.book=self.receipts=None;self._owns_store=store is None
        self.paths={n:private_path(self.root/(n+'.sqlite')) for n in ('wallet','delivery','ledger','requests','receipts')}
        if create:
            checked=[p for n,p in self.paths.items() if n!='ledger' or store is None]
            need(all(not p.exists() and not any(Path(str(p)+s).exists() for s in ('-wal','-shm','-journal')) for p in checked),'alpha workspace contains journals; no overwrite or repair')
        try:
            if store is None:self.store=P4IncrementalStore(self.paths['ledger'],self.genesis,self.policy,create=create,clock=clock)
            else:
                need(type(store) is P4IncrementalStore and store.path==self.paths['ledger'] and store.genesis==self.genesis and encode(store.policy)==encode(self.policy),'borrowed alpha store differs')
                self.store=store
            self.wallet=P4AlphaWallet(self.paths['wallet'],self.genesis,self.policy,self.store,create=create,clock=clock)
            self.delivery=P4AlphaDelivery(self.paths['wallet'],self.paths['delivery'],self.genesis,self.policy,self.endpoint,self.store,create=create,clock=clock)
            self.book=RequestBook(self.paths['requests'],self.policy['genesis_sha256'],create=create,clock=clock)
            self.receipts=AlphaReceiptCatalog(self.paths['receipts'],create=create)
        except BaseException:self.close();raise
    def close(self):
        for name in ('receipts','book','delivery','wallet'):
            obj=getattr(self,name,None)
            if obj is not None:obj.close();setattr(self,name,None)
        if self.store is not None:
            if self._owns_store:self.store.close()
            self.store=None
    def import_checkpoint(self,segment,*,expected_tip):
        result=self.store.import_segment(segment,expected_tip=expected_tip)
        return {'status':result['status'],'checkpoint':result['checkpoint'],'report':result['report'],'wallet_reservations_changed':False}
    def refresh(self,*,expected_tip):
        result=self.store.collect(self.endpoint,expected_tip=expected_tip)
        return {'status':result['status'],'checkpoint':result['checkpoint'],'report':result['report'],
                'rpc_requests':result['rpc_requests'],'captured_source_height':result['captured_source_height'],
                'submission_performed':False,'wallet_reservations_changed':False}
    def sync(self,*,expected_revision):
        current=self.store.current();need(current is not None,'authenticated alpha checkpoint unavailable')
        return self.wallet.sync(current['checkpoint']['id'],expected_revision=expected_revision)
    def _receipt_references(self):
        from p4_alpha_custody import receipt_reference
        rows=self.receipts.entries()
        for ref in rows.values():
            with self.wallet.atomic(write=False):
                _,_,_,ds,_=self.wallet._load(historical=True)
            match=[d for d in ds if d['id']==ref['decision_id']];need(len(match)==1,'orphaned alpha receipt reference')
            body=match[0]['review']['body']
            expected=receipt_reference(self.delivery,ref['decision_id'],payer=body['sender'],grant_id=body['grant_id'])
            need(encode(expected)==encode(ref),'retained alpha receipt differs from original history')
        return rows
    def retain_receipt(self,rid):
        from p4_alpha_custody import receipt_reference
        entry,selection=self._selection(rid)
        ref=receipt_reference(self.delivery,entry['decision_id'],**selection)
        return self.receipts.put(ref)
    def capsule(self,rid,capsule_id):
        from p4_alpha_custody import make_receipt
        hash_text(capsule_id);entry,selection=self._selection(rid)
        refs=self._receipt_references();need(capsule_id in refs,'retained alpha capsule unavailable')
        ref=refs[capsule_id]
        need(ref['decision_id']==entry['decision_id'] and ref['payer']==selection['payer'] and ref['wire_sha256']==hashlib.sha256(self.recover(rid)).hexdigest(),'selected alpha receipt differs')
        return make_receipt(self.delivery,entry['decision_id'],checkpoint_id=ref['checkpoint_id'],**selection)
    @contextmanager
    def backup_history(self,password):
        from p4_alpha_custody import backup,MAGIC,MAX_BACKUP_BYTES
        from p4_custody import _private_source
        _password(password)
        with tempfile.TemporaryDirectory(prefix='.1soft-alpha-history-',dir=self.root) as folder:
            output=Path(folder)/'history.p4alpha';result=backup(self.delivery,output,password)
            with _private_source(output,MAX_BACKUP_BYTES) as source:
                size=0;digest=hashlib.sha256()
                while raw:=source.read(HISTORY_BLOCK_BYTES):size+=len(raw);need(size<=MAX_BACKUP_BYTES,'alpha history output exceeds bound');digest.update(raw)
                need(0<size<=MAX_BACKUP_BYTES and size==os.fstat(source.fileno()).st_size and hmac.compare_digest(digest.hexdigest(),result['backup_sha256']),'alpha history output differs')
                source.seek(0);need(source.read(len(MAGIC))==MAGIC,'alpha history format differs');source.seek(0)
                yield {'source':source,'size':size,'sha256':digest.hexdigest(),'format':'alpha-v1'}
    def state(self):
        # This read preserves older original holdings even if their authority expired.
        entries=self.book.entries();wallet=self.wallet.historical_status()
        with self.wallet.atomic(write=False):_,_,_,decisions,_=self.wallet._load(historical=True)
        byid={d['id']:d for d in decisions};view=None
        try:view=self.store.current()
        except ValueError:pass
        current=view is not None
        # Revision is an opaque content ID. Compare the authenticated original wallet context instead.
        with self.wallet.atomic(write=False):_,context,_,_,latest=self.wallet._load(historical=True)
        wallet_current=current and context['checkpoint_id']==view['checkpoint']['id']
        ready=False
        if wallet_current:
            try:self.wallet._fresh(context,self.clock(),latest);ready=True
            except ValueError:pass
        wallet={**wallet,'historical_context':not wallet_current,'current_spending_authority':False}
        ledger=project_report(view['report'],self.genesis,self.policy) if current else None
        refs=self._receipt_references();requests=[];now=integer(self.clock(),1)
        for entry in entries:
            did=entry['decision_id'];stage='request_open' if did is None else 'review_bound_unsigned';delivery=None;capsules=[]
            if did in byid:
                need(encode(byid[did]['review'])==encode(entry['review']),'request decision review differs')
                stage=next(d['status'] for d in wallet['decisions'] if d['id']==did)
                if stage=='pending':stage='signed_reserved'
                body=entry['review']['body'];delivery=self.delivery.inspect(did,payer=body['sender'],grant_id=body['grant_id'])
                capsules=[cid for cid,ref in refs.items() if ref['decision_id']==did]
            req=entry['request'];requests.append({'request_id':entry['request_id'],'request':req,'decision_id':did,'stage':stage,
                'request_open':req['created_ns']<=now<req['expires_ns'],'delivery':delivery,'capsule_ids':capsules,'current_spending_authority':False})
        return {'schema':1,'format':'1soft/local-platform-state/v1','asset':'DEV','development_profile':'durable-private-alpha-v1',
            'current_evidence_available':current,'wallet_current':wallet_current,'signing_ready':ready,'wallet':wallet,'ledger':ledger,'requests':requests,
            'roles':{k:{'payer':v['payer'],'grant_id':v['grant_id']} for k,v in self.roles.items()},
            'genesis_sha256':self.policy['genesis_sha256'],'policy_id':content_id(self.policy),
            'limits':{'rpc_height':4096,'offline_height':4096,'rpc_batch_blocks':64,'wallet_observations':4096,'wallet_decisions':256,'requests':64,
                'receipt_capsules':256,'checkpoint_progression':True,'trust_renewal':False,'absolute_not_after_ns':self.policy['absolute_not_after_ns']},
            'real_funds_supported':False,'automatic_resend':False,'public_deployment':False}
