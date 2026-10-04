"""Composition of the pinned P4 components, with one financial journal.

The request book correlates local intent. Only P4Wallet reserves funds, only
P4Delivery claims an attempt, and only verified exact execution retires a hold.
No alternate signer, network retry, trust renewal or journal migration exists.
"""
import hashlib
import hmac
import os
from contextlib import contextmanager
from pathlib import Path
import tempfile
import time

from block_application import encode
from native_core import identifier
from p4_evidence import (check_clock, content_id, freeze, hash_text, integer,
                         need, policy_checked, verify_evidence)
from p4_read_store import P4ReadStore, private_path
from p4_wallet import P4Wallet, matched_receipt
from p4_delivery import P4Delivery
from payment_rpc import endpoint_port
from p4_delivery import collect_evidence
from p4_explorer import project_report
from p4_receipt_capsule import make_capsule, encode_capsule
from p4_receipt_archive import P4ReceiptArchive
from payment_requests import RequestBook, parse_request
from offline_signer import _password

HISTORY_CAPTURE_BYTES=8*1024*1024
HISTORY_BACKUP_BYTES=16*1024*1024
HISTORY_BLOCK_BYTES=65536


def checked_roles(roles, workspace):
    need(type(roles) is dict and 1<=len(roles)<=8, 'bounded fixed roles required')
    checked={}; lanes=set(); vaults=set()
    for name,row in roles.items():
        identifier(name)
        need(type(row) is dict and set(row)=={'payer','grant_id','vault'}, 'invalid role fields')
        identifier(row['payer']); grant=row['grant_id']
        need(type(grant) is str, 'explicit role required')
        if grant: identifier(grant)
        vault=row['vault']
        need(type(vault) is str and vault.endswith('.pem') and
             vault==Path(vault).name and '/' not in vault and '\\' not in vault and
             not vault.startswith('.') and len(vault)<=64, 'fixed vault filename required')
        lane=(row['payer'],grant)
        need(lane not in lanes and vault not in vaults, 'role or vault alias refused')
        private_path(Path(workspace)/vault)
        need((Path(workspace)/vault).is_file(), 'development vault is missing')
        lanes.add(lane);vaults.add(vault);checked[name]=dict(row)
    return checked


class PlatformService:
    def __init__(self,workspace,genesis_bytes,policy,endpoint,roles,*,create=False,clock=time.time_ns,
                 approval_factory=None):
        need(type(create) is bool, 'invalid creation mode')
        need(approval_factory is None or callable(approval_factory), 'invalid approval factory')
        self.root=Path(workspace).absolute();self.clock=clock
        self.genesis=bytes(genesis_bytes);self.policy=policy_checked(policy)
        endpoint_port(endpoint);self.endpoint=endpoint;self.roles=checked_roles(roles,self.root)
        self.wallet=self.delivery=self.store=self.book=None
        self.approval=None
        self.paths={name:private_path(self.root/(name+'.sqlite'))
                    for name in ('wallet','delivery','ledger','requests','receipts')}
        if create:
            need(all(not p.exists() and not any(Path(str(p)+s).exists()
                 for s in ('-wal','-shm','-journal')) for p in self.paths.values()),
                 'workspace already contains journals; no overwrite or repair')
        try:
            self.wallet=P4Wallet(self.paths['wallet'],self.genesis,self.policy,create=create,clock=clock)
            self.delivery=P4Delivery(self.paths['wallet'],self.paths['delivery'],self.genesis,
                                     self.policy,self.endpoint,create=create,clock=clock)
            self.store=P4ReadStore(self.paths['ledger'],self.genesis,self.policy,create=create,clock=clock)
            self.book=RequestBook(self.paths['requests'],self.policy['genesis_sha256'],create=create,clock=clock)
            if create:
                with P4ReceiptArchive(self.paths['receipts'],self.genesis,self.policy,
                                     now_ns=self.clock(),create=True):pass
            else:
                need(self.paths['receipts'].is_file(),'receipt archive is not initialized')
            if approval_factory is not None:
                self.approval=approval_factory(self.wallet)
                need(self.approval is not None and
                     getattr(self.approval,'wallet',None) is self.wallet and
                     callable(getattr(self.approval,'approve',None)) and
                     callable(getattr(self.approval,'reconcile',None)),
                     'invalid fenced approval adapter')
        except BaseException:self.close();raise

    def close(self):
        approval=getattr(self,'approval',None);self.approval=None
        try:
            if approval is not None:
                close=getattr(approval,'close',None)
                if callable(close):close()
        finally:
            for name in ('book','store','delivery','wallet'):
                obj=getattr(self,name,None)
                if obj is not None:obj.close();setattr(self,name,None)
    def __enter__(self):return self
    def __exit__(self,*_):self.close()

    @contextmanager
    def backup_history(self,password):
        """Complete private format-3 history; the owned file lives only while streamed."""
        _password(password)
        from p4_custody import backup, _private_source
        with tempfile.TemporaryDirectory(prefix='.1soft-history-',dir=self.root) as folder:
            output=Path(folder)/'history.p4b3'
            result=backup(self.delivery,output,password,format_version=3,
                max_capture_blob_bytes=HISTORY_CAPTURE_BYTES,max_backup_bytes=HISTORY_BACKUP_BYTES)
            with _private_source(output,HISTORY_BACKUP_BYTES) as source:
                digest=hashlib.sha256();size=0
                while True:
                    raw=source.read(HISTORY_BLOCK_BYTES)
                    if not raw:break
                    size+=len(raw);need(size<=HISTORY_BACKUP_BYTES,'history output exceeds browser bound')
                    digest.update(raw)
                need(0<size<=HISTORY_BACKUP_BYTES and size==os.fstat(source.fileno()).st_size and
                     hmac.compare_digest(digest.hexdigest(),result['backup_sha256']),
                     'complete history output differs')
                source.seek(0);need(source.read(10)==b'1SOFTP4B3\n','history format differs');source.seek(0)
                yield {'source':source,'size':size,'sha256':digest.hexdigest()}

    def _role(self,name):
        need(type(name) is str and name in self.roles, 'unknown fixed role')
        return self.roles[name]

    def _selection(self,rid):
        entry=self.book.selected(rid);need(entry['decision_id'] is not None,'request has no signed decision')
        body=entry['review']['body']
        role=[r for r in self.roles.values() if r['payer']==body['sender'] and r['grant_id']==body['grant_id']]
        need(len(role)==1, 'saved decision role differs')
        selection=dict(payer=role[0]['payer'],grant_id=role[0]['grant_id'])
        # An unsigned request binding never masquerades as a signing decision.
        self.wallet.recover(entry['decision_id'],**selection)
        return entry,selection

    def add_request(self,value):return self.book.add(value)

    def prepare(self,rid,role,*,valid_until,invoice_terms=None):
        row=self._role(role);entry=self.book.selected(rid)
        req=parse_request(entry['request'],self.policy['genesis_sha256'],now_ns=self.clock())
        prepared=self.wallet.prepare(payer=row['payer'],recipient=req['recipient'],
            units=int(req['units']),valid_until=valid_until,grant_id=row['grant_id'],invoice_terms=invoice_terms)
        if entry['review'] is not None:
            need(encode(entry['review'])==encode(prepared['review']),
                 'request is bound to an earlier review; inspect original decision')
        return {**prepared,'request_id':rid,'role':role}

    def approve(self,rid,role,review,confirmation,*,password):
        row=self._role(role);entry=self.book.selected(rid);value=freeze(review,32768)
        approval=getattr(self,'approval',None)
        hash_text(confirmation)
        need(hmac.compare_digest(content_id(value),confirmation),'review confirmation differs')
        body=value['body']
        need(body['sender']==row['payer'] and body['grant_id']==row['grant_id'],'reviewed role differs')
        # Recovery after a committed signature does not open the vault or repeat signing.
        with self.wallet.atomic(write=False):
            _,_,_,decisions,_=self.wallet._load(historical=True)
            previous=[d for d in decisions if d['id']==confirmation]
            if previous:
                need(len(previous)==1 and entry['decision_id']==confirmation and
                     encode(previous[0]['review'])==encode(value)==encode(entry['review']),
                     'saved decision binding differs')
        if previous:
            # Reconciliation opens its own historical read transaction, after the
            # decision audit above has released this wallet transaction.
            if approval is not None:
                outcome=approval.reconcile(value,confirmation,request_id=rid)
                need(type(outcome) is dict and outcome.get('status') in
                     {'reconciled','already_reconciled','unfenced_decision'},
                     'fence reconciliation is not confirmed')
            result={'status':'original_signed_decision_retained','decision_id':confirmation,
                    'broadcast':False,'signing_performed':False}
            if approval is not None:
                result.update(fence_status=outcome['status'],fence_request_id=rid)
            return result
        current=self.prepare(rid,role,valid_until=body['valid_until'],invoice_terms=value.get('invoice_terms'))
        need(encode(current['review'])==encode(value) and current['confirmation']==confirmation,
             'wallet or requested payment changed; review again')
        self.book.bind_review(rid,value)  # Durable correlation before any key access.
        if approval is None:
            result=self.wallet.approve(value,confirmation,vault=self.root/row['vault'],password=password)
        else:
            result=approval.approve(value,confirmation,vault=self.root/row['vault'],password=password,
                                    request_id=rid)
            need(type(result) is dict and result.get('fence_status')=='decision_committed' and
                 result.get('request_id')==rid,'fenced approval outcome is not confirmed')
        response={'status':result['status'],'decision_id':result['decision_id'],
                  'wire_sha256':hashlib.sha256(self.recover(rid)).hexdigest(),'broadcast':False}
        if approval is not None:
            response.update(fence_status=result['fence_status'],fence_request_id=rid)
        return response

    def recover(self,rid):
        entry,selection=self._selection(rid)
        return self.wallet.recover(entry['decision_id'],**selection)

    def submission_review(self,rid):
        entry,selection=self._selection(rid)
        return {**self.delivery.prepare(entry['decision_id'],**selection),'request_id':rid}

    def submit(self,rid,review,confirmation):
        entry,selection=self._selection(rid);value=freeze(review,32768)
        need(value['decision_id']==entry['decision_id'] and value['payer']==selection['payer'] and
             value['grant_id']==selection['grant_id'],'submission selection differs')
        return self.delivery.send(value,confirmation)

    def collect(self,rid):
        entry,selection=self._selection(rid)
        return self.delivery.collect(entry['decision_id'],**selection)

    def reconcile(self,rid,*,expected_revision):
        entry,selection=self._selection(rid)
        return self.delivery.reconcile(entry['decision_id'],expected_revision=expected_revision,**selection)

    def retain_receipt(self,rid):
        entry,selection=self._selection(rid);raw=self.recover(rid)
        evidence=self.delivery.export_receipt(entry['decision_id'],**selection)
        now=self.clock()
        capsule=make_capsule(evidence,self.genesis,self.policy,raw,payer=selection['payer'],now_ns=now)
        with P4ReceiptArchive(self.paths['receipts'],self.genesis,self.policy,now_ns=self.clock()) as archive:
            return archive.put(capsule,now_ns=self.clock(),expected_payer=selection['payer'],
                               expected_wire_sha256=hashlib.sha256(raw).hexdigest())

    def capsule(self,rid,capsule_id):
        _,selection=self._selection(rid);wire_hash=hashlib.sha256(self.recover(rid)).hexdigest()
        with P4ReceiptArchive(self.paths['receipts'],self.genesis,self.policy,
                             now_ns=self.clock(),read_only=True) as archive:
            return encode_capsule(archive.get(capsule_id,now_ns=self.clock(),
                expected_payer=selection['payer'],expected_wire_sha256=wire_hash))

    def import_checkpoint(self,evidence,*,expected_tip):
        result=self.store.import_evidence(evidence,expected_tip=expected_tip)
        return {**result,'wallet_reservations_changed':False}

    def refresh(self,*,expected_tip):
        now=self.clock();check_clock(self.policy,now)
        result=collect_evidence(self.endpoint,self.genesis,self.policy,now)
        saved=self.import_checkpoint(result['evidence'],expected_tip=expected_tip)
        return {**saved,'rpc_requests':result['rpc_requests'],'submission_performed':False}

    def sync(self,*,expected_revision):
        current=self.store.current();need(current is not None,'verified ledger checkpoint unavailable')
        return self.wallet.sync(self.store.export(current['evidence_id']),expected_revision=expected_revision)

    def state(self):
        # GET never collects evidence or writes an observation/decision/attempt.
        entries=self.book.entries()
        with self.wallet.atomic(write=False):
            _,_,historical_report,decisions,_=self.wallet._load(historical=True)
        by_id={d['id']:d for d in decisions}
        try:
            wallet=self.wallet.status();report=self.store.current()
            ledger=None if report is None else project_report(report,self.genesis,self.policy)
            current=True
        except ValueError:
            wallet=None;ledger=None;current=False
        status={} if wallet is None else {d['id']:d['status'] for d in wallet['decisions']}
        requests=[];now=integer(self.clock(),1)
        for entry in entries:
            did=entry['decision_id'];stage='request_open' if did is None else 'review_bound_unsigned'
            delivery=None;capsules=[]
            if did in by_id:
                need(encode(by_id[did]['review'])==encode(entry['review']),'request decision review differs')
                stage='recorded' if status.get(did)=='recorded' else (
                    'recorded_historical' if not current and matched_receipt(historical_report,by_id[did]) is not None else 'signed_reserved')
                body=entry['review']['body'];selection=dict(payer=body['sender'],grant_id=body['grant_id'])
                delivery=self.delivery.inspect(did,**selection)
                if current:
                    wire_hash=hashlib.sha256(bytes.fromhex(by_id[did]['wire_hex'])).hexdigest()
                    with P4ReceiptArchive(self.paths['receipts'],self.genesis,self.policy,
                                         now_ns=self.clock(),read_only=True) as archive:
                        ids=[r[0] for r in archive.db.execute('SELECT capsule_id FROM capsules WHERE wire_sha256=?',(wire_hash,))]
                        for cid in ids:
                            archive.inspect(cid,now_ns=self.clock(),expected_payer=body['sender'],
                                            expected_wire_sha256=wire_hash)
                            capsules.append(cid)
            req=entry['request']
            requests.append({'request_id':entry['request_id'],'request':req,'decision_id':did,
                'stage':stage,'request_open':req['created_ns']<=now<req['expires_ns'],
                'delivery':delivery,'capsule_ids':capsules,'current_spending_authority':False})
        return {'schema':1,'format':'1soft/local-platform-state/v1','asset':'DEV',
            'current_evidence_available':current,'wallet':wallet,'ledger':ledger,'requests':requests,
            'roles':{k:{'payer':v['payer'],'grant_id':v['grant_id']} for k,v in self.roles.items()},
            'genesis_sha256':self.policy['genesis_sha256'],'policy_id':content_id(self.policy),
            'limits':{'rpc_height':64,'offline_height':512,'wallet_observations':32,'wallet_decisions':256,
                      'requests':64,'receipt_capsules':32,'trust_renewal':False},
            'real_funds_supported':False,'automatic_resend':False,'public_deployment':False}
