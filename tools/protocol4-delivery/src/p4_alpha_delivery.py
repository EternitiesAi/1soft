"""At-most-one local dispatch with original history references, not proof copies."""
from __future__ import annotations
from contextlib import contextmanager
import hashlib
import time
from pathlib import Path
from block_application import encode
from commit_verifier import exact,load_json
from p4_evidence import content_id,freeze,hash_text,integer,need
from p4_incremental_evidence import check_clock
from p4_alpha_wallet import P4AlphaWallet
from p4_wallet import matched_receipt,revision
from p4_delivery import P4Delivery,observation,MAX_ATTEMPTS
from p4_read_store import private_path

MAX_RECEIPTS=256
MAX_RECEIPT_BYTES=8*1024*1024

class P4AlphaDelivery(P4Delivery):
    APPLICATION_ID=0x31504144
    VERSION=2
    REVIEW_FORMAT='1soft/p4-alpha-delivery-review/v1'

    def __init__(self,wallet_path,path,genesis,policy,endpoint,store,*,create=False,clock=time.time_ns):
        self.store=store
        super().__init__(wallet_path,path,genesis,policy,endpoint,create=create,clock=clock)

    @contextmanager
    def atomic(self,write=True):
        with super().atomic(write=write):
            started=self.clock() if write else None
            self._commit_checkpoint=None
            yield
            if write:
                _,_,_,latest=self.wallet._catalog()
                dates=[latest,started]
                for table,column in [('config','created_ns'),('attempts','claimed_ns'),('responses','observed_ns'),('receipts','checked_ns')]:
                    value=self.db.execute(f'SELECT max({column}) FROM {table}').fetchone()[0]
                    if value is not None:dates.append(integer(value))
                final=self.clock();cid=self._commit_checkpoint or self.wallet._active_checkpoint
                if cid is None:check_clock(self.wallet.policy,final,max(dates))
                else:self.store.check_current(cid,now=final,previous_ns=max(dates))

    def _response_atomic(self):
        # Endpoint feedback is inert observational data after the original durable
        # claim, not a new dispatch approval or positive execution receipt.
        return P4Delivery.atomic(self)

    def _open_wallet(self,path,genesis,policy,clock):
        return P4AlphaWallet(path,genesis,policy,self.store,clock=clock)

    def _audit(self,decisions):
        private_path(self.path);need(self._config()==self.config,'alpha delivery immutable configuration changed')
        for suffix in ('','-wal','-shm'):
            p=Path(str(self.path)+suffix)
            if p.exists():need(p.stat().st_size<=64*1024*1024,'alpha delivery physical quota exceeded')
        _,obs,_,_=self.wallet._catalog();proofs={r[1]:r for r in obs};byid={d['id']:d for d in decisions}
        attempts={};responses={};receipts={};last=self.config[7]
        rows=self.db.execute('SELECT * FROM attempts ORDER BY seq').fetchmany(MAX_ATTEMPTS+1)
        need(len(rows)<=MAX_ATTEMPTS,'alpha attempt capacity exceeded')
        receipt_rows=self.db.execute('SELECT * FROM receipts ORDER BY seq').fetchmany(MAX_RECEIPTS+1)
        need(len(receipt_rows)<=MAX_RECEIPTS and all(type(r[4]) is bytes and 0<len(r[4])<=4096 for r in receipt_rows)
             and sum(len(r[4]) for r in receipt_rows)<=MAX_RECEIPT_BYTES,'alpha receipt reference quota exceeded')
        ids=[]
        for _,_,_,raw in rows:
            need(type(raw) is bytes and 0<len(raw)<=16384,'invalid original alpha delivery review')
            q=load_json(raw,max_bytes=16384);ids.append(q['evidence_id'])
        for _,_,eid,_,raw in receipt_rows:
            v=load_json(raw,max_bytes=4096);exact(v,{'wallet_evidence_id','checkpoint_id'},'alpha delivery receipt reference')
            ids.extend([v['wallet_evidence_id'],v['checkpoint_id']]);need(eid==v['checkpoint_id'],'receipt checkpoint identity differs')
        # A bound of256 original decisions and their wallet origins. A larger distinct batch fails closed.
        views=self.store.checkpoint_batch(ids,historical=True) if ids else {}
        for n,(seq,did,at,raw) in enumerate(rows,1):
            integer(seq,n,n);integer(at,last);need(did in byid and did not in attempts,'orphaned or duplicate original attempt')
            q=load_json(raw,max_bytes=16384);need(encode(q)==raw,'original dispatch review encoding differs')
            count=integer(q['decision_count'],1,len(decisions));prior=decisions[:count]
            need(any(d['id']==did for d in prior) and q['evidence_id'] in proofs,'attempt lost its original decision or wallet checkpoint')
            origin=proofs[q['evidence_id']];integer(at,max(origin[3],*(d['signed_ns'] for d in prior)))
            v=views[q['evidence_id']];self.wallet._origin_fresh(v['context'],v['checkpoint'],at,origin[3])
            expected=self._derive_review(v['context'],v['report'],prior,byid[did],at,self.config)
            need(encode(q)==encode(expected),'original dispatch review differs from authenticated origin')
            attempts[did]={'seq':seq,'at':at,'review':q};last=at
        rows=self.db.execute('SELECT * FROM responses').fetchmany(MAX_ATTEMPTS+1)
        need(len(rows)<=MAX_ATTEMPTS,'alpha response capacity exceeded')
        for did,at,raw in rows:
            need(did in attempts and did not in responses and type(raw) is bytes,'orphaned or duplicate endpoint response')
            integer(at,attempts[did]['at']);v=observation(load_json(raw,max_bytes=4096))
            need(encode(v)==raw,'endpoint response encoding differs');responses[did]=v;last=max(last,at)
        prior_at=self.config[7]
        for n,(seq,did,eid,at,raw) in enumerate(receipt_rows,1):
            integer(seq,n,n);integer(at,prior_at);prior_at=at;hash_text(eid)
            need(did in byid and did not in receipts,'orphaned or duplicate original receipt')
            ref=load_json(raw,max_bytes=4096);need(encode(ref)==raw and ref['wallet_evidence_id'] in proofs,'original receipt source differs')
            original=proofs[ref['wallet_evidence_id']];integer(at,max(original[3],byid[did]['signed_ns']))
            v=views[eid];old=views[ref['wallet_evidence_id']]
            need(v['checkpoint']['height']>=old['checkpoint']['height'],'receipt moves behind original wallet context')
            integer(at,v['checkpoint']['checked_ns']);check_clock(self.wallet.policy,at,checkpoint=v['checkpoint'])
            found=matched_receipt(v['report'],byid[did]);need(found is not None,'original successful included receipt is missing')
            receipts[did]={'checkpoint_id':eid,'evidence_id':eid,'receipt':found,'checked_ns':at};last=max(last,at)
        return attempts,responses,receipts,last

    def import_receipt(self,decision_id,checkpoint_id,*,payer,grant_id=''):
        hash_text(checkpoint_id)
        with self.wallet.atomic(write=False):
            _,_,report,ds,wclock=self.wallet._load(historical=True);d=self._selected(ds,decision_id,payer,grant_id)
            with self.atomic():
                _,_,receipts,last=self._audit(ds);now=self.clock()
                self.store.check_current(checkpoint_id,now=now,previous_ns=max(wclock,last))
                v=self.store.current(now=now,checkpoint_id=checkpoint_id);r=v['report']
                need(r['state_height']>=report['state_height'],'receipt checkpoint moves backwards')
                found=matched_receipt(r,d)
                if found is None:
                    self.store.check_current(checkpoint_id,now=self.clock(),previous_ns=now)
                    return {'status':'unavailable','decision_id':decision_id,'historical_absence_proven':False,'wallet_reservations_changed':False}
                if decision_id in receipts:
                    need(encode(found['record'])==encode(receipts[decision_id]['receipt']['record']),'conflicting original execution receipt')
                    self.store.check_current(checkpoint_id,now=self.clock(),previous_ns=now)
                    return {'status':'already_collected','decision_id':decision_id,'evidence_id':receipts[decision_id]['evidence_id'],'wallet_reservations_changed':False}
                raw=encode({'wallet_evidence_id':report['evidence_id'],'checkpoint_id':checkpoint_id})
                size=self.db.execute('SELECT coalesce(sum(length(payload)),0) FROM receipts').fetchone()[0]
                need(len(receipts)<MAX_RECEIPTS and size+len(raw)<=MAX_RECEIPT_BYTES,'alpha receipt capacity reached; no eviction')
                at=self.clock();self.store.check_current(checkpoint_id,now=at,previous_ns=now)
                self._commit_checkpoint=checkpoint_id
                self.db.execute('INSERT INTO receipts VALUES (?,?,?,?,?)',(len(receipts)+1,decision_id,checkpoint_id,at,raw))
        return {'status':'receipt_collected','decision_id':decision_id,'evidence_id':checkpoint_id,'wallet_reservations_changed':False}

    def collect(self,decision_id,*,payer,grant_id=''):
        with self.wallet.atomic(write=False):
            _,_,_,ds,_=self.wallet._load(historical=True);self._selected(ds,decision_id,payer,grant_id)
            with self.atomic(write=False):self._audit(ds)
        current=self.store.current();need(current is not None,'authenticated alpha read tip missing')
        result=self.store.collect(self.endpoint,expected_tip=current['checkpoint']['id'])
        saved=self.import_receipt(decision_id,result['checkpoint']['id'],payer=payer,grant_id=grant_id)
        return {**saved,'rpc_requests':result.get('rpc_requests',0),'submission_performed':False}

    def export_receipt(self,decision_id,*,payer,grant_id=''):
        with self.wallet.atomic(write=False):
            _,_,_,ds,_=self.wallet._load(historical=True);self._selected(ds,decision_id,payer,grant_id)
            with self.atomic(write=False):
                _,_,receipts,_=self._audit(ds);need(decision_id in receipts,'original exact receipt unavailable; outcome unknown')
                return receipts[decision_id]['checkpoint_id']

    def reconcile(self,decision_id,*,payer,grant_id='',expected_revision):
        cid=self.export_receipt(decision_id,payer=payer,grant_id=grant_id)
        received=self.store.checkpoint_at(cid,historical=True)
        with self.wallet.atomic(write=False):
            wid,_,report,ds,_=self.wallet._load(historical=True);d=self._selected(ds,decision_id,payer,grant_id)
            need(expected_revision==revision(wid,self.wallet.policy_id,report['evidence_id'],ds),'reviewed wallet revision changed')
            saved=matched_receipt(received['report'],d);need(saved is not None,'original exact receipt missing')
            current=self.store.current();need(current is not None,'current alpha read context missing')
            fresh=matched_receipt(current['report'],d)
            need(fresh is not None and encode(saved['record'])==encode(fresh['record']),'current original receipt differs')
            old=matched_receipt(report,d)
            if old is not None:
                need(encode(old['record'])==encode(saved['record']),'wallet original receipt conflicts')
                return {'status':'already_recorded','decision_id':decision_id,'wallet_sync_performed':False,'revision':expected_revision}
        result=self.wallet.sync(current['checkpoint']['id'],expected_revision=expected_revision)
        return {**result,'decision_id':decision_id,'wallet_sync_performed':result['status']=='checkpoint_recorded'}
