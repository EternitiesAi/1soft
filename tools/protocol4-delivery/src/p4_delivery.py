"""Decision-bound P4 delivery; one attempted submission per local delivery journal.

The original P4Wallet remains the sole signing and reservation authority. A
separate journal stores attempt intent, endpoint observations and verified positive
receipts. An attempt is committed BEFORE network I/O. A crash in that gap means
unknown dispatch, not safe-to-retry. No retry, reset, arbitrary transaction, key,
public endpoint or absence-based retirement interface is offered.
"""
from __future__ import annotations

import base64
from contextlib import contextmanager
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time

from block_application import encode, restore
from commit_verifier import exact, load_json
from native_core import canonical, identifier
from payment_rpc import endpoint_port
from payment_transport import _worker as submit_once
from p4_evidence import (MAX_EVIDENCE_BYTES, check_clock, content_id, extends,
                         freeze, hash_text, integer, need, verify_evidence)
from p4_read_store import private_path
from p4_wallet import (P4Wallet, fresh, matched_receipt, pending, revision,
                       rotation_pending, ROTATION_REVIEW_FORMAT)
import p4_rpc

APP_ID = 0x31503444
REVIEW_FORMAT = '1soft/p4-delivery-review/v1'
MAX_ATTEMPTS = 256
MAX_RECEIPTS = 32
MAX_RECEIPT_BYTES = 64 * 1024 * 1024
COLUMNS = {
    'config': ('id','version','delivery_id','wallet_id','policy_id','genesis_sha256','endpoint','created_ns'),
    'attempts': ('seq','decision_id','claimed_ns','review'),
    'responses': ('decision_id','observed_ns','payload'),
    'receipts': ('seq','decision_id','evidence_id','checked_ns','payload'),
}


def disjoint_paths(wallet_path, delivery_path):
    """Refuse database-to-sidecar aliases before opening or creating either DB."""
    w, d = Path(os.path.abspath(wallet_path)), Path(os.path.abspath(delivery_path))
    suffixes = ('', '-wal', '-shm', '-journal')
    ws = {str(w)+s for s in suffixes}; ds = {str(d)+s for s in suffixes}
    need(not ws.intersection(ds), 'wallet and delivery database/sidecar paths overlap')
    return private_path(w), private_path(d)


def observation(value):
    """A sanitized endpoint observation is not proof of execution or nonexecution."""
    v = freeze(value, 4096)
    kind = v.get('observation')
    if kind in ('endpoint_admitted', 'endpoint_declined'):
        exact(v, {'observation','check_tx_code','response_sha256'}, 'endpoint observation')
        integer(v['check_tx_code'],0,2**32-1); hash_text(v['response_sha256'])
        need((v['check_tx_code']==0)==(kind=='endpoint_admitted'), 'inconsistent CheckTx observation')
    else:
        exact(v, {'observation','reason'}, 'unresolved observation')
        need(kind=='unresolved' and type(v['reason']) is str and len(v['reason'])<=128,
             'invalid unresolved observation')
    return v


def collect_evidence(endpoint, genesis, policy, now_ns):
    """Use the unchanged P4 read worker in a bounded, key-free subprocess."""
    endpoint_port(endpoint); check_clock(policy, now_ns)
    import protocol4_application
    root = Path(protocol4_application.__file__).resolve().parents[1]
    request = {'endpoint':endpoint,'genesis':base64.b64encode(genesis).decode(),
               'policy':policy,'now_ns':now_ns}
    with tempfile.TemporaryFile() as out:
        try:
            proc = subprocess.run([sys.executable,str(Path(p4_rpc.__file__).resolve()),
                '--native-root',str(root)], input=encode(request),stdout=out,
                stderr=subprocess.DEVNULL,timeout=p4_rpc.PROCESS_TIMEOUT,
                check=False,env={**os.environ,'PYTHONPATH':''})
        except subprocess.TimeoutExpired as exc:
            raise ValueError('P4 receipt collection did not complete') from exc
        need(proc.returncode==0 and out.tell()<=MAX_EVIDENCE_BYTES+4096,
             'P4 receipt worker failed or exceeded its bound')
        out.seek(0); raw=out.read(MAX_EVIDENCE_BYTES+4097)
    value=load_json(raw,max_bytes=MAX_EVIDENCE_BYTES+4096)
    exact(value,{'schema','status','evidence','rpc_requests'},'P4 read worker')
    integer(value['schema'],1,1); integer(value['rpc_requests'],1,p4_rpc.MAX_REQUESTS)
    need(value['status']=='collected','no collected P4 evidence')
    return value


class P4Delivery:
    """Private development transport bound to one existing wallet and endpoint.

    One unresolved attempt per decision, with no replacement/retry API. This is
    at-most-one dispatch invocation through this journal, NOT globally exactly-once
    execution. Copies, other journals, raw signed-byte submission and hostile local
    filesystem/clock control are outside the coordination boundary.
    """
    def __init__(self, wallet_path, path, genesis, policy, endpoint, *, create=False,
                 clock=time.time_ns):
        need(type(create) is bool, 'invalid delivery creation mode')
        endpoint_port(endpoint)
        wallet_path, self.path = disjoint_paths(wallet_path,path)
        self.wallet=None; self.db=None; self.clock=clock; self.endpoint=endpoint
        try:
            self.wallet=P4Wallet(wallet_path,genesis,policy,clock=clock)
            with self.wallet.atomic(write=False):
                wid,_,_,_=self.wallet._catalog()
            self.wallet_id=wid
            if create:
                now=clock(); check_clock(self.wallet.policy,now)
                fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                os.close(fd)
            else:
                need(self.path.is_file(),'delivery journal is not initialized')
            self.db=sqlite3.connect(self.path.as_uri()+'?mode=rw',uri=True,
                                    isolation_level=None,timeout=5)
            if create:
                self.db.execute('PRAGMA journal_mode=WAL'); self.db.execute('PRAGMA synchronous=FULL')
                with self.atomic():
                    self.db.execute(f'PRAGMA application_id={APP_ID}')
                    self.db.execute('CREATE TABLE config(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, delivery_id TEXT NOT NULL, wallet_id TEXT NOT NULL, policy_id TEXT NOT NULL, genesis_sha256 TEXT NOT NULL, endpoint TEXT NOT NULL, created_ns INTEGER NOT NULL)')
                    self.db.execute('CREATE TABLE attempts(seq INTEGER PRIMARY KEY, decision_id TEXT UNIQUE NOT NULL, claimed_ns INTEGER NOT NULL, review BLOB NOT NULL)')
                    self.db.execute('CREATE TABLE responses(decision_id TEXT PRIMARY KEY, observed_ns INTEGER NOT NULL, payload BLOB NOT NULL)')
                    self.db.execute('CREATE TABLE receipts(seq INTEGER PRIMARY KEY, decision_id TEXT UNIQUE NOT NULL, evidence_id TEXT NOT NULL, checked_ns INTEGER NOT NULL, payload BLOB NOT NULL)')
                    self.db.execute('INSERT INTO config VALUES (1,1,?,?,?,?,?,?)',
                        (secrets.token_hex(32),wid,self.wallet.policy_id,
                         self.wallet.policy['genesis_sha256'],endpoint,now))
                fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                try:os.fsync(fd)
                finally:os.close(fd)
            self.config=self._config()
            need(self.db.execute('PRAGMA journal_mode').fetchone()[0]=='wal','delivery journal mode differs')
            self.db.execute('PRAGMA synchronous=FULL')
        except BaseException:
            self.close(); raise

    def close(self):
        if self.db is not None:self.db.close(); self.db=None
        if self.wallet is not None:self.wallet.close(); self.wallet=None
    def __enter__(self):return self
    def __exit__(self,*_):self.close()

    @contextmanager
    def atomic(self,write=True):
        need(not self.db.in_transaction,'delivery transaction already active')
        self.db.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        try:
            yield
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:self.db.execute('ROLLBACK')
            raise

    def _config(self):
        need(self.db.execute('PRAGMA application_id').fetchone()[0]==APP_ID,
             'not a P4 delivery database; no migration or repair')
        objects=self.db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        need(set(objects)=={('table',x) for x in COLUMNS},'unexpected delivery schema')
        for table,cols in COLUMNS.items():
            need(tuple(r[1] for r in self.db.execute(f'PRAGMA table_info({table})'))==cols,
                 'delivery columns differ')
        rows=self.db.execute('SELECT * FROM config').fetchall()
        need(len(rows)==1 and rows[0][:2]==(1,1),'delivery configuration missing or malformed')
        r=rows[0]; hash_text(r[2]);integer(r[7])
        need(r[3:7]==(self.wallet_id,self.wallet.policy_id,self.wallet.policy['genesis_sha256'],self.endpoint),
             'delivery wallet, policy, genesis or endpoint differs')
        return tuple(r)

    @staticmethod
    def _selected(decisions,decision_id,payer,grant_id):
        hash_text(decision_id);identifier(payer)
        need(type(grant_id) is str,'explicit delivery role required')
        if grant_id:identifier(grant_id)
        found=[d for d in decisions if d['id']==decision_id]
        need(len(found)==1,'signed wallet decision unavailable')
        d=found[0];body=d['review']['body']
        need(body['sender']==payer and body['grant_id']==grant_id,'delivery payer or role differs')
        return d

    def _review(self,e,r,decisions,d,now,config):
        fresh(e,self.wallet.policy,now)
        need(matched_receipt(r,d) is None,'payment is already recorded; no submission allowed')
        body=d['review']['body'];payer=body['sender'];raw=bytes.fromhex(d['wire_hex'])
        need(d['review']['format']==ROTATION_REVIEW_FORMAT or
             not rotation_pending(r,decisions,payer),
             'payer key rotation is unresolved; payment submission is paused')
        # Validate the original transfer at the saved current checkpoint. Include
        # ALL local reservations in deficit checks, not a new hold or second budget.
        held=pending(r,decisions);ledger=restore(e['state']['genesis'],e['state']['native'])
        try:
            owner=ledger._account(payer)
            total=sum(int(x['review']['debit_units']) for x in held if x['review']['body']['sender']==payer)
            need(total<=owner['balance'],'account reservations exceed recorded funds')
            bid=d['review']['budget_id']
            if bid is not None:
                b=ledger.db.execute('SELECT * FROM budgets WHERE id=?',(bid,)).fetchone()
                need(b is not None,'signed budget unavailable')
                total=sum(int(x['review']['debit_units']) for x in held if x['review']['budget_id']==bid)
                need(b['spent']+total<=b['cap'],'shared budget reservations exceed remaining allowance')
            ledger.apply(load_json(raw,max_bytes=16384),height=r['state_height']+1)
        finally:ledger.close()
        return {'schema':1,'format':REVIEW_FORMAT,'delivery_id':config[2],
            'wallet_id':self.wallet_id,'policy_id':self.wallet.policy_id,
            'wallet_revision':revision(self.wallet_id,self.wallet.policy_id,r['evidence_id'],decisions),
            'decision_count':len(decisions),'evidence_id':r['evidence_id'],'decision_id':d['id'],
            'payer':payer,'grant_id':body['grant_id'],'wire_sha256':hashlib.sha256(raw).hexdigest(),
            'endpoint':self.endpoint,'valid_until':body['valid_until'],
            'debit_units':d['review']['debit_units'],'state_height':r['state_height'],
            'registry_epoch':r['registry_epoch']}

    def _audit(self,decisions):
        need(self._config()==self.config,'delivery configuration changed')
        _,obs,_,_=self.wallet._catalog();proofs={r[1]:r for r in obs}
        byid={d['id']:d for d in decisions};attempts={};responses={};receipts={};last=self.config[7]
        rows=self.db.execute('SELECT * FROM attempts ORDER BY seq').fetchall()
        need(len(rows)<=MAX_ATTEMPTS,'delivery attempt capacity exceeded')
        for n,(seq,did,at,raw) in enumerate(rows,1):
            integer(seq,n,n);integer(at,last);need(did in byid,'attempt lost its original wallet decision')
            need(type(raw) is bytes and 0<len(raw)<=16384,'invalid delivery review bytes')
            review=load_json(raw,max_bytes=16384);need(encode(review)==raw,'noncanonical stored delivery review')
            count=integer(review['decision_count'],1,len(decisions));prior=decisions[:count]
            need(any(d['id']==did for d in prior),'attempt predates its signed decision')
            need(review['evidence_id'] in proofs,'delivery review lost its wallet checkpoint')
            o=proofs[review['evidence_id']];integer(at,max(o[3],*(d['signed_ns'] for d in prior)))
            e=load_json(o[4],max_bytes=MAX_EVIDENCE_BYTES)
            r=verify_evidence(e,self.wallet.genesis,self.wallet.policy,now_ns=at)
            expected=self._review(e,r,prior,byid[did],at,self.config)
            need(encode(review)==encode(expected),'stored delivery review differs from signed context')
            attempts[did]={'seq':seq,'at':at,'review':review};last=at
        for did,at,raw in self.db.execute('SELECT * FROM responses'):
            need(did in attempts and type(raw) is bytes,'orphaned or invalid endpoint response')
            integer(at,attempts[did]['at']);v=observation(load_json(raw,max_bytes=4096))
            need(encode(v)==raw,'endpoint observation encoding differs')
            responses[did]=v;last=max(last,at)
        rows=self.db.execute('SELECT * FROM receipts ORDER BY seq').fetchall()
        need(len(rows)<=MAX_RECEIPTS and sum(len(r[4]) for r in rows)<=MAX_RECEIPT_BYTES,
             'receipt storage limit exceeded')
        prior_receipt_ns=self.config[7]
        for n,(seq,did,eid,at,raw) in enumerate(rows,1):
            integer(seq,n,n);integer(at,prior_receipt_ns);hash_text(eid)
            prior_receipt_ns=at
            need(did in byid and type(raw) is bytes and 0<len(raw)<=MAX_EVIDENCE_BYTES+4096,
                 'invalid receipt record')
            v=load_json(raw,max_bytes=MAX_EVIDENCE_BYTES+4096)
            exact(v,{'wallet_evidence_id','evidence'},'delivery receipt evidence')
            need(encode(v)==raw and v['wallet_evidence_id'] in proofs,'receipt source binding differs')
            integer(at,max(proofs[v['wallet_evidence_id']][3],byid[did]['signed_ns']))
            old=load_json(proofs[v['wallet_evidence_id']][4],max_bytes=MAX_EVIDENCE_BYTES)
            e=v['evidence'];r=verify_evidence(e,self.wallet.genesis,self.wallet.policy,now_ns=at)
            extends(old,e);found=matched_receipt(r,byid[did])
            need(found is not None and r['evidence_id']==eid,'exact signed payment receipt is missing')
            receipts[did]={'evidence':e,'evidence_id':eid,'receipt':found,'checked_ns':at};last=max(last,at)
        return attempts,responses,receipts,last

    def prepare(self,decision_id,*,payer,grant_id=''):
        with self.wallet.atomic(write=False):
            _,e,r,ds,wclock=self.wallet._load();d=self._selected(ds,decision_id,payer,grant_id)
            with self.atomic(write=False):
                attempts,_,receipts,last=self._audit(ds)
                need(decision_id not in attempts,'dispatch already claimed; collect evidence, never auto-resend')
                need(decision_id not in receipts,'receipt already collected; reconcile instead')
                now=self.clock();check_clock(self.wallet.policy,now,max(wclock,last))
                review=self._review(e,r,ds,d,now,self.config)
                fresh(e,self.wallet.policy,self.clock(),now)
                return {'review':review,'confirmation':content_id(review),
                        'submission_performed':False,'wallet_reservations_changed':False}

    def send(self,review,confirmation):
        """Consumes one exact review. I/O starts only after durable attempt commit."""
        review=freeze(review,16384);hash_text(confirmation)
        need(hmac.compare_digest(content_id(review),confirmation),'delivery confirmation differs')
        with self.wallet.atomic():
            _,e,r,ds,wclock=self.wallet._load()
            d=self._selected(ds,review['decision_id'],review['payer'],review['grant_id'])
            with self.atomic():
                attempts,_,receipts,last=self._audit(ds)
                need(d['id'] not in attempts,'dispatch already claimed; no retry permitted')
                need(d['id'] not in receipts,'receipt already collected; no submission permitted')
                need(len(attempts)<MAX_ATTEMPTS,'delivery capacity reached')
                now=self.clock();check_clock(self.wallet.policy,now,max(wclock,last))
                expected=self._review(e,r,ds,d,now,self.config)
                need(encode(expected)==encode(review),'wallet or delivery review changed; review again')
                at=self.clock();fresh(e,self.wallet.policy,at,now)
                self.db.execute('INSERT INTO attempts VALUES (?,?,?,?)',
                                (len(attempts)+1,d['id'],at,encode(review)))
        # Both SQLite locks are released before HTTP. There is deliberately no
        # fictitious transaction spanning a local DB and an external node.
        raw=bytes.fromhex(d['wire_hex'])
        outcome=observation(submit_once(self.endpoint,raw,len(attempts)+1))
        with self.atomic():
            need(self._config()==self.config,'delivery configuration changed during dispatch')
            row=self.db.execute('SELECT claimed_ns,review FROM attempts WHERE decision_id=?',(d['id'],)).fetchone()
            need(row is not None and row[1]==encode(review),'attempt record changed during dispatch')
            now=self.clock();integer(now,row[0])
            self.db.execute('INSERT INTO responses VALUES (?,?,?)',(d['id'],now,encode(outcome)))
        return {'decision_id':d['id'],'transport_observation':outcome['observation'],
                'submission_attempt_recorded':True,'execution_proven':False,
                'wallet_reservations_changed':False,'automatic_resend':False}

    def inspect(self,decision_id,*,payer,grant_id=''):
        """Historical inspection remains possible after expiry; no renewed authority."""
        with self.wallet.atomic(write=False):
            _,_,_,ds,_=self.wallet._load(historical=True);self._selected(ds,decision_id,payer,grant_id)
            with self.atomic(write=False):
                attempts,responses,receipts,_=self._audit(ds)
                return {'decision_id':decision_id,'attempt_recorded':decision_id in attempts,
                    'transport_observation':responses.get(decision_id,{}).get('observation','unresolved' if decision_id in attempts else 'not_attempted'),
                    'receipt_status':'verified_historical_receipt' if decision_id in receipts else 'unavailable',
                    'evidence_id':receipts.get(decision_id,{}).get('evidence_id'),
                    'historical_absence_proven':False,'current_spending_authority':False,
                    'wallet_reservations_changed':False,'automatic_resend':False}

    def import_receipt(self,decision_id,evidence,*,payer,grant_id=''):
        e=freeze(evidence)
        with self.wallet.atomic(write=False):
            _,old,report,ds,wclock=self.wallet._load();d=self._selected(ds,decision_id,payer,grant_id)
            with self.atomic():
                _,_,receipts,last=self._audit(ds)
                now=self.clock();check_clock(self.wallet.policy,now,max(wclock,last))
                r=verify_evidence(e,self.wallet.genesis,self.wallet.policy,now_ns=now);extends(old,e)
                receipt=matched_receipt(r,d)
                if receipt is None:
                    check_clock(self.wallet.policy,self.clock(),now)
                    return {'status':'unavailable','decision_id':decision_id,
                            'historical_absence_proven':False,'wallet_reservations_changed':False}
                if decision_id in receipts:
                    need(encode(receipt['record'])==encode(receipts[decision_id]['receipt']['record']),
                         'conflicting execution receipt')
                    check_clock(self.wallet.policy,self.clock(),now)
                    return {'status':'already_collected','decision_id':decision_id,
                            'evidence_id':receipts[decision_id]['evidence_id'],'wallet_reservations_changed':False}
                raw=encode({'wallet_evidence_id':report['evidence_id'],'evidence':e})
                size=self.db.execute('SELECT coalesce(sum(length(payload)),0) FROM receipts').fetchone()[0]
                need(len(receipts)<MAX_RECEIPTS and size+len(raw)<=MAX_RECEIPT_BYTES,'receipt capacity reached; no eviction')
                at=self.clock();check_clock(self.wallet.policy,at,now)
                self.db.execute('INSERT INTO receipts VALUES (?,?,?,?,?)',
                    (len(receipts)+1,decision_id,r['evidence_id'],at,raw))
        return {'status':'receipt_collected','decision_id':decision_id,
                'evidence_id':r['evidence_id'],'wallet_reservations_changed':False}

    def collect(self,decision_id,*,payer,grant_id=''):
        # Fail wrong selection/expiry locally BEFORE opening any network connection.
        with self.wallet.atomic(write=False):
            _,_,_,ds,wclock=self.wallet._load();self._selected(ds,decision_id,payer,grant_id)
            with self.atomic(write=False): _,_,_,last=self._audit(ds)
            now=self.clock();check_clock(self.wallet.policy,now,max(wclock,last))
        result=collect_evidence(self.endpoint,self.wallet.genesis,self.wallet.policy,now)
        fresh(result['evidence'],self.wallet.policy,self.clock(),now)
        return {**self.import_receipt(decision_id,result['evidence'],payer=payer,grant_id=grant_id),
                'rpc_requests':result['rpc_requests'],'submission_performed':False}

    def export_receipt(self,decision_id,*,payer,grant_id=''):
        with self.wallet.atomic(write=False):
            _,_,_,ds,_=self.wallet._load(historical=True);self._selected(ds,decision_id,payer,grant_id)
            with self.atomic(write=False):
                _,_,receipts,_=self._audit(ds)
                need(decision_id in receipts,'exact receipt unavailable; outcome unknown')
                return freeze(receipts[decision_id]['evidence'])

    def reconcile(self,decision_id,*,payer,grant_id='',expected_revision):
        """Only the existing wallet's authenticated sync can retire an obligation."""
        proof=self.export_receipt(decision_id,payer=payer,grant_id=grant_id)
        with self.wallet.atomic(write=False):
            wid,e,r,ds,_=self.wallet._load();d=self._selected(ds,decision_id,payer,grant_id)
            need(expected_revision==revision(wid,self.wallet.policy_id,r['evidence_id'],ds),
                 'reviewed wallet revision changed')
            old=verify_evidence(proof,self.wallet.genesis,self.wallet.policy,now_ns=self.clock())
            received=matched_receipt(old,d);need(received is not None,'exact receipt missing')
            existing=matched_receipt(r,d)
            if existing is not None:
                need(encode(existing['record'])==encode(received['record']),'wallet and collected receipt conflict')
                check_clock(self.wallet.policy,self.clock())
                return {'status':'already_recorded','decision_id':decision_id,
                        'wallet_sync_performed':False,'revision':expected_revision}
        # No multi-database atomicity claim: if sync commits and the return is lost,
        # reopening this method recognizes the already recorded exact receipt.
        result=self.wallet.sync(proof,expected_revision=expected_revision)
        return {'status':'wallet_reconciled','decision_id':decision_id,
                'wallet_sync_performed':True,'revision':result['revision']}
