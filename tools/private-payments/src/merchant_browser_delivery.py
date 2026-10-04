"""Explicit same-host alpha browser bridge. Enrollment remains operator-only.

Only a frozen owner-private session and canonical independently configured book
select a destination. Browser input cannot supply paths, tokens, packets or time.
The merchant owns consumption; the bridge validates bytes before returning them.
"""
import hashlib
import hmac
import http.client
import io
import re
import time
from urllib.parse import urlsplit

from block_application import encode
from commit_verifier import b64, exact, load_json
from local_devnet import read_private
from merchant_alpha import (AlphaMerchantBook, MAX_RECEIPT_BYTES, MAX_PROOF_BYTES,
    make_signature, parse_packet, verify_proof)
from merchant_book import MAX_QUOTES, MAX_RESOURCE_BYTES
from merchant_ops import SESSION_FORMAT, loopback_origin
from merchant_http import _DeadlineReader
from p4_evidence import content_id, hash_text, integer, need
from p4_read_store import private_path
from payment_x402 import parse_payment_required, parse_payment_response
from private_payment_desk import AlphaPrivatePaymentDesk

FORMAT='1soft/alpha-browser-resource-review/v1'
WORK_SECONDS=120


def _sha(raw): return hashlib.sha256(raw).hexdigest()


class _HeaderReader:
    """Bound aggregate response header work before the HTTP parser accepts it."""
    def __init__(self, stream, connection, deadline):
        self.stream=stream;self.connection=connection;self.deadline=deadline
        self.bytes=0;self.lines=0
    def readline(self, limit=-1):
        remaining=self.deadline-time.monotonic();need(remaining>0,'merchant response deadline exceeded')
        self.connection.settimeout(remaining)
        bound=65536-self.bytes
        raw=self.stream.readline(min(bound+1,limit) if limit>0 else bound+1)
        self.bytes+=len(raw);self.lines+=1
        need(self.bytes<=65536 and self.lines<=66,'merchant response headers exceed bound')
        return raw
    def read(self, size=-1): return self.stream.read(size)
    def flush(self): return self.stream.flush()
    def close(self): return self.stream.close()


class AlphaMerchantBridge:
    def __init__(self, session_path, book_factory, genesis_bytes, policy):
        need(callable(book_factory),'independent read-only merchant factory required')
        self.session_path=private_path(session_path);self.factory=book_factory
        self.genesis=genesis_bytes;self.policy=policy
        self._session=read_private(self.session_path,65536)
        value=load_json(self._session,max_bytes=65536)
        exact(value,{'schema','format','origin','quote_ids','session_token','configured_seconds'},'merchant session')
        integer(value['schema'],1,1);integer(value['configured_seconds'],1,300)
        need(value['format']==SESSION_FORMAT and encode(value)==self._session,'canonical original merchant session required')
        self.port=loopback_origin(value['origin']);self.origin=value['origin']
        token=value['session_token']
        need(type(token) is str and re.fullmatch('[0-9a-f]{64}',token) is not None,'bounded original merchant session required')
        ids=value['quote_ids']
        need(type(ids) is list and 1<=len(ids)<=MAX_QUOTES and len(set(ids))==len(ids),'bounded unique retained quotes required')
        for qid in ids: hash_text(qid)
        self.quote_ids=tuple(ids);self._token=token;self._fingerprint=_sha(self._session)
        with self.factory() as book:
            self._check_book(book)
            self._path=book.path;self._policy_id=book.policy_id
            self._quotes={qid:self._quote_pin(book.selected(qid)) for qid in ids}

    def _check_book(self,book):
        need(type(book) is AlphaMerchantBook and book.read_only,'canonical read-only alpha merchant book required')
        need(book.genesis==self.genesis and encode(book.policy)==encode(self.policy),'original merchant genesis/policy differs')
        if hasattr(self,'_path'):
            need(book.path==self._path and book.policy_id==self._policy_id,'original merchant book context differs')

    def _quote_pin(self,row):
        e=row['expectation'];need(e.merchant_origin==self.origin,'original fixed loopback origin differs')
        parsed=urlsplit(e.resource_url);route=parsed.path+('?' + parsed.query if parsed.query else '')
        need(e.resource_url==self.origin+route and route.startswith('/') and not route.startswith('//') and
             route.isascii() and all(32<ord(c)<127 for c in route),'exact bounded merchant route required')
        return row['required_header'],e,row['resource_sha256'],route

    def _context(self):
        need(hmac.compare_digest(read_private(self.session_path,65536),self._session),'original merchant session changed')

    def _row(self,desk,rid,*,packet=False):
        self._context();hash_text(rid)
        need(type(desk) is AlphaPrivatePaymentDesk and desk.platform.genesis==self.genesis and
             encode(desk.platform.policy)==encode(self.policy),'canonical original alpha invoice payer required')
        invoice,e=desk._selected(rid)
        qid=invoice['quote_sha256'];need(qid in self._quotes,'invoice is outside configured merchant quotes')
        with self.factory() as book:
            self._check_book(book);row=book.selected(qid)
            need(self._quote_pin(row)==self._quotes[qid] and row['required_header']==invoice['required_header'] and
                 row['expectation']==e,'retained buyer/merchant quote differs')
            binding=book.payment_binding(qid)
        entry=desk.platform.book.selected(rid);review=entry['review']
        need(review is not None and review['body']['sender']==binding['payer'],'original enrolled payer differs')
        wire=desk.recover(rid);need(_sha(wire)==binding['wire_sha256'],'original enrolled wire differs')
        q=parse_payment_required(invoice['required_header'],e,now_ns=row['created_ns'])
        if binding['fulfilled_ns'] is None:
            now=integer(desk.platform.clock(),1)
            need(now<row['expires_ns'] and now<self.policy['absolute_not_after_ns'],'new resource consumption is expired')
        result=dict(invoice=invoice,expectation=e,quote=row,binding=binding,wire=wire,
            decision_id=entry['decision_id'],grant_id=review['body']['grant_id'],mime=q['offer']['resource'].get('mimeType','application/octet-stream'))
        if packet:
            raw=desk.platform.capsule(rid,binding['reference_id'])
            need(_sha(raw)==binding['capsule_sha256'],'original enrolled packet bytes differ')
            parsed=parse_packet(raw)
            need(parsed['capsule_id']==binding['reference_id'] and parsed['reference']['payer']==binding['payer'] and
                 parsed['wire_hex']==wire.hex(),'original enrolled packet identity differs')
            result['packet']=raw
            self._context()
            with self.factory() as book:
                self._check_book(book)
                need(book.payment_binding(qid)==binding and self._quote_pin(book.selected(qid))==self._quotes[qid],
                     'original merchant binding changed during packet inspection')
        return result

    def status(self,desk,rid):
        # No packet or transport on inspection. Absent enrollment is an ordinary
        # visible state, while changed configuration/correlation still refuses.
        self._context();hash_text(rid)
        need(type(desk) is AlphaPrivatePaymentDesk and desk.platform.genesis==self.genesis and
             encode(desk.platform.policy)==encode(self.policy),'canonical original alpha invoice payer required')
        invoice,e=desk._selected(rid);qid=invoice['quote_sha256']
        if qid not in self._quotes:return dict(configured=False,consumption_retained=False)
        with self.factory() as book:
            self._check_book(book);row=book.selected(qid)
            need(self._quote_pin(row)==self._quotes[qid] and row['required_header']==invoice['required_header'] and row['expectation']==e,
                 'retained buyer/merchant quote differs')
            enrolled=row['enrollment'] is not None
            binding=book.payment_binding(qid) if enrolled else None
        if enrolled:
            original=desk.platform.book.selected(rid)['review']
            need(original is not None and original['body']['sender']==binding['payer'] and
                 _sha(desk.recover(rid))==binding['wire_sha256'],'original enrolled payer/wire differs')
        retained=enrolled and binding['fulfilled_ns'] is not None
        eligible=retained or (desk.platform.clock()<row['expires_ns'] and desk.platform.clock()<self.policy['absolute_not_after_ns'])
        return dict(configured=True,enrolled=enrolled,consumption_retained=retained,
            retrieval_available=bool(enrolled and eligible),resource_received_by_browser=False,
            fulfilled_ns=str(binding['fulfilled_ns']) if retained else None,
            resource_sha256=row['resource_sha256'],quote_sha256=qid,
            reference_id=binding['reference_id'] if enrolled else None,
            wire_sha256=binding['wire_sha256'] if enrolled else None,
            capsule_sha256=binding['capsule_sha256'] if enrolled else None,
            native_txid=binding['native_txid'] if enrolled else None,
            full_public_ledger_disclosed=True,merchant_identity_authenticated=False)

    def _review(self,r,rid):
        b=r['binding'];e=r['expectation']
        value=dict(format=FORMAT,request_id=rid,decision_id=r['decision_id'],quote_sha256=r['invoice']['quote_sha256'],
            merchant_origin=e.merchant_origin,resource_url=e.resource_url,resource_sha256=r['quote']['resource_sha256'],
            payer=b['payer'],grant_id=r['grant_id'],wire_sha256=b['wire_sha256'],capsule_sha256=b['capsule_sha256'],
            reference_id=b['reference_id'],native_txid=b['native_txid'],genesis_sha256=e.genesis_sha256,
            policy_id=self._policy_id,session_context_sha256=self._fingerprint,
            fulfilled_ns=None if b['fulfilled_ns'] is None else str(b['fulfilled_ns']),
            full_public_ledger_disclosed=True,signing_or_submission_performed=False)
        return dict(review=value,confirmation=content_id(value),summary=value)

    def review(self,desk,rid):
        return self._review(self._row(desk,rid,packet=True),rid)

    def _post(self,r,deadline):
        e=r['expectation'];remaining=deadline-time.monotonic();need(remaining>0,'merchant work deadline exceeded')
        class Connection(http.client.HTTPConnection):
            def send(self,data):
                left=deadline-time.monotonic();need(left>0,'merchant send deadline exceeded')
                if self.sock is None:
                    self.timeout=min(5,left);self.connect()
                left=deadline-time.monotonic();need(left>0,'merchant send deadline exceeded after connect')
                self.sock.settimeout(min(5,left))
                return super().send(data)
        connection=Connection('127.0.0.1',self.port,timeout=min(5,remaining))
        response=None
        class Response(http.client.HTTPResponse):
            def __init__(self,sock,*args,**kwargs):
                super().__init__(sock,*args,**kwargs)
                # Keep the original SocketIO reference alive when HTTPConnection
                # closes its socket for Connection: close. All actual reads use
                # recv with an absolute deadline underneath buffering.
                self._socket_guard=self.fp
                self.fp=_HeaderReader(io.BufferedReader(_DeadlineReader(sock,deadline)),sock,deadline)
            def close(self):
                try:super().close()
                finally:
                    guard=getattr(self,'_socket_guard',None)
                    if guard is not None:guard.close()
        connection.response_class=Response
        try:
            # Header serialization at quote creation restores identical original
            # bytes; it is never the AS-OF time for proof or consumption checks.
            signature=make_signature(required_header=r['invoice']['required_header'],expectation=e,
                exact_wire=r['wire'],capsule=r['packet'],payer=r['binding']['payer'],now_ns=r['quote']['created_ns'])
            route=self._quotes[r['invoice']['quote_sha256']][3]
            self._context()
            connection.request('POST',route,body=r['packet'],headers={'X-1soft-Merchant-Session':self._token,
                'Origin':self.origin,'Content-Type':'application/json','PAYMENT-SIGNATURE':signature,'Connection':'close'})
            response=connection.getresponse();headers=response.getheaders()
            need(response.status==200 and len(headers)<=64,'merchant resource response refused')
            names=set()
            for k,v in headers:
                need(k.lower() not in names and k.isascii() and v.isascii() and all(32<=ord(c)<127 for c in v),
                     'duplicate or malformed merchant response header');names.add(k.lower())
            length=response.getheader('Content-Length')
            need(type(length) is str and re.fullmatch('[1-9][0-9]{0,4}',length) is not None,'exact merchant resource length required')
            size=integer(int(length),1,MAX_RESOURCE_BYTES)
            need(response.getheader('Content-Type')==r['mime'] and response.getheader('Transfer-Encoding') is None and
                 response.getheader('Content-Encoding') is None and response.getheader('Connection')=='close','merchant resource encoding differs')
            raw=response.fp.read(size+1)
            need(len(raw)==size and _sha(raw)==r['quote']['resource_sha256'],'merchant resource bytes differ')
            header=response.getheader('PAYMENT-RESPONSE');b=r['binding']
            parsed=parse_payment_response(header,e,payer=b['payer'],quote_sha256=r['invoice']['quote_sha256'],
                wire_sha256=b['wire_sha256'],capsule_sha256=b['capsule_sha256'])
            need(parsed['response']['transaction']==b['native_txid'],'merchant response changes original native transaction')
            return raw,header
        finally:
            if response is not None:response.close()
            connection.close()

    def retrieve(self,desk,rid,review,confirmation):
        deadline=time.monotonic()+WORK_SECONDS
        r=self._row(desk,rid,packet=True);expected=self._review(r,rid)
        need(encode(review)==encode(expected['review']) and confirmation==expected['confirmation'],'exact resource review confirmation required')
        self._context();resource,response=self._post(r,deadline)
        proof=self.proof(desk,rid)
        need(proof['resource']==resource and proof['payment_response_header']==response,'retained proof differs from returned resource')
        need(time.monotonic()<deadline,'merchant work deadline exceeded')
        return dict(request_id=rid,resource=resource,resource_sha256=_sha(resource),proof=proof['raw'],
            quote_sha256=r['invoice']['quote_sha256'],wire_sha256=r['binding']['wire_sha256'],
            capsule_sha256=r['binding']['capsule_sha256'],native_txid=r['binding']['native_txid'],
            fulfilled_ns=proof['fulfilled_ns'],payment_response_header=response)

    def proof(self,desk,rid):
        r=self._row(desk,rid,packet=True);qid=r['invoice']['quote_sha256'];b=r['binding']
        need(b['fulfilled_ns'] is not None,'original completed consumption required')
        with self.factory() as book:
            self._check_book(book);raw=book.export_proof(qid);assignment=book.assignment(qid)
        need(len(raw)<=MAX_PROOF_BYTES,'merchant proof exceeds transport bound')
        verified=verify_proof(raw,genesis_bytes=self.genesis,policy=self.policy,expectation=r['expectation'],
            assignment=assignment,now_ns=b['fulfilled_ns'])
        value=load_json(raw,max_bytes=MAX_PROOF_BYTES)
        need(b64(value['capsule_b64'],max_size=MAX_RECEIPT_BYTES)==r['packet'] and
             verified['native_txid']==b['native_txid'],'proof changes original enrolled receipt')
        return dict(raw=raw,resource=b64(value['resource_b64'],max_size=MAX_RESOURCE_BYTES),
            payment_response_header=value['response_header'],fulfilled_ns=b['fulfilled_ns'],report=verified)
