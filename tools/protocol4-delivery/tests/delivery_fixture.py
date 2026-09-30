"""Loopback development node over real P4 execution; synthetic committee signatures.

Never use these deterministic fixture signing seeds or genesis for funds.
"""
import base64
from contextlib import contextmanager
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from pathlib import Path
import socket
import threading

from block_application import encode
from commit_verifier import load_json
from native_core import canonical
from wallet_fixture import Chain, PASSWORD
from p4_wallet import P4Wallet
from p4_delivery import P4Delivery


class Fixture:
    def __init__(self,root,mode='drop'):
        self.root=Path(root);self.chain=Chain(root);self.mode=mode;self.reads=[];self.submissions=[]
        self.proof=self.chain.evidence();self.wp=self.root/'wallet.sqlite';self.dp=self.root/'delivery.sqlite'
        self.wallet=P4Wallet(self.wp,self.chain.genesis,self.chain.policy,create=True,clock=self.chain.clock)
        self.wallet.sync(self.proof,expected_revision=None);self.revision=self.wallet.status()['revision']
        outer=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*_):pass
            def do_POST(self):
                raw=self.rfile.read(int(self.headers['Content-Length']));q=json.loads(raw);outer.reads.append(q)
                method=q['method']
                if method=='broadcast_tx_sync':
                    wire=base64.b64decode(q['params']['tx'],validate=True);outer.submissions.append(wire)
                    outcome=outer.chain.app.check_tx(wire)
                    if outer.mode=='drop_before':self.drop();return
                    if outer.mode=='reject':outcome={**outcome,'code':1}
                    if outcome['code']==0 and outer.mode!='admit_only':
                        result=outer.chain.block([wire]);assert result['tx_results'][0]['code']==0
                        outer.publish()
                    if outer.mode=='drop':self.drop();return
                    result={'code':outcome['code'],'hash':hashlib.sha256(wire).hexdigest().upper()}
                    if outer.mode=='wrong_hash':result['hash']='0'*64
                    if outer.mode=='boolean_code':result['code']=False
                    self.reply(q,result);return
                if method=='abci_query':
                    if outer.mode=='read_error':self.reply(q,None,error=True);return
                    s=outer.proof['state'];self.reply(q,{'response':{'code':0,'height':str(s['height']),
                        'value':base64.b64encode(encode(s)).decode()}})
                elif method=='commit':
                    h=int(q['params']['height'])
                    if outer.mode=='missing_commit':self.reply(q,None,error=True);return
                    self.reply(q,{'signed_header':outer.proof['headers'][h-1]['signed_header']})
                elif method=='block':
                    h=int(q['params']['height']);sh=outer.proof['headers'][h-1]['signed_header']
                    self.reply(q,{'block_id':sh['commit']['block_id'],
                       'block':{'header':sh['header'],'data':{'txs':outer.proof['history'][h-1]['txs']}}})
                else:raise AssertionError('Unexpected RPC '+method)
            def drop(self):
                self.close_connection=True
                try:self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                self.connection.close()
            def reply(self,q,result,error=False):
                v={'jsonrpc':'2.0','id':q['id']}
                if error:v['error']={'code':-1,'message':'fixture unavailable'}
                else:v['result']=result
                raw=encode(v);self.send_response(200);self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        self.server=HTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=lambda:self.server.serve_forever(poll_interval=.02),daemon=True)
        self.thread.start();self.url=f'http://127.0.0.1:{self.server.server_port}/'
        self.delivery=self.open_delivery(create=True)
    def open_wallet(self):return P4Wallet(self.wp,self.chain.genesis,self.chain.policy,clock=self.chain.clock)
    def open_delivery(self,**kwargs):
        return P4Delivery(self.wp,self.dp,self.chain.genesis,self.chain.policy,self.url,clock=self.chain.clock,**kwargs)
    def publish(self):self.proof=self.chain.evidence()
    def sign(self,grant='raven',units=58):
        p=self.wallet.prepare(payer=self.chain.payer,recipient=self.chain.merchant,units=units,
                              valid_until=min(32,self.proof['state']['height']+30),grant_id=grant)
        ans=self.wallet.approve(p['review'],p['confirmation'],vault=self.root/((grant or 'owner')+'.pem'),password=PASSWORD)
        self.revision=self.wallet.status()['revision']
        return ans['decision_id']
    def selection(self,grant='raven'):return {'payer':self.chain.payer,'grant_id':grant}
    def review(self,did,grant='raven'):return self.delivery.prepare(did,**self.selection(grant))
    def send(self,did,grant='raven'):
        p=self.review(did,grant);return self.delivery.send(p['review'],p['confirmation'])
    def held(self):return int(self.wallet.status()['pending_debit_units'])
    def sync(self):
        r=self.wallet.sync(self.proof,expected_revision=self.wallet.status()['revision']);self.revision=r['revision'];return r
    def turnover(self):
        self.chain.block([self.chain.admin()])
        while self.chain.app.state['registry']['epoch']==0:self.chain.block([])
        self.publish()
    def close(self):
        self.delivery.close();self.wallet.close();self.server.shutdown();self.server.server_close();self.thread.join(2);self.chain.close()
