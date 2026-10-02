"""Private HTTP + actual native application; signatures are synthetic committees.

Each block commits the preceding state, preserving the H/H+1 relationship. No
validator engine runs here. Only deterministic disposable keys and DEV balances.
"""
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
from pathlib import Path
import socket
import tempfile
import threading

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from block_application import BlockApplication
from certified_wallet import CertifiedWallet, nanos
from commit_verifier import encode, header_hash, load_json
from native_core import NativeLedger, address, canonical, public, sign
from certificate_fixture import validators, make_header, make_commit, STAMP

PASSWORD = b'1soft-disposable-delivery-fixture-password'
KEYS = [Ed25519PrivateKey.from_private_bytes(bytes([i])*32) for i in range(71,76)]
IDS = [address(public(k)) for k in KEYS]


class Scenario:
    def __init__(self, *, version=3, compact=False, current_clock=False):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.clock = nanos(STAMP) + 10**9
        self.stamp = STAMP
        if current_clock:
            self.stamp = datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
            self.clock = nanos(self.stamp)
        self.genesis = {'chain_id':'1soft-delivery-fixture', 'asset':'DEV', 'fee':2,
                        'protocol_version':version, 'allocations':[
                            {'public_key':public(KEYS[0]),'units':1000},
                            {'public_key':public(KEYS[1]),'units':0}]}
        if compact:
            self.genesis['state_commitment'] = 'smt-v1'
        self.engine, self.trust, self.committee = validators(self.genesis)
        self.raw = encode(self.engine)
        self.policy = {'schema':1, 'genesis_sha256':hashlib.sha256(self.raw).hexdigest(),
                       'trust_expires_utc':'2030-01-01T00:00:00Z','minimum_header_height':1,
                       'maximum_age_seconds':300,'future_skew_seconds':5}
        self.app = BlockApplication(self.root/'app.sqlite'); self.app.init_chain(self.genesis['chain_id'], self.genesis)
        self.headers = {}; self.blocks = {}; self.snapshots = {}; self.exposed = None
        self.lock = threading.RLock(); self.seen=[]; self.mode='drop_after_execution'; self.requests=[]
        self.native_results=[]
        model = NativeLedger(':memory:', self.genesis)
        try:
            ops=[]
            if version==3:
                ops.append({'type':'budget_create','id':'project','cap':100,'expires':100,'recipients':[IDS[1]]})
            for i,label in [(2,'raven'),(3,'atlas'),(4,'worker')]:
                op={'type':'grant','id':label,'public_key':public(KEYS[i]),'cap':100,
                    'expires':100,'recipients':[IDS[1]]}
                if version==3:op['budget_id']='project'
                ops.append(op)
            raws=[canonical(sign(KEYS[0],model.body(IDS[0],n,op))) for n,op in enumerate(ops)]
        finally:model.close()
        self.block(raws); self.block([])
        self.exposed=self.witness(1)
        self.wallet_path=self.root/'wallet.sqlite'; self.delivery_path=self.root/'delivery.sqlite'
        self.wallet=CertifiedWallet(self.wallet_path,self.raw,self.policy,clock=lambda:self.clock)
        self.wallet.sync(self.exposed)
        for i,k in enumerate(KEYS):
            p=self.root/f'key{i}.pem'
            p.write_bytes(k.private_bytes(ser.Encoding.PEM,ser.PrivateFormat.PKCS8,ser.BestAvailableEncryption(PASSWORD)))
            p.chmod(0o600)

    def block(self, raws):
        with self.lock:
            h=self.app.height+1
            state=json.loads(self.app.query('/state')['value'])
            self.snapshots[h-1]=state
            prior=self.headers[h-1]['commit']['block_id'] if h>1 else None
            header=make_header(self.trust,h,state['app_hash'],raws,previous=prior)
            header['version']['app']=str(self.genesis['protocol_version']); header['time']=self.stamp
            commit=make_commit(header,self.trust,self.committee)
            self.headers[h]=commit
            self.blocks[h]={'block_id':commit['commit']['block_id'],
                'block':{'header':header,'data':{'txs':[base64.b64encode(r).decode() for r in raws]}}}
            result=self.app.finalize_block(raws,h,header_hash(header)); self.app.commit()
            self.snapshots[h]=json.loads(self.app.query('/state')['value'])
            return result

    def witness(self, height):
        return {'schema':1, 'state':self.snapshots[height],'state_commit':self.headers[height+1]}

    def latest_after(self, raw):
        result=self.block([raw]); h=self.app.height
        self.block([]); self.exposed=self.witness(h)
        return result

    def sign(self, who=2, units=58, until=100):
        w=self.wallet
        b=self.body(who,units,until)
        r=w.review(self.exposed,b,public(KEYS[who]))
        return w.approve(self.exposed,b,public(KEYS[who]),r['confirmation'],self.root/f'key{who}.pem',PASSWORD)

    def body(self,who=2,units=58,until=100):
        grant={2:'raven',3:'atlas',4:'worker'}.get(who,'')
        state=self.exposed['state']['native']
        from block_application import restore
        l=restore(self.genesis,state)
        try:
            nonce=l._account(IDS[0])['nonce'] if not grant else l.db.execute(
                'SELECT nonce FROM grants WHERE id=?',(l.grant_storage_id(IDS[0],grant),)).fetchone()[0]
            return l.body(IDS[0],nonce,{'type':'transfer','to':IDS[1],'units':units},grant_id=grant,valid_until=until)
        finally:l.close()

    def continuation(self):
        origin=self.wallet.db.execute('SELECT height FROM checkpoint WHERE id=1').fetchone()[0]
        target=int(self.exposed['state_commit']['header']['height'])
        return [self.headers[h] for h in range(origin+1,target)]

    def holds(self):
        return sum(self.wallet.pending()['pending_account_units'].values())

    def close(self):
        self.wallet.close();self.app.close();self.temp.cleanup()

    @contextmanager
    def rpc(self):
        c=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                c.requests.append(request)
                method=request['method'];params=request['params']
                if method=='broadcast_tx_sync':
                    raw=base64.b64decode(params['tx'],validate=True);c.seen.append(raw)
                    code = 7 if c.mode=='decline' else 0
                    if c.mode!='decline':
                        result=c.latest_after(raw)
                        code=result['tx_results'][0]['code']
                        c.native_results.append(code)
                        assert code==0 or (code==1 and
                            result['tx_results'][0]['log']=='transaction already executed'), result
                    if c.mode=='drop_after_execution':
                        self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
                    result={'code':code,
                            'hash':hashlib.sha256(raw).hexdigest().upper()}
                elif method=='abci_query':
                    assert params['path']=='/state'
                    result={'response':{'code':0,'height':str(c.exposed['state']['height']),
                       'value':base64.b64encode(encode(c.exposed['state'])).decode()}}
                elif method=='block':result=c.blocks[int(params['height'])]
                elif method=='commit':
                    result={'signed_header':c.headers[int(params['height'])],'canonical':True}
                else:raise AssertionError(method)
                raw=encode({'jsonrpc':'2.0','id':request['id'],'result':result})
                self.send_response(200);self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(raw)));self.end_headers()
                self.wfile.write(raw)
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        server.daemon_threads=True
        thread=threading.Thread(target=lambda:server.serve_forever(poll_interval=.01),daemon=True);thread.start()
        try:yield f'http://127.0.0.1:{server.server_port}/'
        finally:server.shutdown();server.server_close();thread.join(2)
