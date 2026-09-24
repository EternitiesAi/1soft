"""Actual loopback HTTP and process-crash tests, NOT a real blockchain network."""
import base64
from contextlib import contextmanager
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from commit_verifier import encode, load_json, sha, header_hash, verify_packet
from native_core import NativeLedger, Reject, address, canonical, public, sign, DOMAIN
from payment_rpc import endpoint_port, MAX_RESPONSE
from payment_transport import DispatchJournal
from transport_fixture import fixture, packet, NOW_NS, DEADLINE, header, certificate

ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def endpoint(mode='admit', ledger_path=None):
    seen = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            tx = base64.b64decode(request['params']['tx'], validate=True)
            seen.append({'request':request,'raw':tx,'path':self.path})
            if mode == 'execute_then_drop':
                genesis = fixture()[2]
                db = NativeLedger(ledger_path, genesis)
                db.apply(json.loads(tx),height=1); db.close()
            if mode in ('drop','execute_then_drop'):
                self.connection.shutdown(socket.SHUT_RDWR); self.connection.close(); return
            if mode == 'stall':
                time.sleep(2); return
            if mode == 'redirect':
                self.send_response(302); self.send_header('Location','http://example.invalid/never-contact'); self.end_headers(); return
            result = {'jsonrpc':'2.0','id':request['id'], 'result':{'code':7 if mode=='decline' else 0,
                'hash':hashlib.sha256(tx).hexdigest().upper(),'data':'','log':'not a receipt','codespace':''}}
            if mode == 'wrong_hash': result['result']['hash'] = '0'*64
            if mode == 'wrong_id': result['id'] += 1
            if mode == 'boolean_id': result['id'] = True
            if mode == 'boolean_code': result['result']['code'] = False
            if mode == 'string_code': result['result']['code'] = '0'
            if mode == 'rpc_error': result = {'jsonrpc':'2.0','id':request['id'],'error':{'code':-32000,'message':'untrusted'}}
            if mode == 'oversized': result['result']['log'] = 'x'*(MAX_RESPONSE+1)
            data = encode(result)
            if mode == 'duplicate_json': data = b'{"jsonrpc":"2.0","id":1,"id":1,"result":{}}'
            if mode == 'invalid_json': data = b'<html>not a receipt</html>'
            self.send_response(500 if mode=='http_error' else 200)
            self.send_header('Content-Type','text/html' if mode=='wrong_type' else 'application/json')
            self.send_header('Content-Length',str(len(data)+(10 if mode=='truncated' else 0)))
            if mode == 'duplicate_length': self.send_header('Content-Length',str(len(data)))
            if mode == 'ambiguous_framing': self.send_header('Transfer-Encoding','chunked')
            if mode == 'compressed': self.send_header('Content-Encoding','gzip')
            self.end_headers()
            try: self.wfile.write(data)
            except OSError: pass
    server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
    server.daemon_threads = True; server.block_on_close = False
    thread = threading.Thread(target=lambda:server.serve_forever(poll_interval=.01),daemon=True)
    thread.start()
    try: yield f'http://127.0.0.1:{server.server_port}/',seen
    finally: server.shutdown(); server.server_close(); thread.join(timeout=2)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.owner,self.merchant,self.g,self.engine,self.trust,self.keys,self.raw = fixture()
        self.genesis = encode(self.engine); self.gsha = hashlib.sha256(self.genesis).hexdigest()
        self.now = NOW_NS; self.journal = None; self.url = 'http://127.0.0.1:27657/'
    def tearDown(self):
        if self.journal: self.journal.close()
        self.temp.cleanup()
    def open(self, url=None, **kwargs):
        if self.journal: self.journal.close()
        self.url = url or self.url
        self.journal = DispatchJournal(self.root/'dispatch.sqlite',self.genesis,self.gsha,self.url,
                                       kwargs.pop('deadline',DEADLINE),clock=lambda:self.now,**kwargs)
        return self.journal
    def queue(self): return self.journal.queue(self.raw,public(self.owner))
    def changed_raw(self, units=21):
        env=json.loads(self.raw);env['body']['op']['units']=units
        return canonical(sign(self.owner,env['body']))
    def test_endpoint_requires_literal_loopback_and_no_path_credentials_or_query(self):
        for bad in ['http://localhost:1234/','https://127.0.0.1:1234/','http://127.0.0.1:80/',
                    'http://127.0.0.1:70000/','http://127.0.0.1:1234/other','http://127.0.0.1:1234/?x=1',
                    'http://user@127.0.0.1:1234/','http://127.0.0.1:1234/#x','http://2130706433:1234/',
                    'http://192.168.1.2:1234/','http://127.0.0.1:01234/']:
            with self.subTest(endpoint=bad),self.assertRaises(ValueError): endpoint_port(bad)
        self.assertEqual(endpoint_port('http://127.0.0.1:65535/'),65535)
    def test_queue_does_not_open_socket_or_worker(self):
        self.open()
        with patch('payment_transport._worker',side_effect=AssertionError('no I/O')):
            row=self.queue()
        self.assertEqual(row['status'],'queued');self.assertEqual(row['attempts'],0)
        self.assertFalse(row['current_authority_verified'])
    def test_wire_hash_and_native_intention_id_are_distinct(self):
        self.open();row=self.queue()
        self.assertEqual(row['wire_sha256'],hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(row['native_txid'],sha(DOMAIN+canonical(json.loads(self.raw)['body'])).hex())
        self.assertNotEqual(row['wire_sha256'],row['native_txid'])
    def test_invalid_signature_refused(self):
        self.open();env=json.loads(self.raw);env['signature']='0'*128
        with self.assertRaises(ValueError): self.journal.queue(canonical(env),public(self.owner))
    def test_wrong_signer_refused(self):
        self.open()
        with self.assertRaises(ValueError): self.journal.queue(self.raw,public(self.merchant))
    def test_noncanonical_wire_refused(self):
        self.open()
        for raw in [self.raw+b'\n',json.dumps(json.loads(self.raw),indent=2).encode()]:
            with self.assertRaises(ValueError):self.journal.queue(raw,public(self.owner))
    def test_duplicate_keys_refused(self):
        self.open()
        with self.assertRaises(ValueError):self.journal.queue(b'{"body":{},"body":{}}',public(self.owner))
    def test_wrong_chain_refused_even_if_signed(self):
        self.open();env=json.loads(self.raw);env['body']['chain_id']='other'
        with self.assertRaises(ValueError):self.journal.queue(canonical(sign(self.owner,env['body'])),public(self.owner))
    def test_administrative_transaction_not_transported(self):
        self.open();env=json.loads(self.raw);env['body']['op']={'type':'fence'}
        with self.assertRaises(ValueError):self.journal.queue(canonical(sign(self.owner,env['body'])),public(self.owner))
    def test_same_intention_queue_idempotent(self):
        self.open();a=self.queue();b=self.queue();self.assertEqual(a,b)
        self.assertEqual(len(self.journal.events(a['native_txid'])),1)
    def test_conflicting_same_nonce_rejected(self):
        self.open();self.queue()
        with self.assertRaises(ValueError):self.journal.queue(self.changed_raw(),public(self.owner))
    def test_changed_signed_envelope_never_replaces_queue(self):
        self.open();a=self.queue()
        with self.assertRaises(ValueError):self.journal.queue(self.changed_raw(),public(self.owner))
        self.assertEqual(self.journal.export(a['native_txid']),self.raw)
    def test_exact_dispatch_confirmation_required_before_io(self):
        self.open();row=self.queue()
        with patch('payment_transport._worker',side_effect=AssertionError('no I/O')):
            with self.assertRaises(ValueError):self.journal.dispatch(row['native_txid'],'0'*64)
        self.assertEqual(self.journal.status(row['native_txid'])['attempts'],0)
    def test_endpoint_cannot_change_on_existing_journal(self):
        self.open();self.queue();self.journal.close();self.journal=None
        with self.assertRaises(ValueError):self.open('http://127.0.0.1:27658/')
    def test_policy_cannot_be_silently_extended(self):
        self.open();self.queue();self.journal.close();self.journal=None
        with self.assertRaises(ValueError):self.open(deadline='2026-09-26T12:00:00Z')
    def test_wrong_pinned_genesis_refused(self):
        with self.assertRaises(ValueError):DispatchJournal(self.root/'a.sqlite',self.genesis,'0'*64,self.url,DEADLINE)
    def test_private_journal_permissions(self):
        self.open();self.assertEqual((self.root/'dispatch.sqlite').stat().st_mode&0o777,0o600)
    def test_unsafe_journal_parent_refused(self):
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):self.open()
    def test_symlinked_journal_refused(self):
        (self.root/'target').write_bytes(b'');(self.root/'target').chmod(0o600)
        (self.root/'dispatch.sqlite').symlink_to(self.root/'target')
        with self.assertRaises(ValueError):self.open()
    def test_symlinked_sidecar_refused(self):
        (self.root/'target').write_bytes(b'');(self.root/'target').chmod(0o600)
        (self.root/'dispatch.sqlite-wal').symlink_to(self.root/'target')
        with self.assertRaises(ValueError):self.open()
    def test_second_process_cannot_take_active_dispatch_journal(self):
        self.open();row=self.queue();(self.root/'genesis.json').write_bytes(self.genesis)
        code='''from payment_transport import DispatchJournal
from pathlib import Path
import sys
try:
 DispatchJournal(Path(sys.argv[1]),Path(sys.argv[2]).read_bytes(),sys.argv[3],sys.argv[4],sys.argv[5])
except BlockingIOError: raise SystemExit(0)
raise SystemExit(9)
'''
        p=subprocess.run([sys.executable,'-c',code,str(self.root/'dispatch.sqlite'),str(self.root/'genesis.json'),self.gsha,self.url,DEADLINE],
            env=dict(os.environ,PYTHONPATH=str(ROOT/'src')),capture_output=True,timeout=5)
        self.assertEqual(p.returncode,0,p.stderr)
    def test_expired_policy_prevents_dispatch_but_not_export(self):
        self.open();row=self.queue();self.now += 2*86400*10**9
        with patch('payment_transport._worker',side_effect=AssertionError('no I/O')):
            with self.assertRaises(ValueError):self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'])
        self.assertEqual(self.journal.export(row['native_txid']),self.raw)
    def test_clock_rollback_prevents_dispatch(self):
        self.open();row=self.queue();self.now -= 1
        with self.assertRaises(ValueError):self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'])
    def test_worker_sees_attempt_committed_before_io(self):
        self.open();row=self.queue()
        def observer(*_):
            import sqlite3
            c=sqlite3.connect(self.root/'dispatch.sqlite')
            self.assertEqual(c.execute('SELECT status,attempts FROM payments').fetchone(),('dispatching',1));c.close()
            return {'observation':'unresolved','reason':'test observation'}
        with patch('payment_transport._worker',side_effect=observer):
            self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'])
    def test_real_rpc_admission_is_not_settlement(self):
        with endpoint() as (url,seen):
            self.open(url);row=self.queue();out=self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'])
            self.assertEqual(out['status'],'endpoint_admitted');self.assertFalse(out['receipt_verified'])
            self.assertEqual(len(seen),1);self.assertEqual(seen[0]['raw'],self.raw)
            self.assertEqual(seen[0]['request']['method'],'broadcast_tx_sync')
    def test_endpoint_decline_is_not_proof_of_nonexecution(self):
        with endpoint('decline') as (url,seen):
            self.open(url);row=self.queue();out=self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'])
            self.assertEqual(out['status'],'endpoint_declined');self.assertFalse(out['receipt_verified'])
            with self.assertRaises(ValueError):self.journal.queue(self.changed_raw(),public(self.owner))
    def test_connection_failure_does_not_auto_retry(self):
        with endpoint() as (url,_):pass
        self.open(url);row=self.queue();out=self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'])
        self.assertEqual(out['status'],'unresolved');self.assertEqual(out['attempts'],1)
    def test_socket_loss_after_actual_ledger_execution_stays_unresolved(self):
        path=self.root/'endpoint-ledger.sqlite'
        with endpoint('execute_then_drop',path) as (url,seen):
            self.open(url);row=self.queue();out=self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'])
            self.assertEqual(out['status'],'unresolved');self.assertEqual(len(seen),1)
            ledger=NativeLedger(path,self.g)
            self.assertEqual(ledger.balance(address(public(self.merchant))),20);ledger.close()
            proved=self.journal.prove(row['native_txid'],encode(packet()))
            self.assertTrue(proved['receipt_verified']);self.assertFalse(proved['live_network_provenance_established'])
    def test_no_implicit_second_send_after_response(self):
        with endpoint() as (url,seen):
            self.open(url);row=self.queue();self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'])
            with self.assertRaises(ValueError):self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'])
            self.assertEqual(len(seen),1)
    def test_explicit_replay_reuses_exact_bytes(self):
        with endpoint() as (url,seen):
            self.open(url);row=self.queue();self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'])
            out=self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'],replay=True)
            self.assertEqual(out['attempts'],2);self.assertEqual([r['raw'] for r in seen],[self.raw,self.raw])
            self.assertNotEqual(seen[0]['request']['id'],seen[1]['request']['id'])
    def test_replay_cannot_be_first_dispatch(self):
        self.open();row=self.queue()
        with self.assertRaises(ValueError):self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'],replay=True)
    def test_malformed_and_mismatched_responses_remain_unresolved(self):
        for mode in ['wrong_hash','wrong_id','boolean_id','boolean_code','string_code','rpc_error',
                     'duplicate_json','invalid_json','http_error','wrong_type','oversized',
                     'truncated','duplicate_length','ambiguous_framing','compressed','redirect']:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as subroot,endpoint(mode) as (url,seen):
                with DispatchJournal(Path(subroot)/'j.sqlite',self.genesis,self.gsha,url,DEADLINE,clock=lambda:self.now) as j:
                    row=j.queue(self.raw,public(self.owner));out=j.dispatch(row['native_txid'],row['dispatch_confirmation'])
                    self.assertEqual(out['status'],'unresolved');self.assertFalse(out['receipt_verified']);self.assertEqual(len(seen),1)
    def test_total_worker_deadline_is_bounded(self):
        with endpoint('stall') as (url,seen):
            self.open(url);row=self.queue();started=time.monotonic()
            with patch('payment_transport.WORKER_TIMEOUT',.4):out=self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'])
            self.assertLess(time.monotonic()-started,2);self.assertEqual(out['status'],'unresolved')
    def test_environment_proxies_do_not_intercept_loopback(self):
        with endpoint() as (url,seen):
            self.open(url);row=self.queue()
            with patch.dict(os.environ,{'HTTP_PROXY':'http://example.invalid:1234','HTTPS_PROXY':'http://example.invalid:1234','ALL_PROXY':'http://example.invalid:1234','NO_PROXY':''}):
                out=self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'])
            self.assertEqual(out['status'],'endpoint_admitted');self.assertEqual(len(seen),1)
    def _crash_dispatch(self, after_response=False):
        row=self.queue();self.journal.close();self.journal=None
        (self.root/'genesis.json').write_bytes(self.genesis)
        code='''from pathlib import Path
import os,sys
import payment_transport as p
original=p._worker
def crash(*args):
 if sys.argv[8]=='yes': original(*args)
 os._exit(29)
p._worker=crash
with p.DispatchJournal(Path(sys.argv[1]),Path(sys.argv[2]).read_bytes(),sys.argv[3],sys.argv[4],sys.argv[5],clock=lambda:int(sys.argv[9])) as j:
 j.dispatch(sys.argv[6],sys.argv[7])
'''
        p=subprocess.run([sys.executable,'-c',code,str(self.root/'dispatch.sqlite'),str(self.root/'genesis.json'),self.gsha,self.url,DEADLINE,
            row['native_txid'],row['dispatch_confirmation'],'yes' if after_response else 'no',str(self.now)],
            env=dict(os.environ,PYTHONPATH=str(ROOT/'src')),capture_output=True,timeout=8)
        self.assertEqual(p.returncode,29,p.stderr)
        self.open();self.assertEqual(self.journal.status(row['native_txid'])['status'],'dispatching')
        self.assertEqual(self.journal.export(row['native_txid']),self.raw)
        return row
    def test_crash_before_socket_preserves_ambiguous_attempt(self):
        with endpoint() as (url,seen):
            self.open(url);row=self._crash_dispatch();self.assertEqual(seen,[])
            with self.assertRaises(ValueError):self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'])
            self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'],replay=True)
            self.assertEqual(len(seen),1)
    def test_crash_after_response_preserves_attempt_and_exact_replay(self):
        with endpoint() as (url,seen):
            self.open(url);row=self._crash_dispatch(after_response=True);self.assertEqual(len(seen),1)
            self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'],replay=True)
            self.assertEqual([x['raw'] for x in seen],[self.raw,self.raw])
    def test_restart_preserves_status_and_endpoint_observation(self):
        with endpoint() as (url,seen):
            self.open(url);row=self.queue();self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'])
            self.open();out=self.journal.status(row['native_txid'])
            self.assertEqual(out['status'],'endpoint_admitted');self.assertEqual(out['attempts'],1)
            self.assertEqual(len(self.journal.events(row['native_txid'])),3)
    def test_corrupt_stored_bytes_refused_before_dispatch(self):
        self.open();row=self.queue();self.journal.db.execute('UPDATE payments SET raw=?',(self.changed_raw(),))
        with patch('payment_transport._worker',side_effect=AssertionError('no I/O')):
            with self.assertRaises(ValueError):self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'])
    def test_requested_payment_proof_required(self):
        self.open();row=self.queue();cert=packet();cert['transactions']=[]
        with self.assertRaises(ValueError):self.journal.prove(row['native_txid'],encode(cert))
        self.assertFalse(self.journal.status(row['native_txid'])['receipt_verified'])
    def test_forged_validator_signature_refused(self):
        self.open();row=self.queue();cert=packet();cert['state_commit']['commit']['signatures'][0]['signature']=base64.b64encode(b'\0'*64).decode()
        with self.assertRaises(ValueError):self.journal.prove(row['native_txid'],encode(cert))
    def test_other_payment_proof_refused(self):
        self.open();row=self.queue()
        with self.assertRaises(ValueError):self.journal.prove(row['native_txid'],encode(packet(self.changed_raw())))
    def test_verified_receipt_prevents_any_resend(self):
        self.open();row=self.queue();result=self.journal.prove(row['native_txid'],encode(packet()))
        self.assertEqual(result['status'],'receipt_verified')
        for replay in (False,True):
            with self.assertRaises(ValueError):self.journal.dispatch(row['native_txid'],row['dispatch_confirmation'],replay=replay)
    def test_repeat_proof_does_not_duplicate_settlement_event(self):
        self.open();row=self.queue();proof=encode(packet())
        self.journal.prove(row['native_txid'],proof);self.journal.prove(row['native_txid'],proof)
        self.assertEqual([e['event'] for e in self.journal.events(row['native_txid'])].count('native_receipt_verified'),1)
    def test_verified_receipt_persists_across_restart(self):
        self.open();row=self.queue();self.journal.prove(row['native_txid'],encode(packet()));self.open()
        self.assertTrue(self.journal.status(row['native_txid'])['receipt_verified'])
    def test_expired_trust_does_not_accept_new_proof(self):
        self.open();row=self.queue();self.now += 2*86400*10**9
        with self.assertRaises(ValueError):self.journal.prove(row['native_txid'],encode(packet()))
    def test_status_cannot_claim_verified_without_certificate(self):
        self.open();row=self.queue();self.journal.db.execute("UPDATE payments SET status='receipt_verified'")
        with self.assertRaises(ValueError):self.journal.status(row['native_txid'])
    def test_corrupted_saved_certificate_detected(self):
        self.open();row=self.queue();self.journal.prove(row['native_txid'],encode(packet()))
        self.journal.db.execute("UPDATE payments SET proof=?",(b'{}',))
        with self.assertRaises(ValueError):self.journal.status(row['native_txid'])


    def test_same_body_different_valid_signature_does_not_match_export(self):
        self.open();row=self.queue();cert=packet()
        replacement=canonical(sign(self.merchant,json.loads(self.raw)['body']))
        # Deliberately dishonest synthetic committee claims execution by another
        # key. This is NOT real ledger execution or a real validator certificate.
        cert['transactions'][0]['tx']=base64.b64encode(replacement).decode()
        h1=header(self.trust,1,cert['transactions'][0]['commit']['header']['app_hash'],[replacement])
        c1=certificate(h1,self.trust,self.keys)
        cert['transactions'][0]['commit']=c1
        cert['transactions'][0]['block']={'block_id':c1['commit']['block_id'],
            'block':{'header':h1,'data':{'txs':[base64.b64encode(replacement).decode()]}}}
        receipt=cert['state']['native']['receipts'][0]
        record=json.loads(receipt[3]);record['envelope']=json.loads(replacement)
        record['signer_public_key']=public(self.merchant)
        receipt[3]=encode(record).decode();receipt[4]=sha(encode(record)).hex()
        native_hash=sha(encode(self.g)).hex()
        state_hash=sha(encode({'domain':'ETERNITIES/ABCI-STATE/v1','genesis':native_hash,
            'height':1,'native':cert['state']['native']})).hex()
        cert['state']['app_hash']=state_hash
        cert['state_commit']=certificate(header(self.trust,2,state_hash,previous=c1['commit']['block_id']),self.trust,self.keys)
        self.assertEqual(verify_packet(cert,self.trust,expected_txids=[row['native_txid']])['status'],'verified')
        with self.assertRaisesRegex(ValueError,'exact exported transaction'):
            self.journal.prove(row['native_txid'],encode(cert))

    def test_saved_proof_rehashed_after_corruption_still_fails_signatures(self):
        self.open();row=self.queue();self.journal.prove(row['native_txid'],encode(packet()))
        altered=packet();altered['state_commit']['commit']['signatures'][0]['signature']=base64.b64encode(bytes(64)).decode()
        raw=encode(altered)
        self.journal.db.execute('UPDATE payments SET proof=?,proof_hash=?',(raw,sha(raw).hex()))
        with self.assertRaises(ValueError):self.journal.status(row['native_txid'])


class DispatchCliTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.owner,_,_,engine,_,_,self.raw=fixture()
        self.genesis=encode(engine);(self.root/'genesis.json').write_bytes(self.genesis)
        (self.root/'signed.json').write_bytes(self.raw+b'\n')
    def tearDown(self):self.tmp.cleanup()
    def call(self,*args,url='http://127.0.0.1:27657/'):
        return subprocess.run([sys.executable,str(ROOT/'scripts/payment_dispatch.py'),'--genesis',str(self.root/'genesis.json'),
            '--genesis-sha256',hashlib.sha256(self.genesis).hexdigest(),'--journal',str(self.root/'dispatch.sqlite'),
            '--endpoint',url,'--trust-expires-utc','2030-01-01T00:00:00Z',*args],capture_output=True,text=True,timeout=8)
    def queued(self,url='http://127.0.0.1:27657/'):
        p=self.call('queue','--envelope',str(self.root/'signed.json'),'--signer-public-key',public(self.owner),url=url)
        self.assertEqual(p.returncode,0,p.stderr);return json.loads(p.stdout)
    def test_wallet_export_newline_is_imported_without_changing_wire(self):
        row=self.queued();self.assertEqual(row['wire_sha256'],hashlib.sha256(self.raw).hexdigest())
    def test_extra_newlines_not_silently_normalized(self):
        (self.root/'signed.json').write_bytes(self.raw+b'\n\n')
        p=self.call('queue','--envelope',str(self.root/'signed.json'),'--signer-public-key',public(self.owner))
        self.assertEqual(p.returncode,2)
    def test_cli_send_requires_explicit_confirmation(self):
        row=self.queued();p=self.call('send','--txid',row['native_txid'])
        self.assertEqual(p.returncode,2)
    def test_cli_actual_send_and_receipt_proof(self):
        with endpoint() as (url,seen):
            row=self.queued(url);p=self.call('send','--txid',row['native_txid'],'--confirm',row['dispatch_confirmation'],url=url)
            self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout)['status'],'endpoint_admitted')
            proof=self.root/'proof.json';proof.write_bytes(encode(packet()))
            p=self.call('prove','--txid',row['native_txid'],'--certificate',str(proof),url=url)
            self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout)['status'],'receipt_verified')
            self.assertEqual(len(seen),1)
    def test_export_no_overwrite(self):
        row=self.queued();target=self.root/'out.json';target.write_bytes(b'preserve')
        p=self.call('export','--txid',row['native_txid'],'--output',str(target))
        self.assertEqual(p.returncode,2);self.assertEqual(target.read_bytes(),b'preserve')
    def test_export_preserves_existing_signature(self):
        row=self.queued();target=self.root/'out.json'
        p=self.call('export','--txid',row['native_txid'],'--output',str(target))
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(target.read_bytes(),self.raw+b'\n')
    def test_cli_events_distinguish_attempt_from_receipt(self):
        row=self.queued();p=self.call('events','--txid',row['native_txid'])
        self.assertEqual(p.returncode,0);self.assertEqual(json.loads(p.stdout)['events'][0]['event'],'queued')


if __name__ == '__main__': unittest.main()
