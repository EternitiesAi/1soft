"""Developer tests only: local P4 ABCI, process deaths, and synthetic signatures."""
from __future__ import annotations
import base64
from concurrent.futures import ThreadPoolExecutor
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from block_application import BlockApplication, encode
from commit_verifier import header_hash, trust_from_genesis
from native_core import digest, canonical
from protocol4_abci_wire import Request, Response, read_frame, write_frame, encode_finalization
from protocol4_abci_server import dispatch
from protocol4_application import Protocol4Application
from recovery_checks import (checkpoint, fingerprint, verify_boundary, remove_dead_socket,
    verify_payment_rows, verify_replayed_anchor, write_new, read_json, validate_state, sha)
from recovery_fixture import model
from validator_witness import nanos

ROOT=Path(__file__).resolve().parents[3]
ADDON=Path(__file__).resolve().parents[1]

class Peer:
    def __init__(self,path):
        self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.socket.settimeout(8)
        self.socket.connect(str(path));self.stream=self.socket.makefile('rwb',buffering=0)
    def request(self,q):
        write_frame(self.stream,q);data=read_frame(self.stream)
        if data is None:raise ConnectionError('no ABCI reply')
        r=Response.FromString(data)
        if r.WhichOneof('value')=='exception':raise ValueError('ABCI exception')
        return r
    def close(self):self.stream.close();self.socket.close()
    def __enter__(self):return self
    def __exit__(self,*_):self.close()

def initialize(peer,g):
    q=Request();v=q.init_chain;v.chain_id=g['chain_id'];v.initial_height=1;v.app_state_bytes=encode(g)
    for row in g['validator_registry']['validators']:
        item=v.validators.add();item.pub_key.ed25519=bytes.fromhex(row['public_key']);item.power=row['power']
    return peer.request(q)

def command(method):
    q=Request();getattr(q,method).SetInParent();return q

class ProcessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.c=model()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='p4-recovery-');self.root=Path(self.tmp.name)
        (self.root/'genesis.json').write_bytes(encode(self.c['genesis']))
        self.procs=[];self.run_id='abcdef0123456789'*2
    def tearDown(self):
        for p,handle in self.procs:
            if p.poll() is None:p.terminate()
            try:p.wait(5)
            except subprocess.TimeoutExpired:p.kill();p.wait(5)
            handle.close()
        self.tmp.cleanup()
    def start(self,kill=0,notice=False,emission=False):
        log=(self.root/f'process-{len(self.procs)}.log').open('wb')
        args=[sys.executable,str(ADDON/'scripts/serve_probe.py'),'--db',str(self.root/'app.sqlite'),
              '--socket',str(self.root/'app.sock'),'--genesis',str(self.root/'genesis.json'),
              '--boundary',str(self.root/f'boundary-{len(self.procs)}.json'),'--run-id',self.run_id,
              '--kill-height',str(kill)]
        if emission:args+=['--kill-emission']
        if notice:args+=['--snapshot-notice',str(self.root/'snapshot.json'),
                         '--snapshot-release',str(self.root/'release.json')]
        p=subprocess.Popen(args,stdout=log,stderr=log,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        self.procs.append((p,log));deadline=time.monotonic()+8
        while not (self.root/'app.sock').exists():
            if p.poll() is not None:raise AssertionError((self.root/f'process-{len(self.procs)-1}.log').read_text())
            if time.monotonic()>=deadline:raise AssertionError('ABCI startup timeout')
            time.sleep(.02)
        return p
    def crash_at(self,height,event=False):
        c=self.c;p=self.start(0 if event else height,emission=event)
        with Peer(self.root/'app.sock') as peer:
            initialize(peer,c['genesis'])
            for i in range(height):
                response=peer.request(Request.FromString(c['requests'][i]))
                self.assertEqual(response.SerializeToString(),c['responses'][i])
                if i+1==height:
                    with self.assertRaises((ConnectionError,OSError,ValueError)):peer.request(command('commit'))
                else:peer.request(command('commit'))
        self.assertEqual(p.wait(8),-signal.SIGKILL)
        observed=read_json(self.root/'boundary-0.json');saved=checkpoint(self.root/'app.sqlite',c['genesis'])
        result=verify_boundary(observed,saved,run_id=self.run_id,pid=p.pid,height=height,returncode=p.returncode)
        self.assertFalse(result['reply_received']);self.assertEqual(saved['state'],c['states'][height-1])
        remove_dead_socket(self.root/'app.sock',observed,p)
        second=self.start()
        self.assertNotEqual(second.pid,p.pid)
        with Peer(self.root/'app.sock') as peer:
            info=peer.request(command('info')).info;self.assertEqual(info.last_block_height,height)
            # Exact committed replay returns saved response; Commit then is a no-op.
            replay=peer.request(Request.FromString(c['requests'][height-1]))
            self.assertEqual(replay.SerializeToString(),c['responses'][height-1])
            before=checkpoint(self.root/'app.sqlite',c['genesis']);peer.request(command('commit'))
            self.assertEqual(checkpoint(self.root/'app.sqlite',c['genesis']),before)
            for i in range(height,10):
                self.assertEqual(peer.request(Request.FromString(c['requests'][i])).SerializeToString(),c['responses'][i])
                peer.request(command('commit'))
            raw=command('check_tx');raw.check_tx.tx=c['first']
            self.assertNotEqual(peer.request(raw).check_tx.code,0)
        final=checkpoint(self.root/'app.sqlite',c['genesis'])
        self.assertEqual(final['state'],c['states'][-1]);verify_payment_rows(final['state'],[c['first'],c['second']])
        self.assertEqual(final['state']['registry']['epoch'],1)
        return saved,final
    def test_emission_selector_kills_only_after_update_is_durable(self):
        saved,_=self.crash_at(4,event=True);self.assertTrue(saved['latest_block']['result']['validator_updates'])
    def test_crash_at_schedule_keeps_authorization_and_payment(self):
        saved,_=self.crash_at(1);self.assertEqual(saved['state']['registry']['pending']['phase'],'queued')
    def test_crash_at_emission_preserves_exact_validator_update(self):
        saved,_=self.crash_at(4);self.assertTrue(saved['latest_block']['result']['validator_updates'])
    def test_crash_at_activation_keeps_new_epoch_without_reemission(self):
        saved,_=self.crash_at(6);self.assertEqual(saved['state']['registry']['epoch'],1)
        self.assertEqual(saved['latest_block']['result']['validator_updates'],[])
    def test_crash_at_post_turnover_payment_cannot_debit_twice(self):
        saved,_=self.crash_at(7);self.assertEqual(len(saved['state']['native']['receipts']),2)
    def snapshot_at(self,h):
        c=self.c;source=Protocol4Application(':memory:',expected_genesis=c['genesis'])
        source.init_chain(c['genesis']['chain_id'],c['genesis'],c['genesis']['validator_registry']['validators'])
        for i in range(h):dispatch(source,Request.FromString(c['requests'][i]));source.commit()
        try:
            desc=source.list_snapshots()[0];self.assertEqual(desc['format'],2)
            self.start(notice=True)
            with Peer(self.root/'app.sock') as peer:
                q=command('offer_snapshot')
                for k,v in desc.items():setattr(q.offer_snapshot.snapshot,k,v)
                q.offer_snapshot.app_hash=bytes.fromhex(source.app_hash)
                self.assertEqual(peer.request(q).offer_snapshot.result,1)
                for n in range(desc['chunks']):
                    q=command('apply_snapshot_chunk');q.apply_snapshot_chunk.index=n
                    q.apply_snapshot_chunk.chunk=source.load_snapshot_chunk(h,2,n);q.apply_snapshot_chunk.sender='fixture'
                    if n+1==desc['chunks']:
                        with ThreadPoolExecutor(max_workers=1) as pool:
                            answer=pool.submit(peer.request,q);deadline=time.monotonic()+8
                            while not (self.root/'snapshot.json').exists():
                                self.assertLess(time.monotonic(),deadline);time.sleep(.02)
                            snap=checkpoint(self.root/'app.sqlite',c['genesis'])
                            self.assertEqual(snap['local_block_count'],0);self.assertIsNone(snap['latest_block'])
                            self.assertEqual(snap['state'],c['states'][h-1]);self.assertEqual(snap['snapshot_marker']['height'],h)
                            self.assertEqual(read_json(self.root/'snapshot.json')['checkpoint'],fingerprint(snap))
                            write_new(self.root/'release.json',{'run_id':self.run_id})
                            self.assertEqual(answer.result(8).apply_snapshot_chunk.result,1)
                    else:self.assertEqual(peer.request(q).apply_snapshot_chunk.result,1)
                missing=command('query');missing.query.path=f'/block/{h}'
                self.assertNotEqual(peer.request(missing).query.code,0)
                for i in range(h,10):
                    peer.request(Request.FromString(c['requests'][i]));peer.request(command('commit'))
                for old in range(1,h+1):
                    q=command('query');q.query.path=f'/block/{old}'
                    self.assertNotEqual(peer.request(q).query.code,0)
            final=checkpoint(self.root/'app.sqlite',c['genesis'])
            self.assertEqual(final['state'],c['states'][-1]);self.assertEqual(final['local_block_count'],10-h)
            # P4 deliberately removes its eligibility marker once ordinary execution begins.
            self.assertIsNone(final['snapshot_marker'])
            verify_payment_rows(final['state'],[c['first'],c['second']])
            return snap,final
        finally:source.close()
    def test_snapshot_queued_then_turnover_and_new_payment(self):self.snapshot_at(2)
    def test_snapshot_emitted_then_turnover_and_new_payment(self):self.snapshot_at(4)
    def test_snapshot_activated_then_new_payment(self):self.snapshot_at(6)

class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.c=model()
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def verify(self,**kw):
        c=self.c
        args=dict(genesis=c['genesis'],history=c['history'],state=c['states'][-1],headers=c['headers'],
             initial_hash=header_hash(c['headers'][0]['header']).hex(),now_ns=nanos(c['headers'][-1]['header']['time'])+10**9)
        args.update(kw);return verify_replayed_anchor(**args)
    def test_dynamic_anchor_reexecutes_money_and_authorization(self):
        result=self.verify();self.assertEqual(result['height'],10);self.assertEqual(result['headers_verified'],11)
        self.assertFalse(result['wallet_authority'])
    def test_wrong_initial_header_pin_refused(self):
        with self.assertRaises(ValueError):self.verify(initial_hash='f'*64)
    def test_missing_final_header_refused(self):
        with self.assertRaises(ValueError):self.verify(headers=self.c['headers'][:-1])
    def test_intermediate_missing_header_refused(self):
        hs=self.c['headers'][:3]+self.c['headers'][4:]
        with self.assertRaises(ValueError):self.verify(headers=hs)
    def test_tampered_signed_header_refused(self):
        hs=copy.deepcopy(self.c['headers']);hs[5]['header']['validators_hash']='0'*64
        with self.assertRaises(ValueError):self.verify(headers=hs)
    def test_same_state_does_not_allow_changed_block_input(self):
        h=copy.deepcopy(self.c['history']);h[0]['txs'].reverse()
        with self.assertRaisesRegex(ValueError,'not included'):self.verify(history=h)
    def test_signed_admin_mutation_refused(self):
        h=copy.deepcopy(self.c['history']);raw=json.loads(base64.b64decode(h[0]['txs'][0]));raw['approvals'].pop()
        h[0]['txs'][0]=base64.b64encode(encode(raw)).decode()
        with self.assertRaises(ValueError):self.verify(history=h)
    def test_money_state_change_refused(self):
        s=copy.deepcopy(self.c['states'][-1]);s['native']['accounts'][0][4]+=1
        with self.assertRaises(ValueError):self.verify(state=s)
    def test_registry_change_refused(self):
        s=copy.deepcopy(self.c['states'][-1]);s['registry']['epoch']+=1
        with self.assertRaises(ValueError):self.verify(state=s)
    def test_exact_one_hour_expiry_refused(self):
        with self.assertRaises(ValueError):self.verify(now_ns=nanos(self.c['headers'][0]['header']['time'])+3600*10**9)
    def test_negative_or_boolean_clock_refused(self):
        for n in (-1,True):
            with self.subTest(n=n),self.assertRaises(ValueError):self.verify(now_ns=n)
    def test_ordered_wires_must_match_receipts(self):
        with self.assertRaises(ValueError):verify_payment_rows(self.c['states'][-1],[self.c['second'],self.c['first']])
    def test_receipt_count_cannot_hide_missing_payment(self):
        with self.assertRaises(ValueError):verify_payment_rows(self.c['states'][-1],[self.c['first']])
    def test_history_height_bool_cannot_impersonate_one(self):
        h=copy.deepcopy(self.c['history']);h[0]['height']=True
        with self.assertRaises(ValueError):self.verify(history=h)
    def test_receipt_id_alone_is_not_signed_wire(self):
        wire=json.loads(self.c['first']);wire['signature']='a'*128
        with self.assertRaises(ValueError):verify_payment_rows(self.c['states'][-1],[canonical(wire),self.c['second']])
    def test_output_is_exclusive(self):
        path=self.root/'e.json';write_new(path,{'x':1})
        with self.assertRaises(FileExistsError):write_new(path,{'x':2})
        self.assertEqual(read_json(path),{'x':1})
    def test_symlink_output_refused(self):
        target=self.root/'target';target.write_text('keep');p=self.root/'e.json';p.symlink_to(target)
        with self.assertRaises((ValueError,OSError)):write_new(p,{'x':1})
        self.assertEqual(target.read_text(),'keep')
    def test_legacy_static_trust_still_rejects_p4(self):
        from native_core import public
        c=self.c
        engine={'chain_id':c['genesis']['chain_id'],'initial_height':'1','validators':[
            {'pub_key':{'type':'tendermint/PubKeyEd25519','value':base64.b64encode(bytes.fromhex(row['public_key'])).decode()},
             'power':str(row['power'])} for row in c['genesis']['validator_registry']['validators']], 'app_state':c['genesis']}
        with self.assertRaisesRegex(ValueError,'static trust anchor refuses'):trust_from_genesis(engine)
    def test_legacy_node_still_rejects_p4(self):
        with self.assertRaisesRegex(ValueError,'legacy node refuses'):BlockApplication(':memory:',expected_genesis=self.c['genesis'])
    def test_old_signer_refuses_before_unlock(self):
        from offline_signer import approve_intent
        from native_core import public
        with patch('offline_signer._load_vault',side_effect=AssertionError('no unlock')):
            with self.assertRaisesRegex(ValueError,'legacy offline signer refuses'):
                approve_intent(Path('unused'),b'not-a-password',self.c['genesis'],json.loads(self.c['first'])['body'],public(self.c['payers'][0]),'no')

class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.c=model(end=4)
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.db=self.root/'node.sqlite'
        app=Protocol4Application(self.db,expected_genesis=self.c['genesis'])
        app.init_chain(self.c['genesis']['chain_id'],self.c['genesis'],self.c['genesis']['validator_registry']['validators'])
        for raw in self.c['requests']:dispatch(app,Request.FromString(raw));app.commit()
        app.close();self.saved=checkpoint(self.db,self.c['genesis'])
        self.observation={'schema':1,'run_id':'a'*32,'pid':123,'height':4,'phase':'committed-before-reply',
                          'genesis_sha256':digest(self.c['genesis']),'checkpoint':fingerprint(self.saved)}
    def tearDown(self):self.tmp.cleanup()
    def check(self,observed=None,**kw):
        return verify_boundary(observed or self.observation,self.saved,run_id='a'*32,pid=123,height=4,returncode=kw.get('returncode',-9))
    def test_exact_boundary_can_be_checked_without_mutating_database(self):
        before=self.db.read_bytes();self.check();self.assertEqual(self.db.read_bytes(),before)
    def test_timeout_without_sigkill_does_not_count(self):
        with self.assertRaises(ValueError):self.check(returncode=None)
    def test_normal_exit_does_not_count(self):
        with self.assertRaises(ValueError):self.check(returncode=0)
    def test_other_signal_does_not_count(self):
        with self.assertRaises(ValueError):self.check(returncode=-15)
    def test_wrong_process_refused(self):
        o=copy.deepcopy(self.observation);o['pid']=124
        with self.assertRaises(ValueError):self.check(o)
    def test_prior_run_refused(self):
        o=copy.deepcopy(self.observation);o['run_id']='b'*32
        with self.assertRaises(ValueError):self.check(o)
    def test_boolean_nested_checkpoint_cannot_impersonate_receipt_count(self):
        o=copy.deepcopy(self.observation);o['checkpoint']['native_receipt_count']=True
        with self.assertRaises(ValueError):self.check(o)
    def test_wrong_genesis_observation_refused(self):
        o=copy.deepcopy(self.observation);o['genesis_sha256']='0'*64
        with self.assertRaises(ValueError):self.check(o)
    def test_changed_full_response_and_matching_encoding_still_refused(self):
        db=sqlite3.connect(self.db);raw=db.execute('SELECT result FROM blocks WHERE height=4').fetchone()[0]
        result=json.loads(raw);result['validator_updates']=[]
        db.execute('UPDATE blocks SET result=?,response=? WHERE height=4',(encode(result).decode(),encode_finalization(result)))
        db.commit();db.close()
        with self.assertRaisesRegex(ValueError,'independently replayed'):checkpoint(self.db,self.c['genesis'])
    def test_missing_history_refused(self):
        db=sqlite3.connect(self.db);db.execute('DELETE FROM history WHERE height=2');db.commit();db.close()
        with self.assertRaises(ValueError):checkpoint(self.db,self.c['genesis'])
    def test_modified_native_state_and_rehash_refused(self):
        from protocol4_application import application_hash
        db=sqlite3.connect(self.db);s=json.loads(db.execute('SELECT state FROM committed').fetchone()[0]);s['native']['accounts'][0][4]+=1
        db.execute('UPDATE committed SET state=?,app_hash=?',(encode(s).decode(),application_hash(self.c['genesis'],4,s)));db.commit();db.close()
        with self.assertRaises(ValueError):checkpoint(self.db,self.c['genesis'])
    def test_socket_cleanup_requires_actual_recorded_inode(self):
        sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);p=self.root/'x.sock';sock.bind(str(p));m=p.stat()
        observed={'pid':123,'socket':{'device':m.st_dev,'inode':m.st_ino+1}}
        proc=SimpleNamespace(pid=123,poll=lambda:-9)
        try:
            with self.assertRaises(ValueError):remove_dead_socket(p,observed,proc)
            self.assertTrue(p.exists())
        finally:sock.close()

if __name__=='__main__':unittest.main()
