"""Local private ABCI/process tests. No CometBFT votes or public/real funds."""
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from abci_wire import Client
from block_application import BlockApplication
from certificate_fixture import validators,make_header,make_commit
from commit_verifier import encode
from run_state_sync import build_case,verify_snapshot_anchor,verify_history_window,run
from serve_abci_state_sync_crash import read_event,write_event,remove_exact_socket

ROOT=Path(__file__).resolve().parents[1]


def await_event(control,name,proc,seconds=10):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        v=read_event(control,name)
        if v is not None:return v
        if proc.poll() is not None:raise AssertionError('supervisor stopped: '+str(proc.returncode))
        time.sleep(.02)
    raise AssertionError('missing event '+name)


def process_case(root, *, smt=False, keep=None):
    root=Path(root);root.mkdir(mode=0o700,exist_ok=True)
    case=build_case('local-final-apply-test',3 if smt else 1,state_commitment='smt-v1' if smt else None)
    g=case['genesis'];src=BlockApplication(':memory:',expected_genesis=g,block_history_keep=keep)
    src.init_chain(g['chain_id'],g)
    for h in range(1,5):
        src.finalize_block([case['pre_snapshot_tx']] if h==1 else [],h,hashlib.sha256(str(h).encode()).digest());src.commit()
    snapshot=src.list_snapshots()[0];control=root/'control';control.mkdir(mode=0o700)
    genesis=root/'genesis.json';genesis.write_bytes(encode(g));sock=root/'a.sock';db=root/'app.sqlite'
    run_id=os.urandom(16).hex()
    cmd=[sys.executable,str(ROOT/'scripts/serve_abci_state_sync_crash.py'),'--db',str(db),
         '--socket',str(sock),'--genesis',str(genesis),'--control-dir',str(control),'--run-id',run_id]
    if keep is not None:cmd+=['--block-history-keep',str(keep)]
    log=open(root/'process.log','wb');proc=subprocess.Popen(cmd,stdout=log,stderr=subprocess.STDOUT)
    try:
        await_event(control,'pause-ready.json',proc)
        with Client(str(sock),timeout=10) as client:
            assert client.call('offer_snapshot',snapshot=snapshot,app_hash=bytes.fromhex(src.app_hash)).result==1
            for i in range(snapshot['chunks']-1):
                assert client.call('apply_snapshot_chunk',index=i,chunk=src.load_snapshot_chunk(4,1,i),sender='fixture').result==1
            try:client.call('apply_snapshot_chunk',index=snapshot['chunks']-1,
                           chunk=src.load_snapshot_chunk(4,1,snapshot['chunks']-1),sender='fixture')
            except ConnectionError:pass
            else:raise AssertionError('final Apply unexpectedly returned')
        killed=await_event(control,'killed.json',proc)
        assert killed['returncode']==-9 and killed['checkpoint']=={'height':4,'app_hash':src.app_hash,'local_block_rows':0}
        assert killed['install']['transaction_active'] is False
        # No automatic recreation/restart until a deliberately supplied marker.
        assert not sock.exists()
        write_event(control,'resume.json',{'schema':1,'run_id':run_id,'resume':True})
        ready=await_event(control,'recovery-ready.json',proc)
        assert ready['pid']!=killed['pid']
        with Client(str(sock),timeout=10) as client:
            assert client.call('info').last_block_height==4
            assert client.call('offer_snapshot',snapshot=snapshot,app_hash=bytes.fromhex(src.app_hash)).result==1
            for i in range(snapshot['chunks']):
                assert client.call('apply_snapshot_chunk',index=i,chunk=src.load_snapshot_chunk(4,1,i),sender='fixture').result==1
            recovery=await_event(control,'recovered.json',proc)
            assert recovery['checkpoint_recovery'] is True and recovery['transaction_active'] is False
            assert client.call('check_tx',tx=case['pre_snapshot_tx']).code!=0
            # New non-empty block after recovery, then enough blocks to prune.
            for h in range(5,10):
                txs=[case['post_snapshot_tx']] if h==5 else []
                block_hash=hashlib.sha256(str(h).encode()).digest()
                src.finalize_block(txs,h,block_hash);src.commit()
                answer=client.call('finalize_block',txs=txs,height=h,hash=block_hash)
                assert all(r.code==0 for r in answer.tx_results)
                assert client.call('commit').retain_height==0
            query=client.call('query',path='/state');assert query.code==0
            target=json.loads(query.value);assert target==json.loads(src.query('/state')['value'])
            hist=json.loads(client.call('query',path='/history').value)
            if keep is not None:verify_history_window(hist,height=9,bootstrap=4,keep=keep,receipts=2)
            # Once ordinary blocks exist, snapshot-only recovery must be closed.
            assert client.call('offer_snapshot',snapshot=snapshot,app_hash=bytes.fromhex(src.app_hash)).result==2
        result={'commitment':'smt-v1' if smt else 'legacy-flat-v1','keep':keep,
                'observed_exit':killed['returncode'],'snapshot_height':4,'final_height':9,
                'app_hash':src.app_hash,'native_receipts':len(src.native['receipts']),
                'post_snapshot_payment_executed':True,'state_equal':True,
                'checkpoint_recovery_observed':True,'retention_flag_repeated':False,
                'engine_executed':False,'history':hist}
        (root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        return result
    finally:
        src.close()
        if proc.poll() is None:proc.terminate()
        try:proc.wait(timeout=8)
        except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
        log.close()


class ProcessTests(unittest.TestCase):
    def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def test_flat_kill_recovery_and_new_payment(self):process_case(self.root/'flat')
    def test_smt_kill_recovery_and_new_payment(self):process_case(self.root/'smt',smt=True)
    def test_flat_retained_kill_recovery_and_new_payment(self):process_case(self.root/'flat',keep=2)
    def test_smt_retained_kill_recovery_and_new_payment(self):process_case(self.root/'smt',smt=True,keep=2)
    def test_incomplete_event_is_unknown(self):
        (self.root/'partial.json').write_bytes(b'{');(self.root/'partial.json').chmod(0o600)
        self.assertIsNone(read_event(self.root,'partial.json'))
    def test_duplicate_event_fields_refused(self):
        (self.root/'bad.json').write_bytes(b'{"x":1,"x":2}\n');(self.root/'bad.json').chmod(0o600)
        with self.assertRaises(ValueError):read_event(self.root,'bad.json')
    def test_event_output_never_overwrites(self):
        write_event(self.root,'event.json',{'x':1})
        with self.assertRaises(FileExistsError):write_event(self.root,'event.json',{'x':2})
        self.assertEqual(read_event(self.root,'event.json'),{'x':1})
    def test_event_symlink_refused(self):
        write_event(self.root,'event.json',{'x':1});(self.root/'link.json').symlink_to(self.root/'event.json')
        with self.assertRaises(OSError):read_event(self.root,'link.json')
    def test_wrong_socket_inode_is_not_unlinked(self):
        sock=socket.socket(socket.AF_UNIX);path=self.root/'sock';sock.bind(str(path));m=path.stat()
        try:
            with self.assertRaises(ValueError):remove_exact_socket(path,{'device':m.st_dev,'inode':m.st_ino+1})
            self.assertTrue(path.exists())
        finally:sock.close()
    def test_regular_file_never_unlinked_as_socket(self):
        path=self.root/'file';path.write_text('preserve');m=path.stat()
        with self.assertRaises(ValueError):remove_exact_socket(path,{'device':m.st_dev,'inode':m.st_ino})
        self.assertEqual(path.read_text(),'preserve')
    def test_missing_engine_explicit_for_retention_and_crash(self):
        r=run(str(self.root/'missing'),self.root/'out.json',1,block_history_keep=2,final_apply_crash=True)
        self.assertEqual(r['status'],'unassessed');self.assertEqual(r['checks'],[])
        self.assertFalse(r['final_apply_recovery_verified'])
    def test_invalid_retention_rejected_before_run(self):
        for value in (True,1,2.0,'2',65):
            with self.assertRaises(ValueError):run('missing',self.root/'out.json',1,block_history_keep=value)
        self.assertFalse((self.root/'out.json').exists())


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        c=build_case('anchor-test',1);engine,self.trust,self.keys=validators(c['genesis']);self.raw=encode(engine)
        h=make_header(self.trust,6,'a'*64,previous={'hash':'b'*64,'parts':{'total':1,'hash':'c'*64}});self.signed=make_commit(h,self.trust,self.keys)
        self.mark={'height':5,'app_hash':'a'*64}
    def test_exact_signed_next_height_verifies(self):
        self.assertEqual(verify_snapshot_anchor(self.signed,self.raw,self.mark)['height'],6)
    def test_endpoint_hash_alone_is_not_signed_evidence(self):
        with self.assertRaises(ValueError):verify_snapshot_anchor({'app_hash':'a'*64},self.raw,self.mark)
    def test_forged_signature_refused(self):
        s=copy.deepcopy(self.signed);s['commit']['signatures'][0]['signature']='AA=='
        with self.assertRaises(ValueError):verify_snapshot_anchor(s,self.raw,self.mark)
    def test_wrong_marker_height_refused(self):
        with self.assertRaises(ValueError):verify_snapshot_anchor(self.signed,self.raw,{**self.mark,'height':4})
    def test_wrong_marker_hash_refused(self):
        with self.assertRaises(ValueError):verify_snapshot_anchor(self.signed,self.raw,{**self.mark,'app_hash':'b'*64})
    def test_boolean_height_refused(self):
        with self.assertRaises(ValueError):verify_snapshot_anchor(self.signed,self.raw,{**self.mark,'height':True})
    def test_history_scope_false_is_required(self):
        value={'scope':'local_application_block_results','application_height':10,'native_receipt_count':2,
            'availability':{'keep_blocks':2,'bootstrap_height':5,'pruned_through':8,'retained_from':9,
                'retained_through':10,'retained_count':2,'within_configured_window':True},
            'native_receipts_pruned':False,'cometbft_retain_height':0,'engine_history_pruning_requested':False,
            'historical_transaction_absence_proven':False,'total_storage_bounded':False}
        verify_history_window(value,height=10,bootstrap=5,keep=2,receipts=2)
        for k,v in [('native_receipts_pruned',True),('cometbft_retain_height',False),('total_storage_bounded',True)]:
            with self.assertRaises(ValueError):verify_history_window({**value,k:v},height=10,bootstrap=5,keep=2,receipts=2)

if __name__=='__main__':unittest.main()
