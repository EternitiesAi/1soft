import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from abci_server import Server
from abci_wire import Client
from block_application import BlockApplication, encode
from native_core import NativeLedger, address, canonical, public, sign
import state_sync
from state_sync import (APPLY_ACCEPT, APPLY_REJECT_SNAPSHOT, APPLY_RETRY,
                        OFFER_ABORT, OFFER_ACCEPT, OFFER_REJECT, OFFER_REJECT_FORMAT,
                        CHUNK_BYTES, FORMAT, MAX_METADATA_BYTES)


def fixture(*, smt=False):
    owner = Ed25519PrivateKey.from_private_bytes(bytes([21])*32)
    merchant = Ed25519PrivateKey.from_private_bytes(bytes([22])*32)
    genesis = {'chain_id':'1soft-state-sync-test','asset':'DEV','fee':2,
               'protocol_version':3 if smt else 1,
               'allocations':[{'public_key':public(owner),'units':1000},
                              {'public_key':public(merchant),'units':0}]}
    if smt: genesis['state_commitment']='smt-v1'
    return owner, merchant, genesis


def payment(genesis, owner, merchant, nonce=0, units=40):
    ledger=NativeLedger(':memory:',genesis)
    try:
        body=ledger.body(address(public(owner)),nonce,
                         {'type':'transfer','to':address(public(merchant)),'units':units},
                         valid_until=100)
        return canonical(sign(owner,body))
    finally: ledger.close()


def duplicate_account_snapshot(source, genesis):
    desc=source.list_snapshots()[0]
    raw=b''.join(source.load_snapshot_chunk(desc['height'],desc['format'],i)
                 for i in range(desc['chunks']))
    payload=json.loads(raw)
    payload['native']['accounts'].append(list(payload['native']['accounts'][0]))
    raw=encode(payload)
    desc=state_sync._descriptor(payload['height'],raw,genesis,payload['app_hash'])
    chunks=[raw[i:i+CHUNK_BYTES] for i in range(0,len(raw),CHUNK_BYTES)]
    return desc,chunks


class StateSyncTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()

    def apps(self, *, smt=False):
        owner,merchant,genesis=fixture(smt=smt)
        source=BlockApplication(self.root/('source-smt.sqlite' if smt else 'source.sqlite'),expected_genesis=genesis)
        source.init_chain(genesis['chain_id'],genesis)
        tx=payment(genesis,owner,merchant)
        source.finalize_block([tx],1,hashlib.sha256(b'1').digest());source.commit()
        source.finalize_block([],2,hashlib.sha256(b'2').digest());source.commit()
        target=BlockApplication(self.root/('target-smt.sqlite' if smt else 'target.sqlite'),expected_genesis=genesis)
        return source,target,genesis,tx

    def transfer_snapshot(self, source, target):
        snapshots=source.list_snapshots();self.assertEqual(len(snapshots),1)
        desc=snapshots[0]
        chunks=[source.load_snapshot_chunk(desc['height'],desc['format'],i) for i in range(desc['chunks'])]
        self.assertTrue(all(chunks));self.assertEqual(target.offer_snapshot(desc,bytes.fromhex(source.app_hash)),OFFER_ACCEPT)
        for index,chunk in enumerate(chunks):
            result=target.apply_snapshot_chunk(index,chunk,'peerA')
            self.assertEqual(result['result'],APPLY_ACCEPT,result)
        return desc,chunks

    def check_roundtrip(self, *, smt=False):
        source,target,genesis,tx=self.apps(smt=smt)
        try:
            desc,chunks=self.transfer_snapshot(source,target)
            self.assertEqual(target.height,source.height)
            self.assertEqual(target.app_hash,source.app_hash)
            self.assertEqual(target.query('/state')['value'],source.query('/state')['value'])
            self.assertEqual(target.check_tx(tx)['code'],1)
            self.assertEqual(target.query('/block/2')['code'],1,'state sync must not invent unauthenticated block metadata')
            if smt:
                from native_core import digest
                self.assertIsNotNone(target.proof_index)
                self.assertEqual(target.proof_index.audit(digest(genesis),target.height,target.app_hash)['height'],2)
            target.close();target=BlockApplication(self.root/('target-smt.sqlite' if smt else 'target.sqlite'),expected_genesis=genesis)
            self.assertEqual(target.info()['height'],2)
            marker=target.db.execute('SELECT height,app_hash FROM state_sync_marker WHERE id=1').fetchone()
            self.assertEqual(marker,(2,target.app_hash))
            block_hash=hashlib.sha256(b'3').digest()
            a=source.finalize_block([],3,block_hash);source.commit()
            b=target.finalize_block([],3,block_hash);target.commit()
            self.assertEqual(a,b);self.assertEqual(source.query('/state')['value'],target.query('/state')['value'])
            self.assertEqual(target.query('/block/3')['code'],0)
            self.assertEqual(target.db.execute('SELECT height,app_hash FROM state_sync_marker WHERE id=1').fetchone(),marker,
                             'later block commits preserve the local state-sync receipt')
        finally:
            source.close();target.close()

    def test_flat_snapshot_roundtrip_and_next_block(self):self.check_roundtrip(smt=False)
    def test_smt_snapshot_roundtrip_and_proof_index(self):self.check_roundtrip(smt=True)

    def test_height_zero_advertises_no_snapshot(self):
        _,_,genesis=fixture();app=BlockApplication(self.root/'zero.sqlite',expected_genesis=genesis)
        try:
            app.init_chain(genesis['chain_id'],genesis);self.assertEqual(app.list_snapshots(),[])
        finally:app.close()

    def test_unanchored_fresh_app_aborts_offer(self):
        source,target,genesis,tx=self.apps()
        unanchored=BlockApplication(self.root/'unanchored.sqlite')
        try:
            desc=source.list_snapshots()[0]
            self.assertEqual(unanchored.offer_snapshot(desc,bytes.fromhex(source.app_hash)),OFFER_ABORT)
        finally:source.close();target.close();unanchored.close()

    def test_initialized_app_aborts_offer_without_mutation(self):
        source,target,genesis,tx=self.apps()
        other=BlockApplication(self.root/'other.sqlite',expected_genesis=genesis)
        try:
            other.init_chain(genesis['chain_id'],genesis);before=other.query('/state')['value']
            self.assertEqual(other.offer_snapshot(source.list_snapshots()[0],bytes.fromhex(source.app_hash)),OFFER_ABORT)
            self.assertEqual(other.query('/state')['value'],before)
        finally:source.close();target.close();other.close()

    def test_wrong_format_rejected(self):
        source,target,genesis,tx=self.apps()
        try:
            desc={**source.list_snapshots()[0],'format':99}
            self.assertEqual(target.offer_snapshot(desc,bytes.fromhex(source.app_hash)),OFFER_REJECT_FORMAT)
        finally:source.close();target.close()

    def test_wrong_trusted_app_hash_rejected(self):
        source,target,genesis,tx=self.apps()
        try:
            desc=source.list_snapshots()[0]
            self.assertEqual(target.offer_snapshot(desc,b'\0'*32),OFFER_REJECT)
            self.assertFalse(target.info()['initialized'])
        finally:source.close();target.close()

    def test_wrong_expected_genesis_rejected(self):
        source,target,genesis,tx=self.apps()
        bad=copy.deepcopy(genesis);bad['chain_id']='different-chain'
        wrong=BlockApplication(self.root/'wrong.sqlite',expected_genesis=bad)
        try:
            desc=source.list_snapshots()[0]
            self.assertEqual(wrong.offer_snapshot(desc,bytes.fromhex(source.app_hash)),OFFER_REJECT)
        finally:source.close();target.close();wrong.close()

    def test_metadata_over_bound_rejected(self):
        source,target,genesis,tx=self.apps()
        try:
            desc={**source.list_snapshots()[0],'metadata':b'x'*(MAX_METADATA_BYTES+1)}
            self.assertEqual(target.offer_snapshot(desc,bytes.fromhex(source.app_hash)),OFFER_REJECT)
        finally:source.close();target.close()


    def test_noncanonical_metadata_rejected(self):
        source,target,genesis,tx=self.apps()
        try:
            desc=source.list_snapshots()[0]
            parsed=json.loads(desc['metadata'])
            desc={**desc,'metadata':json.dumps(parsed,indent=2).encode()}
            self.assertEqual(target.offer_snapshot(desc,bytes.fromhex(source.app_hash)),OFFER_REJECT)
        finally:source.close();target.close()

    def test_internal_install_failure_rolls_back_everything(self):
        source,target,genesis,tx=self.apps(smt=True)
        try:
            desc=source.list_snapshots()[0];chunks=[source.load_snapshot_chunk(desc['height'],FORMAT,i) for i in range(desc['chunks'])]
            self.assertEqual(target.offer_snapshot(desc,bytes.fromhex(source.app_hash)),OFFER_ACCEPT)
            target.db.execute("CREATE TRIGGER fail_sync BEFORE INSERT ON state_sync_marker BEGIN SELECT RAISE(ABORT,'fixture failure'); END")
            for i,chunk in enumerate(chunks[:-1]):self.assertEqual(target.apply_snapshot_chunk(i,chunk,'peer')['result'],APPLY_ACCEPT)
            with self.assertRaises(sqlite3.IntegrityError):target.apply_snapshot_chunk(len(chunks)-1,chunks[-1],'peer')
            self.assertIsNone(target.db.execute('SELECT 1 FROM committed').fetchone())
            self.assertIsNone(target.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='proof_checkpoint'").fetchone())
            self.assertFalse(target.info()['initialized'])
        finally:source.close();target.close()

    def test_duplicate_account_row_rejects_and_keeps_abci_endpoint_healthy(self):
        source,target,genesis,tx=self.apps()
        private=self.root/'abci'
        private.mkdir(mode=0o700)
        server=None;thread=None
        try:
            desc,chunks=duplicate_account_snapshot(source,genesis)
            server=Server(str(private/'app.sock'),target)
            thread=threading.Thread(target=server.serve_forever,
                                    kwargs={'poll_interval':.01},daemon=True)
            thread.start()
            with Client(str(server.owned_path)) as peer:
                offered=peer.call('offer_snapshot',snapshot=desc,
                                  app_hash=bytes.fromhex(source.app_hash))
                self.assertEqual(offered.result,OFFER_ACCEPT)
                for index,chunk in enumerate(chunks):
                    applied=peer.call('apply_snapshot_chunk',index=index,chunk=chunk,
                                      sender='malformed-peer')
                    self.assertEqual(applied.result,APPLY_REJECT_SNAPSHOT)
                self.assertEqual(peer.call('echo',message='still serving').message,
                                 'still serving')
            self.assertFalse(server.failed.is_set())
            self.assertEqual(server.metrics()['internal_faults'],0)
            self.assertFalse(target.info()['initialized'])
            self.assertIsNone(target.db.execute('SELECT 1 FROM committed').fetchone())
        finally:
            if server is not None:
                server.shutdown()
                if thread is not None:thread.join(2)
                server.server_close()
            source.close();target.close()

    def test_apphash_mismatch_closes_restored_native_ledger(self):
        source,target,genesis,tx=self.apps()
        owner,merchant,_=fixture()
        alternate=BlockApplication(self.root/'alternate.sqlite',expected_genesis=genesis)
        try:
            alternate.init_chain(genesis['chain_id'],genesis)
            alternate_tx=payment(genesis,owner,merchant,units=50)
            alternate.finalize_block([alternate_tx],1,hashlib.sha256(b'1').digest())
            alternate.commit()
            alternate.finalize_block([],2,hashlib.sha256(b'2').digest())
            alternate.commit()

            desc=alternate.list_snapshots()[0]
            raw=b''.join(alternate.load_snapshot_chunk(desc['height'],desc['format'],i)
                         for i in range(desc['chunks']))
            payload=json.loads(raw)
            # A different but ledger-valid branch shares the genesis/height while
            # its native state does not match the trusted source branch AppHash.
            payload['app_hash']=source.app_hash
            raw=encode(payload)
            desc=state_sync._descriptor(payload['height'],raw,genesis,source.app_hash)
            chunks=[raw[i:i+CHUNK_BYTES] for i in range(0,len(raw),CHUNK_BYTES)]
            self.assertEqual(target.offer_snapshot(desc,bytes.fromhex(source.app_hash)),OFFER_ACCEPT)

            import block_application
            original_restore=block_application.restore
            tracked=[]

            class TrackedLedger:
                def __init__(self,ledger):
                    self.ledger=ledger
                    self.closed=False
                def close(self):
                    self.closed=True
                    self.ledger.close()

            def tracked_restore(restore_genesis,state):
                ledger=TrackedLedger(original_restore(restore_genesis,state))
                tracked.append(ledger)
                return ledger

            with patch('block_application.restore',side_effect=tracked_restore):
                result=None
                for index,chunk in enumerate(chunks):
                    result=target.apply_snapshot_chunk(index,chunk,'alternate-peer')
            self.assertEqual(result['result'],APPLY_REJECT_SNAPSHOT)
            self.assertEqual(len(tracked),1)
            self.assertTrue(tracked[0].closed)
            self.assertFalse(target.info()['initialized'])
        finally:
            source.close();target.close();alternate.close()

    def test_tampered_final_payload_never_commits(self):
        source,target,genesis,tx=self.apps()
        try:
            desc=source.list_snapshots()[0];chunks=[source.load_snapshot_chunk(desc['height'],FORMAT,i) for i in range(desc['chunks'])]
            self.assertEqual(target.offer_snapshot(desc,bytes.fromhex(source.app_hash)),OFFER_ACCEPT)
            bad=bytearray(chunks[-1]);bad[-1]^=1;chunks[-1]=bytes(bad)
            for i,chunk in enumerate(chunks[:-1]):self.assertEqual(target.apply_snapshot_chunk(i,chunk,'peerA')['result'],APPLY_ACCEPT)
            self.assertEqual(target.apply_snapshot_chunk(len(chunks)-1,chunks[-1],'peerA')['result'],APPLY_REJECT_SNAPSHOT)
            self.assertFalse(target.info()['initialized']);self.assertIsNone(target.db.execute('SELECT 1 FROM committed').fetchone())
        finally:source.close();target.close()

    def test_out_of_order_requests_exact_missing_chunk(self):
        source,target,genesis,tx=self.apps()
        try:
            with patch('state_sync.CHUNK_BYTES',512):
                desc=source.list_snapshots()[0];chunks=[source.load_snapshot_chunk(desc['height'],FORMAT,i) for i in range(desc['chunks'])]
                self.assertGreater(len(chunks),1)
                self.assertEqual(target.offer_snapshot(desc,bytes.fromhex(source.app_hash)),OFFER_ACCEPT)
                r=target.apply_snapshot_chunk(1,chunks[1],'peerB')
                self.assertEqual(r['result'],APPLY_RETRY);self.assertEqual(r['refetch_chunks'],[0])
                for i,c in enumerate(chunks):self.assertEqual(target.apply_snapshot_chunk(i,c,'peerB')['result'],APPLY_ACCEPT)
        finally:source.close();target.close()

    def test_duplicate_identical_chunk_is_idempotent_changed_duplicate_rejects(self):
        source,target,genesis,tx=self.apps()
        try:
            with patch('state_sync.CHUNK_BYTES',512):
                desc=source.list_snapshots()[0];chunks=[source.load_snapshot_chunk(desc['height'],FORMAT,i) for i in range(desc['chunks'])]
                self.assertGreater(len(chunks),1)
                self.assertEqual(target.offer_snapshot(desc,bytes.fromhex(source.app_hash)),OFFER_ACCEPT)
                self.assertEqual(target.apply_snapshot_chunk(0,chunks[0],'peer')['result'],APPLY_ACCEPT)
                self.assertEqual(target.apply_snapshot_chunk(0,chunks[0],'peer')['result'],APPLY_ACCEPT)
                altered=bytearray(chunks[0]);altered[0]^=1
                self.assertEqual(target.apply_snapshot_chunk(0,bytes(altered),'peer')['result'],APPLY_REJECT_SNAPSHOT)
        finally:source.close();target.close()

    def test_cached_snapshot_remains_loadable_after_source_advances(self):
        source,target,genesis,tx=self.apps()
        try:
            desc=source.list_snapshots()[0];first=source.load_snapshot_chunk(desc['height'],FORMAT,0)
            source.finalize_block([],3,hashlib.sha256(b'3').digest());source.commit()
            self.assertEqual(source.load_snapshot_chunk(desc['height'],FORMAT,0),first)
            self.assertEqual(source.list_snapshots()[0]['height'],3)
        finally:source.close();target.close()

    def test_partial_chunks_are_process_local_and_restart_cleanly(self):
        source,target,genesis,tx=self.apps()
        path=self.root/'target.sqlite'
        try:
            desc=source.list_snapshots()[0];chunks=[source.load_snapshot_chunk(desc['height'],FORMAT,i) for i in range(desc['chunks'])]
            self.assertEqual(target.offer_snapshot(desc,bytes.fromhex(source.app_hash)),OFFER_ACCEPT)
            if len(chunks)>1:self.assertEqual(target.apply_snapshot_chunk(0,chunks[0],'peer')['result'],APPLY_ACCEPT)
            target.close();target=BlockApplication(path,expected_genesis=genesis)
            self.assertFalse(target.info()['initialized'])
            self.transfer_snapshot(source,target);self.assertEqual(target.height,source.height)
        finally:source.close();target.close()

    def test_checkpoint_only_recovery_accepts_same_snapshot_after_lost_reply(self):
        source,target,genesis,tx=self.apps()
        target_path=self.root/'target.sqlite'
        try:
            desc=source.list_snapshots()[0]
            app_hash=source.app_hash
            chunks=[source.load_snapshot_chunk(desc['height'],desc['format'],i)
                    for i in range(desc['chunks'])]
            self.assertEqual(target.offer_snapshot(desc,bytes.fromhex(app_hash)),OFFER_ACCEPT)
            real_install=target.state_sync._install

            def install_then_lose_reply(payload, checked, **kwargs):
                real_install(payload,checked,**kwargs)
                raise RuntimeError('simulated process death before APPLY_ACCEPT')

            with patch.object(target.state_sync,'_install',side_effect=install_then_lose_reply):
                for index,chunk in enumerate(chunks[:-1]):
                    self.assertEqual(target.apply_snapshot_chunk(index,chunk,'peer')['result'],APPLY_ACCEPT)
                with self.assertRaisesRegex(RuntimeError,'before APPLY_ACCEPT'):
                    target.apply_snapshot_chunk(len(chunks)-1,chunks[-1],'peer')

            target.close()
            target=BlockApplication(target_path,expected_genesis=genesis)
            self.assertEqual(target.offer_snapshot(desc,bytes.fromhex(app_hash)),OFFER_ACCEPT)
            for index,chunk in enumerate(chunks):
                self.assertEqual(target.apply_snapshot_chunk(index,chunk,'peer')['result'],APPLY_ACCEPT)
            self.assertEqual(target.height,2)
            self.assertEqual(target.app_hash,app_hash)
            self.assertEqual(target.query('/state')['value'],source.query('/state')['value'])
            self.assertEqual(target.db.execute(
                'SELECT height,app_hash FROM state_sync_marker WHERE id=1').fetchone(),
                (2,app_hash))
        finally:
            source.close();target.close()

    def test_checkpoint_only_recovery_accepts_newer_snapshot_after_source_restart(self):
        source,target,genesis,tx=self.apps(smt=True)
        source_path=self.root/'source-smt.sqlite'
        target_path=self.root/'target-smt.sqlite'
        try:
            first_desc=source.list_snapshots()[0]
            first_hash=source.app_hash
            first_chunks=[source.load_snapshot_chunk(first_desc['height'],FORMAT,i)
                          for i in range(first_desc['chunks'])]
            self.assertEqual(target.offer_snapshot(first_desc,bytes.fromhex(first_hash)),OFFER_ACCEPT)
            real_install=target.state_sync._install

            def install_then_lose_reply(payload, checked, **kwargs):
                real_install(payload,checked)
                raise RuntimeError('simulated process death before APPLY_ACCEPT')

            with patch.object(target.state_sync,'_install',side_effect=install_then_lose_reply):
                for index,chunk in enumerate(first_chunks[:-1]):
                    self.assertEqual(target.apply_snapshot_chunk(index,chunk,'peer')['result'],APPLY_ACCEPT)
                with self.assertRaisesRegex(RuntimeError,'before APPLY_ACCEPT'):
                    target.apply_snapshot_chunk(len(first_chunks)-1,first_chunks[-1],'peer')

            target.close()
            target=BlockApplication(target_path,expected_genesis=genesis)
            self.assertEqual(target.db.execute(
                'SELECT height,app_hash FROM state_sync_marker WHERE id=1').fetchone(),
                (2,first_hash))

            # A source restart clears its process-local old-snapshot cache.
            source.close()
            source=BlockApplication(source_path,expected_genesis=genesis)
            source.finalize_block([],3,hashlib.sha256(b'3').digest());source.commit()
            snapshots=source.list_snapshots()
            self.assertEqual([item['height'] for item in snapshots],[3])
            self.assertEqual(source.load_snapshot_chunk(2,FORMAT,0),b'')
            newer=snapshots[0]
            newer_chunks=[source.load_snapshot_chunk(newer['height'],newer['format'],i)
                          for i in range(newer['chunks'])]

            self.assertEqual(target.offer_snapshot(newer,bytes.fromhex(source.app_hash)),OFFER_ACCEPT)
            for index,chunk in enumerate(newer_chunks):
                self.assertEqual(target.apply_snapshot_chunk(index,chunk,'peer')['result'],APPLY_ACCEPT)
            self.assertEqual(target.height,3)
            self.assertEqual(target.app_hash,source.app_hash)
            self.assertEqual(target.query('/state')['value'],source.query('/state')['value'])
            marker=(3,target.app_hash)
            self.assertEqual(target.db.execute(
                'SELECT height,app_hash FROM state_sync_marker WHERE id=1').fetchone(),marker)
            from native_core import digest
            self.assertEqual(target.proof_index.audit(
                digest(genesis),target.height,target.app_hash)['height'],3)

            # Recovery cannot roll the checkpoint backward.
            self.assertEqual(target.offer_snapshot(first_desc,bytes.fromhex(first_hash)),OFFER_REJECT)
            # Once a normal block commits, this is no longer a checkpoint-only recovery state.
            block4=hashlib.sha256(b'4').digest()
            source.finalize_block([],4,block4);source.commit()
            target.finalize_block([],4,block4);target.commit()
            newer_again=source.list_snapshots()[0]
            before=target.query('/state')['value']
            self.assertEqual(target.offer_snapshot(newer_again,bytes.fromhex(source.app_hash)),OFFER_ABORT)
            self.assertEqual(target.query('/state')['value'],before)
        finally:
            source.close();target.close()

    def test_state_sync_marker_tamper_is_detected_on_reopen(self):
        source,target,genesis,tx=self.apps()
        path=self.root/'target.sqlite'
        try:
            self.transfer_snapshot(source,target);target.close()
            db=sqlite3.connect(path);db.execute("UPDATE state_sync_marker SET app_hash=?",('0'*64,));db.commit();db.close()
            with self.assertRaises(Exception):BlockApplication(path,expected_genesis=genesis)
            target=BlockApplication(':memory:')
        finally:source.close();target.close()


if __name__=='__main__':unittest.main()
