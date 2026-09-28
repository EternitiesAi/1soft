import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch

from commit_verifier import encode, load_json, header_hash
from certificate_fixture import make_commit
from receipt_capsule import (ArchiveError, MAX_BYTES, pack_receipt, verify_capsule, sha,
                             transaction_identity)
from receipt_archive import ReceiptArchive, write_new
from fixtures_archive import case

ROOT = Path(__file__).resolve().parents[1]

class CapsuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.c = case()
    def verify(self, capsule=None, **kwargs):
        c = self.c
        args = {'expected_transaction':c['raw'], 'expected_header_hash':c['pin'], **kwargs}
        return verify_capsule(c['capsule'] if capsule is None else capsule,
                              c['genesis'], c['genesis_sha256'], **args)
    def changed(self): return copy.deepcopy(self.c['capsule'])
    def test_proof_survives_old_block_result_pruning(self):
        self.assertEqual(self.c['old_block_code'], 2)
        r = self.verify(); self.assertEqual(r['status'], 'verified-historical-receipt')
        self.assertTrue(r['inclusion_to_state_ancestry_verified'])
        self.assertFalse(r['historical_absence_proven']);self.assertFalse(r['wallet_reservations_changed'])
    def test_selected_smt_proof_omits_other_state(self):
        c = self.c['capsule']
        self.assertEqual(len(c['witness']['entries']),1)
        self.assertNotIn('native',c['witness']);self.assertEqual(c['witness']['entries'][0]['table'],'receipts')
    def test_flat_commitment_keeps_full_state(self):
        c=case(False)
        self.assertEqual(c['capsule']['proof_kind'],'legacy-full-state-v1')
        self.assertEqual(c['capsule']['witness'],c['packet']['state'])
        verify_capsule(c['capsule'],c['genesis'],c['genesis_sha256'],
                       expected_transaction=c['raw'],expected_header_hash=c['pin'])
    def test_protocol_one_full_state_receipt(self):
        c=case(smt=False, protocol=1)
        r=verify_capsule(c['capsule'],c['genesis'],c['genesis_sha256'],
                         expected_transaction=c['raw'],expected_header_hash=c['pin'])
        self.assertEqual(r['proof_kind'],'legacy-full-state-v1')
    def test_protocol_two_full_state_receipt(self):
        c=case(smt=False, protocol=2)
        r=verify_capsule(c['capsule'],c['genesis'],c['genesis_sha256'],
                         expected_transaction=c['raw'],expected_header_hash=c['pin'])
        self.assertEqual(r['receipt']['envelope']['body']['version'],2)
    def test_no_network_or_key_unlock_for_verification(self):
        with patch('socket.socket',side_effect=AssertionError('no network')), \
             patch('certified_wallet._load_vault',side_effect=AssertionError('no private key')):
            self.verify()
    def test_wrong_external_header_pin_refused(self):
        with self.assertRaises(ValueError):self.verify(expected_header_hash='0'*64)
    def test_wrong_genesis_pin_refused(self):
        with self.assertRaises(ValueError):verify_capsule(self.c['capsule'], self.c['genesis'],'0'*64,
                expected_transaction=self.c['raw'],expected_header_hash=self.c['pin'])
    def test_wrong_exact_signed_transaction_refused(self):
        raw=base64.b64decode(self.c['items'][1]['tx'])
        with self.assertRaises(ValueError):self.verify(expected_transaction=raw)
    def test_body_same_but_signature_changed_is_not_same_payment_bytes(self):
        env=json.loads(self.c['raw']);env['signature']='0'*128
        with self.assertRaises(ValueError):self.verify(expected_transaction=encode(env))
    def test_missing_ancestry_refused(self):
        c=self.changed();c['continuation']=[]
        with self.assertRaises(ValueError):self.verify(c)
    def test_wrong_ancestry_order_refused(self):
        c=self.changed();c['continuation'].reverse()
        with self.assertRaises(ValueError):self.verify(c)
    def test_forged_intermediate_commit_refused(self):
        c=self.changed();c['continuation'][0]['commit']['signatures'][0]['signature']='AA=='
        with self.assertRaises(ValueError):self.verify(c)
    def test_alternate_valid_signed_branch_refused(self):
        c=self.changed();h=c['continuation'][0]['header'];h['last_block_id']['parts']['hash']='ab'*32
        c['continuation'][0]=make_commit(h,self.c['trust'],self.c['keys'])
        with self.assertRaisesRegex(ValueError,'does not extend'):self.verify(c)
    def test_forged_final_commit_refused(self):
        c=self.changed();c['state_commit']['commit']['signatures'][0]['signature']='AA=='
        with self.assertRaises(ValueError):self.verify(c)
    def test_tampered_merkle_proof_refused(self):
        c=self.changed();c['witness']['entries'][0]['siblings'][0]='0'*64
        with self.assertRaises(ValueError):self.verify(c)
    def test_receipt_absence_proof_cannot_be_an_archived_receipt(self):
        from state_tree import make_witness
        c=self.changed();s=self.c['state']
        c['witness']=make_witness(s['genesis'],s['height'],s['native'],[('receipts','f'*64)])
        with self.assertRaises(ValueError):self.verify(c)
    def test_unsupported_version_refused(self):
        c=self.changed();c['schema']=True
        with self.assertRaises(ValueError):self.verify(c)
    def test_extra_authority_field_refused(self):
        c=self.changed();c['paid']=True
        with self.assertRaises(ValueError):self.verify(c)
    def test_capsule_does_not_determine_its_own_trust(self):
        c=self.changed();c['expected_header_hash']=self.c['pin']
        with self.assertRaises(ValueError):self.verify(c)
    def test_duplicate_input_json_refused(self):
        with self.assertRaises(ValueError):load_json(b'{"schema":1,"schema":2}')
    def test_packet_wrong_state_refused_before_packing(self):
        p=copy.deepcopy(self.c['packet']);p['state']['native']['accounts'][0][4]+=1
        with self.assertRaises(ValueError):pack_receipt(p,self.c['genesis'],self.c['genesis_sha256'],
            expected_transaction=self.c['raw'],expected_header_hash=self.c['pin'],continuation=self.c['links'])
    def test_duplicate_requested_transaction_witness_refused(self):
        p=copy.deepcopy(self.c['packet']);p['transactions']*=2
        with self.assertRaises(ValueError):pack_receipt(p,self.c['genesis'],self.c['genesis_sha256'],
            expected_transaction=self.c['raw'],expected_header_hash=self.c['pin'],continuation=self.c['links'])
    def test_adjacent_inclusion_needs_no_intermediate_headers(self):
        c=case(count=1)
        self.assertEqual(c['capsule']['continuation'],[])
    def test_oversized_capsule_refused(self):
        c=self.changed();c['oversized']='x'*(MAX_BYTES+1)
        with self.assertRaises(ValueError):self.verify(c)

class ArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.c=case()
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.path=self.root/'receipts.sqlite'
        self.a=self.open(create=True)
    def tearDown(self): self.a.close();self.tmp.cleanup()
    def open(self, **args):return ReceiptArchive(self.path,self.c['genesis'],self.c['genesis_sha256'],**args)
    def put(self,a=None,c=None):
        c=c or self.c
        return (a or self.a).put(c['capsule'],expected_transaction=c['raw'],expected_header_hash=c['pin'])
    def test_store_reopen_lookup_and_exact_export(self):
        r=self.put();self.a.close();self.a=self.open()
        self.assertEqual(self.a.lookup(self.c['raw'])['status'],'available')
        self.assertEqual(self.a.export(r['evidence_id']),self.c['capsule'])
    def test_caller_mutation_after_verification_cannot_change_stored_bytes(self):
        c=copy.deepcopy(self.c['capsule'])
        actual=verify_capsule
        def mutate_after(*args, **kwargs):
            r=actual(*args, **kwargs)
            c['transaction']='AA=='
            return r
        with patch('receipt_archive.verify_capsule',side_effect=mutate_after):
            r=self.a.put(c,expected_transaction=self.c['raw'],expected_header_hash=self.c['pin'])
        self.assertEqual(self.a.export(r['evidence_id']),self.c['capsule'])
    def test_duplicate_is_idempotent(self):
        self.put();before=list(self.a.db.iterdump());r=self.put()
        self.assertEqual(r['status'],'already_stored');self.assertEqual(list(self.a.db.iterdump()),before)
    def test_missing_is_unavailable_not_unpaid(self):
        r=self.a.lookup(self.c['raw']);self.assertEqual(r['status'],'unavailable')
        self.assertFalse(r['historical_absence_proven']);self.assertFalse(r['wallet_reservations_changed'])
    def test_read_only_inspection(self):
        self.put();self.a.close();self.a=self.open(read_only=True)
        self.assertEqual(self.a.lookup(self.c['raw'])['status'],'available')
        with self.assertRaises(ValueError):self.put()
    def test_existing_empty_file_is_not_initialized(self):
        self.a.close();self.path.unlink();self.path.touch(mode=0o600)
        with self.assertRaises(ValueError):self.open()
        self.assertEqual(self.path.read_bytes(),b'')
    def test_never_reinitializes_existing_archive(self):
        self.put();before=self.a.lookup(self.c['raw'])
        with self.assertRaises(FileExistsError):self.open(create=True)
        self.assertEqual(self.a.lookup(self.c['raw']),before)
    def test_wallet_database_is_not_used_or_modified(self):
        p=self.root/'wallet.sqlite';db=sqlite3.connect(p);db.execute('CREATE TABLE decisions(secret TEXT)');db.commit();db.close();p.chmod(0o600)
        before=p.read_bytes()
        with self.assertRaises(ValueError):ReceiptArchive(p,self.c['genesis'],self.c['genesis_sha256'])
        self.assertEqual(p.read_bytes(),before)
    def test_missing_policy_refused(self):
        self.a.db.execute('DELETE FROM archive_policy');self.a.close()
        with self.assertRaises(ValueError):self.open()
    def test_payload_corruption_refused_even_if_digest_index_rewritten(self):
        self.put();row=self.a.db.execute('SELECT * FROM capsules').fetchone();c=json.loads(row[6])
        c['state_commit']['commit']['signatures'][0]['signature']='AA=='
        raw=encode(c)
        self.a.db.execute('UPDATE capsules SET id=?,payload=?,bytes=?',(sha(raw),raw,len(raw)))
        with self.assertRaises(ValueError):self.a.lookup(self.c['raw'])
    def test_index_tampering_refused(self):
        self.put();self.a.db.execute('UPDATE capsules SET receipt_hash=?',('a'*64,))
        with self.assertRaises(ValueError):self.a.lookup(self.c['raw'])
    def test_capacity_refuses_instead_of_evicting(self):
        self.put();self.a.db.execute('UPDATE archive_policy SET max_entries=1')
        other=case(selected=2)
        with self.assertRaisesRegex(ValueError,'capacity reached'):self.put(c=other)
        self.assertEqual(self.a.lookup(self.c['raw'])['status'],'available')
        self.assertEqual(self.a.lookup(other['raw'])['status'],'unavailable')
    def test_byte_limit_refuses_without_partial_row(self):
        self.a.db.execute('UPDATE archive_policy SET max_bytes=1')
        with self.assertRaises(ValueError):self.put()
        self.assertEqual(self.a.db.execute('SELECT count(*) FROM capsules').fetchone()[0],0)
    def test_failed_insert_leaves_no_row(self):
        # A SQLite authorizer provides a local DB fault without altering schema.
        def deny(action, *args):return sqlite3.SQLITE_DENY if action==sqlite3.SQLITE_INSERT else sqlite3.SQLITE_OK
        self.a.db.set_authorizer(deny)
        with self.assertRaises(sqlite3.DatabaseError):self.put()
        self.a.db.set_authorizer(None)
        self.assertEqual(self.a.lookup(self.c['raw'])['status'],'unavailable')
    def test_two_writers_create_one_record(self):
        def work(_):
            with self.open() as a:return self.put(a)['status']
        with ThreadPoolExecutor(max_workers=2) as pool:statuses=list(pool.map(work,range(2)))
        self.assertEqual(sorted(statuses),['already_stored','stored'])
    def test_readonly_export_is_not_new_state_or_authority(self):
        r=self.put();before=list(self.a.db.iterdump());self.a.export(r['evidence_id']);self.a.lookup(self.c['raw'])
        self.assertEqual(list(self.a.db.iterdump()),before)
    def test_competing_valid_receipts_are_preserved_no_winner(self):
        # Exact same signed transaction executes at a different height/sequence
        # on a separately constructed synthetic fork under the same genesis keys.
        alternate=fork_case(self.c)
        self.put();self.put(c=alternate)
        r=self.a.lookup(self.c['raw']);self.assertEqual(r['status'],'conflict')
        self.assertTrue(r['competing_receipts']);self.assertIsNone(r['selected_winner'])
        self.assertEqual(len(r['evidence_ids']),2)
        for evidence in r['evidence_ids']:self.a.export(evidence)
    def test_conflict_result_does_not_depend_on_arrival_order(self):
        alt=fork_case(self.c);self.put(c=alt);self.put()
        first=self.a.lookup(self.c['raw'])
        p=self.root/'second.sqlite'
        with ReceiptArchive(p,self.c['genesis'],self.c['genesis_sha256'],create=True) as second:
            self.put(second);self.put(second,alt)
            self.assertEqual(second.lookup(self.c['raw']),first)
    def test_distinct_signed_headers_at_same_height_are_not_silently_selected(self):
        alt=copy.deepcopy(self.c['capsule'])
        h=alt['state_commit']['header'];h['consensus_hash']='c3'*32
        alt['state_commit']=make_commit(h,self.c['trust'],self.c['keys'])
        self.put()
        self.a.put(alt,expected_transaction=self.c['raw'],expected_header_hash=header_hash(h).hex())
        r=self.a.lookup(self.c['raw'])
        self.assertEqual(r['status'],'conflict');self.assertTrue(r['competing_signed_headers'])
        self.assertFalse(r['competing_receipts']);self.assertIsNone(r['selected_winner'])
    def test_executed_but_not_archived_payment_is_unavailable_not_absent(self):
        self.put();other=base64.b64decode(self.c['items'][1]['tx'])
        self.assertTrue(any(row[0]==transaction_identity(other)[0] for row in self.c['state']['native']['receipts']))
        r=self.a.lookup(other)
        self.assertEqual(r['status'],'unavailable');self.assertFalse(r['historical_absence_proven'])
    def test_same_receipt_in_later_state_does_not_conflict(self):
        later=case(count=8)
        self.put();self.put(c=later)
        r=self.a.lookup(self.c['raw']);self.assertEqual(r['status'],'available');self.assertEqual(len(r['evidence_ids']),2)
    def test_symlink_archive_refused(self):
        self.a.close();self.path.rename(self.root/'real');self.path.symlink_to(self.root/'real')
        with self.assertRaises(ValueError):self.open()
    def test_sidecar_alias_refused(self):
        self.a.close();p=Path(str(self.path)+'-wal');p.unlink(missing_ok=True);p.symlink_to(self.path)
        with self.assertRaises(ValueError):self.open()
    def test_group_readable_archive_refused(self):
        self.a.close();self.path.chmod(0o640)
        with self.assertRaises(ValueError):self.open()
    def test_export_output_never_overwritten(self):
        p=self.root/'receipt.json';write_new(p,encode(self.c['capsule']));old=p.read_bytes()
        with self.assertRaises(FileExistsError):write_new(p,b'{}')
        self.assertEqual(p.read_bytes(),old)
    def test_failed_export_does_not_discard_archived_evidence(self):
        r=self.put()
        with patch('receipt_archive.os.fsync',side_effect=OSError('fixture IO failure')):
            with self.assertRaises(OSError):write_new(self.root/'out.json',encode(self.a.export(r['evidence_id'])))
        self.assertEqual(self.a.lookup(self.c['raw'])['status'],'available')
    def test_archive_bytes_are_private(self):
        self.assertEqual(self.path.stat().st_mode&0o777,0o600)
    def crash(self,after_commit):
        (self.root/'genesis.json').write_bytes(self.c['genesis'])
        (self.root/'capsule.json').write_bytes(encode(self.c['capsule']))
        (self.root/'transaction.json').write_bytes(self.c['raw'])
        code='''import json,os,sys
from pathlib import Path
from receipt_archive import ReceiptArchive
r=Path(sys.argv[1]);a=ReceiptArchive(r/'receipts.sqlite',(r/'genesis.json').read_bytes(),sys.argv[2])
if sys.argv[4]=='before':
 def stop(sql):
  if sql=='COMMIT':os._exit(37)
 a.db.set_trace_callback(stop)
a.put(json.loads((r/'capsule.json').read_bytes()),expected_transaction=(r/'transaction.json').read_bytes(),expected_header_hash=sys.argv[3])
os._exit(38)
'''
        p=subprocess.run([sys.executable,'-c',code,str(self.root),self.c['genesis_sha256'],self.c['pin'],
                          'after' if after_commit else 'before'],capture_output=True,timeout=10)
        self.assertEqual(p.returncode,38 if after_commit else 37,p.stderr)
    def test_actual_process_exit_before_commit_has_no_record(self):
        self.crash(False);self.assertEqual(self.a.lookup(self.c['raw'])['status'],'unavailable')
    def test_actual_process_exit_after_commit_retains_exact_record(self):
        self.crash(True);r=self.a.lookup(self.c['raw']);self.assertEqual(r['status'],'available')
        self.assertEqual(self.a.export(r['evidence_ids'][0]),self.c['capsule'])


def fork_case(original):
    """Move only the selected signed transaction behind an empty first block."""
    from block_application import BlockApplication
    from certificate_fixture import make_header
    g=original['state']['genesis'];trust=original['trust'];keys=original['keys'];raw=original['raw']
    app=BlockApplication(':memory:',expected_genesis=g);app.init_chain(g['chain_id'],g)
    previous=None;headers=[];item=None
    try:
        for h in range(1,7):
            txs=[raw] if h==2 else []
            head=make_header(trust,h,app.app_hash,txs,previous);head['version']['app']='3'
            signed=make_commit(head,trust,keys);headers.append(signed);previous=signed['commit']['block_id']
            app.finalize_block(txs,h,header_hash(head));app.commit()
            if h==2:item={'tx':base64.b64encode(raw).decode(),'commit':signed,
                         'block':{'block_id':previous,'block':{'header':head,'data':{'txs':[base64.b64encode(raw).decode()]}}}}
        state=json.loads(app.query('/state')['value']);head=make_header(trust,7,app.app_hash,previous=previous)
        head['version']['app']='3';sc=make_commit(head,trust,keys)
        packet={'schema':1,'state':state,'state_commit':sc,'transactions':[item]}
        pin=header_hash(head).hex()
        capsule=pack_receipt(packet,original['genesis'],original['genesis_sha256'],expected_transaction=raw,
                             expected_header_hash=pin,continuation=headers[2:])
        return {**original,'capsule':capsule,'pin':pin}
    finally:app.close()


if __name__=='__main__':unittest.main()
