"""Version-2 persistence uses original proof authority and original logical bounds."""
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from block_application import encode
from p4_evidence import MAX_EVIDENCE_BYTES, content_id, nanos
from p4_fixture import build, bundle
from p4_read_store import P4ReadStore
import test_store as legacy


class CreationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.c = build()
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.path = self.root/'read.sqlite'
    def tearDown(self): self.temp.cleanup()
    def create(self, **args):
        return P4ReadStore(self.path, self.c['genesis'], self.c['policy'], create=True,
                           clock=lambda:self.c['now_ns'], **args)
    def test_explicit_format2_creates_seventh_logical_bytes_column(self):
        try: store = self.create(storage_version=2)
        except TypeError as error: self.fail('missing explicit format-2 creation: '+str(error))
        with store:
            self.assertEqual(store.db.execute('SELECT version FROM config').fetchone(), (2,))
            self.assertEqual(tuple(r[1] for r in store.db.execute('PRAGMA table_info(observations)')),
                             ('seq','evidence_id','parent_id','checked_ns','height','payload','logical_bytes'))
    def test_default_and_explicit_format1_keep_original_schema(self):
        for selected in (None, 1):
            with self.create(**({} if selected is None else {'storage_version':selected})) as store:
                self.assertEqual(store.db.execute('SELECT version FROM config').fetchone(), (1,))
                self.assertEqual(tuple(r[1] for r in store.db.execute('PRAGMA table_info(observations)')),
                                 ('seq','evidence_id','parent_id','checked_ns','height','payload'))
                self.assertEqual(store.storage_stats(), {'format_version':1,'observations':0,
                    'logical_evidence_bytes':0,'stored_payload_bytes':0,'spending_authority':False})
            self.path.unlink()
    def test_unsupported_selector_refused_before_file_creation(self):
        for version in (0, 3, True, '2', 2.0):
            with self.assertRaises(ValueError): self.create(storage_version=version)
            self.assertFalse(self.path.exists())
    def test_existing_stores_detect_version_but_refuse_creation_selector(self):
        for version in (1, 2):
            with self.create(storage_version=version): pass
            raw = self.path.read_bytes()
            with P4ReadStore(self.path,self.c['genesis'],self.c['policy'],read_only=True,
                             clock=lambda:self.c['now_ns']) as store:
                self.assertEqual(store.storage_stats()['format_version'], version)
            for selected in (1, 2):
                with self.assertRaises(ValueError):
                    P4ReadStore(self.path,self.c['genesis'],self.c['policy'],storage_version=selected)
                self.assertEqual(self.path.read_bytes(), raw)
            self.path.unlink()
    def test_original_format1_payload_bytes_are_unchanged(self):
        evidence = bundle(self.c,3); raw = encode(evidence)
        with self.create() as store:
            result=store.import_evidence(evidence,expected_tip=None)
            self.assertEqual(store.db.execute('SELECT payload FROM observations').fetchone()[0],raw)
            self.assertEqual(store.storage_stats(), {'format_version':1,'observations':1,
                'logical_evidence_bytes':len(raw),'stored_payload_bytes':len(raw),'spending_authority':False})
            self.assertEqual(encode(store.export(result['evidence_id'])),raw)


class StoreTestsFormat2(legacy.StoreTests):
    """Every existing StoreTests case, including processes/CAS, runs for version2."""
    def open(self, **args):
        if args.get('create'): args['storage_version'] = 2
        return super().open(**args)

    def test_framed_rehashed_signature_tampering_reaches_full_verifier(self):
        from p4_storage_codec import encode_payload
        self.ingest(); evidence=bundle(self.c,3)
        evidence['headers'][1]['signed_header']['commit']['signatures'][0]['signature']='AA=='
        raw=encode(evidence)
        self.s.db.execute('UPDATE observations SET evidence_id=?,payload=?,logical_bytes=?',
                          (content_id(evidence),encode_payload(raw),len(raw)))
        with self.assertRaises(ValueError): self.s.current()
    def test_exact_original_exports_ids_metrics_and_reopen(self):
        expected=[]; tip=None
        for height in (3,5,8,16):
            raw=encode(bundle(self.c,height)); result=self.ingest(height,tip=tip)
            self.assertEqual(result['evidence_id'],hashlib.sha256(raw).hexdigest())
            tip=result['evidence_id']; expected.append((tip,raw))
        stats=self.s.storage_stats()
        self.assertEqual(stats['format_version'],2); self.assertEqual(stats['observations'],4)
        self.assertEqual(stats['logical_evidence_bytes'],sum(len(raw) for _,raw in expected))
        self.assertLess(stats['stored_payload_bytes'],stats['logical_evidence_bytes'])
        self.assertFalse(stats['spending_authority'])
        self.s.close(); self.s=self.open(read_only=True)
        for evidence_id,raw in expected: self.assertEqual(encode(self.s.export(evidence_id)),raw)
        self.assertEqual(self.s.storage_stats(),stats)
    def test_storage_metrics_do_not_requalify_expired_trust(self):
        self.ingest(); before=self.all_rows(); stats=self.s.storage_stats()
        self.now=nanos(self.c['policy']['anchor_time'])+3600*10**9
        self.assertEqual(self.s.storage_stats(),stats)
        with self.assertRaises(ValueError):self.s.current()
        self.assertEqual(self.all_rows(),before)
    def test_logical_capacity_not_compressed_payload_controls_admission(self):
        first=self.ingest(); before=self.all_rows()
        logical=len(encode(bundle(self.c,3)))+len(encode(bundle(self.c,8)))-1
        with patch('p4_read_store.MAX_STORED_BYTES',logical):
            with self.assertRaisesRegex(ValueError,'capacity reached'):self.ingest(8,tip=first['evidence_id'])
        self.assertEqual(self.all_rows(),before)
    def test_expiry_during_compression_preserves_original_tip(self):
        import p4_storage_codec
        first=self.ingest();before=self.all_rows()
        original=p4_storage_codec.encode_payload
        def expire(raw):
            result=original(raw)
            self.now=nanos(self.c['policy']['anchor_time'])+3600*10**9
            return result
        with patch('p4_read_store.encode_payload',side_effect=expire):
            with self.assertRaisesRegex(ValueError,'currently valid'):self.ingest(8,tip=first['evidence_id'])
        self.assertEqual(self.all_rows(),before)
    def test_compression_error_rolls_back_and_store_remains_usable(self):
        first=self.ingest();before=self.all_rows()
        with patch('p4_read_store.encode_payload',side_effect=ValueError('compression refused')):
            with self.assertRaisesRegex(ValueError,'compression refused'):self.ingest(8,tip=first['evidence_id'])
        self.assertEqual(self.all_rows(),before)
        self.assertEqual(self.ingest(8,tip=first['evidence_id'])['status'],'recorded')
    def test_bad_descriptor_refused_before_any_proof_blob_fetch(self):
        self.ingest()
        bad=[('logical_bytes',0),('logical_bytes',MAX_EVIDENCE_BYTES+1),('logical_bytes',b'bad'),
             ('logical_bytes',1.5),('payload','not a blob'),('payload',b''),('payload',b'x'*15),
             ('payload',b'x'*(MAX_EVIDENCE_BYTES+16)),('height',513),('checked_ns',b'bad'),
             ('evidence_id',b'0'*64),('seq',2)]
        original=self.s.db.execute('SELECT * FROM observations').fetchone()
        for column,value in bad:
            with self.subTest(column=column,value_type=type(value).__name__):
                self.s.db.execute('DELETE FROM observations')
                self.s.db.execute('INSERT INTO observations VALUES (?,?,?,?,?,?,?)',original)
                self.s.db.execute('UPDATE observations SET '+column+'=?',(value,))
                statements=[];self.s.db.set_trace_callback(statements.append)
                with self.assertRaises(ValueError):self.s._catalog()
                self.s.db.set_trace_callback(None)
                self.assertFalse(any(sql.startswith('SELECT * FROM observations') or
                    sql.startswith('SELECT seq,payload') for sql in statements), statements)
    def test_aggregate_original_capacity_refused_before_blob_fetch(self):
        first=self.ingest();self.ingest(8,tip=first['evidence_id']);statements=[]
        self.s.db.set_trace_callback(statements.append)
        with patch('p4_read_store.MAX_STORED_BYTES',1):
            with self.assertRaisesRegex(ValueError,'capacity exceeded'):self.s._catalog()
        self.s.db.set_trace_callback(None)
        self.assertFalse(any(sql.startswith('SELECT seq,payload') for sql in statements))
    def test_exact_record_count_cap_refused_before_descriptor_or_blob_fetch(self):
        self.ingest();record=self.s.db.execute('SELECT * FROM observations').fetchone()
        self.s.db.execute('DELETE FROM observations')
        parent='0'*64
        for seq in range(1,34):
            evidence_id=hashlib.sha256(str(seq).encode()).hexdigest()
            self.s.db.execute('INSERT INTO observations VALUES (?,?,?,?,?,?,?)',
                (seq,evidence_id,parent,record[3],seq,record[5],record[6]))
            parent=evidence_id
        statements=[];self.s.db.set_trace_callback(statements.append)
        with self.assertRaisesRegex(ValueError,'capacity exceeded'):self.s._catalog()
        self.s.db.set_trace_callback(None)
        self.assertFalse(any('FROM observations ORDER BY seq' in sql for sql in statements))
    def test_exact_aggregate_logical_cap_refused_before_blob_fetch(self):
        self.ingest();record=self.s.db.execute('SELECT * FROM observations').fetchone()
        self.s.db.execute('DELETE FROM observations')
        parent='0'*64
        for seq in range(1,6):
            evidence_id=hashlib.sha256(str(seq).encode()).hexdigest()
            self.s.db.execute('INSERT INTO observations VALUES (?,?,?,?,?,?,?)',
                (seq,evidence_id,parent,record[3],seq,record[5],MAX_EVIDENCE_BYTES))
            parent=evidence_id
        statements=[];self.s.db.set_trace_callback(statements.append)
        with self.assertRaisesRegex(ValueError,'capacity exceeded'):self.s._catalog()
        self.s.db.set_trace_callback(None)
        self.assertFalse(any(sql.startswith('SELECT seq,payload') for sql in statements))
    def test_frame_descriptor_mismatch_and_corruption_retained(self):
        self.ingest(); original=self.s.db.execute('SELECT payload,logical_bytes FROM observations').fetchone()
        for payload,logical in ((original[0],original[1]+1),(original[0][:-1],original[1]),
                                (b'bad-prefix'+original[0][10:],original[1])):
            with self.subTest(logical=logical):
                self.s.db.execute('UPDATE observations SET payload=?,logical_bytes=?',(payload,logical))
                before=self.all_rows()
                with self.assertRaises(ValueError):self.s.current()
                self.assertEqual(self.all_rows(),before)
    def test_compressed_proof_with_wrong_original_content_id_refused(self):
        self.ingest();self.s.db.execute('UPDATE observations SET evidence_id=?',('e'*64,))
        with self.assertRaisesRegex(ValueError,'content changed'):self.s.current()


if __name__=='__main__':unittest.main()
