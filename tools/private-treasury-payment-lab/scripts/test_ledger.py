import hashlib,json,os,sqlite3,subprocess,sys,tempfile,unittest
from pathlib import Path
from ledger import Bridge,Ledger,Outbox

FIXTURES=Path(os.environ['TREASURY_FIXTURES'])
BINARY=Path(os.environ['TREASURY_BINARY'])
EXPECTED_SHA=os.environ['TREASURY_EXPECTED_BINARY_SHA256']
GENESIS=json.loads((FIXTURES/'genesis.json').read_text())
RAW={name:(FIXTURES/(name+'.tx')).read_bytes() for name in ['a','b','after_a_b','after_b_a','revoked_a_b','duplicate_request']}
def txid(raw):return hashlib.sha256(b'1soft/private-treasury-payment-lab/transaction/v1\0'+raw).hexdigest()
class AtomicLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.directory=Path(self.tmp.name);os.chmod(self.directory,0o700)
        self.db=self.directory/'ledger.sqlite';self.outpath=self.directory/'outbox.sqlite'
        self.bridge=Bridge(BINARY,EXPECTED_SHA)
        self.ledger=Ledger(self.db,GENESIS,self.bridge)
    def tearDown(self):self.ledger.close();self.tmp.cleanup()
    def test_actual_payment_commits_all_effects_and_reopens(self):
        result=self.ledger.apply(RAW['a'],2);self.assertEqual(result,txid(RAW['a']))
        state=self.ledger.snapshot();self.assertEqual(len(state['notes']),4);self.assertEqual(state['fees'],2)
        self.assertEqual(len(state['nullifiers']),1);self.assertEqual(len(state['authority_nullifiers']),2)
        self.assertIn(result,state['receipts']);self.assertEqual(state['parent'],RAW['a'][8+9*32:8+10*32].hex())
        self.ledger.close();self.ledger=Ledger(self.db,GENESIS,self.bridge);self.assertEqual(self.ledger.snapshot(),state)
    def test_both_race_orders_and_refreshed_exact_exhaustion(self):
        for first,second,refresh in [('a','b','after_a_b'),('b','a','after_b_a')]:
            with self.subTest(first=first):
                db=self.directory/(first+'.sqlite');ledger=Ledger(db,GENESIS,self.bridge)
                try:
                    ledger.apply(RAW[first],2);before=ledger.snapshot()
                    with self.assertRaises(ValueError):ledger.apply(RAW[second],2)
                    self.assertEqual(ledger.snapshot(),before)
                    ledger.apply(RAW[refresh],2);state=ledger.snapshot()
                    self.assertEqual(len(state['notes']),6);self.assertEqual(state['fees'],4)
                    self.assertEqual(len(state['receipts']),2);self.assertEqual(len(state['nullifiers']),2)
                    with self.assertRaises(ValueError):ledger.apply(RAW[first],2)
                    self.assertEqual(ledger.snapshot(),state)
                finally:ledger.close()
    def test_revocation_rejects_prepared_authority_without_refill(self):
        before=self.ledger.snapshot();self.ledger.revoke(GENESIS['grants'][0][0]);state=self.ledger.snapshot()
        for field in ['parent','notes','nullifiers','fees','receipts']:self.assertEqual(state[field],before[field])
        with self.assertRaises(ValueError):self.ledger.apply(RAW['a'],2)
        with self.assertRaises(ValueError):self.ledger.apply(RAW['b'],2)
        self.assertEqual(self.ledger.snapshot(),state);self.ledger.apply(RAW['revoked_a_b'],2)
        self.assertEqual(self.ledger.snapshot()['fees'],2)
    def test_sqlite_failure_rolls_back_authority_notes_fees_and_receipt(self):
        before=self.ledger.snapshot()
        with sqlite3.connect(self.db) as c:c.execute("CREATE TRIGGER fail_receipt BEFORE INSERT ON receipts BEGIN SELECT RAISE(ABORT,'receipt-fault'); END")
        with self.assertRaises(sqlite3.DatabaseError):self.ledger.apply(RAW['a'],2)
        self.assertEqual(self.ledger.snapshot(),before)
        with sqlite3.connect(self.db) as c:c.execute('DROP TRIGGER fail_receipt')
        self.ledger.apply(RAW['a'],2);self.assertEqual(self.ledger.snapshot()['fees'],2)
    def test_proof_encoding_and_height_failures_change_nothing(self):
        before=self.ledger.snapshot()
        for raw in [b'',RAW['a'][:-1],RAW['a']+b'0',RAW['a'][:8]+b'\xff'*32+RAW['a'][40:],RAW['a'][:-1]+bytes([RAW['a'][-1]^1])]:
            with self.subTest(size=len(raw)):
                with self.assertRaises(ValueError):self.ledger.apply(raw,2)
                self.assertEqual(self.ledger.snapshot(),before)
        for height in [0,20,True,-1,2**64]:
            with self.subTest(height=height):
                with self.assertRaises(ValueError):self.ledger.apply(RAW['a'],height)
                self.assertEqual(self.ledger.snapshot(),before)
    def test_outbox_retains_exact_bytes_and_claims_only_once(self):
        out=Outbox(self.outpath);ident=out.retain(RAW['a']);self.assertEqual(ident,txid(RAW['a']))
        self.assertEqual(out.export(ident),RAW['a']);out.claim(ident);out.close()
        out=Outbox(self.outpath)
        try:
            self.assertEqual(out.export(ident),RAW['a'])
            with self.assertRaises(ValueError):out.claim(ident)
            with self.assertRaises(ValueError):out.retain(RAW['a'])
            with self.assertRaises(ValueError):out.record_local_receipt(ident,self.ledger)
            self.ledger.revoke(GENESIS['grants'][0][0])
            with self.assertRaises(ValueError):self.ledger.apply(RAW['a'],2)
            self.assertEqual(out.status(ident),'claimed');self.assertEqual(out.export(ident),RAW['a'])
        finally:out.close()
    def test_lost_return_after_process_commit_does_not_create_second_payment(self):
        out=Outbox(self.outpath);ident=out.retain(RAW['a']);out.claim(ident);out.close();self.ledger.close()
        code="from ledger import *; import os,json,hashlib; from pathlib import Path; b=Path(os.environ['TREASURY_BINARY']); l=Ledger(Path(os.environ['TEST_DB']),json.loads(Path(os.environ['TREASURY_FIXTURES'],'genesis.json').read_text()),Bridge(b,os.environ['TREASURY_EXPECTED_BINARY_SHA256'])); l.apply(Path(os.environ['TREASURY_FIXTURES'],'a.tx').read_bytes(),2); os._exit(0)"
        subprocess.run([sys.executable,'-c',code],env=dict(os.environ,TEST_DB=str(self.db)),check=True,timeout=90)
        self.ledger=Ledger(self.db,GENESIS,self.bridge);out=Outbox(self.outpath)
        try:
            self.assertEqual(out.export(ident),RAW['a']);self.assertEqual(out.status(ident),'claimed')
            out.record_local_receipt(ident,self.ledger);self.assertEqual(out.status(ident),'recorded-local')
            self.assertEqual(self.ledger.snapshot()['fees'],2)
            with self.assertRaises(ValueError):self.ledger.apply(out.export(ident),2)
            with self.assertRaises(ValueError):out.claim(ident)
        finally:out.close()

    def test_concurrent_claims_and_shared_parent_holds(self):
        import concurrent.futures,threading
        mask=os.umask(0o077);os.umask(mask)
        out=Outbox(self.outpath);ident=out.retain(RAW['a']);out.close();barrier=threading.Barrier(2)
        def claim():
            box=Outbox(self.outpath)
            try:
                barrier.wait(timeout=10)
                try:box.claim(ident);return 'claimed'
                except ValueError:return 'refused'
            finally:box.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(lambda _:claim(),range(2)))
        self.assertEqual(sorted(results),['claimed','refused'])
        after=os.umask(0o077);os.umask(after);self.assertEqual(after,mask)
        out=Outbox(self.outpath)
        try:
            with self.assertRaisesRegex(ValueError,'held'):out.retain(RAW['b'])
            self.assertEqual(out.export(ident),RAW['a'])
        finally:out.close()
    def test_crash_before_commit_retains_unknown_claim_and_no_ledger_effect(self):
        before=self.ledger.snapshot();self.ledger.close()
        code="from ledger import *; import os,json,hashlib; from pathlib import Path; b=Path(os.environ['TREASURY_BINARY']); raw=Path(os.environ['TREASURY_FIXTURES'],'a.tx').read_bytes(); out=Outbox(Path(os.environ['TEST_OUTBOX'])); i=out.retain(raw); out.claim(i); l=Ledger(Path(os.environ['TEST_DB']),json.loads(Path(os.environ['TREASURY_FIXTURES'],'genesis.json').read_text()),Bridge(b,os.environ['TREASURY_EXPECTED_BINARY_SHA256'])); l.db.create_function('crash_now',0,lambda:os._exit(0)); l.db.execute('CREATE TRIGGER crash_receipt BEFORE INSERT ON receipts BEGIN SELECT crash_now(); END'); l.apply(raw,2)"
        subprocess.run([sys.executable,'-c',code],env=dict(os.environ,TEST_DB=str(self.db),TEST_OUTBOX=str(self.outpath)),check=True,timeout=90)
        self.ledger=Ledger(self.db,GENESIS,self.bridge);self.assertEqual(self.ledger.snapshot(),before)
        out=Outbox(self.outpath)
        try:
            ident=txid(RAW['a']);self.assertEqual(out.status(ident),'claimed');self.assertEqual(out.export(ident),RAW['a'])
            with self.assertRaises(ValueError):out.claim(ident)
            with self.assertRaises(ValueError):out.record_local_receipt(ident,self.ledger)
        finally:out.close()
    def test_new_transaction_cannot_pay_same_request_twice(self):
        self.assertNotEqual(txid(RAW['duplicate_request']),txid(RAW['a']))
        self.bridge.verify(RAW['duplicate_request'])
        self.ledger.apply(RAW['a'],2);before=self.ledger.snapshot()
        with self.assertRaisesRegex(ValueError,'executed request'):self.ledger.apply(RAW['duplicate_request'],2)
        self.assertEqual(self.ledger.snapshot(),before)
    def test_same_parent_execution_is_serialized_across_connections(self):
        import concurrent.futures,threading
        barrier=threading.Barrier(2)
        def apply(name):
            ledger=Ledger(self.db,GENESIS,self.bridge)
            try:
                barrier.wait(timeout=15)
                try:ledger.apply(RAW[name],2);return 'accepted'
                except ValueError:return 'refused'
            finally:ledger.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(apply,['a','b']))
        self.assertEqual(sorted(results),['accepted','refused']);self.assertEqual(self.ledger.snapshot()['fees'],2)
    def test_trust_identity_permission_and_backward_height_fail_closed(self):
        with self.assertRaises(ValueError):Bridge(BINARY,'0'*64)
        wrong=dict(GENESIS,fee=3)
        with self.assertRaisesRegex(ValueError,'pinned genesis'):Ledger(self.db,wrong,self.bridge)
        insecure=self.directory/'public';insecure.mkdir(mode=0o755);insecure.chmod(0o755)
        with self.assertRaises(ValueError):Outbox(insecure/'out.sqlite')
        self.ledger.apply(RAW['a'],2);before=self.ledger.snapshot()
        with self.assertRaisesRegex(ValueError,'backward'):self.ledger.apply(RAW['after_a_b'],1)
        self.assertEqual(self.ledger.snapshot(),before)

    def test_failed_initial_lock_preserves_cause_and_closes_connection(self):
        import ledger as module
        from unittest.mock import patch
        real_connection=module.connection;created=[]
        def short_timeout(path):
            c=real_connection(path);c.execute('PRAGMA busy_timeout=1');created.append(c);return c
        writer=sqlite3.connect(self.db,isolation_level=None);writer.execute('BEGIN IMMEDIATE')
        try:
            with patch.object(module,'connection',side_effect=short_timeout):
                with self.assertRaisesRegex(sqlite3.OperationalError,'locked'):Ledger(self.db,GENESIS,self.bridge)
            self.assertEqual(len(created),1)
            with self.assertRaisesRegex(sqlite3.ProgrammingError,'closed'):created[0].execute('SELECT 1')
        finally:writer.execute('ROLLBACK');writer.close()

if __name__=='__main__':unittest.main()
