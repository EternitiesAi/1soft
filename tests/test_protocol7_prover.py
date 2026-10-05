"""Canonical envelopes and optional real P7 prover/journal fault qualification."""
import hashlib, json, os, sqlite3, subprocess, tempfile, threading, unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from protocol7_prover import Prover, canonical_inputs
from protocol7_treasury import canonical, bootstrap_digest, numfield, Unavailable
from protocol7_worker import Worker
from protocol7_wallet import CertifiedTreasuryJournal

class EnvelopeTests(unittest.TestCase):
    def test_closed_counts_canonical_fields_and_integer_bounds(self):
        for p,w in [([],[]),(['00'*32]*31,['00'*32]*31),
                    (['00'*32]*30,['00'*32]*32)]:
            with self.assertRaises(ValueError): canonical_inputs(p,w)
        for value in ['ff'*32, 'AA'*32, True, 1, '0']:
            with self.assertRaises((ValueError,TypeError)):
                canonical_inputs([value]*30,['00'*32]*31)

@unittest.skipUnless(all(os.environ.get(k) for k in ('P7_REPORT','P7_WORKER','P7_PROVER','P7_REQUEST_FIXTURE')),
                     'unassessed: actual P7 prover, verifier and receipt inputs not supplied')
class ProverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report=json.loads(Path(os.environ['P7_REPORT']).read_bytes())
        cls.rawg=canonical(cls.report['genesis'])
        artifacts=Path(os.environ['P7_REPORT']+'.artifacts')
        worker=Path(os.environ['P7_WORKER'])
        cls.worker=Worker(worker,hashlib.sha256(worker.read_bytes()).hexdigest(),(artifacts/'fixture-a.tx').read_bytes())
        cls.binary=Path(os.environ['P7_PROVER']);cls.sha=hashlib.sha256(cls.binary.read_bytes()).hexdigest()
        cls.prover=Prover(cls.binary,cls.sha,expected_genesis=cls.rawg,worker=cls.worker)
        request=subprocess.check_output([os.environ['P7_REQUEST_FIXTURE']],
              input=bytes.fromhex(bootstrap_digest(cls.report['genesis'])))
        assert len(request)==2088
        cls.public=[request[136+i*32:136+(i+1)*32].hex() for i in range(30)]
        cls.witness=[request[1096+i*32:1096+(i+1)*32].hex() for i in range(31)]
        # A real arbitrary proof, deliberately absent from the twelve fixtures.
        cls.raw=cls.prover.produce(cls.public,cls.witness)
        cls.other=(artifacts/'fixture-a.tx').read_bytes()
        assert cls.raw not in [(artifacts/('fixture-'+n+'.tx')).read_bytes()
                              for n in cls.report['inputs']['fixtures']]
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=Path(self.temp.name)/'journal.sqlite'
        self.wallet=CertifiedTreasuryJournal(self.path,expected_genesis=self.rawg,worker=self.worker)
    def tearDown(self):
        self.wallet.close();self.temp.cleanup()
    def rows(self):
        return self.wallet.db.execute('SELECT COUNT(*) FROM obligations').fetchone()[0]
    def test_actual_prepare_reopen_exact_wire_and_duplicate_refused_before_proving(self):
        ident=self.wallet.prepare(self.prover,self.public,self.witness)
        raw=self.wallet.export(ident)
        self.assertTrue(self.worker.verify(raw));self.assertEqual(self.wallet.status(ident)['attempts'],0)
        with patch.object(self.prover,'produce',side_effect=AssertionError('must refuse before proof')) as call:
            with self.assertRaises(ValueError):self.wallet.prepare(self.prover,self.public,self.witness)
            call.assert_not_called()
        self.wallet.close()
        self.wallet=CertifiedTreasuryJournal(self.path,expected_genesis=self.rawg,worker=self.worker)
        self.assertEqual(self.wallet.export(ident),raw)
        self.assertEqual(self.wallet.status(ident)['attempts'],0)
    def test_current_roots_grant_generation_owner_and_window_refused_before_proving(self):
        for i in (1,4,7,8,20,25,26,27,28,29):
            p=self.public.copy();p[i]=numfield(123456)
            with patch.object(self.prover,'produce',side_effect=AssertionError('must refuse before proof')) as call:
                with self.assertRaises(ValueError):self.wallet.prepare(self.prover,p,self.witness)
                call.assert_not_called()
            self.assertEqual(self.rows(),0)
        p=self.public.copy();p[15]=numfield(2)
        with self.assertRaises(ValueError):self.wallet.prepare(self.prover,p,self.witness)
        self.assertEqual(self.rows(),0)
    def test_changed_witness_is_refused_by_actual_child_and_leaves_journal_usable(self):
        w=self.witness.copy();w[0]=numfield(11)
        with self.assertRaises(Unavailable):self.wallet.prepare(self.prover,self.public,w)
        self.assertEqual(self.rows(),0)
        self.assertFalse(self.wallet.db.in_transaction)
        ident=self.wallet.retain(self.raw);self.assertEqual(self.wallet.export(ident),self.raw)
    def test_measured_binary_symlink_permissions_and_changed_pin_refused(self):
        with self.assertRaises(Unavailable):Prover(self.binary,'00'*32,expected_genesis=self.rawg,worker=self.worker)
        link=Path(self.temp.name)/'link';link.symlink_to(self.binary)
        with self.assertRaises(Unavailable):Prover(link,self.sha,expected_genesis=self.rawg,worker=self.worker)
        unsafe=Path(self.temp.name)/'unsafe';unsafe.write_bytes(b'not a binary');unsafe.chmod(0o777)
        with self.assertRaises(Unavailable):Prover(unsafe,hashlib.sha256(unsafe.read_bytes()).hexdigest(),expected_genesis=self.rawg,worker=self.worker)
    def fake(self,body):
        p=Path(self.temp.name)/'fault-child'
        p.write_text('#!/usr/bin/python3\nimport sys,time\n'+body+'\n');p.chmod(0o700)
        return Prover(p,hashlib.sha256(p.read_bytes()).hexdigest(),expected_genesis=self.rawg,worker=self.worker)
    def test_actual_child_bad_output_nonzero_and_private_echo_fail_closed(self):
        altered=bytearray(self.raw);altered[-1]^=1
        for output in (b'short',self.raw+b'\0',self.other,bytes(altered)):
            child=self.fake('sys.stdin.buffer.read(2089)\nsys.stdout.buffer.write(bytes.fromhex('+repr(output.hex())+'))')
            with self.assertRaises(Unavailable):self.wallet.prepare(child,self.public,self.witness)
            self.assertEqual(self.rows(),0);self.assertFalse(self.wallet.db.in_transaction)
        child=self.fake('private=sys.stdin.buffer.read(2089)\nsys.stderr.buffer.write(private)\nsys.exit(7)')
        with self.assertRaises(Unavailable) as error:self.wallet.prepare(child,self.public,self.witness)
        self.assertEqual(str(error.exception),'P7 prover failed or malformed output')
        self.assertEqual(self.rows(),0)
    def test_actual_child_timeout_is_reaped_and_journal_rolls_back(self):
        child=self.fake('sys.stdin.buffer.read(2089)\ntime.sleep(60)')
        with patch('protocol7_prover.WALL_SECONDS',0.2):
            with self.assertRaises(Unavailable) as error:self.wallet.prepare(child,self.public,self.witness)
        self.assertEqual(str(error.exception),'P7 prover wall deadline')
        self.assertEqual(self.rows(),0);self.assertFalse(self.wallet.db.in_transaction)
        self.wallet.retain(self.raw)
    def test_process_failure_or_swapped_output_rolls_back(self):
        # Fault doubles test rollback, never establish actual proving.
        for error in (Unavailable('deadline'),Unavailable('bad output')):
            with patch.object(self.prover,'produce',side_effect=error):
                with self.assertRaises(Unavailable):self.wallet.prepare(self.prover,self.public,self.witness)
            self.assertEqual(self.rows(),0);self.assertFalse(self.wallet.db.in_transaction)
        swapped=bytearray(self.raw);swapped[8+18*32]^=1
        with patch.object(self.prover,'produce',return_value=bytes(swapped)):
            with self.assertRaises(ValueError):self.wallet.prepare(self.prover,self.public,self.witness)
        self.assertEqual(self.rows(),0)
        with patch.object(self.prover,'produce',return_value=self.other):
            with self.assertRaises(ValueError):self.wallet.prepare(self.prover,self.public,self.witness)
        self.assertEqual(self.rows(),0)
    def test_insert_failure_after_real_proof_has_no_partial_obligation_or_attempt(self):
        self.wallet.db.execute("CREATE TEMP TRIGGER refuse_insert BEFORE INSERT ON obligations BEGIN SELECT RAISE(ABORT,'injected'); END")
        with patch.object(self.prover,'produce',return_value=self.raw):
            with self.assertRaises(ValueError):self.wallet.prepare(self.prover,self.public,self.witness)
        self.assertEqual(self.rows(),0)
        self.assertEqual(self.wallet.db.execute('SELECT COUNT(*) FROM attempts').fetchone()[0],0)
        self.wallet.db.execute('DROP TRIGGER refuse_insert')
        self.wallet.retain(self.raw)
    def test_two_connections_serialize_one_reservation(self):
        second=CertifiedTreasuryJournal(self.path,expected_genesis=self.rawg,worker=self.worker)
        barrier=threading.Barrier(2)
        def prepare(wallet):
            barrier.wait(timeout=10)
            try:return ('retained',wallet.prepare(self.prover,self.public,self.witness))
            except ValueError:return ('refused',None)
        try:
            with patch.object(self.prover,'produce',return_value=self.raw) as call,ThreadPoolExecutor(max_workers=2) as pool:
                a=pool.submit(prepare,self.wallet);b=pool.submit(prepare,second)
                results=[a.result(timeout=60),b.result(timeout=60)]
                self.assertEqual(sorted(r[0] for r in results),['refused','retained'])
                self.assertEqual(call.call_count,1)
            self.assertEqual(self.rows(),1)
        finally:second.close()
if __name__=='__main__':unittest.main()
