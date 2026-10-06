"""Fake-worker operator filesystem/caller tests; no native or engine claim."""
import os
from pathlib import Path
import socket
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from test_protocol8_consensus import FakeWorker, f, wire
import protocol8_consensus as p
import protocol8_operator as o
from protocol8_application import Application
from protocol8_recovery import RecoveryApplication

class OperatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.workspace = self.root/'app'
        self.worker = self.root/'worker'; self.worker.write_bytes(b'fake-worker'); self.worker.chmod(0o700)
        self.engine = self.root/'engine'; self.engine.write_bytes(b'fake-engine'); self.engine.chmod(0o700)
        self.w = FakeWorker(); self.w.sha256 = o.sha(self.worker.read_bytes())
        fields = [f(v) for v in (8,1,2,3,1,5,6,1,32,1,10,11,12)]
        fields[4] = self.w.root([f(100)])
        self.tx = wire(fields); self.w.kat_statement = fields; self.w.kat_sha256 = o.sha(self.tx)
        self.g = {'format':p.GENESIS_FORMAT,'protocol_version':8,'chain_id':'operator-fake',
            'profile_sha256':p.PROFILE_SHA256,'worker_sha256':self.w.sha256,'kat_sha256':self.w.kat_sha256,
            'validators':[{'public_key':f(v),'power':10} for v in range(1,5)],'pool_id':'cd'*32,
            'asset':f(2),'mission':f(3),'fee':1,'network':f(1),
            'notes':[{'kind':'p8-recipient-v1','commitment':f(100)}]}
        self.raw = p.canonical(self.g); self.pin = o.sha(self.raw)
        self.genesis = self.root/'g.json'; self.genesis.write_bytes(self.raw)
        self.kat = self.root/'kat.tx'; self.kat.write_bytes(self.tx)
        self.patches = [patch.object(o, 'ENGINE_SHA256', o.sha(self.engine.read_bytes())),
                        patch.object(o, 'Worker', return_value=self.w)]
        for x in self.patches: x.start()
    def tearDown(self):
        for x in reversed(self.patches): x.stop()
        self.temp.cleanup()
    def init(self):
        return o.initialize(self.workspace, self.genesis, self.pin, self.kat, self.worker, self.engine)
    def files(self):
        return {p.name:p.read_bytes() for p in self.workspace.iterdir() if p.is_file()}
    def refused(self, call):
        before = self.files()
        with self.assertRaises((o.OperatorError, p.StateError, OSError)): call()
        self.assertEqual(self.files(), before)
    def test_init_doctor_no_database_or_native_doctor(self):
        self.assertFalse(self.init()['database_created'])
        self.assertEqual(set(self.files()), o.REQUIRED)
        self.assertEqual(self.workspace.stat().st_mode & 0o777, 0o700)
        with patch.object(o, 'Worker', side_effect=AssertionError('doctor executed native code')):
            before = self.files(); result = o.doctor(self.workspace, self.pin)
        self.assertEqual(self.files(), before)
        self.assertFalse(result['native_executed']); self.assertFalse(result['store_replay_verified'])
    def test_existing_workspace_and_wrong_external_pin_preserved(self):
        self.init(); self.refused(self.init)
        self.refused(lambda:o.doctor(self.workspace, 'ef'*32))
    def test_pin_failure_before_target_creation(self):
        with patch.object(o, 'Worker', side_effect=AssertionError('native before pins')):
            with self.assertRaises(o.OperatorError):
                o.initialize(self.workspace, self.genesis, 'ef'*32, self.kat, self.worker, self.engine)
        self.assertFalse(self.workspace.exists())
    def test_symlink_and_hardlinked_public_inputs_refused(self):
        self.genesis.unlink(); self.genesis.symlink_to(self.kat)
        with self.assertRaises(OSError): self.init()
        self.genesis.unlink(); self.genesis.write_bytes(self.raw)
        os.link(self.genesis, self.root/'alias')
        with self.assertRaises(o.OperatorError): self.init()
        self.assertFalse(self.workspace.exists())
    def test_writable_or_symlink_ancestors_refused(self):
        self.root.chmod(0o770)
        with self.assertRaises(o.OperatorError): self.init()
        self.root.chmod(0o700)
        alias = self.root/'alias'; alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(o.OperatorError):
            o.initialize(alias/'app', self.genesis, self.pin, self.kat, self.worker, self.engine)
    def test_changed_manifest_and_partial_workspace_refused(self):
        self.init(); manifest = self.workspace/'operator.json'
        value = p.closed_json(manifest.read_bytes(), o.MAX_CONFIG); value['runtime_files'] = {}
        manifest.write_bytes(p.canonical(value))
        self.refused(lambda:o.doctor(self.workspace, self.pin))
        manifest.unlink(); self.refused(lambda:o.doctor(self.workspace, self.pin))
    def test_socket_unknown_member_and_private_mode_refused(self):
        self.init()
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(str(self.workspace/'a.sock'))
            self.refused(lambda:o.doctor(self.workspace, self.pin))
        (self.workspace/'a.sock').unlink()
        (self.workspace/'surprise').write_bytes(b'preserve-me')
        self.refused(lambda:o.doctor(self.workspace, self.pin))
        (self.workspace/'surprise').unlink(); (self.workspace/'kat.tx').chmod(0o640)
        self.refused(lambda:o.doctor(self.workspace, self.pin))
    def test_exclusive_workspace_owner_refused(self):
        self.init()
        with o.locked(self.workspace):
            self.refused(lambda:o.doctor(self.workspace, self.pin))
    def test_binary_or_runtime_change_refused_before_native(self):
        self.init(); self.worker.write_bytes(b'changed')
        self.refused(lambda:o.audit(self.workspace, self.pin))
        self.worker.write_bytes(b'fake-worker')
        with patch.object(o, 'runtime_files', return_value={}):
            self.refused(lambda:o.doctor(self.workspace, self.pin))
    def test_audit_missing_database_never_creates(self):
        self.init(); self.refused(lambda:o.audit(self.workspace, self.pin))
    def test_ordinary_store_refused_without_migration(self):
        self.init()
        with Application(self.workspace/'state.sqlite', self.w, expected_genesis=self.raw): pass
        self.refused(lambda:o.audit(self.workspace, self.pin))
    def test_actual_recovery_schema_suffix_audit_and_gap_refusal(self):
        self.init()
        with RecoveryApplication(self.workspace/'state.sqlite', self.w, expected_genesis=self.raw) as app:
            app.init_chain(self.g['chain_id'], self.raw, self.g['validators'])
            app.finalize_block([self.tx], 1, b'x'*32, bytes.fromhex(app.validators.hash), [], b'test')
            app.commit()
        result = o.audit(self.workspace, self.pin)
        self.assertEqual(result['real_response_heights'], [1]); self.assertIsNone(result['origin_marker'])
        self.assertFalse(result['consensus_verified']); self.assertFalse(result['freshness_established'])
        with sqlite3.connect(self.workspace/'state.sqlite') as db: db.execute('DELETE FROM p8_blocks')
        with sqlite3.connect(self.workspace/'state.sqlite') as db: before = tuple(db.iterdump())
        with self.assertRaises(p.StateError): o.audit(self.workspace, self.pin)
        with sqlite3.connect(self.workspace/'state.sqlite') as db: after = tuple(db.iterdump())
        # Audit explicitly opens SQLite/WAL. Durable contents cannot be repaired;
        # unlike doctor, byte identity of WAL bookkeeping is not its contract.
        self.assertEqual(after, before)
    def test_special_file_and_hardlinked_workspace_refused(self):
        self.init(); (self.workspace/'kat.tx').unlink(); os.mkfifo(self.workspace/'kat.tx', 0o600)
        with self.assertRaises(o.OperatorError): o.doctor(self.workspace, self.pin)
        (self.workspace/'kat.tx').unlink(); (self.workspace/'kat.tx').write_bytes(self.tx)
        (self.workspace/'kat.tx').chmod(0o600); os.link(self.workspace/'kat.tx', self.root/'kat-alias')
        self.refused(lambda:o.doctor(self.workspace, self.pin))

if __name__ == '__main__': unittest.main()
