"""Composite P4 state sync across queued, emitted and activated validator changes."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from block_application import encode
from native_core import NativeLedger, Reject, address, canonical, digest, public, sign
from protocol4_application import Protocol4Application
from protocol4_fixture import fixture
from protocol4_state_sync import (_hash, _metadata, APPLY_ACCEPT, APPLY_REJECT_SNAPSHOT,
                                  CHUNK_BYTES, FORMAT, OFFER_ABORT, OFFER_ACCEPT, OFFER_REJECT,
                                  OFFER_REJECT_FORMAT)
from registry_rules_core import RegistryRules
from validator_sets_core import ValidatorSet


class Protocol4StateSyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.genesis, self.payers, self.admins, self.validators, self.target = fixture()
        self.initial = self.genesis['validator_registry']['validators']
        self.old_hash = ValidatorSet.parse(self.initial).hash
        self.new_hash = ValidatorSet.parse(self.target).hash

    def tearDown(self):
        self.temp.cleanup()

    def _payment(self):
        payer, recipient = [address(public(key)) for key in self.payers]
        ledger = NativeLedger(':memory:', self.genesis)
        try:
            body = ledger.body(payer, 0, {'type': 'transfer', 'to': recipient, 'units': 7},
                               valid_until=20)
        finally:
            ledger.close()
        return canonical(sign(self.payers[0], body))

    def _schedule(self, state):
        rules = RegistryRules(self.genesis['validator_registry'],
                              bound_genesis_sha256=digest(self.genesis))
        body = rules.body(state, {'kind': 'schedule', 'emitted_height': 4,
                                  'target_validators': self.target},
                          valid_from=1, valid_until=3)
        material = rules.signing_bytes(body)
        approvals = sorted(({'public_key': public(key), 'signature': key.sign(material).hex()}
                            for key in self.admins[:3]), key=lambda row: row['public_key'])
        return encode({'body': body, 'approvals': approvals})

    def _commit(self, app, height, txs=()):
        roster = self.initial if height <= 6 else self.target
        votes = [] if height == 1 else [
            {'address': row.address.hex(), 'power': row.power, 'block_id_flag': 2}
            for row in ValidatorSet.parse(roster).validators]
        next_hash = self.old_hash if height <= 4 else self.new_hash
        app.finalize_block(list(txs), height, bytes([height]) * 32,
                           bytes.fromhex(next_hash), votes,
                           b'protocol4-state-sync-fixture:' + str(height).encode())
        app.commit()

    def _source(self, height):
        app = Protocol4Application(Path(self.temp.name) / f'source-{height}.db',
                                   expected_genesis=self.genesis)
        app.init_chain(self.genesis['chain_id'], self.genesis, self.initial)
        self._commit(app, 1, (self._payment(), self._schedule(app.state['registry'])))
        for h in range(2, height + 1):
            self._commit(app, h)
        return app

    def _transfer(self, source, recipient, desc=None, payload=None):
        desc = desc or source.list_snapshots()[0]
        self.assertEqual(recipient.offer_snapshot(desc, bytes.fromhex(source.app_hash)),
                         OFFER_ACCEPT)
        if payload is None:
            chunks = [source.load_snapshot_chunk(desc['height'], desc['format'], i)
                      for i in range(desc['chunks'])]
        else:
            chunks = [payload[i:i + CHUNK_BYTES]
                      for i in range(0, len(payload), CHUNK_BYTES)]
        answer = None
        for i, chunk in enumerate(chunks):
            answer = recipient.apply_snapshot_chunk(i, chunk, 'test-peer')
        return answer['result']

    def test_queued_emitted_activated_snapshots_replay_and_continue(self):
        for height in (2, 4, 6, 7):
            with self.subTest(height=height):
                source = self._source(height)
                path = Path(self.temp.name) / f'recipient-{height}.db'
                recipient = Protocol4Application(path, expected_genesis=self.genesis)
                try:
                    desc = source.list_snapshots()[0]
                    self.assertEqual(desc['format'], FORMAT)
                    self.assertEqual(self._transfer(source, recipient, desc), APPLY_ACCEPT)
                    self.assertEqual(recipient.state, source.state)
                    self.assertEqual(recipient.app_hash, source.app_hash)
                    self.assertEqual(len(recipient.state['native']['receipts']), 1)
                    self.assertEqual(recipient.history(), source.history())
                    self.assertEqual(self._transfer(source, recipient, desc), APPLY_ACCEPT)
                    recipient.close()
                    recipient = Protocol4Application(path, expected_genesis=self.genesis)
                    with self.assertRaisesRegex(Reject, 'response unavailable'):
                        recipient.committed_result(height)
                    self._commit(recipient, height + 1)
                    self._commit(source, height + 1)
                    self.assertEqual(recipient.app_hash, source.app_hash)
                    self.assertEqual(recipient.state, source.state)
                    self.assertEqual(recipient.offer_snapshot(desc, bytes.fromhex(source.app_hash)),
                                     OFFER_ABORT)
                finally:
                    recipient.close()
                    source.close()

    def test_wrong_format_genesis_or_trusted_hash_refused(self):
        source = self._source(4)
        recipient = Protocol4Application(Path(self.temp.name) / 'refusal.db',
                                         expected_genesis=self.genesis)
        try:
            desc = source.list_snapshots()[0]
            self.assertEqual(recipient.offer_snapshot({**desc, 'format': 1},
                                                      bytes.fromhex(source.app_hash)),
                             OFFER_REJECT_FORMAT)
            self.assertEqual(recipient.offer_snapshot(desc, b'\0' * 32), OFFER_REJECT)
            self.assertEqual(self._transfer(source, recipient, desc), APPLY_ACCEPT)
            self.assertEqual(recipient.offer_snapshot(desc, bytes.fromhex(source.app_hash)),
                             OFFER_ACCEPT)  # unchanged snapshot-only checkpoint
        finally:
            recipient.close()
            source.close()

    def test_forged_history_rejected_even_with_matching_trusted_apphash(self):
        source = self._source(4)
        recipient = Protocol4Application(Path(self.temp.name) / 'forged.db',
                                         expected_genesis=self.genesis)
        try:
            desc = source.list_snapshots()[0]
            raw = b''.join(source.load_snapshot_chunk(desc['height'], desc['format'], i)
                           for i in range(desc['chunks']))
            payload = json.loads(raw)
            payload['history'][0]['txs'][1] = base64.b64encode(b'forged-admin-wire').decode()
            forged = encode(payload)
            chunks = (len(forged) + CHUNK_BYTES - 1) // CHUNK_BYTES
            bad_desc = {**desc, 'chunks': chunks, 'hash': _hash(forged),
                        'metadata': _metadata(self.genesis, source.height,
                                              source.app_hash, len(forged), chunks)}
            self.assertEqual(self._transfer(source, recipient, bad_desc, forged),
                             APPLY_REJECT_SNAPSHOT)
            self.assertEqual(recipient.height, 0)
            self.assertIsNone(recipient.state)
        finally:
            recipient.close()
            source.close()

    def test_forged_money_state_rejected_under_trusted_apphash(self):
        source = self._source(6)
        recipient = Protocol4Application(Path(self.temp.name) / 'forged-money.db',
                                         expected_genesis=self.genesis)
        try:
            desc = source.list_snapshots()[0]
            raw = b''.join(source.load_snapshot_chunk(desc['height'], desc['format'], i)
                           for i in range(desc['chunks']))
            payload = json.loads(raw)
            payload['state']['native']['accounts'][0][4] += 1
            forged = encode(payload)
            chunks = (len(forged) + CHUNK_BYTES - 1) // CHUNK_BYTES
            bad_desc = {**desc, 'chunks': chunks, 'hash': _hash(forged),
                        'metadata': _metadata(self.genesis, source.height,
                                              source.app_hash, len(forged), chunks)}
            self.assertEqual(self._transfer(source, recipient, bad_desc, forged),
                             APPLY_REJECT_SNAPSHOT)
            self.assertEqual(recipient.height, 0)
        finally:
            recipient.close()
            source.close()

    def test_snapshot_cannot_import_peer_claimed_block_identity_or_votes(self):
        source = self._source(4)
        recipient = Protocol4Application(Path(self.temp.name) / 'forged-evidence.db',
                                         expected_genesis=self.genesis)
        try:
            desc = source.list_snapshots()[0]
            raw = b''.join(source.load_snapshot_chunk(desc['height'], desc['format'], i)
                           for i in range(desc['chunks']))
            payload = json.loads(raw)
            self.assertEqual(set(payload['history'][0]), {'height', 'txs'})
            payload['history'][0]['block_hash'] = 'f' * 64
            payload['history'][0]['last_commit_votes'] = []
            forged = encode(payload)
            chunks = (len(forged) + CHUNK_BYTES - 1) // CHUNK_BYTES
            bad_desc = {**desc, 'chunks': chunks, 'hash': _hash(forged),
                        'metadata': _metadata(self.genesis, source.height,
                                              source.app_hash, len(forged), chunks)}
            self.assertEqual(self._transfer(source, recipient, bad_desc, forged),
                             APPLY_REJECT_SNAPSHOT)
            self.assertEqual(recipient.height, 0)
        finally:
            recipient.close()
            source.close()

    def test_snapshot_rejects_extra_failed_transaction_replay_inputs(self):
        source = self._source(4)
        recipient = Protocol4Application(Path(self.temp.name) / 'extra-failed-tx.db',
                                         expected_genesis=self.genesis)
        try:
            desc = source.list_snapshots()[0]
            raw = b''.join(source.load_snapshot_chunk(desc['height'], desc['format'], i)
                           for i in range(desc['chunks']))
            payload = json.loads(raw)
            payload['history'][1]['txs'].append(base64.b64encode(b'not-a-transaction').decode())
            forged = encode(payload)
            chunks = (len(forged) + CHUNK_BYTES - 1) // CHUNK_BYTES
            bad_desc = {**desc, 'chunks': chunks, 'hash': _hash(forged),
                        'metadata': _metadata(self.genesis, source.height,
                                              source.app_hash, len(forged), chunks)}
            self.assertEqual(self._transfer(source, recipient, bad_desc, forged),
                             APPLY_REJECT_SNAPSHOT)
            self.assertEqual(recipient.height, 0)
        finally:
            recipient.close()
            source.close()

    def test_local_install_fault_rolls_back_every_record(self):
        source = self._source(4)
        path = Path(self.temp.name) / 'install-fault.db'
        recipient = Protocol4Application(path, expected_genesis=self.genesis)
        try:
            recipient.db.execute('''CREATE TRIGGER fail_snapshot_history BEFORE INSERT ON history
                                    BEGIN SELECT RAISE(ABORT, 'injected local disk fault'); END''')
            desc = source.list_snapshots()[0]
            self.assertEqual(recipient.offer_snapshot(desc, bytes.fromhex(source.app_hash)),
                             OFFER_ACCEPT)
            with self.assertRaises(sqlite3.IntegrityError):
                for i in range(desc['chunks']):
                    recipient.apply_snapshot_chunk(
                        i, source.load_snapshot_chunk(desc['height'], desc['format'], i),
                        'test-peer')
            self.assertEqual(recipient.height, 0)
            self.assertIsNone(recipient.state)
            self.assertIsNone(recipient.db.execute('SELECT 1 FROM committed').fetchone())
            self.assertIsNone(recipient.db.execute('SELECT 1 FROM blocks').fetchone())
            self.assertIsNone(recipient.db.execute('SELECT 1 FROM history').fetchone())
            self.assertIsNone(recipient.db.execute('SELECT 1 FROM snapshot_marker').fetchone())
            recipient.close()
            recipient = Protocol4Application(path, expected_genesis=self.genesis)
            self.assertEqual(recipient.height, 0)
        finally:
            recipient.close()
            source.close()


if __name__ == '__main__':
    unittest.main()
