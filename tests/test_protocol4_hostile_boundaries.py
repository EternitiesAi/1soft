"""Adversarial qualification of the Protocol 4 consensus/state-sync boundary.

These tests deliberately keep two authorities separate: the application checks
the engine-provided last-commit shape, while the independent light-client
verifier authenticates signed headers.  Snapshot tests exercise the public
application API and assert that rejected input cannot mutate the recipient.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest

from block_application import encode
from commit_verifier import VerificationError, verify_signed_header
from protocol4_application import Protocol4Application
from protocol4_fixture import fixture
from protocol4_state_sync import APPLY_REJECT_SNAPSHOT, CHUNK_BYTES, _hash, _metadata
from state_sync import OFFER_ACCEPT, OFFER_REJECT
from validator_sets_core import ValidatorSet
from certificate_fixture import packet_fixture


class Protocol4HostileBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.genesis, self.payers, self.admins, self.validators, self.target = fixture()
        self.initial = self.genesis['validator_registry']['validators']
        self.old_hash = ValidatorSet.parse(self.initial).hash

    def tearDown(self):
        self.temp.cleanup()

    def _app(self, name='app.db'):
        app = Protocol4Application(Path(self.temp.name) / name,
                                   expected_genesis=self.genesis)
        app.init_chain(self.genesis['chain_id'], self.genesis, self.initial)
        return app

    def _advance_one(self, app):
        app.finalize_block([], 1, b'\x01' * 32, bytes.fromhex(self.old_hash), [], b'h1')
        app.commit()

    def test_last_commit_identity_power_flag_and_duplicate_mutations_rejected(self):
        for field, mutate in (
            ('address', lambda vote: vote.update(address='00' * 20)),
            ('power', lambda vote: vote.update(power=vote['power'] + 1)),
            ('block_id_flag', lambda vote: vote.update(block_id_flag=4)),
            ('duplicate_identity', lambda vote, first=None: vote.update(address=first)),
        ):
            with self.subTest(field=field):
                app = self._app(field + '.db')
                try:
                    self._advance_one(app)
                    votes = [{'address': v.address.hex(), 'power': v.power,
                              'block_id_flag': 2}
                             for v in ValidatorSet.parse(self.initial).validators]
                    if field == 'duplicate_identity':
                        mutate(votes[1], votes[0]['address'])
                    else:
                        mutate(votes[0])
                    with self.assertRaisesRegex(ValueError, 'last-commit'):
                        app.finalize_block([], 2, b'\x02' * 32,
                                           bytes.fromhex(self.old_hash), votes, b'h2')
                    self.assertEqual(app.height, 1)
                    self.assertIsNone(app.pending)
                finally:
                    app.close()

    def test_application_metadata_does_not_substitute_for_signed_header_authentication(self):
        app = self._app('metadata.db')
        try:
            self._advance_one(app)
            # The application boundary accepts engine-shaped metadata.  This is
            # intentionally not a certificate and must never be reported as one.
            votes = [{'address': v.address.hex(), 'power': v.power,
                      'block_id_flag': 2}
                     for v in ValidatorSet.parse(self.initial).validators]
            result, _ = app.finalize_block([], 2, b'\x02' * 32,
                                           bytes.fromhex(self.old_hash), votes, b'h2')
            self.assertEqual(result['height'], 2)
            self.assertIn('last_commit_votes', result)
            self.assertEqual(result['last_commit_votes'], votes)
        finally:
            app.close()

        _, trust, _, packet = packet_fixture()
        forged = copy.deepcopy(packet['state_commit'])
        forged['header']['app_hash'] = 'ab' * 32
        with self.assertRaises(VerificationError):
            verify_signed_header(forged, trust)

    def _source(self, height=3):
        source = self._app('source.db')
        self._advance_one(source)
        for h in range(2, height + 1):
            roster = self.initial
            votes = [{'address': v.address.hex(), 'power': v.power,
                      'block_id_flag': 2} for v in ValidatorSet.parse(roster).validators]
            source.finalize_block([], h, bytes([h]) * 32, bytes.fromhex(self.old_hash),
                                  votes, ('h' + str(h)).encode())
            source.commit()
        return source

    def _attempt_payload(self, source, name, transform):
        recipient = Protocol4Application(
            Path(self.temp.name) / (name + '.db'), expected_genesis=self.genesis
        )
        try:
            desc = source.list_snapshots()[0]
            raw = b''.join(source.load_snapshot_chunk(desc['height'], desc['format'], i)
                           for i in range(desc['chunks']))
            payload = json.loads(raw)
            transform(payload)
            forged = encode(payload)
            chunks = (len(forged) + CHUNK_BYTES - 1) // CHUNK_BYTES
            bad_desc = {**desc, 'chunks': chunks, 'hash': _hash(forged),
                        'metadata': _metadata(self.genesis, source.height,
                                               source.app_hash, len(forged), chunks)}
            self.assertEqual(recipient.offer_snapshot(bad_desc,
                             bytes.fromhex(source.app_hash)), OFFER_ACCEPT)
            answer = None
            for i in range(chunks):
                answer = recipient.apply_snapshot_chunk(
                    i, forged[i * CHUNK_BYTES:(i + 1) * CHUNK_BYTES], 'hostile-peer')
            self.assertEqual(answer['result'], APPLY_REJECT_SNAPSHOT)
            self.assertEqual(recipient.height, 0)
            self.assertIsNone(recipient.state)
            self.assertIsNone(recipient.db.execute('SELECT 1 FROM committed').fetchone())
        finally:
            recipient.close()

    def test_malformed_reordered_truncated_and_duplicated_snapshot_data_never_installs(self):
        source = self._source()
        try:
            self._attempt_payload(source, 'malformed',
                                  lambda p: p.update(app_hash='ff' * 32))
            self._attempt_payload(source, 'reordered',
                                  lambda p: p['history'].reverse())
            self._attempt_payload(source, 'duplicated',
                                  lambda p: p['history'].append(copy.deepcopy(p['history'][-1])))
        finally:
            source.close()

    def test_truncated_and_wrong_app_hash_snapshot_data_never_installs(self):
        source = self._source()
        recipient = Protocol4Application(
            Path(self.temp.name) / 'truncated.db', expected_genesis=self.genesis
        )
        try:
            desc = source.list_snapshots()[0]
            self.assertEqual(recipient.offer_snapshot(desc, b'\x00' * 32), OFFER_REJECT)
            before = (recipient.height, recipient.state, recipient.app_hash)
            self.assertEqual(recipient.height, before[0])
            self.assertIsNone(recipient.state)
            self.assertEqual(recipient.offer_snapshot(
                desc, bytes.fromhex(source.app_hash)
            ), OFFER_ACCEPT)
            for index in range(desc['chunks']):
                chunk = source.load_snapshot_chunk(desc['height'], desc['format'], index)
                if index == desc['chunks'] - 1:
                    chunk = chunk[:-1]
                answer = recipient.apply_snapshot_chunk(index, chunk, 'hostile-peer')
            self.assertEqual(answer['result'], APPLY_REJECT_SNAPSHOT)
            self.assertEqual(recipient.height, 0)
            self.assertIsNone(recipient.state)
        finally:
            recipient.close()
            source.close()


if __name__ == '__main__':
    unittest.main()
