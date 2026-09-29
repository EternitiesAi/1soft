"""Private ABCI adapter checks; actual engine acceptance remains a separate gate."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

from commit_verifier import encode
from registry_abci_wire import Request, Response, read_frame, write_frame
from registry_abci_server import Server, dispatch
from registry_application import RegistryApplication
from registry_fixture import fixture, schedule
from validator_sets import ValidatorSet


class RegistryAbciTests(unittest.TestCase):
    def setUp(self):
        self.genesis, self.admins, self.validators, self.target = fixture()
        self.temp = tempfile.TemporaryDirectory()
        self.app = RegistryApplication(Path(self.temp.name) / 'registry.sqlite', self.genesis, create=True)

    def tearDown(self):
        self.app.close()
        self.temp.cleanup()

    def init_request(self):
        request = Request()
        body = request.init_chain
        body.chain_id = self.genesis['chain_id']
        body.app_state_bytes = encode(self.genesis)
        body.initial_height = 1
        for row in self.genesis['validators']:
            update = body.validators.add()
            update.pub_key.ed25519 = bytes.fromhex(row['public_key'])
            update.power = row['power']
        return request

    def finalize_request(self, height, txs=(), *, bad_next=False, bad_vote=False):
        before = self.app.state()
        _, expected = self.app.rules.transition(before, list(txs), height)
        request = Request()
        body = request.finalize_block
        body.height = height
        body.hash = hashlib.sha256(str(height).encode()).digest()
        body.txs.extend(txs)
        body.next_validators_hash = b'\0' * 32 if bad_next else bytes.fromhex(expected['next_validators_hash'])
        if height > 1:
            for validator in ValidatorSet.parse(before['active_validators']).validators:
                vote = body.decided_last_commit.votes.add()
                vote.validator.address = validator.address
                vote.validator.power = validator.power + int(bad_vote)
                vote.block_id_flag = 2
        return request

    def test_init_chain_checks_exact_initial_roster_and_genesis(self):
        request = self.init_request()
        request.init_chain.app_state_bytes = json.dumps(self.genesis, indent=2).encode()
        response = dispatch(self.app, request)
        self.assertEqual(response.WhichOneof('value'), 'init_chain')
        self.assertEqual(response.init_chain.app_hash.hex(), self.app.info()['app_hash'])
        request.init_chain.validators.add().CopyFrom(request.init_chain.validators[0])
        self.assertEqual(dispatch(self.app, request).WhichOneof('value'), 'exception')
        request = self.init_request()
        request.init_chain.validators[0].power += 1
        self.assertEqual(dispatch(self.app, request).WhichOneof('value'), 'exception')

    def test_check_and_proposal_do_not_commit_registry(self):
        wire = schedule(self.app, self.admins, self.target)
        request = Request()
        request.check_tx.tx = wire
        self.assertEqual(dispatch(self.app, request).check_tx.code, 0)
        request = Request()
        request.prepare_proposal.txs.append(wire)
        request.prepare_proposal.height = 1
        request.prepare_proposal.max_tx_bytes = 1_000_000
        self.assertEqual(list(dispatch(self.app, request).prepare_proposal.txs), [wire])
        request = Request()
        request.process_proposal.txs.append(wire)
        request.process_proposal.height = 1
        self.assertEqual(dispatch(self.app, request).process_proposal.status, 1)
        self.assertEqual(self.app.state()['height'], 0)
        self.assertEqual(self.app.state()['sequence'], 0)

    def test_finalize_emits_updates_only_at_scheduled_height(self):
        wire = schedule(self.app, self.admins, self.target)
        observations = []
        for height in range(1, 8):
            request = self.finalize_request(height, (wire,) if height == 1 else ())
            response = dispatch(self.app, request, observations.append)
            self.assertEqual(response.WhichOneof('value'), 'finalize_block')
            self.assertEqual(len(response.finalize_block.validator_updates), 3 if height == 4 else 0)
            self.assertEqual(self.app.state()['height'], height - 1)
            commit = Request()
            commit.commit.SetInParent()
            self.assertEqual(dispatch(self.app, commit).WhichOneof('value'), 'commit')
            self.assertEqual(self.app.state()['height'], height)
        self.assertEqual(self.app.state()['epoch'], 1)
        self.assertEqual([row['height'] for row in observations], list(range(1, 8)))
        self.assertEqual({v['address']: v['power'] for v in observations[6]['votes']},
                         {v.address.hex(): v.power for v in ValidatorSet.parse(self.target).validators})

    def test_wrong_engine_context_refused_before_finalization(self):
        self.assertEqual(dispatch(self.app, self.finalize_request(1, bad_next=True)).WhichOneof('value'), 'exception')
        self.assertEqual(self.app.state()['height'], 0)
        first = self.finalize_request(1)
        self.assertEqual(dispatch(self.app, first).WhichOneof('value'), 'finalize_block')
        commit = Request()
        commit.commit.SetInParent()
        dispatch(self.app, commit)
        self.assertEqual(dispatch(self.app, self.finalize_request(2, bad_vote=True)).WhichOneof('value'), 'exception')
        self.assertEqual(self.app.state()['height'], 1)

    def test_state_sync_wire_rejects_snapshot_without_retry(self):
        offered = Request()
        offered.offer_snapshot.SetInParent()
        self.assertEqual(dispatch(self.app, offered).offer_snapshot.result, 3)
        chunk = Request()
        chunk.apply_snapshot_chunk.SetInParent()
        self.assertEqual(dispatch(self.app, chunk).apply_snapshot_chunk.result, 5)

    def test_socket_server_stops_after_internal_commit_failure(self):
        address = Path(self.temp.name) / 'registry.sock'
        with Server(address, self.app) as server:
            worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
            worker.start()
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.settimeout(2)
                    connection.connect(str(address))
                    with connection.makefile('rwb', buffering=0) as stream:
                        write_frame(stream, self.finalize_request(1))
                        self.assertEqual(Response.FromString(read_frame(stream)).WhichOneof('value'),
                                         'finalize_block')
                        commit = Request()
                        commit.commit.SetInParent()
                        with patch.object(self.app, 'commit', side_effect=OSError('injected storage fault')), \
                                patch('registry_abci_server.logging.exception') as diagnostic:
                            write_frame(stream, commit)
                            self.assertIsNone(read_frame(stream))
                            diagnostic.assert_called_once()
                worker.join(timeout=2)
                self.assertFalse(worker.is_alive())
                self.assertTrue(server.failed)
                self.assertEqual(self.app.state()['height'], 0)
            finally:
                if worker.is_alive():
                    server.shutdown()
                    worker.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
