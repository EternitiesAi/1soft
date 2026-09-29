"""ABCI++ protocol-4 messages keep their own versioned wire contract."""
from __future__ import annotations

from pathlib import Path
import socket
import tempfile
import threading
import unittest

from abci_server import Server
from commit_verifier import encode
from protocol4_abci_server import dispatch
from protocol4_abci_wire import Request, Response, read_frame, write_frame
from protocol4_application import Protocol4Application
from protocol4_fixture import fixture


class Protocol4AbciTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.genesis, *_ = fixture()
        self.app = Protocol4Application(Path(self.temp.name) / 'state.sqlite',
                                        expected_genesis=self.genesis)

    def tearDown(self):
        self.app.close()
        self.temp.cleanup()

    def init_request(self):
        request = Request()
        body = request.init_chain
        body.chain_id = self.genesis['chain_id']
        body.initial_height = 1
        body.app_state_bytes = encode(self.genesis)
        for row in self.genesis['validator_registry']['validators']:
            update = body.validators.add()
            update.pub_key.ed25519 = bytes.fromhex(row['public_key'])
            update.power = row['power']
        return request

    def test_init_proposal_finalization_and_exact_replay_wire(self):
        initialized = dispatch(self.app, self.init_request())
        self.assertEqual(initialized.WhichOneof('value'), 'init_chain')
        self.assertEqual(len(initialized.init_chain.validators), 0)
        old_hash = bytes.fromhex(self.app.state['registry']['next_hash'])
        proposal = Request()
        proposal.process_proposal.height = 1
        proposal.process_proposal.next_validators_hash = old_hash
        self.assertEqual(dispatch(self.app, proposal).process_proposal.status, 1)
        proposal.process_proposal.next_validators_hash = b'\0' * 32
        self.assertEqual(dispatch(self.app, proposal).process_proposal.status, 2)
        request = Request()
        request.finalize_block.height = 1
        request.finalize_block.hash = b'1' * 32
        request.finalize_block.next_validators_hash = old_hash
        first = dispatch(self.app, request)
        self.assertEqual(first.WhichOneof('value'), 'finalize_block')
        self.assertEqual(first.finalize_block.app_hash.hex(), self.app.pending['result']['app_hash'])
        commit = Request()
        commit.commit.SetInParent()
        dispatch(self.app, commit)
        self.assertEqual(self.app.height, 1)
        replay = dispatch(self.app, request)
        self.assertEqual(first.SerializeToString(deterministic=True),
                         replay.SerializeToString(deterministic=True))

    def test_private_socket_uses_protocol4_descriptor(self):
        socket_dir = Path(self.temp.name) / 'socket'
        socket_dir.mkdir(mode=0o700)
        address = socket_dir / 'a.sock'
        with Server(str(address), self.app, request_type=Request,
                    response_type=Response, dispatcher=dispatch) as server:
            worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.01})
            worker.start()
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.settimeout(2)
                    connection.connect(str(address))
                    with connection.makefile('rwb', buffering=0) as stream:
                        write_frame(stream, self.init_request())
                        reply = Response.FromString(read_frame(stream))
                        self.assertEqual(reply.WhichOneof('value'), 'init_chain')
                        self.assertEqual(len(reply.init_chain.validators), 0)
            finally:
                server.shutdown()
                worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
            self.assertFalse(server.failed.is_set())

    def test_snapshot_abci_methods_restore_composite_state(self):
        dispatch(self.app, self.init_request())
        finalized = Request()
        finalized.finalize_block.height = 1
        finalized.finalize_block.hash = b'1' * 32
        finalized.finalize_block.next_validators_hash = bytes.fromhex(
            self.app.state['registry']['next_hash'])
        dispatch(self.app, finalized)
        committed = Request()
        committed.commit.SetInParent()
        dispatch(self.app, committed)

        listing = Request()
        listing.list_snapshots.SetInParent()
        snapshot = dispatch(self.app, listing).list_snapshots.snapshots[0]
        self.assertEqual(snapshot.format, 2)
        receiver = Protocol4Application(Path(self.temp.name) / 'recipient.sqlite',
                                        expected_genesis=self.genesis)
        try:
            offered = Request()
            offered.offer_snapshot.snapshot.CopyFrom(snapshot)
            offered.offer_snapshot.app_hash = bytes.fromhex(self.app.app_hash)
            self.assertEqual(dispatch(receiver, offered).offer_snapshot.result, 1)
            for index in range(snapshot.chunks):
                load = Request()
                load.load_snapshot_chunk.height = snapshot.height
                load.load_snapshot_chunk.format = snapshot.format
                load.load_snapshot_chunk.chunk = index
                chunk = dispatch(self.app, load).load_snapshot_chunk.chunk
                apply = Request()
                apply.apply_snapshot_chunk.index = index
                apply.apply_snapshot_chunk.chunk = chunk
                apply.apply_snapshot_chunk.sender = 'local-test'
                self.assertEqual(dispatch(receiver, apply).apply_snapshot_chunk.result, 1)
            self.assertEqual(receiver.state, self.app.state)
            self.assertEqual(receiver.app_hash, self.app.app_hash)
        finally:
            receiver.close()

    def test_oversized_block_query_is_a_rejection_not_server_failure(self):
        dispatch(self.app, self.init_request())
        query = Request()
        query.query.path = '/block/' + '9' * 500
        reply = dispatch(self.app, query)
        self.assertEqual(reply.WhichOneof('value'), 'query')
        self.assertEqual(reply.query.code, 1)
        self.assertIn('invalid protocol-4 block height', reply.query.log)


if __name__ == '__main__':
    unittest.main()
