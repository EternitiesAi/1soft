import io
import os
from pathlib import Path
import tempfile
import unittest
from abci_wire import Request, Response, uvarint, read_frame, write_frame, MAX_FRAME
from abci_server import dispatch, Server
from block_application import BlockApplication
from native_core import canonical
from test_block_application import fixture, signed

class WireTests(unittest.TestCase):
    def test_info_golden_frame(self):
        r=Request(); r.info.SetInParent(); out=io.BytesIO(); write_frame(out,r)
        self.assertEqual(out.getvalue(),bytes.fromhex('021a00'))

    def test_commit_golden_frame(self):
        r=Request(); r.commit.SetInParent(); out=io.BytesIO(); write_frame(out,r)
        self.assertEqual(out.getvalue(),bytes.fromhex('025a00'))

    def test_finalize_golden_tag_and_height(self):
        r=Request();r.finalize_block.height=7
        self.assertEqual(r.SerializeToString(),bytes.fromhex('a201022807'))

    def test_finalize_response_app_hash_tag(self):
        r=Response();r.finalize_block.app_hash=b'abc'
        self.assertEqual(r.SerializeToString(),bytes.fromhex('aa01052a03616263'))

    def test_round_trip(self):
        b=io.BytesIO();r=Request();r.echo.message='hello';write_frame(b,r);b.seek(0)
        self.assertEqual(Request.FromString(read_frame(b)).echo.message,'hello')

    def test_unknown_request_fields_tolerated(self):
        r=Request.FromString(bytes.fromhex('a201052807980601'))
        self.assertEqual(r.finalize_block.height,7)

    def test_eof(self):self.assertIsNone(read_frame(io.BytesIO(b'')))
    def test_partial_varint(self):
        with self.assertRaises(ValueError):read_frame(io.BytesIO(b'\x80'))
    def test_partial_message(self):
        with self.assertRaises(ValueError):read_frame(io.BytesIO(b'\x03a'))
    def test_oversized_frame(self):
        with self.assertRaises(ValueError):read_frame(io.BytesIO(bytes.fromhex('81808001')))
    def test_overflow(self):
        with self.assertRaises(ValueError):read_frame(io.BytesIO(b'\xff'*10))
    def test_noncanonical_length(self):
        with self.assertRaises(ValueError):read_frame(io.BytesIO(b'\x80\x00'))
    def test_uvarint_bounds(self):
        for n in [-1,MAX_FRAME+1,True]:
            with self.assertRaises(ValueError):uvarint(n)

    def test_dispatch_lifecycle(self):
        app=BlockApplication(':memory:')
        owner,_,_,genesis=fixture()
        try:
            r=Request();r.init_chain.chain_id=genesis['chain_id'];r.init_chain.app_state_bytes=canonical(genesis)
            r.init_chain.initial_height=1
            self.assertEqual(len(dispatch(app,r).init_chain.app_hash),32)
            r=Request();r.check_tx.tx=signed(genesis,owner)
            self.assertEqual(dispatch(app,r).check_tx.code,0)
            r=Request();r.finalize_block.txs.append(signed(genesis,owner));r.finalize_block.height=1;r.finalize_block.hash=b'h'*32
            self.assertEqual(dispatch(app,r).finalize_block.tx_results[0].code,0)
            self.assertEqual(app.height,0)
            r=Request();r.commit.SetInParent();dispatch(app,r)
            self.assertEqual(app.height,1)
        finally:app.close()

    def test_unknown_method_returns_exception(self):
        app=BlockApplication(':memory:')
        try:self.assertEqual(dispatch(app,Request()).WhichOneof('value'),'exception')
        finally:app.close()

    def test_state_sync_snapshot_wire_and_dispatch_roundtrip(self):
        owner,_,_,genesis=fixture()
        source=BlockApplication(':memory:',expected_genesis=genesis)
        target=BlockApplication(':memory:',expected_genesis=genesis)
        try:
            source.init_chain(genesis['chain_id'],genesis)
            r=Request();r.finalize_block.txs.append(signed(genesis,owner));r.finalize_block.height=1;r.finalize_block.hash=b's'*32
            self.assertEqual(dispatch(source,r).finalize_block.tx_results[0].code,0)
            r=Request();r.commit.SetInParent();dispatch(source,r)
            listed=dispatch(source,Request(list_snapshots={})).list_snapshots if False else None
            r=Request();r.list_snapshots.SetInParent();response=dispatch(source,r)
            self.assertEqual(len(response.list_snapshots.snapshots),1)
            snap=response.list_snapshots.snapshots[0]
            self.assertEqual((snap.height,snap.format), (1,1))
            r=Request();r.offer_snapshot.snapshot.CopyFrom(snap);r.offer_snapshot.app_hash=bytes.fromhex(source.app_hash)
            self.assertEqual(dispatch(target,r).offer_snapshot.result,1)
            for index in range(snap.chunks):
                r=Request();r.load_snapshot_chunk.height=snap.height;r.load_snapshot_chunk.format=snap.format;r.load_snapshot_chunk.chunk=index
                chunk=dispatch(source,r).load_snapshot_chunk.chunk;self.assertTrue(chunk)
                a=Request();a.apply_snapshot_chunk.index=index;a.apply_snapshot_chunk.chunk=chunk;a.apply_snapshot_chunk.sender='peer'
                self.assertEqual(dispatch(target,a).apply_snapshot_chunk.result,1)
            self.assertEqual(target.info()['height'],1);self.assertEqual(target.app_hash,source.app_hash)
        finally:source.close();target.close()

    def test_snapshot_request_message_fields_round_trip(self):
        r=Request();r.offer_snapshot.snapshot.height=9;r.offer_snapshot.snapshot.format=1
        r.offer_snapshot.snapshot.chunks=2;r.offer_snapshot.snapshot.hash=b'h'*32
        r.offer_snapshot.snapshot.metadata=b'meta';r.offer_snapshot.app_hash=b'a'*32
        raw=r.SerializeToString();got=Request.FromString(raw).offer_snapshot
        self.assertEqual(got.snapshot.height,9);self.assertEqual(got.snapshot.chunks,2)
        self.assertEqual(got.snapshot.hash,b'h'*32);self.assertEqual(got.app_hash,b'a'*32)

    @unittest.skipUnless(os.name=='posix','Unix-socket server is Linux/WSL scope')
    def test_socket_existing_path_not_replaced(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'app.sock';p.write_text('keep')
            app=BlockApplication(':memory:')
            try:
                with self.assertRaises(ValueError):Server(str(p),app)
                self.assertEqual(p.read_text(),'keep')
            finally:app.close()

    @unittest.skipUnless(os.name=='posix','Unix-socket server is Linux/WSL scope')
    def test_socket_directory_must_be_private(self):
        with tempfile.TemporaryDirectory() as d:
            os.chmod(d,0o755);app=BlockApplication(':memory:')
            try:
                with self.assertRaises(ValueError):Server(str(Path(d)/'app.sock'),app)
            finally:app.close()

if __name__=='__main__':unittest.main()
