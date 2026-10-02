"""Real private Unix sockets and framed I/O, not a running consensus engine."""
from contextlib import contextmanager
import io
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from abci_server import Server
from abci_wire import Request, Response, Client, read_frame, write_frame, uvarint
from block_application import BlockApplication
from node_io import FrameIO, FrameDeadline, duration
from test_block_application import fixture, signed
from native_core import canonical


def wait_for(predicate, timeout=2):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if predicate():return
        time.sleep(.005)
    raise AssertionError('condition did not become true')

def request_wire(method='echo',message='ping'):
    request=Request()
    if method=='echo':request.echo.message=message
    else:getattr(request,method).SetInParent()
    b=io.BytesIO();write_frame(b,request);return b.getvalue()

@contextmanager
def running(**kwargs):
    with tempfile.TemporaryDirectory() as d:
        app=BlockApplication(':memory:');owner,_,_,g=fixture();app.init_chain(g['chain_id'],g)
        server=Server(str(Path(d)/'app.sock'),app,**kwargs)
        thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True)
        thread.start()
        try:yield server,app,g,owner
        finally:
            server.shutdown();thread.join(2);server.server_close();app.close()

def connect(server):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(2);s.connect(str(server.owned_path));return s

class FrameIOTests(unittest.TestCase):
    def setUp(self):self.a,self.b=socket.socketpair()
    def tearDown(self):self.a.close();self.b.close()
    def test_idle_before_first_byte_is_not_partial_frame_timeout(self):
        stream=FrameIO(self.a,receive_seconds=.08)
        def sender():time.sleep(.15);self.b.sendall(request_wire())
        t=threading.Thread(target=sender);t.start()
        stream.begin_read();got=read_frame(stream);t.join()
        self.assertEqual(Request.FromString(got).echo.message,'ping')
    def test_partial_length_deadline(self):
        stream=FrameIO(self.a,receive_seconds=.08);self.b.sendall(b'\x80');stream.begin_read()
        with self.assertRaises(FrameDeadline):read_frame(stream)
    def test_partial_body_deadline(self):
        stream=FrameIO(self.a,receive_seconds=.08);self.b.sendall(b'\x05a');stream.begin_read()
        with self.assertRaises(FrameDeadline):read_frame(stream)
    def test_slow_drip_cannot_reset_absolute_deadline(self):
        stream=FrameIO(self.a,receive_seconds=.10);self.b.sendall(b'\x40')
        stop=threading.Event()
        def drip():
            while not stop.wait(.025):
                try:self.b.sendall(b'a')
                except OSError:return
        thread=threading.Thread(target=drip);thread.start();start=time.monotonic()
        try:
            stream.begin_read()
            with self.assertRaises(FrameDeadline):read_frame(stream)
            self.assertLess(time.monotonic()-start,.5)
        finally:stop.set();thread.join()
    def test_back_to_back_pipelined_frames_are_not_overread(self):
        self.b.sendall(request_wire(message='one')+request_wire(message='two'))
        stream=FrameIO(self.a)
        stream.begin_read();self.assertEqual(Request.FromString(read_frame(stream)).echo.message,'one')
        stream.begin_read();self.assertEqual(Request.FromString(read_frame(stream)).echo.message,'two')
    def test_response_write_deadline(self):
        self.a.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,4096)
        stream=FrameIO(self.a,send_seconds=.08);stream.begin_write();start=time.monotonic()
        with self.assertRaises(FrameDeadline):stream.write(b'x'*(1024*1024))
        self.assertLess(time.monotonic()-start,.5)
    def test_write_begin_does_not_apply_old_receive_timer(self):
        stream=FrameIO(self.a,receive_seconds=.05,send_seconds=.5)
        self.b.sendall(request_wire());stream.begin_read();read_frame(stream);time.sleep(.08)
        r=Response();r.echo.message='ok';stream.begin_write();write_frame(stream,r)
        self.b.settimeout(1)
        f=self.b.makefile('rb');self.assertEqual(Response.FromString(read_frame(f)).echo.message,'ok');f.close()
    def test_expired_deadline_not_extended_on_next_read(self):
        now=[0.0];stream=FrameIO(self.a,receive_seconds=.1,clock=lambda:now[0]);self.b.sendall(b'a')
        stream.begin_read();self.assertEqual(stream.read(1),b'a');now[0]=1
        self.b.sendall(b'b')
        with self.assertRaises(FrameDeadline):stream.read(1)
    def test_invalid_io_durations_refused(self):
        for value in (True,False,0,-1,121,float('inf'),float('nan'),'5'):
            with self.subTest(value=value),self.assertRaises(ValueError):duration(value,'x')
    def test_eof_cleanly_returned(self):
        self.b.close();stream=FrameIO(self.a);stream.begin_read();self.assertIsNone(read_frame(stream))

class ServerLimitsTests(unittest.TestCase):
    def test_excess_connections_do_not_create_extra_worker_threads(self):
        with running(max_connections=2) as (server,app,g,owner):
            clients=[connect(server) for _ in range(2)]
            try:
                wait_for(lambda:server.metrics()['active_connections']==2)
                for _ in range(24):
                    extra=connect(server)
                    try:self.assertEqual(extra.recv(1),b'')
                    finally:extra.close()
                m=server.metrics();self.assertEqual(m['started_threads'],2);self.assertEqual(m['peak_connections'],2)
                self.assertEqual(m['rejected_connections'],24)
            finally:
                for c in clients:c.close()
            wait_for(lambda:server.metrics()['active_connections']==0)
            with Client(str(server.owned_path)) as c:self.assertEqual(c.call('echo',message='alive').message,'alive')
    def test_connection_gate_precedes_thread_construction(self):
        with tempfile.TemporaryDirectory() as d:
            app=BlockApplication(':memory:');server=Server(str(Path(d)/'s'),app,max_connections=1)
            first,peer1=socket.socketpair();second,peer2=socket.socketpair()
            try:
                with patch('abci_server.threading.Thread') as factory:
                    server.process_request(first,'local-a')
                    server.process_request(second,'local-b')
                    self.assertEqual(factory.call_count,1)
                    self.assertEqual(server.metrics()['rejected_connections'],1)
                    server.server_close()
            finally:
                for sock in (first,peer1,second,peer2):sock.close()
                app.close()
    def test_partial_frame_releases_slot_and_does_not_quarantine_node(self):
        with running(max_connections=1,frame_seconds=.10) as (server,app,g,owner):
            c=connect(server);c.sendall(b'\x80')
            try:self.assertEqual(c.recv(1),b'')
            finally:c.close()
            wait_for(lambda:server.metrics()['active_connections']==0)
            self.assertEqual(server.metrics()['receive_deadlines'],1);self.assertFalse(server.failed.is_set())
            with Client(str(server.owned_path)) as good:self.assertEqual(good.call('check_tx',tx=signed(g,owner)).code,0)
    def test_connection_can_be_idle_between_complete_frames(self):
        with running(frame_seconds=.05) as (server,*_):
            with Client(str(server.owned_path)) as c:
                self.assertEqual(c.call('echo',message='before').message,'before');time.sleep(.15)
                self.assertEqual(c.call('echo',message='after').message,'after')
            self.assertEqual(server.metrics()['receive_deadlines'],0)
    def test_malformed_frame_only_closes_its_client(self):
        with running() as (server,app,g,owner):
            c=connect(server);c.sendall(b'\x80\x00')
            try:self.assertEqual(c.recv(1),b'')
            finally:c.close()
            wait_for(lambda:server.metrics()['malformed_frames']==1)
            self.assertFalse(server.failed.is_set())
            with Client(str(server.owned_path)) as good:self.assertEqual(good.call('echo',message='ok').message,'ok')
    def test_oversized_frame_refused_without_body_allocation(self):
        with running() as (server,*_):
            c=connect(server);c.sendall(bytes.fromhex('81808001'))
            try:self.assertEqual(c.recv(1),b'')
            finally:c.close()
            wait_for(lambda:server.metrics()['malformed_frames']==1)
    def test_server_close_releases_idle_client_threads(self):
        with running() as (server,*_):
            c=connect(server);wait_for(lambda:server.metrics()['active_connections']==1)
            server.server_close()
            try:self.assertEqual(c.recv(1),b'')
            finally:c.close()
            self.assertEqual(server.metrics()['active_connections'],0);self.assertFalse(server.failed.is_set())
    def test_internal_application_fault_quarantines_not_cached_rejection(self):
        with running() as (server,app,g,owner),patch.object(app,'check_tx',side_effect=RuntimeError('test internal fault')):
            with self.assertLogs(level='ERROR'):
                c=connect(server);req=Request();req.check_tx.tx=signed(g,owner);b=io.BytesIO();write_frame(b,req);c.sendall(b.getvalue())
                try:self.assertEqual(c.recv(1),b'')
                finally:c.close()
                wait_for(lambda:server.failed.is_set())
            self.assertEqual(server.metrics()['internal_faults'],1)
    def test_nonreader_response_deadline_then_healthy_client(self):
        import abci_server
        original=abci_server.dispatch
        def oversized_response(app,req):
            if req.WhichOneof('value')=='echo' and req.echo.message=='large':
                r=Response();r.echo.message='x'*(1024*1024);return r
            return original(app,req)
        with running(reply_seconds=.12,max_connections=1) as (server,*_),patch('abci_server.dispatch',side_effect=oversized_response):
            c=connect(server);c.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4096);c.sendall(request_wire(message='large'))
            try:
                wait_for(lambda:server.metrics()['reply_deadlines']==1)
                wait_for(lambda:server.metrics()['active_connections']==0)
            finally:c.close()
            with Client(str(server.owned_path)) as good:self.assertEqual(good.call('echo',message='alive').message,'alive')
            self.assertFalse(server.failed.is_set())
    def test_slow_frame_in_one_slot_does_not_delay_other_healthy_client(self):
        with running(frame_seconds=.3,max_connections=2) as (server,*_):
            slow=connect(server);slow.sendall(b'\x40x')
            try:
                start=time.monotonic()
                with Client(str(server.owned_path)) as good:self.assertEqual(good.call('echo',message='fast').message,'fast')
                self.assertLess(time.monotonic()-start,.25)
            finally:slow.close()
    def test_real_socket_admission_cache_and_commit_invalidation(self):
        with running() as (server,app,g,owner):
            tx=signed(g,owner)
            with Client(str(server.owned_path)) as c:
                self.assertEqual(c.call('check_tx',tx=tx).code,0);self.assertEqual(c.call('check_tx',tx=tx).code,0)
                self.assertEqual(app.admission_stats()['hits'],1)
                self.assertEqual(c.call('finalize_block',txs=[tx],height=1,hash=b'x'*32).tx_results[0].code,0)
                c.call('commit');self.assertEqual(c.call('check_tx',tx=tx).code,1)
    def test_unknown_request_does_not_quarantine(self):
        with running() as (server,*_):
            c=connect(server);f=c.makefile('rwb',buffering=0)
            try:
                write_frame(f,Request());resp=Response.FromString(read_frame(f));self.assertEqual(resp.WhichOneof('value'),'exception')
            finally:f.close();c.close()
            self.assertFalse(server.failed.is_set())
    def test_oversized_query_response_is_explicit_error_not_node_failure(self):
        with running() as (server,app,*_),patch.object(app,'query',return_value={
            'code':0,'log':'','value':b'x'*(2*1024*1024),'height':0}):
            with Client(str(server.owned_path)) as c:
                result=c.call('query',path='/state')
                self.assertEqual(result.code,1);self.assertEqual(result.value,b'')
                self.assertIn('local frame limit',result.log)
                self.assertEqual(c.call('echo',message='still alive').message,'still alive')
            self.assertFalse(server.failed.is_set());self.assertEqual(server.metrics()['oversized_replies'],1)
    def test_invalid_configuration_refused_before_binding_socket(self):
        with tempfile.TemporaryDirectory() as d:
            app=BlockApplication(':memory:');path=str(Path(d)/'s')
            try:
                for opts in ({'max_connections':0},{'max_connections':True},{'max_connections':129},
                             {'frame_seconds':float('nan')},{'reply_seconds':0},{'close_seconds':False}):
                    with self.subTest(opts=opts),self.assertRaises(ValueError):Server(path,app,**opts)
                    self.assertFalse(Path(path).exists())
            finally:app.close()

if __name__=='__main__':unittest.main()
