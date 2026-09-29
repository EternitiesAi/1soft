"""Private Unix-socket ABCI server. This is an application endpoint, not a node."""
from __future__ import annotations
import json
import logging
import os
from pathlib import Path
import socketserver
import socket
import time
import stat
import threading

from google.protobuf.message import DecodeError
from native_core import Reject, parse_wire
from block_application import BlockApplication
from abci_wire import Request, Response, read_frame, write_frame, MAX_FRAME
from node_io import FrameIO, FrameDeadline, duration


def dispatch(app: BlockApplication, request):
    method = request.WhichOneof('value')
    response = Response()
    if method is None:
        response.exception.error='unsupported request'; return response
    req = getattr(request, method)
    out = getattr(response, method); out.SetInParent()
    try:
        if method == 'echo': out.message = req.message
        elif method == 'flush': pass
        elif method == 'info':
            data=app.info(); out.data=data['name']; out.version='0.16.0-dev'
            out.app_version=data['version']; out.last_block_height=data['height']
            out.last_block_app_hash=bytes.fromhex(data['app_hash'])
        elif method == 'init_chain':
            out.app_hash=bytes.fromhex(app.init_chain(req.chain_id, parse_wire(req.app_state_bytes), req.initial_height))
        elif method == 'check_tx':
            result=app.check_tx(req.tx); out.code=result['code']; out.log=result['log']
            out.data=result['data'].encode(); out.codespace='eternities-native' if out.code else ''
        elif method == 'prepare_proposal':
            out.txs.extend(app.prepare_proposal(list(req.txs),req.height,req.max_tx_bytes))
        elif method == 'process_proposal':
            out.status=1 if app.process_proposal(list(req.txs),req.height) else 2
        elif method == 'finalize_block':
            result=app.finalize_block(list(req.txs),req.height,req.hash)
            out.app_hash=bytes.fromhex(result['app_hash'])
            for r in result['tx_results']:
                t=out.tx_results.add(code=r['code'],log=r['log'],data=r['data'].encode())
                if t.code: t.codespace='eternities-native'
        elif method == 'commit': app.commit()
        elif method == 'query':
            if len(req.path)>512 or req.data:
                out.code=1; out.log='unsupported query input'; out.height=app.height
            else:
                result=app.query(req.path,req.height,req.prove)
                out.code=result['code']; out.log=result['log']; out.value=result['value']; out.height=result['height']
            if out.code: out.codespace='eternities-native'
        elif method == 'list_snapshots':
            for item in app.list_snapshots():
                snap=out.snapshots.add(); snap.height=item['height']; snap.format=item['format']
                snap.chunks=item['chunks']; snap.hash=item['hash']; snap.metadata=item['metadata']
        elif method == 'offer_snapshot':
            offered={'height':req.snapshot.height,'format':req.snapshot.format,'chunks':req.snapshot.chunks,
                     'hash':bytes(req.snapshot.hash),'metadata':bytes(req.snapshot.metadata)}
            out.result=app.offer_snapshot(offered,bytes(req.app_hash))
        elif method == 'load_snapshot_chunk':
            out.chunk=app.load_snapshot_chunk(req.height,req.format,req.chunk)
        elif method == 'apply_snapshot_chunk':
            result=app.apply_snapshot_chunk(req.index,bytes(req.chunk),req.sender)
            out.result=result['result']; out.refetch_chunks.extend(result['refetch_chunks'])
            out.reject_senders.extend(result['reject_senders'])
        elif method == 'extend_vote': pass  # application adds no vote extensions
        elif method == 'verify_vote_extension': out.status=1 if not req.vote_extension else 2
        else: raise Reject('unsupported request')
    except Reject as exc:
        response=Response(); response.exception.error=str(exc)
    return response


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        channel = FrameIO(self.request, receive_seconds=self.server.frame_seconds,
                          send_seconds=self.server.reply_seconds)
        while not self.server.failed.is_set() and not self.server.closing.is_set():
            try:
                channel.begin_read()
                wire = read_frame(channel)
                if wire is None:
                    return
                request = self.server.request_type.FromString(wire)
            except FrameDeadline:
                self.server.count('receive_deadlines'); return
            except (ValueError, DecodeError):
                self.server.count('malformed_frames'); return
            except (ConnectionError, OSError):
                return
            # Only decoding errors above are client framing faults. Internal
            # application errors below must quarantine, not become cached rejects.
            response = self.server.dispatcher(self.server.app, request)
            if response.ByteSize() > MAX_FRAME:
                self.server.count('oversized_replies')
                if request.WhichOneof('value') == 'query':
                    # Full-state reads can outgrow this private transport. Prefer
                    # compact proofs; do not quarantine an otherwise healthy node.
                    response = self.server.response_type()
                    response.query.code = 1
                    response.query.log = 'response exceeds local frame limit; request compact records'
                    response.query.height = self.server.app.height
                else:
                    return
            try:
                channel.begin_write()
                write_frame(channel, response)
                self.server.count('completed_frames')
            except FrameDeadline:
                self.server.count('reply_deadlines'); return
            except (ConnectionError, OSError):
                return


_UnixServer = getattr(socketserver, 'ThreadingUnixStreamServer', object)


class Server(_UnixServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 16

    def __init__(self, path: str, app: BlockApplication, *, max_connections: int = 16,
                 frame_seconds: float = 5.0, reply_seconds: float = 5.0,
                 close_seconds: float = 5.0, request_type=Request,
                 response_type=Response, dispatcher=None):
        if _UnixServer is object or os.name != 'posix':
            raise RuntimeError('ABCI server requires Linux/WSL or another Unix environment')
        if type(max_connections) is not int or not 1 <= max_connections <= 128:
            raise ValueError('max_connections must be an integer between 1 and 128')
        self.frame_seconds = duration(frame_seconds, 'frame_seconds')
        self.reply_seconds = duration(reply_seconds, 'reply_seconds')
        self.close_seconds = duration(close_seconds, 'close_seconds')
        self.max_connections = max_connections
        p = Path(path)
        if p.exists() or p.is_symlink():
            raise ValueError('socket path already exists; refusing to replace')
        parent = p.parent
        if not parent.is_dir():
            raise ValueError('create a private socket directory first')
        mode = parent.stat()
        if mode.st_uid != os.getuid() or stat.S_IMODE(mode.st_mode) & 0o077:
            raise ValueError('socket directory must be owned by this user and mode 0700')
        self.app = app
        self.request_type = request_type
        self.response_type = response_type
        # Preserve the legacy module-level dispatch hook while allowing a
        # versioned P4 dispatcher to be passed explicitly.
        self.dispatcher = dispatcher if dispatcher is not None else lambda app, req: dispatch(app, req)
        self.failed = threading.Event()
        self.closing = threading.Event()
        self._clients_lock = threading.Lock()
        self._clients = {}
        self._counters = dict(accepted_connections=0, rejected_connections=0,
                              peak_connections=0, started_threads=0, completed_frames=0,
                              receive_deadlines=0, reply_deadlines=0, malformed_frames=0,
                              internal_faults=0, oversized_replies=0)
        super().__init__(path, Handler)
        os.chmod(path, 0o600)
        self.owned_path = p
        self.owned_inode = p.stat().st_ino

    def count(self, key):
        with self._clients_lock:
            self._counters[key] += 1

    def metrics(self):
        with self._clients_lock:
            return {**self._counters, 'active_connections':len(self._clients),
                    'max_connections':self.max_connections, 'failed':self.failed.is_set(),
                    'scope':'private local ABCI I/O only; not public P2P/RPC protection'}

    def process_request(self, request, client_address):
        # Gate BEFORE thread creation. ThreadingMixIn's ordinary process_request
        # would create a thread first; checking slots in handle() was too late.
        with self._clients_lock:
            if self.failed.is_set() or self.closing.is_set() or len(self._clients) >= self.max_connections:
                self._counters['rejected_connections'] += 1
                self.shutdown_request(request)
                return
            thread = threading.Thread(target=self._serve_client, args=(request, client_address),
                                      daemon=True, name='1soft-abci-client')
            self._clients[request] = thread
            self._counters['accepted_connections'] += 1
            self._counters['peak_connections'] = max(self._counters['peak_connections'],len(self._clients))
            try:
                thread.start()
                self._counters['started_threads'] += 1
            except BaseException:
                self._clients.pop(request)
                self.shutdown_request(request)
                raise

    def _quarantine(self):
        self.count('internal_faults')
        self.failed.set()
        # Shutdown is called outside the serve_forever thread to avoid deadlock.
        threading.Thread(target=self.shutdown, daemon=True).start()

    def _serve_client(self, request, address):
        try:
            self.finish_request(request, address)
        except Exception:
            logging.exception('Internal ABCI fault; stopping the endpoint')
            self._quarantine()
        finally:
            try:
                self.shutdown_request(request)
            finally:
                with self._clients_lock:
                    self._clients.pop(request, None)

    def server_close(self):
        self.closing.set()
        super().server_close()
        with self._clients_lock:
            clients = list(self._clients.items())
        # Release idle/partial-read clients. A worker already executing native
        # code is allowed bounded join time; Python cannot safely kill its thread.
        for sock, _ in clients:
            try: sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass
        deadline = time.monotonic() + self.close_seconds
        for _, thread in clients:
            if thread is not threading.current_thread():
                thread.join(timeout=max(0, deadline-time.monotonic()))
        if any(t.is_alive() for _, t in clients):
            self.failed.set()
        try:
            if self.owned_path.lstat().st_ino == self.owned_inode:
                self.owned_path.unlink()
        except FileNotFoundError:
            pass
