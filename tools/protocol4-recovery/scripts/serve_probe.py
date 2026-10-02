#!/usr/bin/env python3
"""TEST ONLY: observe format-2 bootstrap, or kill this child after durable Commit.
No remote trigger, new signing key, production switch or database reset exists.
"""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import signal
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT/'src'),str(Path(__file__).resolve().parents[1]/'src')]
from abci_server import Server
from native_core import digest
from protocol4_abci_server import dispatch as ordinary_dispatch
from protocol4_abci_wire import Request, Response
from protocol4_application import Protocol4Application
from recovery_checks import checkpoint, fingerprint, read_json, write_new, integer, need


def run(args):
    need(os.name == 'posix', 'POSIX test fixture required')
    integer(args.kill_height)
    need(not (args.kill_height and args.kill_emission), 'select one crash boundary')
    need(len(args.run_id) == 32 and all(c in '0123456789abcdef' for c in args.run_id), 'run identifier required')
    for p in (args.boundary, args.snapshot_notice, args.snapshot_release):
        if p is not None: need(not p.exists() and not p.is_symlink(), 'old observation must not be reused')
    genesis = read_json(args.genesis,131072)
    app = Protocol4Application(args.db,expected_genesis=genesis)
    server = None
    def dispatch(a, request):
        method = request.WhichOneof('value')
        with a.lock:
            pending = a.pending
            had_snapshot_offer = a.state_sync._offer is not None
            response = ordinary_dispatch(a,request)
            if (method == 'commit' and pending is not None and
                    (a.height == args.kill_height or
                     args.kill_emission and bool(pending['result']['validator_updates']))):
                saved = checkpoint(args.db,genesis)
                m = Path(args.socket).lstat()
                write_new(args.boundary, {'schema':1,'run_id':args.run_id,'pid':os.getpid(),
                    'phase':'committed-before-reply','height':a.height,'genesis_sha256':digest(genesis),
                    'checkpoint':fingerprint(saved),'socket':{'device':m.st_dev,'inode':m.st_ino}})
                # Handler has not encoded/written response. This child only.
                os.kill(os.getpid(),signal.SIGKILL)
            if (method == 'apply_snapshot_chunk' and had_snapshot_offer and
                    a.state_sync._offer is None and response.apply_snapshot_chunk.result == 1 and
                    args.snapshot_notice is not None and
                    a.genesis is not None and not args.snapshot_notice.exists()):
                saved = checkpoint(args.db,genesis)
                need(saved['snapshot_marker'] is not None and saved['local_block_count'] == 0,
                     'snapshot observation is not an untouched install')
                write_new(args.snapshot_notice, {'schema':1,'run_id':args.run_id,'pid':os.getpid(),
                    'phase':'snapshot-installed-before-reply','checkpoint':fingerprint(saved)})
                if args.snapshot_release is not None:
                    deadline = time.monotonic()+30
                    while not args.snapshot_release.exists():
                        need(time.monotonic()<deadline,'snapshot inspection deadline')
                        time.sleep(.025)
                    need(read_json(args.snapshot_release)=={'run_id':args.run_id}, 'snapshot release belongs to another run')
            return response
    try:
        server = Server(str(args.socket),app,request_type=Request,response_type=Response,dispatcher=dispatch)
        def stop(*_): raise KeyboardInterrupt
        signal.signal(signal.SIGTERM,stop); signal.signal(signal.SIGINT,stop)
        try: server.serve_forever(poll_interval=.05)
        except KeyboardInterrupt: pass
        return 2 if server.failed.is_set() else 0
    finally:
        if server: server.server_close()
        app.close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for k in ('db','socket','genesis','boundary'):
        p.add_argument('--'+k,type=Path,required=True)
    p.add_argument('--run-id',required=True);p.add_argument('--kill-height',type=int,default=0)
    p.add_argument('--kill-emission',action='store_true')
    p.add_argument('--snapshot-notice',type=Path);p.add_argument('--snapshot-release',type=Path)
    return run(p.parse_args())

if __name__=='__main__': raise SystemExit(main())
