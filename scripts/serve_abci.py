#!/usr/bin/env python3
"""Run the development application behind a private ABCI Unix socket (Linux/WSL)."""
import argparse
import json
import signal
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from block_application import BlockApplication, APP_NAME
from abci_server import Server

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db',required=True)
    parser.add_argument('--socket',required=True)
    parser.add_argument('--genesis',required=True,help='Native app genesis, not the engine genesis')
    parser.add_argument('--max-connections', type=int, default=16, help='private ABCI worker limit, 1-128')
    parser.add_argument('--frame-seconds', type=float, default=5.0, help='absolute deadline once a frame starts')
    parser.add_argument('--reply-seconds', type=float, default=5.0, help='absolute response-write deadline')
    parser.add_argument('--no-admission-cache', action='store_true', help='explicit local comparison mode')
    args=parser.parse_args()
    genesis=json.loads(Path(args.genesis).read_text())
    app=BlockApplication(args.db,expected_genesis=genesis,admission_cache=not args.no_admission_cache)
    server=None
    try:
        server=Server(args.socket,app,max_connections=args.max_connections,
                      frame_seconds=args.frame_seconds,reply_seconds=args.reply_seconds)
        def stop(*_): raise KeyboardInterrupt
        signal.signal(signal.SIGTERM,stop)
        signal.signal(signal.SIGINT,stop)
        print(json.dumps({'application':APP_NAME,'socket':args.socket,'status':'ready',
                          'max_connections':server.max_connections,'frame_seconds':server.frame_seconds,
                          'reply_seconds':server.reply_seconds,'admission_cache':not args.no_admission_cache}),flush=True)
        try: server.serve_forever(poll_interval=.1)
        except KeyboardInterrupt: pass
        return 2 if server.failed.is_set() else 0
    finally:
        if server: server.server_close()
        app.close()

if __name__=='__main__': raise SystemExit(main())
