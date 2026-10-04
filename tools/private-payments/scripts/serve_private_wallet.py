#!/usr/bin/env python3
"""Serve committed invoices from an already ready private development workspace.

This entry point owns only its loopback HTTP listener. The caller separately
owns network lifecycle, quote enrollment and encrypted invoice import.
"""
import os
from pathlib import Path
import signal
import sys
import threading
from contextlib import contextmanager
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/p) for p in ('src','scripts','tools/validator-transition/src',
    'tools/protocol4-client/src','tools/protocol4-wallet/src','tools/protocol4-delivery/src',
    'tools/protocol4-explorer/src','tools/protocol4-receipts/src','tools/protocol4-custody/src','tools/local-platform/src',
    'tools/private-payments/src','tools/private-payments/scripts')]
from block_application import encode
from p4_evidence import integer,need
from invoice_book import open_invoice_storage
from merchant_devnet import network_for_workspace
from merchant_browser import MerchantBrowserService,ready_for_browser
from platform_http import server
from private_payment_desk import desk_for_platform
from importlib import import_module
private_cli=import_module('1soft_private')


def parser():
    p=private_cli.PrivateParser(description=__doc__)
    for field in ('workspace','engine','invoices'):p.add_argument('--'+field,type=private_cli.path_argument,required=True)
    p.add_argument('--port',type=int,default=0)
    p.add_argument('--merchant-session',type=private_cli.path_argument,
        help='Existing owner-private alpha merchant session; enrollment remains operator-only')
    return p


def main(argv=None):
    os.umask(0o077);args=parser().parse_args(argv);integer(args.port,0,65535)
    # Do not context-manage the network: __enter__ starts validators.
    network=network_for_workspace(args.workspace,args.engine)
    try:
        ready_for_browser(network)
        fulfillment=None
        if args.merchant_session is not None:
            from merchant_alpha_ops import AlphaMerchantOps
            from merchant_browser_delivery import AlphaMerchantBridge
            merchant=AlphaMerchantOps(network)
            fulfillment=AlphaMerchantBridge(args.merchant_session,
                lambda:merchant.book(read_only=True),merchant.genesis,network.policy())
        @contextmanager
        def service():
            with network.service() as platform, open_invoice_storage(args.invoices,
                    network.config['genesis_sha256'],clock=network.clock) as invoices:
                yield MerchantBrowserService(desk_for_platform(platform,invoices),fulfillment=fulfillment)
        with service() as svc:svc.state()  # Validate retained correlation before listening.
        stopped=threading.Event()
        signal.signal(signal.SIGINT,lambda *_:stopped.set())
        signal.signal(signal.SIGTERM,lambda *_:stopped.set())
        with server(service,port=args.port) as web:
            web.timeout=.25
            print(encode(dict(status='committed_merchant_wallet_running',
                url=f'http://127.0.0.1:{web.server_port}/',genesis_sha256=network.config['genesis_sha256'],
                network_lifecycle_performed=False,invoice_data_decrypted=False,real_funds_supported=False,
                merchant_fulfillment_available=fulfillment is not None,
                shutdown='Ctrl+C closes only this HTTP listener; the separate network owner keeps its validators')).decode(),flush=True)
            while not stopped.is_set():web.handle_request()
        print(encode(dict(status='owned_http_listener_closed',network_lifecycle_performed=False,
            data_preserved=True)).decode(),flush=True)
    finally:network.close_read_store()
    return 0

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:
        print('1soft refused or could not finish this local invoice view. Original files and obligations are retained.',file=sys.stderr)
        raise SystemExit(1)
