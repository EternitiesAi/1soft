#!/usr/bin/env python3
"""Create or run an owned private four-validator DEV recipient-pool workspace."""
import argparse
import getpass
import os
from pathlib import Path
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT/p) for p in (
    'src', 'scripts', 'tools/validator-transition/src', 'tools/protocol4-client/src',
    'tools/protocol4-wallet/src', 'tools/protocol4-delivery/src', 'tools/protocol4-custody/src',
    'tools/protocol4-explorer/src', 'tools/protocol4-receipts/src',
    'tools/local-platform/src', 'tools/private-payments/src')]

from block_application import encode
from merchant_devnet import MerchantNetwork, initialize, MIN_RECIPIENTS, MAX_RECIPIENTS
from p4_evidence import integer, need

REFUSAL = '1soft refused or could not finish this development network operation. Preserve the original private workspace and inspect its retained obligations.'


class PrivateParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, '1soft refused invalid command arguments. Use --help for supported arguments.\n')


def path_argument(value):
    need(type(value) is str and 0 < len(value) <= 4096 and
         all(ord(c) >= 32 and ord(c) != 127 for c in value), 'bounded private path required')
    return Path(value)


def parser():
    result = PrivateParser(description=__doc__)
    sub = result.add_subparsers(dest='command', required=True, parser_class=PrivateParser)
    for command in ('init', 'run'):
        p = sub.add_parser(command)
        p.add_argument('--workspace', type=path_argument, required=True)
        p.add_argument('--engine', type=path_argument, required=True)
        if command == 'init':
            p.add_argument('--recipient-count', type=int, default=3)
            p.add_argument('--invoice-commitments', action='store_true',
                help='create a fresh v3 workspace with native signed invoice terms')
        else: p.add_argument('--seconds', type=int, default=60,
            help='1-300 second operating window, including startup; shutdown has separate bounded waits')
    return result


def password(*, confirm=False):
    need(sys.stdin.isatty() and sys.stderr.isatty(), 'interactive private terminal required')
    first = getpass.getpass('Development vault password: ').encode('utf-8')
    need(16 <= len(first) <= 1024 and b'\n' not in first and b'\r' not in first,
         'bounded vault password required')
    if confirm:
        need(first == getpass.getpass('Repeat development vault password: ').encode('utf-8'), 'passwords differ')
    return first


def _cleanup(network):
    """Try every owned Popen handle even when the inherited shutdown fails."""
    owned = tuple(network.engines)+tuple(network.apps)
    errors = []
    try:
        stopped = network.stop()
        need(type(stopped) is dict and type(stopped.get('warnings')) is list,
             'owned shutdown report unavailable')
        if stopped['warnings']: errors.append('owned shutdown reported a warning')
    except BaseException:
        errors.append('owned network shutdown failed')
    for process in owned:
        try:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)
                    errors.append('owned process required forced shutdown')
        except BaseException:
            errors.append('owned process cleanup failed')
    for handle in tuple(network.handles):
        try: handle.close()
        except BaseException: errors.append('owned log cleanup failed')
    network.handles = []
    if network.lock is not None:
        try: network.lock.__exit__(); network.lock = None
        except BaseException: errors.append('owned workspace lock cleanup failed')
    network.stopped = True
    alive = 0
    for process in owned:
        try:
            if process.poll() is None: alive += 1
        except BaseException:
            errors.append('owned process state unavailable'); alive += 1
    return {'owned_processes_after_cleanup': alive, 'cleanup_errors': errors}


def run_network(args, *, monotonic=None, sleep=None):
    seconds = integer(args.seconds, 1, 300)
    monotonic = monotonic or time.monotonic; sleep = sleep or time.sleep
    network = MerchantNetwork(args.workspace, args.engine)
    initialized = network.ready(); secret = None
    if not initialized: secret = password(confirm=False)
    deadline = monotonic()+seconds; interrupted = False
    try:
        network.start()
        if not initialized:
            setup = network.bootstrap(password=secret)
            need(setup['trust_renewed'] is False and network.ready(), 'original development setup unavailable')
        secret = None
        print('1soft private development network ready; this command owns its bounded operating window.',
              file=sys.stderr, flush=True)
        while True:
            remaining = deadline-monotonic()
            if remaining <= 0: break
            network.health(); sleep(min(.2, remaining))
    except KeyboardInterrupt:
        interrupted = True
    finally:
        secret = None
        cleanup = _cleanup(network)
    need(cleanup['owned_processes_after_cleanup'] == 0 and cleanup['cleanup_errors'] == [],
         'owned network cleanup was incomplete; data preserved')
    return {'status': 'owned_merchant_development_network_stopped', 'validator_count': 4,
        'merchant_recipient_count': len(network.config['merchant_recipients']),
        'genesis_sha256': network.config['genesis_sha256'], 'operating_window_seconds': seconds,
        'stop_reason': 'interrupted' if interrupted else 'window_elapsed', 'data_preserved': True,
        'trust_renewed': False, 'real_funds': False, 'public_deployment': False,
        'production_custody': False, 'onchain_privacy': False, **cleanup}


def execute(args):
    if args.command == 'run': return run_network(args)
    need(args.command == 'init', 'unsupported development network operation')
    count = integer(args.recipient_count, MIN_RECIPIENTS, MAX_RECIPIENTS)
    secret = password(confirm=True)
    options = {'invoice_commitments': True} if args.invoice_commitments else {}
    try: q = initialize(args.workspace, args.engine, password=secret, recipient_count=count, **options)
    finally: secret = None
    return {'status': 'merchant_development_workspace_initialized',
        'genesis_sha256': q['genesis_sha256'], 'endpoint': q['endpoint'],
        'merchant_recipients': q['merchant_recipients'], 'merchant_recipient_count': len(q['merchant_recipients']),
        'real_funds': False, 'public_deployment': False, 'production_custody': False, 'onchain_privacy': False}


def main(argv=None):
    os.umask(0o077)
    value = execute(parser().parse_args(argv))
    print(encode(value).decode('ascii'), flush=True)
    return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception:
        print(REFUSAL, file=sys.stderr); raise SystemExit(1)
    except KeyboardInterrupt:
        print(REFUSAL, file=sys.stderr); raise SystemExit(130)
