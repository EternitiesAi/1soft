#!/usr/bin/env python3
"""Explicit finite-pool local DEV billing; PUBLIC resource bytes only.

Uses an already ready merchant workspace. It never starts engines, unlocks keys,
signs, submits, retries or changes wallet obligations. Full payment capsules
disclose public ledger evidence; this local fixture provides no onchain privacy.
"""
import argparse
import hashlib
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT / p) for p in (
    'src', 'scripts', 'tools/validator-transition/src', 'tools/protocol4-client/src',
    'tools/protocol4-wallet/src', 'tools/protocol4-delivery/src',
    'tools/protocol4-explorer/src', 'tools/protocol4-receipts/src',
    'tools/local-platform/src', 'tools/private-payments/src')]

from block_application import encode
from local_devnet import read_private
from merchant_book import MAX_QUOTES, MAX_RESOURCE_BYTES
from p4_evidence import MAX_EVIDENCE_BYTES, hash_text, integer, need
from p4_read_store import private_path

MAX_WIRE_BYTES = 16384
MAX_STDOUT_BYTES = 256 * 1024
REFUSAL = '1soft refused or could not finish this merchant operation. Retained assignments and original obligations are preserved.'


class MerchantParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, '1soft refused invalid merchant arguments. Use --help for supported arguments.\n')


def path_argument(value):
    if not (type(value) is str and 0 < len(value) <= 4096 and
            all(32 <= ord(c) != 127 for c in value)):
        raise argparse.ArgumentTypeError('bounded path required')
    return Path(value)


def output_path(path):
    target = private_path(path)
    need(not target.is_relative_to(ROOT) and not target.exists() and not target.is_symlink(),
         'new private output outside source required')
    return target


def parser():
    result = MerchantParser(description=__doc__)
    sub = result.add_subparsers(dest='command', required=True, parser_class=MerchantParser)
    for command in ('init-book', 'add-quote', 'inspect', 'export-quote', 'export-proof', 'enroll-wire', 'serve'):
        p = sub.add_parser(command)
        for name in ('workspace', 'engine'): p.add_argument('--' + name, type=path_argument, required=True)
        if command in ('export-quote', 'export-proof', 'enroll-wire'): p.add_argument('--quote-id', required=True)
        if command == 'add-quote':
            p.add_argument('--recipient-index', type=int, required=True)
            p.add_argument('--origin', required=True)
            p.add_argument('--resource-path', required=True)
            p.add_argument('--amount-units', required=True)
            p.add_argument('--resource', type=path_argument, required=True,
                help='Owner-only file containing explicitly PUBLIC resource bytes (not private invoice data).')
            p.add_argument('--public-resource-confirmation', required=True,
                help='Independent SHA256 confirmation that these exact resource bytes may be disclosed publicly.')
            p.add_argument('--expires-ns', type=int, required=True)
            p.add_argument('--description', default='')
            p.add_argument('--mime-type', default='application/octet-stream')
        if command == 'export-quote':
            p.add_argument('--required-out', type=path_argument, required=True)
            p.add_argument('--expectation-out', type=path_argument, required=True)
        if command == 'export-proof': p.add_argument('--proof-out', type=path_argument, required=True)
        if command == 'enroll-wire':
            p.add_argument('--payer', required=True)
            p.add_argument('--wire', type=path_argument, required=True)
            p.add_argument('--evidence', type=path_argument, required=True)
            p.add_argument('--wire-confirmation', required=True,
                help='Independently confirmed SHA256 of the exact caller-selected original public wire.')
        if command == 'serve':
            p.add_argument('--quote-id', action='append', required=True,
                help='Fixed retained quote; repeat the flag for each exact route.')
            p.add_argument('--session-file', type=path_argument, required=True)
            p.add_argument('--seconds', type=int, required=True)
            p.add_argument('--port', type=int)
    return result


def execute(args):
    command = args.command; resource = wire = evidence = None
    if command in ('export-quote', 'export-proof', 'enroll-wire'): hash_text(args.quote_id)
    if command == 'export-proof': output_path(args.proof_out)
    if command == 'export-quote':
        required = output_path(args.required_out); expected = output_path(args.expectation_out)
        need(required != expected, 'quote output files must be distinct')
    if command == 'serve':
        integer(args.seconds, 1, 300); output_path(args.session_file)
        need(1 <= len(args.quote_id) <= MAX_QUOTES and len(set(args.quote_id)) == len(args.quote_id),
             'bounded unique fixed merchant quote selection required')
        for qid in args.quote_id: hash_text(qid)
        if args.port is not None: integer(args.port, 1, 65535)
    if command == 'add-quote':
        hash_text(args.public_resource_confirmation)
        resource = read_private(args.resource, MAX_RESOURCE_BYTES)
        need(0 < len(resource) and hashlib.sha256(resource).hexdigest() == args.public_resource_confirmation,
             'independent exact PUBLIC resource bytes confirmation differs')
    if command == 'enroll-wire':
        hash_text(args.wire_confirmation)
        wire = read_private(args.wire, MAX_WIRE_BYTES)
        need(0 < len(wire) and hashlib.sha256(wire).hexdigest() == args.wire_confirmation,
             'independently selected exact original native wire confirmation differs')
        evidence = read_private(args.evidence, MAX_EVIDENCE_BYTES)
    # Import only after parser/file guards. The validated network checks source,
    # engine and workspace pins normally; no engine lifecycle/key API is called.
    from merchant_devnet import MerchantNetwork
    from merchant_ops import MerchantOps
    network = MerchantNetwork(args.workspace, args.engine)
    ops = MerchantOps(network)
    if command == 'init-book': return ops.init_book()
    if command == 'inspect': return ops.inspect()
    if command == 'add-quote':
        return ops.add_quote(recipient_index=args.recipient_index, merchant_origin=args.origin,
            resource_path=args.resource_path, amount_units=args.amount_units, resource=resource,
            expires_ns=args.expires_ns, description=args.description, mime_type=args.mime_type)
    if command == 'export-quote':
        return ops.export_quote(args.quote_id, required_out=args.required_out, expectation_out=args.expectation_out)
    if command == 'export-proof': return ops.export_proof(args.quote_id, proof_out=args.proof_out)
    if command == 'enroll-wire':
        return ops.enroll_wire(args.quote_id, payer=args.payer, wire=wire, evidence=evidence)
    if command == 'serve':
        return ops.serve(tuple(args.quote_id), session_file=args.session_file, seconds=args.seconds, port=args.port)
    raise ValueError('unsupported merchant operation')


def main(argv=None):
    os.umask(0o077)
    args = parser().parse_args(argv)
    value = execute(args); raw = encode(value)
    need(0 < len(raw) <= MAX_STDOUT_BYTES, 'merchant result exceeds bounded stdout')
    print(raw.decode('ascii'), flush=True)
    return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception:
        print(REFUSAL, file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print(REFUSAL, file=sys.stderr)
        raise SystemExit(130)
