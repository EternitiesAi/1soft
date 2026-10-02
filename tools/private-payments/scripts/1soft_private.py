#!/usr/bin/env python3
"""Explicit private-invoice and native DEV payment operations on a ready runtime."""
import argparse
from dataclasses import asdict, fields
import getpass
import os
from pathlib import Path
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT / p) for p in (
    'src', 'scripts', 'tools/validator-transition/src', 'tools/protocol4-client/src',
    'tools/protocol4-wallet/src', 'tools/protocol4-delivery/src',
    'tools/protocol4-explorer/src', 'tools/protocol4-receipts/src',
    'tools/local-platform/src', 'tools/private-payments/src')]

from block_application import encode
from commit_verifier import load_json
from invoice_book import initialize_invoice_storage, open_invoice_storage
from invoice_privacy import MAX_PLAINTEXT_BYTES, MAX_ENVELOPE_BYTES
from local_devnet import private_new, read_private
from merchant_devnet import network_for_workspace
from native_core import identifier
from p4_evidence import content_id, hash_text, integer, need
from p4_read_store import private_path
from p4_receipt_capsule import MAX_CAPSULE_BYTES
from payment_x402 import MAX_REQUIRED_HEADER, NativePaymentExpectation, parse_payment_required
from private_payment_desk import PrivatePaymentDesk

MAX_REVIEW_BYTES = 65536
MAX_EXPECTATION_BYTES = 4096
APPROVAL_FORMAT = '1soft/private-cli-approval/v1'
SUBMISSION_FORMAT = '1soft/private-cli-submission/v1'
REFUSAL = '1soft refused or could not finish this private operation. Inspect the retained private files and original obligations.'


class PrivateParser(argparse.ArgumentParser):
    def error(self, _message):
        # argparse normally echoes unknown values. An accidentally supplied
        # password or private invoice text must not enter diagnostics.
        self.exit(2, '1soft refused invalid command arguments. Use --help for the supported arguments.\n')


def path_argument(value):
    need(type(value) is str and 0 < len(value) <= 4096 and
         all(ord(c) >= 32 and ord(c) != 127 for c in value), 'bounded private path required')
    return Path(value)


def parser():
    result = PrivateParser(description=__doc__)
    sub = result.add_subparsers(dest='command', required=True, parser_class=PrivateParser)
    standalone = ('init-invoices', 'inspect', 'open-invoice', 'export-invoice')
    for command in standalone:
        p = sub.add_parser(command)
        p.add_argument('--invoices', type=path_argument, required=True)
        p.add_argument('--genesis-sha256', required=True)
        if command in ('open-invoice', 'export-invoice'):
            p.add_argument('--request-id', required=True)
            p.add_argument('--output', type=path_argument, required=True)
        elif command == 'inspect':
            p.add_argument('--request-id')
    p = sub.add_parser('check-quote')
    p.add_argument('--required', type=path_argument, required=True)
    p.add_argument('--expectation', type=path_argument, required=True)
    wallet = ('import-invoice', 'prepare', 'approve', 'recover', 'submission-review',
              'submit', 'collect', 'retain-receipt', 'reconcile', 'payment-header', 'export-receipt')
    for command in wallet:
        p = sub.add_parser(command)
        for option in ('workspace', 'engine', 'invoices'):
            p.add_argument('--'+option, type=path_argument, required=True)
        if command == 'import-invoice':
            for option in ('required', 'expectation', 'content'):
                p.add_argument('--'+option, type=path_argument, required=True)
        else:
            p.add_argument('--request-id', required=True)
        if command in ('prepare', 'approve'):
            p.add_argument('--role', choices=('owner', 'raven', 'atlas'), required=True)
        if command == 'prepare': p.add_argument('--valid-until', type=int, required=True)
        if command in ('prepare', 'recover', 'submission-review', 'payment-header', 'export-receipt'):
            p.add_argument('--output', type=path_argument, required=True)
        if command in ('approve', 'submit'):
            p.add_argument('--review', type=path_argument, required=True)
            p.add_argument('--confirmation', required=True)
        if command == 'approve': p.add_argument('--terms-confirmation', required=True)
        if command == 'reconcile': p.add_argument('--expected-revision', required=True)
        if command in ('payment-header', 'export-receipt'): p.add_argument('--capsule-id', required=True)
    return result


def password(*, confirm=False, payment=False):
    need(sys.stdin.isatty() and sys.stderr.isatty(), 'interactive private terminal required')
    prompt = 'Payment vault password: ' if payment else 'Invoice-data vault password: '
    first = getpass.getpass(prompt).encode('utf-8')
    need(16 <= len(first) <= 1024 and b'\n' not in first and b'\r' not in first,
         'bounded vault password required')
    if confirm:
        need(first == getpass.getpass('Repeat invoice-data vault password: ').encode('utf-8'),
             'passwords differ')
    return first


def output_path(path):
    path = private_path(path)
    need(not path.is_relative_to(ROOT) and not path.exists() and not path.is_symlink(),
         'new private output outside source required')
    return path


def json_input(path, maximum, *, canonical=True):
    raw = read_private(path, maximum)
    value = load_json(raw, max_bytes=maximum)
    need(type(value) is dict and (not canonical or encode(value) == raw), 'bounded canonical JSON object required')
    return value


def offer_inputs(args):
    raw = read_private(args.required, MAX_REQUIRED_HEADER)
    header = raw.decode('ascii')  # Preserve exact header: no strip or normalization.
    value = json_input(args.expectation, MAX_EXPECTATION_BYTES)
    need(set(value) == {f.name for f in fields(NativePaymentExpectation)}, 'independent expectation fields required')
    expected = NativePaymentExpectation(**value)
    return header, expected


def saved(path, raw, *, maximum, status, sensitive=False):
    need(type(raw) is bytes and 0 < len(raw) <= maximum, 'bounded output bytes required')
    target = output_path(path); private_new(target, raw)
    return {'status': status, 'output': str(target), 'bytes': len(raw),
            'private_output': True, 'plaintext_returned_on_stdout': False,
            'output_contains_invoice_plaintext': sensitive, 'spending_authority': False}


def review_input(args, *, submission=False):
    wrapper = json_input(args.review, MAX_REVIEW_BYTES)
    expected_fields = {'schema', 'format', 'request_id', 'prepared'}
    if not submission: expected_fields.add('role')
    need(set(wrapper) == expected_fields and type(wrapper['schema']) is int and wrapper['schema'] == 1 and
         wrapper['format'] == (SUBMISSION_FORMAT if submission else APPROVAL_FORMAT) and
         wrapper['request_id'] == args.request_id, 'exact independently selected review wrapper required')
    prepared = wrapper['prepared']; need(type(prepared) is dict, 'original prepared review required')
    if submission:
        need(set(prepared) == {'review', 'confirmation', 'submission_performed',
             'wallet_reservations_changed', 'request_id'} and
             prepared['submission_performed'] is False and prepared['wallet_reservations_changed'] is False,
             'original unsigned submission review required')
    else:
        need(wrapper['role'] == args.role and set(prepared) == {'review', 'confirmation', 'reserved',
             'signed', 'broadcast', 'request_id', 'role', 'terms', 'terms_confirmation'} and
             prepared['role'] == args.role and prepared['reserved'] is False and
             prepared['signed'] is False and prepared['broadcast'] is False,
             'original native and terms review required')
        need(type(prepared['terms']) is dict and
             content_id(prepared['terms']) == prepared['terms_confirmation'] == args.terms_confirmation and
             prepared['terms'].get('native_confirmation') == args.confirmation and
             prepared['terms'].get('request_id') == args.request_id and
             prepared['terms'].get('role') == args.role,
             'independently confirmed merchant terms differ')
    need(type(prepared['review']) is dict and prepared['request_id'] == args.request_id and
         content_id(prepared['review']) == prepared['confirmation'] == args.confirmation,
         'independently confirmed native review differs')
    return prepared


def wallet_operation(args, desk):
    """Dispatch to the actual desk. Password input is the only terminal boundary."""
    command = args.command
    if hasattr(args, 'request_id'): hash_text(args.request_id)
    for name in ('confirmation', 'terms_confirmation', 'expected_revision', 'capsule_id'):
        if hasattr(args, name): hash_text(getattr(args, name))
    if hasattr(args, 'role'): identifier(args.role)
    if hasattr(args, 'output'): output_path(args.output)  # Before review/key/RPC work.
    if command == 'import-invoice':
        header, expected = offer_inputs(args)
        parse_payment_required(header, expected, now_ns=desk.platform.clock())
        content = json_input(args.content, MAX_PLAINTEXT_BYTES, canonical=False)
        secret = password()
        try: return desk.import_invoice(header, expected, content, invoice_password=secret)
        finally: secret = None
    if command == 'prepare':
        integer(args.valid_until, 1, 512)
        prepared = desk.prepare(args.request_id, args.role, valid_until=args.valid_until)
        wrapper = {'schema': 1, 'format': APPROVAL_FORMAT, 'request_id': args.request_id,
                   'role': args.role, 'prepared': prepared}
        result = saved(args.output, encode(wrapper), maximum=MAX_REVIEW_BYTES, status='native_and_terms_review_written')
        return {**result, 'request_id': args.request_id, 'confirmation': prepared['confirmation'],
                'terms_confirmation': prepared['terms_confirmation'], 'signed': False, 'broadcast': False}
    if command == 'approve':
        prepared = review_input(args)
        # Rebuild both trusted terms and native review before opening a key.
        current_terms = desk._terms(args.request_id, args.role, args.confirmation)
        need(encode(current_terms) == encode(prepared['terms']), 'retained merchant terms changed')
        secret = password(payment=True)
        try: return desk.approve(args.request_id, args.role, prepared['review'], args.confirmation,
                                 args.terms_confirmation, payment_password=secret)
        finally: secret = None
    if command == 'recover':
        return saved(args.output, desk.recover(args.request_id), maximum=16384, status='original_signed_wire_written')
    if command == 'submission-review':
        prepared = desk.submission_review(args.request_id)
        wrapper = {'schema': 1, 'format': SUBMISSION_FORMAT, 'request_id': args.request_id, 'prepared': prepared}
        result = saved(args.output, encode(wrapper), maximum=MAX_REVIEW_BYTES, status='submission_review_written')
        return {**result, 'request_id': args.request_id, 'confirmation': prepared['confirmation'],
                'submission_performed': False, 'wallet_reservations_changed': False}
    if command == 'submit':
        prepared = review_input(args, submission=True)
        return desk.submit(args.request_id, prepared['review'], args.confirmation)
    if command == 'collect': return desk.collect(args.request_id)
    if command == 'retain-receipt': return desk.retain_receipt(args.request_id)
    if command == 'reconcile': return desk.reconcile(args.request_id, expected_revision=args.expected_revision)
    if command == 'payment-header':
        value = desk.payment_header(args.request_id, args.capsule_id)
        result = saved(args.output, encode(value), maximum=MAX_REVIEW_BYTES, status='public_payment_signature_material_written')
        return {**result, 'request_id': args.request_id, 'capsule_id': args.capsule_id,
                'full_public_ledger_disclosed': True, 'resource_delivery_authorized': False}
    if command == 'export-receipt':
        desk.recover(args.request_id)  # Check immutable invoice/request/original correlation.
        raw = desk.platform.capsule(args.request_id, args.capsule_id)
        result = saved(args.output, raw, maximum=MAX_CAPSULE_BYTES, status='public_native_receipt_capsule_written')
        return {**result, 'request_id': args.request_id, 'capsule_id': args.capsule_id,
                'full_public_ledger_disclosed': True, 'resource_delivery_authorized': False}
    raise ValueError('unsupported private operation')


def execute(args):
    if hasattr(args, 'genesis_sha256'): hash_text(args.genesis_sha256)
    if hasattr(args, 'request_id') and args.request_id is not None: hash_text(args.request_id)
    if hasattr(args, 'output'): output_path(args.output)
    command = args.command
    if command == 'check-quote':
        header, expected = offer_inputs(args)
        checked = parse_payment_required(header, expected, now_ns=time.time_ns())
        return {'status': 'independent_native_quote_checked', 'request_id': checked['request_id'],
                'quote_sha256': checked['quote_sha256'], 'expectation': asdict(expected),
                'request': checked['request'], 'spending_authority': False, 'onchain_privacy': False}
    if command == 'init-invoices':
        output_path(args.invoices)  # Initialization never overwrites or repairs.
        secret = password(confirm=True)
        try: return initialize_invoice_storage(args.invoices, args.genesis_sha256, password=secret)
        finally: secret = None
    if command in ('inspect', 'open-invoice', 'export-invoice'):
        with open_invoice_storage(args.invoices, args.genesis_sha256) as book:
            if command == 'inspect':
                rows = [book.selected(args.request_id)] if args.request_id else book.entries()
                return {'status': 'retained_encrypted_invoices_inspected', 'invoices': rows,
                        'spending_authority': False, 'onchain_privacy': False, 'data_decrypted': False}
            if command == 'export-invoice':
                return saved(args.output, book.envelope(args.request_id), maximum=MAX_ENVELOPE_BYTES,
                             status='encrypted_invoice_envelope_written')
            book.selected(args.request_id)  # Selection checked before unlocking invoice data.
            secret = password()
            try: plaintext = book.decrypt(args.request_id, password=secret)
            finally: secret = None
            return saved(args.output, encode(plaintext), maximum=65536,
                         status='invoice_plaintext_written_to_private_file', sensitive=True)
    # Connect to an already initialized ready workspace; no engine start,
    # bootstrap, trust renewal or stop is reachable from this entry point.
    network = network_for_workspace(args.workspace, args.engine)
    need(network.ready(), 'existing ready native workspace required')
    with network.service() as service:
        with open_invoice_storage(args.invoices, network.config['genesis_sha256'], clock=network.clock) as invoices:
            return wallet_operation(args, PrivatePaymentDesk(service, invoices))


def main(argv=None):
    os.umask(0o077)
    args = parser().parse_args(argv)
    value = execute(args)
    print(encode(value).decode('ascii'), flush=True)
    return 0


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception:
        # Database, parser and cryptography diagnostics may contain private
        # context. Preserve a failing exit code without reflecting that context.
        print(REFUSAL, file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print(REFUSAL, file=sys.stderr)
        raise SystemExit(130)
