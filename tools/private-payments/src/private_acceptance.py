"""Real four-validator private-invoice journey; transparent development ledger.

The only injected fault is a local dropped admission observation after one real
RPC call. It is labelled as an injection, never as an observed network outage.
"""
import base64
from contextlib import ExitStack
from dataclasses import asdict, replace
import hashlib
import http.client
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time
import traceback
import uuid
from unittest.mock import patch

from block_application import encode
from commit_verifier import load_json
from local_devnet import ROOT, PIN_SHA, LocalNetwork, initialize, private_new, read_private, rpc, wait, verify_engine
from p4_evidence import need
from p4_receipt_capsule import verify_capsule
from invoice_book import initialize_invoice_storage, open_invoice_storage
from merchant_book import MerchantBook
from merchant_http import server
from payment_x402 import NativePaymentExpectation, make_payment_required, parse_payment_response, payment_header
from private_payment_desk import PrivatePaymentDesk
from private_cli_acceptance import invoke
from native_core import address
import p4_delivery

PRIVATE_CHECKS = (
    'four real validators and applications owned',
    'initial native fees and supply verified',
    'authenticated merchant returns pinned 402 quote',
    'invoice import grants no spending authority',
    'private content absent from financial and merchant data',
    'dedicated invoice data vault differs from payment vault',
    'terms review includes fee and immutable merchant pins',
    'explicit approval retains one original and fourteen unit hold',
    'merchant independently enrolls original exact wire',
    'recipient cannot be reassigned to another quote',
    'invalid proof cannot fulfill resource or retire hold',
    'one real RPC call with deliberately dropped local observation',
    'uncertain delivery retains original fourteen unit hold',
    'attempted original cannot be rearmed',
    'same original transfer actually committed',
    'positive receipt collected from actual signed chain',
    'portable receipt independently replayed',
    'capsule retention preserves financial hold',
    'response loss follows durable merchant fulfillment',
    'repeat proof returns original immutable public resource',
    'merchant response is not financial reconciliation',
    'one native identity consumed in merchant database',
    'owned runtime stopped before cold restart',
    'private runtime files remain unaliased',
    'same four validators resume with original trust inputs',
    'cold reopen preserves dedicated data vault and exact ciphertext',
    'cold reopen decrypts original invoice without replacing key',
    'cold reopen preserves original wire and all financial decisions',
    'cold reopen preserves attempt observation and receipt',
    'cold merchant reopen preserves original fulfillment',
    'reopened merchant replays proof before returning saved resource',
    'restart has no new signature or submission and hold stays reserved',
    'only explicit native reconciliation retires original hold',
    'native balances fees budget and total supply conserved',
    'exact source and pinned engine unchanged',
    'owned process and merchant thread cleanup complete',
    'actual CLI creates dedicated invoice vault through terminal',
    'actual CLI imports pinned quote without signing',
    'actual CLI prepares and approves two explicit confirmations',
    'actual CLI recovers unchanged wire without password',
    'actual CLI records original submission review',
    'actual CLI exports exact receipt and response header',
    'actual CLI cold decryption writes only explicit private output',
    'actual CLI explicitly reconciles with expected revision',
)


def stop_owned_web(web, thread, *, workers, errors, seconds=5):
    """Keep cleanup independent and bounded; retain generic failure categories."""
    if web is not None and thread is not None and thread.is_alive():
        def shutdown():
            try: web.shutdown()
            except BaseException: errors.append('merchant_shutdown_failed')
        stopper=threading.Thread(target=shutdown, daemon=True); workers.append(stopper)
        stopper.start(); stopper.join(seconds)
        if stopper.is_alive(): errors.append('merchant_shutdown_incomplete')
    if web is not None:
        try: web.server_close()
        except BaseException: errors.append('merchant_close_failed')
    if thread is not None:
        try:
            thread.join(seconds)
            if thread.is_alive(): errors.append('merchant_thread_alive')
        except BaseException: errors.append('merchant_join_failed')


def source_snapshot(source=None):
    if source is not None:
        if source.get('qualification_format') == '1soft/native-invoice-candidate/v1':
            from native_invoice_qualification import source_checked
        else:
            from release_check import source_checked
        actual = source_checked(source)
        return {k: actual[k] for k in ('commit', 'tree', 'source_id', 'tracked_files')}
    # Development runs include new bytes and explicitly cannot qualify a release.
    names = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z', '--cached', '--others', '--exclude-standard']).split(b'\0')
    files = []
    for name in sorted(set(n for n in names if n)):
        path = ROOT / name.decode(); need(path.is_file() and not path.is_symlink(), 'source file missing or aliased')
        raw = path.read_bytes()
        files.append({'path': name.decode(), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                      'mode': '100755' if path.stat().st_mode & 0o111 else '100644'})
    identity = {'commit': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD']).decode().strip(),
                'tree': subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD^{tree}']).decode().strip(),
                'files': files}
    tracked = subprocess.check_output(['git', '-C', str(ROOT), 'ls-files', '-z', '--cached']).split(b'\0')
    return {**{k: identity[k] for k in ('commit', 'tree')}, 'source_id': hashlib.sha256(encode(identity)).hexdigest(),
            'tracked_files': len([n for n in tracked if n]), 'snapshot_files': len(files)}


def run_private(engine, output, *, source=None, run_id=None):
    output = Path(output).absolute()
    need(not output.is_relative_to(ROOT) and not output.is_symlink(), 'acceptance output must be outside source')
    for parent in (output.parent, *output.parent.parents):
        need(not parent.is_symlink(), 'aliased acceptance output parent refused')
    output.mkdir(mode=0o700, exist_ok=False)
    report = {'schema': 1, 'status': 'running', 'run_id': run_id or str(uuid.uuid4()),
        'scope': 'actual four-validator local private invoice and merchant payment',
        'checks': [], 'consensus_executed': False, 'validator_count': 0,
        'source_qualified': source is not None, 'real_funds': False, 'public_network': False,
        'independent_hosts': False, 'onchain_privacy': False, 'invoice_encryption_executed': False,
        'native_signature_authenticates_resource': False, 'full_public_ledger_disclosed': True,
        'browser_visual_acceptance': 'unassessed', 'production_custody': 'unassessed',
        'globally_exactly_once_service_delivery': False,
        'injection': 'local admission observation deliberately dropped after one real RPC submission'}
    report['cli_calls'] = []; report['cleanup_errors'] = []
    net = web = thread = None; all_children = []; all_threads=[]; saved_logs = False
    payment_password = secrets.token_urlsafe(32).encode(); invoice_password = secrets.token_urlsafe(32).encode()
    session_token = secrets.token_hex(32)
    private_content = {'description': 'Confidential local invoice '+secrets.token_hex(16),
        'contact': secrets.token_hex(16)+'@example.invalid', 'content': 'Private negotiated terms '+secrets.token_hex(16)}
    forbidden = [payment_password, invoice_password, session_token.encode(), *(v.encode() for v in private_content.values())]

    def check(name, condition):
        need(name in PRIVATE_CHECKS and name not in {c['name'] for c in report['checks']}, 'invalid acceptance check')
        report['checks'].append({'name': name, 'passed': bool(condition)})
        print(encode({'check': name, 'passed': bool(condition)}).decode(), flush=True)
        need(condition, name)

    def cli(command, args, password=None):
        result = invoke(command, [str(a) for a in args], password=password)
        report['cli_calls'].append({'command': command,
            **{k: result[k] for k in ('password_prompts', 'returncode', 'stdout_sha256',
                                      'terminal_sha256', 'owned_processes_after_cleanup')}})
        return result['value']

    def stop_web():
        nonlocal web, thread
        try: stop_owned_web(web, thread, workers=all_threads, errors=report['cleanup_errors'])
        except BaseException: report['cleanup_errors'].append('merchant_cleanup_failed')
        finally: web = thread = None

    def logs(workspace):
        nonlocal saved_logs
        if saved_logs: return
        for name in [*(f'app{i}.log' for i in range(4)), *(f'engine{i}.log' for i in range(4))]:
            p = workspace / name
            if not p.exists(): continue
            raw = read_private(p, maximum=5*1024*1024)
            for secret in forbidden: raw = raw.replace(secret, b'[REDACTED]')
            private_new(output / name, raw)
        saved_logs = True

    try:
        report['source'] = source_snapshot(source)
        verify_engine(engine); report.update(engine_sha256=PIN_SHA, engine_version='0.38.25')
        with ExitStack() as stack:
            tmp = stack.enter_context(tempfile.TemporaryDirectory(prefix='one-private-'))
            root = Path(tmp); root.chmod(0o700); workspace = root / 'wallet'
            config = initialize(workspace, engine, password=payment_password)
            net = LocalNetwork(workspace, engine).start(); all_children.extend(net.apps+net.engines)
            # Registered after temp so processes always stop before private files go.
            def stop_net():
                try:
                    if net is not None: report['shutdown'] = net.stop()
                except BaseException: report['cleanup_errors'].append('native_cleanup_failed')
                try: logs(workspace)
                except BaseException: report['cleanup_errors'].append('log_retention_failed')
            stack.callback(stop_net); stack.callback(stop_web)
            net.bootstrap(password=payment_password)
            report.update(consensus_executed=True, validator_count=4)
            check(PRIVATE_CHECKS[0], len(net.apps)==len(net.engines)==4 and all(p.poll() is None for p in all_children))
            genesis = read_private(workspace/'engine-genesis.json'); policy = net.policy()
            payer = config['roles']['owner']['payer']
            with net.service() as svc:
                initial = svc.state(); balances = {a['id']: a['recorded_balance'] for a in initial['wallet']['accounts']}
                check(PRIVATE_CHECKS[1], balances[payer]=='994' and balances['system:fees']=='6')
            invoices = root/'invoices'
            cli('init-invoices', ['--invoices', invoices, '--genesis-sha256', config['genesis_sha256']], invoice_password)
            check(PRIVATE_CHECKS[36], read_private(invoices/'invoice-data.pem').startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----') and
                  report['cli_calls'][-1]['password_prompts']==2)
            merchant_dir = root/'merchant'; merchant_dir.mkdir(mode=0o700); merchant_path = merchant_dir/'merchant.sqlite'
            with MerchantBook(merchant_path, genesis, policy, clock=time.time_ns, create=True): pass
            def book_factory(): return MerchantBook(merchant_path, genesis, policy, clock=time.time_ns)
            web = server(book_factory, session_token=session_token, port=0)
            port = web.server_port; origin = web.origin; route = '/premium/report'
            expected = NativePaymentExpectation(origin, origin+route, '1soft:'+config['chain_id'], '1soft:DEV',
                config['genesis_sha256'], config['merchant'], '12')
            now = time.time_ns()
            required = make_payment_required(expected, created_ns=now, expires_ns=now+600*10**9,
                quote_nonce=secrets.token_hex(32), description='Public local development resource')
            resource = b'1soft local premium resource: immutable public fixture bytes.\n'
            with book_factory() as merchant: qid = merchant.add_quote(required, expected, resource=resource)['quote_sha256']
            web.configure_quote(qid)
            def start_web():
                nonlocal thread
                thread = threading.Thread(target=lambda: web.serve_forever(poll_interval=.01), daemon=True)
                all_threads.append(thread); thread.start()
            start_web()
            def call(method, body=None, signature=None):
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=30)
                headers = {'X-1soft-Merchant-Session': session_token, 'Origin': origin, 'Sec-Fetch-Site': 'same-origin'}
                if method=='POST': headers.update({'Content-Type': 'application/json', 'PAYMENT-SIGNATURE': signature or 'invalid'})
                try:
                    conn.request(method, route, body, headers); response = conn.getresponse()
                    return response.status, list(response.getheaders()), response.read(128*1024)
                finally: conn.close()
            status, headers, _ = call('GET')
            check(PRIVATE_CHECKS[2], status==402 and payment_header(headers, 'PAYMENT-REQUIRED')==required)
            private_new(root/'required-header.txt', required.encode('ascii'))
            private_new(root/'expectation.json', encode(asdict(expected)))
            private_new(root/'private-content.json', encode(private_content))
            base_args = ['--workspace', workspace, '--engine', engine, '--invoices', invoices]
            imported = cli('import-invoice', [*base_args, '--required', root/'required-header.txt',
                '--expectation', root/'expectation.json', '--content', root/'private-content.json'], invoice_password)
            rid = imported['request_id']
            check(PRIVATE_CHECKS[37], report['cli_calls'][-1]['password_prompts']==1 and imported['spending_authority'] is False)
            with net.service() as svc, open_invoice_storage(invoices, config['genesis_sha256']) as invoice:
                desk = PrivatePaymentDesk(svc, invoice)
                ciphertext = invoice.envelope(rid)
                vault_bytes = read_private(invoices/'invoice-data.pem')
                state = svc.state()
                check(PRIVATE_CHECKS[3], imported['spending_authority'] is False and
                    state['wallet']['pending_debit_units']=='0' and svc.book.selected(rid)['decision_id'] is None and
                    svc.delivery.db.execute('SELECT count(*) FROM attempts').fetchone()[0]==0)
                with book_factory() as merchant: public_data = encode(state)+encode(merchant.selected(qid)['required_header'])+ciphertext
                check(PRIVATE_CHECKS[4], all(v.encode() not in public_data for v in private_content.values()))
                cli('prepare', [*base_args, '--request-id', rid, '--role', 'raven', '--valid-until',
                    state['wallet']['state_height']+32, '--output', root/'approval.json'])
                prepared = load_json(read_private(root/'approval.json'))['prepared']
                check(PRIVATE_CHECKS[5], vault_bytes!=read_private(workspace/'raven.pem') and
                    invoice.invoice_key_public!=prepared['review']['signer_public_key'] and
                    address(invoice.invoice_key_public) not in (payer, config['merchant']))
                check(PRIVATE_CHECKS[6], prepared['review']['debit_units']=='14' and
                    prepared['terms']['resource_url']==expected.resource_url and prepared['terms']['quote_sha256']==qid)
                approved = cli('approve', [*base_args, '--request-id', rid, '--role', 'raven', '--review', root/'approval.json',
                    '--confirmation', prepared['confirmation'], '--terms-confirmation', prepared['terms_confirmation']], payment_password)
                check(PRIVATE_CHECKS[38], report['cli_calls'][-1]['password_prompts']==1 and approved['wire_sha256'])
                wire = desk.recover(rid); wire_hash = hashlib.sha256(wire).hexdigest()
                cli('recover', [*base_args, '--request-id', rid, '--output', root/'cli-original.json'])
                check(PRIVATE_CHECKS[39], read_private(root/'cli-original.json')==wire and report['cli_calls'][-1]['password_prompts']==0)
                check(PRIVATE_CHECKS[7], approved['wire_sha256']==wire_hash and svc.state()['wallet']['pending_debit_units']=='14')
                independent_evidence = svc.store.export(svc.store.current()['evidence_id'])
                with book_factory() as merchant:
                    enrolled = merchant.enroll_wire(qid, payer, wire, evidence=independent_evidence)
                    check(PRIVATE_CHECKS[8], enrolled['wire_sha256']==wire_hash and merchant.selected(qid)['fulfillment'] is None)
                    rebound = replace(expected, resource_url=origin+'/premium/other')
                    other_header = make_payment_required(rebound, created_ns=time.time_ns(), expires_ns=now+600*10**9, quote_nonce=secrets.token_hex(32))
                    try: merchant.add_quote(other_header, rebound, resource=b'other public resource')
                    except ValueError: rejected = True
                    else: rejected = False
                    check(PRIVATE_CHECKS[9], rejected and len(merchant.entries())==1)
                bad_status, _, _ = call('POST', b'{}', 'invalid')
                with book_factory() as merchant:
                    check(PRIVATE_CHECKS[10], bad_status==400 and merchant.selected(qid)['fulfillment'] is None and
                        svc.state()['wallet']['pending_debit_units']=='14')
                submissions = []; submit_once = p4_delivery.submit_once
                def drop_observation(*args, **kwargs):
                    observation = submit_once(*args, **kwargs); submissions.append(observation)
                    return {'observation': 'unresolved', 'reason': 'local acceptance deliberately discarded admission response'}
                cli('submission-review', [*base_args, '--request-id', rid, '--output', root/'submission.json'])
                submission = load_json(read_private(root/'submission.json'))['prepared']
                check(PRIVATE_CHECKS[40], submission==desk.submission_review(rid))
                with patch('p4_delivery.submit_once', side_effect=drop_observation):
                    attempt = desk.submit(rid, submission['review'], submission['confirmation'])
                check(PRIVATE_CHECKS[11], len(submissions)==1 and submissions[0]['observation']=='endpoint_admitted')
                check(PRIVATE_CHECKS[12], attempt['submission_attempt_recorded'] and not attempt['execution_proven'] and
                    svc.state()['wallet']['pending_debit_units']=='14' and svc.delivery.db.execute('SELECT count(*) FROM attempts').fetchone()[0]==1)
                try: desk.submission_review(rid)
                except ValueError: rearm_refused = True
                else: rearm_refused = False
                check(PRIVATE_CHECKS[13], rearm_refused)
                txhash = base64.b64encode(hashlib.sha256(wire).digest()).decode()
                committed = wait(lambda: rpc(config['ports'][4], 'tx', {'hash': txhash}), 30)
                check(PRIVATE_CHECKS[14], committed['tx_result']['code']==0 and base64.b64decode(committed['tx'], validate=True)==wire)
                collected = desk.collect(rid)
                check(PRIVATE_CHECKS[15], collected['status']=='receipt_collected')
                retained = desk.retain_receipt(rid); cid = retained['capsule_id']; capsule = svc.capsule(rid, cid)
                proof = verify_capsule(capsule, genesis, policy, now_ns=time.time_ns(), expected_payer=payer, expected_wire_sha256=wire_hash)
                check(PRIVATE_CHECKS[16], proof['capsule_id']==cid and proof['binding']['height']>=1)
                check(PRIVATE_CHECKS[17], svc.state()['wallet']['pending_debit_units']=='14')
                signature = desk.payment_header(rid, cid)['payment_signature_header']
                cli('export-receipt', [*base_args, '--request-id', rid, '--capsule-id', cid, '--output', root/'cli-capsule.json'])
                cli('payment-header', [*base_args, '--request-id', rid, '--capsule-id', cid, '--output', root/'cli-payment-header.json'])
                cli_header = load_json(read_private(root/'cli-payment-header.json'))
                check(PRIVATE_CHECKS[41], read_private(root/'cli-capsule.json', maximum=16*1024*1024)==capsule and
                    cli_header['payment_signature_header']==signature)
                # Real client abandons a real HTTP return. Merchant commits first;
                # the test waits for independent DB observation before replaying.
                request = ('POST '+route+' HTTP/1.0\r\nHost: 127.0.0.1:'+str(port)+
                    '\r\nX-1soft-Merchant-Session: '+session_token+'\r\nContent-Type: application/json\r\n'+
                    'PAYMENT-SIGNATURE: '+signature+'\r\nContent-Length: '+str(len(capsule))+'\r\n\r\n').encode()+capsule
                with socket.create_connection(('127.0.0.1', port), timeout=30) as sock:
                    sock.sendall(request)
                    def fulfilled():
                        with book_factory() as merchant: return merchant.selected(qid)['fulfillment']
                    first_fulfillment = wait(fulfilled, 30)
                check(PRIVATE_CHECKS[18], first_fulfillment['capsule_sha256']==cid)
                status, headers, returned = call('POST', capsule, signature)
                response_header = payment_header(headers, 'PAYMENT-RESPONSE')
                response = parse_payment_response(response_header, expected, payer=payer, quote_sha256=qid,
                    wire_sha256=wire_hash, capsule_sha256=cid)
                check(PRIVATE_CHECKS[19], status==200 and returned==resource)
                check(PRIVATE_CHECKS[20], svc.state()['wallet']['pending_debit_units']=='14' and
                    response['execution_proven'] is False and response['wallet_reservations_changed'] is False)
                with book_factory() as merchant:
                    merchant_before = merchant.db.execute('SELECT * FROM fulfillments').fetchall()
                    check(PRIVATE_CHECKS[21], len(merchant_before)==1 and merchant.selected(qid)['fulfillment']==first_fulfillment)
                financial_before = {n: svc.wallet.db.execute('SELECT * FROM '+n).fetchall() for n in ('observations', 'decisions')}
                delivery_before = {n: svc.delivery.db.execute('SELECT * FROM '+n).fetchall() for n in ('attempts', 'responses', 'receipts')}
                private_new(output/'original-wire.json', wire); private_new(output/'public-receipt-capsule.json', capsule)
                private_new(output/'invoice-envelope.json', ciphertext); private_new(output/'engine-genesis.json', genesis)
                private_new(output/'policy.json', encode(policy))
                report['payment'] = {'request_id': rid, 'quote_sha256': qid, 'wire_sha256': wire_hash, 'capsule_sha256': cid,
                    'native_txid': proof['binding']['native_txid'], 'inclusion_height': proof['binding']['height']}
                report['invoice_encryption_executed'] = True
            original_policy = read_private(workspace/'policy.json'); original_config = read_private(workspace/'workspace.json')
            old_children = list(net.apps+net.engines); old_height = net.height()
            stop_web(); stopped = net.stop()
            check(PRIVATE_CHECKS[22], all(p.poll() is not None for p in old_children) and not stopped['warnings'])
            check(PRIVATE_CHECKS[23], all(not p.is_symlink() and not p.stat().st_mode&0o077 for p in root.rglob('*')))
            net = LocalNetwork(workspace, engine).start(); all_children.extend(net.apps+net.engines)
            wait(lambda: net.height()>old_height, 30)
            check(PRIVATE_CHECKS[24], all(net.height(i)>old_height for i in range(4)) and
                read_private(workspace/'policy.json')==original_policy and read_private(workspace/'workspace.json')==original_config)
            with net.service() as svc, open_invoice_storage(invoices, config['genesis_sha256']) as invoice:
                desk = PrivatePaymentDesk(svc, invoice)
                check(PRIVATE_CHECKS[25], read_private(invoices/'invoice-data.pem')==vault_bytes and invoice.envelope(rid)==ciphertext)
                check(PRIVATE_CHECKS[26], desk.open_invoice(rid, invoice_password=invoice_password)==private_content)
                cli('open-invoice', ['--invoices', invoices, '--genesis-sha256', config['genesis_sha256'],
                    '--request-id', rid, '--output', root/'explicit-decrypted-output.json'], invoice_password)
                check(PRIVATE_CHECKS[42], load_json(read_private(root/'explicit-decrypted-output.json'))==private_content and
                    report['cli_calls'][-1]['password_prompts']==1)
                check(PRIVATE_CHECKS[27], desk.recover(rid)==wire and financial_before==
                    {n: svc.wallet.db.execute('SELECT * FROM '+n).fetchall() for n in financial_before})
                check(PRIVATE_CHECKS[28], delivery_before=={n: svc.delivery.db.execute('SELECT * FROM '+n).fetchall() for n in delivery_before})
                with book_factory() as merchant:
                    check(PRIVATE_CHECKS[29], merchant.db.execute('SELECT * FROM fulfillments').fetchall()==merchant_before)
                    repeated = merchant.fulfill(qid, signature, capsule)
                    check(PRIVATE_CHECKS[30], repeated['native_execution_reverified'] is True and
                        repeated['resource']==resource and repeated['fulfilled_ns']==first_fulfillment['fulfilled_ns'])
                check(PRIVATE_CHECKS[31], svc.state()['wallet']['pending_debit_units']=='14' and
                    svc.delivery.db.execute('SELECT count(*) FROM attempts').fetchone()[0]==1 and
                    svc.wallet.db.execute('SELECT count(*) FROM decisions').fetchone()[0]==1)
                cli('reconcile', [*base_args, '--request-id', rid, '--expected-revision', svc.state()['wallet']['revision']])
                check(PRIVATE_CHECKS[43], report['cli_calls'][-1]['password_prompts']==0)
                final = svc.state()
                check(PRIVATE_CHECKS[32], final['wallet']['pending_debit_units']=='0')
                balances = {a['id']: int(a['recorded_balance']) for a in final['wallet']['accounts']}
                check(PRIVATE_CHECKS[33], balances[payer]==980 and balances[config['merchant']]==12 and
                    balances['system:fees']==8 and sum(balances.values())==1000 and final['wallet']['budgets'][0]['spent']=='14')
                private_new(output/'public-final-state.json', encode(final))
            verify_engine(engine); report['engine_sha256_after'] = PIN_SHA
            report['source_after'] = source_snapshot(source); report['source_unchanged'] = report['source_after']==report['source']
            check(PRIVATE_CHECKS[34], report['source_unchanged'])
        report['owned_processes_after_cleanup'] = sum(p.poll() is None for p in all_children)
        report['owned_threads_after_cleanup'] = sum(t.is_alive() for t in all_threads)
        check(PRIVATE_CHECKS[35], report['owned_processes_after_cleanup']==report['owned_threads_after_cleanup']==0 and
            web is None and thread is None and not report['shutdown']['warnings'] and not report['cleanup_errors'])
        need(len(report['checks'])==len(PRIVATE_CHECKS) and {c['name'] for c in report['checks']}==set(PRIVATE_CHECKS),
             'incomplete actual acceptance')
        report['status'] = 'passed'
    except Exception as exc:
        report['status'] = 'failed'; report['error_type'] = type(exc).__name__
        report['error_frames'] = [{'file': Path(f.filename).name, 'line': f.lineno, 'function': f.name}
                                  for f in traceback.extract_tb(exc.__traceback__)]
        # Generic exception metadata avoids leaking invoice/key/password contents.
    finally:
        stop_web()
        if net is not None:
            try:
                shutdown = net.stop()
                if shutdown['warnings']: report['status'] = 'failed'
            except BaseException: report['cleanup_errors'].append('final_native_cleanup_failed')
        report['owned_processes_after_cleanup'] = sum(p.poll() is None for p in all_children)
        report['owned_threads_after_cleanup'] = sum(t.is_alive() for t in all_threads)
        if report['owned_processes_after_cleanup'] or report['owned_threads_after_cleanup'] or report['cleanup_errors']:
            report['status'] = 'failed'
        raw = encode(report)
        need(all(secret not in raw for secret in forbidden), 'report contains private data')
        private_new(output/'result.json', raw)
    return report
