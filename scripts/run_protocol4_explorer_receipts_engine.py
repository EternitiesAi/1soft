#!/usr/bin/env python3
"""Real-engine qualification of the P4 explorer and portable receipt archive.

The existing delivery runner owns the one-host eight-node network and disposable
signing keys. This runner consumes only its exported public evidence and the two
original signed payments after that runner has closed and removed its private
wallet/delivery runtime. The explorer/read store and archive use a separate private
temporary directory and are removed before this process exits.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch

# Keep clean-source acceptance from being invalidated by Python cache files,
# including bytecode writes by child Python processes in the baseline runner.
sys.dont_write_bytecode = True
os.environ['PYTHONDONTWRITEBYTECODE'] = '1'

ROOT = Path(__file__).resolve().parents[1]
CLIENT_SRC = ROOT / 'tools/protocol4-client/src'
EXPLORER_SRC = ROOT / 'tools/protocol4-explorer/src'
RECEIPTS_SRC = ROOT / 'tools/protocol4-receipts/src'
sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'scripts'),
                str(ROOT / 'tools/validator-transition/src'), str(CLIENT_SRC),
                str(EXPLORER_SRC), str(RECEIPTS_SRC)]

from block_application import encode
from commit_verifier import load_json
from native_core import canonical
from p4_evidence import MAX_EVIDENCE_BYTES, check_clock, verify_evidence
from p4_explorer import current_view, project_report, snapshot_view
from p4_explorer_web import server as explorer_server
from p4_read_store import P4ReadStore
from p4_receipt_capsule import encode_capsule, make_capsule, verify_capsule
from run_protocol4_delivery_engine import git as git_output
from run_protocol4_delivery_engine import run as run_delivery
from run_protocol4_engine import PIN


def _git(*args: str) -> str:
    return git_output(*args)


def _source_identity() -> dict:
    return {'head': _git('rev-parse', 'HEAD'),
            'tree': _git('rev-parse', 'HEAD^{tree}'),
            'status': _git('status', '--porcelain', '--untracked-files=all')}


def _check(report: dict, name: str, condition: bool, details=None) -> None:
    report['checks'].append({'name': name, 'passed': bool(condition), 'details': details})
    if not condition:
        raise AssertionError(name)


def _write_new(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def _json_bytes(value) -> bytes:
    return encode(value) + b'\n'


def _amount(view: dict, account_id: str) -> str:
    rows = [row for row in view['accounts'] if row['id'] == account_id]
    if len(rows) != 1:
        raise AssertionError(f'expected one explorer account {account_id!r}')
    return rows[0]['recorded_balance']


def _budget(view: dict, label: str) -> dict:
    rows = [row for row in view['budgets'] if row['id'].endswith('::' + label)]
    if len(rows) != 1:
        raise AssertionError(f'expected one explorer budget {label!r}')
    return rows[0]


def _stable_view(view: dict) -> dict:
    result = copy.deepcopy(view)
    result.get('checkpoint', {}).pop('checked_at_ns', None)
    return result


def _http_get(port: int, path: str) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    try:
        connection.request('GET', path)
        response = connection.getresponse()
        body = response.read(17 * 1024 * 1024)
        return response.status, {key.lower(): value for key, value in response.getheaders()}, body
    finally:
        connection.close()


def _no_private_artifacts(root: Path) -> bool:
    forbidden = {'wallet.sqlite', 'delivery.sqlite', 'priv_validator_key.json',
                 'node_key.json', 'wallet.key'}
    key_markers = (b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN RSA PRIVATE KEY-----',
                   b'-----BEGIN EC PRIVATE KEY-----', b'"private_key"')
    for path in root.rglob('*'):
        if not path.is_file():
            continue
        name = path.name.lower()
        if (name in forbidden or ('private' in name and 'key' in name) or
            path.suffix.lower() in ('.pem', '.key', '.sqlite', '.db') or
            any(name.endswith(suffix) for suffix in
                ('.sqlite-wal', '.sqlite-shm', '.sqlite-journal', '.db-wal', '.db-shm', '.db-journal'))):
            return False
        # Check bounded chunks so a key cannot be hidden in a renamed JSON or log.
        tail = b''
        with path.open('rb') as stream:
            while chunk := stream.read(1024 * 1024):
                sample = tail + chunk
                if any(marker in sample for marker in key_markers):
                    return False
                tail = sample[-64:]
    return True


def run(engine: str, expected_sha256: str, output: Path) -> dict:
    output = Path(output).resolve()
    if output.is_relative_to(ROOT):
        raise ValueError('acceptance output must be outside the source checkout')
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    binary = Path(engine).resolve()
    initial_source = _source_identity()
    report = {'schema': 1, 'status': 'unassessed', 'checks': [],
              'source_commit': initial_source['head'], 'source_tree': initial_source['tree'],
              'source_dirty_before': bool(initial_source['status']),
              'engine_required_sha256': expected_sha256,
              'scope': 'pinned one-host eight-node P4 turnover; explorer and portable positive receipts',
              'real_funds': False, 'independent_hosts': False, 'public_release_ready': False,
              'wallet_or_delivery_database_packaged': False,
              'started_at_ns': time.time_ns()}
    runtime_paths: list[Path] = []
    httpd = None
    http_thread = None
    temp = None
    try:
        _check(report, 'source checkout is clean at a fixed commit and tree',
               not initial_source['status'])
        _check(report, 'pinned engine file exists', binary.is_file(), str(binary))
        observed_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
        _check(report, 'engine matches independent SHA256 pin',
               len(expected_sha256) == 64 and observed_sha == expected_sha256,
               {'observed_sha256': observed_sha})
        version = subprocess.check_output([str(binary), 'version'], text=True,
                                          timeout=10).strip()
        _check(report, 'engine version matches repository pin',
               version.lstrip('v') == PIN, {'version': version, 'required': PIN})

        # The old runner owns every engine/application process. Capturing its
        # TemporaryDirectory path lets this runner assert that its private runtime
        # was removed before any portable capsule is consumed.
        original_tempdir = tempfile.TemporaryDirectory
        def tracked_tempdir(*args, **kwargs):
            item = original_tempdir(*args, **kwargs)
            runtime_paths.append(Path(item.name))
            return item
        with patch.object(tempfile, 'TemporaryDirectory', new=tracked_tempdir):
            delivery = run_delivery(str(binary), expected_sha256, output / 'delivery')
        _check(report, 'existing P4 engine delivery acceptance passed',
               delivery.get('status') == 'passed',
               {'status': delivery.get('status'), 'reason': delivery.get('reason')})
        _check(report, 'existing delivery acceptance qualified its clean source',
               delivery.get('source_qualified') is True,
               {'source_commit': delivery.get('source_commit'),
                'source_dirty_before': delivery.get('source_dirty_before'),
                'source_dirty_after': delivery.get('source_dirty_after')})
        principal_check = next((row for row in delivery.get('checks', [])
                                if row.get('name') == 'exactly two principal original wires submitted'), None)
        _check(report, 'delivery acceptance submitted the two original payments once',
               principal_check is not None and principal_check.get('passed') is True and
               delivery.get('diagnostics', {}).get('principal_submissions') == 2,
               {'principal_submissions': delivery.get('diagnostics', {}).get('principal_submissions'),
                'total_proxy_submissions': delivery.get('diagnostics', {}).get('total_proxy_submissions')})
        broadcast_check = next((row for row in delivery.get('checks', [])
                                if row.get('name') ==
                                'total broadcasts are exactly two originals and one declined diagnostic'), None)
        _check(report, 'baseline broadcast inventory has two originals and one declined diagnostic only',
               broadcast_check is not None and broadcast_check.get('passed') is True and
               delivery.get('diagnostics', {}).get('declined_submissions') == 1 and
               delivery.get('diagnostics', {}).get('total_proxy_submissions') == 3,
               {'principal_submissions': delivery.get('diagnostics', {}).get('principal_submissions'),
                'declined_submissions': delivery.get('diagnostics', {}).get('declined_submissions'),
                'total_proxy_submissions': delivery.get('diagnostics', {}).get('total_proxy_submissions')})
        _check(report, 'delivery runner closed and removed its private runtime',
               len(runtime_paths) == 1 and not runtime_paths[0].exists(),
               {'runtime_count': len(runtime_paths), 'removed': bool(runtime_paths) and
                not runtime_paths[0].exists()})

        delivery_dir = output / 'delivery'
        genesis_bytes = (delivery_dir / 'engine-genesis.json').read_bytes()
        policy_bytes = (delivery_dir / 'policy.json').read_bytes()
        genesis_sha256 = hashlib.sha256(genesis_bytes).hexdigest()
        policy = load_json(policy_bytes, max_bytes=4096)
        _check(report, 'exported policy bytes are canonical and genesis-pinned',
               encode(policy) == policy_bytes and
               policy['genesis_sha256'] == genesis_sha256,
               {'genesis_sha256': genesis_sha256,
                'policy_id': hashlib.sha256(encode(policy)).hexdigest()})

        raven_wire = (delivery_dir / 'raven-signed.json').read_bytes()
        atlas_wire = (delivery_dir / 'atlas-signed.json').read_bytes()
        raven_evidence_bytes = (delivery_dir / 'raven-receipt-evidence.json').read_bytes()
        atlas_evidence_bytes = (delivery_dir / 'atlas-receipt-evidence.json').read_bytes()
        raven_evidence = load_json(raven_evidence_bytes, max_bytes=MAX_EVIDENCE_BYTES)
        atlas_evidence = load_json(atlas_evidence_bytes, max_bytes=MAX_EVIDENCE_BYTES)
        payer = delivery.get('arithmetic', {}).get('payer')
        if not payer:
            # The baseline report intentionally stores only arithmetic; read the
            # exact payer from the already signed original transaction body.
            payer = load_json(raven_wire, max_bytes=16384)['body']['sender']
        raven_tx = load_json(raven_wire, max_bytes=16384)
        atlas_tx = load_json(atlas_wire, max_bytes=16384)
        _check(report, 'two distinct original signed transfers are the only capsule inputs',
               raven_tx['body']['sender'] == atlas_tx['body']['sender'] == payer and
               raven_tx['body']['op']['type'] == atlas_tx['body']['op']['type'] == 'transfer' and
               raven_wire != atlas_wire,
               {'raven_wire_sha256': hashlib.sha256(raven_wire).hexdigest(),
                'atlas_wire_sha256': hashlib.sha256(atlas_wire).hexdigest()})

        now_ns = time.time_ns()
        check_clock(policy, now_ns)
        before_view = snapshot_view(raven_evidence, genesis_bytes, policy, now_ns=now_ns)
        _check(report, 'pre-turnover explorer snapshot separates state and signed-header heights',
               int(before_view['checkpoint']['header_height']) ==
               int(before_view['checkpoint']['state_height']) + 1,
               {'state_height': before_view['checkpoint']['state_height'],
                'header_height': before_view['checkpoint']['header_height']})
        _check(report, 'pre-turnover explorer snapshot reports the original registry epoch and roster',
               before_view['checkpoint']['registry_epoch'] == '0' and
               before_view['registry']['active_hash'].lower() ==
               delivery['initial_roster_hash'].lower(),
               {'registry_epoch': before_view['checkpoint']['registry_epoch'],
                'active_hash': before_view['registry']['active_hash']})
        _check(report, 'pre-turnover account and studio budget views reflect Raven execution',
               _amount(before_view, payer) == '928' and
               _amount(before_view, raven_tx['body']['op']['to']) == '58' and
               (_budget(before_view, 'studio')['cap'],
                _budget(before_view, 'studio')['spent'],
                _budget(before_view, 'studio')['recorded_remaining']) == ('100', '60', '40'),
               {'payer_balance': _amount(before_view, payer),
                'recipient_balance': _amount(before_view, raven_tx['body']['op']['to']),
                'studio': _budget(before_view, 'studio')})
        _check(report, 'pre-turnover explorer view carries no spending authority',
               before_view['spending_authority'] is False and
               before_view['pending_wallet_debits_included'] is False and
               before_view['latest_state_guaranteed'] is False)
        raven_payments = before_view['payments']
        _check(report, 'pre-turnover view contains only the Raven original payment receipt',
               len(raven_payments) == 1 and
               raven_payments[0]['wire_sha256'] == hashlib.sha256(raven_wire).hexdigest() and
               raven_payments[0]['payer'] == payer and
               raven_payments[0]['units'] == '58' and raven_payments[0]['fee_units'] == '2',
               {'payment_count': len(raven_payments),
                'wire_sha256s': [p['wire_sha256'] for p in raven_payments]})
        _write_new(output / 'raven-explorer-view.json', _json_bytes(before_view))

        # Both proofs are assembled only from public files exported by the old
        # runner. It has already closed and deleted wallet.sqlite/delivery.sqlite.
        atlas_verified = verify_evidence(atlas_evidence, genesis_bytes, policy, now_ns=now_ns)
        capsules = []
        for label, wire in (('raven', raven_wire), ('atlas', atlas_wire)):
            capsule_now_ns = time.time_ns()
            capsule = make_capsule(atlas_evidence, genesis_bytes, policy, wire,
                                   payer=payer, now_ns=capsule_now_ns)
            capsule_bytes = encode_capsule(capsule)
            verified_capsule = verify_capsule(capsule_bytes, genesis_bytes, policy,
                now_ns=capsule_now_ns, expected_payer=payer,
                expected_wire_sha256=hashlib.sha256(wire).hexdigest())
            _check(report, label + ' portable capsule verifies the exact original receipt',
                   verified_capsule['status'] == 'verified-p4-payment-receipt' and
                   verified_capsule['payer'] == payer and
                   verified_capsule['binding']['wire_sha256'] == hashlib.sha256(wire).hexdigest() and
                   verified_capsule['transaction']['body'] == load_json(wire, max_bytes=16384)['body'] and
                   verified_capsule['amount_units'] == ('58' if label == 'raven' else '38') and
                   verified_capsule['fee_units'] == '2' and
                   capsule['policy_id'] == hashlib.sha256(encode(policy)).hexdigest() and
                   'policy' not in capsule and 'now_ns' not in capsule and
                   'checked_at_ns' not in capsule,
                   {'capsule_id': verified_capsule['capsule_id'],
                    'native_txid': verified_capsule['binding']['native_txid'],
                    'receipt_height': verified_capsule['receipt_height'],
                    'state_height': verified_capsule['state_height'],
                    'registry_epoch': verified_capsule['registry_epoch']})
            capsules.append((label, capsule, capsule_bytes, wire, verified_capsule))
            _write_new(output / f'{label}-payment-capsule.json', capsule_bytes)
            _write_new(output / f'{label}-payment-capsule-report.json',
                       _json_bytes(verified_capsule))

        final_wire_hashes = {hashlib.sha256(raven_wire).hexdigest(),
                             hashlib.sha256(atlas_wire).hexdigest()}
        final_payment_view = project_report(atlas_verified, genesis_bytes, policy)
        final_payment_hashes = {p['wire_sha256'] for p in final_payment_view['payments']}
        _check(report, 'post-turnover state contains exactly the two original payment receipts',
               final_wire_hashes == final_payment_hashes and
               len(final_payment_view['payments']) == 2 and
               len([p for p in final_payment_view['payments']
                    if p['wire_sha256'] in final_wire_hashes]) == 2 and
               sorted(p['units'] for p in final_payment_view['payments']) == ['38', '58'],
               {'principal_wire_sha256s': sorted(final_wire_hashes),
                'payment_wire_sha256s': sorted(final_payment_hashes),
                'payment_units': sorted(p['units'] for p in final_payment_view['payments'])})

        final_view_expected = final_payment_view
        _check(report, 'post-turnover explorer snapshot separates state and signed-header heights',
               int(final_view_expected['checkpoint']['header_height']) ==
               int(final_view_expected['checkpoint']['state_height']) + 1,
               {'state_height': final_view_expected['checkpoint']['state_height'],
                'header_height': final_view_expected['checkpoint']['header_height']})
        _check(report, 'post-turnover explorer snapshot shows the replacement epoch and roster',
               final_view_expected['checkpoint']['registry_epoch'] == '1' and
               final_view_expected['registry']['active_hash'].lower() ==
               delivery['replacement_roster_hash'].lower(),
               {'registry_epoch': final_view_expected['checkpoint']['registry_epoch'],
                'active_hash': final_view_expected['registry']['active_hash'],
                'next_hash': final_view_expected['registry']['next_hash']})
        _check(report, 'post-turnover accounts and shared budget conserve the two payments',
               _amount(final_view_expected, payer) == '888' and
               _amount(final_view_expected, raven_tx['body']['op']['to']) == '96' and
               (_budget(final_view_expected, 'studio')['cap'],
                _budget(final_view_expected, 'studio')['spent'],
                _budget(final_view_expected, 'studio')['recorded_remaining']) == ('100', '100', '0') and
               final_view_expected['recorded_supply_units'] == '1000',
               {'payer_balance': _amount(final_view_expected, payer),
                'recipient_balance': _amount(final_view_expected, raven_tx['body']['op']['to']),
                'studio': _budget(final_view_expected, 'studio'),
                'recorded_supply_units': final_view_expected['recorded_supply_units']})
        _check(report, 'post-turnover explorer view remains historical and read-only',
               final_view_expected['spending_authority'] is False and
               final_view_expected['pending_wallet_debits_included'] is False and
               final_view_expected['latest_state_guaranteed'] is False)

        temp = tempfile.TemporaryDirectory(prefix='p4-explorer-receipts-')
        private_root = Path(temp.name)
        store_path = private_root / 'read.sqlite'
        with P4ReadStore(store_path, genesis_bytes, policy, create=True) as store:
            imported = store.import_evidence(atlas_evidence, expected_tip=None)
        _check(report, 'fresh private P4ReadStore accepted final Atlas evidence',
               imported['status'] == 'recorded' and
               imported['state_height'] == atlas_verified['state_height'], imported)
        stored_view = current_view(store_path, genesis_bytes, policy)
        _check(report, 'P4 explorer current_view reverified persisted state',
               _stable_view(stored_view) == _stable_view(final_view_expected),
               {'state_height': stored_view['checkpoint']['state_height'],
                'header_height': stored_view['checkpoint']['header_height']})
        _write_new(output / 'atlas-explorer-view.json', _json_bytes(stored_view))

        httpd = explorer_server(store_path, genesis_bytes, policy, port=0,
                                label='Local P4 engine acceptance')
        http_thread = threading.Thread(target=httpd.serve_forever,
                                       kwargs={'poll_interval': .05}, daemon=True)
        http_thread.start()
        port = httpd.server_port
        _check(report, 'P4 explorer server binds only literal IPv4 loopback',
               httpd.server_address[0] == '127.0.0.1',
               {'host': httpd.server_address[0], 'port': port})
        status, headers, view_raw = _http_get(port, '/api/view')
        served_view = load_json(view_raw)
        _check(report, 'P4 explorer HTTP view is read-only and byte-equivalent to verified current view',
               status == 200 and _stable_view(served_view) == {**_stable_view(stored_view),
                   'label': 'Local P4 engine acceptance'} and
               type(served_view.get('checkpoint', {}).get('checked_at_ns')) is str and
               not any(marker in json.dumps(served_view) for marker in
                       ('"history"', '"headers"', '"envelope"', '"signature"')) and
               headers.get('content-type', '').startswith('application/json'),
               {'http_status': status, 'host': '127.0.0.1', 'port': port})
        status, headers, html = _http_get(port, '/')
        _check(report, 'P4 explorer serves a local UI with no remote asset references',
               status == 200 and len(html) > 0 and b'https://' not in html and
               b'http://' not in html and
               headers.get('content-type', '').startswith('text/html'),
               {'http_status': status, 'html_bytes': len(html)})
        for asset_path, asset_kind in (('/assets/explorer.css', 'text/css'),
                                       ('/assets/explorer.js', 'text/javascript')):
            asset_status, asset_headers, asset_body = _http_get(port, asset_path)
            _check(report, 'P4 explorer serves local ' + asset_path.rsplit('/', 1)[-1],
                   asset_status == 200 and len(asset_body) > 0 and
                   b'https://' not in asset_body and b'http://' not in asset_body and
                   asset_headers.get('content-type', '').startswith(asset_kind),
                   {'http_status': asset_status, 'asset_bytes': len(asset_body)})

        # Tampering with the capsule evidence must fail its independent full
        # P4 replay, even though its outer identity and DB metadata still parse.
        label, sample_capsule, _, sample_wire, sample_verified = capsules[-1]
        tampered = copy.deepcopy(sample_capsule)
        account_rows = tampered['evidence']['state']['native']['accounts']
        account_rows[0][4] += 1
        tamper_rejected = False
        try:
            verify_capsule(tampered, genesis_bytes, policy, now_ns=now_ns,
                           expected_payer=payer,
                           expected_wire_sha256=hashlib.sha256(sample_wire).hexdigest())
        except (ValueError, TypeError, KeyError):
            tamper_rejected = True
        _check(report, 'tampered capsule evidence is refused by standalone verification',
               tamper_rejected)

        # The web capsule route must export the same portable proof builder output
        # for each exact transaction after both source DBs have been removed.
        capsule_route_ids = {}
        for label, capsule, capsule_bytes, wire, verified_capsule in capsules:
            txid = verified_capsule['binding']['native_txid']
            status, headers, body = _http_get(port, '/api/capsule/' + txid)
            route_capsule = load_json(body, max_bytes=len(capsule_bytes) + 1)
            _check(report, label + ' explorer capsule route returns the exact selected proof',
                   status == 200 and encode_capsule(route_capsule) == capsule_bytes and
                   headers.get('content-type', '').startswith('application/json'),
                   {'http_status': status, 'native_txid': txid})
            capsule_route_ids[label] = txid

        # The archive uses its own temporary private DB and reopens it from the
        # exported capsule files; wallet/delivery state is not an input here.
        from p4_receipt_archive import P4ReceiptArchive
        archive_path = private_root / 'archive.sqlite'
        archive_ids = {}
        with P4ReceiptArchive(archive_path, genesis_bytes, policy,
                              now_ns=time.time_ns(), create=True) as archive:
            for label, capsule, capsule_bytes, wire, verified_capsule in capsules:
                expected_wire = hashlib.sha256(wire).hexdigest()
                result = archive.put(capsule, now_ns=time.time_ns(), expected_payer=payer,
                    expected_wire_sha256=expected_wire)
                _check(report, label + ' capsule stored in separate P4 receipt archive',
                       result['status'] == 'stored')
                archive_ids[label] = result['capsule_id']
                duplicate = archive.put(capsule, now_ns=time.time_ns(), expected_payer=payer,
                    expected_wire_sha256=expected_wire)
                _check(report, label + ' archive duplicate is idempotent',
                       duplicate['status'] == 'already_stored' and
                       duplicate['capsule_id'] == archive_ids[label])
            try:
                archive.put(tampered, now_ns=time.time_ns(), expected_payer=payer,
                    expected_wire_sha256=hashlib.sha256(sample_wire).hexdigest())
                archive_tamper_rejected = False
            except (ValueError, TypeError, KeyError):
                archive_tamper_rejected = True
            _check(report, 'receipt archive refuses tampered capsule without replacing records',
                   archive_tamper_rejected)
        with P4ReceiptArchive(archive_path, genesis_bytes, policy,
                              now_ns=time.time_ns(), read_only=True) as archive:
            for label, capsule, capsule_bytes, wire, verified_capsule in capsules:
                expected_wire = hashlib.sha256(wire).hexdigest()
                restored = archive.get(archive_ids[label], now_ns=time.time_ns(),
                    expected_payer=payer, expected_wire_sha256=expected_wire)
                inspected = archive.inspect(archive_ids[label], now_ns=time.time_ns(),
                    expected_payer=payer, expected_wire_sha256=expected_wire)
                _check(report, label + ' archived capsule reopens and reverifies',
                       encode_capsule(restored) == capsule_bytes and
                       inspected['status'] == 'verified-p4-payment-receipt' and
                       inspected['binding']['wire_sha256'] == expected_wire and
                       inspected['binding']['native_txid'] == verified_capsule['binding']['native_txid'],
                       {'capsule_id': archive_ids[label],
                        'native_txid': inspected['binding']['native_txid'],
                        'receipt_height': inspected['receipt_height']})
        report['artifacts'] = {'delivery_output': 'delivery/',
            'raven_explorer_view': 'raven-explorer-view.json',
            'atlas_explorer_view': 'atlas-explorer-view.json',
            'raven_capsule': 'raven-payment-capsule.json',
            'atlas_capsule': 'atlas-payment-capsule.json',
            'wallet_or_delivery_database_packaged': False,
            'private_read_store_or_archive_packaged': False,
            'principal_original_wires': 2,
            'capsule_route_ids': capsule_route_ids}
        report['verified_final_state'] = {'state_height': final_view_expected['checkpoint']['state_height'],
            'header_height': final_view_expected['checkpoint']['header_height'],
            'header_hash': final_view_expected['checkpoint']['header_hash'],
            'registry_epoch': final_view_expected['checkpoint']['registry_epoch'],
            'active_roster_hash': final_view_expected['registry']['active_hash'],
            'payer_balance': _amount(final_view_expected, payer),
            'recipient_balance': _amount(final_view_expected, raven_tx['body']['op']['to']),
            'studio_budget': _budget(final_view_expected, 'studio')}
        report['policy_sha256'] = hashlib.sha256(policy_bytes).hexdigest()
        _check(report, 'original engine genesis and fixed policy bytes remain unchanged',
               (delivery_dir / 'engine-genesis.json').read_bytes() == genesis_bytes and
               (delivery_dir / 'policy.json').read_bytes() == policy_bytes and
               encode(policy) == policy_bytes,
               {'genesis_sha256': genesis_sha256,
                'policy_sha256': report['policy_sha256']})
        report['submission_scope'] = {'original_successful_payments': 2,
            'preexisting_declined_diagnostic_broadcasts':
                delivery.get('diagnostics', {}).get('declined_submissions'),
            'new_signatures_or_submissions_by_this_runner': 0}
        report['status'] = 'passed'
    except BaseException as exc:
        report['status'] = 'failed'
        report['reason'] = f'{type(exc).__name__}: {exc}'
        import traceback
        report['traceback'] = traceback.format_exc().replace(str(ROOT), '<source>').replace(
            str(output), '<output>')
    finally:
        if httpd is not None:
            if http_thread is not None and http_thread.is_alive():
                httpd.shutdown()
            httpd.server_close()
        if http_thread is not None:
            http_thread.join(5)
        if temp is not None:
            temp.cleanup()
        final_source = _source_identity()
        final_engine_sha = hashlib.sha256(binary.read_bytes()).hexdigest() if binary.is_file() else None
        report['source_dirty_after'] = bool(final_source['status'])
        report['source_commit_after'] = final_source['head']
        report['source_tree_after'] = final_source['tree']
        report['source_qualified'] = (not initial_source['status'] and
            not final_source['status'] and initial_source['head'] == final_source['head'] and
            initial_source['tree'] == final_source['tree'])
        report['engine_sha256_after'] = final_engine_sha
        report['engine_unchanged'] = final_engine_sha == report.get('engine_required_sha256')
        final_checks = [
            ('source checkout remains clean at the same commit and tree',
             report['source_qualified'], {'before': initial_source, 'after': final_source}),
            ('pinned engine binary remains unchanged', report['engine_unchanged'],
             {'after_sha256': final_engine_sha}),
            ('no private keys or live databases appear in acceptance output',
             _no_private_artifacts(output), None),
        ]
        for name, passed, details in final_checks:
            report['checks'].append({'name': name, 'passed': bool(passed), 'details': details})
            if not passed:
                report['status'] = 'failed'
                report.setdefault('reason', name)
        report['finished_at_ns'] = time.time_ns()
        (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', required=True)
    parser.add_argument('--engine-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run(args.engine, args.engine_sha256, args.output)
    print(json.dumps({key: result.get(key) for key in
                      ('status', 'reason', 'source_qualified', 'engine_unchanged')}))
    raise SystemExit(0 if result['status'] == 'passed' and
                     result.get('source_qualified') and result.get('engine_unchanged') else 1)
