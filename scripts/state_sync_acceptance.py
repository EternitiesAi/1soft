"""Strict local state-sync evidence checks. No authority or recovery implementation.

Shared by the runner and its supplemental matrix. Observations are author-owned
local test data; source/engine pins and signatures do not attest independent hosts.
"""
from __future__ import annotations

import base64
import hashlib
import sqlite3
from pathlib import Path

from block_application import application_hash, restore
from commit_verifier import encode, load_json, pinned_genesis, verify_signed_header
from native_core import canonical


def require(ok, message):
    if not ok:
        raise ValueError(message)


def int_value(value, minimum=0):
    return type(value) is int and minimum <= value <= 2**63-2


def hash_value(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def validate_marker(marker):
    require(type(marker) is dict and set(marker) == {'height', 'app_hash'} and
            int_value(marker['height'], 1) and hash_value(marker['app_hash']), 'invalid bootstrap marker')


def verify_marker_commitment(marker, signed, genesis_bytes):
    validate_marker(marker)
    digest = hashlib.sha256(genesis_bytes).hexdigest()
    trust = pinned_genesis(genesis_bytes, digest)
    verified = verify_signed_header(signed, trust, expected_height=marker['height'] + 1)
    require(verified['app_hash'].lower() == marker['app_hash'], 'signed H+1 commitment differs from installed snapshot')
    return {'genesis_sha256': digest, 'header_height': verified['height'],
            'header_hash': verified['block_hash'].lower(), 'app_hash': marker['app_hash']}


def checkpoint(path):
    """Consistent read of killed/paused application's durable data, without edits."""
    db = sqlite3.connect(Path(path).resolve().as_uri()+'?mode=ro', uri=True, timeout=2)
    try:
        db.execute('BEGIN')
        state = db.execute('SELECT genesis,height,app_hash,state FROM committed WHERE id=1').fetchone()
        marker = db.execute('SELECT height,app_hash FROM state_sync_marker WHERE id=1').fetchone()
        count = db.execute('SELECT count(*) FROM blocks').fetchone()[0]
        require(state is not None and marker is not None, 'snapshot checkpoint unavailable')
        genesis, height, app_hash, native = state
        genesis, native = load_json(genesis.encode()), load_json(native.encode())
        require(marker == (height, app_hash) and count == 0, 'not an untouched snapshot-only checkpoint')
        require(application_hash(genesis, height, native) == app_hash, 'durable snapshot hash differs')
        ledger = restore(genesis, native)
        ledger.close()
        return {'marker': {'height': height, 'app_hash': app_hash}, 'block_rows': 0,
                'native_receipts': len(native['receipts'])}
    finally:
        db.close()


def validate_probe(event, *, mode, run_id, expected_pid=None):
    fields = {'schema','run_id','pid','phase','mode','height','app_hash','checkpoint_recovery','block_rows','socket'}
    require(type(event) is dict and set(event) == fields, 'incomplete install-boundary observation')
    require(type(event['schema']) is int and event['schema'] == 1 and event['run_id'] == run_id and
            event['mode'] == mode and event['phase'] == 'after-durable-install-before-apply-return' and
            int_value(event['pid'], 1) and (expected_pid is None or event['pid'] == expected_pid) and
            int_value(event['height'], 1) and hash_value(event['app_hash']) and
            event['checkpoint_recovery'] is (mode == 'recovery') and
            type(event['block_rows']) is int and event['block_rows'] == 0,
            'install-boundary identity or phase differs')
    require(type(event['socket']) is dict and set(event['socket']) == {'device','inode'} and
            int_value(event['socket']['device']) and int_value(event['socket']['inode'], 1),
            'socket identity missing')


def validate_recovery(value, marker, final_height, run_id):
    validate_marker(marker)
    require(type(value) is dict and set(value) == {'crash','exit_code','durable','recovery','same_node_home',
                                                 'engine_restarted','recovery_retention_flag'}, 'incomplete crash evidence')
    validate_probe(value['crash'], mode='crash', run_id=run_id)
    validate_probe(value['recovery'], mode='recovery', run_id=run_id)
    killed = value['crash']; recovered = value['recovery']
    require(type(value['exit_code']) is int and value['exit_code'] == -9 and
            value['same_node_home'] is True and value['engine_restarted'] is True and
            value['recovery_retention_flag'] is None, 'kill/restart evidence differs')
    require(type(value['durable']) is dict and type(value['durable'].get('block_rows')) is int and
            type(value['durable'].get('native_receipts')) is int, 'durable counts must be exact integers')
    require(value['durable'] == {'marker': {'height': killed['height'], 'app_hash': killed['app_hash']},
                                'block_rows': 0, 'native_receipts': 1}, 'durable killed checkpoint differs')
    require(killed['pid'] != recovered['pid'] and killed['height'] <= recovered['height'] < final_height and
            marker == {'height': recovered['height'], 'app_hash': recovered['app_hash']},
            'restart did not install the reported continuing checkpoint')
    if killed['height'] == recovered['height']:
        require(killed['app_hash'] == recovered['app_hash'], 'same-height snapshot changed')


def validate_history(value, *, final_height, bootstrap, keep, receipt_count):
    require(type(value) is dict and value.get('scope') == 'local_application_block_results', 'history evidence missing')
    a = value.get('availability')
    require(type(a) is dict and final_height - bootstrap > keep, 'history window has not yet pruned')
    expected = {'keep_blocks': keep, 'bootstrap_height': bootstrap, 'pruned_through': final_height - keep,
                'retained_from': final_height - keep + 1, 'retained_through': final_height, 'retained_count': keep}
    require(type(value.get('application_height')) is int and value['application_height'] == final_height and
            all(type(a.get(k)) is int and a[k] == v for k,v in expected.items()) and
            a.get('within_configured_window') is True, 'retained window differs')
    require(value.get('native_receipts_pruned') is False and
            type(value.get('native_receipt_count')) is int and value['native_receipt_count'] == receipt_count and
            type(value.get('cometbft_retain_height')) is int and value['cometbft_retain_height'] == 0 and
            value.get('engine_history_pruning_requested') is False and
            value.get('historical_transaction_absence_proven') is False and
            value.get('total_storage_bounded') is False, 'retention evidence implies changed native history')


def validate_payment_continuation(state, marker, pre_wire, post_wire):
    validate_marker(marker)
    require(type(state) is dict and set(state) == {'genesis','height','app_hash','native'} and
            int_value(state['height'], marker['height'] + 1), 'continued state unavailable')
    require(application_hash(state['genesis'], state['height'], state['native']) == state['app_hash'],
            'continued state AppHash differs')
    ledger = restore(state['genesis'], state['native'])
    ledger.close()
    receipts = state['native']['receipts']
    require(len(receipts) == 2 and pre_wire != post_wire, 'two distinct executed payments required')
    records = [load_json(r[3].encode()) for r in receipts]
    require(canonical(records[0]['envelope']) == pre_wire and canonical(records[1]['envelope']) == post_wire and
            1 <= records[0]['height'] <= marker['height'] < records[1]['height'] <= state['height'],
            'receipt bytes or before/after snapshot ordering differs')
    return [{'txid': r['txid'], 'height': r['height'],
             'wire_sha256': hashlib.sha256(wire).hexdigest()} for r, wire in zip(records, (pre_wire, post_wire))]
