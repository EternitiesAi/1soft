"""Bounded read-only wallet refresh: collect -> verify headers -> reconcile state.

The endpoint is a source of untrusted bytes only. Genesis and policy are already
pinned in CertifiedWallet. A successful full-state sync may reconcile holds;
header-only progress cannot. No vault, signing, broadcast, payment retry, policy
renewal, database replacement or cross-device authority is offered here.
"""
from __future__ import annotations
import sqlite3

from block_application import restore
from certified_wallet import MAX_ROWS, nanos
from commit_verifier import block_id, encode, load_json, verify_state_witness
from native_core import require
from payment_rpc import endpoint_port
from wallet_catchup import MAX_HEADERS, _snapshot_anchor, progress_anchor
from wallet_refresh_rpc import fetch, MAX_OUTPUT, SNAPSHOT_COMMIT_ATTEMPTS


def _anchor(wallet):
    """Consistent, validated local frontier and clock; never locks during HTTP."""
    wallet.db.execute('BEGIN IMMEDIATE')
    try:
        now = wallet._time_check(None)
        row = wallet.db.execute('SELECT height,clock_ns FROM checkpoint WHERE id=1').fetchone()
        require(row is not None and now >= row[1], 'local clock moved backwards')
        if row[0]:
            anchor = progress_anchor(wallet) or _snapshot_anchor(wallet)
            require(now >= anchor['clock_ns'], 'local clock moved backwards past header progress')
        else:
            require(not wallet.db.execute('SELECT 1 FROM decisions LIMIT 1').fetchone(),
                    'unanchored journal contains signing decisions')
            anchor = None
        wallet.db.execute('COMMIT')
        return anchor
    except BaseException:
        if wallet.db.in_transaction: wallet.db.execute('ROLLBACK')
        raise


def _same(left, right):
    if left is None or right is None:
        return left is right
    return (left['height'] == right['height'] and
            block_id(left['block_id']).SerializeToString() == block_id(right['block_id']).SerializeToString())


def _target(wallet, payload):
    """Validate the full witness BEFORE accepting header progress toward it."""
    raw = encode(payload)
    require(len(raw) <= MAX_OUTPUT, 'target witness too large')
    witness = load_json(raw, max_bytes=MAX_OUTPUT)
    require(type(witness) is dict and set(witness)=={'schema','state','state_commit'} and
            type(witness['schema']) is int and witness['schema']==1, 'invalid target witness')
    state = witness['state']
    cert = verify_state_witness(state, witness['state_commit'], wallet.trust)
    require(cert['height'] >= wallet.policy['minimum_header_height'], 'below policy minimum height')
    wallet._time_check(nanos(witness['state_commit']['header']['time']))
    require(all(type(rows) is list and len(rows) <= MAX_ROWS for rows in state['native'].values()),
            'target exceeds wallet row limit')
    ledger = restore(state['genesis'], state['native'])
    try:
        require(int(dict(ledger.db.execute('SELECT k,v FROM meta'))['height']) <= state['height'],
                'native height exceeds target state')
    finally:
        ledger.close()
    return witness, cert['height']


def refresh_wallet(wallet, endpoint: str, *, max_batches: int = 2,
                   headers_per_batch: int = MAX_HEADERS) -> dict:
    """One explicit finite refresh, not a background follower.

    Capture a target ONCE. Resume from committed header progress on the next call,
    even when a previous call stopped after a successful batch. At most four
    batches (256 headers), one state query, and at most four fixed-height
    commitment reads per call. A still-producing node is
    not chased within the call. If the target ages out, header progress stays but
    only a later fresh full-state sync may reconcile funds.
    """
    require(not wallet.db.in_transaction, 'refresh requires an idle wallet connection')
    endpoint_port(endpoint)
    require(type(max_batches) is int and 1 <= max_batches <= 4, 'max_batches must be 1 through 4')
    require(type(headers_per_batch) is int and 1 <= headers_per_batch <= MAX_HEADERS,
            'headers_per_batch must be 1 through 64')
    report = {'schema':1, 'status':'unavailable', 'state_synced':False,
              'headers_accepted':0, 'batches_committed':0, 'rpc_attempts':0,
              'request_bound':1 + SNAPSHOT_COMMIT_ATTEMPTS + max_batches*headers_per_batch,
              'target_header_height':None,
              'broadcast':False, 'signed':False, 'latest_state_guaranteed':False,
              'scope':'one explicitly requested read-only loopback refresh'}
    def collect(request):
        result = fetch(request)
        # Defensive parent validation; no child success label is financial proof.
        require(type(result) is dict and result.get('status') in ('collected','unavailable','rejected'),
                'invalid worker status')
        require(set(result) == ({'status','rpc_attempts','payload'} if result['status']=='collected'
                                else {'status','rpc_attempts'}), 'unexpected worker fields')
        reads = result.get('rpc_attempts')
        bound = 1 + SNAPSHOT_COMMIT_ATTEMPTS if request['mode']=='snapshot' else request['count']
        require(reads is None or type(reads) is int and 0 <= reads <= bound,
                'invalid worker counts')
        if result['status']=='collected':
            require((type(reads) is int and 2 <= reads <= bound) if request['mode']=='snapshot'
                    else reads == bound, 'incomplete worker counts')
        report['rpc_attempts'] = None if reads is None or report['rpc_attempts'] is None else report['rpc_attempts'] + reads
        return result
    try:
        _anchor(wallet)  # An expired policy or corrupt local frontier forbids I/O.
        found = collect({'mode':'snapshot','endpoint':endpoint})
        if found['status']!='collected':
            report['status'] = found['status']; return report
        witness, target = _target(wallet, found['payload'])
        report['target_header_height'] = target
        current = _anchor(wallet)
        if current is not None and current['height'] > target:
            report['status']='target_behind_wallet'; return report
        if current is None:
            # Initial trust comes from supplied genesis/policy, never discovery.
            # As for the existing offline sync, initial state requires all proofs.
            summary = wallet.sync(witness)
        else:
            for _ in range(max_batches):
                start = _anchor(wallet)
                if start['height'] >= target: break
                count = min(headers_per_batch, target - start['height'])
                chunk = collect({'mode':'headers','endpoint':endpoint,'start':start['height']+1,'count':count})
                if chunk['status']!='collected':
                    report['status']=chunk['status']; return report
                require(type(chunk.get('payload')) is list and len(chunk['payload'])==count,
                        'worker omitted requested headers')
                if not _same(start, _anchor(wallet)):
                    report['status']='concurrent_progress'; return report
                headers = chunk['payload']
                if start['height']+count == target:
                    require(block_id(headers[-1]['commit']['block_id']).SerializeToString() ==
                            block_id(witness['state_commit']['commit']['block_id']).SerializeToString(),
                            'last header differs from captured target block ID')
                # Existing method rechecks EACH signature, height, exact previous
                # block ID, policy/clock and commits only the complete batch.
                wallet.advance_headers(headers)
                report['headers_accepted'] += count
                report['batches_committed'] += 1
            last = _anchor(wallet)
            report['verified_header_height'] = last['height']
            if last['height'] < target:
                report['status']='headers_only'; return report
            if last['height'] > target:
                report['status']='concurrent_progress'; return report
            summary = wallet.sync(witness)  # Rechecks freshness, evidence and ALL holds.
        report.update(status='synced', state_synced=True,
                      state_header_height=summary['state_height']+1,
                      inventory_digest=summary['inventory_digest'],
                      decision_count=summary['decision_count'],
                      pending_account_units=summary['pending_account_units'],
                      pending_budget_units=summary['pending_budget_units'])
        return report
    except (ValueError, KeyError, TypeError, sqlite3.Error):
        # Do not interpolate endpoint-controlled logs into the terminal. Previously
        # committed header batches survive; existing decisions never get deleted.
        report['status']='rejected'
        return report
