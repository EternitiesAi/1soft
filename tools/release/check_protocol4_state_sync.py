#!/usr/bin/env python3
"""Fail-closed semantic acceptance for private fresh P4 state-sync evidence.

A runner's booleans are necessary bookkeeping, never state or signature authority.
The original private packets are checked before a digest-only public projection.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT/'src'), str(ROOT/'scripts'),
               str(ROOT/'tools/protocol4-client/src'),
               str(ROOT/'tools/validator-transition/src')]
from check_release import require
from commit_verifier import encode, load_json
from p4_evidence import verify_evidence, extends, policy_checked, nanos
from protocol4_application import Protocol4Application
from protocol4_state_sync import FORMAT, DOMAIN, _hash, _parse_metadata, CHUNK_BYTES

PIN = '0.38.25'
ENGINE_SHA256 = '218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024'
CHECK_IDS = ('source-controller-identity','pinned-engine-real-consensus',
'four-sources-fresh-target','external-genesis-fixed-trust','format2-real-abci-transfer',
'engine-trusted-apphash','signed-next-height-native-history','exact-composite-native-effects',
'marker-no-fabricated-blocks','ordinary-payment-continuation','original-policy-current-evidence',
'complete-owned-process-outcomes')
CRASH_IDS = ('durable-commit-before-final-apply-reply','owned-sigkill-observed',
'same-store-home-restart','snapshot-only-restart-audit','actual-checkpoint-reoffer-recovery',
'rollback-refusal-continuation')
PROFILES = ('basic', 'final-apply-crash')

def validate_envelope(value, profile, source, engine_sha256, process):
    require(profile in PROFILES, 'unknown P4 profile')
    require(type(process) is dict and type(process.get('returncode')) is int
            and process['returncode'] == 0 and process.get('timed_out') is False
            and process.get('log_truncated') is False, 'incomplete process')
    require(type(value) is dict and value.get('schema') == '1soft-protocol4-state-sync-v1'
            and value.get('status') == 'passed' and value.get('profile') == profile,
            'P4 scenario incomplete')
    require(value.get('source') == source and value.get('source_dirty_before') is False
            and value.get('source_dirty_after') is False, 'source differs or is dirty')
    require(value.get('engine_sha256') == engine_sha256 and value.get('engine_version') == PIN,
            'engine differs from external pin')
    require(value.get('public_network') is False and value.get('real_funds') is False,
            'unsafe scenario scope')
    expected = list(CHECK_IDS + (CRASH_IDS if profile == 'final-apply-crash' else ()))
    checks = value.get('checks')
    require(type(checks) is list and len(checks) == len(expected)
            and all(type(c) is dict and type(c.get('id')) is str
                    and c.get('passed') is True and 'skipped' not in c for c in checks),
            'missing, skipped, or failed checks')
    require(sorted(c['id'] for c in checks) == sorted(expected), 'check IDs differ')
    for name in ('snapshot_evidence','final_evidence','snapshot_transfer','payments',
                 'target_restart','install','trust_pin','processes','logs'):
        require(name in value, 'original private evidence missing: ' + name)
    if profile == 'final-apply-crash':
        require('crash' in value, 'original crash evidence missing')
    return expected

def b64(value):
    require(type(value) is str, 'base64 text required')
    try: raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc: raise ValueError('invalid base64') from exc
    require(base64.b64encode(raw).decode() == value, 'noncanonical base64')
    return raw

def validate_result(value, profile, source, engine_sha256, process, genesis_bytes, policy, *, now_ns):
    expected = validate_envelope(value, profile, source, engine_sha256, process)
    p = policy_checked(policy)
    trust = value['trust_pin']
    require(type(trust) is dict and trust.get('policy') == p
            and trust.get('engine_genesis_sha256') == hashlib.sha256(genesis_bytes).hexdigest()
            and trust.get('native_genesis_sha256') ==
                hashlib.sha256(encode(load_json(genesis_bytes)['app_state'])).hexdigest(),
            'independent genesis/policy pin differs')
    require(type(trust.get('pinned_at_ns')) is int and type(trust.get('target_started_at_ns')) is int
            and trust['pinned_at_ns'] < trust['target_started_at_ns']
            and trust.get('target_never_started') is True, 'target started before trust pin')
    snapshot, final = value['snapshot_evidence'], value['final_evidence']
    snap_report = verify_evidence(snapshot, genesis_bytes, p, now_ns=now_ns)
    final_report = verify_evidence(final, genesis_bytes, p, now_ns=now_ns)
    extends(snapshot, final)
    sh, fh = snap_report['state_height'], final_report['state_height']
    require(value.get('evidence_origin') == {'state':'target-ABCI-query',
            'headers':'source-engine-RPC','history':'source-blocks-with-target-durable-equality'},
            'mixed evidence origin missing or changes authority')
    final_time = nanos(final['headers'][-1]['signed_header']['header']['time'])
    require(now_ns-300*10**9 <= final_time <= now_ns+p['max_clock_drift_seconds']*10**9,
            'current checkpoint outside original freshness bound')
    engine_log = value.get('engine_sync',{}).get('original_log')
    require(type(engine_log) is str and 'Snapshot restored' in engine_log
            and 'Verified ABCI app' in engine_log, 'engine light-client/application verification absent')
    require(1 <= sh < fh, 'ordinary continuation missing')
    transfer = value['snapshot_transfer']
    require(type(transfer) is dict and type(transfer.get('format')) is int and transfer.get('format') == FORMAT
            and transfer.get('height') == sh and transfer.get('offered_app_hash') == snap_report['app_hash'],
            'wrong format or light-client AppHash')
    chunks = [b64(x) for x in transfer.get('chunks', [])]
    raw = b''.join(chunks)
    metadata = _parse_metadata(b64(transfer.get('metadata')))
    require(chunks and len(chunks) == metadata['chunks'] and
            all(len(c) == CHUNK_BYTES for c in chunks[:-1]) and 0 < len(chunks[-1]) <= CHUNK_BYTES
            and metadata['height'] == sh and metadata['payload_bytes'] == len(raw)
            and metadata['app_hash'] == snap_report['app_hash']
            and transfer.get('hash') == _hash(raw).hex(), 'snapshot chunk identity differs')
    validate_trace(transfer, chunks, crash=profile == 'final-apply-crash')
    payload = load_json(raw)
    require(encode(payload) == raw and payload == {
        'schema':2, 'domain':DOMAIN, 'genesis':snapshot['state']['genesis'],
        'height':sh, 'app_hash':snapshot['state']['app_hash'],
        'state':{'native':snapshot['state']['native'],'registry':snapshot['state']['registry']},
        'history':snapshot['history']}, 'snapshot bytes differ from signed replay')
    require(metadata['genesis_sha256'] == hashlib.sha256(encode(payload['genesis'])).hexdigest(),
            'snapshot genesis metadata differs')
    Protocol4Application._audit_history(payload['genesis'], payload['state'], sh,
                                        payload['app_hash'], payload['history'], strict_txs=True)
    install = value['install']
    require(type(install) is dict and install.get('height') == sh
            and install.get('app_hash') == payload['app_hash'] and install.get('state') == payload['state']
            and install.get('history') == payload['history'] and install.get('marker') ==
                {'height':sh,'app_hash':payload['app_hash']}
            and type(install.get('block_rows')) is int and install.get('block_rows') == 0 and install.get('transaction_active') is False,
            'durable composite checkpoint differs')
    require(value.get('source_final_state') == final['state'] and
            value.get('target_final_state') == final['state'] and
            value.get('source_final_history') == final['history'] and
            value.get('target_final_history') == final['history'], 'source/target composite state differs')
    require(type(value.get('first_target_block')) is int and value['first_target_block'] == sh+1
            and type(value.get('snapshot_response_code')) is int and value.get('snapshot_response_code') == 1 and
            value.get('final_marker') is None, 'snapshot response invented or continuation absent')
    unavailable = value.get('unavailable_responses')
    require(type(unavailable) is list and len(unavailable) == sh
            and all(type(r) is dict and set(r) == {'height','code','log'}
                    and type(r['height']) is int and r['height'] == h
                    and type(r['code']) is int and r['code'] == 1
                    and r['log'] == 'protocol-4 response unavailable'
                    for h,r in enumerate(unavailable,1)), 'historical response refusal evidence differs')
    payments = value['payments']
    require(type(payments) is dict and set(payments) == {'pre','post'}, 'original payment wires missing')
    for phase in ('pre','post'):
        wire = b64(payments[phase]); wh = hashlib.sha256(wire).hexdigest()
        matching = [r for r in final_report['receipts'] if r['wire_sha256'] == wh]
        require(len(matching) == 1, 'original signed payment not independently verified')
        h = matching[0]['height']
        require(h <= sh if phase == 'pre' else sh < h <= fh, 'payment outside expected snapshot phase')
    restart = value['target_restart']
    require(type(restart) is dict and restart.get('database_before') == restart.get('database_after')
            and restart.get('home_before') == restart.get('home_after')
            and restart.get('before') == restart.get('after')
            and restart.get('old_pid') != restart.get('new_pid')
            and all(type(restart.get(k)) is int and restart[k] > 0 for k in ('old_pid','new_pid')),
            'same database/home restart evidence differs')
    restart_evidence = restart.get('evidence')
    require(type(restart_evidence) is dict, 'restart checkpoint signed evidence missing')
    restart_report = verify_evidence(restart_evidence, genesis_bytes, p, now_ns=now_ns)
    require(restart_evidence['state'] == restart['before'], 'restart checkpoint proof differs')
    extends(snapshot, restart_evidence); extends(restart_evidence, final)
    require(sh < restart_report['state_height'] <= fh, 'restart precedes ordinary continuation')
    processes = value['processes']
    require(type(processes) is list and len(processes) >= 10
            and len({(x.get('pid'),x.get('birth')) for x in processes}) == len(processes)
            and all(type(x) is dict and type(x.get('pid')) is int and x['pid'] > 0
                    and type(x.get('birth')) is str and x['birth']
                    and x.get('alive_after') is False and type(x.get('returncode')) is int
                    for x in processes), 'owned process cleanup incomplete')
    logs = value['logs']
    require(type(logs) is list and logs and all(type(x) is dict and
            type(x.get('bytes')) is int and x['bytes'] > 0 and x.get('truncated') is False
            and type(x.get('sha256')) is str and len(x['sha256']) == 64 for x in logs),
            'missing or truncated execution logs')
    methods = transfer.get('methods')
    require(type(methods) is list and set(methods) == {
            'list_snapshots','offer_snapshot','load_snapshot_chunk','apply_snapshot_chunk'},
            'actual format2 ABCI methods absent')
    if profile == 'final-apply-crash':
        validate_crash(value, genesis_bytes, p, now_ns=now_ns)
    return {'check_ids':expected, 'snapshot_height':sh, 'final_height':fh,
            'snapshot_app_hash':snap_report['app_hash'], 'final_app_hash':final_report['app_hash'],
            'snapshot_evidence_id':snap_report['evidence_id'],
            'final_evidence_id':final_report['evidence_id'], 'verified_headers':final_report['verified_headers'],
            'signed_payments':2, 'registry_epoch':final_report['registry_epoch'],
            'public_network_ready':False, 'real_funds_ready':False}



def validate_trace(transfer, chunks, *, crash=False, final_reply_required=True):
    """Decode the saved original P4 ABCI packets; method names cannot stand in."""
    from protocol4_abci_wire import Request, Response
    trace = transfer.get('trace')
    require(type(trace) is list and 4 <= len(trace) <= 2048, 'original ABCI transfer trace missing')
    observed = set(); loaded = set(); applied = set(); listed = False; offered = False; lost_final = False
    desc = {'height':transfer['height'],'format':2,'chunks':len(chunks),
            'hash':transfer['hash'],'metadata':transfer['metadata']}
    def descriptor(s):
        return {'height':s.height,'format':s.format,'chunks':s.chunks,
                'hash':s.hash.hex(),'metadata':base64.b64encode(s.metadata).decode()}
    for row in trace:
        require(type(row) is dict and 'request' in row, 'invalid ABCI trace')
        try:
            request = Request.FromString(b64(row['request']))
            response = None if row.get('response') is None else Response.FromString(b64(row['response']))
        except Exception as exc: raise ValueError('invalid original ABCI packet') from exc
        method = request.WhichOneof('value')
        require(method in {'list_snapshots','offer_snapshot','load_snapshot_chunk','apply_snapshot_chunk'},
                'unsupported method in snapshot trace')
        require(response is None or response.WhichOneof('value') == method, 'ABCI response method differs')
        observed.add(method)
        q = getattr(request,method)
        if method == 'list_snapshots':
            require(response is not None, 'ListSnapshots reply missing')
            listed |= any(descriptor(s) == desc for s in response.list_snapshots.snapshots)
        elif method == 'offer_snapshot':
            if descriptor(q.snapshot) == desc:
                require(q.app_hash.hex() == transfer['offered_app_hash'], 'OfferSnapshot trusted AppHash differs')
                require(response is not None and response.offer_snapshot.result == 1, 'OfferSnapshot refused')
                offered = True
        elif method == 'load_snapshot_chunk':
            if q.height == desc['height'] and q.format == 2:
                require(response is not None and 0 <= q.chunk < len(chunks)
                        and response.load_snapshot_chunk.chunk == chunks[q.chunk], 'LoadSnapshotChunk differs')
                loaded.add(q.chunk)
        elif method == 'apply_snapshot_chunk':
            require(0 <= q.index < len(chunks) and q.chunk == chunks[q.index],
                    'ApplySnapshotChunk differs')
            if response is None:
                require(crash and q.index == len(chunks)-1, 'ApplySnapshotChunk reply missing')
                lost_final = True
            else:
                require(response.apply_snapshot_chunk.result == 1
                        and not response.apply_snapshot_chunk.refetch_chunks
                        and not response.apply_snapshot_chunk.reject_senders, 'ApplySnapshotChunk refused')
                applied.add(q.index)
    require(observed == {'list_snapshots','offer_snapshot','load_snapshot_chunk','apply_snapshot_chunk'}
            and listed and offered and loaded == set(range(len(chunks)))
            and (applied == loaded if final_reply_required else
                 lost_final and applied == set(range(len(chunks)-1))),
            'partial original format2 transfer')


def validate_crash(value,genesis_bytes,policy,*,now_ns):
    crash=value['crash'];initial=crash.get('initial_install',{});recovered=crash.get('recovered',{})
    killed=crash.get('killed',{});ready=crash.get('ready',{})
    old=crash.get('initial_evidence')
    require(type(old) is dict,'initial signed crash checkpoint missing')
    checked=verify_evidence(old,genesis_bytes,policy,now_ns=now_ns)
    extends(old,value['snapshot_evidence'])
    oh=checked['state_height'];nh=value['install']['height']
    require(crash.get('recovery_kind')==('same' if oh==nh else 'newer') and nh>=oh,
            'recovery monotonicity or same/newer label differs')
    expected_state={'native':old['state']['native'],'registry':old['state']['registry']}
    require(initial.get('height')==oh and initial.get('app_hash')==old['state']['app_hash']
            and initial.get('state')==expected_state and initial.get('history')==old['history']
            and initial.get('marker')=={'height':oh,'app_hash':old['state']['app_hash']}
            and type(initial.get('block_rows')) is int and initial['block_rows']==0
            and initial.get('transaction_active') is False and initial.get('checkpoint_recovery') is False,
            'initial durable pre-reply commit differs')
    require(type(killed.get('returncode')) is int and killed['returncode']==-9 and
            killed.get('signal')=='SIGKILL' and killed.get('install')==initial and
            killed.get('pid')==initial.get('pid')==ready.get('pid') and
            killed.get('birth')==initial.get('birth')==ready.get('birth') and
            killed.get('run_id')==initial.get('run_id')==ready.get('run_id') and
            initial.get('socket_device')==ready.get('device') and
            initial.get('socket_inode')==ready.get('inode'), 'owned SIGKILL boundary identity differs')
    require(recovered==value['install'] and recovered.get('checkpoint_recovery') is True
            and recovered.get('pid')!=initial.get('pid') and recovered.get('birth')!=initial.get('birth')
            and recovered.get('run_id')==initial.get('run_id'), 'actual audited recovery install differs')
    fields=('height','app_hash','state','history','marker','block_rows','transaction_active',
            'database_device','database_inode')
    reopened=crash.get('restart_checkpoint',{});rollback=crash.get('rollback_after',{})
    require(all(reopened.get(k)==initial.get(k)==rollback.get(k) for k in fields) and
            recovered.get('database_device')==initial.get('database_device') and
            recovered.get('database_inode')==initial.get('database_inode') and
            type(crash.get('rollback_offer_result')) is int and crash['rollback_offer_result']==3,
            'same-store restart audit or rollback refusal changed committed checkpoint')
    transfer=crash.get('initial_transfer',{})
    chunks=[b64(x) for x in transfer.get('chunks',[])];raw=b''.join(chunks)
    require(transfer.get('height')==oh and transfer.get('format')==2 and
            transfer.get('offered_app_hash')==checked['app_hash'] and transfer.get('hash')==_hash(raw).hex(),
            'initial crash transfer identity differs')
    meta=_parse_metadata(b64(transfer.get('metadata')))
    require(meta['height']==oh and meta['app_hash']==checked['app_hash'] and meta['payload_bytes']==len(raw)
            and meta['chunks']==len(chunks) and all(len(x)==CHUNK_BYTES for x in chunks[:-1]),
            'initial crash chunks differ')
    payload=load_json(raw)
    require(encode(payload)==raw and payload=={'schema':2,'domain':DOMAIN,
            'genesis':old['state']['genesis'],'height':oh,'app_hash':checked['app_hash'],
            'state':expected_state,'history':old['history']}, 'initial lost-reply snapshot bytes differ')
    validate_trace(transfer,chunks,crash=True,final_reply_required=False)

def artifact_manifest(root):
    import os, stat
    root = Path(os.path.abspath(root))
    for parent in (root,*root.parents):
        require(not parent.is_symlink(), 'private output ancestor aliased')
    metadata = root.stat()
    require(os.name=='posix' and stat.S_ISDIR(metadata.st_mode) and metadata.st_uid==os.getuid()
            and not stat.S_IMODE(metadata.st_mode)&0o077, 'private owned POSIX output required')
    records=[];total=0
    for path in sorted(root.rglob('*')):
        require(not path.is_symlink(), 'private artifact aliased')
        meta=path.stat()
        require(meta.st_uid==os.getuid() and not stat.S_IMODE(meta.st_mode)&0o077,
                'private artifact permissions differ')
        if path.is_dir():continue
        require(stat.S_ISREG(meta.st_mode) and meta.st_nlink==1,'private artifact not a regular single-link file')
        relative=path.relative_to(root).as_posix()
        if relative in ('result.json','result.next'):continue
        require(meta.st_size<=64*1024*1024,'private artifact exceeds bound')
        raw=path.read_bytes();total+=len(raw)
        records.append({'path':relative,'mode':format(stat.S_IMODE(meta.st_mode),'04o'),
                        'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
    require(records and len(records)<=4096 and total<=256*1024*1024,'private fixture membership/size bound')
    return records

def verify_private_artifacts(value,root):
    expected=value.get('artifacts')
    require(type(expected) is list and expected==artifact_manifest(root),'original private artifact bytes/membership differ')
    files={x['path']:x for x in expected}
    for log in value.get('logs',[]):
        item=files.get(log.get('name'))
        require(item is not None and item['bytes']==log['bytes'] and item['sha256']==log['sha256'],
                'original stdout/stderr hash differs')
    sync=value.get('engine_sync',{})
    if 'log_names' in sync:
        names=sync['log_names']
        require(type(names) is list and names and all(n in files and n.startswith('engine4') for n in names),
                'target engine log membership differs')
        original=''.join((Path(root)/n).read_bytes().decode('utf-8',errors='replace') for n in names)
        require(original==sync.get('original_log'),'original target engine verification log differs')
    return True

def main():
    import time
    from check_release import source_identity,store_json
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--private-output',type=Path,required=True)
    p.add_argument('--process-receipt',type=Path,required=True)
    p.add_argument('--genesis-sha256',required=True);p.add_argument('--policy-sha256',required=True)
    p.add_argument('--engine',type=Path,required=True);p.add_argument('--engine-sha256',required=True)
    p.add_argument('--profile',choices=PROFILES,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    require(not a.output.exists() and not a.output.is_relative_to(ROOT),'new validation output outside checkout required')
    source=source_identity(ROOT)
    require(a.engine_sha256==ENGINE_SHA256 and a.engine.is_file() and not a.engine.is_symlink()
            and hashlib.sha256(a.engine.read_bytes()).hexdigest()==a.engine_sha256,'actual engine bytes differ')
    original=(a.private_output/'result.json').read_bytes()
    require(0<len(original)<=64*1024*1024,'bounded original private result required')
    value=load_json(original,max_bytes=64*1024*1024)
    require(encode(value)==original,'private result is not canonical original bytes')
    genesis=(a.private_output/'engine-genesis.json').read_bytes()
    policy_raw=(a.private_output/'read-policy.json').read_bytes()
    require(hashlib.sha256(genesis).hexdigest()==a.genesis_sha256 and
            hashlib.sha256(policy_raw).hexdigest()==a.policy_sha256,'external raw genesis/policy pin differs')
    process=load_json(a.process_receipt.read_bytes(),max_bytes=131072)
    verify_private_artifacts(value,a.private_output)
    result=validate_result(value,a.profile,source,a.engine_sha256,process,genesis,load_json(policy_raw),now_ns=time.time_ns())
    require(source_identity(ROOT)==source and hashlib.sha256(a.engine.read_bytes()).hexdigest()==a.engine_sha256,
            'source/engine changed during validation')
    store_json(a.output,{'schema':'1soft-protocol4-state-sync-semantic-check-v1','status':'passed',
        'profile':a.profile,'source_id':source['source_id'],'commit':source['commit'],'tree':source['tree'],
        'engine_sha256':a.engine_sha256,'original_private_result_sha256':hashlib.sha256(original).hexdigest(),
        'process_receipt_sha256':hashlib.sha256(a.process_receipt.read_bytes()).hexdigest(),
        'engine_genesis_sha256':a.genesis_sha256,'policy_sha256':a.policy_sha256,**result})
    print('Original P4 private evidence independently revalidated; public digest result written.')
    return 0
if __name__=='__main__':raise SystemExit(main())
