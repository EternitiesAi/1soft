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
import re
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

def validate_process_receipt(process):
    require(type(process) is dict and type(process.get('returncode')) is int
            and process['returncode']==0 and process.get('timed_out') is False
            and process.get('log_truncated') is False and process.get('cleanup_complete') is True
            and process.get('rescue_actions')==[] and process.get('cleanup_errors')==[]
            and process.get('owned_survivors')==[] and type(process.get('owned_survivor_count')) is int
            and process['owned_survivor_count']==0 and type(process.get('pid')) is int
            and process['pid']>0 and type(process.get('birth')) is str and process['birth']
            and process.get('alive_after') is False, 'outer process outcome/cleanup incomplete')

def validate_envelope(value,profile,source,engine_sha256,process):
    validate_process_receipt(process)
    return scenario_envelope(value,profile,source,engine_sha256)

def scenario_run_id(value):
    run_id=value.get('run_id')
    require(type(run_id) is str and re.fullmatch('[0-9a-f]{32}',run_id),
            'P4 scenario run identity must be 32 lowercase hex characters')
    return run_id

def scenario_envelope(value,profile,source,engine_sha256):
    require(profile in PROFILES,'unknown P4 profile')
    require(type(value) is dict and value.get('schema') == '1soft-protocol4-state-sync-v1'
            and value.get('status') == 'completed-awaiting-external-validation' and value.get('profile') == profile,
            'P4 scenario incomplete')
    scenario_run_id(value)
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
    validate_process_receipt(process)
    return validate_core(value,profile,source,engine_sha256,genesis_bytes,policy,now_ns=now_ns)

def validate_core(value,profile,source,engine_sha256,genesis_bytes,policy,*,now_ns):
    expected=scenario_envelope(value,profile,source,engine_sha256)
    p=policy_checked(policy)
    trust = value['trust_pin']
    require(type(trust) is dict and trust.get('policy') == p
            and trust.get('engine_genesis_sha256') == hashlib.sha256(genesis_bytes).hexdigest()
            and trust.get('native_genesis_sha256') ==
                hashlib.sha256(encode(load_json(genesis_bytes)['app_state'])).hexdigest(),
            'independent genesis/policy pin differs')
    require(type(trust.get('pinned_at_ns')) is int and type(trust.get('target_started_at_ns')) is int
            and trust['pinned_at_ns'] < trust['target_started_at_ns']
            and trust.get('target_never_started') is True, 'target started before trust pin')
    before=trust.get('pre_target')
    require(type(before) is dict and type(before.get('checked_at_ns')) is int
            and before['checked_at_ns'] < trust['pinned_at_ns'] < trust['target_started_at_ns'],
            'trust not independently verified before actual target start')
    verify_evidence(before.get('evidence'),genesis_bytes,p,now_ns=before['checked_at_ns'])
    snapshot, final = value['snapshot_evidence'], value['final_evidence']
    extends(before['evidence'],snapshot)
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
    require(type(install) is dict and install.get('run_id')==value['run_id'] and install.get('height') == sh
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
    validate_processes_and_identities(value,genesis_bytes)
    logs = value['logs']
    require(type(logs) is list and logs and all(type(x) is dict and
            type(x.get('bytes')) is int and x['bytes'] > 0 and x.get('truncated') is False
            and type(x.get('sha256')) is str and len(x['sha256']) == 64
            and x.get('complete') is True and x.get('closed') is True and x.get('fsynced') is True
            and x.get('capture_error') is None for x in logs),
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


def exact_integer(value,low=0):
    return type(value) is int and value>=low

CONTROLLED_ENGINE_CONNECTIONS=('consensus','query','mempool','snapshot')
CONTROLLED_ENGINE_MESSAGE='connection terminated. Did the application crash? Please restart CometBFT'

def validate_controlled_engine_exit(row,profile,killed,initial,run_id,engine_log,socket_path):
    """Only first target engine EOF after the observed deliberate child kill."""
    import re
    cause=row.get('causal_exit')
    require(profile=='final-apply-crash' and row.get('name')=='engine4'
            and row.get('role')=='engine' and type(row.get('returncode')) is int
            and row['returncode']==0 and row.get('stop_requested') is False
            and row.get('termination_signal') is None and row.get('rescue_used') is False
            and row.get('cleanup_error') is None and row.get('alive_after') is False,
            'controlled engine exit role/outcome differs')
    require(type(cause) is dict and set(cause)=={
            'kind','run_id','event_file','event_sha256','child_pid','child_birth',
            'engine_before_kill','kill_requested_at_ns','reaped_at_ns','observed_at_ns',
            'log_name','log_sha256','socket_path'}
            and cause['kind']=='controlled-final-apply-application-kill'
            and cause['event_file']=='control4/killed.json' and cause['log_name']=='engine4.log'
            and all(type(cause[k]) is str and re.fullmatch('[0-9a-f]{64}',cause[k])
                    for k in ('event_sha256','log_sha256')), 'controlled engine cause receipt differs')
    before=cause['engine_before_kill']
    require(type(before) is dict and set(before)=={
            'name','pid','birth','spawned_at_ns','alive','observed_at_ns'}
            and before['alive'] is True
            and all(before.get(k)==row.get(k) for k in ('name','pid','birth','spawned_at_ns'))
            and before==killed.get('engine_before_kill'), 'pre-kill owned engine observation differs')
    require(type(run_id) is str and re.fullmatch('[0-9a-f]{32}',run_id),
            'controlled crash run identity must be 32 lowercase hex characters')
    require(cause['run_id']==run_id==killed.get('run_id')==initial.get('run_id')
            and (cause['child_pid'],cause['child_birth'])==
                (killed.get('pid'),killed.get('birth'))==(initial.get('pid'),initial.get('birth'))
            and type(killed.get('returncode')) is int and killed['returncode']==-9
            and killed.get('signal')=='SIGKILL' and killed.get('stop_requested') is True
            and killed.get('termination_signal')==9 and killed.get('rescue_used') is False
            and killed.get('cleanup_error') is None and initial.get('checkpoint_recovery') is False
            and initial.get('transaction_active') is False, 'controlled final-Apply kill identity differs')
    times=[before.get('spawned_at_ns'),before.get('observed_at_ns'),
           cause['kill_requested_at_ns'],cause['reaped_at_ns'],cause['observed_at_ns']]
    require(all(type(n) is int and n>0 for n in times) and times==sorted(times)
            and times[2]==killed.get('kill_requested_at_ns')
            and times[3]==killed.get('reaped_at_ns') and times[2]-times[1]<=10**9
            and times[3]-times[2]<=5*10**9 and times[4]-times[3]<=10*10**9,
            'controlled engine exit outside observed post-kill window')
    require(type(socket_path) is str and Path(socket_path).is_absolute()
            and str(Path(socket_path))==socket_path and cause['socket_path']==socket_path,
            'controlled engine original target socket differs')
    prefix=r'(?:E\[\d{4}-\d{2}-\d{2}\|\d{2}:\d{2}:\d{2}\.\d{3}\] )?'
    errors=('read message: EOF','read message: read unix @->'+socket_path+
            ': read: connection reset by peer')
    diagnostics=[prefix+re.escape(connection+' '+CONTROLLED_ENGINE_MESSAGE+
        ' module=proxy err='+json.dumps(error,ensure_ascii=False))
        for connection in CONTROLLED_ENGINE_CONNECTIONS for error in errors]
    require(type(engine_log) is str and any(re.fullmatch(pattern,line)
            for line in engine_log.splitlines() for pattern in diagnostics)
            and hashlib.sha256(engine_log.encode()).hexdigest()==cause['log_sha256'],
            'controlled engine original proxy transport-loss diagnostic missing')

def validate_processes_and_identities(value,genesis_bytes):
    import re
    processes=value['processes'];profile=value['profile']
    required=[*('engine'+str(i) for i in range(5)),*('app'+str(i) for i in range(5)),
              'app4-restart','engine4-restart']
    if profile=='final-apply-crash':required+=['engine4-recovery','pause-ready.json','recovery-ready.json']
    require(type(processes) is list and len(processes)==len(required) and
            all(type(x) is dict for x in processes),'owned process membership differs')
    require(sorted(x.get('name','') for x in processes)==sorted(required) and
            len({(x.get('pid'),x.get('birth')) for x in processes})==len(processes),
            'owned role/identity membership differs')
    records={x['name']:x for x in processes}
    cleanup=value.get('service_cleanup',{})
    require(cleanup.get('complete') is True and cleanup.get('rescue_actions')==[]
            and cleanup.get('errors')==[] and cleanup.get('owned_survivors')==[],
            'service cleanup/log failure or rescue')
    for name,row in records.items():
        role=('engine' if name.startswith('engine') else
              'final-apply-pause-child' if name=='pause-ready.json' else
              'recovery-child' if name=='recovery-ready.json' else
              'crash-supervisor' if name=='app4' and profile=='final-apply-crash' else 'app')
        require(row.get('role')==role and exact_integer(row.get('pid'),1) and
                type(row.get('birth')) is str and row['birth'].isdigit() and
                row.get('alive_after') is False and row.get('rescue_used') is False and
                row.get('cleanup_error') is None and type(row.get('stop_requested')) is bool and
                type(row.get('returncode')) is int,'unobserved or rescued process outcome')
        if 'causal_exit' in row:
            validate_controlled_engine_exit(row,profile,value.get('crash',{}).get('killed',{}),
                value.get('crash',{}).get('initial_install',{}),value.get('run_id'),
                value.get('engine_sync',{}).get('original_logs',{}).get(name),
                value.get('crash',{}).get('ready',{}).get('socket'))
        elif role=='final-apply-pause-child':
            require(row['stop_requested'] is True,'deliberate child stop absent')
            killed=value.get('crash',{}).get('killed',{})
            require(row['returncode']==-9 and row.get('termination_signal')==9 and
                    (row['pid'],row['birth'])==(killed.get('pid'),killed.get('birth')),
                    'SIGKILL is not the identified deliberate final-Apply child')
        else:
            require(row['stop_requested'] is True and row.get('termination_signal')==15 and
                    row['returncode'] in ((0,-15) if role=='engine' else (0,)),
                    'unexpected nonzero service exit')
    nodes=value.get('nodes')
    require(type(nodes) is list and len(nodes)==5 and all(type(x) is dict for x in nodes)
            and [x.get('index') for x in nodes]==list(range(5)),'node membership differs')
    engine=load_json(genesis_bytes);initial={base64.b64decode(r['pub_key']['value']).hex()
                                           for r in engine['validators']}
    require(len(initial)==4 and {n.get('validator_public_key') for n in nodes[:4]}==initial
            and nodes[4].get('validator_public_key') not in initial
            and len({n.get('node_id') for n in nodes})==5
            and len({n.get('home_path') for n in nodes})==5
            and len({(n.get('home_device'),n.get('home_inode')) for n in nodes})==5
            and len({n.get('validator_public_key') for n in nodes})==5,'source roster or fresh nonvalidator differs')
    for node in nodes:
        require(type(node.get('node_id')) is str and re.fullmatch('[0-9a-f]{40}',node['node_id'])
                and type(node.get('home_path')) is str and node['home_path'].startswith('/')
                and exact_integer(node.get('home_device')) and exact_integer(node.get('home_inode'),1)
                and all(type(node.get(k)) is str and re.fullmatch('[0-9a-f]{64}',node[k])
                        for k in ('node_key_sha256','validator_key_sha256','validator_public_key')), 'node/home identity malformed')
    trust=value['trust_pin'];sources=trust.get('sources')
    require(type(sources) is list and len(sources)==4 and all(type(x) is dict for x in sources)
            and [x.get('index') for x in sources]==list(range(4)) and
            trust.get('source_pids')==[records['engine'+str(i)]['pid'] for i in range(4)],
            'four source process pins differ')
    for i,entry in enumerate(sources):
        engine_row,app=records['engine'+str(i)],records['app'+str(i)]
        require((entry.get('engine_pid'),entry.get('engine_birth'))==(engine_row['pid'],engine_row['birth'])
                and (entry.get('app_pid'),entry.get('app_birth'))==(app['pid'],app['birth'])
                and exact_integer(entry.get('observed_height'),1),'source PID/birth substituted')
    inventory=trust.get('target_initial_inventory')
    require(type(inventory) is list and inventory and all(type(x) is str for x in inventory)
            and not any('blockstore' in x or 'state.db' in x or 'state.sqlite' in x for x in inventory),
            'target engine/application was previously started')
    restart=value['target_restart'];target=nodes[4]
    require(restart.get('identity_before')==restart.get('identity_after')==target
            and restart.get('home_before')==restart.get('home_after')==target['home_path']
            and type(restart.get('database_before')) is str and restart['database_before'].startswith('/')
            and restart['database_before']==restart.get('database_after')
            and all(exact_integer(restart.get(k)) for k in ('database_device_before','database_device_after'))
            and all(exact_integer(restart.get(k),1) for k in ('database_inode_before','database_inode_after'))
            and restart['database_device_before']==restart['database_device_after']
            and restart['database_inode_before']==restart['database_inode_after']
            and (restart.get('old_pid'),restart.get('old_birth'))==
                (records['app4']['pid'],records['app4']['birth'])
            and (restart.get('new_pid'),restart.get('new_birth'))==
                (records['app4-restart']['pid'],records['app4-restart']['birth']),
            'same-store/home/key/process restart binding differs')
    if profile=='final-apply-crash':
        crash=value['crash']
        require(crash.get('ready',{}).get('socket')==str(Path(restart['database_before']).parent/'a.sock')
                and crash.get('identity_before')==crash.get('identity_after')==target
                and (crash['initial_install']['pid'],crash['initial_install']['birth'])==
                    (records['pause-ready.json']['pid'],records['pause-ready.json']['birth'])
                and (crash['recovered']['pid'],crash['recovered']['birth'])==
                    (records['recovery-ready.json']['pid'],records['recovery-ready.json']['birth']),
                'crash home/key/child identity differs')

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
            killed.get('run_id')==initial.get('run_id')==ready.get('run_id')==value['run_id'] and
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
    probe=crash.get('rollback_probe')
    require(type(probe) is dict and probe.get('kind')=='manual-direct-ABCI-coherent-older-checkpoint',
            'coherent direct ABCI rollback probe missing or mislabelled')
    older=probe.get('evidence')
    older_report=verify_evidence(older,genesis_bytes,policy,now_ns=now_ns)
    extends(older,old)
    require(1<=older_report['state_height']<oh,'rollback probe is not strictly older')
    from protocol4_abci_wire import Request,Response
    request=Request.FromString(b64(probe.get('request')))
    response=Response.FromString(b64(probe.get('response')))
    require(request.WhichOneof('value')=='offer_snapshot' and response.WhichOneof('value')=='offer_snapshot'
            and response.offer_snapshot.result==3,'original older OfferSnapshot refusal absent')
    q=request.offer_snapshot;desc=q.snapshot
    chunks=[b64(x) for x in probe.get('chunks',[])];raw=b''.join(chunks)
    meta=_parse_metadata(bytes(desc.metadata));os=older['state']
    require(desc.format==2 and desc.height==meta['height']==os['height'] and
            desc.chunks==meta['chunks']==len(chunks) and chunks
            and all(len(x)==CHUNK_BYTES for x in chunks[:-1]) and 0<len(chunks[-1])<=CHUNK_BYTES
            and meta['payload_bytes']==len(raw) and bytes(desc.hash)==_hash(raw)
            and q.app_hash.hex()==meta['app_hash']==older_report['app_hash']
            and meta['genesis_sha256']==hashlib.sha256(encode(os['genesis'])).hexdigest(),
            'older descriptor/metadata/hash/trusted AppHash incoherent')
    payload=load_json(raw)
    require(encode(payload)==raw and payload=={'schema':2,'domain':DOMAIN,'genesis':os['genesis'],
            'height':os['height'],'app_hash':os['app_hash'],
            'state':{'native':os['native'],'registry':os['registry']},'history':older['history']},
            'older canonical snapshot differs from independently signed replay')
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

# Only these target control metadata files use the shared write_event codec.
# Its bytes are sorted ASCII JSON plus exactly one newline; financial and
# checkpoint files retain the original newline-free commit_verifier codec.
EVENT_RECEIPTS=frozenset('control4/'+name for name in (
    'installed.json','restart-audited.json','recovered.json','pause-ready.json',
    'killed.json','recovery-ready.json','recovery-exit.json'))

def retained_json(root,name):
    raw=(Path(root)/name).read_bytes()
    event=name in EVENT_RECEIPTS
    item=load_json(raw,max_bytes=4096 if event else 16*1024*1024)
    expected=encode(item)+(b'\n' if event else b'')
    require((not event or type(item) is dict) and expected==raw,
            'noncanonical original receipt: '+name)
    return item

def verify_retained_controlled_engine_exit(value,row,root):
    cause=row['causal_exit']
    require(row['name']=='engine4' and cause['event_file']=='control4/killed.json'
            and cause['log_name']=='engine4.log','retained controlled engine names differ')
    raw=(root/cause['event_file']).read_bytes();killed=retained_json(root,cause['event_file'])
    require(hashlib.sha256(raw).hexdigest()==cause['event_sha256']
            and all(killed.get(k)==value['crash']['killed'].get(k) for k in (
                'run_id','pid','birth','returncode','signal','stop_requested','termination_signal',
                'rescue_used','cleanup_error','engine_before_kill','kill_requested_at_ns','reaped_at_ns')),
            'retained controlled engine kill cause differs')
    event_install=retained_json(root,'control4/installed.json')
    require(killed.get('install')==event_install
            and event_install.get('run_id')==killed.get('run_id')==value['run_id'],
            'retained kill original install event differs')
    ready=retained_json(root,'control4/pause-ready.json')
    app_start=retained_json(root,'process-app4-started.json');argv=app_start.get('argv')
    require(app_start.get('name')=='app4' and app_start.get('role')=='crash-supervisor'
            and type(argv) is list and argv.count('--socket')==1
            and argv.index('--socket')+1<len(argv)
            and cause['socket_path']==ready.get('socket')==
                argv[argv.index('--socket')+1]==str(root/'app4/a.sock')
            and ready.get('run_id')==value['run_id']
            and (ready.get('pid'),ready.get('birth'))==
                (value['crash']['ready'].get('pid'),value['crash']['ready'].get('birth')),
            'retained controlled engine original application socket differs')
    raw_log=(root/cause['log_name']).read_bytes()
    require(hashlib.sha256(raw_log).hexdigest()==cause['log_sha256']
            and raw_log.decode('utf-8')==value['engine_sync']['original_logs'][row['name']],
            'retained controlled engine log differs')
    return True

def verify_retained_proofs(value,root):
    """Bind report fields to the original per-process and filesystem observations."""
    root=Path(root)
    run_id=scenario_run_id(value)
    def original(name):
        return retained_json(root,name)
    fixed=original('trust-pin.json')
    require(fixed=={k:v for k,v in value['trust_pin'].items() if k!='target_started_at_ns'}
            and original('pre-target-evidence.json')==fixed['pre_target']['evidence'],
            'prelaunch original trust/evidence receipt differs')
    require(original('read-policy.json')==fixed['policy'],'original fixed policy differs')
    processes={x['name']:x for x in value['processes']}
    services={n:x for n,x in processes.items() if n not in ('pause-ready.json','recovery-ready.json')}
    for name,row in services.items():
        start=original('process-'+name+'-started.json');exit=original('process-'+name+'-exit.json')
        require(start=={k:row[k] for k in ('name','pid','birth','role','argv','spawned_at_ns')}
                and exit==row,'retained owned PID/birth/start/exit differs')
        if 'causal_exit' in row:
            verify_retained_controlled_engine_exit(value,row,root)
        require(type(row['argv']) is list and all(type(x) is str for x in row['argv'])
                and exact_integer(row['spawned_at_ns'],1),'owned command/start malformed')
        i=int(name[6] if name.startswith('engine') else name[3])
        if name.startswith('engine'):
            argv=row['argv']
            require(len(argv)==4 and argv[1:3]==['start','--home']
                    and argv[3]==value['nodes'][i]['home_path'],'engine home substituted')
        else:
            argv=row['argv']
            require(argv.count('--run-id')==1 and argv.index('--run-id')+1<len(argv)
                    and argv[argv.index('--run-id')+1]==run_id
                    and argv.count('--socket')==1 and argv.index('--socket')+1<len(argv)
                    and argv[argv.index('--socket')+1]==str(root/('app'+str(i))/'a.sock'),
                    'application run identity/socket substituted')
            require('--database' in argv and argv[argv.index('--database')+1]==str(root/('app'+str(i))/'state.sqlite')
                    and '--genesis' in argv and argv[argv.index('--genesis')+1]==str(root/'protocol4-genesis.json'),
                    'application database/genesis substituted')
            if name=='app4' and value['profile']=='final-apply-crash':
                require(argv.count('--crash-engine-start-receipt')==1 and
                        argv[argv.index('--crash-engine-start-receipt')+1]==str(root/'process-engine4-started.json'),
                        'crash engine observation receipt substituted')
            else:
                require('--crash-engine-start-receipt' not in argv,'unexpected crash observation role')
    require(value['trust_pin']['target_started_at_ns']==services['app4']['spawned_at_ns']
            and all(services['app'+str(i)]['spawned_at_ns']<fixed['pinned_at_ns']
                    and services['engine'+str(i)]['spawned_at_ns']<fixed['pinned_at_ns'] for i in range(4)),
            'actual pretarget process times differ')
    log_names=[x['name'] for x in value['logs']]
    require(sorted(log_names)==sorted(n+'.log' for n in services),'complete owned stdout membership differs')
    for i,node in enumerate(value['nodes']):
        require(original('node-'+str(i)+'-initial.json')==node,'initial original node identity differs')
        home=root/'nodes'/('node'+str(i));meta=home.stat()
        require(node['home_path']==str(home) and (node['home_device'],node['home_inode'])==(meta.st_dev,meta.st_ino)
                and hashlib.sha256((home/'config/node_key.json').read_bytes()).hexdigest()==node['node_key_sha256']
                and hashlib.sha256((home/'config/priv_validator_key.json').read_bytes()).hexdigest()==node['validator_key_sha256'],
                'retained engine home/key bytes differ')
    restart=value['target_restart']
    require(original('node-4-ordinary-before.json')==restart['identity_before']
            and original('node-4-ordinary-after.json')==restart['identity_after']
            and restart['database_before']==str(root/'app4/state.sqlite'),'actual ordinary restart observations differ')
    db=(root/'app4/state.sqlite').stat()
    require((restart['database_device_after'],restart['database_inode_after'])==(db.st_dev,db.st_ino),
            'actual retained database replaced')
    def checkpoint(control,event_name,expected):
        event=original(control+'/'+event_name)
        require(event.get('run_id')==run_id,'original checkpoint event run identity differs')
        raw=(root/control/event['record_file']).read_bytes()
        require(hashlib.sha256(raw).hexdigest()==event['record_sha256'] and original(control+'/'+event['record_file'])==expected,
                'original install checkpoint receipt differs')
        return event
    if value['profile']=='basic':
        checkpoint('control4','installed.json',value['install'])
    else:
        crash=value['crash']
        require(original('node-4-crash-restarted.json')==crash['identity_after'],'actual crash home observation differs')
        checkpoint('control4','installed.json',crash['initial_install'])
        checkpoint('control4','restart-audited.json',crash['restart_checkpoint'])
        checkpoint('control4','recovered.json',crash['recovered'])
        for ready_name,exit_name in (('pause-ready.json','killed.json'),('recovery-ready.json','recovery-exit.json')):
            ready=original('control4/'+ready_name);exit=original('control4/'+exit_name);row=processes[ready_name]
            require(ready.get('run_id')==exit.get('run_id')==run_id
                    and ready.get('socket')==str(root/'app4/a.sock')
                    and (ready['pid'],ready['birth'])==(row['pid'],row['birth'])==
                    (exit['pid'],exit['birth']) and all(exit[k]==row[k] for k in
                        ('returncode','stop_requested','termination_signal','rescue_used','cleanup_error')),
                    'actual supervised child birth/exit differs')
        probe=crash['rollback_probe']
        require(original('older-checkpoint-evidence.json')==probe['evidence']
                and (root/'rollback-offer-request.bin').read_bytes()==b64(probe['request'])
                and (root/'rollback-offer-response.bin').read_bytes()==b64(probe['response'])
                and all((root/('rollback-chunk-'+str(i)+'.bin')).read_bytes()==b64(x)
                        for i,x in enumerate(probe['chunks'])),'original coherent rollback packets differ')
    return True

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
    if value.get('schema')=='1soft-protocol4-state-sync-v1':verify_retained_proofs(value,root)
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
