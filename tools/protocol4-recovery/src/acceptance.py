"""Validate this test runner's bound observations, never confer release authority."""
from __future__ import annotations
import base64
from block_application import encode
from native_core import digest
from recovery_checks import (need, integer, hex64, sha, validate_state, verify_boundary,
                              verify_replayed_anchor, verify_payment_rows, fingerprint)

PROFILES=('bootstrap-after-turnover','commit-reply-loss-at-emission')

def validate(report, *, source, engine_hash):
    need(type(report) is dict and report.get('schema') == 1 and type(report.get('schema')) is int,
         'invalid acceptance envelope')
    profile=report.get('profile');need(profile in PROFILES, 'unsupported acceptance profile')
    need(report.get('status') == 'passed' and report.get('source') == source and
         report.get('engine_sha256') == hex64(engine_hash) and report.get('engine_version') == '0.38.25',
         'wrong source, engine, or result')
    need(report.get('public_network') is False and report.get('real_funds') is False and
         report.get('release_status') == 'blocked' and report.get('independent_operators') is False,
         'scope of acceptance changed')
    checks=report.get('checks')
    need(type(checks) is list and checks and all(type(c) is dict and c.get('passed') is True for c in checks),
         'incomplete checks')
    names=[c.get('name') for c in checks]
    need(all(type(n) is str and n for n in names) and len(names) == len(set(names)), 'ambiguous check names')
    required={'ordered-payments','dynamic-signed-anchor','matching-source-and-target','post-transition-payment'}
    required |= {'untouched-format2-bootstrap','no-imported-block-evidence','post-snapshot-payment'} if profile==PROFILES[0] else {
        'durable-commit-before-lost-reply','same-store-restart','no-duplicate-emission'}
    need(required.issubset(names), 'missing semantic observations')
    evidence=report['evidence'];g=evidence['genesis'];final=evidence['final_checkpoint'];target=evidence['target_checkpoint']
    need(digest(g) == report['genesis_sha256'] and g.get('protocol_version') == 4 and
         type(g.get('protocol_version')) is int, 'P4 genesis differs')
    validate_state(g,final['state'],final['height'],final['app_hash'],final['history'])
    validate_state(g,target['state'],target['height'],target['app_hash'],target['history'])
    for field in ('height','app_hash','state','history'):
        need(encode(final[field]) == encode(target[field]), 'source and target differ')
    wires=[base64.b64decode(t,validate=True) for t in evidence['payment_wires']]
    need(len(wires) == (3 if profile==PROFILES[0] else 2), 'missing expected payments')
    payments=verify_payment_rows(final['state'],wires)
    checked=verify_replayed_anchor(g,final['history'],final['state'],evidence['signed_headers'],
                                  report['initial_header_hash'],report['observed_at_ns'])
    need(checked == evidence['verified_anchor'], 'anchor summary not derived from evidence')
    registry=final['state']['registry'];integer(registry['epoch'],1,1)
    emission=integer(evidence['emitted_height'],1,508);activation=emission+2
    records=[__import__('json').loads(r[3]) for r in final['state']['native']['receipts']]
    need(records[0]['height'] < emission and records[1]['height'] >= activation,
         'payments do not cross the validator transition')
    need(registry['last_activation_height'] == activation and registry['pending'] is None,
         'transition did not activate')
    if profile==PROFILES[0]:
        boot=evidence['bootstrap_checkpoint'];obs=evidence['bootstrap_observation']
        integer(boot['height'],activation,511)
        validate_state(g,boot['state'],boot['height'],boot['app_hash'],boot['history'])
        need(type(boot.get('local_block_count')) is int and boot['local_block_count']==0 and
             boot.get('latest_block') is None and boot['snapshot_marker'] == {'height':boot['height'],'app_hash':boot['app_hash']},
             'bootstrap imported local block metadata')
        need(type(obs.get('schema')) is int and obs['schema']==1 and obs.get('phase')=='snapshot-installed-before-reply' and
             obs.get('run_id') == report['run_id'] and type(obs.get('pid')) is int and obs['pid']>0 and
             encode(obs.get('checkpoint')) == encode(fingerprint(boot)), 'bootstrap receipt differs')
        need(len(boot['state']['native']['receipts'])==2 and records[2]['height']>boot['height'] and
             boot['history'] == final['history'][:boot['height']], 'post-snapshot payment or replay lineage missing')
        missing=evidence.get('unavailable_blocks')
        need(missing == list(range(1,boot['height']+1)) and all(type(h) is int for h in missing),
             'historical block unavailability not inspected')
        need(target['snapshot_marker'] is None and target['local_block_count']==target['height']-boot['height'],
             'target did not proceed from snapshot into ordinary blocks')
    else:
        crash=evidence['crash'];saved=crash['checkpoint']
        validate_state(g,saved['state'],saved['height'],saved['app_hash'],saved['history'])
        verify_boundary(crash['observation'],saved,run_id=report['run_id'],pid=crash['pid'],height=emission,
                        returncode=crash['returncode'])
        need(saved['history']==final['history'][:emission] and len(saved['state']['native']['receipts'])==1,
             'crash checkpoint not in final chain')
        need(saved['state']['registry']['pending']['phase']=='emitted' and
             saved['latest_block']['result']['validator_updates'], 'crash did not target emission')
        need(type(crash.get('restarted_pid')) is int and crash['restarted_pid']>0 and
             crash['restarted_pid'] != crash['pid'] and crash.get('same_database_inode') is True and
             crash.get('same_engine_identity') is True, 'same-store process restart not observed')
        need(crash['saved_response_after_recovery'] == saved['latest_block']['response_sha256'],
             'emitted full response changed after recovery')
        need(crash['emission_heights'] == [emission] and all(type(h) is int for h in crash['emission_heights']),
             'validator updates duplicated or missing')
    return {'status':'verified-local-acceptance','profile':profile,'height':final['height'],
            'app_hash':final['app_hash'],'receipt_count':payments['receipt_count'],
            'release_status':'blocked','public_network':False,'real_funds':False}
