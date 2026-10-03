"""Explicit P4 incremental proofs under a prospective fixed-horizon policy.

Only a genesis-created replay can authorize a cursor. Serialized cached state,
snapshot markers and peer verification flags are never a continuation authority.
Legacy full-proof formats and their policy semantics are not dispatched here.
"""
from __future__ import annotations

import copy
import hashlib

from block_application import encode
from commit_verifier import block_id, exact, hexbytes, load_json, merkle_root, sha
from development_profile import DURABLE_PROFILE, max_height_for
from native_core import canonical
from protocol4_application import Protocol4Application, Protocol4Replay, MAX_TX_BYTES
from p4_evidence import (content_id, freeze, hash_text, integer, need, p4_genesis)
from validator_witness import nanos, verify_header

POLICY_FORMAT = '1soft/protocol4-read-policy/v2'
SEGMENT_FORMAT = '1soft/protocol4-incremental-segment/v1'
CONTEXT_FORMAT = '1soft/protocol4-authenticated-context/v1'
CHECKPOINT_FORMAT = '1soft/protocol4-incremental-checkpoint/v1'
MAX_SEGMENT_BLOCKS = 64
MAX_SEGMENT_BYTES = 16*1024*1024
MAX_STATE_BYTES = 4*1024*1024
MAX_EXECUTION_RECORDS = 65536
ZERO = '0'*64
HISTORY_DOMAIN = b'1soft/protocol4-incremental-history/v1\0'


def policy_v2_checked(value):
    p=freeze(value,4096)
    exact(p, {'schema','format','genesis_sha256','anchor_height','anchor_hash',
              'anchor_time','trust_period_seconds','max_clock_drift_seconds',
              'expected_block_version','checkpoint_progression','absolute_not_after_ns'},
          'external incremental P4 policy')
    integer(p['schema'],2,2)
    need(p['format']==POLICY_FORMAT and p['checkpoint_progression'] is True,
         'explicit checkpoint progression required')
    hash_text(p['genesis_sha256']);hash_text(p['anchor_hash'])
    integer(p['anchor_height'],1,4097)
    anchor=nanos(p['anchor_time'])
    integer(p['trust_period_seconds'],3600,3600)
    integer(p['max_clock_drift_seconds'],0,60)
    integer(p['expected_block_version'],11,11)
    integer(p['absolute_not_after_ns'],anchor+86400*10**9,anchor+86400*10**9)
    return p


def check_clock(policy,now_ns,previous_ns=None,*,checkpoint=None):
    p=policy_v2_checked(policy);now=integer(now_ns)
    root=nanos(p['anchor_time'])
    base=root if checkpoint is None else integer(checkpoint['lookahead_time_ns'],root)
    expiry=min(base+p['trust_period_seconds']*10**9,p['absolute_not_after_ns'])
    need(root<=now<expiry,'incremental trust interval or fixed horizon expired')
    if previous_ns is not None:
        integer(previous_ns,root)
        need(previous_ns<=now,'stored admission or local clock regressed')
    return expiry


def identity(entry):
    return {'header':entry['signed_header']['header'],
            'block_id':entry['signed_header']['commit']['block_id']}


def history_step(previous,entry,row):
    return hashlib.sha256(HISTORY_DOMAIN+bytes.fromhex(previous)+
        bytes.fromhex(content_id(entry))+bytes.fromhex(content_id(row))).hexdigest()


def checked_segment(value,maximum=MAX_SEGMENT_BYTES):
    s=freeze(value,maximum)
    exact(s,{'schema','format','parent_checkpoint','from_height','state','history','headers'},
          'incremental segment')
    integer(s['schema'],1,1);need(s['format']==SEGMENT_FORMAT,'unsupported incremental segment')
    if s['parent_checkpoint'] is not None:hash_text(s['parent_checkpoint'])
    start=integer(s['from_height'],0,4096)
    state=s['state']
    exact(state,{'genesis','height','app_hash','native','registry'},'incremental composite state')
    height=integer(state['height'],start+1,min(start+MAX_SEGMENT_BLOCKS,4096))
    need(len(encode(state))<=MAX_STATE_BYTES,'bounded incremental state required')
    need(type(s['history']) is list and len(s['history'])==height-start,
         'complete consecutive delta block bodies required')
    need(type(s['headers']) is list and len(s['headers'])==height-start+1,
         'delta and signed lookahead headers required')
    return s


class VerifiedCursor:
    """Owned in-process full-prefix replay, discarded after any failed advance."""
    def __init__(self,genesis_bytes,policy):
        self.policy=policy_v2_checked(policy)
        self.genesis_bytes=bytes(genesis_bytes)
        self.genesis,self.initial=p4_genesis(self.genesis_bytes,self.policy['genesis_sha256'])
        need(self.genesis.get('development_profile')==DURABLE_PROFILE,
             'incremental path requires explicit durable-alpha genesis')
        self.app=Protocol4Replay(self.genesis)
        self.lookahead=None;self.summary=None;self.history_id=ZERO
        self.attempts=[];self.updates=[];self.transitions=[]
        self.anchor_seen=False
        self.successful={}

    def close(self):self.app.close()

    def advance(self,history,headers,*,now_ns,expected_state=None):
        start=self.app.height
        need(type(history) is list and 1<=len(history)<=MAX_SEGMENT_BLOCKS and
             type(headers) is list and len(headers)==len(history)+1,
             'bounded consecutive delta required')
        end=start+len(history)
        integer(end,1,max_height_for(self.genesis))
        summaries=[];previous=None
        hp={'expected_app_version':4,'expected_block_version':self.policy['expected_block_version'],
            'max_clock_drift_seconds':self.policy['max_clock_drift_seconds']}
        # Authenticate all supplied signatures/ancestry BEFORE executing their bodies.
        for offset,entry in enumerate(headers):
            h=start+offset+1
            info=verify_header(entry,self.genesis['chain_id'],hp,now_ns)
            need(info['height']==h,'nonconsecutive incremental header')
            if offset==0 and self.lookahead is not None:
                need(encode(identity(entry))==encode(identity(self.lookahead)),
                     'previous authenticated lookahead identity changed')
            elif h==1:
                need(info['validators_hash']==self.initial.hash,'first roster differs from genesis')
                parent=block_id(entry['signed_header']['header']['last_block_id'],allow_empty=True)
                need(not parent.hash and parent.part_set_header.total==0 and not parent.part_set_header.hash,
                     'height-one header invents earlier block')
            else:
                need(previous is not None,'missing authenticated previous header')
            if previous is not None:
                prior=headers[offset-1]['signed_header']
                need(info['validators_hash']==previous['next_validators_hash'],
                     'unannounced validator roster')
                need(block_id(entry['signed_header']['header']['last_block_id']).SerializeToString()==
                     block_id(prior['commit']['block_id']).SerializeToString(),
                     'complete previous block ID differs')
                need(info['time_ns']>previous['time_ns'],'header timestamp failed to advance')
            if h==self.policy['anchor_height']:
                need(info['block_hash']==self.policy['anchor_hash'] and
                     info['time_ns']==nanos(self.policy['anchor_time']),
                     'independent original anchor differs')
                self.anchor_seen=True
            summaries.append(info);previous=info
        need(self.anchor_seen,'original externally pinned anchor not reached')
        for offset,row in enumerate(history):
            h=start+offset+1
            exact(row,{'height','txs'},'incremental block body')
            integer(row['height'],h,h)
            need(type(row['txs']) is list and len(row['txs'])<=64 and
                 all(type(t) is str and len(t)<=(MAX_TX_BYTES+2)//3*4 for t in row['txs']),
                 'bounded canonical transaction encodings required')
            txs=[Protocol4Application._wire_from_b64(t) for t in row['txs']]
            Protocol4Application._bounds(txs)
            header=headers[offset]['signed_header']['header']
            need(merkle_root([sha(raw) for raw in txs])==hexbytes(header['data_hash'],32,empty=True),
                 'transaction list is not signed block data')
            need(summaries[offset]['app_hash']==self.app.app_hash,
                 'header does not commit prior composite state')
            before_epoch=self.app.state['registry']['epoch']
            after,out=self.app.advance(txs,h)
            need(out['validators_hash']==summaries[offset]['validators_hash'] and
                 out['next_validators_hash']==summaries[offset]['next_validators_hash'],
                 'signed roster schedule differs from authorized registry execution')
            need(out['app_hash']==summaries[offset+1]['app_hash'],
                 'signed next-height hash differs from native and registry execution')
            need(len(self.attempts)+len(txs)<=MAX_EXECUTION_RECORDS,
                 'execution record quota reached; no eviction')
            for index,(raw,result) in enumerate(zip(txs,out['tx_results'])):
                kind='administrative' if 'receipt' in result else ('payment' if result['code']==0 else 'rejected')
                attempt={'height':h,'index':index,'wire_sha256':hashlib.sha256(raw).hexdigest(),
                         'code':result['code'],'kind':kind,'id':result['data']}
                self.attempts.append(attempt)
                if kind=='payment':
                    key=(h,attempt['wire_sha256'],result['data'])
                    need(key not in self.successful,'ambiguous successful native execution')
                    self.successful[key]=attempt
            if out['validator_updates']:
                self.updates.append({'emitted_height':h,'active_height':h+2,'updates':out['validator_updates']})
            if after['registry']['epoch']!=before_epoch:
                self.transitions.append({'height':h,'epoch':after['registry']['epoch'],
                                         'active_hash':after['registry']['active_hash']})
            retained=self.lookahead if offset==0 and self.lookahead is not None else headers[offset]
            self.history_id=history_step(self.history_id,retained,row)
        _,ahead=self.app.rules.transition(self.app.state['registry'],[],end+1)
        need(ahead['validators_hash']==summaries[-1]['validators_hash'] and
             ahead['next_validators_hash']==summaries[-1]['next_validators_hash'],
             'lookahead roster differs from queued registry schedule')
        state={'genesis':self.genesis,'height':end,'app_hash':self.app.app_hash,**self.app.state}
        need(len(encode(state))<=MAX_STATE_BYTES,'authenticated state exceeds profile bound')
        if expected_state is not None:
            need(encode(state)==encode(expected_state),'supplied composite checkpoint differs from replay')
        self.app.audit()
        self.lookahead=copy.deepcopy(headers[-1]);self.summary=summaries[-1]
        return state

    def view(self,checkpoint,*,now_ns,current_authority):
        # The returned view is copied; callers cannot mutate this verified cursor.
        state={'genesis':self.genesis,'height':self.app.height,'app_hash':self.app.app_hash,**self.app.state}
        receipts=[]
        for row in state['native']['receipts']:
            record=load_json(row[3].encode(),max_bytes=32768)
            wire=hashlib.sha256(canonical(record['envelope'])).hexdigest()
            attempt=self.successful.get((record['height'],wire,row[0]))
            need(attempt is not None,'receipt does not name one successful included payment')
            receipts.append({'native_txid':row[0],'receipt_sha256':row[4],'wire_sha256':wire,
                             'height':record['height'],'index':attempt['index'],'record':record})
        accounts=[{'id':r[0],'public_key':r[1],'nonce':r[2],'epoch':r[3],
                   'recorded_balance':str(r[4])} for r in state['native']['accounts']]
        expiry=min(checkpoint['lookahead_time_ns']+3600*10**9,self.policy['absolute_not_after_ns'])
        report={'schema':1,'status':'verified-p4-incremental-state','evidence_id':checkpoint['id'],
            'policy_id':content_id(self.policy),'genesis_sha256':self.policy['genesis_sha256'],
            'state_height':self.app.height,'app_hash':self.app.app_hash,
            'header_height':self.app.height+1,'header_hash':self.summary['block_hash'],
            'verified_headers':self.app.height+1,'registry_epoch':state['registry']['epoch'],
            'registry':state['registry'],'accounts':accounts,'receipts':receipts,
            'attempts':self.attempts,'validator_updates':self.updates,
            'validator_transitions':self.transitions,'grants':state['native']['grants'],
            'budgets':state['native']['budgets'],'grant_budgets':state['native']['grant_budgets'],
            'recorded_supply_units':str(sum(int(a['recorded_balance']) for a in accounts)),
            'trust_expires_ns':expiry,'checked_at_ns':now_ns,
            'native_execution_replayed':True,'registry_authorization_replayed':True,
            'signed_block_inclusion_verified':True,'actual_abci_responses_observed':False,
            'latest_state_guaranteed':False,'pending_wallet_debits_included':False,
            'spending_authority':False,'independent_validator_hosts_verified':False,
            'historical_context':not current_authority}
        context={'format':CONTEXT_FORMAT,'checkpoint_id':checkpoint['id'],'state':state,
                 'lookahead':self.lookahead,'current_authority':current_authority,
                 'policy_id':content_id(self.policy),'store_id':checkpoint['store_id']}
        cp={**checkpoint,'state':state}
        return copy.deepcopy({'report':report,'checkpoint':cp,'context':context})
