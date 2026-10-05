"""P6 static-genesis ordered atomic treasury state; incompatible with P1-P5."""
from __future__ import annotations
import copy, hashlib, importlib.util, re
from pathlib import Path
from protocol5_encoding import canonical_json as canonical, decode_canonical_json, comet_validator_set

ROOT=Path(__file__).resolve().parents[1]
PROFILE_SHA256='4e12c9a2eafd2d4f3e82106ba1128e1fc6301b24b871d30714eb0ca3b93115bd'
_spec=importlib.util.spec_from_file_location('_p6_frozen_treasury_primitives',ROOT/'tools/private-treasury-payment-lab/scripts/ledger.py')
_lab=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_lab)
parse,field,integer,ZERO=_lab.parse,_lab.field,_lab.integer,_lab.ZERO
MAX_HEIGHT=64;MAX_HISTORY=64;MAX_STATE_BYTES=262144;MAX_TX_BYTES=4096
STATE_DOMAIN=b'1soft/protocol6-static-treasury/apphash/v1\0'
TX_DOMAIN=b'1soft/protocol6-static-treasury/transaction/v1\0'
LOGS={0:'',1:'malformed treasury transaction',2:'current treasury authority differs',3:'treasury execution window differs',4:'treasury value anchor differs',5:'treasury replay or duplicate',6:'invalid treasury proof',7:'treasury capacity exceeded'}
class StateError(ValueError):pass
class CapacityError(StateError):pass
def need(condition,message):
    if not condition:raise StateError(message)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def txid(raw):parse(raw);return digest(TX_DOMAIN+raw)
def result(code,data=''):return {'code':code,'log':LOGS[code],'data':data}
def hex32(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None
def genesis_document(raw):
    g=decode_canonical_json(raw,max_bytes=16384)
    need(type(g) is dict and set(g)=={'protocol_version','chain_id','profile_sha256','worker_sha256','kat_sha256','validators','treasury'},'closed P6 genesis required')
    need(type(g['protocol_version']) is int and g['protocol_version']==6,'P6 fresh genesis required')
    need(type(g['chain_id']) is str and re.fullmatch('[a-zA-Z0-9_-]{1,50}',g['chain_id']) is not None,'P6 chain identity')
    need(g['profile_sha256']==PROFILE_SHA256 and digest((ROOT/'tools/private-treasury-payment-lab/PROFILE_V1.json').read_bytes())==PROFILE_SHA256,'frozen treasury profile differs')
    need(hex32(g['worker_sha256']) and g['worker_sha256']!='00'*32 and hex32(g['kat_sha256']) and g['kat_sha256']!='00'*32,'P6 bridge pins')
    _lab.validate_genesis(g['treasury']);need(len(g['treasury']['notes'])==2,'two initial restricted notes required')
    v=g['validators'];need(type(v) is list and len(v)==4,'four P6 validators required')
    for row in v:
        need(type(row) is dict and set(row)=={'public_key','power'} and hex32(row['public_key']) and row['public_key']!='00'*32 and type(row['power']) is int and 1<=row['power']<=1000000,'P6 validator entry')
    keys=[r['public_key'] for r in v]
    need(keys==sorted(keys) and len(set(keys))==4 and len({r['power'] for r in v})==1,'fixed equal-power P6 validator roster')
    comet_validator_set(v)
    return g
def initial_state(g,w):
    need(w.sha256==g['worker_sha256'] and w.kat_sha256==g['kat_sha256'],'P6 worker/genesis pins differ')
    t=copy.deepcopy(g['treasury']);t.update(fees=0,nullifiers=[],authority_nullifiers=[])
    t['anchors']=[w.note_root(t['notes'])]
    return {'version':6,'treasury':t,'receipts':[],'blocks':[]}
def application_hash(g,height,state):
    need(type(height) is int and 0<=height<=MAX_HEIGHT,'P6 height bound')
    raw=canonical({'genesis_sha256':digest(canonical(g)),'height':height,'state':state})
    need(len(canonical(state))<=MAX_STATE_BYTES,'P6 state byte bound')
    return digest(STATE_DOMAIN+raw)
def _attempt(g,s,raw,h,index,w):
    try:p=parse(raw)
    except ValueError:return result(1)
    t=s['treasury'];ident=txid(raw)
    if not integer(p[15])<=h<integer(p[16]):return result(3)
    for i,k in [(1,'genesis'),(2,'asset'),(3,'mission'),(5,'parent_id'),(7,'parent')]:
        if p[i]!=t[k]:return result(2)
    if integer(p[14])!=t['epoch'] or integer(p[17])!=t['fee'] or p[4]!=w.context_root(t):return result(2)
    slot=next((i for i,pair in enumerate(t['grants']) if pair==[p[6],p[8]] and pair[1]!=ZERO),None)
    if slot is None:return result(2)
    if p[20] not in t['anchors']:return result(4)
    if (p[21] in t['nullifiers'] or p[11]==p[12] or any(p[i] in t['authority_nullifiers'] for i in (11,12))
        or any(r['txid']==ident or r['statement'][18]==p[18] for r in s['receipts'])
        or any(p[i] in t['notes'] for i in (22,23))):return result(5)
    if len(t['notes'])+2>16 or len(s['receipts'])>=7 or t['fees']+t['fee']>2**64-1:return result(7)
    if not w.verify(raw):return result(6)
    before_note=t['anchors'][-1];position=len(t['notes'])
    t['parent']=p[9];t['grants'][slot][1]=p[10];t['notes'].extend(p[22:24])
    t['nullifiers'].append(p[21]);t['authority_nullifiers'].extend(p[11:13]);t['fees']+=t['fee']
    after_note=w.note_root(t['notes']);t['anchors'].append(after_note)
    s['receipts'].append({'txid':ident,'raw':raw.hex(),'raw_sha256':digest(raw),'statement':p,'height':h,'tx_index':index,'fee':t['fee'],
        'note_root_before':before_note,'note_root_after':after_note,'authority_root_before':p[4],'authority_root_after':w.context_root(t),
        'merchant_position':position,'change_position':position+1})
    return result(0,ident)
def execute_block(g,state,txs,height,w):
    need(type(state) is dict and set(state)=={'version','treasury','receipts','blocks'} and state['version']==6,'P6 state shape')
    need(type(height) is int and height==len(state['blocks'])+1 and 1<=height<=MAX_HEIGHT,'P6 sequential height required')
    need(type(txs) is list and len(txs)<=2 and all(type(x) is bytes and len(x)<=MAX_TX_BYTES for x in txs),'P6 block bounds')
    count=sum(len(b['transactions']) for b in state['blocks'])+len(txs)
    if count>MAX_HISTORY:raise CapacityError('P6 history exhausted')
    s=copy.deepcopy(state);results=[_attempt(g,s,raw,height,i,w) for i,raw in enumerate(txs)]
    s['blocks'].append({'height':height,'transactions':[r.hex() for r in txs],'results':results})
    if len(canonical(s))>MAX_STATE_BYTES:raise CapacityError('P6 state byte budget exhausted')
    return s,results
def replay(g,state,height,w):
    need(type(state) is dict and set(state)=={'version','treasury','receipts','blocks'} and type(state['blocks']) is list and type(height) is int and len(state['blocks'])==height and 0<=height<=MAX_HEIGHT,'P6 replay shape')
    actual=initial_state(g,w)
    for h,b in enumerate(state['blocks'],1):
        need(type(b) is dict and set(b)=={'height','transactions','results'} and b['height']==h and type(b['transactions']) is list,'P6 history block shape')
        txs=[]
        for v in b['transactions']:
            need(type(v) is str and len(v)<=MAX_TX_BYTES*2,'P6 history transaction bound')
            try:r=bytes.fromhex(v)
            except ValueError:raise StateError('P6 history transaction encoding') from None
            need(r.hex()==v,'P6 canonical history transaction')
            txs.append(r)
        actual,_=execute_block(g,actual,txs,h,w)
    need(canonical(actual)==canonical(state),'P6 replayed state or receipts differ')
    return actual
