"""Executed registry state under synthetic validator signatures, no live engine."""
import base64
from datetime import datetime,timezone,timedelta
import time
from native_core import public
from commit_verifier import TrustAnchor,encode,header_hash,sha
from validator_sets import ValidatorSet,document_id
from validator_witness import start_witness,extend_witness
from certificate_fixture import make_header
from transition_fixture import sign_header
from registry_rules import APP_VERSION
from registry_fixture import fixture,authorize
from registry_application import RegistryApplication


def history_case(path):
    g,admins,vals,target=fixture();app=RegistryApplication(path,g,create=True)
    initial=ValidatorSet.parse(g['validators']);keymap={public(k):k for k in vals}
    engine={'chain_id':g['chain_id'],'initial_height':'1','app_state':g,'validators':[
        {'address':v.address.hex().upper(),'pub_key':{'type':'tendermint/PubKeyEd25519','value':base64.b64encode(v.public_key).decode()},'power':str(v.power)}
        for v in initial.validators]}
    engine_raw=encode(engine);entries=[];previous=None;responses=[]
    stamp=(time.time_ns()//10**9-60)*10**9
    start=datetime.fromtimestamp(stamp//10**9,timezone.utc)
    try:
        body=app.rules.body(app.state(),{'kind':'schedule','emitted_height':4,'target_validators':target},valid_from=1,valid_until=1)
        raw=authorize(app.rules,body,admins[:3])
        for height in range(1,9):
            txs=[raw] if height==1 else []
            before=app.state();_,result=app.rules.transition(before,txs,height)
            current=ValidatorSet.parse(before['next_validators'])
            following=target if result['next_validators_hash']!=initial.hash else g['validators']
            trust=TrustAnchor(g['chain_id'],current.validators,bytes.fromhex(current.hash),app.rules.genesis_hash,current.total_power)
            h=make_header(trust,height,app.rules.state_hash(before),txs,previous)
            h['version']['app']=str(APP_VERSION);h['next_validators_hash']=result['next_validators_hash'].upper()
            h['time']=(start+timedelta(seconds=height-1)).isoformat().replace('+00:00','Z')
            sh=sign_header(h,current,keymap);previous=sh['commit']['block_id']
            entries.append({'signed_header':sh,'validators':current.json(),'next_validators':following})
            if height<=7:
                response=app.finalize_block(txs,height,header_hash(h));app.commit();responses.append(response)
        p={'schema':1,'format':'1soft/validator-policy/v1','genesis_sha256':sha(engine_raw).hex(),
           'anchor_height':1,'anchor_hash':header_hash(entries[0]['signed_header']['header']).hex(),
           'anchor_time':entries[0]['signed_header']['header']['time'],'trust_period_seconds':3600,'max_clock_drift_seconds':5,
           'expected_block_version':11,'expected_app_version':APP_VERSION}
        now=stamp+60*10**9
        w=start_witness(entries[0],engine_raw,p,now_ns=now)
        w=extend_witness(w,entries[1:],engine_raw,p,expected_parent_sha256=document_id(w),now_ns=now)
        return {'engine_genesis':engine_raw,'genesis':g,'policy':p,'witness':w,'snapshot':app.export_snapshot(),
                'now_ns':now,'responses':responses,'target':target,'signed_action':raw}
    finally:app.close()
