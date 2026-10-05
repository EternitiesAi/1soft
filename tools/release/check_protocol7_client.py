#!/usr/bin/env python3
"""Strict source-bound P7 actual-quorum/real-proof owner/payment client receipt checker."""
import argparse,json,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'scripts'))
from protocol7_treasury import canonical,digest,genesis_document,bootstrap_digest,parse,packet,txid,need,PROFILE,ZERO
from protocol7_worker import Worker
from protocol7_certificate import verify_state
from run_protocol7_client import CHECKS,CLAIMS,SOURCE_NAMES,SOURCE_PREFIXES
from run_protocol7_engine import ENGINE_SHA256
from protocol7_wallet import checked_observation,_resolve,_continuation
FIXTURES={'a','b','rotated_a','reactivated_a','after_rotated_a_revoke_b','revoked_a_b','pre_enroll_a','after_enroll_b','after_a_b','after_b_a','duplicate_request','after_a_revoke_b'}
def load(path):
    raw=Path(path).read_bytes();need(len(raw)<=2*1024*1024 and raw.endswith(b'\n'),'P7 bounded canonical report required')
    v=json.loads(raw);need(canonical(v)+b'\n'==raw,'P7 canonical report bytes');return v
def validate(v,path,worker_binary):
    expected={'format','status','source','checks','claims','inputs','commands','genesis','genesis_sha256','bootstrap_sha256','artifacts','processes','wallet_startup','prepared_at_height','declared_owner_height','owner_record','payment_record','held_obligation','transport','wallet_status'}
    need(type(v) is dict and set(v)==expected and v['format']=='1soft/protocol7-client-engine/v1' and v['status']=='qualified-one-host-certified-owner-payment-client','P7 closed completed report required')
    need(type(v['claims']) is dict and set(v['claims'])==set(CLAIMS) and all(v['claims'][k] is b for k,b in CLAIMS.items()),'P7 unsupported claim')
    checks=v['checks'];need(type(checks) is list and len(checks)==len(CHECKS) and [x.get('id') for x in checks if type(x) is dict]==list(CHECKS)
        and all(type(x) is dict and set(x)=={'id','passed','evidence'} and x['passed'] is True and type(x['evidence']) is dict for x in checks),'P7 check roster incomplete or failed')
    source=v['source'];need(type(source) is dict and set(source)=={'commit','tree','clean','status_porcelain','files'} and source['clean'] is True and source['status_porcelain']=='','P7 executed source was not clean')
    def git(*a):return subprocess.check_output(['git','-C',str(ROOT),*a],stderr=subprocess.DEVNULL)
    for k in ('commit','tree'):need(type(source[k]) is str and re.fullmatch('[0-9a-f]{40}',source[k]) is not None,'P7 Git identity')
    need(git('rev-parse',source['commit']+'^{tree}').decode().strip()==source['tree'],'P7 source tree differs')
    paths=set(SOURCE_NAMES)|{p for p in git('ls-tree','-r','--name-only',source['commit']).decode().splitlines() if p.startswith(SOURCE_PREFIXES)}
    need(type(source['files']) is dict and set(source['files'])==paths,'P7 dependency source coverage differs')
    for rel,row in source['files'].items():
        need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and row['bytes']>=0,'P7 source receipt shape')
        raw=(ROOT/rel).read_bytes();need(raw==git('show',source['commit']+':'+rel) and len(raw)==row['bytes'] and digest(raw)==row['sha256'],'P7 current/committed/executed source differs')
    inputs=v['inputs'];need(type(inputs) is dict and set(inputs)=={'engine','worker','prover','fixtures'},'P7 input roster')
    for n in ('engine','worker','prover'):
        row=inputs[n];need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and 0<row['bytes']<=64*1024*1024,'P7 binary receipt bound')
    need(inputs['engine']['sha256']==ENGINE_SHA256,'P7 engine identity differs')
    need(type(inputs['fixtures']) is dict and set(inputs['fixtures'])==FIXTURES,'P7 twelve actual fixture roster')
    directory=Path(path).with_name(Path(path).name+'.artifacts')
    names={f'app{i}.log' for i in range(4)}|{f'engine{i}.log' for i in range(4)}|{'fixture-'+n+'.tx' for n in FIXTURES}|{'fixture-genesis.json','fixture-enroll-genesis.json','fixture.log','commands.json','bootstrap-genesis.json','owner-record.json','payment-record.json','held-obligation.json'}
    artifacts=v['artifacts'];need(type(artifacts) is list and len(artifacts)==len(names) and {x.get('name') for x in artifacts}==names,'P7 artifact roster differs')
    actual={}
    for row in artifacts:
        need(type(row) is dict and set(row)=={'name','bytes','sha256'} and type(row['bytes']) is int and 0<=row['bytes']<=8*1024*1024,'P7 artifact receipt bound')
        p=directory/row['name'];need(not p.is_symlink() and p.is_file(),'P7 regular raw artifact required')
        raw=p.read_bytes();need(len(raw)==row['bytes'] and digest(raw)==row['sha256'],'P7 actual artifact differs');actual[row['name']]=raw
    for n,sha in inputs['fixtures'].items():need(digest(actual['fixture-'+n+'.tx'])==sha,'P7 actual fixture digest differs')
    g=v['genesis'];need(digest(canonical(g))==v['genesis_sha256'] and bootstrap_digest(g)==v['bootstrap_sha256'],'P7 full/acyclic genesis receipt differs')
    kat=actual['fixture-a.tx']
    w=Worker(worker_binary,g['worker_sha256'],kat);genesis_document(canonical(g),w)
    need(inputs['worker']['sha256']==g['worker_sha256'] and Path(worker_binary).stat().st_size==inputs['worker']['bytes'],'P7 measured worker receipt differs')
    initial=json.loads(actual['fixture-genesis.json']);need(initial==g['treasury'],'P7 initial treasury differs')
    for n in FIXTURES:
        raw=actual['fixture-'+n+'.tx'];need(parse(raw)[1]==g['treasury']['genesis'] and w.verify(raw),'P7 actual fixture proof/domain fails')
    need(actual['commands.json']==canonical(v['commands']) and type(v['commands']) is list and len(v['commands'])==1,'P7 signed command artifacts differ')
    for raw in v['commands']:packet(bytes.fromhex(raw))
    processes=v['processes'];need(type(processes) is list and len(processes)>=11,'P7 process receipts missing');seen=set();roles=set();provers=[]
    for p in processes:
        need(type(p) is dict and set(p)=={'role','node','pid','start_ticks','executable_sha256','exit_code'} and p['role'] in ('engine','application','fixture-prover') and type(p['node']) is int and p['node'] in range(4)
            and type(p['pid']) is int and p['pid']>0 and type(p['start_ticks']) is int and p['start_ticks']>0 and type(p['exit_code']) is int and p['exit_code'] in (0,-15),'P7 complete typed process lifecycle required')
        identity=(p['pid'],p['start_ticks']);need(identity not in seen,'duplicate P7 process identity');seen.add(identity)
        if p['role']=='fixture-prover':provers.append(p);wanted=inputs['prover']['sha256'];need(p['exit_code']==0,'P7 fixture prover failed')
        else:roles.add((p['role'],p['node']));wanted=ENGINE_SHA256 if p['role']=='engine' else source['files']['scripts/serve_abci_p7_admission.py']['sha256']
        need(p['executable_sha256']==wanted,'P7 process executable binding differs')
    need(len(provers)==1 and roles=={(r,i) for r in ('engine','application') for i in range(4)},'P7 exact fixture/four-validator roles missing')
    startup=next(row for row in checks if row['id']=='all_four_initialized')['evidence'];need(set(startup)=={'worker_startup'} and type(startup['worker_startup']) is list and len(startup['worker_startup'])==4,'P7 startup receipts absent')
    need(all(row==w.startup for row in startup['worker_startup']),'P7 KAT/profile/worker startup identity differs')

    need(v['wallet_startup']==w.startup and actual['bootstrap-genesis.json']==canonical(g),'P7 client measured startup/bootstrap differs')
    rawg=canonical(g);owner=bytes.fromhex(v['commands'][0]);payment=actual['fixture-rotated_a.tx'];oldpayment=actual['fixture-a.tx']
    prepared=v['prepared_at_height'];declared=v['declared_owner_height']
    need(type(prepared) is int and 0<prepared<=62 and type(declared) is int and declared==prepared+2 and packet(owner)['body']['height']==declared,'P7 actual future owner height differs')
    probe=next(row for row in checks if row['id']=='future_owner_admission_nonreserving')['evidence']
    need(probe=={'state_height':prepared,'declared_height':declared,'raw_sha256':digest(owner),'check_code':0},'P7 future admission evidence differs')
    probe=next(row for row in checks if row['id']=='early_owner_consensus_refused')['evidence']
    need(probe=={'height':declared-1,'prepared':[],'process_status':2},'P7 early consensus evidence differs')
    observations={}
    keys={'format','genesis','genesis_sha256','profile_sha256','worker_sha256','kat_sha256','bootstrap_sha256','kind','txid','raw','raw_sha256','state_height','receipt','witness','signed_header','certificate'}
    for kind,wire in [('owner',owner),('payment',payment)]:
        record=v[kind+'_record']
        need(type(record) is dict and set(record)==keys and record['format']=='1soft/protocol7-exact-execution-record/v1','P7 client exact typed record shape')
        o,certificate=checked_observation(record['witness'],record['signed_header'],rawg,w);observations[kind]=o
        reason,receipt=_resolve(wire,o,w)
        need(reason=='executed-exact' and record['kind']==kind and record['raw']==wire.hex() and record['raw_sha256']==digest(wire) and record['txid']==txid(wire)
            and record['state_height']==o['witness']['height'] and record['receipt']==receipt and receipt['kind']==kind and record['certificate']==certificate,'P7 client exact signed completion differs')
        expected={'genesis':rawg.hex(),'genesis_sha256':digest(rawg),'profile_sha256':g['profile_sha256'],'worker_sha256':g['worker_sha256'],'kat_sha256':g['kat_sha256'],'bootstrap_sha256':bootstrap_digest(g)}
        need(all(record[k]==value for k,value in expected.items()) and actual[kind+'-record.json']==canonical(record),'P7 client exported record/pins differ')
    _continuation(observations['owner'],observations['payment'])
    before=observations['owner']['witness'];after=observations['payment']['witness']
    need([row['kind'] for row in before['state']['receipts']]==['owner'] and [row['kind'] for row in after['state']['receipts']]==['owner','payment'],'P7 actual owner/payment sequence differs')
    need(before['state']['receipts'][0]['raw']==owner.hex() and before['state']['receipts'][0]['height']==declared and before['state']['receipts'][0]['body']['kind']=='rotate','P7 owner exact future-height execution absent')
    t=after['state']['treasury'];need(t['owner_sequence']==1 and t['fees']==2 and len(t['notes'])==5 and len(t['nullifiers'])==1 and len(t['authority_nullifiers'])==2,'P7 client atomic value evidence differs')
    held=v['held_obligation'];need(type(held) is dict and set(held)=={'txid','raw','status','witness','signed_header'} and held['txid']==txid(oldpayment) and held['raw']==oldpayment.hex(),'P7 stale exact obligation differs')
    need(held['witness']==before and held['signed_header']==observations['owner']['signed_header'] and _resolve(oldpayment,observations['owner'],w)[0]=='rotated-grant','P7 actual rotation/stale certificate differs')
    expectedheld={'txid':txid(oldpayment),'kind':'payment','status':'observed-held','attempts':0,'hold_reason':'rotated-grant','certified_height':before['height']}
    need(held['status']==expectedheld and actual['held-obligation.json']==canonical(held),'P7 unclaimed stale hold improperly changed')
    need(type(v['wallet_status']) is dict and set(v['wallet_status'])=={'owner','payment'},'P7 client status kinds differ')
    for kind,wire in [('owner',owner),('payment',payment)]:
        expected={'txid':txid(wire),'kind':kind,'status':'recorded-certified','attempts':1,'hold_reason':None,'certified_height':after['height']}
        need(v['wallet_status'][kind]==expected,'P7 client exact one-attempt completion status differs')
    transport=v['transport'];need(type(transport) is dict and set(transport)=={'owner','payment'},'P7 client transport kind roster differs')
    for kind,wire in [('owner',owner),('payment',payment)]:
        item=transport[kind]
        need(type(item) is dict and set(item)=={'rpc_returned','response_accepted','response_discarded','calls','delivery','test_injection'} and all(item[k] is True for k in ('rpc_returned','response_accepted','response_discarded'))
            and item['calls']==[digest(wire)] and item['delivery']=={'txid':txid(wire),'outcome':'unknown','attempts':1} and item['test_injection']=='intentional response discard; actual validator submission','P7 client lost-return one-attempt evidence differs')
    return {'qualified':True,'status':v['status'],'check_count':len(CHECKS),'source_commit':source['commit'],'source_tree':source['tree'],'genesis_sha256':digest(rawg),
            'owner_declared_height':declared,'state_height':after['height'],'owner_txid':txid(owner),'payment_txid':txid(payment),'stale_first_claim_refused':True,
            'claim':'one-host finite owner/payment recovery; no freshness/custody/public deployment'}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--worker',type=Path,required=True);a=p.parse_args()
    try:result=validate(load(a.report),a.report,a.worker)
    except Exception as exc:print(json.dumps({'qualified':False,'status':'failed','error':str(exc)},sort_keys=True));return 1
    print(json.dumps(result,sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
