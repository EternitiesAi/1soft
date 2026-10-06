#!/usr/bin/env python3
"""Closed independent public execution replay; encrypted disclosures remain undecrypted."""
import argparse,json,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'scripts'))
from protocol7_treasury import canonical,digest,bootstrap_digest,genesis_document,parse,txid,need,PROFILE,PROFILE_SHA256,field
from protocol7_worker import Worker
from protocol7_certificate import verify_state
from protocol7_wallet import checked_observation,_resolve
from run_protocol7_merchant import CHECKS,CLAIMS,SOURCE_NAMES
from protocol7_merchant import MerchantBook
from protocol7_vault import ORIGIN_KEYS
from run_protocol7_engine import SOURCE_PREFIXES,ENGINE_SHA256

FIXTURES={'a','b','rotated_a','reactivated_a','after_rotated_a_revoke_b','revoked_a_b',
          'pre_enroll_a','after_enroll_b','after_a_b','after_b_a','duplicate_request','after_a_revoke_b'}
def load(path):
    raw=Path(path).read_bytes()
    need(len(raw)<=2*1024*1024 and raw.endswith(b'\n'),'P7 bounded report required')
    v=json.loads(raw);need(canonical(v)+b'\n'==raw,'P7 canonical report required');return v
def validate(v,path,worker_binary):
    keys={'format','status','source','checks','claims','inputs','commands','genesis','genesis_sha256',
          'bootstrap_sha256','prepared_public','prepared_wire','prepared_txid','prover_run',
          'transport','record','artifacts','processes','controller_runs','cli_commands','quotes','inspections',
          'encrypted_disclosure','lost_result','recovered_result','restart'}
    need(type(v) is dict and set(v)==keys and v['format']=='1soft/protocol7-merchant-engine/v1'
         and v['status']=='qualified-one-host-merchant-fulfillment','P7 closed completed merchant report required')
    need(type(v['claims']) is dict and set(v['claims'])==set(CLAIMS)
         and all(v['claims'][k] is b for k,b in CLAIMS.items()),'P7 prover unsupported claim')
    checks=v['checks']
    need(type(checks) is list and len(checks)==len(CHECKS) and [c.get('id') for c in checks if type(c) is dict]==list(CHECKS)
         and all(set(c)=={'id','passed','evidence'} and c['passed'] is True and type(c['evidence']) is dict for c in checks),
         'P7 prover check roster failed')
    need(checks[0]['evidence']=={'candidate':False},'P7 prover candidate is not qualification')
    source=v['source']
    need(type(source) is dict and set(source)=={'commit','tree','clean','status_porcelain','files'}
         and source['clean'] is True and source['status_porcelain']=='','P7 clean executed source required')
    def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args],stderr=subprocess.DEVNULL)
    for k in ('commit','tree'):
        need(type(source[k]) is str and re.fullmatch('[0-9a-f]{40}',source[k]) is not None,'P7 source identity')
    need(git('rev-parse',source['commit']+'^{tree}').decode().strip()==source['tree'],'P7 source tree differs')
    names=set(SOURCE_NAMES)|{p for p in git('ls-tree','-r','--name-only',source['commit']).decode().splitlines() if p.startswith(SOURCE_PREFIXES)}
    need(type(source['files']) is dict and set(source['files'])==names,'P7 prover dependency coverage differs')
    for name,row in source['files'].items():
        need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int,'P7 source row')
        raw=(ROOT/name).read_bytes()
        need(raw==git('show',source['commit']+':'+name) and len(raw)==row['bytes'] and digest(raw)==row['sha256'],
             'P7 current/committed/executed source differs')
    inputs=v['inputs']
    need(type(inputs) is dict and set(inputs)=={'engine','worker','fixture_prover','prover','request_fixture','controller'},'P7 binary roster')
    for row in inputs.values():
        need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int
             and 0<row['bytes']<=64*1024*1024 and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None,'P7 binary identity')
    need(inputs['engine']['sha256']==ENGINE_SHA256,'P7 engine identity differs')
    directory=Path(path).with_name(Path(path).name+'.artifacts')
    names={f'app{i}.log' for i in range(4)}|{f'engine{i}.log' for i in range(4)}|{'fixture-'+n+'.tx' for n in FIXTURES}|{'fixture-genesis.json','fixture-enroll-genesis.json','fixture.log','commands.json','merchant-disclosure-encrypted.json'}
    rows=v['artifacts'];need(type(rows) is list and len(rows)==len(names) and {r.get('name') for r in rows}==names,'P7 raw artifact roster differs')
    artifacts={}
    for r in rows:
        need(type(r) is dict and set(r)=={'name','bytes','sha256'} and type(r['bytes']) is int and 0<=r['bytes']<=8*1024*1024,'P7 artifact row')
        p=directory/r['name'];need(p.is_file() and not p.is_symlink(),'P7 regular artifact required')
        raw=p.read_bytes();need(len(raw)==r['bytes'] and digest(raw)==r['sha256'],'P7 raw artifact differs')
        artifacts[r['name']]=raw
    need(v['commands']==[] and artifacts['commands.json']==canonical([]),'P7 unexpected owner command')
    g=v['genesis'];rawg=canonical(g)
    worker=Worker(worker_binary,inputs['worker']['sha256'],artifacts['fixture-a.tx'])
    need(Path(worker_binary).stat().st_size==inputs['worker']['bytes'],'P7 worker size differs')
    genesis_document(rawg,worker)
    need(g['worker_sha256']==inputs['worker']['sha256'] and digest(rawg)==v['genesis_sha256']
         and bootstrap_digest(g)==v['bootstrap_sha256'],'P7 genesis pins differ')
    need(json.loads(artifacts['fixture-genesis.json'])==g['treasury'],'P7 fixture treasury differs')
    wire=bytes.fromhex(v['prepared_wire']);public=parse(wire)
    need(public==v['prepared_public'] and txid(wire)==v['prepared_txid'] and worker.verify(wire)
         and public[1]==g['treasury']['genesis'],'P7 arbitrary proof differs')
    need(all(public!=parse(artifacts['fixture-'+n+'.tx']) for n in FIXTURES),'P7 proof is still a fixed fixture statement')
    run=v['prover_run']
    need(type(run) is dict and set(run)=={'pid','start_ticks','exit_code','binary_sha256','request_bytes','response_bytes'}
         and type(run['pid']) is int and run['pid']>0 and type(run['exit_code']) is int and run['exit_code']==0
         and type(run['start_ticks']) is int and run['start_ticks']>0
         and run['binary_sha256']==inputs['prover']['sha256'] and run['request_bytes']==2088 and run['response_bytes']==4168,
         'P7 measured prover completion missing')
    record=v['record']
    record_keys={'format','genesis','genesis_sha256','profile_sha256','worker_sha256','kat_sha256','bootstrap_sha256',
                 'kind','txid','raw','raw_sha256','state_height','receipt','witness','signed_header','certificate'}
    need(type(record) is dict and set(record)==record_keys and record['format']=='1soft/protocol7-exact-execution-record/v1'
         and record['kind']=='payment','P7 exact record shape')
    o,certificate=checked_observation(record['witness'],record['signed_header'],rawg,worker)
    reason,receipt=_resolve(wire,o,worker)
    need(reason=='executed-exact' and canonical(record['receipt'])==canonical(receipt) and canonical(record['certificate'])==canonical(certificate)
         and type(record['state_height']) is int
         and record['state_height']==o['witness']['height'] and record['raw']==wire.hex()
         and record['raw_sha256']==digest(wire) and record['txid']==txid(wire),'P7 exact quorum completion differs')
    pins={'genesis':rawg.hex(),'genesis_sha256':digest(rawg),'bootstrap_sha256':bootstrap_digest(g),
          **{k:g[k] for k in ('profile_sha256','worker_sha256','kat_sha256')}}
    need(all(record[k]==value for k,value in pins.items()),'P7 exported pins differ')
    state=o['witness']['state'];need(len(state['receipts'])==1 and state['receipts'][0]['raw']==wire.hex()
          and state['treasury']['fees']==2 and len(state['treasury']['notes'])==5
          and len(state['treasury']['nullifiers'])==1,'P7 native payment effect differs')
    t=v['transport']
    need(type(t) is dict and set(t)=={'rpc_returned','response_accepted','response_discarded','calls','delivery'}
         and all(t[k] is True for k in ('rpc_returned','response_accepted','response_discarded'))
         and t['calls']==[digest(wire)] and t['delivery']=={'txid':txid(wire),'outcome':'unknown','attempts':1},
         'P7 lost return one-attempt evidence differs')
    evidence={c['id']:c['evidence'] for c in checks}
    need(evidence['certificate_only_refused']=={'refusal':'P7 exact certified merchant payment required'} and
         evidence['wrong_quote_refused']=={'refusal':'P7 certified payment differs from retained quote'} and
         evidence['five_opening_mutations_refused']=={'refusals':{k:'P7 merchant opening commitment mismatch' for k in
             ('recipient','payment','payment_blind','payment_expiry','payment_note_secret')}} and
         evidence['helper_unavailable_refused']=={'injected':True,'failure_class':'unavailable'} and
         evidence['actual_fulfillment_lost_return']=={'actual_cli_returned':True,'application_return_discarded':True,'application_outcome':'unknown'} and
         evidence['read_only_inspection_unchanged']=={'api_main_wal_shm_bytes_unchanged':True,'actual_cli_rows_unchanged':True} and
         evidence['immutable_origin_conflict_refused']=={'refusal':'P7 merchant certified exact execution required'} and
         evidence['wrong_key_and_ciphertext_refused']=={'wrong_key_refusal':'P7 merchant key authentication refused',
             'ciphertext_refusal':'P7 merchant disclosure authentication refused','synthetic_store_mutation':True},
         'P7 merchant causal refusal/read-only evidence differs')
    quotes=v['quotes'];need(type(quotes) is dict and set(quotes)=={'original','other'},'P7 exact quote roster')
    adapter=object.__new__(MerchantBook);adapter.g=g;adapter.raw_genesis=rawg
    original=quotes['original'];core=original['core']
    adapter.book_id=core['book_id'];adapter.namespace=core['merchant_namespace'];adapter.recipient=core['recipient']
    for q in quotes.values():
        need(type(q) is dict and set(q)=={'core','request','quote_sha256'},'P7 closed quote response')
        request,_=adapter._quote(q['core'])
        need(request==q['request'] and q['quote_sha256']==digest(canonical(q['core'])),'P7 exact quote-derived request')
    need(public[18]==original['request']!=quotes['other']['request'] and core['resource']!=quotes['other']['core']['resource'] and
         all(core[k]==quotes['other']['core'][k] for k in ('amount','recipient','payment_expiry','grant_id','generation','valid_from','valid_until')),
         'P7 different resource/same payment terms quote test differs')
    from protocol7_treasury import integer
    need(public[6]==core['grant_id'] and integer(public[26])==core['generation'] and integer(public[28])==core['owner_epoch'] and
         integer(public[15])==core['valid_from'] and integer(public[16])==core['valid_until'],'P7 public quote domains differ')
    expected_result=adapter._result(core,record)
    need(canonical(v['lost_result'])==canonical(v['recovered_result'])==canonical(expected_result),'P7 exact durable local resource result differs')
    inspections=v['inspections'];need(type(inspections) is list and len(inspections)==3,'P7 inspection roster differs')
    for i,row in enumerate(inspections):
        expected={'request':original['request'],'quote_sha256':original['quote_sha256'],
                  'status':'quoted' if i==0 else 'fulfilled','txid':None if i==0 else txid(wire),
                  'result_sha256':None if i==0 else digest(canonical(expected_result)),
                  'latest_state_established':False,'retry_authorized':False,'external_delivery_established':False,
                  'merchant_note_redemption_established':False}
        need(type(row) is dict and set(row)==set(expected) and all(row[k]==expected[k] and type(row[k]) is type(expected[k]) for k in expected),
             'P7 closed exact read-only inspection differs')
    encrypted=artifacts['merchant-disclosure-encrypted.json'];d=json.loads(encrypted)
    need(canonical(d)==encrypted and type(d) is dict and set(d)=={'format','pins','request','origin_sha256','nonce','ciphertext'} and
         d['format']=='1soft/protocol7-merchant-disclosure-envelope/v1' and d['request']==original['request'] and
         d['origin_sha256']==digest(canonical(record)) and v['encrypted_disclosure']=={'bytes':len(encrypted),'sha256':digest(encrypted)},
         'P7 encrypted disclosure artifact identity differs')
    expected_pins={'format':'1soft/protocol7-merchant-book/v1','book_id':adapter.book_id,'merchant_namespace':adapter.namespace,
        'recipient':adapter.recipient,'genesis_sha256':digest(rawg),'bootstrap_sha256':bootstrap_digest(g),
        'profile_sha256':g['profile_sha256'],'worker_sha256':inputs['worker']['sha256'],'kat_sha256':g['kat_sha256'],
        'controller_sha256':inputs['controller']['sha256'],'parameter_sha256':PROFILE['parameter_sha256'],
        'verifying_key_sha256':PROFILE['verifying_key_sha256']}
    need(canonical(d['pins'])==canonical(expected_pins),'P7 encrypted disclosure pins differ')
    from protocol7_treasury import hexbytes
    hexbytes(d['nonce'],12)
    ct=d['ciphertext'];need(type(ct) is str and len(ct)%2==0 and 32<len(ct)<=2048,'P7 encrypted disclosure bound')
    hexbytes(ct,len(ct)//2)
    restart=v['restart'];need(type(restart) is dict and set(restart)=={'witness','signed_header','certificate',
        'store_before','store_after','old_application_pid','old_engine_pid','new_application_pid','new_engine_pid'},'P7 restart shape')
    _,restart_cert=checked_observation(restart['witness'],restart['signed_header'],rawg,worker)
    need(canonical(restart['certificate'])==canonical(restart_cert) and restart['witness']['state']['receipts']==state['receipts'] and
         restart['witness']['state']['treasury']==state['treasury'] and restart['witness']['state']['blocks'][:len(state['blocks'])]==state['blocks'],
         'P7 restarted authenticated full state differs')
    need(canonical(restart['witness'])!=canonical(record['witness']) and
         evidence['valid_recertification_conflict_refused']=={'refusal':'P7 immutable merchant origin conflict',
             'new_state_height':restart['witness']['height'],'original_state_height':record['state_height']},
         'P7 distinct valid recertification immutable conflict differs')
    sr=restart['store_before']
    need(type(sr) is dict and set(sr)=={'device','inode','uid','mode'} and all(type(x) is int for x in sr.values()) and
         sr==restart['store_after'] and sr['mode']==0o600 and sr['inode']>0,'P7 restart exact private store differs')
    processes=v['processes'];need(type(processes) is list and 12<=len(processes)<=240,'P7 merchant lifecycle bound')
    seen=set();roles=set();byrole={r:[] for r in ('fixture-prover','arbitrary-prover','note-controller','merchant-cli')}
    for p in processes:
        need(type(p) is dict and set(p)=={'role','node','pid','start_ticks','executable_sha256','exit_code'} and
             p['role'] in ('engine','application',*byrole) and type(p['node']) is int and p['node'] in range(4) and
             type(p['pid']) is int and p['pid']>0 and type(p['start_ticks']) is int and p['start_ticks']>0 and
             type(p['exit_code']) is int and p['exit_code'] in (0,-15),'P7 complete process row required')
        ident=(p['pid'],p['start_ticks']);need(ident not in seen,'P7 duplicate process');seen.add(ident)
        if p['role'] in byrole:
            byrole[p['role']].append(p);need(p['exit_code']==0,'P7 helper generation failed')
            if p['role']=='merchant-cli':want=source['files']['scripts/owner_treasury_merchant.py']['sha256']
            else:want=inputs[{'fixture-prover':'fixture_prover','arbitrary-prover':'prover','note-controller':'controller'}[p['role']]]['sha256']
        else:
            roles.add((p['role'],p['node']));want=ENGINE_SHA256 if p['role']=='engine' else source['files']['scripts/serve_abci_p7_admission.py']['sha256']
        need(p['executable_sha256']==want,'P7 process identity differs')
    need(len(byrole['fixture-prover'])==len(byrole['arbitrary-prover'])==1 and len(byrole['merchant-cli'])==5 and
         roles=={(r,i) for r in ('engine','application') for i in range(4)},'P7 four-validator/prover/caller coverage')
    need(byrole['arbitrary-prover'][0]['pid']==run['pid'] and byrole['arbitrary-prover'][0]['start_ticks']==run['start_ticks'],
         'P7 actual arbitrary prover identity differs')
    for role in ('application','engine'):
        old,new=restart['old_'+role+'_pid'],restart['new_'+role+'_pid']
        need(type(old) is int and type(new) is int and old!=new and
             all(any(p['role']==role and p['node']==3 and p['pid']==pid for p in processes) for pid in (old,new)),
             'P7 real same-store replacement process coverage')
    cr=v['controller_runs'];need(type(cr) is list and 1<=len(cr)<=128 and len(cr)==len(byrole['note-controller']),'P7 merchant native helper coverage')
    for row,p in zip(cr,byrole['note-controller']):
        need(type(row) is dict and set(row)=={'operation','pid','start_ticks','exit_code','binary_sha256','request_bytes','response_bytes'} and
             row['operation'] in ('construct','merchant') and row['request_bytes']==(2088 if row['operation']=='construct' else 1256) and
             all(type(row[k]) is int for k in ('request_bytes','response_bytes','pid','start_ticks','exit_code')) and
             row['response_bytes']==(2088 if row['operation']=='construct' else 32) and row['pid']==p['pid'] and
             row['start_ticks']==p['start_ticks'] and row['exit_code']==0 and row['binary_sha256']==inputs['controller']['sha256'],
             'P7 measured closed merchant projection differs')
    cli=v['cli_commands'];operations=('quote','enroll','fulfill','fulfill','inspect')
    need(type(cli) is list and len(cli)==len(operations),'P7 merchant caller roster differs')
    cli_runs=[]
    for reply,op in zip(cli,operations):
        need(type(reply) is dict and set(reply)=={'format','status','operation','result'} and
             reply['format']=='1soft/protocol7-merchant-command-result/v1' and reply['status']=='completed-local-command' and
             reply['operation']==op and type(reply['result']) is dict,'P7 closed actual merchant response differs')
        result=dict(reply['result']);execution=result.pop('execution',None)
        need(type(execution) is dict and set(execution)=={'note_controller'} and type(execution['note_controller']) is list,
             'P7 merchant caller native execution evidence missing')
        cli_runs.extend(execution['note_controller'])
        expected=original if op=='quote' else ({'request':original['request'],'txid':txid(wire),'quote_sha256':original['quote_sha256']} if op=='enroll' else
                  (expected_result if op=='fulfill' else inspections[-1]))
        need(canonical(result)==canonical(expected) and set(result)==set(expected),'P7 actual merchant result differs')
    need(cr[-len(cli_runs):]==cli_runs and all(r['operation']=='merchant' for r in cli_runs),'P7 actual caller projection records differ')
    return {'qualified':True,'status':v['status'],'check_count':len(CHECKS),'source_commit':source['commit'],
        'genesis_sha256':digest(rawg),'txid':txid(wire),'state_height':o['witness']['height'],
        'public_execution_independently_replayed':True,'encrypted_disclosure_independently_decrypted':False,
        'claim':'exact certified public payment independently replayed; private disclosure checked in measured local run, no public redemption/deployment'}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--worker',type=Path,required=True);a=p.parse_args()
    try:result=validate(load(a.report),a.report,a.worker)
    except Exception as exc:
        print(json.dumps({'qualified':False,'error':str(exc)},sort_keys=True));return 1
    print(json.dumps(result,sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
