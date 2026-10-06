#!/usr/bin/env python3
"""Closed source/artifact/actual quorum replay; ciphertext is not independently decrypted."""
import argparse,json,re,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'scripts'))
from protocol7_treasury import canonical,digest,bootstrap_digest,genesis_document,application_hash,parse,txid,need,PROFILE,PROFILE_SHA256,field,integer,numfield,ZERO
from protocol7_worker import Worker
from protocol7_wallet import checked_observation,_resolve
from protocol7_certificate import verify_state
from protocol7_vault import ENVELOPE
from run_protocol7_reconciliation import CHECKS,CLAIMS,SOURCE_NAMES
from run_protocol7_engine import SOURCE_PREFIXES,ENGINE_SHA256
from check_protocol7_prover import FIXTURES,load

def validate_restart_metadata(r,processes,rawg):
    keys={'format','node','before','after','observed','signed_header','certificate','before_store','after_store',
          'old_application','application','engine','latest_state_guaranteed'}
    need(type(r) is dict and set(r)==keys and r['format']=='1soft/protocol7-authenticated-restart/v1'
         and type(r['node']) is int and r['node']==3 and r['latest_state_guaranteed'] is False,'P7 closed authenticated restart required')
    for name in ('before','after','observed'):
        s=r[name]
        need(type(s) is dict and set(s)=={'genesis','height','app_hash','state'} and canonical(s['genesis'])==rawg
             and type(s['height']) is int and 0<=s['height']<64 and type(s['state']) is dict
             and set(s['state'])=={'version','treasury','receipts','blocks'} and type(s['state']['version']) is int and s['state']['version']==7
             and type(s['state']['blocks']) is list and len(s['state']['blocks'])==s['height']
             and application_hash(s['genesis'],s['height'],s['state'])==s['app_hash'],'P7 restart full state identity differs')
    before=r['before'];after=r['after']
    need(canonical(r['observed'])==canonical(after) and after['height']>=before['height']
         and canonical(after['state']['blocks'][:before['height']])==canonical(before['state']['blocks'])
         and all(b['transactions']==[] and b['results']==[] for b in after['state']['blocks'][before['height']:])
         and canonical({**after['state'],'blocks':after['state']['blocks'][:before['height']]})==canonical(before['state']),
         'P7 restart full checkpoint differs')
    store=r['before_store']
    need(type(store) is dict and set(store)=={'device','inode','uid','mode'}
         and all(type(x) is int and x>=0 for x in store.values()) and store['inode']>0 and store['mode']==0o600
         and r['after_store']==store,'P7 restart same private store differs')
    matched={}
    for name,role in (('old_application','application'),('application','application'),('engine','engine')):
        p=r[name];need(type(p) is dict and set(p)=={'pid','start_ticks'} and all(type(x) is int and x>0 for x in p.values()),'P7 restart process reference')
        rows=[row for row in processes if row['role']==role and row['node']==3 and all(row[k]==p[k] for k in p)]
        need(len(rows)==1,'P7 restart measured process missing');matched[name]=rows[0]
    need(matched['application']['start_ticks']>matched['old_application']['start_ticks']
         and matched['engine']['start_ticks']>=matched['application']['start_ticks'],'P7 replacement application/engine order differs')
    cert=r['certificate'];need(type(cert) is dict and cert.get('state_height')==after['height']
         and cert.get('header_height')==after['height']+1 and cert.get('app_hash')==after['app_hash'],
         'P7 restart certificate metadata differs')
    return r

def validate(v,path,worker_binary):
    keys={'format','status','source','checks','claims','inputs','commands','records','transports','prover_runs',
          'genesis','genesis_sha256','bootstrap_sha256','imported_note','vault_inventory','vault_ciphertext',
          'controller_runs','artifacts','processes','cli_commands','preparation_statuses','restart'}
    need(type(v) is dict and set(v)==keys and v['format']=='1soft/protocol7-preparation-reconciliation-engine/v2'
         and v['status']=='qualified-one-host-preparation-reconciliation','P7 closed completed custody report required')
    need(type(v['claims']) is dict and set(v['claims'])==set(CLAIMS)
         and all(v['claims'][k] is b for k,b in CLAIMS.items()),'P7 custody unsupported claim')
    checks=v['checks']
    need(type(checks) is list and len(checks)==len(CHECKS) and [c.get('id') for c in checks if type(c) is dict]==list(CHECKS)
         and all(set(c)=={'id','passed','evidence'} and c['passed'] is True and type(c['evidence']) is dict for c in checks),
         'P7 custody check roster failed')
    need(checks[0]['evidence']=={'candidate':False},'P7 custody candidate is not qualification')
    evidence={c['id']:c['evidence'] for c in checks}
    need(evidence['spent_input_and_duplicate_refused']=={'refusal':'P7 change spent/anchor refused'},'P7 actual spent-input guard evidence differs')
    need(evidence['revoked_grant_refused_before_proving']=={'refusal':'P7 change generation/epoch/grant refused','prover_calls':0},
         'P7 active-grant guard evidence differs')
    need(evidence['missing_retained_source_refused']=={'refusal':'P7 retained source request absent or ambiguous','prover_calls':0},
         'P7 missing retained source guard differs')
    need(evidence['stale_retained_authority_refused']=={'refusal':'P7 retained authority continuity refused','prover_calls':0},
         'P7 stale retained source guard differs')
    need(evidence['authenticated_handoff_race_refused']=={'authenticated_advance':'third','handoffs':1,
         'prover_calls':0,'ciphertext_unchanged':True,'refusal':'P7 change spent/anchor refused'},'P7 authenticated handoff race evidence differs')
    source=v['source']
    need(type(source) is dict and set(source)=={'commit','tree','clean','status_porcelain','files'}
         and source['clean'] is True and source['status_porcelain']=='','P7 clean executed source required')
    def git(*args):return subprocess.check_output(['git','-C',str(ROOT),*args],stderr=subprocess.DEVNULL)
    for k in ('commit','tree'):need(type(source[k]) is str and re.fullmatch('[0-9a-f]{40}',source[k]) is not None,'P7 source identity')
    need(git('rev-parse',source['commit']+'^{tree}').decode().strip()==source['tree'],'P7 source tree differs')
    names=set(SOURCE_NAMES)|{p for p in git('ls-tree','-r','--name-only',source['commit']).decode().splitlines() if p.startswith(SOURCE_PREFIXES)}
    need(type(source['files']) is dict and set(source['files'])==names,'P7 custody dependency coverage differs')
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
    names={f'app{i}.log' for i in range(4)}|{f'engine{i}.log' for i in range(4)}|{'fixture-'+n+'.tx' for n in FIXTURES}|{'fixture-genesis.json','fixture-enroll-genesis.json','fixture.log','commands.json','vault-encrypted.json'}
    rows=v['artifacts'];need(type(rows) is list and len(rows)==len(names) and {r.get('name') for r in rows}==names,'P7 custody raw artifact roster differs')
    artifacts={}
    for r in rows:
        need(type(r) is dict and set(r)=={'name','bytes','sha256'} and type(r['bytes']) is int and 0<=r['bytes']<=8*1024*1024,'P7 artifact row')
        p=directory/r['name'];need(p.is_file() and not p.is_symlink(),'P7 regular artifact required')
        raw=p.read_bytes();need(len(raw)==r['bytes'] and digest(raw)==r['sha256'],'P7 raw artifact differs');artifacts[r['name']]=raw
    need(type(v['commands']) is list and len(v['commands'])==2 and artifacts['commands.json']==canonical(v['commands']),'P7 owner command roster differs')
    processes=v['processes'];need(type(processes) is list and 12<=len(processes)<=256,'P7 custody lifecycle bound')
    identities=set();roles=set();byrole={r:[] for r in ('fixture-prover','arbitrary-prover','note-controller','custody-cli')}
    for p in processes:
        need(type(p) is dict and set(p)=={'role','node','pid','start_ticks','executable_sha256','exit_code'}
             and p['role'] in ('engine','application',*byrole) and type(p['node']) is int and p['node'] in range(4)
             and type(p['pid']) is int and p['pid']>0 and type(p['start_ticks']) is int and p['start_ticks']>0
             and type(p['exit_code']) is int and p['exit_code'] in (0,-15),'P7 complete process row required')
        ident=(p['pid'],p['start_ticks']);need(ident not in identities,'P7 duplicate process');identities.add(ident)
        if p['role'] in byrole:
            byrole[p['role']].append(p);need(p['exit_code']==0,'P7 helper generation failed')
            if p['role']=='custody-cli':want=source['files']['scripts/owner_treasury_custody.py']['sha256']
            else:
                name={'fixture-prover':'fixture_prover','arbitrary-prover':'prover','note-controller':'controller'}[p['role']]
                want=inputs[name]['sha256']
        else:
            roles.add((p['role'],p['node']));want=ENGINE_SHA256 if p['role']=='engine' else source['files']['scripts/serve_abci_p7_admission.py']['sha256']
        need(p['executable_sha256']==want,'P7 process identity differs')
    need(len(byrole['fixture-prover'])==1 and len(byrole['arbitrary-prover'])==3 and len(byrole['custody-cli'])==8
         and roles=={(r,i) for r in ('engine','application') for i in range(4)},'P7 four-validator/prover coverage')
    restart=validate_restart_metadata(v['restart'],processes,canonical(v['genesis']))
    need(evidence['same_store_restart_converges']=={'node':3,'full_state':True,'signed_next_header':True,'same_store':True},
         'P7 full authenticated restart evidence differs')
    runs=v['prover_runs'];need(type(runs) is list and len(runs)==3,'P7 three arbitrary proofs required')
    for run,p in zip(runs,byrole['arbitrary-prover']):
        need(type(run) is dict and set(run)=={'pid','start_ticks','exit_code','binary_sha256','request_bytes','response_bytes'}
             and run['pid']==p['pid'] and run['start_ticks']==p['start_ticks'] and run['exit_code']==0
             and run['binary_sha256']==inputs['prover']['sha256'] and run['request_bytes']==2088 and run['response_bytes']==4168,
             'P7 measured prover completion differs')
    cr=v['controller_runs'];need(type(cr) is list and 1<=len(cr)<=192 and len(cr)==len(byrole['note-controller']),'P7 note controller coverage')
    for run,p in zip(cr,byrole['note-controller']):
        need(type(run) is dict and set(run)=={'operation','pid','start_ticks','exit_code','binary_sha256','request_bytes','response_bytes'}
             and run['operation'] in ('derive','construct') and type(run['request_bytes']) is int
             and run['request_bytes'] in (2088,*range(2122,2603,32)) and run['response_bytes']==(256 if run['operation']=='derive' else 2088)
             and run['pid']==p['pid'] and run['start_ticks']==p['start_ticks'] and run['exit_code']==0
             and run['binary_sha256']==inputs['controller']['sha256'],'P7 measured note completion differs')
    cli=v['cli_commands']
    need(type(cli) is list and len(cli)==8,'P7 actual custody caller roster differs')
    cli_runs=[]
    status_keys={'format','status','input','request','source_txid','vault_revision','as_of_height','as_of_app_hash',
                 'txid','raw_sha256','attempts','hold_reason','completed_at','latest_state_guaranteed',
                 'in_flight_state_known','retry_authorized','automatic_retry'}
    statuses=v['preparation_statuses']
    labels=('stage_without_wire','second_retained','second_attempted','second_certified','third_certified')
    need(type(statuses) is dict and set(statuses)==set(labels),'P7 reconciliation snapshot roster')
    for status in statuses.values():
        need(type(status) is dict and set(status)==status_keys and status['format']=='1soft/protocol7-preparation-status/v1'
             and all(status[k] is False for k in ('latest_state_guaranteed','in_flight_state_known','retry_authorized','automatic_retry')),
             'P7 closed reconciliation snapshot/authority flags differ')
    operations=('prepare','inspect-prepared','recover-prepared','inspect-prepared','inspect-prepared',
                'prepare-retained','recover-prepared','inspect-prepared')
    for reply,operation,proof_index in zip(cli,operations,(1,None,None,None,None,2,None,None)):
        need(type(reply) is dict and set(reply)=={'format','status','operation','result'}
             and reply['format']=='1soft/protocol7-custody-command-result/v1' and reply['status']=='completed-local-command'
             and reply['operation']==operation,'P7 actual custody caller response differs')
        result=reply['result']
        keys=status_keys|{'execution'} if operation=='inspect-prepared' else {'txid','raw_sha256','execution'}|({'request','attempts'} if proof_index is not None else set())
        need(type(result) is dict and set(result)==keys,'P7 closed public custody response required')
        execution=result['execution'];ekeys={'note_controller'}|({'prover'} if proof_index is not None else set())
        need(type(execution) is dict and set(execution)==ekeys and type(execution['note_controller']) is list
             and all(r in cr for r in execution['note_controller']),'P7 caller controller lifecycle differs')
        cli_runs.extend(execution['note_controller'])
        if proof_index is not None:need(execution['prover']==runs[proof_index] and result['attempts']==0,'P7 caller actual prepare completion differs')
    for index,label in zip((1,3,4,7),labels[1:]):
        need({k:x for k,x in cli[index]['result'].items() if k!='execution'}==statuses[label],
             'P7 actual caller reconciliation binding differs')
    need(len(cli_runs)==len({(r['pid'],r['start_ticks']) for r in cli_runs}) and len(cli_runs)>0,'P7 caller controller lifecycle duplicates')
    g=v['genesis'];rawg=canonical(g);inv=v['vault_inventory'];vc=v['vault_ciphertext']
    need(type(inv) is dict and set(inv)=={'vault_id','revision','notes','retained_preparations'}
         and inv['revision']==5 and type(inv['notes']) is list and len(inv['notes'])==3
         and type(inv['retained_preparations']) is list and len(inv['retained_preparations'])==2,'P7 bounded immutable custody history differs')
    need(type(inv['vault_id']) is str and re.fullmatch('[0-9a-f]{64}',inv['vault_id']) is not None,'P7 vault ID')
    ciphertext=artifacts['vault-encrypted.json'];envelope=json.loads(ciphertext)
    need(type(vc) is dict and set(vc)=={'bytes','sha256','header'} and vc['bytes']==len(ciphertext) and vc['sha256']==digest(ciphertext)
         and type(envelope) is dict and set(envelope)=={'header','ciphertext'} and canonical(envelope)==ciphertext
         and envelope['header']==vc['header'],'P7 encrypted artifact binding differs')
    h=vc['header'];pins={'format':ENVELOPE,'vault_id':inv['vault_id'],'genesis_sha256':digest(rawg),
                       'bootstrap_sha256':bootstrap_digest(g),'profile_sha256':PROFILE_SHA256,
                       'parameter_sha256':PROFILE['parameter_sha256'],'verifying_key_sha256':PROFILE['verifying_key_sha256'],
                       'worker_sha256':inputs['worker']['sha256'],'kat_sha256':g['kat_sha256'],'controller_sha256':inputs['controller']['sha256']}
    need(type(h) is dict and set(h)==set(pins)|{'revision','nonce'} and h['revision']==5 and all(h[k]==b for k,b in pins.items())
         and type(h['nonce']) is str and re.fullmatch('[0-9a-f]{24}',h['nonce']) is not None
         and type(envelope['ciphertext']) is str and re.fullmatch('[0-9a-f]{32,4194336}',envelope['ciphertext']) is not None
         and len(envelope['ciphertext'])%2==0,'P7 closed ciphertext pins differ')
    # No key is supplied: this checker checks canonical ciphertext/pins only.
    # Runtime custody tests and the actual trace check decryption/opening use.
    worker=Worker(worker_binary,inputs['worker']['sha256'],artifacts['fixture-a.tx'])
    need(Path(worker_binary).stat().st_size==inputs['worker']['bytes'],'P7 worker size differs');genesis_document(rawg,worker)
    need(g['worker_sha256']==inputs['worker']['sha256'] and digest(rawg)==v['genesis_sha256']
         and bootstrap_digest(g)==v['bootstrap_sha256'] and json.loads(artifacts['fixture-genesis.json'])==g['treasury'],'P7 genesis pins differ')
    need(verify_state(restart['after'],restart['signed_header'],rawg,worker)==restart['certificate'],
         'P7 independently replayed restart certificate differs')
    records=v['records'];need(type(records) is dict and set(records)=={'first','other_revoke','second','third','active_revoke'},'P7 exact execution roster')
    observations={};wires={};public={}
    rkeys={'format','genesis','genesis_sha256','profile_sha256','worker_sha256','kat_sha256','bootstrap_sha256',
           'kind','txid','raw','raw_sha256','state_height','receipt','witness','signed_header','certificate'}
    for label in ('first','other_revoke','second','third','active_revoke'):
        r=records[label];kind='payment' if label in ('first','second','third') else 'owner'
        need(type(r) is dict and set(r)==rkeys and r['format']=='1soft/protocol7-exact-execution-record/v1' and r['kind']==kind,'P7 exact record shape')
        wire=bytes.fromhex(r['raw']);o,cert=checked_observation(r['witness'],r['signed_header'],rawg,worker)
        reason,receipt=_resolve(wire,o,worker)
        need(reason=='executed-exact' and r['receipt']==receipt and r['certificate']==cert and r['state_height']==o['witness']['height']
             and r['raw_sha256']==digest(wire) and r['txid']==txid(wire),'P7 exact certified execution differs')
        rpins={'genesis':rawg.hex(),'genesis_sha256':digest(rawg),'bootstrap_sha256':bootstrap_digest(g),**{k:g[k] for k in ('profile_sha256','worker_sha256','kat_sha256')}}
        need(all(r[k]==b for k,b in rpins.items()),'P7 exact execution pins differ')
        observations[label]=o['witness'];wires[label]=wire
        if kind=='payment':
            public[label]=parse(wire);need(worker.verify(wire),'P7 actual proof refused')
    first=public['first'];second=public['second'];third=public['third'];note=v['imported_note']
    need(all(reply['result']['txid']==records[label]['txid'] and reply['result']['raw_sha256']==digest(wires[label])
             for reply,label in zip([cli[i] for i in (0,2,5,6)],('second','second','third','third')))
         and cli[0]['result']['request']==second[18] and cli[5]['result']['request']==third[18],
         'P7 caller exact prepare/recovery wire differs')
    need(type(note) is dict and set(note)=={'commitment','agent_key','nullifier','root','path'} and type(note['path']) is list and len(note['path'])==4,'P7 public imported note shape')
    for x in (note['commitment'],note['agent_key'],note['nullifier'],note['root'],*note['path']):field(x)
    t0=observations['first']['state']['treasury'];t1=observations['other_revoke']['state']['treasury'];t2=observations['second']['state']['treasury'];t3=observations['third']['state']['treasury'];t4=observations['active_revoke']['state']['treasury']
    final=observations['active_revoke'];before=restart['before']
    need(before['height']>=final['height'] and canonical(before['state']['blocks'][:final['height']])==canonical(final['state']['blocks'])
         and all(b['transactions']==[] and b['results']==[] for b in before['state']['blocks'][final['height']:])
         and canonical({**final['state'],'blocks':before['state']['blocks']})==canonical(before['state']),
         'P7 restart final certified history differs')
    need(note['commitment']==first[23] and note['agent_key']==first[29] and note['nullifier']==second[21]
         and note['root']==worker.note_root(t0['notes'])==second[20] and t0['notes']==t1['notes'],'P7 actual change input binding differs')
    # The verified second proof checks its private opening and authenticated
    # path. The exported path is informational and is not separately attested.
    need(integer(first[25])==0 and integer(second[25])==1 and [t['owner_sequence'] for t in (t0,t1,t2,t3,t4)]==[0,1,1,1,2]
         and all(first[i]==second[i] for i in (1,2,3,5,6,14,26,28,29)),'P7 sequence/stable note domain differs')
    need(t0['fees']==2 and t2['fees']==4 and len(t0['notes'])==5 and len(t2['notes'])==7
         and t0['nullifiers']==[first[21]] and t2['nullifiers']==[first[21],second[21]]
         and next(x for x in t4['grants'] if x['id']==first[6])['commitment']==ZERO,'P7 native custody state effect differs')
    need(integer(third[25])==1 and all(first[i]==third[i] for i in (1,2,3,5,6,14,26,28,29))
         and third[7]==second[9] and third[8]==second[10] and second[7]==first[9] and second[8]==first[10]
         and third[20]==worker.note_root(t2['notes']) and second[23] in t2['notes']
         and t3['fees']==6 and len(t3['notes'])==9 and t3['nullifiers']==[first[21],second[21],third[21]],
         'P7 retained authority and third native state effects differ')
    # The actual third proof checks private CHANGE4 conservation/opening/path;
    # private values are not exported or separately attested by this checker.
    need(inv['notes']==[first[23],second[23],third[23]] and inv['retained_preparations']==[second[18],third[18]],'P7 imported encrypted inventory differs')
    for label,observation,wirelabel,source_label,input_label,revision in (
        ('stage_without_wire','first',None,'first','first',2),
        ('second_retained','other_revoke','second','first','first',2),
        ('second_attempted','other_revoke','second','first','first',2),
        ('second_certified','second','second','first','first',2),
        ('third_certified','third','third','second','second',5)):
        s=statuses[label];o=observations[observation]
        need(s['input']==public[input_label][23] and s['source_txid']==records[source_label]['txid']
             and s['vault_revision']==revision and s['as_of_height']==o['height'] and s['as_of_app_hash']==o['app_hash'],
             'P7 reconciliation AS-OF origin binding differs')
        if wirelabel is None:
            need(s['status']=='staged-without-retained-wire' and s['request']==numfield(9059)
                 and all(s[k] is None for k in ('txid','raw_sha256','attempts','hold_reason','completed_at')),
                 'P7 staged absence snapshot differs')
        else:
            state='retained-held' if label=='second_retained' else ('attempted-held' if label=='second_attempted' else 'recorded-certified')
            completed=records[wirelabel]['state_height'] if state=='recorded-certified' else None
            need(s['status']==state and s['request']==public[wirelabel][18] and s['txid']==records[wirelabel]['txid']
                 and s['raw_sha256']==digest(wires[wirelabel]) and s['attempts']==(0 if state=='retained-held' else 1)
                 and s['completed_at']==completed and s['hold_reason']==(None if completed is not None else 'unknown'),
                 'P7 exact reconciliation status differs')
    need(v['commands']==[wires[k].hex() for k in ('other_revoke','active_revoke')],'P7 owner command exact binding differs')
    for index,label in enumerate(('first','other_revoke','second','third','active_revoke'),1):
        rows=observations[label]['state']['receipts'];need(len(rows)==index and [r['raw'] for r in rows]==[wires[k].hex() for k in ('first','other_revoke','second','third','active_revoke')[:index]],'P7 certified execution order differs')
    transports=v['transports'];need(type(transports) is dict and set(transports)==set(records),'P7 transport roster differs')
    for label,t in transports.items():
        wire=wires[label];need(type(t) is dict and set(t)=={'rpc_returned','response_accepted','response_discarded','calls','delivery'}
             and all(t[k] is True for k in ('rpc_returned','response_accepted','response_discarded')) and t['calls']==[digest(wire)]
             and t['delivery']=={'txid':txid(wire),'outcome':'unknown','attempts':1},'P7 one-attempt lost return differs')
    need(all(first!=parse(artifacts['fixture-'+n+'.tx']) and second!=parse(artifacts['fixture-'+n+'.tx']) and third!=parse(artifacts['fixture-'+n+'.tx']) for n in FIXTURES),'P7 reused fixed fixture')
    return {'qualified':True,'status':v['status'],'check_count':len(CHECKS),'source_commit':source['commit'],
            'genesis_sha256':digest(rawg),'first_txid':txid(wires['first']),'respend_txid':txid(wires['second']),'retained_authority_txid':txid(wires['third']),
            'state_height':observations['active_revoke']['height'],'ciphertext_independently_decrypted':False,
            'claim':'actual one-host read-only preparation reconciliation and retained authority progression; external-key custody tested at runtime; no production/rollback claim'}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('report',type=Path);p.add_argument('--worker',type=Path,required=True);a=p.parse_args()
    try:r=validate(load(a.report),a.report,a.worker)
    except Exception as exc:print(json.dumps({'qualified':False,'error':str(exc)},sort_keys=True));return 1
    print(json.dumps(r,sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
