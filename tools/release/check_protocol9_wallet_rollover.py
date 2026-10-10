#!/usr/bin/env python3
"""Separate pinned native public replay of the P9 wallet rollover receipt.

Reported transport/custody exercises are not independently observable from the
public ledger. Signed history, native proofs, exact outputs and input segments
are independently re-executed here. This is not an external security audit.
"""
import argparse, json, subprocess, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'));sys.path.insert(0,str(ROOT/'scripts'))
import protocol8_transfer as n
from protocol8_worker import Worker
from protocol9_certificate import verify_history
from run_protocol9_wallet_rollover import CHECKS

def preflight(r):
    n.need(type(r) is dict and r.get('format')=='1soft/protocol9-wallet-rollover/v1' and
        r.get('status')=='qualified-one-host-p9-wallet-rollover' and not r.get('error') and not r.get('cleanup_error'),'qualified rollover receipt required')
    checks=r.get('checks');n.need(type(checks) is list and tuple(x['id'] for x in checks)==CHECKS and
        all(x['passed'] is True for x in checks),'complete exact checks required')
    processes=r.get('processes');n.need(type(processes) is list and bool(processes) and
        all(type(p['exit_code']) is int and p['exit_code'] in (0,-15) for p in processes),'owned processes did not stop normally')
    cold=r.get('cold_process');n.need(type(cold) is dict and cold['exit_code']==0 and cold['process_reaped'] is True,'cold process incomplete')
    for group in ('worker_audits','private_process_audits'):
        audits=r.get(group);n.need(type(audits) is list and bool(audits) and all(a['call_count']==a['reaped_count'] and a['timeout_count']==0 for a in audits),'native audit incomplete')
    runs=r.get('native_processes');n.need(type(runs) is list and bool(runs) and all(x['process_reaped'] is True and x['exit_code']==0 and not x.get('timed_out') for x in runs),'fixture child incomplete')
    payments=r.get('payments');n.need(type(payments) is list and len(payments)==3 and
        [p['input_segment'] for p in payments]==[0,0,1] and
        all(type(p['committed_height']) is int and p['committed_height']>64 for p in payments[1:]),'old/new post64 payments absent')
    n.need(type(r.get('generator_payments')) is list and len(r['generator_payments'])==7 and
        type(r.get('observations')) is list and len(r['observations'])==5,'complete journey required')

def verify(receipt,worker_path):
    raw_receipt=receipt.read_bytes();n.need(len(raw_receipt)<=32*1024**2,'receipt bound');r=json.loads(raw_receipt);preflight(r)
    artifacts=receipt.with_name(receipt.name+'.artifacts');n.need(artifacts.is_dir() and not artifacts.is_symlink(),'public artifact directory required')
    def artifact(name):
        n.need(type(name) is str and Path(name).name==name and name not in ('','.','..'),'flat artifact membership')
        p=artifacts/name;n.need(p.is_file() and not p.is_symlink() and p.stat().st_size<=8*1024**2,'bounded public artifact');return p.read_bytes()
    for pin in r['artifacts']:
        raw=artifact(pin['name']);n.need(len(raw)==pin['bytes'] and n.sha(raw)==pin['sha256'],'artifact identity changed')
    runtime=[name for name in r['source']['files'] if name.startswith(('src/','scripts/','tools/recipient-','tools/shielded-consensus/halo2/','tools/segmented-fixture/'))]
    runtime.append('tools/release/check_protocol9_wallet_rollover.py')
    for name in runtime:
        raw=(ROOT/name).read_bytes();pin=r['source']['files'][name]
        n.need(len(raw)==pin['bytes'] and n.sha(raw)==pin['sha256'],'executed runtime identity changed')
    genesis=artifact('fixture-genesis.json');n.need(n.sha(genesis)==r['genesis_sha256'],'full genesis identity changed')
    worker=Worker(worker_path,r['inputs']['worker']['sha256'],artifact('fixture-kat.tx'))
    certificates=[];prior=None
    for observation in r['observations']:
        witness=observation['witness']
        if prior is not None:n.need(witness['height']>prior['height'] and witness['blocks'][:len(prior['blocks'])]==prior['blocks'],'history extension differs')
        cert,ledger=verify_history(witness,observation['signed_header'],genesis,worker)
        n.need(cert==observation['certificate'],'certificate differs');certificates.append(cert);prior=witness
    n.need([o['witness']['checkpoint']['accepted_count'] for o in r['observations']]==[0,1,8,9,10],'authenticated journey counts differ')
    rollover=r['observations'][2]['witness'];final=r['observations'][-1]['witness']
    n.need(rollover['height']>64 and rollover['checkpoint']['notes_count']==17 and
        final['checkpoint']['notes_count']==21 and final['checkpoint']['fees']==10 and len(ledger['receipts'])==10,'rollover/final ledger differs')
    rows={x['txid']:x for x in ledger['receipts']};notes={x['commitment']:x for x in ledger['notes']}
    identities=[]
    for p in r['payments']+r['generator_payments']:
        raw=artifact(p['artifact']);ident=n.txid(raw);n.need(ident==p['txid'] and n.sha(raw)==p['wire_sha256'] and rows[ident]['raw']==raw.hex(),'exact accepted original differs')
        identities.append(ident)
    n.need(len(set(identities))==10 and set(identities)==set(rows),'accepted payment inventory differs')
    for p in r['payments']:
        row=rows[p['txid']];result=p['result'];note=notes[p['input']]
        n.need(row==result['receipt'] and result['status']=='executed-exact' and result['txid']==p['txid'] and
            result['raw_sha256']==p['wire_sha256'] and result['genesis_sha256']==n.sha(genesis) and
            p['committed_height']==row['height'] and p['input_segment']==note['segment'] and
            note['height']<row['height'],'wallet receipt/input segment differs')
        index=result['observation'];o=r['observations'][index]['witness']
        n.need(result['state_height']==o['height'] and result['app_hash']==o['app_hash'] and
            row['height']<=o['height'],'exact result observation differs')
    n.need(r['payments'][1]['input']==n.parse(artifact(r['payments'][0]['artifact']))[11] and
        r['payments'][2]['input']==n.parse(artifact(r['generator_payments'][-1]['artifact']))[11],'old/new input origin differs')
    competing=artifact(r['competing']['artifact']);accepted=artifact(r['payments'][1]['artifact'])
    n.need(n.sha(competing)==r['competing']['wire_sha256'] and worker.verify(competing,json.loads(genesis)['network']) and
        n.parse(competing)[5]==n.parse(accepted)[5] and n.parse(competing)[6]!=n.parse(accepted)[6] and
        n.txid(competing) not in rows and r['competing']['codes']==[5]*4,'valid competing older input evidence differs')
    audit=worker.audit();n.need(audit['call_count']==audit['reaped_count'] and audit['timeout_count']==0,'public native processes not reaped')
    return {'format':'1soft/protocol9-wallet-rollover-public-check/v1','status':'verified-full-native-public-history',
        'source_commit':subprocess.check_output(['git','-C',str(ROOT),'rev-parse','HEAD'],text=True).strip(),
        'executed_runtime_commit':r['source']['commit'],'receipt_sha256':n.sha(raw_receipt),
        'signed_observations':5,'certificates':certificates,'exact_receipts':10,'wallet_receipts':3,
        'generator_receipts':7,'notes':21,'post64_input_segments':[0,1],'worker_audit':audit,
        'claims':{'full_native_public_history':True,'separate_process':True,'freshness':False,
            'independent_security_review':False,'compact_witness':False,
            'private_openings_or_amounts_independently_verified':False,
            'lost_response_and_custody_exercises':'reported by native runner; not inferable from public ledger'}}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('receipt','worker','output'):p.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args();n.need(not args.output.exists(),'fresh public result required')
    result=verify(args.receipt,args.worker);args.output.write_bytes(n.canonical(result)+b'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('worker_audit','certificates')}))
    return 0
if __name__=='__main__':raise SystemExit(main())
