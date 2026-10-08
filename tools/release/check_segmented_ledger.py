"""Separate native proof/header verification. No public full-history replay claim."""
import argparse
import hashlib
import json
import sys
from pathlib import Path
from commit_verifier import Validator,TrustAnchor,merkle_root,verify_signed_header
import protocol8_transfer as n
from protocol8_worker import Worker
from protocol9_consensus import genesis_document,application_hash,genesis_shape

def run(args):
    n.need(not args.output.exists(),'fresh public-check output required')
    raw=args.report.read_bytes();n.need(len(raw)<=4*1024**2,'report byte bound');r=json.loads(raw)
    n.need(n.canonical(r)+b'\n'==raw,'canonical receipt required')
    n.need(r['status']=='qualified-one-host-segmented-recipient-ledger' and len(r['checks'])==16 and
           all(type(c['passed']) is bool and c['passed'] for c in r['checks']),'required successful receipt')
    artifacts=args.report.with_name(args.report.name+'.artifacts')
    n.need(not artifacts.is_symlink() and artifacts.is_dir(),'artifact directory')
    names=set()
    for row in r['artifacts']:
        name=row['name'];n.need(type(name) is str and Path(name).name==name and name not in names,'artifact name')
        n.need(type(row['bytes']) is int and 0<=row['bytes']<=8*1024**2,'artifact byte bound')
        names.add(name);p=artifacts/name
        n.need(p.is_file() and not p.is_symlink() and p.stat().st_size==row['bytes'] and
               n.sha(p.read_bytes())==row['sha256'],'artifact bytes differ')
    n.need(names=={p.name for p in artifacts.iterdir()},'artifact membership differs')
    genesis=(artifacts/'fixture-genesis.json').read_bytes();g=genesis_shape(genesis)
    n.need(n.sha(genesis)==args.genesis_sha256 and n.canonical(r['genesis'])==genesis,'external full-genesis pin differs')
    vals=[Validator(hashlib.sha256(bytes.fromhex(v['public_key'])).digest()[:20],bytes.fromhex(v['public_key']),v['power']) for v in g['validators']]
    vals.sort(key=lambda v:(-v.power,v.address));frozen=tuple(vals)
    anchor=TrustAnchor(g['chain_id'],frozen,merkle_root([v.encoded() for v in frozen]),args.genesis_sha256,sum(v.power for v in frozen))
    witness=r['checkpoint_witness'];cert=verify_signed_header(r['signed_header'],anchor,expected_height=witness['height']+1)
    n.need(cert['app_hash']==witness['app_hash']==application_hash(g,witness['checkpoint']), 'signed checkpoint differs')
    kat=(artifacts/'fixture-first.tx').read_bytes()
    worker=Worker(args.worker,g['worker_sha256'],kat);n.need(genesis_document(genesis,worker)==g,'native genesis differs')
    proofnames={'fixture-first.tx','fixture-competing.tx'}|{f'fixture-payment-{i:02}.tx' for i in range(1,10)}
    n.need({name for name in names if name.endswith('.tx')}==proofnames,'proof membership differs')
    statements={}
    for name in sorted(proofnames):
        wire=(artifacts/name).read_bytes();n.need(worker.verify(wire,g['network']),'invalid public native proof')
        statements[name]=n.parse(wire)
    first=statements['fixture-first.tx'];competing=statements['fixture-competing.tx']
    n.need(first[5]==competing[5] and first[6]!=competing[6],'competing proof relation differs')
    audit=worker.audit();n.need(audit['call_count']==audit['reaped_count'] and audit['timeout_count']==0,'native child not reaped')
    value={'status':'passed-separate-public-proof-and-header-check','source_commit':r['source']['commit'],
           'genesis_sha256':args.genesis_sha256,'native_proofs':11,'state_height':witness['height'],
           'header_height':witness['height']+1,'app_hash':witness['app_hash'],'worker_audit':audit,
           'claims':{'static_quorum_as_of':True,'public_native_proofs':True,'full_history_replay':False,
                     'freshness':False,'independent_operators':False,'external_security_review':False}}
    args.output.write_bytes(n.canonical(value)+b'\n')
    print(json.dumps({k:value[k] for k in ('status','native_proofs','state_height','header_height')}))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('report','worker','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--genesis-sha256',required=True);run(p.parse_args())
