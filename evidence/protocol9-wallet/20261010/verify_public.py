"""Separate process, full native public-history verification; not external review."""
import json,subprocess,sys
from pathlib import Path
r=Path('/home/xnuonux/1soft-p7-certified-client-20261005');sys.path.insert(0,str(r/'src'));sys.path.insert(0,str(r/'scripts'))
import protocol8_transfer as n
from protocol8_worker import Worker
from protocol9_certificate import verify_history
from run_protocol9_wallet_engine import CHECKS
o=Path(__file__).resolve().parent;receipt=json.loads((o/'native-02.json').read_bytes());a=o/'native-02.json.artifacts'
assert receipt['status']=='qualified-one-host-p9-wallet-journey'
assert tuple(row['id'] for row in receipt['checks'])==CHECKS and all(row['passed'] is True for row in receipt['checks'])
assert all(type(p['exit_code']) is int for p in receipt['processes']) and receipt['cold_process']['process_reaped'] is True
for row in receipt['artifacts']:
    raw=(a/row['name']).read_bytes();assert len(raw)==row['bytes'] and n.sha(raw)==row['sha256']
for name in ('src/protocol9_certificate.py','src/protocol9_consensus.py','src/protocol9_store.py','src/protocol9_wallet.py','src/protocol9_payment.py','src/protocol8_worker.py','src/protocol8_transfer.py','src/commit_verifier.py'):
    raw=(r/name).read_bytes();pin=receipt['source']['files'][name];assert len(raw)==pin['bytes'] and n.sha(raw)==pin['sha256']
genesis=(a/'fixture-genesis.json').read_bytes();assert n.sha(genesis)==receipt['genesis_sha256']
worker_path=Path('/home/xnuonux/1soft-p8-alpha-native-20261007/pinned-bin/recipient-consensus-bridge')
worker=Worker(worker_path,receipt['inputs']['worker']['sha256'],(a/'fixture-kat.tx').read_bytes())
certs=[]
for observation in receipt['observations']:
    cert,ledger=verify_history(observation['witness'],observation['signed_header'],genesis,worker)
    assert cert==observation['certificate'];certs.append(cert)
assert len(ledger['notes'])==5 and len(ledger['receipts'])==2
for payment,name in zip(receipt['payments'],('alice','bob')):
    raw=(a/('fixture-'+name+'-payment.tx')).read_bytes();assert n.txid(raw)==payment['txid'] and n.sha(raw)==payment['wire_sha256']
    row=next(row for row in ledger['receipts'] if row['txid']==payment['txid'])
    assert row==payment['result']['receipt'] and row['raw']==raw.hex()
    assert payment['result']['genesis_sha256']==n.sha(genesis)
audit=worker.audit();assert audit['call_count']==audit['reaped_count'] and audit['timeout_count']==0
value={'format':'1soft/protocol9-public-history-check/v1','status':'verified-full-native-public-history',
    'source_commit':subprocess.check_output(['git','-C',str(r),'rev-parse','HEAD'],text=True).strip(),
    'executed_runtime_commit':receipt['source']['commit'],'signed_observations':len(certs),'certificates':certs,
    'exact_receipts':2,'notes':5,'worker_audit':audit,
    'claims':{'full_native_public_history':True,'separate_process':True,'freshness':False,'independent_security_review':False,'compact_witness':False}}
(o/'public-check-01.json').write_bytes(n.canonical(value)+b'\n');print(json.dumps({k:v for k,v in value.items() if k not in ('worker_audit','certificates')}))
