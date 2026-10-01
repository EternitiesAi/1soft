"""Exact-source candidate qualification, separate from historical byte seals."""
import argparse
from copy import deepcopy
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import traceback
import unittest
import uuid

from block_application import encode
from local_devnet import ROOT,PIN_SHA,verify_engine,private_new
from p4_evidence import need
import release_check as legacy
from merchant_qualification import MERCHANT_CHECKS,actual_report_matches

PARENT='a09afbf9c437c749b184fe33668ed3309ac52ca5'
QUALIFICATION_FORMAT='1soft/native-invoice-candidate/v1'
INVENTORY='tools/private-payments/NATIVE_INVOICE_SOURCE.json'
INVOICE_CHECKS=(
    'explicit v3 workspace has exact fresh native invoice capability',
    'three original quotes bind exact public resource digests',
    'owner and both grants sign independently reconstructed invoice commitments',
    'generic native capsules alone make no invoice authenticity claim',
    'three merchant verifications replay execution and authenticate exact invoice terms',
    'genuine same amount recipient payment refuses a different invoice preimage',
    'cold exact wires preserve original signed invoice commitments',
)

def reduced(source):return {k:source[k] for k in ('commit','tree','source_id','tracked_files')}

def compare_candidate(current,parent,changed,added):
    need(set(current)==set(parent)|set(added) and not set(parent)&set(added),
         'candidate membership differs; no deletion or unexpected addition')
    need(set(changed)<=set(parent),'unknown changed parent path')
    for name,before in parent.items():
        need((current[name]!=before) if name in changed else (current[name]==before),
             'unlisted change or expected change missing: '+name)

def source_checked(expected=None):
    source=legacy.base.source_identity(ROOT)
    need(subprocess.run(['git','-C',str(ROOT),'merge-base','--is-ancestor',PARENT,source['commit']],
         capture_output=True,timeout=15).returncode==0,'candidate parent is not ancestor')
    inventory=json.loads((ROOT/INVENTORY).read_bytes())
    need(set(inventory)=={'schema','format','parent_commit','parent_files','changed','added','files'} and
         type(inventory['schema']) is int and inventory['schema']==1 and
         inventory['format']==QUALIFICATION_FORMAT and inventory['parent_commit']==PARENT,
         'candidate inventory header differs')
    parent={}
    for record in legacy.base.git(ROOT,'ls-tree','-rz','--full-tree',PARENT).split(b'\0'):
        if not record:continue
        meta,name=record.split(b'\t',1);mode,kind,blob=meta.decode().split();name=name.decode()
        need(kind=='blob' and mode in ('100644','100755'),'parent source kind differs')
        raw=legacy.base.git(ROOT,'cat-file','blob',blob)
        parent[name]=dict(path=name,mode=mode,git_blob=blob,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    need(len(parent)==491 and inventory['parent_files']==[parent[n] for n in sorted(parent)],
         'complete exact 491-file parent inventory differs')
    changed=inventory['changed'];added=inventory['added']
    need(type(changed) is list and type(added) is list and changed==sorted(set(changed)) and
         added==sorted(set(added)) and INVENTORY in added,'unique changed and added paths required')
    current={r['path']:r for r in source['files']}
    compare_candidate(current,parent,changed,added)
    need(inventory['files']==[current[n] for n in sorted(current) if n!=INVENTORY],
         'complete candidate byte mode inventory differs')
    source['qualification_format']=QUALIFICATION_FORMAT
    if expected is not None:need(source==expected,'source changed during candidate qualification')
    return source

def invoice_report_matches(report,source,run_id):
    try:
        need(type(report) is dict and report.get('native_signature_authenticates_resource') is True and
             type(report.get('invoice_commitment_version')) is int and report['invoice_commitment_version']==1 and
             type(report.get('workspace_schema')) is int and report['workspace_schema']==3,'native capability claim differs')
        checks=report['checks'];expected=set(MERCHANT_CHECKS)|set(INVOICE_CHECKS)
        need(type(checks) is list and len(checks)==len(expected) and
             all(type(c) is dict and c.get('passed') is True and type(c.get('name')) is str for c in checks) and
             {c['name'] for c in checks}==expected,'incomplete original or invoice checks')
        need(len({p['invoice_commitment'] for p in report['payments']})==3,'invoice commitments must be distinct')
        for p in report['payments']:
            need(all(type(p.get(k)) is str and re.fullmatch('[0-9a-f]{64}',p[k]) for k in
                 ('invoice_commitment','resource_sha256','invoice_artifact_sha256')) and
                 p.get('invoice_artifact')=='public-invoice-'+p['role']+'.json','payment commitment evidence absent')
        need(type(report.get('wrong_invoice_proof_sha256')) is str and
             re.fullmatch('[0-9a-f]{64}',report['wrong_invoice_proof_sha256']),'negative proof evidence absent')
        # Preserve the unchanged original predicate for its 37 invariants. The
        # new signature claim is independently required above, never erased in
        # persisted evidence. Only this local predicate projection is legacy.
        projected=deepcopy(report)
        projected['native_signature_authenticates_resource']=False
        projected['checks']=[c for c in checks if c['name'] in MERCHANT_CHECKS]
        return actual_report_matches(projected,source,run_id)
    except (ValueError,KeyError,TypeError,AttributeError):return False

def public_artifacts_match(report,directory):
    """Replay retained public original preimages/proofs at recorded run times.

    Historical inspection does not renew trust or fulfill an expired live quote.
    No runtime database, password, private plaintext or signing key is opened.
    """
    import base64
    from commit_verifier import load_json
    from invoice_terms import terms_commitment
    from payment_x402 import (NativePaymentExpectation,TrustedMerchantAssignment,
        parse_payment_required,verify_merchant_payment)
    root=Path(directory)
    def raw(name):
        p=root/name
        need(p.is_file() and not any(v.is_symlink() for v in (p,*p.parents)) and
             0<p.stat().st_size<=16*1024*1024,'bounded regular retained proof required')
        return p.read_bytes()
    try:
        genesis=raw('engine-genesis.json');policy=load_json(raw('policy.json'))
        originals={}
        for payment in report['payments']:
            role=payment['role'];need(role in ('owner','raven','atlas'),'unknown retained role')
            artifact_raw=raw('public-invoice-'+role+'.json')
            need(hashlib.sha256(artifact_raw).hexdigest()==payment['invoice_artifact_sha256'],'invoice artifact hash differs')
            a=load_json(artifact_raw);need(encode(a)==artifact_raw and type(a['schema']) is int and a['schema']==1,'invoice artifact schema differs')
            expectation=NativePaymentExpectation(**a['expectation']);now=a['historical_verification_ns']
            quote=parse_payment_required(a['required_header'],expectation,now_ns=now)
            resource=base64.b64decode(a['public_resource'],validate=True)
            commitment=terms_commitment(quote['invoice_terms'])
            need(a['invoice_terms']==quote['invoice_terms'] and
                 hashlib.sha256(resource).hexdigest()==a['resource_sha256']==payment['resource_sha256']==a['invoice_terms']['resource_sha256'] and
                 quote['quote_sha256']==payment['quote_sha256'] and quote['request_id']==payment['request_id'],
                 'retained public resource or original invoice differs')
            wire=raw('wire-'+role+'.json');capsule=raw('capsule-'+role+'.json');packet=load_json(wire)
            payer=packet['body']['sender']
            need(hashlib.sha256(wire).hexdigest()==payment['wire_sha256'] and
                 hashlib.sha256(capsule).hexdigest()==payment['capsule_sha256'] and
                 packet['body']['op']['invoice_commitment']==commitment==payment['invoice_commitment'],
                 'retained original signed commitment differs')
            assignment=TrustedMerchantAssignment(quote['quote_sha256'],quote['request_id'],expectation.recipient,payer,payment['wire_sha256'])
            proof=verify_merchant_payment(signature_header=a['payment_signature_header'],required_header=a['required_header'],
                expectation=expectation,assignment=assignment,exact_wire=wire,capsule=capsule,
                genesis_bytes=genesis,policy=policy,payer=payer,now_ns=now)
            need(proof['native_signature_authenticates_resource'] is True and proof['native_txid']==payment['native_txid'] and
                 proof['receipt_report']['recipient']==payment['recipient'] and proof['receipt_report']['amount_units']==payment['units'] and proof['receipt_report']['fee_units']==payment['fee'],
                 'retained positive invoice proof differs')
            originals[role]=(expectation,payer,wire,capsule,payment)
        negative_raw=raw('wrong-invoice-proof.json')
        need(hashlib.sha256(negative_raw).hexdigest()==report['wrong_invoice_proof_sha256'],'negative proof hash differs')
        a=load_json(negative_raw);need(a['refused_for_commitment'] is True,'negative proof outcome differs')
        original,payer,wire,capsule,payment=originals[a['original_role']]
        other=NativePaymentExpectation(**a['expectation'])
        need(other.recipient==original.recipient and other.amount_units==original.amount_units and
             other.resource_url!=original.resource_url and a['original_wire_sha256']==payment['wire_sha256'] and
             a['original_capsule_sha256']==payment['capsule_sha256'],'negative proof changes original genuine payment context')
        quote=parse_payment_required(a['required_header'],other,now_ns=a['historical_verification_ns'])
        assignment=TrustedMerchantAssignment(quote['quote_sha256'],quote['request_id'],other.recipient,payer,payment['wire_sha256'])
        try:
            verify_merchant_payment(signature_header=a['payment_signature_header'],required_header=a['required_header'],
                expectation=other,assignment=assignment,exact_wire=wire,capsule=capsule,
                genesis_bytes=genesis,policy=policy,payer=payer,now_ns=a['historical_verification_ns'])
        except ValueError as exc:return 'commitment' in str(exc)
        return False
    except (ValueError,KeyError,TypeError,OSError,AttributeError):return False

def groups():
    result=dict(legacy.base.GROUPS)
    for tool in ('client','wallet','delivery','recovery','explorer','receipts'):
        name='p4_'+tool;directory='tools/protocol4-'+tool+'/tests'
        result[name]=(directory,'test_*.py',[directory])
    for name,directory in (('local_platform','tools/local-platform/tests'),
                           ('private_payments','tools/private-payments/tests')):
        result[name]=(directory,'test_*.py',[directory])
    return result

def worker(group,output,source_id,run_id):
    directory,pattern,paths=groups()[group]
    paths=[ROOT/p for p in paths]+[ROOT/directory,ROOT/'src',ROOT/'scripts',ROOT/'tests']+sorted((ROOT/'tools').glob('*/src'))
    paths += [ROOT/'tools/protocol4-client/tests',ROOT/'tools/protocol4-wallet/tests',ROOT/'tools/protocol4-delivery/tests']
    sys.path[:0]=[str(p) for p in paths];os.environ['PYTHONPATH']=os.pathsep.join(map(str,paths))
    os.environ['PYTHONDONTWRITEBYTECODE']='1'
    suite=unittest.TestLoader().discover(str(ROOT/directory),pattern=pattern)
    expected=[t.id() for t in legacy.base.flatten(suite)]
    class Result(unittest.TextTestResult):
        def __init__(self,*a,**kw):super().__init__(*a,**kw);self.ids=[]
        def addSuccess(self,t):super().addSuccess(t);self.ids.append(t.id())
    result=unittest.TextTestRunner(verbosity=2,resultclass=Result).run(suite)
    value=dict(schema=1,group=group,source_id=source_id,run_id=run_id,expected_ids=expected,
        successful_ids=result.ids,run=result.testsRun,skips=len(result.skipped),errors=len(result.errors),
        failures=len(result.failures),expected_failures=len(result.expectedFailures),unexpected_successes=len(result.unexpectedSuccesses))
    value['passed']=legacy.base.successful(value);legacy.base.store_json(output,value)
    return 0 if value['passed'] else 1

def qualify(engine,output):
    output=Path(output).absolute()
    need(not output.is_relative_to(ROOT) and not any(p.is_symlink() for p in (output,*output.parents)),
         'fresh outside-source regular output required')
    output.mkdir(mode=0o700,exist_ok=False)
    try:return _qualify_checked(engine,output)
    except Exception as exc:
        # No preflight source or execution is invented. An existing final result
        # is never replaced; invalid/occupied output paths fail before creation.
        result=dict(schema=1,format=QUALIFICATION_FORMAT,status='failed-preflight',source=None,
            local_automated_qualification=False,error_type=type(exc).__name__,
            unassessed_gates=list(groups())+['javascript','official-go-vectors','all-actual-validator-scenarios'])
        private_new(output/'result.json',encode(result));return result

def _qualify_checked(engine,output):
    source=source_checked();binary=verify_engine(engine);run_id=uuid.uuid4().hex
    output=Path(output).absolute();need(not output.is_relative_to(ROOT),'outside-source output required')
    need(not any(p.is_symlink() for p in (output,*output.parents)),'aliased output refused')
    report=dict(schema=1,format=QUALIFICATION_FORMAT,status='running',source=reduced(source),
        run_id=run_id,gates=[],python_tests=0,javascript_tests=0,go_response_vectors=0,
        historical_445_file_byte_seal_claimed=False,changed_parent_paths=[],
        onchain_privacy=False,production_custody=False,independent_security_review=False,
        independent_hosts=False,public_release_ready=False,real_funds_ready=False)
    inventory=json.loads((ROOT/INVENTORY).read_bytes());report['changed_parent_paths']=inventory['changed']
    packages={}
    for line in (ROOT/'requirements.txt').read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):continue
        name,version=line.split('==');packages[name]=importlib.metadata.version(name)
        need(packages[name]==version,'installed package differs from exact pin')
    report['packages']=packages;private_new(output/'source.json',encode(source))
    def checked():source_checked(source);verify_engine(binary)
    def execute(name,command,path,predicate,timeout=600):
        checked();process=legacy.base.run_process(command,ROOT,output/(name+'.log'),timeout)
        value=json.loads(path.read_bytes()) if path.is_file() else None
        passed=process['returncode']==0 and not process['timed_out'] and not process['log_truncated'] and value is not None and predicate(value)
        report['gates'].append(dict(name=name,passed=bool(passed),process=process,
            result_path=str(path.relative_to(output)),result_sha256=None if value is None else hashlib.sha256(path.read_bytes()).hexdigest()))
        legacy.base.store_json(output/'progress.json',report,replace=(output/'progress.json').exists())
        print(encode(dict(gate=name,passed=bool(passed))).decode(),flush=True)
        need(passed,'candidate gate failed: '+name);checked();return value
    try:
        script=ROOT/'tools/private-payments/scripts/qualify_native_invoice.py'
        for group in groups():
            path=output/(group+'.json')
            child=execute(group,[sys.executable,'-B',str(script),'--worker',group,'--output',str(path),
                '--source-id',source['source_id'],'--run-id',run_id],path,
                lambda q,g=group:legacy.base.successful(q) and q.get('group')==g and q.get('source_id')==source['source_id'] and q.get('run_id')==run_id)
            report['python_tests']+=child['run']
        for label,path in (('legacy-javascript','reference/kernel.test.mjs'),
                           ('local-javascript','tools/local-platform/tests/wallet.test.cjs')):
            # Exact original JavaScript entrypoints are recorded as process evidence.
            checked();process=legacy.base.run_process(['node','--test',path],ROOT,output/(label+'.log'),120)
            js=legacy.base.javascript_result((output/(label+'.log')).read_bytes())
            need(process['returncode']==0 and not process['timed_out'] and not process['log_truncated'] and js['passed'],'JavaScript gate failed: '+label)
            report['javascript_tests']+=js['tests'];report[label]={**process,**js};checked()
        vectors=output/'p4-go-vectors.json'
        process=legacy.base.run_process([sys.executable,str(ROOT/'tools/local-platform/scripts/go_vectors.py'),'--output',str(vectors)],ROOT,output/'go-vectors.log',120)
        need(process['returncode']==0 and not process['timed_out'] and not process['log_truncated'] and vectors.is_file(),'P4 response vectors unavailable')
        env={**os.environ,'GOPROXY':'off','GOTOOLCHAIN':'local','GOSUMDB':'off','GOTELEMETRY':'off'}
        with (output/'go.log').open('xb') as log:
            os.chmod(log.name,0o600)
            process=subprocess.run(['go','run','.'],cwd=ROOT/'tools/validator-registry/upstream',env=env,
                input=vectors.read_bytes(),stdout=log,stderr=subprocess.STDOUT,timeout=180)
        raw=(output/'go.log').read_bytes();need(len(raw)<1024*1024 and process.returncode==0,'official offline Go probe failed')
        oracle=json.loads(raw);need(oracle['status']=='passed' and oracle['engine_version']=='0.38.25' and
            oracle['vectors']==['protocol4-height-'+str(i) for i in range(1,5)],'official response vector identities differ')
        report['go_response_vectors']=4;private_new(output/'go-result.json',encode(oracle));checked()
        engine_commands=(
            ('p4-baseline',[sys.executable,str(ROOT/'scripts/run_protocol4_engine.py'),'--engine',str(binary),'--engine-sha256',PIN_SHA,'--output',str(output/'p4-baseline.json')],output/'p4-baseline.json'),
            ('p4-delivery',[sys.executable,str(ROOT/'scripts/run_protocol4_delivery_engine.py'),'--engine',str(binary),'--engine-sha256',PIN_SHA,'--output',str(output/'p4-delivery')],output/'p4-delivery/result.json'),
            ('p4-ledger-receipts',[sys.executable,str(ROOT/'scripts/run_protocol4_explorer_receipts_engine.py'),'--engine',str(binary),'--engine-sha256',PIN_SHA,'--output',str(output/'p4-ledger-receipts')],output/'p4-ledger-receipts/result.json'))
        for name,args,path in engine_commands:
            execute(name,args,path,lambda q,n=name:legacy.engine_report_matches(q,source,n))
        for name in ('bootstrap-after-turnover','commit-reply-loss-at-emission'):
            path=output/name/'result.json'
            execute(name,[sys.executable,str(ROOT/'tools/protocol4-recovery/scripts/run_engine.py'),'--cometbft',str(binary),'--engine-sha256',PIN_SHA,'--output',str(output/name),'--profile',name],path,
                lambda q,n=name:legacy.revalidate_recovery(q,source,n))
        for name in ('local-product','local-cli','private-consensus','merchant-legacy','invoice-consensus'):
            path=output/name/'result.json'
            execute(name,[sys.executable,'-B',str(script),'--actual',name,'--engine',str(binary),'--output',str(output/name),
                '--source-file',str(output/'source.json'),'--run-id',run_id],path,
                lambda q,n=name:actual_matches(q,source,run_id,n,output/n),timeout=600)
        checked();report.update(status='passed',source_after=reduced(source),source_unchanged=True,engine_sha256=PIN_SHA,
            engine_unchanged=True,local_automated_qualification=True,unassessed_gates=[])
    except Exception as exc:
        report.update(status='failed',error_type=type(exc).__name__,error_message=str(exc),
            error_frames=[dict(file=Path(f.filename).name,line=f.lineno,function=f.name) for f in traceback.extract_tb(exc.__traceback__)])
    private_new(output/'result.json',encode(report));return report

def actual_matches(report,source,run_id,name,directory=None):
    if name in ('local-product','local-cli'):
        expected=37 if name=='local-product' else 9
        return (type(report) is dict and report.get('status')=='passed' and len(report.get('checks',[]))==expected and
            all(c.get('passed') is True for c in report['checks']) and len({c['name'] for c in report['checks']})==expected)
    if name=='merchant-legacy':return actual_report_matches(report,reduced(source),run_id)
    if name=='invoice-consensus':return (invoice_report_matches(report,reduced(source),run_id) and
        directory is not None and public_artifacts_match(report,directory))
    if name=='private-consensus':
        # Import the unchanged historical report predicate, not its byte seal.
        sys.path.insert(0,str(ROOT/'tools/private-payments/scripts'))
        import qualify_private
        from private_acceptance import PRIVATE_CHECKS
        return qualify_private.acceptance_report_matches(report,source,run_id,PRIVATE_CHECKS)
    return False

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--engine',type=Path);p.add_argument('--output',required=True,type=Path)
    p.add_argument('--worker',choices=tuple(groups()));p.add_argument('--source-id');p.add_argument('--run-id')
    p.add_argument('--actual',choices=('local-product','local-cli','private-consensus','merchant-legacy','invoice-consensus'))
    p.add_argument('--source-file',type=Path);a=p.parse_args(argv)
    if a.worker:return worker(a.worker,a.output,a.source_id,a.run_id)
    if a.actual:
        source=json.loads(a.source_file.read_bytes());source_checked(source);verify_engine(a.engine)
        if a.actual=='local-product':
            from product_acceptance import run_product
            result=run_product(a.engine,a.output)
        elif a.actual=='local-cli':
            from cli_acceptance import run_cli
            result=run_cli(a.engine,a.output)
        elif a.actual=='private-consensus':
            from private_acceptance import run_private
            result=run_private(a.engine,a.output,source=source,run_id=a.run_id)
        else:
            from merchant_acceptance import run_merchant
            result=run_merchant(a.engine,a.output,source=source,run_id=a.run_id,invoice_commitments=a.actual=='invoice-consensus')
        source_checked(source);verify_engine(a.engine)
        return 0 if actual_matches(result,source,a.run_id,a.actual,a.output) else 1
    need(a.engine is not None,'pinned engine required')
    return 0 if qualify(a.engine,a.output)['status']=='passed' else 1
