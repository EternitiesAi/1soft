"""One exact clean-source local qualification command. No downloads or deployment."""
import hashlib
import importlib.util
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from block_application import encode
from local_devnet import ROOT,PIN_SHA,verify_engine,private_new
from p4_evidence import need
from product_acceptance import run_product
from cli_acceptance import run_cli

PARENT='e1c53b1dade261625e581415501b1f04ae9e6a9d'
ENGINE_CHECK_COUNTS={'p4-baseline':27,'p4-delivery':42,'p4-ledger-receipts':44,
    'bootstrap-after-turnover':7,'commit-reply-loss-at-emission':7}
spec=importlib.util.spec_from_file_location('local_release_existing_gate',ROOT/'tools/release/check_release.py')
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)


def engine_report_matches(report,source,profile):
    """Require the unchanged runners' observed provenance, not just their exit code.

    Ledger/receipt acceptance reports its independently checked required pin and
    observed final binary hash, whereas the other runners also record an initial
    observed hash. Recovery uses the complete nested source identity. Full recovery
    evidence is replayed separately by its existing validator.
    """
    if type(report) is not dict or profile not in ENGINE_CHECK_COUNTS:return False
    if type(report.get('schema')) is not int or report['schema']!=1 or report.get('status')!='passed':return False
    checks=report.get('checks')
    if type(checks) is not list or len(checks)!=ENGINE_CHECK_COUNTS[profile]:return False
    if not all(type(c) is dict and c.get('passed') is True and type(c.get('name')) is str and c['name'] for c in checks):return False
    if len({c['name'] for c in checks})!=len(checks):return False
    if profile.startswith('p4-'):
        if (report.get('source_commit')!=source['commit'] or report.get('source_tree')!=source['tree'] or
            report.get('source_dirty_before') is not False or report.get('source_dirty_after') is not False or
            report.get('source_qualified') is not True or report.get('engine_required_sha256')!=PIN_SHA or
            report.get('engine_sha256_after')!=PIN_SHA):return False
        if profile=='p4-ledger-receipts':
            return (report.get('source_commit_after')==source['commit'] and
                report.get('source_tree_after')==source['tree'] and report.get('engine_unchanged') is True)
        return report.get('engine_sha256')==PIN_SHA and report.get('engine_version')=='0.38.25'
    expected={key:source[key] for key in ('commit','tree','source_id')}
    verified=report.get('verification')
    return (report.get('source')==expected and report.get('profile')==profile and
        report.get('engine_sha256')==PIN_SHA and report.get('engine_version')=='0.38.25' and
        report.get('consensus_executed') is True and type(verified) is dict and
        verified.get('status')=='verified-local-acceptance' and verified.get('profile')==profile and
        verified.get('release_status')=='blocked' and verified.get('public_network') is False and
        verified.get('real_funds') is False)


def revalidate_recovery(report,source,profile):
    if not engine_report_matches(report,source,profile):return False
    directory=ROOT/'tools/protocol4-recovery/src'
    # This is the unchanged repository evidence replay, not a replacement fixture.
    sys.path.insert(0,str(directory))
    try:
        spec=importlib.util.spec_from_file_location('local_release_recovery_acceptance',directory/'acceptance.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        expected={key:source[key] for key in ('commit','tree','source_id')}
        return module.validate(report,source=expected,engine_hash=PIN_SHA)==report['verification']
    finally:sys.path.remove(str(directory))


def source_checked(expected=None):
    identity=base.source_identity(ROOT)
    need(subprocess.run(['git','-C',str(ROOT),'merge-base','--is-ancestor',PARENT,identity['commit']],
                        capture_output=True,timeout=15).returncode==0,'pinned parent is not an ancestor')
    dependencies=json.loads((ROOT/'tools/local-platform/DEPENDENCIES.json').read_bytes())
    need(dependencies['parent_commit']==PARENT and len(dependencies['files'])==421,'complete pinned parent inventory required')
    parent_rows={}
    for record in subprocess.check_output(['git','-C',str(ROOT),'ls-tree','-rz','--full-tree',PARENT],timeout=15).split(b'\0'):
        if record:
            metadata,name=record.split(b'\t',1);mode,kind,blob=metadata.decode().split()
            need(kind=='blob' and mode in ('100644','100755'),'parent source kind differs')
            parent_rows[name.decode()]=(mode,blob)
    need({r['path'] for r in dependencies['files']}==set(parent_rows) and len(parent_rows)==421,
         'pinned parent inventory membership differs')
    current={row['path']:row for row in identity['files']}
    for row in dependencies['files']:
        need(current.get(row['path'])==row and parent_rows[row['path']]==(row['mode'],row['git_blob']),
             'inherited source byte or mode changed')
    own=json.loads((ROOT/'tools/local-platform/SOURCE_MANIFEST.json').read_bytes())
    names=set()
    for row in own['files']:
        name='tools/local-platform/'+row['path'];need(name not in names and name in current,'invalid local source inventory')
        names.add(name);r=current[name]
        need(r['sha256']==row['sha256'] and r['bytes']==row['bytes'] and r['mode']==row['mode'],'local source manifest changed')
    expected_names={r['path'] for r in identity['files'] if r['path'].startswith('tools/local-platform/') and
                    not r['path'].endswith(('/SOURCE_MANIFEST.json','/DEPENDENCIES.json'))}
    need(names==expected_names,'local source inventory membership differs')
    if expected is not None:need(identity==expected,'source identity changed during qualification')
    return identity


def qualify(engine,output):
    source=source_checked();binary=verify_engine(engine)
    output=Path(output).absolute();need(not output.is_relative_to(ROOT),'qualification output must be outside source')
    for p in (output.parent,*output.parent.parents):need(not p.is_symlink(),'aliased output parent refused')
    output.mkdir(mode=0o700,exist_ok=False)
    report={'schema':1,'status':'running','source_commit':source['commit'],'source_tree':source['tree'],
        'source_id':source['source_id'],'source_tracked_files':source['tracked_files'],
        'engine_sha256':PIN_SHA,'python':sys.version.split()[0],'gates':[],
        'python_tests':0,'javascript_tests':0,'go_response_vectors':0,
        'local_automated_qualification':False,'browser_visual_check':'unassessed',
        'independent_security_review':False,'independent_hosts':False,'public_release_ready':False,
        'real_funds_ready':False,'spending_or_deployment_authorized':False,
        'unassessed':['rendered browser/mobile UI and human acceptance','host/custody security',
            'independent validator operators','public network/economic and genesis decisions',
            'long-running P4 proof collection beyond 64 blocks','post-expiry archival verification',
            'copied journals and cross-device financial coordination','interrupted first journal initialization']}
    packages={}
    for line in (ROOT/'requirements.txt').read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):continue
        name,version=line.split('==');packages[name]=importlib.metadata.version(name)
        need(packages[name]==version,'installed package differs from exact pin')
    report['packages']=packages;private_new(output/'source.json',encode(source));private_new(output/'started.json',encode(report))
    def execute(name,args,result_path,predicate,timeout=600):
        source_checked(source);verify_engine(binary)
        process=base.run_process(args,ROOT,output/(name+'.log'),timeout)
        value=json.loads(result_path.read_bytes()) if result_path.is_file() else None
        passed=process['returncode']==0 and not process['timed_out'] and not process['log_truncated'] and value is not None and predicate(value)
        gate={'name':name,'passed':bool(passed),'process':process,
              'result_path':str(result_path.relative_to(output)),'result_sha256':None if value is None else hashlib.sha256(result_path.read_bytes()).hexdigest()}
        report['gates'].append(gate);base.store_json(output/'progress.json',report,replace=(output/'progress.json').exists())
        print(encode({'gate':name,'passed':bool(passed)}).decode(),flush=True)
        need(passed,'qualification gate did not pass: '+name);source_checked(source)
        return value
    try:
        inherited=execute('inherited-components',[sys.executable,str(ROOT/'tools/release/check_release.py'),
            '--output',str(output/'inherited'),'--timeout','600'],output/'inherited/result.json',
            lambda q:q['local_checks']=='passed' and q['source_id']==source['source_id'] and q['source_unchanged'])
        report['python_tests']+=inherited['python_tests'];report['javascript_tests']+=inherited['javascript']['tests']
        for name in ('client','wallet','delivery','recovery','explorer','receipts'):
            path=output/(name+'-tests.json')
            result=execute(name+'-components',[sys.executable,str(ROOT/f'tools/protocol4-{name}/tools/verify.py'),
                '--report',str(path)],path,
                lambda q:q.get('passed') is True and q['tests']>0 and q['failures']==q['errors']==q['skips']==0 and
                    sorted(q.get('successful_ids',q.get('passed_ids',[])))==sorted(q['expected_ids']))
            report['python_tests']+=result['tests']
        run_id=uuid.uuid4().hex;path=output/'local-tests.json'
        local=execute('local-components',[sys.executable,str(ROOT/'tools/local-platform/scripts/test_worker.py'),
            '--output',str(path),'--source-id',source['source_id'],'--run-id',run_id],path,
            lambda q:base.successful(q) and q['source_id']==source['source_id'] and q['run_id']==run_id and q['group']=='local_platform')
        report['python_tests']+=local['run']
        process=base.run_process(['node','--test','tools/local-platform/tests/wallet.test.cjs'],ROOT,output/'local-javascript.log',120)
        js=base.javascript_result((output/'local-javascript.log').read_bytes())
        need(process['returncode']==0 and not process['timed_out'] and not process['log_truncated'] and js['passed'],'local JavaScript did not pass')
        report['javascript_tests']+=js['tests'];report['local_javascript']={**process,**js}
        vectors=output/'p4-go-vectors.json'
        process=base.run_process([sys.executable,str(ROOT/'tools/local-platform/scripts/go_vectors.py'),'--output',str(vectors)],
                                 ROOT,output/'go-vectors.log',120)
        need(process['returncode']==0 and vectors.is_file(),'P4 response vectors unavailable')
        env={**os.environ,'GOPROXY':'off','GOTOOLCHAIN':'local','GOSUMDB':'off','GOTELEMETRY':'off'}
        with (output/'go.log').open('xb') as log:
            os.chmod(log.name,0o600)
            proc=subprocess.run(['go','run','.'],cwd=ROOT/'tools/validator-registry/upstream',env=env,
                input=vectors.read_bytes(),stdout=log,stderr=subprocess.STDOUT,timeout=180)
        raw=(output/'go.log').read_bytes();need(len(raw)<1024*1024 and proc.returncode==0,'official offline Go probe did not complete')
        oracle=json.loads(raw);need(oracle['status']=='passed' and oracle['engine_version']=='0.38.25' and
            oracle['vectors']==['protocol4-height-'+str(i) for i in range(1,5)],'official response vector identities differ')
        report['go_response_vectors']=4;private_new(output/'go-result.json',encode(oracle));source_checked(source)
        execute('p4-baseline',[sys.executable,str(ROOT/'scripts/run_protocol4_engine.py'),'--engine',str(binary),
            '--engine-sha256',PIN_SHA,'--output',str(output/'p4-baseline.json')],output/'p4-baseline.json',
            lambda q:engine_report_matches(q,source,'p4-baseline'))
        execute('p4-delivery',[sys.executable,str(ROOT/'scripts/run_protocol4_delivery_engine.py'),'--engine',str(binary),
            '--engine-sha256',PIN_SHA,'--output',str(output/'p4-delivery')],output/'p4-delivery/result.json',
            lambda q:engine_report_matches(q,source,'p4-delivery'))
        execute('p4-ledger-receipts',[sys.executable,str(ROOT/'scripts/run_protocol4_explorer_receipts_engine.py'),'--engine',str(binary),
            '--engine-sha256',PIN_SHA,'--output',str(output/'p4-ledger-receipts')],output/'p4-ledger-receipts/result.json',
            lambda q:engine_report_matches(q,source,'p4-ledger-receipts'))
        for profile in ('bootstrap-after-turnover','commit-reply-loss-at-emission'):
            execute(profile,[sys.executable,str(ROOT/'tools/protocol4-recovery/scripts/run_engine.py'),'--cometbft',str(binary),
                '--engine-sha256',PIN_SHA,'--output',str(output/profile),'--profile',profile],output/profile/'result.json',
                lambda q:revalidate_recovery(q,source,profile))
        # These run in this pinned interpreter and shut down only owned process
        # handles before disposable runtime removal. Their source is rechecked.
        for label,fn in (('local-product',run_product),('local-cli',run_cli)):
            source_checked(source);verify_engine(binary)
            result=fn(binary,output/label)
            checks=result['checks'];expected_count=37 if label=='local-product' else 9
            need(result['status']=='passed' and len(checks)==expected_count and all(c['passed'] is True for c in checks) and
                 len({c['name'] for c in checks})==expected_count,label+' did not pass')
            report['gates'].append({'name':label,'passed':True,'observed_checks':len(result['checks']),
                'result_path':label+'/result.json','result_sha256':hashlib.sha256((output/label/'result.json').read_bytes()).hexdigest()})
            print(encode({'gate':label,'passed':True}).decode(),flush=True);source_checked(source)
        report['status']='passed';report['local_automated_qualification']=True
        after=source_checked(source);report['source_identity_after']={k:after[k] for k in ('commit','tree','source_id','tracked_files')}
        report['source_unchanged']=True;verify_engine(binary);report['engine_unchanged']=True
    except Exception as exc:
        report['status']='failed';report['error_type']=type(exc).__name__
    private_new(output/'result.json',encode(report));return report
