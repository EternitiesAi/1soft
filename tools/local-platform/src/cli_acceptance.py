"""Actual one-command startup, encrypted vault entry and cold CLI recovery."""
import hashlib
import http.client
import os
from pathlib import Path
import secrets
import select
import signal
import subprocess
import sys
import tempfile
import time

from block_application import encode
from commit_verifier import load_json
from local_devnet import ROOT,WorkspaceLock,read_private,private_new
from p4_evidence import need


def run_cli(engine,output):
    output=Path(output).absolute();output.mkdir(mode=0o700,exist_ok=False)
    report={'schema':1,'status':'running','checks':[],'scope':'actual CLI on a private four-validator development network',
            'browser_interaction_executed':False,'real_funds':False,'public_release_ready':False}
    child=None;handles=[];password=secrets.token_urlsafe(32).encode()
    def check(name,yes):
        report['checks'].append({'name':name,'passed':bool(yes)});need(yes,name)
    def stop():
        if child is None:return
        if child.poll() is None:child.terminate()
        try:child.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid,signal.SIGKILL);child.wait(timeout=10)
            raise ValueError('owned CLI did not stop gracefully')
        need(child.returncode==0,'owned CLI exited with failure')
    try:
        with tempfile.TemporaryDirectory(prefix='one-local-cli-') as temporary:
            workspace=Path(temporary)/'wallet'
            def launch(command,secret=None):
                nonlocal child
                stderr=(output/(command+'-stderr.log')).open('xb')
                os.chmod(stderr.name,0o600);handles.append(stderr)
                child=subprocess.Popen([sys.executable,str(ROOT/'tools/local-platform/scripts/1soft.py'),command,
                    '--workspace',str(workspace),'--engine',str(engine),'--port','0'],stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,stderr=stderr,start_new_session=True,
                    env={**os.environ,'PYTHONPATH':'','PYTHONDONTWRITEBYTECODE':'1'})
                if secret is not None:child.stdin.write(secret+b'\n'+secret+b'\n');child.stdin.flush()
                child.stdin.close();deadline=time.monotonic()+100
                while time.monotonic()<deadline:
                    if select.select([child.stdout],[],[],.25)[0]:
                        line=child.stdout.readline(65537)
                        need(0<len(line)<=65536,'CLI readiness output is incomplete')
                        raw=load_json(line,max_bytes=65536)
                        if raw.get('status')=='local_development_wallet_running':
                            private_new(output/(command+'-ready.json'),encode(raw));return raw
                    need(child.poll() is None,'CLI stopped before readiness')
                raise ValueError('CLI did not become ready')
            try:
                ready=launch('new',password)
                check('single new command creates and starts four real validators',ready['validator_count']==4)
                policy=read_private(workspace/'policy.json');config=read_private(workspace/'workspace.json')
                def call(path,value=None,raw=False):
                    port=int(ready['url'].split(':')[2].rstrip('/'));origin=ready['url'].rstrip('/')
                    conn=http.client.HTTPConnection('127.0.0.1',port,timeout=55)
                    headers={'Origin':origin,'Sec-Fetch-Site':'same-origin'}
                    if value is not None:headers.update({'Content-Type':'application/json','X-1soft-CSRF':csrf})
                    try:
                        conn.request('POST' if value is not None else 'GET',path,
                                     None if value is None else encode(value),headers)
                        response=conn.getresponse();body=response.read(17*1024*1024)
                        need(response.status==200,'CLI product route did not complete')
                        return body if raw else load_json(body,max_bytes=17*1024*1024)
                    finally:conn.close()
                csrf=call('/api/session')['csrf'];state=call('/api/state')
                check('CLI serves a verified development wallet',state['current_evidence_available'])
                recipient=state['ledger']['grants'][0]['recipients'][0]
                rid=call('/api/create-request',{'recipient':recipient,'units':'10','note':'CLI durable recovery','lifetime_seconds':600})['request_id']
                prepared=call('/api/prepare',{'request_id':rid,'role':'raven','valid_until':state['wallet']['state_height']+32})
                call('/api/sign',{'request_id':rid,'role':'raven','review_json':prepared['review_json'],
                     'confirmation':prepared['confirmation'],'password':password.decode()})
                original=call('/api/original/'+rid,raw=True);state=call('/api/state')
                check('one canonical wallet records a fee-inclusive unsigned-network obligation',
                      state['wallet']['pending_debit_units']=='12' and not state['requests'][0]['delivery']['attempt_recorded'])
                stop();remaining=child.stdout.read();private_new(output/'new-tail.log',remaining)
                check('first CLI shutdown retains data and releases all child locks',
                      all(not (workspace/f'app{i}/a.sock').exists() for i in range(4)))
                with WorkspaceLock(workspace):pass
                child=None
                ready=launch('start')
                csrf=call('/api/session')['csrf'];reopened=call('/api/state')
                check('start resumes the exact workspace without asking for a vault password',
                      reopened['wallet']['pending_debit_units']=='12' and
                      read_private(workspace/'policy.json')==policy and read_private(workspace/'workspace.json')==config)
                check('cold CLI recovery returns the exact original signed payment',call('/api/original/'+rid,raw=True)==original)
                check('cold CLI recovery cannot invent a submission or execution',
                      not reopened['requests'][0]['delivery']['attempt_recorded'] and reopened['requests'][0]['stage']=='signed_reserved')
                private_new(output/'state-after-cli-restart.json',encode(reopened))
                stop();private_new(output/'start-tail.log',child.stdout.read())
                check('second CLI shutdown preserves journals and removes owned sockets',
                      all(not (workspace/f'app{i}/a.sock').exists() for i in range(4)))
                with WorkspaceLock(workspace):pass
                child=None
                for handle in handles:handle.flush()
                check('disposable vault password never appears in raw CLI outputs',
                      all(password not in p.read_bytes() for p in output.iterdir() if p.is_file()))
                report['status']='passed'
            finally:
                if child is not None:
                    try:stop()
                    except ValueError:report['status']='failed'
    except Exception as exc:
        report['status']='failed';report['error_type']=type(exc).__name__
    finally:
        password=None
        for handle in handles:handle.close()
        private_new(output/'result.json',encode(report))
    return report
