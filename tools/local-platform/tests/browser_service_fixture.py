#!/usr/bin/env python3
"""Owned loopback browser fixture: actual application/API, synthetic committee/RPC.

No CometBFT, user workspace, production keys, installation or public listener.
Only generated, public deterministic development fixtures are used and removed.
"""
from pathlib import Path
import json
import shutil
import sys
import tempfile
import threading
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/p) for p in ('src','scripts','tools/validator-transition/src',
 'tools/protocol4-client/src','tools/protocol4-wallet/src','tools/protocol4-delivery/src',
 'tools/protocol4-explorer/src','tools/protocol4-receipts/src','tools/protocol4-custody/src','tools/local-platform/src',
 'tools/protocol4-wallet/tests','tools/protocol4-delivery/tests','tools/protocol4-client/tests')]
from delivery_fixture import Fixture
from platform_service import PlatformService
from platform_http import server
from backup_browser_audit import audit_download

def main():
    with tempfile.TemporaryDirectory(prefix='1soft-browser-fixture-') as name:
        root=Path(name);root.chmod(0o700)
        downloads=root/'downloads';downloads.mkdir(mode=0o700);audits=[]
        node=root/'node';node.mkdir(mode=0o700)
        fx=Fixture(node,mode='normal');web=None;thread=None
        try:
            workspace=root/'platform';workspace.mkdir(mode=0o700)
            for role in ('owner','raven','atlas'):
                shutil.copyfile(node/(role+'.pem'),workspace/(role+'.pem'))
                (workspace/(role+'.pem')).chmod(0o600)
            roles={n:dict(payer=fx.chain.payer,grant_id='' if n=='owner' else n,vault=n+'.pem')
                   for n in ('owner','raven','atlas')}
            def service(**kw):
                return PlatformService(workspace,fx.chain.genesis,fx.chain.policy,
                    fx.url,roles,clock=fx.chain.clock,**kw)
            with service(create=True) as svc:
                svc.import_checkpoint(fx.proof,expected_tip=None);svc.sync(expected_revision=None)
            web=server(service,port=0)
            thread=threading.Thread(target=lambda:web.serve_forever(poll_interval=.01),daemon=True)
            thread.start()
            print(json.dumps(dict(schema=1,origin=f'http://127.0.0.1:{web.server_port}',
                download_dir_linux=str(downloads),download_dir_windows='\\\\wsl.localhost\\Ubuntu'+str(downloads).replace('/','\\'),
                scope='actual P4 application and guarded API; synthetic committee/scripted RPC; no CometBFT')),flush=True)
            # EOF and explicit stop both close this fixture only.
            for line in sys.stdin:
                if line.strip()=='stop':break
                q=json.loads(line)
                assert type(q) is dict and set(q)=={'operation','filename','stage'} and q['operation']=='audit-backup'
                audit=audit_download(service,downloads,q['filename'],q['stage']);audits.append(audit)
                print(json.dumps({'backup_audit':audit}),flush=True)
            assert [a['stage'] for a in audits]==['signed-pending','receipt-complete']
            print(json.dumps(dict(schema=1,submissions=len(fx.submissions),backup_audits=audits)),flush=True)
        finally:
            if web is not None:web.shutdown();web.server_close()
            if thread is not None:thread.join(2);assert not thread.is_alive()
            fx.close()
    print(json.dumps(dict(schema=1,owned_cleanup=True)),flush=True)

if __name__=='__main__':main()
