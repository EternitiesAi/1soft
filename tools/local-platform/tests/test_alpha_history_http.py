"""Actual loopback HTTP format boundary with key-free opaque transport fixtures.

These bytes test download framing, not encrypted archive validity or consensus.
"""
from contextlib import contextmanager,closing
import http.client
import io
import json
import threading
import unittest
from platform_http import server

class AlphaHistoryHttpTests(unittest.TestCase):
    def setUp(self):
        self.raw=b'1SOFTP4A1\nopaque public transport fixture'
        self.format='alpha-v1';self.declared=None;self.omit_format=False
        self.cleaned=0;self.read_sizes=[]
        owner=self
        class Source(io.BytesIO):
            def read(inner,n=-1):
                owner.read_sizes.append(n);return super().read(n)
        class Service:
            def __enter__(inner):return inner
            def __exit__(inner,*args):pass
            @contextmanager
            def backup_history(inner,password):
                assert password==b'public backup passphrase'
                with Source(owner.raw) as source:
                    item={'source':source,'size':len(owner.raw) if owner.declared is None else owner.declared}
                    if not owner.omit_format:item['format']=owner.format
                    try:yield item
                    finally:owner.cleaned+=1
        self.web=server(Service,port=0)
        self.thread=threading.Thread(target=lambda:self.web.serve_forever(poll_interval=.01),daemon=True)
        self.thread.start();self.addCleanup(self.close_server);self.origin=f'http://127.0.0.1:{self.web.server_port}'
        code,raw,_=self.call('GET','/api/session');self.assertEqual(code,200)
        self.token=json.loads(raw)['csrf']
    def close_server(self):
        self.web.shutdown();self.web.server_close();self.thread.join(2)
        self.assertFalse(self.thread.is_alive())
    def call(self,method,path,body=None):
        headers={'Origin':self.origin}
        if method=='POST':headers|={'Content-Type':'application/json','X-1soft-CSRF':self.token}
        with closing(http.client.HTTPConnection('127.0.0.1',self.web.server_port,timeout=5)) as c:
            c.request(method,path,body=None if body is None else json.dumps(body),headers=headers)
            r=c.getresponse();return r.status,r.read(),dict(r.getheaders())
    def download(self):
        return self.call('POST','/api/backup-history',{'passphrase':'public backup passphrase',
            'repeat_passphrase':'public backup passphrase','scope_confirmed':True})
    def test_alpha_attachment_header_magic_filename_and_closed_source(self):
        code,raw,headers=self.download()
        self.assertEqual(code,200);self.assertEqual(raw,self.raw)
        self.assertEqual(headers['X-1Soft-Backup-Format'],'alpha-v1')
        self.assertEqual(headers['Content-Disposition'],'attachment; filename="1soft-recovery-history.p4alpha"')
        self.assertEqual(headers['Content-Length'],str(len(raw)))
        self.assertEqual(self.call('GET','/api/session')[0],200)
        self.assertEqual(self.cleaned,1)
    def test_absent_profile_preserves_legacy_format_and_limit(self):
        self.omit_format=True;self.raw=b'1SOFTP4B3\nopaque public legacy fixture'
        code,raw,headers=self.download()
        self.assertEqual(code,200);self.assertEqual(raw,self.raw)
        self.assertNotIn('X-1Soft-Backup-Format',headers)
        self.assertEqual(headers['Content-Disposition'],'attachment; filename="1soft-recovery-history.p4b3"')
        self.declared=16*1024*1024+1
        self.assertEqual(self.download()[0],400)
    def test_unknown_profile_or_mixed_magic_refuses_before_binary_reply(self):
        original=self.raw
        for fmt,raw,omit in [('alpha-v2',original,False),(None,original,False),
                ('alpha-v1',b'1SOFTP4B3\nwrong profile',False),('alpha-v1',original,True)]:
            self.format,self.raw,self.omit_format=fmt,raw,omit
            with self.subTest(fmt=fmt,omit=omit):
                code,_,headers=self.download();self.assertEqual(code,400)
                self.assertEqual(headers['Content-Type'],'application/json')
    def test_alpha_complete_above_legacy_cap_and_oversize_declared_refusal(self):
        self.raw=b'1SOFTP4A1\n'+b'x'*(16*1024*1024-9)
        code,raw,headers=self.download();self.assertEqual(code,200)
        self.assertEqual(len(raw),16*1024*1024+1)
        self.assertLessEqual(max(self.read_sizes),65536)
        self.declared=180*1024*1024+1;self.read_sizes=[]
        self.assertEqual(self.download()[0],400)
        self.assertEqual(self.read_sizes,[])
        self.declared=True
        self.assertEqual(self.download()[0],400)

if __name__=='__main__':unittest.main()
