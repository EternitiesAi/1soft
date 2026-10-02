"""Real historical pair exports and guarded downloads; no engines."""
from contextlib import contextmanager
import hashlib
import http.client
import json
import unittest
from unittest.mock import patch

import test_service as service_helpers
import test_http as http_helpers
from p4_custody import RecoveryArchive, restore_backup

SECRET = b'public historical backup passphrase'


class HistoryServiceTests(unittest.TestCase):
    setUp = service_helpers.ServiceTests.setUp
    tearDown = service_helpers.ServiceTests.tearDown
    open = service_helpers.ServiceTests.open
    request = service_helpers.ServiceTests.request
    sign = service_helpers.ServiceTests.sign
    send = service_helpers.ServiceTests.send

    def rows(self):
        return {name:tuple(obj.db.iterdump()) for name,obj in
                ((name,getattr(self.service,name)) for name in ('wallet','delivery','store','book'))}

    def download(self):
        self.assertTrue(callable(getattr(self.service,'backup_history',None)), 'historical backup service is missing')
        with self.service.backup_history(SECRET) as item:
            raw=item['source'].read()
            self.assertEqual(len(raw),item['size'])
            self.assertEqual(hashlib.sha256(raw).hexdigest(),item['sha256'])
            self.assertEqual(b'1SOFTP4B3\n',raw[:10])
        self.assertFalse(list(self.workspace.glob('.1soft-history-*')))
        backup=self.root/'download.p4b3';backup.write_bytes(raw);backup.chmod(0o600)
        restored=self.root/'history.sqlite'
        restore_backup(backup,restored,self.fx.chain.genesis,self.fx.chain.policy,SECRET)
        return RecoveryArchive(restored,self.fx.chain.genesis,self.fx.chain.policy)

    def test_expired_shared_history_keeps_all_roles_originals_and_unknown_hold(self):
        a=self.request('58','Hidden generic Raven');self.sign(a)
        b=self.request('38','Other role Atlas');self.sign(b,'atlas')
        original_a=self.service.recover(a);original_b=self.service.recover(b)
        self.fx.mode='drop';self.send(a)
        self.fx.chain.now+=3700*10**9
        self.assertFalse(self.service.state()['current_evidence_available'])
        before=self.rows();reads=list(self.fx.reads);submissions=list(self.fx.submissions)
        with patch('p4_wallet._load_vault',side_effect=AssertionError('vault accessed')):
            with self.download() as archive:
                view=archive.inspect();self.assertEqual('100',view['pending_debit_units'])
                self.assertEqual(2,len(view['decisions']))
                self.assertEqual(original_a,archive.recover(self.service.book.selected(a)['decision_id'],payer=self.fx.chain.payer,grant_id='raven'))
                self.assertEqual(original_b,archive.recover(self.service.book.selected(b)['decision_id'],payer=self.fx.chain.payer,grant_id='atlas'))
                self.assertFalse(view['current_spending_authority']);self.assertFalse(view['dispatch_enabled'])
        self.assertEqual(before,self.rows());self.assertEqual(reads,self.fx.reads);self.assertEqual(submissions,self.fx.submissions)

    def test_failure_cleans_owned_directory_and_preserves_journals(self):
        self.assertTrue(callable(getattr(self.service,'backup_history',None)), 'historical backup service is missing')
        before=self.rows()
        for target in ('max_capture_blob_bytes','max_backup_bytes'):
            with patch('platform_service.HISTORY_CAPTURE_BYTES' if target=='max_capture_blob_bytes' else 'platform_service.HISTORY_BACKUP_BYTES',1):
                with self.assertRaises(ValueError):
                    with self.service.backup_history(SECRET):self.fail('oversize accepted')
            self.assertFalse(list(self.workspace.glob('.1soft-history-*')))
            self.assertEqual(before,self.rows())
        self.service.wallet.db.execute('UPDATE decisions SET payload=?',(b'{}',))
        # With no decisions yet, corrupt the retained proof instead.
        self.service.wallet.db.execute('UPDATE observations SET payload=?',(b'{}',))
        with self.assertRaises(ValueError):
            with self.service.backup_history(SECRET):self.fail('corrupt history accepted')
        self.assertFalse(list(self.workspace.glob('.1soft-history-*')))


class HistoryHttpTests(unittest.TestCase):
    setUp = http_helpers.HttpTests.setUp
    tearDown = http_helpers.HttpTests.tearDown
    call = http_helpers.HttpTests.call
    request = http_helpers.HttpTests.request

    def service(self,**kw):
        self.opens=getattr(self,'opens',0)+1
        return http_helpers.HttpTests.service(self,**kw)

    def body(self,**overrides):
        return dict(passphrase=SECRET.decode(),repeat_passphrase=SECRET.decode(),scope_confirmed=True)|overrides

    def test_attachment_is_complete_private_format_three_and_cleans(self):
        before=self.opens
        original=self.web.RequestHandlerClass.reply_headers
        checked=[]
        def headers(handler,code,size,*args,**kwargs):
            if code==200:
                folders=list(self.workspace.glob('.1soft-history-*'));self.assertEqual(1,len(folders))
                self.assertEqual(0o700,folders[0].stat().st_mode&0o777)
                file=folders[0]/'history.p4b3';self.assertEqual(0o600,file.stat().st_mode&0o777)
                self.assertEqual(size,file.stat().st_size);self.assertEqual(b'1SOFTP4B3\n',file.read_bytes()[:10])
                checked.append(True)
            return original(handler,code,size,*args,**kwargs)
        with patch.object(self.web.RequestHandlerClass,'reply_headers',headers):
            code,raw,h=self.call('POST','/api/backup-history',self.body())
        self.assertEqual(200,code,raw);self.assertEqual(before+1,self.opens)
        self.assertEqual([True],checked)
        self.assertEqual(b'1SOFTP4B3\n',raw[:10]);self.assertEqual('application/octet-stream',h['Content-Type'])
        self.assertEqual(str(len(raw)),h['Content-Length']);self.assertEqual('no-store',h['Cache-Control'])
        self.assertEqual('attachment; filename="1soft-recovery-history.p4b3"',h['Content-Disposition'])
        self.assertIn("default-src 'none'",h['Content-Security-Policy']);self.assertEqual('DENY',h['X-Frame-Options'])
        self.assertNotIn(SECRET,raw)
        self.assertEqual(200,self.call('GET','/api/session')[0])  # Sequential handler cleanup barrier.
        self.assertFalse(list(self.workspace.glob('.1soft-history-*')))
        self.assertEqual([],self.fx.submissions)

    def test_input_types_utf8_match_and_scope_refuse_before_service(self):
        cases=[self.body(passphrase=None),self.body(repeat_passphrase=16),self.body(scope_confirmed=1),
               self.body(scope_confirmed=False),self.body(passphrase='a'*15),
               self.body(passphrase='a'*1025),self.body(repeat_passphrase='different passphrase'),
               self.body(passphrase='界'*342,repeat_passphrase='界'*342),self.body(passphrase='\ud800')]
        for body in cases:
            before=self.opens
            code,raw,_=self.call('POST','/api/backup-history',body)
            self.assertEqual(400,code,raw);self.assertEqual(before,self.opens)
            self.assertNotIn(SECRET,raw);self.assertFalse(list(self.workspace.glob('.1soft-history-*')))

    def test_guards_and_exact_fields_refuse_before_service(self):
        cases=[(self.body(),{'Origin':'null'},403),(self.body(),{'Host':'localhost'},403),
               (self.body(),{'Sec-Fetch-Site':'cross-site'},403),(self.body(),{'X-1soft-CSRF':'bad'},403),
               (self.body(),{'Content-Type':'text/plain'},415),(self.body(),{'Content-Encoding':'gzip'},415),
               (self.body()|{'format_version':3},{},400),(self.body()|{'output':'/tmp/x'},{},400)]
        for body,headers,expected in cases:
            before=self.opens
            self.assertEqual(expected,self.call('POST','/api/backup-history',body,headers=headers)[0])
            self.assertEqual(before,self.opens)
        before=self.opens
        self.assertEqual(400,self.call('POST','/api/backup-history',raw=b'{"passphrase":"x","passphrase":"y"}')[0])
        self.assertEqual(413,self.call('POST','/api/backup-history',raw=b'x'*65537)[0])
        self.assertEqual(404,self.call('GET','/api/backup-history')[0]);self.assertEqual(before,self.opens)

    def test_completed_request_cleans_owned_file(self):
        conn=http.client.HTTPConnection('127.0.0.1',self.web.server_port,timeout=5)
        conn.request('POST','/api/backup-history',body=json.dumps(self.body()),headers={
            'Origin':self.origin,'Sec-Fetch-Site':'same-origin','X-1soft-CSRF':self.token,'Content-Type':'application/json'})
        response=conn.getresponse();self.assertEqual(200,response.status)
        response.read();response.close()
        conn.close()
        self.assertEqual(200,self.call('GET','/api/session')[0])  # Prior handler has completed.
        self.assertFalse(list(self.workspace.glob('.1soft-history-*')))

    def test_duplicate_headers_and_transfer_encoding_refuse_before_service(self):
        cases=[('Host',403),('Origin',403),('X-1soft-CSRF',403),('Sec-Fetch-Site',403),
               ('Content-Length',400),('Content-Type',415),('Transfer-Encoding',415)]
        for duplicate,expected in cases:
            before=self.opens;raw=json.dumps(self.body()).encode()
            conn=http.client.HTTPConnection('127.0.0.1',self.web.server_port,timeout=5)
            conn.putrequest('POST','/api/backup-history',skip_host=True,skip_accept_encoding=True)
            headers={'Host':f'127.0.0.1:{self.web.server_port}','Origin':self.origin,
                'X-1soft-CSRF':self.token,'Sec-Fetch-Site':'same-origin',
                'Content-Length':str(len(raw)),'Content-Type':'application/json'}
            for key,value in headers.items():conn.putheader(key,value)
            conn.putheader(duplicate,headers.get(duplicate,'chunked'));conn.endheaders(raw)
            response=conn.getresponse();self.assertEqual(expected,response.status)
            response.read();response.close();conn.close()
            self.assertEqual(before,self.opens)
        self.assertFalse(list(self.workspace.glob('.1soft-history-*')))

    def test_mid_body_read_failure_closes_without_second_reply_and_cleans(self):
        original=self.web.RequestHandlerClass.history_reply
        replies=[];original_headers=self.web.RequestHandlerClass.reply_headers
        def headers(handler,*args,**kwargs):
            replies.append(args[0]);return original_headers(handler,*args,**kwargs)
        def interrupted(handler,item):
            source=item['source']
            class FailingSource:
                calls=0
                def read(inner,n):
                    inner.calls+=1
                    if inner.calls==1:return source.read(min(n,10))
                    raise OSError('injected mid-body source read failure')
            return original(handler,{**item,'source':FailingSource()})
        with patch.object(self.web.RequestHandlerClass,'reply_headers',headers),patch.object(self.web.RequestHandlerClass,'history_reply',interrupted):
            conn=http.client.HTTPConnection('127.0.0.1',self.web.server_port,timeout=5)
            conn.request('POST','/api/backup-history',body=json.dumps(self.body()),headers={
                'Origin':self.origin,'X-1soft-CSRF':self.token,'Content-Type':'application/json'})
            response=conn.getresponse();self.assertEqual(200,response.status)
            with self.assertRaises(http.client.IncompleteRead) as caught:response.read()
            self.assertEqual(b'1SOFTP4B3\n',caught.exception.partial)
            response.close();conn.close()
        self.assertEqual([200],replies)
        self.assertEqual(200,self.call('GET','/api/session')[0])
        self.assertFalse(list(self.workspace.glob('.1soft-history-*')))


if __name__=='__main__':unittest.main()
