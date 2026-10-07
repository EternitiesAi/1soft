"""Actual local HTTP/session guards; protected financial child is a labeled stub."""
import http.client,json,secrets,sys,tempfile,threading,unittest
from unittest.mock import patch
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3];sys.path.insert(0,str(ROOT/'tools/p8-wallet/src'))
from wallet_app import Service,Server,Duplicate,n

class HTTP(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();p=Path(self.temp.name)
        self.service=Service(p/'config',p/'credentials','ab'*32,'http://127.0.0.1:12345',p/'journal')
        self.executed=[]
        def stub(command,extra,confirmation):
            self.executed.append((command,extra,confirmation))
            return {'command':command,'status':'stub-financial-boundary','process':{'pid':1,'process_reaped':True}}
        self.service.invoke=stub
        self.server=Server(self.service);self.thread=threading.Thread(target=self.server.serve_forever);self.thread.start()
    def tearDown(self):self.server.shutdown();self.server.server_close();self.thread.join();self.temp.cleanup()
    def action(self,command='guide',fields=None,confirmation='',nonce=None):
        return {'command':command,'fields':fields or {},'confirmation':confirmation,'nonce':nonce or secrets.token_hex(24)}
    def post(self,body,path='/api/action',**changes):
        headers={'Origin':self.server.origin,'X-1soft-Session':self.service.token,'Content-Type':'application/json'};headers.update(changes)
        headers={k:v for k,v in headers.items() if v is not None}
        con=http.client.HTTPConnection(*self.server.server_address,timeout=5)
        raw=body if type(body) is str else json.dumps(body)
        con.request('POST',path,raw,headers);reply=con.getresponse();status=reply.status;data=reply.read();con.close();return status,json.loads(data)
    def test_real_same_origin_action_reaches_only_stub_child(self):
        status,_=self.post(self.action());self.assertEqual(status,200);self.assertEqual(len(self.executed),1)
    def test_foreign_origin_refused_before_child(self):
        status,_=self.post(self.action(),Origin='https://foreign.invalid');self.assertEqual(status,403);self.assertFalse(self.executed)
    def test_missing_origin_refused(self):self.assertEqual(self.post(self.action(),Origin=None)[0],403)
    def test_missing_or_other_session_refused(self):
        for token in (None,secrets.token_hex(32)):
            with self.subTest(token_present=token is not None):self.assertEqual(self.post(self.action(),**{'X-1soft-Session':token})[0],403)
        self.assertFalse(self.executed)
    def test_rebound_host_and_crosssite_refused(self):
        for change in ({'Host':'wallet.attacker.invalid'},{'Sec-Fetch-Site':'cross-site'}):
            self.assertEqual(self.post(self.action(),**change)[0],403)
        self.assertFalse(self.executed)
    def test_duplicate_action_id_cannot_execute_twice(self):
        body=self.action();self.assertEqual(self.post(body)[0],200);self.assertEqual(self.post(body)[0],409);self.assertEqual(len(self.executed),1)
    def test_busy_refuses_without_queuing_or_claiming(self):
        body=self.action();self.service.lock.acquire()
        try:self.assertEqual(self.post(body)[0],409)
        finally:self.service.lock.release()
        self.assertFalse(self.executed);self.assertNotIn(body['nonce'],self.service.claimed)
        self.assertEqual(self.post(body)[0],200)
    def test_unknown_and_private_context_overrides_refused(self):
        for body in (self.action('sign-raw'),self.action(fields={'credentials':'private'}),self.action()|{'workspace':'other'}):
            self.assertEqual(self.post(body)[0],400)
        self.assertFalse(self.executed)
    def test_duplicate_json_field_and_oversized_body_refused(self):
        self.assertEqual(self.post('{"command":"guide","command":"submit"}')[0],400)
        self.assertEqual(self.post('x'*16385)[0],400);self.assertFalse(self.executed)
    def test_prepare_maps_private_input_and_exact_confirmation(self):
        values={'commitment':'11'*32,'destination':'22'*32,'payment':'4','valid_until':'32','payment_expiry':'56'}
        confirmation='PREPARE '+values['commitment'];self.assertEqual(self.post(self.action('prepare',values,confirmation))[0],200)
        command,argv,token=self.executed[0];self.assertEqual(command,'prepare');self.assertEqual(token,confirmation)
        mapped=dict(zip(argv[::2],argv[1::2]));self.assertEqual(mapped['--payment'],'4');self.assertRegex(mapped['--request'],r'^[0-9a-f]{64}$')
        self.assertGreater(int.from_bytes(bytes.fromhex(mapped['--request']),'little'),0)
        self.assertLess(int.from_bytes(bytes.fromhex(mapped['--request']),'little'),n.MODULUS)
        self.assertNotIn('destination',str(self.service.events));self.assertNotIn(values['destination'],str(self.service.events))
    def test_prepare_request_is_canonical_at_both_entropy_extremes(self):
        values={'commitment':'11'*32,'destination':'22'*32,'payment':'4','valid_until':'32','payment_expiry':'56'}
        for entropy,expected in ((0,1),(n.MODULUS-2,n.MODULUS-1)):
            with self.subTest(entropy=entropy),patch('wallet_app.secrets.randbelow',return_value=entropy) as random:
                argv=self.service.arguments('prepare',values)
                random.assert_called_once_with(n.MODULUS-1)
                request=dict(zip(argv[::2],argv[1::2]))['--request']
                self.assertEqual(int.from_bytes(n.field(request),'little'),expected)
    def test_submit_maps_original_journal_and_endpoint(self):
        ident='11'*32;confirmation='SUBMIT '+ident+' '+'22'*32
        self.assertEqual(self.post(self.action('submit',{'txid':ident},confirmation))[0],200)
        mapped=dict(zip(self.executed[0][1][::2],self.executed[0][1][1::2]));self.assertEqual(mapped['--journal'],str(self.service.journal));self.assertEqual(mapped['--endpoint'],self.service.endpoint)
    def test_integer_float_boolean_and_overflow_refused(self):
        base={'commitment':'11'*32,'destination':'22'*32,'payment':'4','valid_until':'32','payment_expiry':'56'}
        for value in (4,True,4.0,'0','-1','1e3',str(2**64)):
            with self.subTest(value=value):self.assertEqual(self.post(self.action('prepare',base|{'payment':value}))[0],400)
        self.assertFalse(self.executed)
    def test_conflicting_import_source_refused(self):
        values={'opening':'/private/opening','source':'genesis','wire':'/private/wire','output_index':'10'}
        self.assertEqual(self.post(self.action('import-note',values))[0],400);self.assertFalse(self.executed)
    def test_private_session_page_has_cache_frame_and_resource_guards(self):
        con=http.client.HTTPConnection(*self.server.server_address);con.request('GET','/');r=con.getresponse();raw=r.read().decode()
        self.assertEqual(r.status,200);self.assertEqual(r.getheader('Cache-Control'),'no-store');self.assertEqual(r.getheader('X-Frame-Options'),'DENY');self.assertIn(self.service.token,raw)
        self.assertNotIn(str(self.service.credentials),raw);self.assertIn("frame-ancestors 'none'",r.getheader('Content-Security-Policy'));con.close()
    def test_cross_session_token_cannot_act_on_new_server(self):
        other=Service(self.service.workspace,self.service.credentials,self.service.genesis,self.service.endpoint,self.service.journal)
        self.assertNotEqual(other.token,self.service.token);self.assertEqual(self.post(self.action(),**{'X-1soft-Session':other.token})[0],403)
    def test_demo_context_requires_session_and_never_invokes_child(self):
        self.service.demo_inputs=lambda:{'forms':{},'message':'inputs only'}
        self.assertEqual(self.post({},path='/api/context',Origin=None)[0],403)
        self.assertEqual(self.post({},path='/api/context')[0],200)
        self.assertFalse(self.executed);self.assertFalse(self.service.claimed)
    def test_context_unavailable_by_default_and_closed_body(self):
        self.assertEqual(self.post({},path='/api/context')[0],400)
        self.service.demo_inputs=lambda:{'forms':{}}
        self.assertEqual(self.post({'submit':True},path='/api/context')[0],400)
        self.assertFalse(self.executed)
if __name__=='__main__':unittest.main()
