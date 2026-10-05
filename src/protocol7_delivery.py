"""One bounded loopback RPC call; its response cannot certify execution."""
import base64,json,urllib.error,urllib.parse,urllib.request
from protocol7_treasury import COMMAND_MAGIC,packet,parse
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,message,headers,newurl):
        raise urllib.error.HTTPError(request.full_url,code,'redirect refused; obligation remains held',headers,fp)

class LoopbackSubmit:
    def __init__(self,url):
        if type(url) is not str:raise ValueError('explicit loopback URL required')
        p=urllib.parse.urlsplit(url)
        if p.scheme not in ('http','https') or p.hostname not in ('127.0.0.1','::1','localhost') or p.username is not None or p.password is not None or p.path not in ('','/') or p.query or p.fragment or p.port is None or not 1<=p.port<=65535:raise ValueError('local development RPC URL only; no credentials, path or query')
        # Never resolve localhost through an editable hosts file or DNS.
        host='[::1]' if p.hostname=='::1' else '127.0.0.1'
        self.url=p.scheme+'://'+host+':'+str(p.port)+'/'
    def __call__(self,raw):
        if type(raw) is not bytes:raise ValueError('exact prepared wire bytes required')
        if raw[:8]==COMMAND_MAGIC:packet(raw)
        else:parse(raw)
        payload=json.dumps({'jsonrpc':'2.0','id':1,'method':'broadcast_tx_sync','params':{'tx':base64.b64encode(raw).decode('ascii')}}).encode()
        request=urllib.request.Request(self.url,data=payload,headers={'Content-Type':'application/json'})
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({}),_NoRedirect()).open(request,timeout=60) as response:
                reply=response.read(65537)
        except urllib.error.HTTPError as error:
            error.close()
            raise
        if len(reply)>65536:raise ValueError('bounded RPC response exceeded')
        v=json.loads(reply)
        if type(v) is not dict or v.get('jsonrpc')!='2.0' or v.get('id')!=1 or 'error' in v or type(v.get('result')) is not dict or type(v['result'].get('code')) is not int:raise ValueError('RPC response unavailable or malformed; obligation remains held')
        return v['result']
