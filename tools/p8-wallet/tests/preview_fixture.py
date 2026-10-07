#!/usr/bin/env python3
"""Canned UI-only fixture. No proof, custody, node, transaction or file effects."""
import argparse,json,os,signal,sys,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3];sys.path[:0]=[str(ROOT/'tools/p8-wallet/src'),str(ROOT/'tools/payment-console/src'),str(ROOT/'src')]
from wallet_app import Service,Server
from payment_console import guide_view
class Preview(Service):
    def __init__(self,*a):super().__init__(*a);self.prepared=False;self.attempts=0;self.completed=False
    def invoke(self,command,extra,confirmation):
        fields=dict(zip(extra[::2],extra[1::2]));txid='44'*32;wire='55'*32
        inv={'format':'1soft/protocol8-recipient-wallet/v1','wallet_id':'66'*32,'recipient_key':'77'*32,'revision':2,'as_of_height':4,'notes':['11'*32,'22'*32],'obligations':[{'input':'11'*32,'request':'33'*32,'txid':txid,'attempts':self.attempts,'completed':self.completed}] if self.prepared else [],'freshness_established':False,'automatic_retry':False}
        view={'state':'stub-completed','message':'Canned interface fixture only. No financial effect.','can_submit':False}
        display=''
        if command=='guide':view=guide_view(inv,inv['wallet_id'],self.genesis)
        elif command=='prepare':
            if confirmation=='PREPARE '+fields['--commitment']:
                self.prepared=True;view|={'state':'prepared-not-attempted','txid':txid}
            else:view|={'state':'preparation-cancelled'}
        elif command=='review':
            view|={'state':'reviewed','can_submit':self.attempts==0 and self.prepared,'review':{'wire_sha256':wire}}
            display='Canned UI fixture only\nRecipient: '+'88'*32+'\nAmount: 4 atomic units\nNo real transaction or native verification.'
        elif command=='submit':
            if confirmation=='SUBMIT '+txid+' '+wire and self.attempts==0:self.attempts=1
            view|={'state':'attempted-outcome-unknown','txid':txid,'attempts':self.attempts}
        elif command=='status':view|={'state':'attempted-outcome-unknown','txid':txid,'attempts':self.attempts}
        elif command=='reconcile':self.completed=True;view|={'state':'executed-exact','txid':txid,'attempts':self.attempts,'as_of_height':7}
        return {'format':'1soft/local-wallet-action/v1','command':command,'status':'console-completed','console_receipt':{'view':view},'private_display':display,'process':{'pid':os.getpid(),'process_reaped':True},'fixture':True}
def main():
    p=argparse.ArgumentParser();p.add_argument('--receipt',type=Path,required=True);a=p.parse_args();assert not a.receipt.exists()
    with tempfile.TemporaryDirectory(prefix='1soft-ui-only-') as name:
        root=Path(name);service=Preview(root/'workspace',root/'credentials','aa'*32,'http://127.0.0.1:12345',root/'journal');server=Server(service)
        value={'origin':server.origin,'pid':os.getpid(),'start_ticks':int(Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]),'fixture':'canned UI only; no native/custody/node effects'}
        a.receipt.write_text(json.dumps(value,indent=2)+'\n');print(json.dumps(value),flush=True)
        signal.signal(signal.SIGTERM,lambda *args:(_ for _ in ()).throw(KeyboardInterrupt()))
        try:server.serve_forever(poll_interval=.1)
        except KeyboardInterrupt:pass
        finally:server.server_close()
if __name__=='__main__':main()
