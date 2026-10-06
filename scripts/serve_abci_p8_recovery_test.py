#!/usr/bin/env python3
"""Run-token-gated snapshot commit crash; never selected by production server."""
import hashlib, os, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from protocol8_recovery import RecoveryApplication
from protocol8_consensus import canonical,need
from serve_abci_p8_recovery import build_parser,serve

class ObservedApplication(RecoveryApplication):
    def __init__(self,*args,run_token,run_token_sha256,crash_phase,event_log,**kwargs):
        need(type(run_token) is str and len(run_token)==64 and
             hashlib.sha256(run_token.encode('ascii')).hexdigest()==run_token_sha256,
             'private recovery test token differs')
        need(crash_phase in ('observe','after_snapshot_commit'),'recovery test phase differs')
        self.phase=crash_phase;self.events=event_log
        self.event_pid=os.getpid();self.event_ticks=int(Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19])
        super().__init__(*args,**kwargs)
        self.event('startup',height=self.height,app_hash=self.app_hash)
    def event(self,kind,**values):
        raw=canonical({'kind':kind,'pid':self.event_pid,'start_ticks':self.event_ticks,**values})+b'\n'
        fd=os.open(self.events,os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_CLOEXEC|os.O_NOFOLLOW,0o600)
        try:need(os.write(fd,raw)==len(raw),'recovery event write incomplete');os.fsync(fd)
        finally:os.close(fd)
    def _after_snapshot_commit(self):
        row=self.db.execute('SELECT height,app_hash FROM p8_checkpoint WHERE id=1').fetchone()
        need(row is not None,'snapshot durable event missing')
        self.event('after_snapshot_commit',height=row[0],app_hash=row[1])
        if self.phase=='after_snapshot_commit':os._exit(96)
    def offer_snapshot(self,snapshot,app_hash):
        r=super().offer_snapshot(snapshot,app_hash)
        self.event('offer_snapshot',height=snapshot['height'],app_hash=app_hash.hex(),
                   payload_sha256=snapshot['hash'].hex(),chunks=snapshot['chunks'],result=r)
        return r
    def apply_snapshot_chunk(self,index,chunk,sender):
        r=super().apply_snapshot_chunk(index,chunk,sender)
        self.event('apply_snapshot_chunk',height=self.height,index=index,result=r['result'])
        return r

if __name__=='__main__':
    p=build_parser()
    for name in ('run-token','run-token-sha256','crash-phase'):p.add_argument('--'+name,required=True)
    p.add_argument('--event-log',type=Path,required=True);a=p.parse_args()
    serve(a,ObservedApplication,run_token=a.run_token,run_token_sha256=a.run_token_sha256,
          crash_phase=a.crash_phase,event_log=a.event_log)
