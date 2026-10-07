#!/usr/bin/env python3
"""One host-local profile of unchanged protected inventory; no effect command."""
import argparse,cProfile,math,pstats,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts')]
import protocol8_wallet_cli as c

FUNCTIONS={
    'configuration_load':c.load,
    'input_identity_checks':c.inputs,
    'native_objects_and_wallet':c.native,
    'worker_constructor_kat_identity':c.Worker.__init__,
    'worker_binary_open_hash':c.Worker._open,
    'worker_native_call':c.Worker.call,
    'helper_constructor':c.NoteController.__init__,
    'prover_constructor':c.Prover.__init__,
    'wallet_constructor':c.RecipientWallet.__init__,
    'authenticated_inventory':c.RecipientWallet.inventory}

def phases(profile):
    stats=pstats.Stats(profile).stats;result={}
    for label,function in FUNCTIONS.items():
        code=function.__code__
        matches=[v for (path,line,name),v in stats.items() if
            (path,line,name)==(code.co_filename,code.co_firstlineno,code.co_name)]
        c.require(len(matches)==1,'measured host function missing or ambiguous')
        primitive,total,self_seconds,cumulative,_=matches[0]
        c.require(type(total) is int and total>0 and all(math.isfinite(x) and x>=0 for x in (self_seconds,cumulative)),
            'bounded measured host phase required')
        result[label]={'calls':total,'primitive_calls':primitive,
            'self_seconds':round(self_seconds,9),'cumulative_seconds':round(cumulative,9)}
    return result

def run(args):
    args.command='inventory';profile=cProfile.Profile();started=time.monotonic()
    receipt,code=profile.runcall(c.execute,args)
    duration=time.monotonic()-started
    measured=phases(profile) if code==0 else {}
    return {'format':'1soft/protocol8-inventory-host-profile/v1',
        'status':'measured-authenticated-inventory' if code==0 else 'refused',
        'profiled_command':'inventory','wallet_receipt':receipt,
        'host_elapsed_seconds':round(duration,9),'phases':measured,
        'phase_durations_overlap':True,'profile_overhead_assessed':False,
        'performance_improvement_established':False,'runtime_or_lifetime_changed':False,
        'private_payloads_recorded':False,'automatic_retry':False,'freshness_established':False,
        'production_ready':False},code

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('workspace','credentials'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--genesis-sha256',required=True)
    args=parser.parse_args()
    value,code=run(args)
    sys.stdout.buffer.write(c.canonical(value)+b'\n');raise SystemExit(code)
