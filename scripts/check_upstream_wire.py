#!/usr/bin/env python3
"""Compare actual upstream Go protobuf fixtures to the Python subset. Needs Go modules."""
import argparse
import io
import json
from pathlib import Path
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from abci_wire import Request, Response, read_frame
from commit_verifier import vote_sign_bytes, Validator, sha, merkle_root
from block_application import transaction_data_size

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,default=ROOT/'evidence/v05/upstream-wire.json')
    args=parser.parse_args()
    report={'status':'unassessed','consensus_engine_running':False,'checks':[]}
    folder=ROOT/'tools/upstream-wireprobe'
    stage='resolve_dependencies'
    try:
        subprocess.run(['go','mod','tidy'],cwd=folder,check=True,capture_output=True,text=True,timeout=180)
        stage='compile_and_run'
        result=subprocess.run(['go','run','.'],cwd=folder,check=True,capture_output=True,text=True,timeout=180)
        fixtures=json.loads(result.stdout)
        def decode(key,kind):return kind.FromString(read_frame(io.BytesIO(bytes.fromhex(fixtures[key]))))
        checks={'Info request':decode('request_info',Request).WhichOneof('value')=='info',
          'Commit request':decode('request_commit',Request).WhichOneof('value')=='commit',
          'FinalizeBlock height':decode('request_finalize',Request).finalize_block.height==7,
          'FinalizeBlock app hash':decode('response_finalize',Response).finalize_block.app_hash==b'abc',
          'Canonical vote zero time':fixtures['vote_zero_time']==vote_sign_bytes('',1,1,None,'0001-01-01T00:00:00Z').hex(),
          'Canonical vote full block':fixtures['vote_with_block']==vote_sign_bytes('eternities-wire-probe',7,2,
              {'hash':'01'*32,'parts':{'total':1,'hash':'02'*32}},'2026-09-24T12:00:00.123456789Z').hex(),
          'Header hash':fixtures['header_hash']=='f740121f553b5418c3efbd343c2dbfe9e007bb67b0d020a0741374bab65242a4',
          'Validator hash':fixtures['validator_hash']==merkle_root([Validator(sha(bytes([7])*32)[:20],bytes([7])*32,10).encoded()]).hex(),
          'Transaction framing size':int(fixtures['transaction_data_size'])==transaction_data_size([b'',b'1'*127,b'2'*128,b'3'*16384])}
        report['checks']=[{'name':k,'passed':v} for k,v in checks.items()]
        report['fixtures']=fixtures
        report['status']='passed' if all(checks.values()) else 'failed'
    except (OSError,subprocess.SubprocessError) as exc:
        report['reason']=str(exc)
        report['stage']=stage
        if stage=='compile_and_run':report['status']='failed'
        if getattr(exc,'stderr',None):report['stderr']=exc.stderr
    except Exception as exc:report.update(status='failed',reason=str(exc))
    output=args.output;output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return 0 if report['status']=='passed' else 2
if __name__=='__main__':raise SystemExit(main())
