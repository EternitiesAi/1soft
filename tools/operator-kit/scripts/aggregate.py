#!/usr/bin/env python3
import argparse, json, os, stat, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from operator_kit import aggregate, strict_json
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--plan",type=Path,required=True);p.add_argument("--report",type=Path,action="append",required=True)
    p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    plan=strict_json(a.plan.read_bytes());reports=[strict_json(x.read_bytes()) for x in a.report]
    result=aggregate(plan,reports);raw=json.dumps(result,indent=2,sort_keys=True).encode()+b"\n"
    path=a.output.absolute();info=path.parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:
        raise ValueError("private owned output directory required")
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
    print(json.dumps({"ready_for_operator_fault_drills":True,"report_sha256":result["report_sha256"]}))
if __name__=="__main__": main()
