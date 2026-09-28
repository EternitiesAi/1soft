#!/usr/bin/env python3
import argparse, json, os, stat, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from operator_kit import doctor, strict_json
def write_private(path,data):
    path=Path(os.path.abspath(path));info=path.parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:
        raise ValueError("private owned output directory required")
    raw=json.dumps(data,indent=2,sort_keys=True).encode()+b"\n"
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"wb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--plan",type=Path,required=True);p.add_argument("--operator",required=True)
    p.add_argument("--home",type=Path,required=True);p.add_argument("--source-root",type=Path,required=True)
    p.add_argument("--app-db",type=Path,required=True);p.add_argument("--cometbft",type=Path,required=True)
    p.add_argument("--proxy-app",required=True);p.add_argument("--endpoint",required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();plan=strict_json(a.plan.read_bytes())
    report=doctor(plan,a.operator,home=a.home,source_root=a.source_root,app_db=a.app_db,
                  cometbft=a.cometbft,proxy_app=a.proxy_app,endpoint=a.endpoint)
    write_private(a.output,report)
    print(json.dumps({"ready":report["ready"],"operator":report["operator"],"report_sha256":report["report_sha256"]}))
if __name__=="__main__": main()
