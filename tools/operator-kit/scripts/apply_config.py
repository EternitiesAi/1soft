#!/usr/bin/env python3
import argparse, os, stat, sys, tomllib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from operator_kit import strict_json, config_updates, patch_config, validate_plan
def write_private(path,text):
    path=Path(os.path.abspath(path))
    info=path.parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:
        raise ValueError("private owned output directory required")
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"w") as f:
        f.write(text);f.flush();os.fsync(f.fileno())
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--plan",type=Path,required=True);p.add_argument("--operator",required=True)
    p.add_argument("--input",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--proxy-app",required=True)
    a=p.parse_args()
    plan=strict_json(a.plan.read_bytes());validate_plan(plan)
    text=patch_config(a.input.read_text(),config_updates(plan,a.operator,proxy_app=a.proxy_app))
    tomllib.loads(text);write_private(a.output,text)
if __name__=="__main__": main()
