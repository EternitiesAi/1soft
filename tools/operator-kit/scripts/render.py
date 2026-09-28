#!/usr/bin/env python3
import argparse, json, sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"src"))
from operator_kit import strict_json, render_bundle
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--plan",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--proxy-app-template",default="/var/lib/1soft/{name}/app.sock")
    a=p.parse_args()
    plan=strict_json(a.plan.read_bytes())
    result=render_bundle(plan,a.output,proxy_app_template=a.proxy_app_template)
    print(json.dumps(result,indent=2))
if __name__=="__main__": main()
