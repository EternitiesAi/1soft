#!/usr/bin/env python3
"""Cross-check SMT roots/proofs with Node's independently structured implementation."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from state_tree import COLUMNS,StateTree


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    cases=[]
    for count in (0,1,2,17,64,129):
        state={key:[] for key in COLUMNS}
        state['meta']=[[f'key-{i}',str(i*3)] for i in range(count)]
        tree=StateTree(state)
        keys=[('meta',f'key-{i}') for i in range(min(count,8))]+[('meta','absent'),('grant_budgets','key-0')]
        cases.append({'state':state,'root':tree.root.hex(),'proofs':[tree.proof(*key) for key in keys]})
    vectors=args.output/'vectors.json';vectors.write_text(json.dumps(cases,indent=2)+'\n')
    run=subprocess.run(['node',str(ROOT/'tools/state-proof-reference/verify.mjs'),str(vectors)],
                        capture_output=True,text=True,timeout=20)
    (args.output/'node.stdout').write_text(run.stdout);(args.output/'node.stderr').write_text(run.stderr)
    report=json.loads(run.stdout) if run.returncode==0 else {'status':'failed','reason':run.stderr}
    (args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report));return 0 if report.get('status')=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
