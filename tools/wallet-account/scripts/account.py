#!/usr/bin/env python3
"""Read one local 1soft account; never sign, refresh, migrate or send."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from account_view import read_account
from account_report import render_html
from commit_verifier import load_json


def _read(path, bound):
    with path.open('rb') as f: raw=f.read(bound+1)
    if len(raw)>bound: raise ValueError('input exceeds bound')
    return raw


def _export(path, raw):
    # Private exported report, exclusively created. Not a durable backup protocol.
    path=Path(os.path.abspath(path))
    for parent in (path.parent,*path.parent.parents):
        if parent.is_symlink(): raise ValueError('output directory symlink refused')
    info=path.parent.stat()
    if info.st_uid!=os.geteuid() or info.st_mode & 0o077:
        raise ValueError('output directory must be private and owned')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:
        out.write(raw);out.flush();os.fsync(out.fileno())


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--genesis',type=Path,required=True)
    p.add_argument('--policy',type=Path,required=True)
    p.add_argument('--journal',type=Path,required=True)
    p.add_argument('--account',required=True)
    p.add_argument('--limit',type=int,default=50)
    p.add_argument('--format',choices=('json','html'),default='json')
    p.add_argument('--output',type=Path,help='New private output file; never overwritten')
    a=p.parse_args(argv)
    try:
        view=read_account(a.journal,_read(a.genesis,1024*1024),
                          load_json(_read(a.policy,16384),max_bytes=16384),a.account,limit=a.limit)
        raw=(json.dumps(view,indent=2,ensure_ascii=True)+'\n') if a.format=='json' else render_html(view)
        if a.output:
            _export(a.output,raw.encode())
            print(json.dumps({'status':'historical-report-written','state_modified':False,
                              'fresh_payment_authorization':False}))
        else:
            print(raw)
        # Zero means a valid historical view was produced, not current funds or authority.
        return 0
    except (OSError,ValueError,sqlite3.Error,KeyError,TypeError):
        print('Account view unavailable or invalid. No wallet data was changed; no balance can be inferred.',file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
