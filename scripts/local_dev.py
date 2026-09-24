#!/usr/bin/env python3
"""Local 1soft development commands. No Actions, cloud account or auto-installs."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
from verify_checkout import verify_checkout

PIN = '0.38.25'
CORE_FILES = {'src/native_core.py', 'src/offline_signer.py', 'scripts/wallet.py',
              'tests/test_native.py', 'tests/test_offline_signer.py', 'requirements.txt'}
CORE_RUNNER = '''import json,sys,unittest
from pathlib import Path
root=Path.cwd();sys.path[:0]=[str(root/'src'),str(root/'tests')]
suite=unittest.TestSuite()
for pattern in ('test_native.py','test_offline_signer.py'):
 suite.addTests(unittest.defaultTestLoader.discover(str(root/'tests'),pattern=pattern))
count=suite.countTestCases()
result=unittest.TextTestRunner(verbosity=2).run(suite)
passed=count>0 and result.wasSuccessful() and result.testsRun==count and len(result.skipped)<count
print(json.dumps({'scope':'native-and-offline-wallet-only','run':result.testsRun,'skipped':len(result.skipped),'passed':passed,'consensus_verified':False}))
sys.exit(0 if passed else 1)
'''


def run_step(command: list[str], cwd: Path, folder: Path, label: str,
             *, env: dict | None = None, timeout: int = 120) -> dict:
    """Bound execution; timeout terminates the entire local child process group."""
    out = folder/(label+'.log')
    item = {'name': label, 'command': command, 'log': out.name, 'status': 'failed'}
    with out.open('xb') as log:
        try:
            proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=log, stderr=subprocess.STDOUT,
                                    start_new_session=(os.name == 'posix'))
            try:
                code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                if os.name == 'posix':
                    try: os.killpg(proc.pid, signal.SIGTERM)
                    except ProcessLookupError: pass
                else:
                    proc.terminate()
                try: proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    if os.name == 'posix': os.killpg(proc.pid, signal.SIGKILL)
                    else: proc.kill()
                    proc.wait()
                # Also kill surviving descendants after a parent exits on TERM.
                if os.name == 'posix':
                    try: os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                item['reason'] = 'command timed out; process group stopped'
                return item
            item.update(returncode=code, status='passed' if code == 0 else 'failed')
        except OSError as exc:
            item.update(status='unassessed', reason=str(exc))
    return item


def gate_passed(evidence: dict) -> bool:
    checks = evidence.get('checks')
    return evidence.get('status') == 'passed' and type(checks) is list and len(checks) > 0 and all(
        type(check) is dict and check.get('passed') is True for check in checks)


def check_source(root: Path, scope: str) -> dict:
    result = verify_checkout(root)
    if scope == 'full':
        return result
    manifest = json.loads((root/'SOURCE_MANIFEST.json').read_text())
    covered = {entry['path'] for entry in manifest['files']}
    if not CORE_FILES <= covered:
        raise ValueError('core files missing from declared source inventory')
    failures = [item for item in result['errors'] if item['path'] in CORE_FILES]
    return {'status': 'failed' if failures else 'passed', 'scope': 'explicit-core-subset-only',
            'required': len(CORE_FILES), 'matched': len(CORE_FILES)-len(failures), 'errors': failures,
            'complete_source_status': result['status'], 'manifest_sha256': result['manifest_sha256']}


def inspect(root: Path, engine: str | None) -> dict:
    deps = {}
    for name, expected in [('cryptography','46.0.4'),('protobuf','6.33.6')]:
        try: actual = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError: actual = None
        deps[name] = {'expected': expected, 'installed': actual, 'matches': actual == expected}
    binary = engine or str(root/'bin/cometbft')
    found = shutil.which(binary)
    return {'scope': 'environment-inspection-not-a-test', 'python': sys.version.split()[0],
            'platform': sys.platform, 'dependencies': deps, 'go': shutil.which('go'),
            'node': shutil.which('node'), 'engine_path': found,
            'engine_sha256': hashlib.sha256(Path(found).read_bytes()).hexdigest() if found else None,
            'engine_executed': False, 'consensus_verified': False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('doctor','test','build-engine','network'))
    parser.add_argument('--scope', choices=('core','full'), default='core')
    parser.add_argument('--engine', help='Explicit locally trusted engine executable')
    parser.add_argument('--allow-downloads', action='store_true', help='Permit Go dependency downloads; never enables Actions')
    parser.add_argument('--output', type=Path, help='New evidence directory; existing directories are never overwritten')
    args = parser.parse_args(argv)
    if args.command == 'doctor':
        print(json.dumps(inspect(ROOT, args.engine), indent=2)); return 0
    folder = args.output or ROOT/'evidence/local'/datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    report = {'schema':1,'command':args.command,'status':'unassessed','steps':[],
              'github_actions_used':False,'public_network':False,'real_funds':False,
              'consensus_verified':False,'downloads_permitted':args.allow_downloads}
    try:
        folder.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        print(json.dumps({**report,'status':'failed','reason':'new evidence directory required: '+str(exc)}))
        return 1
    try:
        if args.command in ('test','network'):
            report['source'] = check_source(ROOT, args.scope if args.command == 'test' else 'full')
            if report['source']['status'] != 'passed':
                raise ValueError('required source for the selected scope is missing or changed')
        if args.command == 'test':
            command = [sys.executable,'-c',CORE_RUNNER] if args.scope == 'core' else [sys.executable,'scripts/run_tests.py']
            report['scope'] = 'core subset' if args.scope == 'core' else 'complete local Python suite'
            env = dict(os.environ, PYTHONPATH=str(ROOT/'src'))
            report['steps'].append(run_step(command, ROOT, folder, 'python-tests', env=env))
            report['status'] = report['steps'][-1]['status']
        elif args.command == 'build-engine':
            if not args.allow_downloads:
                report['reason'] = 'build requires explicit --allow-downloads; no install attempted'
            elif not shutil.which('go'):
                report['reason'] = 'Go toolchain is not installed; no install attempted'
            else:
                target = ROOT/'bin'; target.mkdir(exist_ok=True)
                env = dict(os.environ, GOBIN=str(target), GOTOOLCHAIN='local')
                step = run_step(['go','install',f'github.com/cometbft/cometbft/cmd/cometbft@v{PIN}'],
                                ROOT, folder, 'engine-build', env=env, timeout=240)
                report['steps'].append(step)
                report['status'] = step['status']
                if step['status'] == 'passed':
                    report['engine_sha256'] = hashlib.sha256((target/'cometbft').read_bytes()).hexdigest()
                    report['reason'] = 'binary built only; no native network has been verified'
        elif args.command == 'network':
            binary = shutil.which(args.engine or str(ROOT/'bin/cometbft'))
            if binary is None:
                report['reason'] = 'pinned local engine absent; no synthetic replacement or automatic install'
            else:
                env = dict(os.environ, GOTOOLCHAIN='local')
                if not args.allow_downloads:
                    env.update(GOPROXY='off', GOSUMDB='off', GONOPROXY='none',
                               GOPRIVATE='', GONOSUMDB='none', GOVCS='*:off')
                probe = run_step([sys.executable,'scripts/check_upstream_wire.py','--output',str(folder/'upstream.json')],
                                 ROOT, folder, 'upstream-codec', env=env, timeout=390)
                report['steps'].append(probe)
                codec = json.loads((folder/'upstream.json').read_text()) if (folder/'upstream.json').exists() else {}
                if probe['status'] != 'passed' or not gate_passed(codec):
                    report['reason'] = 'upstream codec did not pass; validator runs not attempted'
                    report['status'] = 'unassessed' if codec.get('status') == 'unassessed' else 'failed'
                else:
                    for version in (1,2):
                        target = folder/f'protocol-{version}'/'devnet.json'
                        step = run_step([sys.executable,'scripts/run_devnet.py','--cometbft',binary,
                            '--protocol-version',str(version),'--output',str(target)], ROOT, folder,
                            f'network-{version}',env=env,timeout=300)
                        report['steps'].append(step)
                        evidence = json.loads(target.read_text()) if target.exists() else {}
                        if step['status'] != 'passed' or not gate_passed(evidence):
                            report['status'] = 'failed'; report['reason'] = 'network gate did not pass'; break
                    else:
                        report.update(status='passed',consensus_verified=True,
                                      scope='two four-validator local tests, one host, not independent operators')
    except (OSError, ValueError) as exc:
        report.update(status='failed',reason=str(exc))
    (folder/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
    return 0 if report['status']=='passed' else (2 if report['status']=='unassessed' else 1)


if __name__ == '__main__':
    raise SystemExit(main())
