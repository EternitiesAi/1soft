#!/usr/bin/env python3
"""Complete inherited/private qualification plus the finite merchant journey."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import uuid
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(ROOT/p) for p in ('src','scripts','tests','tools/private-payments/scripts')]+[str(p) for p in (ROOT/'tools').glob('*/src')]
import qualify_private as private
from merchant_qualification import actual_report_matches,private_report_matches
from merchant_acceptance import run_merchant
from private_acceptance import PRIVATE_CHECKS
from local_devnet import read_private


def foundation_children_match(report,directory,source):
    """Require retained child provenance and complete counts before more work."""
    try:
        children=[]
        expected=('baseline/result.json','private-components.json','private-consensus/result.json')
        for gate,name in zip(report['gates'],expected):
            private.require(gate['result_path']==name,'unexpected inherited report path')
            path=directory/name
            private.require(not directory.is_symlink() and not path.parent.is_symlink(),
                'aliased inherited report directory')
            child=private.read_report(path)
            private.require(hashlib.sha256(path.read_bytes()).hexdigest()==gate['result_sha256'],
                'nested original report hash differs')
            children.append(child)
        baseline,component,consensus=children
        return (private.baseline_report_matches(baseline,source) and
            private.child_report_matches(component,report['gates'][1].get('process'),source,report['run_id']) and
            private.acceptance_report_matches(consensus,source,report['run_id'],PRIVATE_CHECKS) and
            report['python_tests']==baseline['python_tests']+component['run'] and
            report['javascript_tests']==baseline['javascript_tests'] and
            report['go_response_vectors']==baseline['go_response_vectors'])
    except (KeyError,TypeError,ValueError,OSError):return False


def payment_artifacts_match(report,directory):
    """Check retained public bytes; proof replay belongs to the actual harness."""
    try:
        for payment in report['payments']:
            role=payment['role']
            for name,maximum in (('wire',32768),('capsule',16*1024*1024)):
                raw=read_private(directory/(name+'-'+role+'.json'),maximum)
                private.require(raw and hashlib.sha256(raw).hexdigest()==payment[name+'_sha256'],
                    'retained public payment bytes differ')
        return True
    except (KeyError,TypeError,ValueError,OSError):return False


def qualify(engine,output):
    output=private._output_directory(output)
    report=dict(schema=1,status='running',run_id=uuid.uuid4().hex,source=None,source_after=None,
        source_unchanged=False,engine_sha256=None,engine_sha256_after=None,engine_unchanged=False,
        engine_version=None,gates=[dict(name=n,status='unassessed',passed=False) for n in ('private-foundation','merchant-consensus')],
        python_tests=0,javascript_tests=0,go_response_vectors=0,consensus_executed=False,
        local_automated_qualification=False,owned_processes_after_cleanup=None,owned_threads_after_cleanup=None,
        cleanup_errors=None,native_signature_authenticates_resource=False,onchain_privacy=False,
        real_funds=False,public_network=False,public_release_ready=False,independent_security_review=False,
        spending_or_deployment_authorized=False,scope='finite local three-invoice native DEV qualification',
        unassessed=['native signed invoice commitment','unlimited recipient provisioning or live migration',
            'production custody or hostile OS protection','copied merchant books or cross-device coordination',
            'independent validators/operators or external security review','private ledger/scoped privacy receipts',
            'human mobile/browser acceptance','customer demand/pricing/economics/returns','public or real-money launch'])
    stage=None
    def checked():
        private.source_checked(source);private.legacy.verify_engine(binary)
    def gate(name,value,path,passed):
        retained=private.read_report(path);private.require(retained==value,'returned/retained reports differ')
        row=next(r for r in report['gates'] if r['name']==name)
        row.update(status='passed' if passed else 'failed',passed=passed,result_path=str(path.relative_to(output)),
            result_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        progress=output/'progress.json'
        private.legacy.base.store_json(progress,report,replace=progress.exists())
        private.require(passed,'complete attributed child did not qualify')
    try:
        source=private.source_checked();report['source']=private.reduced(source)
        private.legacy.base.store_json(output/'source.json',source)
        binary=private.legacy.verify_engine(engine);report.update(engine_sha256=private.PIN_SHA,engine_version='0.38.25')
        stage='private-foundation';checked()
        foundation=private.qualify(binary,output/'private-foundation')
        path=output/'private-foundation/result.json'
        gate(stage,foundation,path,private_report_matches(foundation,private.reduced(source)) and
            foundation_children_match(foundation,path.parent,source))
        checked();report.update(python_tests=foundation['python_tests'],javascript_tests=foundation['javascript_tests'],
            go_response_vectors=foundation['go_response_vectors'],inherited_run_id=foundation['run_id'])
        stage='merchant-consensus';checked()
        actual=run_merchant(binary,output/'merchant-consensus',source=source,run_id=report['run_id'])
        report.update(owned_processes_after_cleanup=actual.get('owned_processes_after_cleanup'),
            owned_threads_after_cleanup=actual.get('owned_threads_after_cleanup'),cleanup_errors=actual.get('cleanup_errors'),
            consensus_executed=actual.get('consensus_executed') is True)
        gate(stage,actual,output/'merchant-consensus/result.json',
            actual_report_matches(actual,private.reduced(source),report['run_id']) and
            payment_artifacts_match(actual,output/'merchant-consensus'))
        checked();report.update(status='passed',source_after=private.reduced(source),source_unchanged=True,
            engine_sha256_after=private.PIN_SHA,engine_unchanged=True,local_automated_qualification=True)
    except BaseException as exc:
        report.update(status='failed',error_type=type(exc).__name__)
        if stage is None:report['preflight']=dict(passed=False,error_type=type(exc).__name__)
        else:next(r for r in report['gates'] if r['name']==stage).update(status='failed',passed=False,error_type=type(exc).__name__)
    report['unassessed_gates']=[r['name'] for r in report['gates'] if r['status']=='unassessed']
    private.legacy.base.store_json(output/'result.json',report)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine',required=True,type=Path);parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    try:report=qualify(args.engine,args.output)
    except BaseException as exc:
        print(json.dumps(dict(status='refused',error_type=type(exc).__name__)),flush=True);return 1
    print(json.dumps(report,sort_keys=True),flush=True)
    return 0 if report['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
