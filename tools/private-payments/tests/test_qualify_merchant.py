"""Injected orchestration reports; no test runs an engine or original suite."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import qualify_merchant as wrapper
from private_acceptance import PRIVATE_CHECKS
from test_merchant_qualification import SOURCE, actual, inherited

FULL_SOURCE = {**SOURCE, 'files': []}


class QualifyMerchantTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name)/'qualification'
        self.actual_calls = 0; self.foundation_calls = 0
        self.change = None

    def retained(self, path, value):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        wrapper.private.legacy.base.store_json(path, value)
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def foundation(self, engine, output):
        self.foundation_calls += 1
        output = Path(output); output.mkdir(mode=0o700)
        report = inherited(); report['python_tests'] = 2204
        run = report['run_id']
        baseline = dict(schema=1, status='passed', local_automated_qualification=True,
            source_commit=SOURCE['commit'], source_tree=SOURCE['tree'], source_id=SOURCE['source_id'],
            source_tracked_files=SOURCE['tracked_files'], source_identity_after=SOURCE,
            source_unchanged=True, engine_sha256=wrapper.private.PIN_SHA, engine_unchanged=True,
            python_tests=2069, javascript_tests=38, go_response_vectors=4,
            gates=[dict(name=name, passed=True) for name in wrapper.private.BASELINE_GATES])
        ids = [f'synthetic.private.Test.test_{i}' for i in range(135)]
        component = dict(schema=1, group=wrapper.private.GROUP, source_id=SOURCE['source_id'],
            run_id=run, source=SOURCE, source_after=SOURCE, source_unchanged=True, passed=True,
            expected_ids=ids, successful_ids=list(ids), run=135, errors=0, failures=0, skips=0,
            expected_failures=0, unexpected_successes=0)
        consensus = dict(schema=1, status='passed', run_id=run, source=SOURCE,
            source_after=SOURCE, source_unchanged=True, source_qualified=True,
            consensus_executed=True, validator_count=4, engine_version='0.38.25',
            engine_sha256=wrapper.private.PIN_SHA, engine_sha256_after=wrapper.private.PIN_SHA,
            owned_processes_after_cleanup=0, owned_threads_after_cleanup=0, cleanup_errors=[],
            real_funds=False, public_network=False, onchain_privacy=False, independent_hosts=False,
            checks=[dict(name=name, passed=True) for name in PRIVATE_CHECKS])
        if self.change == 'baseline-failed': baseline['status'] = 'failed'
        if self.change == 'component-source': component['source_after'] = {}
        if self.change == 'component-partial': component['successful_ids'].pop()
        if self.change == 'component-boolean': component['run'] = True
        if self.change == 'consensus-partial': consensus['checks'].pop()
        for gate, child, name in zip(report['gates'], (baseline, component, consensus),
                ('baseline/result.json', 'private-components.json', 'private-consensus/result.json')):
            gate['result_path'] = name; gate['result_sha256'] = self.retained(output/name, child)
            if gate['name'] == 'private-components':
                gate['process'] = dict(returncode=0, timed_out=False, log_truncated=False)
        if self.change == 'component-process': report['gates'][1]['process']['returncode'] = False
        if self.change == 'total-forged': report['python_tests'] = 9999
        self.retained(output/'result.json', report)
        return report

    def merchant(self, engine, output, *, source, run_id):
        self.actual_calls += 1; output = Path(output); output.mkdir(mode=0o700)
        report = actual(); report['run_id'] = run_id
        if self.change == 'actual-failed':
            report['status'] = 'failed'; report['checks'][0]['passed'] = False
        for payment in report['payments']:
            wire = ('synthetic original wire '+payment['role']).encode()
            capsule = ('synthetic original capsule '+payment['role']).encode()
            payment['wire_sha256'] = hashlib.sha256(wire).hexdigest()
            payment['capsule_sha256'] = hashlib.sha256(capsule).hexdigest()
            if self.change != 'missing-artifact' or payment['role'] != 'owner':
                wrapper.private.legacy.private_new(output/('wire-'+payment['role']+'.json'), wire)
            wrapper.private.legacy.private_new(output/('capsule-'+payment['role']+'.json'), capsule)
        if self.change == 'changed-artifact':
            (output/'capsule-owner.json').write_bytes(b'changed retained capsule')
        self.retained(output/'result.json', report)
        return report

    def run_qualification(self):
        with patch.object(wrapper.private, 'source_checked', return_value=FULL_SOURCE), \
             patch.object(wrapper.private.legacy, 'verify_engine', return_value=Path('/not-executed-engine')), \
             patch.object(wrapper.private, 'qualify', side_effect=self.foundation), \
             patch.object(wrapper, 'run_merchant', side_effect=self.merchant):
            return wrapper.qualify('/not-executed-engine', self.output)

    def test_two_successful_gates_retain_final_progress_and_exact_child_receipts(self):
        result = self.run_qualification()
        self.assertEqual('passed', result['status'])
        self.assertTrue(result['local_automated_qualification'])
        self.assertEqual(['passed', 'passed'], [g['status'] for g in result['gates']])
        self.assertEqual(1, self.foundation_calls); self.assertEqual(1, self.actual_calls)
        progress = wrapper.private.read_report(self.output/'progress.json')
        self.assertEqual(['passed', 'passed'], [g['status'] for g in progress['gates']])
        self.assertEqual(result, wrapper.private.read_report(self.output/'result.json'))
        for gate in result['gates']:
            self.assertEqual(gate['result_sha256'], hashlib.sha256((self.output/gate['result_path']).read_bytes()).hexdigest())

    def test_failed_second_gate_preserves_failure_and_never_claims_qualification(self):
        self.change = 'actual-failed'; result = self.run_qualification()
        self.assertEqual('failed', result['status']); self.assertFalse(result['local_automated_qualification'])
        self.assertEqual(['passed', 'failed'], [g['status'] for g in result['gates']])
        self.assertEqual('failed', wrapper.private.read_report(self.output/'merchant-consensus/result.json')['status'])
        self.assertEqual(result, wrapper.private.read_report(self.output/'result.json'))

    def test_failed_nested_baseline_refuses_before_merchant_execution(self):
        self.change = 'baseline-failed'; result = self.run_qualification()
        self.assertEqual('failed', result['status']); self.assertEqual(0, self.actual_calls)
        self.assertEqual(['failed', 'unassessed'], [g['status'] for g in result['gates']])

    def test_wrong_source_partial_ids_boolean_run_or_child_exit_refuse_before_execution(self):
        for i, change in enumerate(('component-source', 'component-partial', 'component-boolean', 'component-process')):
            with self.subTest(change=change):
                self.output = Path(self.tmp.name)/f'component-{i}'; self.change = change
                result = self.run_qualification()
                self.assertEqual('failed', result['status']); self.assertEqual(0, self.actual_calls)
                self.assertEqual('unassessed', result['gates'][1]['status'])

    def test_partial_nested_private_consensus_refuses_before_merchant_execution(self):
        self.change = 'consensus-partial'; result = self.run_qualification()
        self.assertEqual('failed', result['status']); self.assertEqual(0, self.actual_calls)

    def test_top_python_total_must_equal_original_baseline_plus_complete_child_ids(self):
        self.change = 'total-forged'; result = self.run_qualification()
        self.assertEqual('failed', result['status']); self.assertEqual(0, self.actual_calls)

    def test_missing_or_changed_retained_payment_artifact_refuses_second_gate(self):
        for i, change in enumerate(('missing-artifact', 'changed-artifact')):
            with self.subTest(change=change):
                self.output = Path(self.tmp.name)/f'artifact-{i}'; self.change = change
                result = self.run_qualification()
                self.assertEqual('failed', result['status']); self.assertFalse(result['local_automated_qualification'])
                self.assertEqual(['passed', 'failed'], [g['status'] for g in result['gates']])


if __name__ == '__main__': unittest.main()
