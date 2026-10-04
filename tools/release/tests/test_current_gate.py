"""Current checkout coverage must fail closed when its component map drifts."""
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

import check_current as current
from check_current import COMPONENTS, GROUPS, coverage

JS_UNITS = {'reference': 'reference/kernel.test.mjs',
            'wallet': 'tools/local-platform/tests/wallet.test.cjs',
            'history_backup': 'tools/local-platform/tests/backup_history.test.cjs',
            'alpha_history': 'tools/local-platform/tests/alpha_history.test.cjs',
            'merchant_resource': 'tools/local-platform/tests/merchant_resource.test.cjs'}
JS_SCENARIOS = ['tools/local-platform/tests/browser_service.test.cjs',
                'tools/local-platform/tests/browser_workflow.test.cjs',
                'tools/local-platform/tests/merchant_resource_browser.test.cjs',
                'tools/private-payments/tests/browser_comet.test.cjs',
                'tools/private-payments/tests/alpha_invoice_browser.test.cjs',
                'tools/private-payments/tests/alpha_resource_browser.test.cjs']


class CurrentCoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory, pattern, paths in GROUPS.values():
            folder = self.root / directory
            folder.mkdir(parents=True, exist_ok=True)
            (folder / ('test_account_view.py' if 'account' in directory else 'test_example.py')).write_text(
                'import unittest\nclass Example(unittest.TestCase):\n'
                ' def test_real_case(self): self.assertEqual(2 + 2, 4)\n')
        for relative in [*JS_UNITS.values(), *JS_SCENARIOS]:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text('// test inventory fixture\n')

    def test_covers_native_and_every_registered_component(self):
        result = coverage(self.root)
        self.assertEqual(len(result['groups']), 1 + len(COMPONENTS))
        self.assertEqual(len(result['test_files']), 1 + len(COMPONENTS))
        self.assertEqual(result['excluded_test_files'], [])

    def test_new_component_cannot_disappear_from_run(self):
        folder = self.root / 'tools/new-component/tests'
        folder.mkdir(parents=True)
        (folder / 'test_new.py').write_text('')
        with self.assertRaisesRegex(ValueError, 'component coverage'):
            coverage(self.root)

    def test_empty_component_is_refused(self):
        (self.root / 'tools/protocol4-wallet/tests/test_example.py').unlink()
        with self.assertRaisesRegex(ValueError, 'empty test group'):
            coverage(self.root)

    def test_missing_component_is_refused(self):
        folder = self.root / 'tools/protocol4-wallet/tests'
        (folder / 'test_example.py').unlink()
        folder.rmdir()
        with self.assertRaisesRegex(ValueError, 'component coverage'):
            coverage(self.root)

    def test_nested_test_is_refused_until_explicitly_mapped(self):
        folder = self.root / 'tools/protocol4-wallet/tests/nested'
        folder.mkdir()
        (folder / 'test_other.py').write_text('')
        with self.assertRaisesRegex(ValueError, 'uncovered test'):
            coverage(self.root)

    def test_optional_unpublished_catchup_is_named_not_counted(self):
        optional = self.root / 'tools/wallet-account/tests/test_account_catchup.py'
        optional.write_text('raise RuntimeError("unpublished")\n')
        result = coverage(self.root)
        self.assertEqual(result['excluded_test_files'], [str(optional.relative_to(self.root))])
        self.assertNotIn(str(optional.relative_to(self.root)), result['test_files'])

    def test_other_account_tests_cannot_be_silently_excluded(self):
        (self.root / 'tools/wallet-account/tests/test_other.py').write_text('')
        with self.assertRaisesRegex(ValueError, 'uncovered test'):
            coverage(self.root)

    def test_symlinked_test_refused(self):
        target = self.root / 'tools/protocol4-wallet/tests/test_example.py'
        target.unlink()
        target.symlink_to(self.root / 'tests/test_example.py')
        with self.assertRaisesRegex(ValueError, 'aliased test'):
            coverage(self.root)

    def test_javascript_units_and_browser_scenarios_are_distinct(self):
        result = coverage(self.root)
        self.assertEqual(result['javascript_groups'], JS_UNITS)
        self.assertEqual([r['path'] for r in result['javascript_scenarios']], JS_SCENARIOS)
        for record in result['javascript_scenarios']:
            self.assertEqual(record['status'], 'unassessed')
            self.assertIn('separate scenario qualification', record['reason'])
            self.assertNotIn('passed', record)

    def test_missing_javascript_unit_is_refused(self):
        (self.root / JS_UNITS['wallet']).unlink()
        with self.assertRaisesRegex(ValueError, 'JavaScript coverage'):
            coverage(self.root)

    def test_missing_history_unit_cannot_disappear_from_registered_coverage(self):
        (self.root / JS_UNITS['history_backup']).unlink()
        with self.assertRaisesRegex(ValueError, 'JavaScript coverage'):
            coverage(self.root)

    def test_unknown_javascript_test_is_refused(self):
        (self.root / 'tools/local-platform/tests/other.test.cjs').write_text('')
        with self.assertRaisesRegex(ValueError, 'JavaScript coverage'):
            coverage(self.root)

    def test_aliased_javascript_test_is_refused(self):
        target = self.root / JS_UNITS['wallet']
        target.unlink(); target.symlink_to(self.root / JS_UNITS['reference'])
        with self.assertRaisesRegex(ValueError, 'aliased JavaScript test'):
            coverage(self.root)

    def test_missing_browser_scenario_is_not_silently_omitted(self):
        (self.root / JS_SCENARIOS[0]).unlink()
        with self.assertRaisesRegex(ValueError, 'JavaScript coverage'):
            coverage(self.root)


    def test_p4_engine_scenarios_are_registered_without_unit_qualification_claim(self):
        result=coverage(self.root)
        scenarios=result.get('python_engine_scenarios',[])
        self.assertEqual([x['profile'] for x in scenarios],['basic','final-apply-crash'])
        self.assertTrue(all(x['path']=='scripts/run_protocol4_state_sync.py' for x in scenarios))
        self.assertTrue(all(x['status']=='unassessed' for x in scenarios))


class CurrentJavascriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'; self.root.mkdir()
        self.output = Path(self.temp.name) / 'evidence'; self.output.mkdir()
        self.source = {'source_id': 'a' * 64, 'commit': 'b' * 40, 'tree': 'c' * 40}
        self.run_id = 'd' * 32
        self.calls = []
        self.bad = None
        self.bad_group = 'wallet'

    def process(self, command, root, log, timeout):
        name = next(name for name, path in JS_UNITS.items() if command[-1] == path)
        self.calls.append((command, root, log.name, timeout))
        tests = {'reference':30, 'wallet':8, 'history_backup':5, 'alpha_history':8, 'merchant_resource':16}[name]
        mode = self.bad if name == self.bad_group else None
        if mode != 'missing':
            cases = ''.join(f'{"not ok" if mode == "failed" and i == tests else "ok"} '
                            f'{i} - {name} case {1 if mode == "duplicate" else i}\n'
                            for i in range(1, tests + 1))
            raw = (cases + f'# tests {tests}\n# pass {tests - (mode == "failed")}\n'
                   f'# fail {int(mode == "failed")}\n# cancelled 0\n# skipped 0\n# todo 0\n').encode()
            if mode == 'missing_cases': raw = raw[raw.index(b'# tests '):]
            log.write_bytes(b'# tests 8\n' if mode == 'incomplete' else raw)
        return {'returncode': int(mode == 'exit'), 'timed_out': mode == 'timeout',
                'log_truncated': mode == 'truncated', 'seconds': 0.01,
                'observed_log_bytes': log.stat().st_size if log.exists() else 0,
                'log_sha256': current.base.digest(log.read_bytes()) if log.exists() else None}

    def check(self):
        with patch.object(current.base, 'source_identity', return_value=self.source), \
             patch.object(current.base, 'run_process', side_effect=self.process):
            return current.javascript_checks(self.root, self.output, self.source, self.run_id, 30)

    def test_both_suites_have_distinct_source_bound_results(self):
        result = self.check()
        self.assertTrue(result['passed']); self.assertEqual(result['tests'], 67)
        self.assertEqual(result['qualified_tests'], 67)
        self.assertEqual([r['name'] for r in result['groups']], list(JS_UNITS))
        for record, call in zip(result['groups'], self.calls):
            self.assertEqual(record['source_id'], self.source['source_id'])
            self.assertEqual(record['run_id'], self.run_id)
            self.assertEqual(record['path'], JS_UNITS[record['name']])
            self.assertEqual(record['log'], f"javascript-{record['name']}.log")
            self.assertEqual(call[0], ['node', '--test', '--test-reporter=tap', record['path']])
            self.assertEqual(len(record['test_cases']), record['tests'])
            self.assertTrue(all(c['status'] == 'passed' for c in record['test_cases']))
            self.assertEqual(record['test_cases'][0]['id'], record['path'] + '::' + record['name'] + ' case 1')
            self.assertTrue((self.output / f"javascript-{record['name']}.json").is_file())

    def test_failed_wallet_suite_cannot_inherit_reference_pass(self):
        self.bad = 'failed'; result = self.check()
        self.assertFalse(result['passed']); self.assertEqual(result['fail'], 1)
        self.assertEqual(result['qualified_tests'], 59)
        self.assertEqual([r['passed'] for r in result['groups']], [True, False, True, True, True])

    def test_failed_history_suite_cannot_inherit_the_two_original_passes(self):
        self.bad_group = 'history_backup'; self.bad = 'failed'
        result = self.check()
        self.assertFalse(result['passed']); self.assertEqual(result['fail'], 1)
        self.assertEqual(result['qualified_tests'], 62)
        self.assertEqual([r['passed'] for r in result['groups']], [True, True, False, True, True])

    def test_failed_alpha_suite_cannot_inherit_three_original_passes(self):
        self.bad_group='alpha_history';self.bad='failed';result=self.check()
        self.assertFalse(result['passed']);self.assertEqual(result['qualified_tests'],59)
        self.assertEqual([r['passed'] for r in result['groups']],[True,True,True,False,True])

    def test_failed_merchant_resource_cannot_inherit_four_original_passes(self):
        self.bad_group='merchant_resource';self.bad='failed';result=self.check()
        self.assertFalse(result['passed']);self.assertEqual(result['qualified_tests'],51)
        self.assertEqual([r['passed'] for r in result['groups']],[True,True,True,True,False])

    def test_source_change_before_history_prevents_its_execution(self):
        changed = {**self.source, 'source_id': 'e' * 64}
        with patch.object(current.base, 'source_identity', side_effect=[self.source, self.source, changed]), \
             patch.object(current.base, 'run_process', side_effect=self.process):
            with self.assertRaisesRegex(ValueError, 'source changed before JavaScript group: history_backup'):
                current.javascript_checks(self.root, self.output, self.source, self.run_id, 30)
        self.assertEqual(len(self.calls), 2)

    def test_missing_wallet_log_remains_failed_and_named(self):
        self.bad = 'missing'; result = self.check()
        self.assertFalse(result['passed']); self.assertEqual(len(result['groups']), 5)
        self.assertEqual(result['groups'][1]['error_type'], 'FileNotFoundError')
        self.assertEqual(result['qualified_tests'], 59)

    def test_incomplete_wallet_summary_is_refused(self):
        self.bad = 'incomplete'; result = self.check()
        self.assertFalse(result['passed'])
        self.assertEqual(result['groups'][1]['error_type'], 'ValueError')

    def test_process_failure_timeout_or_truncation_cannot_pass(self):
        for mode in ('exit', 'timeout', 'truncated'):
            with self.subTest(mode=mode):
                self.bad = mode
                self.output = Path(self.temp.name) / mode; self.output.mkdir()
                result = self.check()
                self.assertFalse(result['passed'])
                self.assertFalse(result['groups'][1]['passed'])

    def test_missing_or_duplicate_javascript_case_listing_is_refused(self):
        for mode in ('missing_cases', 'duplicate'):
            with self.subTest(mode=mode):
                self.bad = mode
                self.output = Path(self.temp.name) / mode; self.output.mkdir()
                result = self.check()
                self.assertFalse(result['passed'])
                self.assertEqual(result['groups'][1]['error_type'], 'ValueError')

    def test_source_change_prevents_wallet_execution(self):
        changed = {**self.source, 'source_id': 'e' * 64}
        with patch.object(current.base, 'source_identity', side_effect=[self.source, changed]), \
             patch.object(current.base, 'run_process', side_effect=self.process):
            with self.assertRaisesRegex(ValueError, 'source changed before JavaScript group: wallet'):
                current.javascript_checks(self.root, self.output, self.source, self.run_id, 30)
        self.assertEqual(len(self.calls), 1)

    def test_current_run_requires_both_suites_and_never_qualifies_browser(self):
        # Replace process boundaries only; exercise the real report and final gate.
        (self.root / 'requirements.txt').write_text('')
        source = {**self.source, 'tracked_files': 1}
        scenarios = [{'path': p, 'status': 'unassessed',
                      'reason': 'requires separate scenario qualification'} for p in JS_SCENARIOS]
        engine_scenarios=[{'path':'scripts/run_protocol4_state_sync.py','profile':name,
            'status':'unassessed','reason':'requires separate real engine qualification'}
            for name in ('basic','final-apply-crash')]
        profile = {'javascript_groups': JS_UNITS, 'javascript_scenarios': scenarios,
                   'python_engine_scenarios':engine_scenarios}

        def process(command, root, log, timeout):
            if command[0] == 'node': return self.process(command, root, log, timeout)
            group = command[command.index('--worker') + 1]
            child = {'group': group, 'source_id': command[command.index('--source-id') + 1],
                     'run_id': command[command.index('--run-id') + 1],
                     'expected_ids': ['fixture.test_case'], 'successful_ids': ['fixture.test_case'],
                     'run': 1, 'skips': 0, 'failures': 0, 'errors': 0,
                     'expected_failures': 0, 'unexpected_successes': 0}
            Path(command[command.index('--output') + 1]).write_text(json.dumps(child))
            log.write_bytes(b'owned mocked Python process boundary\n')
            return {'returncode': 0, 'timed_out': False, 'log_truncated': False}

        for mode in (None, 'failed', 'missing', 'incomplete'):
            with self.subTest(wallet_result=mode):
                self.bad = mode
                output = Path(self.temp.name) / ('run-' + str(mode))
                with patch.object(current, 'ROOT', self.root), \
                     patch.object(current, 'GROUPS', {'native': ('tests', 'test_*.py', [])}), \
                     patch.object(current, 'coverage', return_value=profile), \
                     patch.object(current.base, 'source_identity', return_value=source), \
                     patch.object(current.base, 'run_process', side_effect=process), \
                     patch('builtins.print'):
                    code = current.run(output, 30)
                result = json.loads((output / 'result.json').read_bytes())
                self.assertEqual(code, 0 if mode is None else 1)
                self.assertEqual(result['local_checks'], 'passed' if mode is None else 'failed')
                self.assertEqual(result['release_status'], 'blocked')
                self.assertFalse(result['public_network_ready'])
                self.assertEqual(result['scenario_qualification'], scenarios+engine_scenarios)
                self.assertTrue(all(x['status']=='unassessed' for x in result['scenario_qualification']))
                self.assertEqual(len(result['javascript']['groups']), 5)
                for record in result['javascript']['groups']:
                    self.assertEqual(record['run_id'], result['run_id'])
                    self.assertEqual(record['source_id'], result['source_id'])
