"""Current checkout coverage must fail closed when its component map drifts."""
from pathlib import Path
import hashlib
import importlib.metadata
import json
import tempfile
import shutil
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


    def test_privacy_components_are_covered_and_boundaries_remain_unassessed(self):
        result = coverage(self.root)
        self.assertIn('shielded_note_lab', result['groups'])
        self.assertEqual(result['groups']['shielded_note_lab'], ['tools/shielded-note-lab/tests/test_example.py'])
        self.assertIn('privacy_proof_benchmark', result['groups'])
        self.assertEqual(result['groups']['privacy_proof_benchmark'],
                         ['tools/privacy-proof-benchmark/tests/test_example.py'])
        boundaries = result['privacy_boundaries']
        self.assertTrue(boundaries)
        self.assertTrue(all(x['status'] == 'unassessed' for x in boundaries))
        self.assertNotIn('passed', [x['status'] for x in boundaries])

    def test_ignored_python_bytecode_fails_before_worker_execution(self):
        stale = self.root / 'tools/shielded-note-lab/src/__pycache__'
        stale.mkdir(parents=True)
        (stale / 'stale.pyc').write_bytes(b'ignored bytecode')
        with self.assertRaisesRegex(ValueError, 'stale Python bytecode directory'):
            current.refuse_python_bytecode(self.root)


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
        lab = self.root / 'tools/shielded-note-lab'
        lab.mkdir(parents=True)
        (lab / 'SOURCE_MANIFEST.json').write_text(json.dumps({'tests': ['test_note_lab.Example.test_real_case']}))
        (lab / 'DEPENDENCIES.json').write_text('{}')
        scenarios = [{'path': p, 'status': 'unassessed',
                      'reason': 'requires separate scenario qualification'} for p in JS_SCENARIOS]
        engine_scenarios=[{'path':'scripts/run_protocol4_state_sync.py','profile':name,
            'status':'unassessed','reason':'requires separate real engine qualification'}
            for name in ('basic','final-apply-crash')]
        profile = {'javascript_groups': JS_UNITS, 'javascript_scenarios': scenarios,
                   'python_engine_scenarios':engine_scenarios,
                   'privacy_boundaries': [{'area': area, 'status': 'unassessed'} for area in current.PRIVACY_BOUNDARIES]}

        def process(command, root, log, timeout):
            if command[0] == 'node': return self.process(command, root, log, timeout)
            if command[1].endswith('tools/shielded-note-lab/tools/verify.py'):
                log.write_bytes(b'owned mocked shielded verifier boundary\n')
                if self.bad in ('missing', 'failed', 'incomplete'):
                    return {'returncode': int(self.bad == 'failed'), 'timed_out': False,
                            'log_truncated': False}
                manifest_bytes = (self.root / 'tools/shielded-note-lab/SOURCE_MANIFEST.json').read_bytes()
                dependency_bytes = (self.root / 'tools/shielded-note-lab/DEPENDENCIES.json').read_bytes()
                test_log = 'tests=[] failures=[] errors=[] skips=[]'
                receipt = {'format': 1, 'status': 'passed',
                           'commit': ('f' * 40 if self.bad == 'mismatch' else source['commit']),
                           'tree': ('e' * 40 if self.bad == 'mismatch' else source['tree']),
                           'tests': sorted(json.loads(manifest_bytes)['tests']),
                           'test_log': test_log,
                           'test_log_sha256': hashlib.sha256(test_log.encode()).hexdigest(),
                           'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
                           'source_id': hashlib.sha256(manifest_bytes + dependency_bytes).hexdigest(),
                           'python': __import__('sys').version,
                           'cryptography': importlib.metadata.version('cryptography'),
                           'claims': {'production_privacy': self.bad == 'claims',
                                      'zero_knowledge': False,
                                      'consensus_integrated': False,
                                      'public_network': False, 'real_funds': False},
                           'network_policy': 'python-process-and-python-child-deny',
                           'network_scope': ('Python socket and DNS APIs in verifier process and Python children; '
                                             'non-Python child and direct os spawn/exec entrypoints refused'),
                           'network_used': False, 'blocked_attempts': 1,
                           'child_network_probe': 'blocked-before-child-user-network',
                           'unassessed': ['independent cryptographic review',
                                           'consensus integration', 'network anonymity',
                                           'production custody', 'external audit']}
                if self.bad == 'missing_evidence':
                    del receipt['network_scope']
                elif self.bad == 'bad_hash':
                    receipt['manifest_sha256'] = '0' * 64
                elif self.bad == 'inventory':
                    receipt['tests'] = ['wrong.test_id']
                elif self.bad == 'integer_claim':
                    receipt['claims']['production_privacy'] = 0
                elif self.bad == 'extra_field':
                    receipt['extra'] = True
                elif self.bad == 'bool_format':
                    receipt['format'] = True
                body = json.dumps(receipt)
                if self.bad == 'duplicate_key':
                    body = body[:-1] + ', "status": "failed"}'
                Path(command[command.index('--report') + 1]).write_text(body)
                return {'returncode': 0, 'timed_out': False, 'log_truncated': False}
            group = command[command.index('--worker') + 1]
            child = {'group': group, 'source_id': command[command.index('--source-id') + 1],
                     'run_id': command[command.index('--run-id') + 1],
                     'expected_ids': ['fixture.test_case'], 'successful_ids': ['fixture.test_case'],
                     'run': 1, 'skips': 0, 'failures': 0, 'errors': 0,
                     'expected_failures': 0, 'unexpected_successes': 0}
            Path(command[command.index('--output') + 1]).write_text(json.dumps(child))
            log.write_bytes(b'owned mocked Python process boundary\n')
            return {'returncode': 0, 'timed_out': False, 'log_truncated': False}

        for mode in (None, 'failed', 'missing', 'incomplete', 'mismatch', 'claims',
                     'missing_evidence', 'bad_hash', 'inventory', 'integer_claim',
                     'extra_field', 'bool_format', 'duplicate_key'):
            with self.subTest(wallet_result=mode):
                self.bad = mode
                output = Path(self.temp.name) / ('run-' + str(mode))
                with patch.object(current, 'ROOT', self.root), \
                     patch.object(current, 'GROUPS', {'native': ('tests', 'test_*.py', [])}), \
                     patch.object(current, 'coverage', return_value=profile), \
                     patch.object(current.base, 'source_identity', return_value=source), \
                     patch.object(current.base, 'run_process', side_effect=process), \
                     patch.object(current, 'privacy_proof_verification',
                                  return_value={'passed': True}), \
                     patch.object(current, 'privacy_proof_halo2_verification',
                                  return_value={'passed': True}), \
                     patch('builtins.print'):
                    code = current.run(output, 30)
                result = json.loads((output / 'result.json').read_bytes())
                if mode is None:
                    self.assertTrue(result['shielded_note_lab_verifier']['passed'],
                                    result['shielded_note_lab_verifier'])
                    self.assertTrue(result['privacy_proof_benchmark_verifier']['passed'])
                self.assertEqual(code, 0 if mode is None else 1)
                self.assertEqual(result['local_checks'], 'passed' if mode is None else 'failed')
                self.assertEqual(result['release_status'], 'blocked')
                self.assertFalse(result['public_network_ready'])
                self.assertEqual(result['scenario_qualification'], scenarios+engine_scenarios)
                self.assertTrue(all(x['status']=='unassessed' for x in result['scenario_qualification']))
                boundaries = result['coverage']['privacy_boundaries']
                self.assertEqual([x['area'] for x in boundaries], list(current.PRIVACY_BOUNDARIES))
                self.assertTrue(all(x['status'] == 'unassessed' for x in boundaries))
                self.assertNotIn('passed', [x['status'] for x in boundaries])
                self.assertEqual(len(result['javascript']['groups']), 5)
                for record in result['javascript']['groups']:
                    self.assertEqual(record['run_id'], result['run_id'])
                    self.assertEqual(record['source_id'], result['source_id'])


class CurrentPrivacyProofVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'
        self.component = self.root / 'tools/privacy-proof-benchmark'
        (self.component / 'src').mkdir(parents=True)
        (self.component / 'go').mkdir()
        self.circuit = self.component / 'go/benchmark.go'
        self.circuit.write_text('package benchmark\n')
        self.python_tests = ['test_contract.Example.test_exact']
        self.go_tests = ['TestExactReceipt']
        self.manifest = {
            'format': 2,
            'package': 'privacy-proof-benchmark',
            'files': [],
            'python_tests': self.python_tests,
            'go_tests': self.go_tests,
            'circuit_files': ['go/benchmark.go'],
            'rust_tests': [],
            'halo2_circuit_files': [],
        }
        self.manifest_path = self.component / 'SOURCE_MANIFEST.json'
        self.manifest_path.write_text(json.dumps(self.manifest))
        self.dependencies = self.component / 'DEPENDENCIES.json'
        self.dependencies.write_text('{}')
        (self.component / 'src/privacy_proof_benchmark.py').write_text(
            'import json\n'
            'EXPECTED_CLAIMS={"production_privacy":False,"consensus_integrated":False,'
            '"network_anonymity":False,"production_custody":False,'
            '"real_funds":False,"independent_review":False}\n'
            'EXPECTED_UNASSESSED=("one","two")\n'
            'def load_unique_json_bytes(data): return json.loads(data)\n'
            'def validate_backend_receipt(value, *, expected_commit, expected_tree, '
            'expected_circuit_digest):\n'
            ' assert value["commit"] == expected_commit\n'
            ' assert value["tree"] == expected_tree\n'
            ' assert value["digest"] == expected_circuit_digest\n'
            ' return value\n')
        self.source = {'commit': 'a' * 40, 'tree': 'b' * 40, 'source_id': 'c' * 64}

    @staticmethod
    def sha(data):
        return hashlib.sha256(data).hexdigest()

    def circuit_digest(self):
        data = self.circuit.read_bytes()
        value = hashlib.sha256()
        value.update(b'go/benchmark.go\0')
        value.update(str(len(data)).encode())
        value.update(b'\0')
        value.update(data)
        return value.hexdigest()

    def receipt(self, output, mode):
        stem = 'privacy-proof-benchmark-verifier'
        contents = {
            'python': b'python tests passed\n',
            'go_test': b'go tests passed\n',
            'go_build': b'',
            'benchmark': b'benchmark passed\n',
        }
        logs = {}
        suffix = {'python': 'python', 'go_test': 'go-test',
                  'go_build': 'go-build', 'benchmark': 'benchmark'}
        for name, raw in contents.items():
            path = output / f'{stem}.{suffix[name]}.log'
            path.write_bytes(raw)
            if name == 'python':
                logs[name] = {'path': path.name, 'sha256': self.sha(raw), 'bytes': len(raw)}
            else:
                logs[name] = {'returncode': 0, 'seconds_ns': 1, 'log': path.name,
                              'log_sha256': self.sha(raw), 'log_bytes': len(raw)}
        digest = self.circuit_digest()
        backend_value = {'commit': self.source['commit'], 'tree': self.source['tree'],
                         'digest': digest}
        backend_path = output / f'{stem}.backend.json'
        backend_path.write_text(json.dumps(
            {'different': True} if mode == 'backend_value' else backend_value))
        backend_bytes = backend_path.read_bytes()
        receipt = {
            'format': 1,
            'status': 'passed',
            'commit': self.source['commit'],
            'tree': self.source['tree'],
            'manifest_sha256': self.sha(self.manifest_path.read_bytes()),
            'source_id': self.sha(self.manifest_path.read_bytes()
                                  + self.dependencies.read_bytes()),
            'circuit_source_digest': digest,
            'python': __import__('sys').version,
            'go': 'go version go1.26.0 linux/amd64',
            'python_tests': self.python_tests,
            'go_tests': self.go_tests,
            'logs': logs,
            'backend_receipt': {'path': backend_path.name,
                                'sha256': self.sha(backend_bytes),
                                'bytes': len(backend_bytes), 'value': backend_value},
            'network_policy': 'linux-user-and-network-namespace',
            'network_used': False,
            'claims': {'production_privacy': False, 'consensus_integrated': False,
                       'network_anonymity': False, 'production_custody': False,
                       'real_funds': False, 'independent_review': False},
            'unassessed': ['one', 'two'],
        }
        if mode == 'commit': receipt['commit'] = 'd' * 40
        elif mode == 'manifest': receipt['manifest_sha256'] = '0' * 64
        elif mode == 'source_id': receipt['source_id'] = '0' * 64
        elif mode == 'circuit': receipt['circuit_source_digest'] = '0' * 64
        elif mode == 'log': receipt['logs']['go_test']['log_sha256'] = '0' * 64
        elif mode == 'path': receipt['logs']['python']['path'] = '../python.log'
        elif mode == 'claim': receipt['claims']['real_funds'] = True
        elif mode == 'integer_claim': receipt['claims']['real_funds'] = 0
        elif mode == 'network': receipt['network_used'] = True
        elif mode == 'tests': receipt['go_tests'] = []
        elif mode == 'go_returncode': receipt['logs']['go_test']['returncode'] = 1
        elif mode == 'extra': receipt['extra'] = True
        elif mode == 'missing': del receipt['backend_receipt']
        return receipt

    def check(self, mode):
        output = Path(self.temp.name) / ('out-' + str(mode))
        output.mkdir()

        def process(command, root, log, timeout):
            receipt = self.receipt(output, mode)
            body = json.dumps(receipt)
            if mode == 'duplicate':
                body = body[:-1] + ',"status":"failed"}'
            Path(command[command.index('--report') + 1]).write_text(body)
            log.write_bytes(b'outer verifier log\n')
            return {'returncode': int(mode == 'process'), 'timed_out': False,
                    'log_truncated': False}

        with patch.object(current.base, 'run_process', side_effect=process):
            return current.privacy_proof_verification(
                self.root, output, self.source, 30)

    def test_exact_source_bound_receipt_passes(self):
        result = self.check(None)
        self.assertTrue(result['passed'], result)

    def test_forged_incomplete_or_unbound_receipts_fail_closed(self):
        modes = ('process', 'commit', 'manifest', 'source_id', 'circuit', 'log',
                 'path', 'backend_value', 'claim', 'integer_claim', 'network',
                 'tests', 'go_returncode', 'extra', 'missing', 'duplicate')
        for mode in modes:
            with self.subTest(mode=mode):
                self.assertFalse(self.check(mode)['passed'])


class CurrentHalo2VerifierBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'; self.output = Path(self.temp.name) / 'evidence'
        component = self.root / 'tools/privacy-proof-benchmark'; (component / 'src').mkdir(parents=True)
        (component / 'halo2/src').mkdir(parents=True)
        self.manifest = {'format': 2, 'package': 'privacy-proof-benchmark', 'files': [],
                         'python_tests': [], 'go_tests': [], 'rust_tests': ['fixture.test'],
                         'circuit_files': [], 'halo2_circuit_files': ['halo2/src/circuit.rs']}
        (component / 'SOURCE_MANIFEST.json').write_text(json.dumps(self.manifest, sort_keys=True))
        (component / 'DEPENDENCIES_HALO2.json').write_text('{}')
        (component / 'halo2/src/circuit.rs').write_text('circuit fixture\n')
        shutil.copyfile(Path(__file__).parents[3] / 'tools/privacy-proof-benchmark/src/privacy_proof_benchmark.py',
                        component / 'src/privacy_proof_benchmark.py')
        self.source = {'commit': 'a' * 40, 'tree': 'b' * 40, 'source_id': 'c' * 64}

    def fixture(self, output):
        component = self.root / 'tools/privacy-proof-benchmark'
        manifest_bytes = (component / 'SOURCE_MANIFEST.json').read_bytes()
        dependency_bytes = (component / 'DEPENDENCIES_HALO2.json').read_bytes()
        digest = hashlib.sha256()
        digest.update(b'halo2/src/circuit.rs'); digest.update(b'\0')
        data = (component / 'halo2/src/circuit.rs').read_bytes()
        digest.update(str(len(data)).encode()); digest.update(b'\0'); digest.update(data)
        public_inputs = ['version', 'genesis', 'asset', 'context', 'epoch', 'height', 'expiry', 'policy',
                         'root', 'nullifier', 'output_commitment_0', 'output_commitment_1', 'fee',
                         'authorization_digest']
        cases = [('valid-proof', 'accept'), ('mutated-proof', 'reject'), ('changed-public-input', 'reject'),
                 ('wrong-verifying-key', 'reject'), ('invalid-membership', 'reject'), ('invalid-nullifier', 'reject'),
                 ('invalid-output-commitment', 'reject'), ('invalid-fee-conservation', 'reject'),
                 ('out-of-range-value', 'reject'), ('changed-authorization-digest', 'reject')]
        report = {'format': 1, 'status': 'passed', 'actual_backend_run': True,
                  'backend': {'id': 'zcash-halo2-pasta-ipa', 'halo2_proofs': '0.4.0', 'halo2_gadgets': '0.6.0',
                              'halo2_poseidon': '0.2.0', 'pasta_curves': '0.6.0', 'field': 'Pallas base field',
                              'commitment_curve': 'Vesta', 'proof_system': 'Halo2 PLONKish IPA',
                              'hash': 'Poseidon P128Pow5T3', 'transcript': 'Blake2b', 'license': 'MIT OR Apache-2.0'},
                  'circuit': {'id': '1soft/privacy-proof-benchmark/halo2-pasta/v1', 'source_digest': digest.hexdigest(),
                              'k': 13, 'domain_rows': 8192, 'estimated_proof_bytes': 3168, 'depth': 4,
                              'inputs': 1, 'outputs': 2, 'value_bits': 64, 'public_inputs': public_inputs,
                              'private_inputs_retained': False},
                  'source': {'commit': self.source['commit'], 'tree': self.source['tree']},
                  'parameters': {'kind': 'deterministic-public-halo2-ipa-parameters', 'ceremony': False,
                                 'reusable': True, 'production': False, 'parameters_sha256': '1' * 64,
                                 'parameters_bytes': 524356, 'verifying_key_binding': 'halo2-proofs-0.4.0-pinned-debug-nonportable',
                                 'verifying_key_sha256': '2' * 64, 'verifying_key_bytes': 26882,
                                 'proving_key_serialization_assessed': False,
                                 'proving_key_serialization_reason': 'halo2_proofs 0.4.0 public API exposes no proving-key serialization'},
                  'artifacts': {'proof_sha256': '3' * 64, 'proof_bytes': 3136,
                                'public_instances_sha256': '4' * 64, 'public_instances_bytes': 448},
                  'metrics': {'parameters_ns': 1, 'keygen_vk_ns': 1, 'keygen_pk_ns': 1,
                              'iterations': 1, 'prove_ns': [1], 'verify_ns': [1]},
                  'cases': [{'id': key, 'expected': value, 'observed': value} for key, value in cases],
                  'claims': {'production_privacy': False, 'consensus_integrated': False, 'network_anonymity': False,
                             'production_custody': False, 'real_funds': False, 'independent_review': False},
                  'unassessed': ['global nullifier uniqueness and consensus ordering', 'production parameter and verifying-key governance',
                                 'independent cryptographic review', 'wallet scanning and recovery',
                                 'network anonymity and metadata resistance', 'production custody and side-channel resistance',
                                 'public-network and real-funds safety']}
        backend_value = json.loads(json.dumps(report))
        backend_path = output / 'privacy-proof-benchmark-halo2-verifier.backend.json'
        backend_path.write_text(json.dumps(backend_value, sort_keys=True))
        logs = {}
        for name, suffix in (('python', 'python'), ('rust_test', 'rust-test'), ('rust_build', 'rust-build'), ('benchmark', 'benchmark')):
            path = output / f'privacy-proof-benchmark-halo2-verifier.{suffix}.log'
            path.write_bytes((name + ' fixture\n').encode())
            if name == 'python':
                logs[name] = {'path': path.name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'bytes': path.stat().st_size}
            else:
                logs[name] = {'returncode': 0, 'seconds_ns': 1, 'log': path.name,
                              'log_sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'log_bytes': path.stat().st_size}
        report['backend_receipt'] = {'path': backend_path.name, 'sha256': hashlib.sha256(backend_path.read_bytes()).hexdigest(),
                                     'bytes': backend_path.stat().st_size, 'value': backend_value}
        report.update({'format': 1, 'status': 'passed', 'commit': self.source['commit'], 'tree': self.source['tree'],
                       'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
                       'source_id': hashlib.sha256(manifest_bytes + dependency_bytes).hexdigest(),
                       'circuit_source_digest': digest.hexdigest(), 'python': __import__('sys').version,
                       'rustc': 'rustc 1.97.1 (abcdef123 2026-09-30)', 'cargo': 'cargo 1.97.1 (abcdef123 2026-09-30)', 'python_tests': [], 'rust_tests': ['fixture.test'],
                       'logs': logs, 'network_policy': 'linux-user-and-network-namespace', 'network_used': False,
                       'claims': {k: False for k in ('production_privacy','consensus_integrated','network_anonymity','production_custody','real_funds','independent_review')},
                       'unassessed': ['global nullifier uniqueness and consensus ordering','production parameter and verifying-key governance','independent cryptographic review','wallet scanning and recovery','network anonymity and metadata resistance','production custody and side-channel resistance','public-network and real-funds safety']})
        report = {key: report[key] for key in ('format', 'status', 'commit', 'tree', 'manifest_sha256', 'source_id',
                                               'circuit_source_digest', 'python', 'rustc', 'cargo', 'python_tests',
                                               'rust_tests', 'logs', 'backend_receipt', 'network_policy',
                                               'network_used', 'claims', 'unassessed')}
        return report

    def test_valid_halo2_receipt_passes_and_security_mutations_fail_closed(self):
        for mode in (None, 'source_id', 'digest', 'tests', 'log', 'backend', 'claims',
                     'claims_extra', 'toolchain', 'unassessed'):
            with self.subTest(mode=mode):
                output = self.output / (mode or 'valid'); output.mkdir(parents=True)
                def process(command, root, log, timeout):
                    report = self.fixture(output)
                    if mode == 'source_id': report['source_id'] = '0' * 64
                    if mode == 'digest': report['circuit_source_digest'] = '0' * 64
                    if mode == 'tests': report['rust_tests'] = ['forged.test']
                    if mode == 'log': report['logs']['rust_test']['log_sha256'] = '0' * 64
                    if mode == 'backend': report['backend_receipt']['value']['source']['commit'] = '0' * 40
                    if mode == 'claims': report['claims']['real_funds'] = True
                    if mode == 'claims_extra': report['claims']['extra'] = False
                    if mode == 'toolchain': report['rustc'] = 'rustc 1.98.0 (abcdef123 2026-10-01)'
                    if mode == 'unassessed': report['unassessed'] = []
                    Path(command[command.index('--report') + 1]).write_text(json.dumps(report))
                    log.write_bytes(b'halo2 boundary fixture\n')
                    return {'returncode': 0, 'timed_out': False, 'log_truncated': False}
                with patch.object(current.base, 'run_process', side_effect=process):
                    result = current.privacy_proof_halo2_verification(self.root, output, self.source, 30)
                self.assertEqual(result['passed'], mode is None, result)
