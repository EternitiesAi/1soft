import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from check_release import (canonical, digest, javascript_result, release_status,
                           run_process, source_identity, store_json, successful, valid_child)


def report():
    return {'expected_ids': ['module.Class.test_one'], 'successful_ids': ['module.Class.test_one'],
            'run': 1, 'skips': 0, 'errors': 0, 'failures': 0,
            'expected_failures': 0, 'unexpected_successes': 0}


class ResultTests(unittest.TestCase):
    def test_exact_nonempty_success_passes(self): self.assertTrue(successful(report()))
    def test_zero_cases_refused(self):
        self.assertFalse(successful({**report(), 'expected_ids': [], 'successful_ids': [], 'run': 0}))
    def test_skip_refused(self): self.assertFalse(successful({**report(), 'skips': 1}))
    def test_expected_failure_refused(self): self.assertFalse(successful({**report(), 'expected_failures': 1}))
    def test_unexpected_success_refused(self): self.assertFalse(successful({**report(), 'unexpected_successes': 1}))
    def test_error_and_failure_refused(self):
        for field in ('errors', 'failures'):
            with self.subTest(field=field): self.assertFalse(successful({**report(), field: 1}))
    def test_duplicate_requested_id_refused(self):
        r = report(); r['expected_ids'] *= 2; r['successful_ids'] *= 2; r['run'] = 2
        self.assertFalse(successful(r))
    def test_duplicated_success_cannot_hide_missing_case(self):
        r = report(); r['expected_ids'].append('another.test'); r['successful_ids'] *= 2; r['run'] = 2
        self.assertFalse(successful(r))
    def test_partial_run_refused(self):
        self.assertFalse(successful({**report(), 'successful_ids': [], 'run': 0}))
    def test_boolean_count_is_not_one_test(self): self.assertFalse(successful({**report(), 'run': True}))
    def test_claimed_pass_without_case_evidence_refused(self): self.assertFalse(successful({'passed': True}))
    def test_local_pass_keeps_release_blocked(self):
        r = release_status(True)
        self.assertEqual(r['local_checks'], 'passed'); self.assertEqual(r['release_status'], 'blocked')
        self.assertFalse(r['real_funds_ready']); self.assertFalse(r['public_network_ready'])
        self.assertFalse(r['consensus_executed']); self.assertTrue(r['unassessed'])
    def test_js_summary_requires_all_counters(self):
        with self.assertRaises(ValueError): javascript_result(b'# tests 30\n# pass 30\n')
    def test_js_skip_cannot_pass(self):
        r = javascript_result(b'# tests 30\n# pass 29\n# fail 0\n# cancelled 0\n# skipped 1\n# todo 0\n')
        self.assertFalse(r['passed'])
    def test_js_duplicate_summary_refused(self):
        with self.assertRaises(ValueError): javascript_result(b'# tests 30\n# tests 30\n')

    def test_passing_result_from_another_source_is_not_reused(self):
        child = {**report(), 'group': 'native', 'source_id': 'old', 'run_id': 'this-run'}
        proc = {'returncode': 0, 'timed_out': False, 'log_truncated': False}
        self.assertFalse(valid_child(child, proc, 'native', 'new', 'this-run'))
    def test_passing_result_from_another_run_is_not_reused(self):
        child = {**report(), 'group': 'native', 'source_id': 'same', 'run_id': 'earlier-run'}
        proc = {'returncode': 0, 'timed_out': False, 'log_truncated': False}
        self.assertFalse(valid_child(child, proc, 'native', 'same', 'new-run'))
    def test_nonzero_child_exit_cannot_be_overridden_by_passing_json(self):
        child = {**report(), 'group': 'native', 'source_id': 'same', 'run_id': 'this-run'}
        proc = {'returncode': 3, 'timed_out': False, 'log_truncated': False}
        self.assertFalse(valid_child(child, proc, 'native', 'same', 'this-run'))


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        self.git('init', '-q'); self.git('config', 'user.name', 'Local test fixture')
        self.git('config', 'user.email', 'fixture@localhost.invalid')
        (self.root/'source.py').write_text('print("fixture")\n')
        (self.root/'.gitignore').write_text('__pycache__/\n')
        self.git('add', '.'); self.git('commit', '-qm', 'fixture')
    def tearDown(self): self.temp.cleanup()
    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.DEVNULL)
    def test_source_includes_every_tracked_file(self):
        s = source_identity(self.root)
        self.assertEqual(s['tracked_files'], 2)
        self.assertEqual(s['tree'], self.git('rev-parse', 'HEAD^{tree}').decode().strip())
        for f in s['files']: self.assertEqual(f['sha256'], digest((self.root/f['path']).read_bytes()))
    def test_edited_source_refused(self):
        (self.root/'source.py').write_text('changed')
        with self.assertRaises(ValueError): source_identity(self.root)
    def test_extra_untracked_code_refused(self):
        (self.root/'new.py').write_text('pass')
        with self.assertRaises(ValueError): source_identity(self.root)
    def test_ignored_generated_cache_is_not_release_source(self):
        (self.root/'__pycache__').mkdir(); (self.root/'__pycache__/dummy.pyc').write_bytes(b'fixture')
        self.assertEqual(source_identity(self.root)['tracked_files'], 2)
    def test_deleted_source_refused(self):
        (self.root/'source.py').unlink()
        with self.assertRaises(ValueError): source_identity(self.root)
    def test_executable_mode_change_refused(self):
        (self.root/'source.py').chmod(0o755)
        with self.assertRaises(ValueError): source_identity(self.root)
    def test_symlink_in_tracked_source_refused(self):
        (self.root/'link.py').symlink_to('source.py'); self.git('add', '.'); self.git('commit', '-qm', 'link')
        with self.assertRaises(ValueError): source_identity(self.root)
    def test_source_id_changes_on_different_commit(self):
        before = source_identity(self.root)
        self.git('commit', '--allow-empty', '-qm', 'different candidate')
        after = source_identity(self.root)
        self.assertEqual(before['tree'], after['tree']); self.assertNotEqual(before['source_id'], after['source_id'])
    def test_output_json_is_exclusive_and_atomic_replace_explicit(self):
        p = self.root/'result.json'; store_json(p, {'status': 'running'})
        with self.assertRaises(FileExistsError): store_json(p, {'status': 'passed'})
        self.assertEqual(json.loads(p.read_bytes()), {'status': 'running'})
        store_json(p, {'status': 'done'}, replace=True)
        self.assertEqual(json.loads(p.read_bytes()), {'status': 'done'})
    def test_subprocess_failure_retains_log(self):
        p = self.root/'test.log'
        r = run_process([sys.executable, '-c', 'print("fixture failure"); raise SystemExit(3)'], self.root, p, 5)
        self.assertEqual(r['returncode'], 3); self.assertFalse(r['timed_out'])
        self.assertIn(b'fixture failure', p.read_bytes())
    def test_subprocess_timeout_is_not_a_pass(self):
        p = self.root/'test.log'
        r = run_process([sys.executable, '-c', 'import time; print("started", flush=True); time.sleep(10)'],
                        self.root, p, 2)
        self.assertTrue(r['timed_out']); self.assertNotEqual(r['returncode'], 0)
        self.assertIn(b'started', p.read_bytes())


if __name__ == '__main__': unittest.main()
