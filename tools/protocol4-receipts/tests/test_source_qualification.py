"""Narrow qualification tests; mocks do not qualify an actual checkout."""
import copy
import importlib.util
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('p4_receipts_test_verify', ROOT / 'tools/verify.py')
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.native = Path('/caller-selected-native-checkout')
        self.parent = '4' * 40
        self.source = {'commit': 'd' * 40, 'tree': 'e' * 40, 'source_id': 'f' * 64,
                       'tracked_files': 1, 'files': [{'path': 'src/pinned.py', 'sha256': 'a' * 64}]}

    def call(self, ancestry=0, source=None, expected=None):
        source = self.source if source is None else source
        with patch.object(verify, '_release_source_identity', return_value=source) as identity, \
             patch.object(verify.subprocess, 'run', return_value=subprocess.CompletedProcess([], ancestry)) as git:
            result = verify.qualified_source(self.native, self.parent, expected=expected)
            identity.assert_called_once_with(self.native)
            self.assertEqual(git.call_args.args[0], ['git', '-C', str(self.native),
                'merge-base', '--is-ancestor', self.parent, source['commit']])
            self.assertEqual(git.call_args.kwargs['timeout'], 15)
            return result

    def test_clean_integrated_descendant_is_qualified_without_requiring_parent_head(self):
        self.assertNotEqual(self.source['commit'], self.parent)
        self.assertEqual(self.call(), self.source)

    def test_unrelated_or_missing_parent_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'not an ancestor'): self.call(ancestry=1)
        with self.assertRaisesRegex(ValueError, 'unable to establish'): self.call(ancestry=128)

    def test_dirty_or_byte_mismatched_source_gate_is_not_bypassed(self):
        with patch.object(verify, '_release_source_identity', side_effect=ValueError('dirty source')), \
             patch.object(verify.subprocess, 'run') as git:
            with self.assertRaisesRegex(ValueError, 'dirty source'):
                verify.qualified_source(self.native, self.parent)
            git.assert_not_called()

    def test_before_after_exact_identity_must_match(self):
        self.assertEqual(self.call(expected=copy.deepcopy(self.source)), self.source)
        for key, value in (('commit', 'b' * 40), ('tree', 'c' * 40),
                           ('source_id', 'a' * 64), ('files', [{'path': 'changed'}])):
            after = copy.deepcopy(self.source); after[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'identity changed'):
                self.call(source=after, expected=self.source)
