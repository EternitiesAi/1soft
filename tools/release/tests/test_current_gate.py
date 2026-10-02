"""Current checkout coverage must fail closed when its component map drifts."""
from pathlib import Path
import tempfile
import unittest

from check_current import COMPONENTS, GROUPS, coverage


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
