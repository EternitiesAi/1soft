"""Explicit backup format selection through the actual private terminal flow."""
import json
import unittest
import test_custody as core
import test_custody_cli as cli_helpers


class FormatCliTests(unittest.TestCase):
    setUp=core.CustodyTests.setUp
    sign=core.CustodyTests.sign
    select=core.CustodyTests.select
    cli=cli_helpers.CustodyCliTests.cli
    backup_args=cli_helpers.CustodyCliTests.backup_args

    def test_terminal_can_select_v2_and_read_historical_archive(self):
        result=self.cli([*self.backup_args(),'--format','2'],terminal=True)
        self.assertEqual(result.returncode,0,result.stdout.decode())
        self.assertTrue(self.bp.read_bytes().startswith(b'1SOFTP4B2\n'))
        result=self.cli(['restore','--backup',str(self.bp),'--output',str(self.ap)],terminal=True)
        self.assertEqual(result.returncode,0,result.stdout.decode())
        result=self.cli(['status','--archive',str(self.ap)])
        self.assertEqual(result.returncode,0,result.stderr.decode())
        view=json.loads(result.stdout)
        self.assertEqual(view['pending_debit_units'],'100')
        self.assertFalse(view['dispatch_enabled'])

    def test_unsupported_format_refuses_before_any_artifact(self):
        result=self.cli([*self.backup_args(),'--format','4'])
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(self.bp.exists())


if __name__=='__main__':unittest.main()
