"""Real local terminal compressed backup/restore/export, with synthetic keys."""
import json
import unittest
from unittest.mock import patch
import test_custody as core
import test_custody_cli as cli_helpers
import test_compressed as compressed_helpers


class CompressedCliTests(unittest.TestCase):
    setUp = compressed_helpers.owned_setup
    sign = core.CustodyTests.sign
    select = core.CustodyTests.select
    rows = core.CustodyTests.rows
    cli = cli_helpers.CustodyCliTests.cli
    backup_args = cli_helpers.CustodyCliTests.backup_args

    def test_terminal_v3_backup_restore_status_and_original_wire_export(self):
        before = self.rows()
        result = self.cli([*self.backup_args(), '--format', '3'], terminal=True)
        self.assertEqual(result.returncode, 0, result.stdout.decode())
        self.assertTrue(self.bp.read_bytes().startswith(b'1SOFTP4B3\n'))
        result = self.cli(['restore', '--backup', str(self.bp), '--output', str(self.ap)], terminal=True)
        self.assertEqual(result.returncode, 0, result.stdout.decode())
        result = self.cli(['status', '--archive', str(self.ap)])
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        view = json.loads(result.stdout)
        self.assertEqual(view['pending_debit_units'], '100')
        self.assertFalse(view['dispatch_enabled'])
        output = self.root/'original.json'
        result = self.cli(['recover', '--archive', str(self.ap), '--decision-id', self.raven,
                           '--payer', self.c.payer, '--grant', 'raven', '--output', str(output)])
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(output.read_bytes(), self.w.recover(self.raven, **self.select()))
        self.assertEqual(self.rows(), before)

    def test_terminal_v3_retains_selected_positive_receipt_and_consumed_unresolved_hold(self):
        q = self.d.prepare(self.atlas,**self.select('atlas'))
        with patch('p4_delivery.submit_once',side_effect=RuntimeError('fixture I/O loss')):
            with self.assertRaises(RuntimeError): self.d.send(q['review'],q['confirmation'])
        self.c.block([self.w.recover(self.raven,**self.select())]); evidence = self.c.evidence()
        self.d.import_receipt(self.raven,evidence,**self.select())
        self.w.sync(evidence,expected_revision=self.w.status()['revision']); before = self.rows()
        for args, terminal in (([*self.backup_args(),'--format','3'],True),
                               (['restore','--backup',str(self.bp),'--output',str(self.ap)],True),
                               (['status','--archive',str(self.ap)],False)):
            result = self.cli(args,terminal=terminal)
            self.assertEqual(result.returncode,0,(result.stdout+result.stderr).decode())
        view = json.loads(result.stdout)
        self.assertEqual(view['pending_debit_units'],'40')
        atlas = next(r for r in view['decisions'] if r['id']==self.atlas)
        self.assertEqual(atlas['transport_observation'],'unresolved')
        self.assertTrue(atlas['attempt_recorded']); self.assertFalse(atlas['safe_to_resend'])
        output = self.root/'receipt.json'
        result = self.cli(['export-receipt','--archive',str(self.ap),'--decision-id',self.raven,
                           '--payer',self.c.payer,'--grant','raven','--output',str(output)])
        self.assertEqual(result.returncode,0,result.stderr.decode())
        self.assertEqual(core.encode(json.loads(output.read_bytes())),core.encode(evidence))
        self.assertEqual(self.rows(),before)

    def test_v3_without_private_terminal_and_unknown_format_create_no_artifact(self):
        for selector in ('3','4'):
            result = self.cli([*self.backup_args(),'--format',selector])
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(self.bp.exists())


if __name__ == '__main__': unittest.main()
