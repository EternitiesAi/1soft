"""Actual-origin read-only reconciliation and labeled audit/transport fault tests."""
import copy,os,unittest
from pathlib import Path
from unittest.mock import patch
from protocol7_vault import ChangeVault
from protocol7_treasury import field,need,parse,digest,numfield
from protocol7_wallet import _resolve
import test_protocol7_vault as origin
DraftVault=ChangeVault
@unittest.skipUnless(all(os.environ.get(k) for k in origin.INPUTS),'unassessed: actual P7 origin/binaries absent')
class PreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):origin.VaultTests.setUpClass()
    def setUp(self):
        self.a=origin.VaultTests();self.a.setUp();self.a.vault.__class__=DraftVault;self.a.import_note()
    def tearDown(self):self.a.tearDown()
    def stage(self):
        with patch.object(self.a.journal,'prepare',side_effect=RuntimeError('explicit before-journal fault')):
            with self.assertRaises(RuntimeError):self.a.prepare()
    def inspect(self):return self.a.vault.preparation_status(self.a.journal,self.a.commitment)
    def assert_readonly(self):
        a=self.a;cipher=a.path.read_bytes();changes=a.journal.db.total_changes;v=self.inspect()
        self.assertEqual(cipher,a.path.read_bytes());self.assertEqual(changes,a.journal.db.total_changes)
        self.assertEqual(set(v),{'format','status','input','request','source_txid','vault_revision','as_of_height','as_of_app_hash',
            'txid','raw_sha256','attempts','hold_reason','completed_at','latest_state_guaranteed','in_flight_state_known',
            'retry_authorized','automatic_retry'})
        for k in ('latest_state_guaranteed','in_flight_state_known','retry_authorized','automatic_retry'):self.assertIs(v[k],False)
        return v
    def test_actual_stage_before_journal_fault_is_point_in_time_absence_without_retry_authority(self):
        self.stage();v=self.assert_readonly()
        self.assertEqual(v['status'],'staged-without-retained-wire')
        self.assertEqual(v['source_txid'],self.a.ident);self.assertEqual(v['as_of_height'],self.a.report['record']['state_height'])
        for k in ('txid','raw_sha256','attempts','hold_reason','completed_at'):self.assertIsNone(v[k])
        with self.assertRaises(ValueError):self.a.vault.recover_prepared(self.a.journal,self.a.commitment)
    def test_actual_retained_wire_lost_local_return_attempt_and_reopen_are_readonly(self):
        a=self.a;ident=a.prepare();raw=a.journal.export(ident);v=self.assert_readonly()
        self.assertEqual((v['status'],v['txid'],v['raw_sha256'],v['attempts'],v['hold_reason']),
                         ('retained-held',ident,digest(raw),0,'unknown'))
        def lost(_):raise TimeoutError('explicit transport fault; no actual RPC in this test')
        a.journal.deliver_once(ident,lost);v=self.assert_readonly()
        self.assertEqual((v['status'],v['attempts'],v['hold_reason']),('attempted-held',1,'unknown'))
        a.vault=a.reopen();a.vault.__class__=DraftVault;self.assertEqual(self.assert_readonly(),v)
        # Explicit audit fault doubles using the actual generated second wire.
        obs,rows=a.journal._audit();row=copy.deepcopy(rows[ident])
        with patch.object(a.journal,'_audit',return_value=(obs,{'a':row,'b':row})):
            with self.assertRaisesRegex(ValueError,'^P7 staged journal wire ambiguous$'):self.inspect()
        row['completed_at']=a.report['record']['state_height']
        with patch.object(a.journal,'_audit',return_value=(obs,{ident:row})):
            with self.assertRaisesRegex(ValueError,'^P7 staged certified completion differs$'):self.inspect()
        self.assertEqual(self.assert_readonly(),v)

    def test_missing_stage_tampered_cipher_and_ambiguous_audit_fault_refuse(self):
        a=self.a
        with self.assertRaisesRegex(ValueError,'^P7 exact staged input absent or ambiguous$'):self.inspect()
        self.stage();cipher=a.path.read_bytes()
        with self.assertRaises(ValueError):a.vault.preparation_status(a.journal,numfield(123))
        a.path.write_bytes(cipher[:-1]+b'x')
        with self.assertRaises((ValueError,RuntimeError)):self.inspect()
        a.path.write_bytes(cipher)
        self.assertEqual(a.path.read_bytes(),cipher)
if __name__=='__main__':unittest.main()
