"""Real P4 replay projected without authority, precision loss, or hidden signing data."""
import copy,json,unittest
from p4_fixture import build,bundle
from p4_evidence import verify_evidence
try:
    from p4_explorer import snapshot_view,project_report
except ImportError:
    snapshot_view=project_report=None

class ProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.c=build(rejected=True)
    def view(self,h=16):
        self.assertIsNotNone(snapshot_view,"P4 verified explorer projection has not been implemented")
        return snapshot_view(bundle(self.c,h),self.c['genesis'],self.c['policy'],now_ns=self.c['now_ns'])
    def test_recorded_balance_and_checkpoint_are_exact(self):
        v=self.view();a=next(a for a in v['accounts'] if a['id']==self.c['payer'])
        self.assertEqual(a['recorded_balance'],'874');self.assertEqual(v['checkpoint']['state_height'],'16')
        self.assertEqual(v['checkpoint']['header_height'],'17');self.assertEqual(v['checkpoint']['registry_epoch'],'2')
        self.assertEqual(v['asset'],'DEV');self.assertFalse(v['spending_authority'])
    def test_payments_exclude_management_and_rejected_duplicates(self):
        v=self.view();self.assertEqual(len(v['payments']),4)
        self.assertEqual(sorted(p['units'] for p in v['payments']),['11','38','58','7'])
        self.assertEqual(sum(p['units']=='38' for p in v['payments']),1)
    def test_page_never_carries_signed_envelopes_or_full_history(self):
        v=self.view();raw=json.dumps(v)
        for word in ['"signature"','"envelope"','"history"','"attempts"','"headers"']:
            self.assertNotIn(word,raw)
        self.assertFalse(v['pending_wallet_debits_included']);self.assertFalse(v['latest_state_guaranteed'])
    def test_budget_remaining_is_recorded_limit_not_authority(self):
        v=self.view();b=v['budgets'][0]
        self.assertEqual((b['cap'],b['spent'],b['recorded_remaining']),('200','100','100'))
        self.assertEqual(v['grants'][0]['budget_id'],b['id'])
    def test_pending_change_does_not_increment_active_epoch(self):
        v=self.view(3);self.assertEqual(v['checkpoint']['registry_epoch'],'0')
        self.assertEqual(v['registry']['pending']['phase'],'queued')
    def test_invalid_evidence_never_becomes_display_data(self):
        self.assertIsNotNone(snapshot_view);e=bundle(self.c);e['state']['native']['accounts'][0][2]+=1
        with self.assertRaises(ValueError):snapshot_view(e,self.c['genesis'],self.c['policy'],now_ns=self.c['now_ns'])
    def test_expired_policy_refuses_view(self):
        self.assertIsNotNone(snapshot_view)
        with self.assertRaises(ValueError):snapshot_view(bundle(self.c),self.c['genesis'],self.c['policy'],now_ns=self.c['now_ns']+3600*10**9)
    def test_missing_account_stays_missing(self):
        self.assertNotIn('unknown', [a['id'] for a in self.view()['accounts']])
    def test_all_native_amounts_epochs_heights_are_strings(self):
        v=self.view()
        for a in v['accounts']:
            for k in ['nonce','epoch','recorded_balance']:self.assertIsInstance(a[k],str)
        for p in v['payments']:
            for k in ['units','fee_units','height','index']:self.assertIsInstance(p[k],str)
