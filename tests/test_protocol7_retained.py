"""Actual certified origin refuses invented retained authority; no witness fabrication."""
import copy,os,unittest
from unittest.mock import patch
from protocol7_treasury import numfield
import test_protocol7_vault as origin

@unittest.skipUnless(all(os.environ.get(k) for k in origin.INPUTS),'unassessed: actual P7 origin/binaries not supplied')
class RetainedSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):origin.VaultTests.setUpClass()
    def setUp(self):
        self.actual=origin.VaultTests();self.actual.setUp();self.actual.import_note()
    def tearDown(self):self.actual.tearDown()
    def test_actual_origin_without_retained_request_unknown_source_and_forgery_refuse_before_proof(self):
        a=self.actual;raw=a.path.read_bytes();calls=[]
        def forbidden(*_):calls.append('unexpected');raise AssertionError('refused authority proved')
        with patch.object(a.prover,'produce',side_effect=forbidden):
            with self.assertRaisesRegex(ValueError,'^P7 retained source request absent or ambiguous$'):
                a.vault.prepare_retained_change(a.journal,a.prover,a.ident,amount=1,valid_until=20,request=numfield(9101))
            with self.assertRaises(ValueError):
                a.vault.prepare_retained_change(a.journal,a.prover,'ab'*32,amount=1,valid_until=20,request=numfield(9101))
            bad=copy.deepcopy(a.report['record']);bad['raw_sha256']='ab'*32
            with patch.object(a.journal,'recorded_receipt',return_value=bad):
                with self.assertRaisesRegex(ValueError,'^P7 origin wire differs$'):
                    a.vault.prepare_retained_change(a.journal,a.prover,a.ident,amount=1,valid_until=20,request=numfield(9101))
        self.assertEqual(calls,[]);self.assertEqual(a.path.read_bytes(),raw)
        self.assertEqual(a.vault.inventory()['retained_preparations'],[])

if __name__=='__main__':unittest.main()
