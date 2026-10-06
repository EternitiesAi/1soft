"""Strict public merchant receipt refuses early claim/source/identity tampering."""
import copy,json,os,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools/release'));sys.path.insert(0,str(ROOT/'scripts'))
from check_protocol7_merchant import validate,load

@unittest.skipUnless(os.environ.get('P7_MERCHANT_REPORT') and os.environ.get('P7_MERCHANT_WORKER'),
                     'unassessed: completed actual merchant engine receipt not supplied')
class ReportTests(unittest.TestCase):
    def test_early_tamper_refused_before_native_replay(self):
        p=Path(os.environ['P7_MERCHANT_REPORT']);base=load(p)
        cases=[]
        def change(fn):
            bad=copy.deepcopy(base);fn(bad);cases.append(bad)
        change(lambda v:v.update(status='candidate-passed'))
        change(lambda v:v.update(extra=True))
        change(lambda v:v['claims'].update(merchant_redemption=True))
        change(lambda v:v['claims'].update(real_funds=True))
        change(lambda v:v['claims'].update(independent_disclosure_decryption=True))
        change(lambda v:v['claims'].update(external_exactly_once_delivery=True))
        change(lambda v:v['claims'].update(quote_precommitted_request=1))
        change(lambda v:v['checks'].pop())
        change(lambda v:v['checks'][0].update(passed=1))
        change(lambda v:v['checks'][0].update(evidence={'candidate':True}))
        change(lambda v:v['checks'][2].update(passed=False))
        change(lambda v:v['source'].update(clean=False))
        change(lambda v:v['source'].update(clean=True,status_porcelain=' M src/protocol7_merchant.py'))
        change(lambda v:v['source']['files'].pop('src/protocol7_merchant.py'))
        change(lambda v:v['source']['files']['src/protocol7_merchant.py'].update(sha256='00'*32))
        change(lambda v:v['inputs']['engine'].update(sha256='00'*32))
        change(lambda v:v['inputs'].pop('controller'))
        change(lambda v:v['artifacts'][0].update(sha256='00'*32))
        change(lambda v:v.update(commands=[{}]))
        for i,v in enumerate(cases):
            with self.subTest(index=i):
                with self.assertRaises((ValueError,KeyError,TypeError)):
                    validate(v,p,Path(os.environ['P7_MERCHANT_WORKER']))

if __name__=='__main__':unittest.main()
