"""Real failed-run public history, explicitly synthetic restart metadata; no engine claim."""
import copy,importlib.util,json,os,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'tools/release'))
import check_protocol7_reconciliation as check
from protocol7_treasury import canonical

@unittest.skipUnless(os.environ.get('P7_RESTART_REPORT'),'actual public history not supplied')
class RestartMetadataTests(unittest.TestCase):
    def test_receipt_equality_cannot_substitute_for_full_state(self):
        v=json.loads(Path(os.environ['P7_RESTART_REPORT']).read_bytes());record=v['records']['active_revoke']
        snapshot=copy.deepcopy(record['witness']);store={'device':1,'inode':1,'uid':1000,'mode':0o600}
        r={'format':'1soft/protocol7-authenticated-restart/v1','node':3,'before':copy.deepcopy(snapshot),
           'after':copy.deepcopy(snapshot),'observed':copy.deepcopy(snapshot),'signed_header':record['signed_header'],
           'certificate':copy.deepcopy(record['certificate']),'before_store':copy.deepcopy(store),'after_store':copy.deepcopy(store),
           'old_application':{'pid':100,'start_ticks':1},'application':{'pid':101,'start_ticks':2},
           'engine':{'pid':102,'start_ticks':3},'latest_state_guaranteed':False}
        processes=[{'role':role,'node':3,**r[key]} for key,role in [('old_application','application'),('application','application'),('engine','engine')]]
        self.assertIs(check.validate_restart_metadata(r,processes,canonical(v['genesis'])),r)
        for name in ('hidden_state','hash','height','store','process','certificate','before_shape'):
            bad=copy.deepcopy(r)
            if name=='hidden_state':bad['observed']['state']['treasury']['fees']+=1
            elif name=='hash':bad['observed']['app_hash']='ab'*32
            elif name=='height':bad['observed']['height']+=1
            elif name=='store':bad['after_store']['inode']+=1
            elif name=='process':bad['engine']['pid']=1
            elif name=='certificate':bad['certificate']['header_height']+=1
            else:
                bad['before']['state']['blocks'][0]['height']=True
                bad['before']['app_hash']=check.application_hash(bad['before']['genesis'],bad['before']['height'],bad['before']['state'])
            self.assertEqual(bad['observed']['state']['receipts'],r['observed']['state']['receipts'])
            with self.subTest(name=name),self.assertRaises(ValueError):check.validate_restart_metadata(bad,processes,canonical(v['genesis']))
if __name__=='__main__':unittest.main()
