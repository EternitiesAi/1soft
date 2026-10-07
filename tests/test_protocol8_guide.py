"""Read-only guide boundaries with explicitly labeled fake inventory authority."""
import copy,io,json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'tools/payment-console/src')]
import payment_console as console
from protocol8_console import parser
from protocol8_wallet import FORMAT

SHA='ab'*32;TX='cd'*32;NOTE='ef'*32;ID='12'*32
def inventory():
    return {'format':FORMAT,'wallet_id':ID,'recipient_key':'34'*32,'revision':3,'as_of_height':7,
        'notes':[NOTE],'obligations':[{'input':NOTE,'request':'56'*32,'txid':TX,'attempts':1,'completed':False}],
        'freshness_established':False,'automatic_retry':False}
def reply():
    return {'status':'authenticated-inventory','wallet_id':ID,'inventory':inventory()}

class GuideTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name);root.chmod(0o700)
        self.args=SimpleNamespace(workspace=root/'config',credentials=root/'credentials',genesis_sha256=SHA,
            command='guide',commitment=None,txid=None,receipt=None)
        self.runner=console.Runner(self.args);self.output=io.StringIO()
    def operate(self):return console.operate(self.args,self.runner,self.output,io.StringIO())
    def test_parser_needs_no_journal_endpoint_or_intent(self):
        base=['--workspace','/tmp/config','--credentials','/tmp/credentials','--genesis-sha256',SHA,'guide']
        args=parser().parse_args(base);self.assertEqual(args.command,'guide')
        self.assertIsNone(args.commitment);self.assertIsNone(args.txid)
        for key in ('journal','endpoint','destination','payment'):self.assertFalse(hasattr(args,key))
        with patch('sys.stderr',io.StringIO()),self.assertRaises(SystemExit):
            parser().parse_args(base+['--commitment',NOTE,'--txid',TX])
    def test_only_one_protected_inventory_child(self):
        with patch.object(self.runner,'run',return_value=reply()) as run:view=self.operate()
        run.assert_called_once_with('wallet','inventory')
        self.assertFalse(view['effectful_commands_started']);self.assertFalse(view['can_submit'])
    def test_note_selection_fills_only_exact_commitment(self):
        self.args.commitment=NOTE
        with patch.object(self.runner,'run',return_value=reply()):view=self.operate()
        self.assertEqual(view['selection'],{'kind':'commitment','identifier':NOTE})
        prep=view['templates'][-1];self.assertEqual(prep['command'],'prepare')
        self.assertEqual(prep['argv'][prep['argv'].index('--commitment')+1],NOTE)
        for key in ('--request','--destination','--payment','--valid-until','--payment-expiry'):
            self.assertTrue(prep['argv'][prep['argv'].index(key)+1].startswith('<'))
    def test_tx_selection_fills_exact_identifier_without_submit_template(self):
        self.args.txid=TX
        with patch.object(self.runner,'run',return_value=reply()):view=self.operate()
        self.assertEqual([x['command'] for x in view['templates']],['observe','import-note','import-note','review','status','reconcile','export','deliver'])
        self.assertIn('--wire',view['templates'][1]['argv']);self.assertNotIn('--genesis-note',view['templates'][1]['argv'])
        self.assertIn('--genesis-note',view['templates'][2]['argv']);self.assertNotIn('--wire',view['templates'][2]['argv'])
        for item in view['templates'][3:]:
            self.assertEqual(item['argv'][item['argv'].index('--txid')+1],TX)
        self.assertFalse(view['selection_confers_authority'])
    def test_private_paths_and_request_id_are_omitted(self):
        self.args.txid=TX
        with patch.object(self.runner,'run',return_value=reply()):view=self.operate()
        raw=json.dumps(view)+console.render(view)
        for value in (str(self.args.workspace),str(self.args.credentials),'56'*32):
            self.assertNotIn(value,raw)
        self.assertIn('<PRIVATE_CREDENTIALS_FILE>',raw)
        self.assertNotIn('recipient_key',view)
        self.assertNotIn('request',view['obligations'][0])
    def test_flags_do_not_infer_phase_execution_or_delivery(self):
        for attempts in (0,1):
            for complete in (False,True):
                inv=inventory();inv['obligations'][0].update(attempts=attempts,completed=complete)
                view=console.guide_view(inv,ID,SHA,txid=TX)
                self.assertEqual(view['obligations'][0]['attempts'],attempts)
                self.assertEqual(view['obligations'][0]['completed'],complete)
                self.assertFalse(view['can_submit']);self.assertFalse(view['selection_confers_authority'])
                for name in ('execution_confirmed','delivery_authorized','phase','balance'):self.assertNotIn(name,view)
    def test_pending_wire_is_explicit_and_not_selectable(self):
        inv=inventory();inv['obligations'][0].update(txid=None,attempts=0,completed=False)
        view=console.guide_view(inv,ID,SHA);self.assertIn('no retained wire recorded',console.render(view))
        with self.assertRaises(ValueError):console.guide_view(inv,ID,SHA,txid=TX)
    def test_held_input_can_be_selected_but_no_availability_inferred(self):
        view=console.guide_view(inventory(),ID,SHA,commitment=NOTE)
        self.assertIn('availability is not inferred',console.render(view))
        self.assertEqual(view['notes'],[NOTE]);self.assertFalse(view['can_submit'])
    def test_missing_selection_refuses_after_inventory_without_other_child(self):
        self.args.txid='98'*32
        with patch.object(self.runner,'run',return_value=reply()) as run,self.assertRaises(ValueError):self.operate()
        run.assert_called_once_with('wallet','inventory')
    def test_invalid_or_double_selection_refuses_before_child(self):
        for commitment,txid in [('not-a-pin',None),(NOTE,TX),(None,'not-a-pin')]:
            self.args.commitment=commitment;self.args.txid=txid
            with patch.object(self.runner,'run') as run,self.assertRaises(ValueError):self.operate()
            run.assert_not_called()
    def test_unknown_fields_and_private_inventory_extension_refuse(self):
        for change in ({'opening':{'secret':'PRIVATE-SENTINEL'}},{'amount':4},{'format':'wrong'}):
            inv={**inventory(),**change}
            with self.assertRaises(ValueError):console.guide_view(inv,ID,SHA)
    def test_context_shapes_and_claims_refuse(self):
        variations=[{'wallet_id':TX},{'freshness_established':True},{'automatic_retry':True},
            {'revision':True},{'as_of_height':0},{'notes':[NOTE,NOTE]},{'recipient_key':'bad'}]
        for change in variations:
            with self.subTest(change=change),self.assertRaises(ValueError):
                console.guide_view({**inventory(),**change},ID,SHA)
        for change in ({'attempts':True},{'attempts':2},{'completed':1},{'txid':'bad'},
            {'opening':'PRIVATE-SENTINEL'},{'txid':None,'completed':True}):
            inv=inventory();inv['obligations'][0].update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):console.guide_view(inv,ID,SHA)
        inv=inventory();inv['obligations']*=2
        with self.assertRaises(ValueError):console.guide_view(inv,ID,SHA)
    def test_view_and_render_are_stable_and_do_not_change_input(self):
        inv=inventory();prior=copy.deepcopy(inv)
        first=console.guide_view(inv,ID,SHA,txid=TX);second=console.guide_view(inv,ID,SHA,txid=TX)
        self.assertEqual(first,second);self.assertEqual(console.render(first),console.render(second));self.assertEqual(inv,prior)
    def test_no_signed_observation_remains_unknown(self):
        inv=inventory();inv['as_of_height']=None
        text=console.render(console.guide_view(inv,ID,SHA))
        self.assertIn('none recorded',text);self.assertIn('current network freshness is not established',text)
    def test_child_refusal_suppresses_diagnostics_and_writes_nothing_by_default(self):
        with patch.object(console.Runner,'run',return_value={'status':'refused','reason':'PRIVATE-SENTINEL'}) as run:
            receipt,code=console.execute(self.args,self.output,io.StringIO())
        self.assertEqual(code,1);run.assert_called_once_with('wallet','inventory')
        self.assertNotIn('PRIVATE-SENTINEL',self.output.getvalue()+json.dumps(receipt))
        self.assertEqual(list(Path(self.temp.name).iterdir()),[])
    def test_optional_receipt_collision_refuses_before_inventory(self):
        self.args.receipt=Path(self.temp.name)/'receipt';self.args.receipt.write_bytes(b'old')
        self.args.receipt.chmod(0o600)
        with patch.object(console.Runner,'run') as run:_,code=console.execute(self.args,self.output,io.StringIO())
        self.assertEqual(code,1);run.assert_not_called();self.assertEqual(self.args.receipt.read_bytes(),b'old')

if __name__=='__main__':unittest.main()
