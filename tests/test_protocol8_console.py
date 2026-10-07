"""Console behavior with labeled fake authority; disposable child-process checks."""
import hmac,io,json,os,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'src'),str(ROOT/'scripts'),str(ROOT/'tools/payment-console/src')]
import payment_console as console
import protocol8_wallet_cli as c
import protocol8_payment as p

SHA='ab'*32;TX='cd'*32;WIRE='ef'*32;ID='12'*32

def projection():
    return {'format':c.REVIEW_FORMAT,'private_review_blind':'57'*32,'wallet_id':ID,'txid':TX,
        'wire_sha256':WIRE,'wire_bytes':3560,'destination':'34'*32,'payment':4,'payment_expiry':56,
        'fee':1,'valid_from':2,'valid_until':32,'attempts':0,'completed':False,'as_of_height':1,
        'wallet_genesis_sha256':SHA,'genesis_sha256':SHA,'runtime_sha256':c.sha(c.canonical(c.runtime_files()))}

def payment(state='attempted-outcome-unknown',result=None):
    return {'status':'payment-status','wallet_id':ID,'txid':TX,'submission_state':state,
        'wallet_attempts':1,'wallet_completed':result is not None and result['status']=='executed-exact',
        'result':result,'execution_confirmed':result is not None and result['status']=='executed-exact'}

class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.args=SimpleNamespace(workspace=self.root/'config',credentials=self.root/'credentials',genesis_sha256=SHA,
            endpoint='http://127.0.0.1:26657',journal=self.root/'journal',txid=TX,command='submit',packet=None,receipt=None)
        self.runner=console.Runner(self.args);self.output=io.StringIO()
    def test_admission_never_execution(self):
        view=console.payment_view(payment('admission-accepted'));self.assertFalse(view['execution_confirmed'])
        self.assertFalse(view['can_submit']);self.assertIn('Execution is not confirmed',console.render(view))
    def test_unknown_and_incomplete_are_distinct(self):
        for state,word in (('attempted-outcome-unknown','unknown'),('attempt-record-incomplete','incomplete')):
            view=console.payment_view(payment(state));self.assertIn(word,console.render(view));self.assertFalse(view['can_submit'])
    def test_signed_exact_conflict_and_unresolved_remain_distinct(self):
        for status in ('executed-exact','conflict-held','unresolved-held'):
            result={'status':status,'state_height':7} if status=='executed-exact' else {'status':status,'as_of_height':7}
            view=console.payment_view(payment(result=result));self.assertEqual(view['state'],status)
            self.assertEqual(view['as_of_height'],7);self.assertFalse(view['can_submit'])
    def test_cancel_does_not_start_payment_child_or_create_journal(self):
        with patch.object(console,'review',return_value=(projection(),'56'*32)),patch.object(self.runner,'run') as run:
            view=console.operate(self.args,self.runner,self.output,io.StringIO('\n'))
        self.assertEqual(view['state'],'cancelled');run.assert_not_called();self.assertFalse(self.args.journal.exists())
        self.assertIn('Amount: 4 atomic units',self.output.getvalue())
        self.assertNotIn('payment',view['review']);self.assertNotIn('destination',view['review'])
    def test_exact_confirmation_reviews_again_and_dispatches_once(self):
        token='SUBMIT '+TX+' '+WIRE+'\n'
        with patch.object(console,'review',return_value=(projection(),'56'*32)) as review,patch.object(self.runner,'run',return_value=payment()) as run:
            view=console.operate(self.args,self.runner,self.output,io.StringIO(token))
        self.assertEqual(review.call_count,2);run.assert_called_once_with('payment','submit')
        self.assertEqual(view['state'],'attempted-outcome-unknown');self.assertTrue(view['review_revalidated'])
    def test_wrong_wire_confirmation_cancels(self):
        with patch.object(console,'review',return_value=(projection(),'56'*32)),patch.object(self.runner,'run') as run:
            view=console.operate(self.args,self.runner,self.output,io.StringIO('SUBMIT '+TX+' '+'00'*32+'\n'))
        self.assertEqual(view['state'],'cancelled');run.assert_not_called()
    def test_stale_attempt_after_confirmation_refuses_before_payment(self):
        later={**projection(),'attempts':1}
        with patch.object(console,'review',side_effect=[(projection(),'56'*32),(later,'78'*32)]),patch.object(self.runner,'run') as run:
            with self.assertRaises(ValueError):console.operate(self.args,self.runner,self.output,io.StringIO('SUBMIT '+TX+' '+WIRE+'\n'))
        run.assert_not_called()
    def test_attempted_or_completed_review_disables_submit(self):
        for delta in ({'attempts':1},{'completed':True}):
            with patch.object(console,'review',return_value=({**projection(),**delta},'56'*32)),patch.object(self.runner,'run') as run:
                with self.assertRaises(ValueError):console.operate(self.args,self.runner,self.output,io.StringIO('SUBMIT '+TX+' '+WIRE+'\n'))
            run.assert_not_called()
    def test_existing_or_symlink_journal_refuses_before_review(self):
        self.args.journal.write_bytes(b'original')
        with patch.object(console,'review') as review:
            with self.assertRaises(ValueError):console.operate(self.args,self.runner,self.output,io.StringIO())
        review.assert_not_called();self.assertEqual(self.args.journal.read_bytes(),b'original')
        self.args.journal.unlink();self.args.journal.symlink_to(self.root/'missing')
        with self.assertRaises(ValueError):console.fresh_journal(self.args)
    def test_bad_endpoint_precedes_child(self):
        self.args.endpoint='http://example.com:26657'
        with patch.object(self.runner,'run') as run:
            with self.assertRaises(ValueError):console.operate(self.args,self.runner,self.output,io.StringIO())
        run.assert_not_called()
    def test_private_review_file_hash_and_membership_are_checked(self):
        def fake(kind,command,extra):
            dest=Path(extra[-1]);raw=c.canonical(projection());c.private_output(dest,raw)
            return {'status':'private-intent-reviewed','txid':TX,'wallet_id':ID,'runtime_sha256':projection()['runtime_sha256'],
                'bytes':len(raw),'sha256':'00'*32,'private_file_created':True,'review_commitment_scheme':c.REVIEW_SCHEME}
        with patch.object(self.runner,'run',side_effect=fake):
            with self.assertRaises(ValueError):console.review(self.args,self.runner)
    def test_refusal_suppresses_private_exception(self):
        with patch.object(console,'operate',side_effect=ValueError('PRIVATE-SENTINEL')):
            receipt,code=console.execute(self.args,self.output,io.StringIO())
        self.assertEqual(code,1);self.assertNotIn('PRIVATE-SENTINEL',self.output.getvalue()+json.dumps(receipt))
    def test_receipt_collision_precedes_any_operation(self):
        self.args.receipt=self.root/'receipt';self.args.receipt.write_bytes(b'old');self.args.receipt.chmod(0o600)
        with patch.object(console,'operate') as operate:
            receipt,code=console.execute(self.args,self.output,io.StringIO())
        operate.assert_not_called();self.assertEqual(code,1);self.assertEqual(self.args.receipt.read_bytes(),b'old')
    def test_render_does_not_claim_latest_validity_or_balances(self):
        text=console.review_text(projection());self.assertIn('current network validity is not established',text)
        self.assertNotIn('balance',text.lower());self.assertNotIn('recipient_secret',text)

    def preparing(self):
        self.args.command='prepare';self.args.commitment=TX;self.args.request='23'*32
        self.args.destination='34'*32;self.args.payment=4;self.args.valid_until=32;self.args.payment_expiry=56
    def test_prepare_cancel_starts_no_child_or_journal(self):
        self.preparing()
        with patch.object(self.runner,'run') as run:
            view=console.operate(self.args,self.runner,self.output,io.StringIO('\n'))
        run.assert_not_called();self.assertEqual(view['state'],'preparation-cancelled')
        self.assertFalse(view['wallet_child_started']);self.assertFalse(view['payment_child_started'])
        self.assertFalse(self.args.journal.exists());self.assertIn('Amount: 4 atomic units',self.output.getvalue())
    def test_prepare_wrong_input_confirmation_cancels(self):
        self.preparing()
        with patch.object(self.runner,'run') as run:
            view=console.operate(self.args,self.runner,self.output,io.StringIO('PREPARE '+WIRE+'\n'))
        run.assert_not_called();self.assertEqual(view['state'],'preparation-cancelled')
    def test_prepare_confirmed_calls_only_wallet_and_omits_private_fields(self):
        self.preparing()
        reply={'status':'original-wire-retained','wallet_id':ID,'txid':WIRE}
        with patch.object(self.runner,'run',return_value=reply) as run:
            view=console.operate(self.args,self.runner,self.output,io.StringIO('PREPARE '+TX+'\n'))
        self.assertEqual(run.call_count,1);kind,command,extra=run.call_args.args
        self.assertEqual((kind,command),('wallet','prepare'));self.assertEqual(extra[1],TX)
        self.assertFalse(view['can_submit']);self.assertFalse(view['payment_child_started'])
        self.assertTrue(view['prepared_not_sent']);self.assertEqual(view['txid'],WIRE)
        for key in ('destination','payment','payment_expiry','request'):self.assertNotIn(key,view)
    def test_prepare_numeric_and_pin_rejection_precedes_child(self):
        self.preparing()
        for key,bad in (('payment',True),('valid_until',0),('payment_expiry',2**64),('commitment','abc')):
            original=getattr(self.args,key);setattr(self.args,key,bad)
            with patch.object(self.runner,'run') as run,self.assertRaises(ValueError):
                console.operate(self.args,self.runner,self.output,io.StringIO('PREPARE '+TX+'\n'))
            run.assert_not_called();setattr(self.args,key,original)
    def test_observe_uses_signed_child_height_without_endpoint(self):
        self.args.command='observe';self.args.packet=self.root/'packet'
        reply={'status':'signed-state-observed','wallet_id':ID,'certificate':
            {'state_height':4,'header_height':5,'genesis_sha256':SHA,'app_hash':WIRE}}
        with patch.object(self.runner,'run',return_value=reply) as run,patch.object(p,'endpoint_port') as endpoint:
            view=console.operate(self.args,self.runner,self.output,io.StringIO())
        run.assert_called_once_with('wallet','observe',['--packet',self.args.packet]);endpoint.assert_not_called()
        self.assertEqual(view['as_of_height'],4);self.assertEqual(view['app_hash'],WIRE);self.assertFalse(view['can_submit'])
        reply['certificate']['genesis_sha256']=TX
        with patch.object(self.runner,'run',return_value=reply),self.assertRaises(ValueError):
            console.operate(self.args,self.runner,self.output,io.StringIO())
    def test_import_keeps_opening_in_file_and_source_forms_separate(self):
        self.args.command='import-note';self.args.opening=self.root/'opening';self.args.wire=self.root/'wire'
        self.args.output_index=11;self.args.genesis_note=False
        for genesis in (False,True):
            self.args.genesis_note=genesis
            with patch.object(self.runner,'run',return_value={'status':'note-imported','wallet_id':ID,'commitment':TX}) as run:
                view=console.operate(self.args,self.runner,self.output,io.StringIO())
            kind,command,extra=run.call_args.args;self.assertEqual((kind,command),('wallet','import-note'))
            self.assertEqual(extra[:4],['--opening',self.args.opening,'--output-index',11])
            self.assertEqual(extra[4:],['--genesis-note'] if genesis else ['--wire',self.args.wire])
            self.assertEqual(view['commitment'],TX);self.assertTrue(view['opening_values_omitted'])
    def test_delivery_verifies_private_output_hash_and_omits_opening(self):
        self.args.command='deliver';self.args.output=self.root/'opening';self.args.output_index=10
        opening={'origin':'01'*32,'note_secret':'02'*32,'blind':'03'*32,'value':4,'expiry':56}
        raw=c.canonical(opening);c.private_output(self.args.output,raw)
        reply={'status':'private-opening-delivered','wallet_id':ID,'txid':TX,'private_file_created':True,'bytes':len(raw),'sha256':c.sha(raw)}
        with patch.object(self.runner,'run',return_value=reply):
            view=console.operate(self.args,self.runner,self.output,io.StringIO())
        self.assertEqual(view['output_sha256'],c.sha(raw));self.assertEqual(view['output_bytes'],len(raw))
        self.assertNotIn(opening['blind'],json.dumps(view)+console.render(view));self.assertNotIn('value',view)
        reply['sha256']=WIRE
        with patch.object(self.runner,'run',return_value=reply),self.assertRaises(ValueError):
            console.operate(self.args,self.runner,self.output,io.StringIO())
    def test_receipt_alias_private_output_refuses_before_any_child(self):
        self.args.command='deliver';self.args.output=self.root/'same';self.args.receipt=self.args.output
        with patch.object(console,'operate') as operate:
            _,code=console.execute(self.args,self.output,io.StringIO())
        self.assertEqual(code,1);operate.assert_not_called();self.assertFalse(self.args.output.exists())

    def test_keyed_blind_is_stable_domain_separated_and_context_bound(self):
        from protocol8_wallet import review_blind
        from protocol8_transfer import Invalid
        context={'wallet_id':ID,'genesis_sha256':SHA,'txid':TX,'wire_sha256':WIRE}
        key=b'K'*32
        derived=hmac.digest(key,b'1soft/protocol8-private-intent-review/key/v2\0','sha256')
        expected=hmac.digest(derived,c.canonical({'format':'1soft/protocol8-private-intent-review/blind/v2',**context}),'sha256').hex()
        blind=review_blind(key,**context);self.assertEqual(blind,expected)
        self.assertEqual(review_blind(key,**context),blind)
        self.assertNotEqual(review_blind(b'X'*32,**context),blind)
        for name in context:self.assertNotEqual(review_blind(key,**{**context,name:'98'*32}),blind)
        for bad in (b'K'*31,bytes(32),'K'*32):
            with self.assertRaises(Invalid):review_blind(bad,**context)
        with self.assertRaises(Invalid):review_blind(key,**{**context,'txid':'abc'})
    def test_private_blind_and_intent_omitted_from_public_review_and_display(self):
        v=projection();public=console.public_review(v,'56'*32);human=console.review_text(v)
        self.assertNotIn(v['private_review_blind'],human+c.canonical(public).decode())
        self.assertNotIn('private_review_blind',public)
        self.assertEqual(public['review_commitment_scheme'],c.REVIEW_SCHEME)
        for name in ('destination','payment','payment_expiry'):self.assertNotIn(name,public)
        missing={k:value for k,value in v.items() if k!='private_review_blind'}
        self.assertNotEqual(c.sha(c.canonical(v)),c.sha(c.canonical(missing)))
    def test_private_review_requires_v2_blind_and_both_genesis_pins(self):
        variants=[{**projection(),'format':'1soft/protocol8-private-intent-review/v1'},
            {k:v for k,v in projection().items() if k!='private_review_blind'},
            {**projection(),'private_review_blind':'ab'},
            {**projection(),'private_review_blind':'00'*32},
            {**projection(),'wallet_genesis_sha256':'98'*32}]
        def fake(v):
            def run(kind,command,extra):
                raw=c.canonical(v);c.private_output(Path(extra[-1]),raw)
                return {'status':'private-intent-reviewed','txid':TX,'wallet_id':ID,
                    'runtime_sha256':v['runtime_sha256'],'bytes':len(raw),'sha256':c.sha(raw),
                    'private_file_created':True,'review_commitment_scheme':c.REVIEW_SCHEME}
            return run
        with patch.object(self.runner,'run',side_effect=fake(projection())):
            value,digest=console.review(self.args,self.runner)
        self.assertEqual(value,projection());self.assertEqual(digest,c.sha(c.canonical(value)))
        for v in variants:
            with self.subTest(v=v),patch.object(self.runner,'run',side_effect=fake(v)),self.assertRaises(ValueError):
                console.review(self.args,self.runner)
    def test_changed_private_blind_refuses_before_dispatch_even_if_digest_repeated(self):
        later={**projection(),'private_review_blind':'98'*32}
        with patch.object(console,'review',side_effect=[(projection(),'56'*32),(later,'56'*32)]),patch.object(self.runner,'run') as run:
            with self.assertRaises(ValueError):console.operate(self.args,self.runner,self.output,io.StringIO('SUBMIT '+TX+' '+WIRE+'\n'))
        run.assert_not_called()

    def test_frozen_review_paths_include_both_fresh_journal_refusals(self):
        from run_protocol8_console import projection_paths_checked,EXPECTED_CHILD_COMMANDS
        calls=[{'keyed_private_projection_checked':i in (6,7,8,9,12)} for i in range(1,20)]
        responses=[{'child_invocations':[{'command':x} for x in names],
            'child_responses':[{'status':'private-intent-reviewed' if x=='review' else 'fake-other'} for x in names]}
            for names in EXPECTED_CHILD_COMMANDS]
        self.assertTrue(projection_paths_checked(calls,responses))
        for ordinal in (6,12):
            calls[ordinal-1]['keyed_private_projection_checked']=False
            self.assertFalse(projection_paths_checked(calls,responses))
            calls[ordinal-1]['keyed_private_projection_checked']=True
    def test_frozen_child_map_rejects_omitted_refusal_review_and_reordered_submit(self):
        from run_protocol8_console import projection_paths_checked,EXPECTED_CHILD_COMMANDS
        from copy import deepcopy
        calls=[{'keyed_private_projection_checked':i in (6,7,8,9,12)} for i in range(1,20)]
        responses=[{'child_invocations':[{'command':x} for x in names],
            'child_responses':[{'status':'private-intent-reviewed' if x=='review' else 'fake-other'} for x in names]}
            for names in EXPECTED_CHILD_COMMANDS]
        for ordinal in (6,12):
            wrong=deepcopy(responses);wrong[ordinal-1]={'child_invocations':[],'child_responses':[]}
            self.assertFalse(projection_paths_checked(calls,wrong))
        wrong=deepcopy(responses);wrong[8]['child_invocations'].reverse()
        self.assertFalse(projection_paths_checked(calls,wrong))

class ChildTests(unittest.TestCase):
    def test_actual_disposable_child_has_canonical_identity_and_is_reaped(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);(root/'scripts').mkdir()
            script=root/'scripts/protocol8_wallet.py'
            script.write_text("import os,json\nfrom pathlib import Path\nv="+repr({'format':c.FORMAT,'command':'inventory','genesis_sha256':SHA,
                'runtime_sha256':c.sha(c.canonical(c.runtime_files())),'status':'authenticated-inventory',
                'automatic_retry':False,'freshness_established':False,'production_ready':False,
                'native_audits':{'worker':{'calls':[{'elapsed_seconds':0.125}]}}})+
                "\nv.update(pid=os.getpid(),start_ticks=int(Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]))\nprint(json.dumps(v,sort_keys=True,separators=(',',':')))\n")
            args=SimpleNamespace(workspace=root/'config',credentials=root/'credentials',genesis_sha256=SHA)
            runner=console.Runner(args)
            with patch.object(console,'ROOT',root):reply=runner.run('wallet','inventory')
            self.assertEqual(reply['pid'],runner.calls[0]['pid']);self.assertTrue(runner.calls[0]['process_reaped'])
            self.assertEqual(reply['native_audits']['worker']['calls'][0]['elapsed_seconds'],0.125)
            self.assertFalse(runner.forced);self.assertFalse(runner.calls[0]['diagnostic_present'])
    def test_operational_receipts_reject_noncanonical_duplicate_and_nonfinite_json(self):
        for raw in (b'{"x":1,"x":2}\n',b'{"x":NaN}\n',b'{"x":Infinity}\n',
                    b'{"x":1e400}\n',b'{"x":0.125}',b'{"x":0.125}\n\n'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):console.operational_reply(raw)
        self.assertEqual(console.operational_reply(b'{"x":0.125}\n'),{'x':0.125})

    def test_actual_child_diagnostics_are_suppressed_and_reaped(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);(root/'scripts').mkdir();(root/'scripts/protocol8_wallet.py').write_text("import sys\nsys.stderr.write('PRIVATE-SENTINEL')\n")
            runner=console.Runner(SimpleNamespace(workspace=root/'config',credentials=root/'credentials',genesis_sha256=SHA))
            with patch.object(console,'ROOT',root),self.assertRaises(ValueError) as error:runner.run('wallet','inventory')
            self.assertNotIn('PRIVATE-SENTINEL',str(error.exception));self.assertTrue(runner.calls[0]['process_reaped'])

if __name__=='__main__':unittest.main()
