"""Console behavior with labeled fake authority; disposable child-process checks."""
import io,json,os,sys,tempfile,unittest
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
    return {'format':'1soft/protocol8-private-intent-review/v1','wallet_id':ID,'txid':TX,
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
                'bytes':len(raw),'sha256':'00'*32,'private_file_created':True}
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

class ChildTests(unittest.TestCase):
    def test_actual_disposable_child_has_canonical_identity_and_is_reaped(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);(root/'scripts').mkdir()
            script=root/'scripts/protocol8_wallet.py'
            script.write_text("import os,json\nfrom pathlib import Path\nv="+repr({'format':c.FORMAT,'command':'inventory','genesis_sha256':SHA,
                'runtime_sha256':c.sha(c.canonical(c.runtime_files())),'status':'authenticated-inventory',
                'automatic_retry':False,'freshness_established':False,'production_ready':False})+
                "\nv.update(pid=os.getpid(),start_ticks=int(Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]))\nprint(json.dumps(v,sort_keys=True,separators=(',',':')))\n")
            args=SimpleNamespace(workspace=root/'config',credentials=root/'credentials',genesis_sha256=SHA)
            runner=console.Runner(args)
            with patch.object(console,'ROOT',root):reply=runner.run('wallet','inventory')
            self.assertEqual(reply['pid'],runner.calls[0]['pid']);self.assertTrue(runner.calls[0]['process_reaped'])
            self.assertFalse(runner.forced);self.assertFalse(runner.calls[0]['diagnostic_present'])
    def test_actual_child_diagnostics_are_suppressed_and_reaped(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);(root/'scripts').mkdir();(root/'scripts/protocol8_wallet.py').write_text("import sys\nsys.stderr.write('PRIVATE-SENTINEL')\n")
            runner=console.Runner(SimpleNamespace(workspace=root/'config',credentials=root/'credentials',genesis_sha256=SHA))
            with patch.object(console,'ROOT',root),self.assertRaises(ValueError) as error:runner.run('wallet','inventory')
            self.assertNotIn('PRIVATE-SENTINEL',str(error.exception));self.assertTrue(runner.calls[0]['process_reaped'])

if __name__=='__main__':unittest.main()
