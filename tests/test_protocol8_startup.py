"""Closed-response unit checks; native qualification is a separate real gate."""
import json,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
import protocol8_transfer as n
from protocol8_worker import Worker

KAT=ROOT/'evidence/protocol8-wallet-guide/20261007/guide-01.journey.console.payment.wallet.json.artifacts/fixture-first.tx'

class Startup(unittest.TestCase):
    def fake(self,reply,mode='batch'):
        raw=KAT.read_bytes()
        class Stub(Worker):
            def call(self,op,body):
                self.calls.append({'operation':op})
                if op=='startup':return reply
                if op=='identities':return json.dumps({k:n.PROFILE[k] for k in ('parameter_sha256','verifying_key_sha256')}).encode()
                return b'OK\n' if body.endswith(raw) else b'INVALID\n'
            def guard(self):pass
        # Only the external process is stubbed; local parsing/cache/startup
        # response/identity decisions use the real Worker implementation.
        with tempfile.NamedTemporaryFile() as b:
            return Stub(b.name,'ab'*32,raw,startup_mode=mode)
    def response(self,**changes):
        v={'valid':True,'corrupt':False,**{k:n.PROFILE[k] for k in ('parameter_sha256','verifying_key_sha256')}}
        v.update(changes);return json.dumps(v).encode()
    def test_batched_positive_caches_only_valid_kat(self):
        w=self.fake(self.response());self.assertEqual([r['operation'] for r in w.calls],['startup'])
        self.assertEqual(list(w.cache),[KAT.read_bytes()]);self.assertTrue(w.startup['valid_proof_verified'])
        self.assertTrue(w.startup['corrupt_proof_refused']);self.assertTrue(w.startup['verifier_only'])
    def test_legacy_comparison_keeps_all_three_calls(self):
        w=self.fake(b'',mode='legacy');self.assertEqual([r['operation'] for r in w.calls],['verify','verify','identities'])
    def test_valid_refusal_has_no_fallback(self):
        with self.assertRaises(n.Unavailable):self.fake(self.response(valid=False))
    def test_corrupt_acceptance_refused(self):
        with self.assertRaises(n.Unavailable):self.fake(self.response(corrupt=True))
    def test_integer_flags_refused(self):
        for kw in ({'valid':1},{'corrupt':0}):
            with self.subTest(kw=kw),self.assertRaises(n.Unavailable):self.fake(self.response(**kw))
    def test_substituted_profile_refused(self):
        for key in ('parameter_sha256','verifying_key_sha256'):
            with self.subTest(key=key),self.assertRaises(n.Unavailable):self.fake(self.response(**{key:'00'*32}))
    def test_private_or_extra_field_refused(self):
        with self.assertRaises(n.Unavailable):self.fake(self.response(private='not retained'))
    def test_missing_and_malformed_response_refused(self):
        for raw in (b'{}',b'null',b'[]',b'not json'):
            with self.subTest(raw=raw),self.assertRaises(n.Unavailable):self.fake(raw)
    def test_unknown_mode_refused(self):
        with self.assertRaises(n.Invalid):self.fake(self.response(),mode='auto')
    def test_duplicate_response_field_refused(self):
        reply=self.response().replace(b'"valid": true',b'"valid": false, "valid": true')
        with self.assertRaises(n.Unavailable):self.fake(reply)
if __name__=='__main__':unittest.main()
