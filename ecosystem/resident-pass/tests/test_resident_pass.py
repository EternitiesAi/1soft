import copy,json,os,sqlite3,subprocess,sys,tempfile,threading,unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from resident_pass.protocol import *
from resident_pass.verifier import Verifier
from fixtures import *

class PassTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'verifier.sqlite';self.now=NOW
        self.v=Verifier(self.path,[RULE],AUDIENCE,NOW+7200,clock=lambda:self.now)
        self.c=card();self.v.install_status(status([self.c]))
    def tearDown(self):self.v.close();self.tmp.cleanup()
    def introduce(self,c=None,key=HOLDER):
        c=c or self.c;ch=self.v.begin(c);return self.v.accept(c,present(key,ch))
    def test_identity_is_not_financial_or_legal_authority(self):
        r=self.introduce();self.assertEqual(r['kind'],'resident')
        for flag in ('financial_authority_created','legal_identity_verified','consciousness_assessed','biographical_continuity_verified'):
            self.assertIs(r[flag],False)
    def test_copy_of_card_is_not_holder_proof(self):
        ch=self.v.begin(self.c)
        with self.assertRaises(Refused):self.v.accept(self.c,present(OTHER,ch))
        self.assertEqual(self.v.accept(self.c,present(HOLDER,ch))['status'],'verified-presentation')
    def test_one_use_challenge(self):
        ch=self.v.begin(self.c);p=present(HOLDER,ch);self.v.accept(self.c,p)
        with self.assertRaises(Refused):self.v.accept(self.c,p)
    def test_altered_challenge_refused(self):
        ch=self.v.begin(self.c);ch['audience']='other.test'
        with self.assertRaises(Refused):self.v.accept(self.c,present(HOLDER,ch))
    def test_forged_card_refused(self):
        c=copy.deepcopy(self.c);c['body']['display_name']='Different'
        with self.assertRaises(Refused):self.v.begin(c)
    def test_wrong_issuer_public_key(self):
        c=card(issuer_key=FOREIGN)
        with self.assertRaises(Refused):self.v.begin(c)
    def test_untrusted_issuer_not_auto_accepted(self):
        c=card(issuer='other',issuer_key=FOREIGN)
        with self.assertRaises(Refused):self.v.begin(c)
    def test_external_issuer_cannot_claim_resident(self):
        rule=IssuerRule('foreign-lab',public(FOREIGN),('external-agent',))
        with Verifier(':memory:',[rule],AUDIENCE,NOW+600,clock=lambda:NOW) as v:
            c=card(kind='resident',issuer='foreign-lab',issuer_key=FOREIGN)
            v.install_status(status([c],issuer='foreign-lab',issuer_key=FOREIGN))
            with self.assertRaises(Refused):v.begin(c)
    def test_external_agent_allowed_under_separate_trust(self):
        rule=IssuerRule('foreign-lab',public(FOREIGN),('external-agent',))
        with Verifier(':memory:',[rule],AUDIENCE,NOW+600,clock=lambda:NOW) as v:
            c=card(kind='external-agent',issuer='foreign-lab',issuer_key=FOREIGN)
            v.install_status(status([c],issuer='foreign-lab',issuer_key=FOREIGN));ch=v.begin(c)
            self.assertEqual(v.accept(c,present(HOLDER,ch))['kind'],'external-agent')
    def test_human_member_is_not_kyc(self):
        rule=IssuerRule('membership-lab',public(FOREIGN),('human-member',))
        with Verifier(':memory:',[rule],AUDIENCE,NOW+600,clock=lambda:NOW) as v:
            c=card(kind='human-member',issuer='membership-lab',issuer_key=FOREIGN)
            v.install_status(status([c],issuer='membership-lab',issuer_key=FOREIGN));ch=v.begin(c)
            self.assertFalse(v.accept(c,present(HOLDER,ch))['legal_identity_verified'])
    def test_wrong_card_audience(self):
        c=card(audience='other.test')
        with self.assertRaises(Refused):self.v.begin(c)
    def test_status_signature_required(self):
        d=status();d['signature']='0'*128
        with self.assertRaises(Refused):self.v.install_status(d)
    def test_status_rollback_refused(self):
        self.v.install_status(status(sequence=2))
        with self.assertRaises(Refused):self.v.install_status(status(sequence=1))
    def test_same_sequence_different_claim_refused(self):
        with self.assertRaises(Refused):self.v.install_status(status(revoked=('card-001',)))
    def test_same_status_idempotent(self):self.v.install_status(status());self.introduce()
    def test_revocation_stops_pending_presentation(self):
        ch=self.v.begin(self.c);p=present(HOLDER,ch)
        self.v.install_status(status(sequence=2,revoked=('card-001',)))
        with self.assertRaises(Refused):self.v.accept(self.c,p)
    def test_revocation_does_not_erase_identity_receipt(self):
        ch=self.v.begin(self.c);self.v.accept(self.c,present(HOLDER,ch))
        self.v.install_status(status(sequence=2,revoked=('card-001',)))
        r=self.v.receipt(ch['nonce']);self.assertFalse(r['new_authentication'])
        self.assertEqual(r['historical_local_result']['subject_id'],self.c['body']['subject_id'])
    def test_reactivate_revoked_epoch_forbidden(self):
        self.v.install_status(status(sequence=2,revoked=('card-001',)))
        with self.assertRaises(Refused):self.v.install_status(status(sequence=3))
    def test_new_key_needs_new_epoch(self):
        c=card(holder=OTHER,credential='card-002',epoch=0)
        with self.assertRaises(Refused):self.v.install_status(status([c],sequence=2))
    def test_rotation_same_alias_old_key_loses_access(self):
        ch=self.v.begin(self.c);old=present(HOLDER,ch)
        c=card(holder=OTHER,credential='card-002',epoch=1)
        self.v.install_status(status([self.c,c],sequence=2,revoked=('card-001',)))
        with self.assertRaises(Refused):self.v.accept(self.c,old)
        r=self.introduce(c,OTHER);self.assertEqual(r['subject_id'],self.c['body']['subject_id'])
    def test_two_active_cards_same_alias_rejected(self):
        with self.assertRaises(Refused):status([self.c,card(holder=OTHER,credential='c2',epoch=1)])
    def test_stale_status_does_not_authenticate(self):
        self.now+=121
        with self.assertRaises(Refused):self.v.begin(self.c)
    def test_new_status_restores_ability_within_same_card_epoch(self):
        self.now+=121;self.v.install_status(status(sequence=2,now=self.now));self.introduce()
    def test_not_listed_means_unknown_not_authenticated(self):
        self.v.install_status(status([],sequence=2))
        with self.assertRaises(Refused):self.v.begin(self.c)
    def test_expired_challenge_even_with_fresh_status(self):
        ch=self.v.begin(self.c,ttl=10);self.now+=10
        with self.assertRaises(Refused):self.v.accept(self.c,present(HOLDER,ch))
    def test_clock_regression_refused(self):
        self.now-=1
        with self.assertRaises(Refused):self.v.begin(self.c)
    def test_policy_expired_refused(self):
        self.now+=7200
        with self.assertRaises(Refused):self.v.begin(self.c)
    def test_future_card_refused(self):
        c=card(now=NOW+100);self.v.install_status(status([c]))
        with self.assertRaises(Refused):self.v.begin(c)
    def test_status_from_future_refused(self):
        with self.assertRaises(Refused):self.v.install_status(status(sequence=2,now=NOW+2))
    def test_status_time_must_not_regress(self):
        with self.assertRaises(Refused):self.v.install_status(status(sequence=2,now=NOW-1))
    def test_no_malformed_numeric_fields(self):
        for name in ('schema','epoch','issued_at','expires_at'):
            c=copy.deepcopy(self.c);c['body'][name]=True
            with self.subTest(name=name),self.assertRaises(Refused):self.v.begin(c)
    def test_extra_sensitive_fields_refused(self):
        c=copy.deepcopy(self.c);c['body']['private_memories']=['not public']
        with self.assertRaises(Refused):issue_card(ISSUER,c['body'])
    def test_control_chars_name_refused(self):
        c=copy.deepcopy(self.c);c['body']['display_name']='Aster\u202ecom'
        with self.assertRaises(Refused):issue_card(ISSUER,c['body'])
    def test_challenge_purpose_cannot_be_reinterpreted(self):
        ch=self.v.begin(self.c,purpose='link-native-account',context_digest=digest({'account':'other'}))
        with self.assertRaises(Refused):self.v.accept(self.c,present(HOLDER,ch))
    def test_ordinary_introduction_has_no_hidden_context(self):
        with self.assertRaises(Refused):self.v.begin(self.c,context_digest=digest({'buy':100}))
    def test_unknown_purpose_refused(self):
        with self.assertRaises(Refused):self.v.begin(self.c,purpose='send-money')
    def test_private_alias_not_derived_from_holder_key(self):
        self.assertEqual(self.c['body']['subject_id'],card(holder=OTHER)['body']['subject_id'])
        self.assertNotIn(public(HOLDER),self.c['body']['subject_id'])
    def test_aliases_differ_by_issuer_and_service(self):
        a=pairwise_subject(bytes(32),'issuer-a','service-a')
        self.assertNotEqual(a,pairwise_subject(bytes(32),'issuer-a','service-b'))
        self.assertNotEqual(a,pairwise_subject(bytes(32),'issuer-b','service-a'))
    def test_duplicate_json_and_floats_refused(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":0.5}',b'{"x":NaN}',b'x'*262145):
            with self.assertRaises(Refused):decode(raw)
    def test_restart_keeps_challenge_consumed(self):
        ch=self.v.begin(self.c);p=present(HOLDER,ch);self.v.accept(self.c,p);self.v.close()
        self.v=Verifier(self.path,[RULE],AUDIENCE,NOW+7200,clock=lambda:self.now)
        with self.assertRaises(Refused):self.v.accept(self.c,p)
    def test_restart_preserves_revocation_epoch(self):
        self.v.install_status(status(sequence=2,revoked=('card-001',)));self.v.close()
        self.v=Verifier(self.path,[RULE],AUDIENCE,NOW+7200,clock=lambda:self.now)
        with self.assertRaises(Refused):self.v.install_status(status(sequence=3))
    def test_two_verifier_connections_consume_only_once(self):
        ch=self.v.begin(self.c);p=present(HOLDER,ch);barrier=threading.Barrier(2)
        def call(_):
            with Verifier(self.path,[RULE],AUDIENCE,NOW+7200,clock=lambda:NOW) as v:
                barrier.wait(timeout=5)
                try:v.accept(self.c,p);return 'accepted'
                except Refused:return 'refused'
        with ThreadPoolExecutor(max_workers=2) as pool:r=list(pool.map(call,range(2)))
        self.assertEqual(sorted(r),['accepted','refused'])
    def test_status_corruption_rechecked(self):
        self.v.db.execute("UPDATE issuer_status SET digest=?",('0'*64,))
        with self.assertRaises(Refused):self.v.begin(self.c)
    def test_changed_journal_policy_refused(self):
        with self.assertRaises(Refused):Verifier(self.path,[RULE],AUDIENCE,NOW+8000,clock=lambda:NOW)
    def test_unsafe_directory_refused(self):
        p=Path(self.tmp.name)/'unsafe';p.mkdir(mode=0o755)
        with self.assertRaises(Refused):Verifier(p/'db',[RULE],AUDIENCE,NOW+7200)
    def test_actual_crash_after_accept_preserves_receipt(self):
        ch=self.v.begin(self.c);p=present(HOLDER,ch)
        data=Path(self.tmp.name)/'data.json';data.write_bytes(canonical({'card':self.c,'presentation':p}))
        code='''import os,sys
from pathlib import Path
from fixtures import *
from resident_pass.verifier import Verifier
from resident_pass.protocol import decode
x=decode(Path(sys.argv[2]).read_bytes())
v=Verifier(sys.argv[1],[RULE],AUDIENCE,NOW+7200,clock=lambda:NOW)
v.accept(x['card'],x['presentation'])
os._exit(0)
'''
        env=dict(os.environ,PYTHONPATH=os.pathsep.join([str(Path(__file__).resolve().parents[1]),str(Path(__file__).parent)]))
        p2=subprocess.run([sys.executable,'-c',code,str(self.path),str(data)],env=env,capture_output=True,timeout=5)
        self.assertEqual(p2.returncode,0,p2.stderr);self.assertFalse(self.v.receipt(ch['nonce'])['new_authentication'])

if __name__=='__main__':unittest.main()
