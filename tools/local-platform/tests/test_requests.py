"""Payment request integrity and nonfinancial durable correlation."""
import hashlib, json, sqlite3, tempfile, unittest
from pathlib import Path
try:
    import payment_requests as module
except ModuleNotFoundError:
    module = None

NOW=1_800_000_000_000_000_000
GENESIS='a'*64
RECIPIENT='lab_'+'b'*64

class Requests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(module, 'payment request implementation is missing')
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        self.root.chmod(0o700); self.now=NOW
    def tearDown(self):
        if hasattr(self,'temp'): self.temp.cleanup()
    def request(self, **changes):
        return module.new_request(GENESIS,RECIPIENT,'58',created_ns=NOW,
                                  expires_ns=NOW+60_000_000_000,note='Rendering',**changes)
    def book(self,create=False):
        return module.RequestBook(self.root/'requests.sqlite',GENESIS,create=create,clock=lambda:self.now)
    def review(self,units=58):
        return {'schema':1,'format':'1soft/p4-transfer-review/v1',
                'wallet_id':'c'*64,'policy_id':'d'*64,'body':{'op':{'type':'transfer','to':RECIPIENT,'units':units}},
                'debit_units':str(units+2)}
    def test_exact_canonical_roundtrip_and_detached_copy(self):
        value=self.request(); raw=module.encode_request(value)
        self.assertEqual(module.parse_request(raw,GENESIS,now_ns=NOW),value)
        parsed=module.parse_request(value,GENESIS,now_ns=NOW); parsed['note']='Changed'
        self.assertEqual(value['note'],'Rendering')
    def test_request_identity_is_exact_bytes(self):
        value=self.request()
        self.assertEqual(module.request_id(value),hashlib.sha256(module.encode_request(value)).hexdigest())
        self.assertNotEqual(module.request_id({**value,'note':'Other'}),module.request_id(value))
    def test_positive_canonical_atomic_units_only(self):
        for units in ['0','01','1.0','-1','1e3',True,58,str(2**63)]:
            with self.subTest(units=units),self.assertRaises(ValueError):
                module.new_request(GENESIS,RECIPIENT,units,created_ns=NOW,expires_ns=NOW+1_000_000_000)
    def test_unknown_authority_and_payment_status_fields_refused(self):
        for field in ['paid','private_key','payer','grant_id','policy','clock']:
            with self.subTest(field=field),self.assertRaises(ValueError):
                module.parse_request({**self.request(),field:'invented'},GENESIS,now_ns=NOW)
    def test_wrong_genesis_duplicate_noncanonical_and_oversized_refused(self):
        raw=module.encode_request(self.request())
        for value,genesis in [(raw,'f'*64),(raw+b' ',GENESIS),(b'{"schema":1,"schema":1}',GENESIS),(b' '*4097,GENESIS)]:
            with self.subTest(),self.assertRaises(ValueError): module.parse_request(value,genesis,now_ns=NOW)
    def test_expiry_boundary_and_future_creation(self):
        value=self.request()
        for now in [NOW-1,NOW+60_000_000_000]:
            with self.subTest(now=now),self.assertRaises(ValueError): module.parse_request(value,GENESIS,now_ns=now)
        self.assertEqual(module.parse_request(value,GENESIS,now_ns=NOW+59_999_999_999)['units'],'58')
    def test_invalid_time_and_note_bounds(self):
        for created,expires,note in [(True,NOW+1,''),(NOW,NOW,''),(NOW,NOW+86_400_000_000_001,''),(NOW,NOW+1,'x'*401),(NOW,NOW+1,'bad\x00')]:
            with self.subTest(),self.assertRaises(ValueError):
                module.new_request(GENESIS,RECIPIENT,'58',created_ns=created,expires_ns=expires,note=note)
    def test_explicit_initialization_and_nonprivate_paths_refused(self):
        with self.assertRaises(ValueError): self.book()
        with self.book(create=True): pass
        with self.assertRaises((ValueError,FileExistsError)): self.book(create=True)
        self.root.chmod(0o755)
        with self.assertRaises(ValueError): self.book()
    def test_reopen_duplicate_import_and_no_financial_status(self):
        value=self.request()
        with self.book(create=True) as book:
            first=book.add(value); second=book.add(value)
            self.assertEqual(first['request_id'],second['request_id']);self.assertEqual(second['status'],'already_retained')
        with self.book() as book:
            rows=book.entries(); self.assertEqual(len(rows),1); self.assertEqual(rows[0]['request'],value)
            self.assertIsNone(rows[0]['decision_id']);self.assertFalse(rows[0]['execution_proven'])
    def test_review_binding_is_durable_and_replay_is_noop(self):
        review=self.review()
        with self.book(create=True) as book:
            rid=book.add(self.request())['request_id'];did=book.bind_review(rid,review)['decision_id']
            self.assertEqual(book.bind_review(rid,review)['decision_id'],did)
        with self.book() as book:
            selected=book.selected(rid);self.assertEqual(selected['decision_id'],did);self.assertEqual(selected['review'],review)
    def test_binding_cannot_change_recipient_or_amount(self):
        with self.book(create=True) as book:
            rid=book.add(self.request())['request_id']
            for review in [self.review(59),{**self.review(),'body':{'op':{'type':'transfer','to':'lab_'+'e'*64,'units':58}}}]:
                with self.assertRaises(ValueError): book.bind_review(rid,review)
            self.assertIsNone(book.selected(rid)['decision_id'])
    def test_second_request_cannot_claim_same_decision(self):
        with self.book(create=True) as book:
            value=self.request(); first=book.add(value)['request_id'];second=book.add({**value,'note':'Second invoice'})['request_id']
            book.bind_review(first,self.review())
            with self.assertRaises(ValueError): book.bind_review(second,self.review())
            self.assertIsNone(book.selected(second)['decision_id'])
    def test_existing_request_cannot_replace_review(self):
        with self.book(create=True) as book:
            rid=book.add(self.request())['request_id'];book.bind_review(rid,self.review())
            with self.assertRaises(ValueError): book.bind_review(rid,{**self.review(),'wallet_id':'f'*64})
    def test_clock_regression_and_expiry_refuse_new_actions(self):
        with self.book(create=True) as book:
            rid=book.add(self.request())['request_id'];self.now-=1
            with self.assertRaises(ValueError): book.bind_review(rid,self.review())
            self.now=NOW+60_000_000_000
            with self.assertRaises(ValueError): book.bind_review(rid,self.review())
            self.assertEqual(book.selected(rid)['request']['units'],'58')
    def test_tampered_request_and_review_rows_refuse(self):
        with self.book(create=True) as book:
            rid=book.add(self.request())['request_id'];book.bind_review(rid,self.review())
        db=sqlite3.connect(self.root/'requests.sqlite');db.execute('UPDATE requests SET payload=?',(b'{}',));db.commit();db.close()
        with self.assertRaises(ValueError):
            with self.book() as book: book.entries()
    def test_capacity_refuses_without_eviction(self):
        with self.book(create=True) as book:
            for i in range(64): book.add({**self.request(),'note':str(i)})
            with self.assertRaises(ValueError): book.add({**self.request(),'note':'65'})
            self.assertEqual(len(book.entries()),64)
    def test_wrong_genesis_and_aliased_database_refuse(self):
        with self.book(create=True):pass
        with self.assertRaises(ValueError): module.RequestBook(self.root/'requests.sqlite','e'*64,clock=lambda:NOW)
        (self.root/'alias.sqlite').symlink_to(self.root/'requests.sqlite')
        with self.assertRaises(ValueError): module.RequestBook(self.root/'alias.sqlite',GENESIS,clock=lambda:NOW)

if __name__=='__main__':unittest.main()
