"""Actual pinned verifier/controller; synthetic merchant storage fault boundaries."""
import copy,json,os,sqlite3,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from protocol7_treasury import canonical,digest,numfield,ZERO,Unavailable
from protocol7_worker import Worker
from protocol7_notes import NoteController
from protocol7_merchant import MerchantBook,MerchantError,quote_request,MAX_QUOTES

INPUTS=('P7_MERCHANT_ORIGIN','P7_MERCHANT_WORKER','P7_MERCHANT_CONTROLLER')
@unittest.skipUnless(all(os.environ.get(k) for k in INPUTS),'unassessed: pinned actual P7 origin/verifier/controller not supplied')
class MerchantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p=Path(os.environ['P7_MERCHANT_ORIGIN']);r=json.loads(p.read_bytes());cls.g=r['genesis'];cls.rawg=canonical(cls.g)
        cls.worker=Worker(os.environ['P7_MERCHANT_WORKER'],cls.g['worker_sha256'],Path(str(p)+'.artifacts/fixture-a.tx').read_bytes())
        controller=Path(os.environ['P7_MERCHANT_CONTROLLER'])
        cls.controller=NoteController(controller,digest(controller.read_bytes()),expected_genesis=cls.rawg,worker=cls.worker)
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='1soft-p7-merchant-test-');self.directory=Path(self.tmp.name)
        self.path=self.directory/'merchant.sqlite';self.key=os.urandom(32);self.bookid=os.urandom(32).hex()
        self.kw={'expected_genesis':self.rawg,'controller':self.controller,'key':self.key,'book_id':self.bookid,
                 'merchant_namespace':'local.test','recipient':numfield(170)}
        self.book=MerchantBook(self.path,**self.kw,create=True)
        self.terms={'resource':b'exact bytes\n','amount':2,'payment_expiry':60,'grant_id':self.g['treasury']['grants'][0]['id'],
                    'generation':1,'valid_from':1,'valid_until':30}
    def tearDown(self):self.book.close();self.tmp.cleanup()
    def quote(self,**changes):return self.book.create_quote(**{**self.terms,**changes})
    def rows(self):return canonical(list(self.book.db.iterdump()))
    def test_explicit_creation_wrong_key_even_empty_and_identity_pins(self):
        missing=self.directory/'missing.sqlite'
        with self.assertRaises(FileNotFoundError):MerchantBook(missing,**self.kw)
        self.assertFalse(missing.exists())
        for key,changed in [('key',os.urandom(32)),('book_id',os.urandom(32).hex()),('merchant_namespace','other'),('recipient',numfield(171))]:
            with self.subTest(key=key):
                with self.assertRaises(MerchantError):MerchantBook(self.path,**{**self.kw,key:changed})
        with self.assertRaises(MerchantError):MerchantBook(self.path,**self.kw,create=True)
    def test_quote_bytes_precommit_nonce_uniqueness_and_read_only_unpaid(self):
        q=self.quote();r=q['request'];self.assertEqual(r,quote_request(q['core']))
        self.assertEqual(int.from_bytes(bytes.fromhex(r),'little')>>248,0)
        rows=self.rows();state=self.book.inspect(r)
        self.assertEqual(state['status'],'quoted');self.assertFalse(state['retry_authorized'])
        self.assertEqual(self.rows(),rows)
        with self.assertRaisesRegex(MerchantError,'certified enrolled'):self.book.fulfill(r)
        nonce=bytes.fromhex(q['core']['nonce'])
        with patch('protocol7_merchant.os.urandom',return_value=nonce):
            with self.assertRaisesRegex(MerchantError,'nonce conflict'):self.quote(resource=b'another resource')
        self.assertEqual(self.rows(),rows)
        core=copy.deepcopy(q['core']);core['resource']=b'another resource'.hex();core['resource_sha256']=digest(b'another resource')
        self.assertNotEqual(quote_request(core),r)
    def test_closed_types_zero_overflow_interval_and_lane_refused_without_rows(self):
        before=self.rows()
        for changes in ({'amount':True},{'amount':0},{'amount':2**64},{'generation':False},{'generation':0},
                        {'payment_expiry':False},{'payment_expiry':29},{'payment_expiry':2**64},
                        {'valid_until':65},{'valid_from':30},{'resource':b''},{'resource':'not bytes'},
                        {'grant_id':ZERO},{'grant_id':'ff'*32}):
            with self.subTest(changes=list(changes)):
                with self.assertRaises(ValueError):self.quote(**changes)
                self.assertEqual(self.rows(),before)
        q=self.quote();core=q['core'];before=self.rows()
        for field in ('resource','nonce','extra'):
            bad=copy.deepcopy(core);bad[field]=ZERO
            with self.assertRaises(ValueError):self.book._quote(bad)
            self.assertEqual(self.rows(),before)
    def test_capacity_and_transactional_return_loss(self):
        for n in range(MAX_QUOTES):self.quote(resource=str(n).encode())
        before=self.rows()
        with self.assertRaisesRegex(MerchantError,'capacity'):self.quote()
        self.assertEqual(self.rows(),before)
        # A separate empty book demonstrates a real committed local quote whose
        # calling code then deliberately discards the returned value.
        p=self.directory/'lost.sqlite'
        with MerchantBook(p,**self.kw,create=True) as b:
            result=b.create_quote(**self.terms);request=result['request']
        with MerchantBook(p,**self.kw) as b:self.assertEqual(b.inspect(request)['status'],'quoted')
    def test_unsafe_mode_hardlink_and_parent_symlink_refused(self):
        alias=self.directory/'alias';os.link(self.path,alias)
        with self.assertRaises(MerchantError):MerchantBook(self.path,**self.kw)
        alias.unlink();self.path.chmod(0o644)
        with self.assertRaises(MerchantError):MerchantBook(self.path,**self.kw)
        self.path.chmod(0o600)
        link=self.directory/'dir';link.symlink_to(self.directory,target_is_directory=True)
        with self.assertRaises(MerchantError):MerchantBook(link/'merchant.sqlite',**self.kw)
    def test_database_replacement_and_schema_corruption_refused(self):
        self.quote();before=self.rows();self.book.db.execute('CREATE TABLE illicit (x INTEGER)')
        with self.assertRaisesRegex(MerchantError,'schema'):self.book.inspect(next(iter(self.book.db.execute('SELECT request FROM quotes')))[0])
        self.book.db.execute('DROP TABLE illicit');self.assertEqual(self.rows(),before)
        self.book.close();copy=self.directory/'replacement.sqlite';copy.write_bytes(self.path.read_bytes());copy.chmod(0o600)
        os.replace(copy,self.path)
        with self.assertRaisesRegex(MerchantError,'replaced'):self.book._private()

if __name__=='__main__':unittest.main()
