"""The public commitment binds every term; strict context precedes signing."""
import copy
import hashlib
import unittest

def terms():
    return {'schema':1, 'format':'1soft/invoice-terms/v1', 'quote_sha256':'a'*64,
            'genesis_sha256':'b'*64, 'merchant_origin':'http://127.0.0.1:39080',
            'resource_url':'http://127.0.0.1:39080/premium/one', 'resource_sha256':'c'*64,
            'network':'1soft:local-dev', 'asset':'1soft:DEV', 'recipient':'lab_'+'d'*64,
            'amount_units':'7', 'created_ns':1000000000, 'expires_ns':2000000000}

class InvoiceTermsTests(unittest.TestCase):
    def functions(self):
        try:
            from invoice_terms import terms_checked, terms_commitment
            return terms_checked, terms_commitment
        except ImportError:
            self.fail('native public terms validator is missing')

    def test_all_public_terms_affect_commitment(self):
        checked, commit = self.functions(); original=terms(); first=commit(original)
        values={'quote_sha256':'e'*64,'genesis_sha256':'e'*64,
            'merchant_origin':'http://127.0.0.1:39081','resource_url':'http://127.0.0.1:39080/premium/two',
            'resource_sha256':'e'*64,'network':'1soft:other','recipient':'lab_'+'e'*64,
            'amount_units':'8','created_ns':1000000001,'expires_ns':2000000001}
        for name,value in values.items():
            candidate=dict(original, **{name:value})
            if name=='merchant_origin':candidate['resource_url']='http://127.0.0.1:39081/premium/one'
            with self.subTest(name=name):self.assertNotEqual(commit(candidate),first)

    def test_domain_and_exact_canonical_preimage(self):
        checked, commit=self.functions()
        # Independent construction, not the product encoder or hash helper.
        import json
        raw=json.dumps(terms(),sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')
        expected=hashlib.sha256(b'1soft/invoice-terms/v1'+bytes([0])+raw).hexdigest()
        self.assertEqual(commit(terms()),expected)
        self.assertNotEqual(commit(terms()),hashlib.sha256(raw).hexdigest())

    def test_context_mismatch_refuses(self):
        checked, commit=self.functions()
        for kwargs in ({'genesis_sha256':'e'*64},{'recipient':'lab_'+'e'*64},{'units':8}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):checked(terms(),**kwargs)

    def test_invoice_expiry_is_inclusive_refusal(self):
        checked, commit=self.functions()
        self.assertEqual(checked(terms(),now_ns=1999999999),terms())
        for now in (999999999,2000000000,2000000001):
            with self.subTest(now=now), self.assertRaises(ValueError):checked(terms(),now_ns=now)

    def test_private_and_unknown_fields_refuse(self):
        checked, commit=self.functions()
        for field in ('private_plaintext','ciphertext','password','wallet_id','extra'):
            with self.subTest(field=field),self.assertRaises(ValueError):commit(dict(terms(),**{field:'secret'}))

    def test_malformed_values_and_ambiguous_urls_refuse(self):
        checked, commit=self.functions()
        cases=[('schema',True),('asset','USD'),('amount_units','07'),('amount_units',7),
            ('recipient','other'),('resource_sha256','A'*64),('expires_ns',True),
            ('network','unregistered'),('merchant_origin','http://example.com'),
            ('resource_url','http://127.0.0.1:39080/a/../b'),
            ('resource_url','http://127.0.0.1:39080/a%0ab'),
            ('resource_url','http://127.0.0.1:39080/a#fragment')]
        for field,value in cases:
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):commit(dict(terms(),**{field:value}))

    def test_returned_terms_do_not_alias_caller(self):
        checked,commit=self.functions(); value=terms(); frozen=checked(value)
        value['amount_units']='20';self.assertEqual(frozen['amount_units'],'7')

if __name__=='__main__':unittest.main()
