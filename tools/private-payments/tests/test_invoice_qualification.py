"""Predicate fixtures are not actual execution evidence."""
from copy import deepcopy
import unittest
import test_merchant_qualification as fixture
from native_invoice_qualification import INVOICE_CHECKS,invoice_report_matches,compare_candidate

def actual():
    r=fixture.actual();r['native_signature_authenticates_resource']=True
    r['invoice_commitment_version']=1;r['workspace_schema']=3
    r['checks'] += [dict(name=n,passed=True) for n in INVOICE_CHECKS]
    r['wrong_invoice_proof_sha256']='d'*64
    for i,p in enumerate(r['payments']):p.update(invoice_commitment=str(i+1)*64,resource_sha256='b'*64,
        invoice_artifact='public-invoice-'+p['role']+'.json',invoice_artifact_sha256='c'*64)
    return r

class InvoiceQualificationTests(unittest.TestCase):
    def test_full_report_fixture_and_original_invariants_accepted(self):
        self.assertTrue(invoice_report_matches(actual(),fixture.SOURCE,fixture.RUN))
    def test_partial_duplicate_failed_or_unknown_checks_refused(self):
        for edit in (lambda r:r['checks'].pop(),lambda r:r['checks'].append(r['checks'][-1]),
            lambda r:r['checks'][-1].update(passed=False),lambda r:r['checks'][-1].update(name='wrong'),
            lambda r:r['checks'][0].update(passed=False)):
            r=actual();edit(r);self.assertFalse(invoice_report_matches(r,fixture.SOURCE,fixture.RUN))
    def test_native_claim_capability_source_or_cleanup_mismatch_refused(self):
        for k,v in [('native_signature_authenticates_resource',False),('invoice_commitment_version',True),
            ('workspace_schema',2),('source_qualified',False),('source_after',None),
            ('cleanup_errors',['unknown']),('owned_processes_after_cleanup',1),('run_id','0'*32)]:
            r=actual();r[k]=v;self.assertFalse(invoice_report_matches(r,fixture.SOURCE,fixture.RUN))
    def test_missing_payment_commitment_and_resource_digest_refused(self):
        for k in ('invoice_commitment','resource_sha256'):
            r=actual();del r['payments'][1][k];self.assertFalse(invoice_report_matches(r,fixture.SOURCE,fixture.RUN))
    def test_unlisted_changes_deletion_and_added_membership_refused(self):
        before={'a':dict(mode='100644',sha256='a'),'b':dict(mode='100644',sha256='b')}
        after={'a':dict(mode='100644',sha256='changed'),'b':before['b'],'c':dict(mode='100644',sha256='new')}
        compare_candidate(after,before,{'a'},{'c'})
        for edit in (lambda r:r.pop('b'),lambda r:r.update(b=dict(mode='100755',sha256='b')),
            lambda r:r.update(d=dict(mode='100644',sha256='extra')),lambda r:r.update(a=before['a'])):
            r=deepcopy(after);edit(r)
            with self.assertRaises(ValueError):compare_candidate(r,before,{'a'},{'c'})

    def test_duplicate_invoice_commitments_refused(self):
        r=actual()
        r['payments'][1]['invoice_commitment']=r['payments'][0]['invoice_commitment']
        self.assertFalse(invoice_report_matches(r,fixture.SOURCE,fixture.RUN))

    def test_source_preflight_failure_retains_exact_unassessed_receipt(self):
        import json,tempfile
        from pathlib import Path
        from unittest.mock import patch
        import native_invoice_qualification as q
        with tempfile.TemporaryDirectory() as root:
            output=Path(root)/'new'
            with patch.object(q,'source_checked',side_effect=ValueError('fixture pin mismatch')):
                result=q.qualify('/not-executed',output)
            self.assertEqual(result['status'],'failed-preflight')
            self.assertIsNone(result['source'])
            self.assertTrue(result['unassessed_gates'])
            self.assertEqual(json.loads((output/'result.json').read_bytes()),result)
            self.assertFalse((output/'source.json').exists())

if __name__=='__main__':unittest.main()
