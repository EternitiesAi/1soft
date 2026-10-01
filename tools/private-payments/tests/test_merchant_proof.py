"""Portable merchant proofs: real native execution, synthetic signed headers.

The actual engine gate remains separate. No merchant or payment-key mocks.
"""
import base64
import copy
from dataclasses import asdict, replace
import hashlib
import importlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

from block_application import encode
from local_devnet import private_new
from payment_x402 import TrustedMerchantAssignment, make_payment_signature, parse_payment_required
import test_committed_invoices as fixtures

ROOT = Path(__file__).resolve().parents[3]
CLI = ROOT / 'tools/private-payments/scripts/verify_merchant_proof.py'


class MerchantProofTests(unittest.TestCase):
    setUp = fixtures.CommittedInvoiceTests.setUp
    offer = fixtures.CommittedInvoiceTests.offer
    imported = fixtures.CommittedInvoiceTests.imported
    signed = fixtures.CommittedInvoiceTests.signed
    capsule = fixtures.CommittedInvoiceTests.capsule

    def api(self):
        self.assertTrue((ROOT/'tools/private-payments/src/merchant_proof.py').is_file(),
                        'portable merchant proof verifier is missing')
        return importlib.import_module('merchant_proof')

    def paid(self):
        self.api()
        qid = self.merchant.add_quote(self.header, self.expected, resource=self.resource)['quote_sha256']
        rid, review, wire = self.signed()
        self.merchant.enroll_wire(qid, self.chain.payer, wire, evidence=self.proof)
        capsule = self.capsule(wire)
        signature = make_payment_signature(required_header=self.header, expectation=self.expected,
            exact_wire=wire, capsule=capsule, payer=self.chain.payer, now_ns=self.chain.now)
        self.merchant.fulfill(qid, signature, capsule)
        quote = parse_payment_required(self.header, self.expected, now_ns=self.chain.now)
        self.assignment = TrustedMerchantAssignment(qid, quote['request_id'], self.expected.recipient,
            self.chain.payer, hashlib.sha256(wire).hexdigest())
        return qid, wire, capsule

    def verify(self, raw, **changes):
        args = dict(genesis_bytes=self.chain.genesis, policy=self.chain.policy,
                    expectation=self.expected, assignment=self.assignment, now_ns=self.chain.now)
        args.update(changes)
        return self.api().verify_merchant_proof(raw, **args)

    def test_export_retains_exact_bytes_and_does_not_change_journals(self):
        qid, wire, capsule = self.paid()
        before = self.merchant.db.total_changes
        raw = self.merchant.export_proof(qid)
        self.assertEqual(self.merchant.db.total_changes, before)
        value = json.loads(raw)
        self.assertEqual(base64.b64decode(value['wire_b64']), wire)
        self.assertEqual(base64.b64decode(value['capsule_b64']), capsule)
        self.assertEqual(base64.b64decode(value['resource_b64']), b'public premium report\n')
        self.assertEqual(value['required_header'], self.header)
        report = self.verify(raw)
        self.assertEqual(report['amount_units'], '7')
        self.assertEqual(report['fee_units'], '2')
        self.assertEqual(report['total_debit_units'], '9')
        self.assertTrue(report['native_execution_replayed'])
        self.assertTrue(report['native_signature_authenticates_resource'])
        self.assertTrue(report['resource_bytes_match_commitment'])
        self.assertEqual(report.get('verification_scope'), 'historical-as-of-caller-selected-time')
        self.assertIs(report['delivery_time_verified'], False)
        for name in ('merchant_identity_authenticated', 'merchant_consumption_proven',
                     'external_service_delivery_verified', 'external_settlement_verified',
                     'latest_network_state_established', 'spending_authority', 'onchain_privacy'):
            self.assertIs(report[name], False)
        self.assertEqual(self.service.state()['wallet']['pending_debit_units'], '9')

    def test_unfulfilled_quote_cannot_export_paid_proof(self):
        self.api()
        qid = self.merchant.add_quote(self.header, self.expected, resource=self.resource)['quote_sha256']
        with self.assertRaises(ValueError): self.merchant.export_proof(qid)
        self.assertEqual(self.merchant.db.execute('SELECT count(*) FROM fulfillments').fetchone()[0], 0)

    def test_export_replays_paid_receipt_instead_of_trusting_retained_success(self):
        qid, wire, capsule = self.paid()
        changed = json.loads(capsule)
        changed['binding']['receipt_sha256'] = '0'*64
        changed = encode(changed)
        # Coherent local display/header metadata still cannot replace replay.
        sig = make_payment_signature(required_header=self.header, expectation=self.expected,
            exact_wire=wire, capsule=changed, payer=self.chain.payer, now_ns=self.chain.now)
        from payment_x402 import _decode, _header, MAX_RESPONSE_HEADER
        response = self.merchant.db.execute('SELECT response_header FROM fulfillments').fetchone()[0]
        r, _ = _decode(response, MAX_RESPONSE_HEADER)
        r['extensions']['1soft-p4']['capsuleSha256'] = hashlib.sha256(changed).hexdigest()
        self.merchant.db.execute('UPDATE fulfillments SET capsule=?,capsule_sha256=?,signature_header=?,response_header=?',
            (changed, hashlib.sha256(changed).hexdigest(), sig, _header(r, MAX_RESPONSE_HEADER)))
        with self.assertRaises(ValueError): self.merchant.export_proof(qid)

    def test_changed_resource_preimage_wire_capsule_and_response_are_refused(self):
        qid, wire, capsule = self.paid(); original = json.loads(self.merchant.export_proof(qid))
        variants = {}
        for field, raw in [('resource_b64', b'changed resource'), ('wire_b64', wire+b' '),
                           ('capsule_b64', capsule+b' '), ('invoice_terms_b64', b'{}')]:
            bad = copy.deepcopy(original); bad[field] = base64.b64encode(raw).decode(); variants[field] = bad
        bad = copy.deepcopy(original); c = json.loads(capsule); c['binding']['native_txid']='0'*64
        bad['capsule_b64']=base64.b64encode(encode(c)).decode(); variants['receipt identity']=bad
        bad=copy.deepcopy(original); bad['response_header']=base64.b64encode(encode({'success':True})).decode()
        variants['unsigned response']=bad
        bad=copy.deepcopy(original); bad['signature_header']=base64.b64encode(encode({'x402Version':2})).decode()
        variants['payment header']=bad
        for name, bad in variants.items():
            with self.subTest(name=name), self.assertRaises(ValueError): self.verify(encode(bad))

    def test_self_selected_replacement_quote_cannot_relabel_genuine_payment(self):
        qid, _, _ = self.paid(); bad=json.loads(self.merchant.export_proof(qid))
        other=replace(self.expected, resource_url='https://merchant.example/other')
        bad['required_header']=self.offer(other,b'other resource',nonce='b'*64)
        with self.assertRaises(ValueError): self.verify(encode(bad),expectation=other)

    def test_external_assignment_pins_cannot_be_inferred_from_bundle(self):
        qid, _, _ = self.paid(); raw=self.merchant.export_proof(qid)
        for changes in (dict(wire_sha256='0'*64),dict(quote_sha256='0'*64),
                        dict(payer=self.chain.merchant),dict(request_id='0'*64)):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                self.verify(raw,assignment=replace(self.assignment,**changes))
        with self.assertRaises(ValueError): self.verify(raw,assignment=asdict(self.assignment))

    def test_verification_time_and_trust_are_supplied_separately(self):
        qid, _, _ = self.paid(); raw=self.merchant.export_proof(qid)
        with self.assertRaises(ValueError): self.verify(raw,now_ns=self.chain.now+7200*10**9)
        with self.assertRaises(ValueError): self.verify(raw,genesis_bytes=self.chain.genesis+b' ')
        policy=copy.deepcopy(self.chain.policy);policy['genesis_sha256']='0'*64
        with self.assertRaises(ValueError): self.verify(raw,policy=policy)
        bad=json.loads(raw);bad['now_ns']=self.chain.now
        with self.assertRaises(ValueError):self.verify(encode(bad))

    def test_duplicate_unknown_deep_oversized_and_noncanonical_input_are_refused(self):
        qid, _, _ = self.paid(); raw=self.merchant.export_proof(qid)
        bad=json.loads(raw);bad['private_key']='SYNTHETIC_SECRET'
        for value in (raw+b' ', b'{"schema":1,'+raw[1:], encode(bad), b'['*80+b']'*80,
                      b' '* (self.api().MAX_PROOF_BYTES+1)):
            with self.subTest(length=len(value)),self.assertRaises(ValueError):self.verify(value)
        bad=json.loads(raw);bad['resource_b64']=bad['resource_b64']+'\n'
        with self.assertRaises(ValueError):self.verify(encode(bad))

    def test_offline_cli_checks_without_engine_keys_or_workspace(self):
        qid, _, _ = self.paid();raw=self.merchant.export_proof(qid)
        self.assertTrue(CLI.is_file(),'offline verifier CLI missing')
        files={'proof':raw,'genesis':self.chain.genesis,'policy':encode(self.chain.policy),
               'expectation':encode(asdict(self.expected)), 'assignment':encode(asdict(self.assignment))}
        args=[]
        for name,value in files.items():
            path=self.root/(name+'.json');private_new(path,value);args+=['--'+name,str(path)]
        run=subprocess.run([sys.executable,'-B',str(CLI),*args,'--as-of-ns',str(self.chain.now)],capture_output=True,timeout=20)
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertTrue(json.loads(run.stdout)['resource_bytes_match_commitment'])
        run=subprocess.run([sys.executable,'-B',str(CLI),*args,'--as-of-ns',str(self.chain.now+7200*10**9)],capture_output=True,timeout=20)
        self.assertNotEqual(run.returncode,0);self.assertEqual(run.stdout,b'')
        self.assertLess(len(run.stderr),512)


if __name__=='__main__':unittest.main()
