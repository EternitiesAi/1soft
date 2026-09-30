"""Private invoice caller over the unchanged canonical P4 financial authority."""
import hashlib

from block_application import encode
from p4_evidence import content_id, hash_text, need
from platform_service import PlatformService
from invoice_book import InvoiceBook
from payment_x402 import NativePaymentExpectation, parse_payment_required, make_payment_signature


class PrivatePaymentDesk:
    """No new signing, reservations, attempt journal, trust or reconciliation rule."""
    def __init__(self, platform, invoices):
        need(type(platform) is PlatformService and type(invoices) is InvoiceBook,
             'canonical platform and dedicated invoice storage required')
        need(platform.policy['genesis_sha256'] == invoices.genesis,
             'invoice and financial context differ')
        self.platform = platform; self.invoices = invoices

    def import_invoice(self, required_header, expectation, content, *, invoice_password):
        row = self.invoices.retain(required_header=required_header, expectation=expectation,
                                   content=content, password=invoice_password)
        # Two stores are not an atomic transaction. A failed unsigned append can
        # be completed by the same live import; original ciphertext is retained.
        request = self.platform.add_request(row['request'])
        need(request['request_id'] == row['request_id'], 'request retention changed invoice identity')
        return {'status': 'encrypted_invoice_and_unsigned_request_retained',
            'request_id': row['request_id'], 'quote_sha256': row['quote_sha256'],
            'envelope_sha256': row['envelope_sha256'], 'execution_proven': False,
            'spending_authority': False, 'onchain_privacy': False}

    def _selected(self, rid, *, live=False):
        row = self.invoices.selected(rid)
        request = self.platform.book.selected(rid)
        need(encode(row['request']) == encode(request['request']),
             'financial request differs from immutable merchant invoice')
        e = NativePaymentExpectation(**row['expectation'])
        if live:
            quote = parse_payment_required(row['required_header'], e, now_ns=self.platform.clock())
            need(quote['request_id'] == rid and quote['quote_sha256'] == row['quote_sha256'],
                 'live merchant invoice identity differs')
        return row, e

    def _terms(self, rid, role, native_confirmation):
        row, e = self._selected(rid, live=True); hash_text(native_confirmation)
        return {'schema': 1, 'format': '1soft/private-payment-consent/v1',
            'request_id': rid, 'quote_sha256': row['quote_sha256'],
            'merchant_origin': e.merchant_origin, 'resource_url': e.resource_url,
            'network': e.network, 'asset': e.asset, 'recipient': e.recipient,
            'amount_units': e.amount_units, 'genesis_sha256': e.genesis_sha256,
            'role': role, 'native_confirmation': native_confirmation,
            'onchain_privacy': False, 'native_signature_authenticates_resource': False}

    def prepare(self, rid, role, *, valid_until):
        self._selected(rid, live=True)
        prepared = self.platform.prepare(rid, role, valid_until=valid_until)
        terms = self._terms(rid, role, prepared['confirmation'])
        return {**prepared, 'terms': terms, 'terms_confirmation': content_id(terms)}

    def approve(self, rid, role, review, confirmation, terms_confirmation, *, payment_password):
        hash_text(terms_confirmation)
        need(content_id(review) == confirmation, 'native review confirmation differs')
        terms = self._terms(rid, role, confirmation)
        need(content_id(terms) == terms_confirmation, 'merchant terms confirmation differs')
        return self.platform.approve(rid, role, review, confirmation, password=payment_password)

    def recover(self, rid):
        self._selected(rid)  # Historical recovery never re-signs or re-encrypts.
        return self.platform.recover(rid)

    def open_invoice(self, rid, *, invoice_password):
        self._selected(rid)
        return self.invoices.decrypt(rid, password=invoice_password)

    def submission_review(self, rid):
        self._selected(rid, live=True)
        return self.platform.submission_review(rid)

    def submit(self, rid, review, confirmation):
        self._selected(rid, live=True)
        return self.platform.submit(rid, review, confirmation)

    def collect(self, rid):
        self._selected(rid)
        return self.platform.collect(rid)

    def retain_receipt(self, rid):
        self._selected(rid)
        return self.platform.retain_receipt(rid)

    def reconcile(self, rid, *, expected_revision):
        self._selected(rid)
        return self.platform.reconcile(rid, expected_revision=expected_revision)

    def payment_header(self, rid, capsule_id):
        row, e = self._selected(rid, live=True)
        wire = self.platform.recover(rid)
        capsule = self.platform.capsule(rid, capsule_id)
        body = row['request']; decision = self.platform.book.selected(rid)['review']
        need(decision is not None, 'invoice has no original signed payment')
        header = make_payment_signature(required_header=row['required_header'], expectation=e,
            exact_wire=wire, capsule=capsule, payer=decision['body']['sender'], now_ns=self.platform.clock())
        return {'payment_signature_header': header, 'quote_sha256': row['quote_sha256'],
            'request_id': rid, 'wire_sha256': hashlib.sha256(wire).hexdigest(),
            'capsule_sha256': hashlib.sha256(capsule).hexdigest(),
            'resource_delivery_authorized': False, 'wallet_reservations_changed': False,
            'full_public_ledger_disclosed': True, 'onchain_privacy': False}
