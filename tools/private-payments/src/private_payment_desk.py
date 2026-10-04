"""Private invoice caller over the unchanged canonical P4 financial authority."""
import hashlib

from block_application import encode
from invoice_terms import terms_commitment
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

    def _native_terms(self, rid):
        row,e=self._selected(rid,live=True)
        q=parse_payment_required(row['required_header'],e,now_ns=self.platform.clock())
        invoice=q.get('invoice_terms')
        if invoice is not None:
            from p4_evidence import p4_genesis
            g,_=p4_genesis(self.platform.genesis,self.platform.policy['genesis_sha256'])
            need(g.get('invoice_commitment_version')==1,'invoice requires explicit fresh genesis capability')
        return invoice

    def _terms(self, rid, role, native_confirmation):
        row, e = self._selected(rid, live=True); hash_text(native_confirmation)
        result = {'schema': 1, 'format': '1soft/private-payment-consent/v1',
            'request_id': rid, 'quote_sha256': row['quote_sha256'],
            'merchant_origin': e.merchant_origin, 'resource_url': e.resource_url,
            'network': e.network, 'asset': e.asset, 'recipient': e.recipient,
            'amount_units': e.amount_units, 'genesis_sha256': e.genesis_sha256,
            'role': role, 'native_confirmation': native_confirmation,
            'onchain_privacy': False, 'native_signature_authenticates_resource': False}
        invoice=self._native_terms(rid)
        if invoice is not None:
            result.update(format='1soft/private-payment-consent/v2',
                resource_sha256=invoice['resource_sha256'],invoice_commitment=terms_commitment(invoice),
                created_ns=invoice['created_ns'],expires_ns=invoice['expires_ns'],
                native_invoice_commitment_required=True)
        return result

    def prepare(self, rid, role, *, valid_until):
        self._selected(rid, live=True)
        prepared = self.platform.prepare(rid, role, valid_until=valid_until,invoice_terms=self._native_terms(rid))
        terms = self._terms(rid, role, prepared['confirmation'])
        return {**prepared, 'terms': terms, 'terms_confirmation': content_id(terms)}

    def approve(self, rid, role, review, confirmation, terms_confirmation, *, payment_password):
        hash_text(terms_confirmation)
        need(content_id(review) == confirmation, 'native review confirmation differs')
        invoice=self._native_terms(rid)
        need(encode(review.get('invoice_terms'))==encode(invoice),'native review changes retained invoice terms')
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


class AlphaPrivatePaymentDesk(PrivatePaymentDesk):
    """Payer-only committed invoices over the original durable alpha journal.

    Alpha historical capsules do not enter the legacy merchant fulfillment lane.
    """
    def __init__(self, platform, invoices):
        from p4_alpha_platform_service import AlphaPlatformService
        from p4_evidence import p4_genesis
        need(type(platform) is AlphaPlatformService and type(invoices) is InvoiceBook,
             'canonical alpha platform and dedicated invoice storage required')
        need(platform.policy['genesis_sha256'] == invoices.genesis,
             'invoice and financial context differ')
        g,_=p4_genesis(platform.genesis,platform.policy['genesis_sha256'])
        need(g.get('invoice_commitment_version')==1,
             'alpha invoices require explicit fresh genesis capability')
        self.platform=platform;self.invoices=invoices

    def import_invoice(self, required_header, expectation, content, *, invoice_password):
        checked=parse_payment_required(required_header,expectation,now_ns=self.platform.clock())
        need(type(checked.get('invoice_terms')) is dict,'alpha payer requires a committed v2 invoice')
        return super().import_invoice(required_header,expectation,content,invoice_password=invoice_password)

    def _native_terms(self, rid):
        invoice=super()._native_terms(rid)
        need(type(invoice) is dict,'alpha payer requires a committed v2 invoice')
        return invoice

    def payment_header(self, rid, capsule_id):
        from merchant_alpha import make_signature
        row,e=self._selected(rid,live=True);wire=self.platform.recover(rid)
        capsule=self.platform.capsule(rid,capsule_id)
        decision=self.platform.book.selected(rid)['review']
        need(decision is not None,'original signed invoice required')
        header=make_signature(required_header=row['required_header'],expectation=e,exact_wire=wire,
            capsule=capsule,payer=decision['body']['sender'],now_ns=self.platform.clock())
        return dict(payment_signature_header=header,quote_sha256=row['quote_sha256'],request_id=rid,
            wire_sha256=hashlib.sha256(wire).hexdigest(),capsule_sha256=hashlib.sha256(capsule).hexdigest(),
            resource_delivery_authorized=False,wallet_reservations_changed=False,onchain_privacy=False,full_public_ledger_disclosed=True)


def desk_for_platform(platform, invoices):
    """Exact version dispatch; no subclass or failed-loader fallback."""
    from p4_alpha_platform_service import AlphaPlatformService
    if type(platform) is PlatformService:return PrivatePaymentDesk(platform,invoices)
    if type(platform) is AlphaPlatformService:return AlphaPrivatePaymentDesk(platform,invoices)
    raise ValueError('unsupported canonical invoice payer platform')
