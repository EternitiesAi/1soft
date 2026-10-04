"""Committed merchant invoices in the existing guarded loopback wallet.

Only configured, retained quotes enter this view. No decrypt, quote fetch,
network lifecycle, alternate signer or retry is reachable through this adapter.
"""
import hashlib
from commit_verifier import load_json
from local_devnet import read_private
from block_application import encode
from invoice_terms import terms_commitment
from p4_evidence import content_id, need
from payment_x402 import parse_payment_required
from private_payment_desk import PrivatePaymentDesk, AlphaPrivatePaymentDesk


class MerchantBrowserService:
    allow_unsigned_requests = False

    def __init__(self, desk, *, fulfillment=None):
        need(type(desk) in (PrivatePaymentDesk, AlphaPrivatePaymentDesk), 'canonical private payment desk required')
        self.desk = desk
        self.policy = desk.platform.policy
        self.clock = desk.platform.clock
        self.book = self  # The HTTP request export must check invoice correlation too.
        if fulfillment is not None:
            from merchant_browser_delivery import AlphaMerchantBridge
            need(type(desk) is AlphaPrivatePaymentDesk and type(fulfillment) is AlphaMerchantBridge,
                 'explicit original alpha merchant capability required')
        self.fulfillment=fulfillment

    def _committed(self, rid, *, live=False):
        row, expected = self.desk._selected(rid, live=live)
        quote = parse_payment_required(row['required_header'], expected,
            now_ns=self.clock() if live else row['request']['created_ns'])
        terms = quote.get('invoice_terms')
        need(type(terms) is dict, 'browser requires a committed v2 invoice')
        entry = self.desk.platform.book.selected(rid)
        review = entry['review']
        if review is not None:
            need(review.get('format') == '1soft/p4-invoice-transfer-review/v1' and
                 encode(review.get('invoice_terms')) == encode(terms) and
                 review['body']['op'].get('invoice_commitment') == terms_commitment(terms),
                 'original review differs from committed merchant invoice')
        return row, terms

    def selected(self, rid):
        self._committed(rid)
        return self.desk.platform.book.selected(rid)

    def add_request(self, _value):
        raise ValueError('merchant browser accepts retained committed invoices only')

    def prepare(self, rid, role, *, valid_until):
        self._committed(rid, live=True)
        return self.desk.prepare(rid, role, valid_until=valid_until)

    def approve(self, *_args, **_kwargs):
        raise ValueError('merchant terms approval is required')

    def approve_invoice(self, rid, role, review, confirmation, terms, terms_confirmation, *, password):
        self._committed(rid, live=True)
        need(review.get('format') == '1soft/p4-invoice-transfer-review/v1',
             'committed native invoice review required')
        original = self.desk._terms(rid, role, confirmation)
        need(encode(original) == encode(terms) and content_id(terms) == terms_confirmation,
             'exact retained merchant terms approval required')
        return self.desk.approve(rid, role, review, confirmation, terms_confirmation,
                                 payment_password=password)

    def recover(self, rid):
        self._committed(rid)
        return self.desk.recover(rid)

    def submission_review(self, rid):
        self._committed(rid, live=True)
        return self.desk.submission_review(rid)

    def submit(self, rid, review, confirmation):
        self._committed(rid, live=True)
        return self.desk.submit(rid, review, confirmation)

    def collect(self, rid):
        self._committed(rid)
        return self.desk.collect(rid)

    def retain_receipt(self, rid):
        self._committed(rid)
        return self.desk.retain_receipt(rid)

    def reconcile(self, rid, *, expected_revision):
        self._committed(rid)
        return self.desk.reconcile(rid, expected_revision=expected_revision)

    def capsule(self, rid, capsule_id):
        self._committed(rid)
        return self.desk.platform.capsule(rid, capsule_id)

    def refresh(self, *, expected_tip):
        return self.desk.platform.refresh(expected_tip=expected_tip)

    def sync(self, *, expected_revision):
        return self.desk.platform.sync(expected_revision=expected_revision)

    def backup_history(self, password):
        # Scope is the complete canonical shared pair, including hidden generic roles.
        return self.desk.platform.backup_history(password)

    def _resource_context(self,rid):
        self._committed(rid)
        need(self.fulfillment is not None,'merchant fulfillment is not configured')
        return self.fulfillment

    def resource_review(self,rid):
        return self._resource_context(rid).review(self.desk,rid)

    def retrieve_purchase(self,rid,review,confirmation):
        return self._resource_context(rid).retrieve(self.desk,rid,review,confirmation)

    def merchant_proof(self,rid):
        return self._resource_context(rid).proof(self.desk,rid)

    def state(self):
        catalog = {}
        for invoice in self.desk.invoices.entries():
            rid = invoice['request_id']
            row, terms = self._committed(rid)  # Historical correlation, never fallback.
            e = row['expectation']
            catalog[rid] = dict(merchant_origin=e['merchant_origin'], resource_url=e['resource_url'],
                network=e['network'], asset=e['asset'], quote_sha256=row['quote_sha256'],
                resource_sha256=terms['resource_sha256'], invoice_commitment=terms_commitment(terms),
                created_ns=str(terms['created_ns']), expires_ns=str(terms['expires_ns']),
                application_data_encrypted=True, data_decrypted=False, onchain_privacy=False,
                fulfillment_proven=False, native_invoice_commitment_required=True)
        state = self.desk.platform.state()
        rows = []
        for entry in state['requests']:
            rid = entry['request_id']
            if rid not in catalog: continue
            request = dict(entry['request'])
            request.update(created_ns=str(request['created_ns']), expires_ns=str(request['expires_ns']))
            delivery=None if self.fulfillment is None else self.fulfillment.status(self.desk,rid)
            if delivery is not None:
                delivery['retrieval_available']=delivery.get('retrieval_available',False) and delivery.get('reference_id') in entry['capsule_ids']
            rows.append({**entry, 'request':request, 'invoice':catalog[rid], 'merchant_delivery':delivery})
        return {**state, 'requests':rows, 'payment_mode':'committed_merchant_invoices',
            'hidden_generic_request_count':len(state['requests'])-len(rows),
            'invoice_data_decrypted':False, 'onchain_privacy':False, 'merchant_fulfillment_performed':False,
            'merchant_fulfillment_available':self.fulfillment is not None}


def ready_for_browser(network):
    """Validate the original explicitly invoice-capable workspace pins.

    Alpha readiness uses its existing marker; legacy v3 uses historical pins.
    This neither starts the network nor grants live wallet authority. Financial
    components still enforce their original policy and clock.
    """
    from local_devnet import LocalNetwork, ALPHA_INVOICE_FORMAT, load_configuration
    if network.config.get('format')==ALPHA_INVOICE_FORMAT:
        need(type(network) is LocalNetwork and network.alpha,'canonical invoice alpha network required')
        need(load_configuration(network.root)==network.config,'original alpha invoice configuration differs')
        need(network.ready(),'original initialized alpha invoice readiness pins required')
        return True
    need(network.config['schema']==3,'browser requires a fresh invoice-capable v3 workspace')
    network._check_config()
    network.policy()  # Canonical, pinned original policy; never renewed.
    path=network.root/'READY.json'
    need(not path.is_symlink() and path.is_file(),'original initialized readiness marker required')
    raw=read_private(path);marker=load_json(raw)
    expected=dict(schema=3,format='1soft/local-development-ready/v3',
        workspace_sha256=hashlib.sha256(read_private(network.root/'workspace.json')).hexdigest(),
        policy_sha256=hashlib.sha256(read_private(network.root/'policy.json')).hexdigest())
    need(type(marker) is dict and type(marker.get('schema')) is int and marker==expected and
         encode(marker)==raw and network._ready_bytes==raw,'original readiness pins differ')
    return True
