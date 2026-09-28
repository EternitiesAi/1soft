"""Acceptance observer for one two-payment product journey; never a new wallet.

The engine runner and local fixture tests both call these existing component APIs.
This helper never signs, submits, syncs a wallet or claims that its inputs establish
independent operators. Every checkpoint report is saved before an assertion can
lose its exact observed result. Failed diagnostics do not imply database rollback.
"""
from __future__ import annotations

import json
from pathlib import Path
import time

from check_release import store_json
from commit_verifier import encode, header_hash, verify_signed_header
from explorer_index import ExplorerIndex
from explorer_rpc import refresh as refresh_explorer
from explorer_web import render
from native_core import canonical
from payment_rpc import endpoint_port
from receipt_archive import ReceiptArchive
from receipt_capsule import pack_receipt, verify_capsule
from receipt_collector import Reader


def require(ok, message):
    if not ok:
        raise AssertionError(message)


def validate_history(view, keep, *, minimum_height=0):
    """Validate explicit retention evidence, not transaction absence or disk size."""
    require(type(keep) is int and 2 <= keep <= 16, 'acceptance retention window must be 2..16')
    require(type(view) is dict and view.get('schema') == 1 and
            view.get('scope') == 'local_application_block_results', 'wrong history evidence')
    h = view['application_height']; a = view['availability']
    require(type(h) is int and h >= max(minimum_height, keep + 1), 'history has not crossed retention boundary')
    for name in ('keep_blocks', 'bootstrap_height', 'pruned_through', 'retained_from',
                 'retained_through', 'retained_count'):
        require(type(a.get(name)) is int, 'history count/height is not an integer')
    require(a['keep_blocks'] == keep and a['bootstrap_height'] == 0 and
            a['retained_count'] == keep and a['retained_from'] == h - keep + 1 and
            a['retained_through'] == h and a['pruned_through'] == h - keep and
            a['within_configured_window'] is True, 'unexpected retained range')
    require(view.get('native_receipts_pruned') is False and
            view.get('engine_history_pruning_requested') is False and
            view.get('historical_transaction_absence_proven') is False and
            view.get('total_storage_bounded') is False and
            type(view.get('cometbft_retain_height')) is int and view['cometbft_retain_height'] == 0,
            'history response claimed unsupported pruning/absence authority')
    return {'application_height': h, 'keep_blocks': keep,
            'retained_count': keep, 'pruned_through': a['pruned_through']}


class ProductObserver:
    """Persisted explorer + receipt checks beside, never inside, a wallet journal."""
    def __init__(self, work, output, genesis_bytes, policy, endpoint, budget_id, *, clock=time.time_ns):
        endpoint_port(endpoint)
        self.work = Path(work); self.work.mkdir(mode=0o700, exist_ok=False)
        self.output = Path(output); self.output.mkdir(mode=0o700, exist_ok=False)
        self.genesis = genesis_bytes; self.policy = policy; self.endpoint = endpoint
        self.budget_id = budget_id; self.clock = clock
        self.index = self.archive = None
        self.steps = []; self.receipts = []
        self.report = {'schema': 1, 'status': 'started', 'stages': self.steps,
                       'wallet_authority': False, 'independent_operators_established': False}
        self.persist()
        try:
            self.index = ExplorerIndex(self.work/'explorer.sqlite', genesis_bytes,
                                       policy['genesis_sha256'], create=True)
            self.archive = ReceiptArchive(self.work/'archive.sqlite', genesis_bytes,
                                          policy['genesis_sha256'], create=True)
        except BaseException:
            self.close(); raise

    def persist(self):
        path = self.output/'observer.json'
        store_json(path, self.report, replace=path.exists())

    def close(self):
        if self.index is not None: self.index.close(); self.index = None
        if self.archive is not None: self.archive.close(); self.archive = None

    @staticmethod
    def journals(wallet, delivery):
        return (list(wallet.db.iterdump()), list(delivery.dispatch.db.iterdump()))

    def begin(self, witness, wallet, delivery):
        """Bootstrap from the exact live state already accepted by the shared wallet."""
        before = self.journals(wallet, delivery)
        end = int(witness['state_commit']['header']['height'])
        require(1 <= end <= 65, 'initial acceptance checkpoint exceeds bounded explorer window')
        checkpoint = wallet.db.execute('SELECT height,block_hash FROM checkpoint WHERE id=1').fetchone()
        require(wallet.pending()['state_height'] == witness['state']['height'] and checkpoint is not None and
                checkpoint[0] == end and checkpoint[1].lower() == header_hash(witness['state_commit']['header']).hex(),
                'initial witness differs from exact wallet checkpoint')
        headers = [Reader(self.endpoint).call('commit', h)['signed_header'] for h in range(1, end)]
        headers.append(witness['state_commit'])
        bodies = [Reader(self.endpoint).call('block', h) for h in range(1, end)]
        evidence = {'schema': 1, 'state': witness['state'], 'state_commit': witness['state_commit'],
                    'headers': headers, 'blocks': bodies}
        pin = header_hash(witness['state_commit']['header']).hex()
        result = self.index.ingest(evidence, initial_header_hash=pin)
        store_json(self.output/'initial-import.json', result)
        require(self.journals(wallet, delivery) == before, 'explorer bootstrap changed monetary journals')
        self.record('signed', wallet, expected_pending=100, expected_spent=0)

    def record(self, name, wallet, *, expected_pending, expected_spent):
        view = self.index.current()
        budgets = [b for b in view['budgets'] if b['id'] == self.budget_id]
        require(len(budgets) == 1, 'selected shared budget missing or ambiguous')
        observed = {'stage': name, 'pending_units': wallet.pending()['pending_budget_units'].get(self.budget_id, 0),
                    'indexed_spent_units': int(budgets[0]['spent']), 'indexed_state_height': view['state_height'],
                    'indexed_anchor_hash': view['anchor_hash'], 'expected_pending': expected_pending,
                    'expected_spent': expected_spent}
        self.steps.append(observed); self.persist()  # Before any caller assertion.
        require(observed['pending_units'] == expected_pending and observed['indexed_spent_units'] == expected_spent,
                'wallet/explorer accounting stage differs')
        require(view['wallet_pending_debits_included'] is False, 'explorer assumed wallet reservation authority')
        return observed

    def before_reconcile(self, name, packet, raw, wallet, delivery, *, expected_pending, expected_spent):
        require(name in ('raven', 'atlas') and name not in {r['name'] for r in self.receipts},
                'duplicate/unknown product payment')
        before = self.journals(wallet, delivery)
        self.report['active_operation'] = name + '_receipt_and_index'; self.persist()
        included = int(packet['transactions'][0]['commit']['header']['height'])
        final = int(packet['state_commit']['header']['height'])
        require(included < final <= included + 65, 'receipt ancestry exceeds supported bound')
        # This separate fixed-height RPC read is checked under the runner's already
        # pinned test genesis. It is NOT a claim of a second independent operator.
        pin_header = Reader(self.endpoint).call('commit', final)['signed_header']
        verify_signed_header(pin_header, self.index.trust, expected_height=final)
        pin = header_hash(pin_header['header']).hex()
        require(pin == header_hash(packet['state_commit']['header']).hex(), 'receipt anchor conflicts with source header')
        links = [Reader(self.endpoint).call('commit', h)['signed_header'] for h in range(included+1, final)]
        capsule = pack_receipt(packet, self.genesis, self.policy['genesis_sha256'], expected_transaction=raw,
                               expected_header_hash=pin, continuation=links)
        result = self.archive.put(capsule, expected_transaction=raw, expected_header_hash=pin)
        require(self.archive.put(capsule, expected_transaction=raw, expected_header_hash=pin)['status'] == 'already_stored',
                'archive duplicate was not idempotent')
        verified = verify_capsule(capsule, self.genesis, self.policy['genesis_sha256'],
                                   expected_transaction=raw, expected_header_hash=pin)
        store_json(self.output/(name+'-capsule.json'), capsule)
        store_json(self.output/(name+'-capsule-verification.json'), verified)
        # The actual explorer collector captures once and retries only fixed H+1.
        # On failure its index may be unchanged; never turn that into nonpayment.
        outcome = refresh_explorer(self.index, self.endpoint, clock=self.clock)
        store_json(self.output/(name+'-explorer-refresh.json'), outcome)
        view = self.index.current()
        matches = [tx for tx in view['transactions'] if tx['id'] == verified['native_txid']]
        require(len(matches) == 1 and matches[0]['record'] == verified['receipt'] and
                matches[0]['block_inclusion_verified'] is True, 'explorer lacks exact included execution receipt')
        require(self.journals(wallet, delivery) == before, 'archive/explorer changed monetary journals')
        self.receipts.append({'name': name, 'evidence_id': result['evidence_id'], 'raw': raw,
                              'pin': pin, 'verified': verified, 'inclusion_height': included})
        return self.record(name+'_before_reconcile', wallet, expected_pending=expected_pending, expected_spent=expected_spent)

    def after_reconcile(self, name, wallet, *, expected_pending, expected_spent):
        observed = self.record(name+'_reconciled', wallet, expected_pending=expected_pending, expected_spent=expected_spent)
        old_view = self.index.current()
        self.index.close(); self.index = None
        self.archive.close(); self.archive = None
        self.index = ExplorerIndex(self.work/'explorer.sqlite', self.genesis, self.policy['genesis_sha256'])
        self.archive = ReceiptArchive(self.work/'archive.sqlite', self.genesis, self.policy['genesis_sha256'])
        require(self.index.current() == old_view, 'explorer view changed across reopen')
        for item in self.receipts:
            require(self.archive.lookup(item['raw'])['status'] == 'available', 'receipt missing after archive reopen')
        return observed

    def finish(self, wallet, delivery, *, expected_receipt_count):
        before = self.journals(wallet, delivery)
        require([(s['pending_units'], s['indexed_spent_units']) for s in self.steps] ==
                [(100,0),(100,60),(40,60),(40,100),(0,100)], 'incomplete product accounting journey')
        require([r['name'] for r in self.receipts] == ['raven','atlas'], 'two ordered receipts required')
        # Offline proof verification: this method has no RPC operation.
        for item in self.receipts:
            c = self.archive.export(item['evidence_id'])
            verified = verify_capsule(c, self.genesis, self.policy['genesis_sha256'],
                                       expected_transaction=item['raw'], expected_header_hash=item['pin'])
            require(verified == item['verified'], 'archived receipt changed')
        view = self.index.current()
        require(view['transaction_count'] == expected_receipt_count, 'explorer receipt count differs')
        require(self.journals(wallet, delivery) == before, 'offline final verification changed monetary journals')
        store_json(self.output/'explorer-evidence.json', self.index.evidence())
        store_json(self.output/'explorer-view.json', view)
        from explorer_index import write_new
        write_new(self.output/'explorer.html', render(view))
        self.report.update(status='passed', active_operation=None, archived_receipts=2,
                           exact_receipts_preserved=True, state_height=view['state_height'])
        self.persist()
        return self.report
