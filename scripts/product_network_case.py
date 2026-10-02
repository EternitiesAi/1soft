"""Opt-in product checks using real devnet RPC, never a replacement engine.

This helper creates only disposable derived indexes/archives and retains public
signed evidence. Called by run_devnet after its genuine validators are running.
Its unit tests use explicit fixtures and do not establish a consensus run.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
for directory in ('tools/explorer/src', 'tools/receipt-archive/src'):
    sys.path.insert(0, str(ROOT / directory))

from commit_verifier import encode, header_hash, pinned_genesis, verify_packet
from explorer_index import ExplorerIndex
from explorer_rpc import refresh
from explorer_web import render
from native_core import DOMAIN, canonical, parse_wire
from receipt_archive import ReceiptArchive
from receipt_capsule import pack_receipt, verify_capsule


def need(ok, message):
    if not ok:
        raise AssertionError(message)


def save(path: Path, value, *, replace=False):
    """Flush each observation before testing it; prior failed attempts stay visible."""
    raw = value if isinstance(value, bytes) else encode(value) + b'\n'
    temp = path.with_name(path.name + '.new') if replace else path
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    if replace:
        os.replace(temp, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(directory)
    finally: os.close(directory)


def check_retention(value, keep):
    """Check local availability only; never derive payment absence from pruning."""
    need(type(value) is dict and value.get('scope') == 'local_application_block_results',
         'missing local history evidence')
    a = value['availability']; height = value['application_height']
    need(type(height) is int and height > keep and a['keep_blocks'] == keep and
         a['retained_count'] == keep and a['retained_from'] == height - keep + 1 and
         a['retained_through'] == height and a['pruned_through'] == height - keep and
         a['bootstrap_height'] == 0 and a['within_configured_window'] is True,
         'retained local block window differs from requested policy')
    need(value['native_receipts_pruned'] is False and value['cometbft_retain_height'] == 0 and
         value['engine_history_pruning_requested'] is False and
         value['historical_transaction_absence_proven'] is False and
         value['total_storage_bounded'] is False, 'local pruning was confused with native history')
    return a


class ProductNetworkCase:
    """The wallet remains authoritative for holds; these clients can only read."""
    def __init__(self, work: Path, output: Path, genesis: bytes, endpoint: str,
                 read_rpc, checked, budget_id: str, *, clock=time.time_ns):
        self.work = Path(work); self.output = Path(output)
        self.work.mkdir(mode=0o700, exist_ok=False)
        self.output.mkdir(mode=0o700, exist_ok=False)
        self.genesis = bytes(genesis)
        self.genesis_hash = hashlib.sha256(genesis).hexdigest()
        self.trust = pinned_genesis(genesis, self.genesis_hash)
        self.endpoint = endpoint; self.rpc = read_rpc; self.checked = checked
        self.budget_id = budget_id; self.clock = clock
        self.index = None; self.archive = None; self.receipts = []
        self.report = {'schema': 1, 'enabled': True, 'status': 'running',
            'scope': 'product clients on the same local validator acceptance run',
            'stages': [], 'payments': [], 'observations': [],
            'source_node_mutations_by_product_clients': False,
            'wallet_mutations_by_product_clients': False,
            'independent_operators_verified': False, 'public_network': False, 'real_funds': False}
        try:
            self.index = ExplorerIndex(self.work / 'explorer.sqlite', genesis, self.genesis_hash, create=True)
            self.archive = ReceiptArchive(self.work / 'receipts.sqlite', genesis, self.genesis_hash, create=True)
            self.persist()
        except BaseException:
            self.close(); raise

    def persist(self):
        save(self.output / 'product-result.json', self.report,
             replace=(self.output / 'product-result.json').exists())

    def observe(self, label, value):
        need(re.fullmatch(r'[a-z0-9-]+', label) is not None, 'invalid evidence label')
        name = f"{len(self.report['observations']):03d}-{label}.json"
        raw = encode(value) + b'\n'
        save(self.output / name, raw)
        self.report['observations'].append({'file': name, 'sha256': hashlib.sha256(raw).hexdigest()})
        self.persist()

    def _refresh(self, label):
        try:
            result = refresh(self.index, self.endpoint, clock=self.clock)
        except Exception as exc:
            self.observe(label + '-refresh-error', {'status': 'raised', 'error_type': type(exc).__name__})
            raise
        self.observe(label + '-refresh-return', result)
        need(result['status'] in ('indexed', 'already_indexed') and result['broadcast'] is False,
             'live explorer refresh did not complete')
        return self.index.current()

    def _stage(self, label, wallet, expected_pending, expected_spent, *, reload=False):
        before = list(wallet.db.iterdump())
        view = self._refresh(label) if reload else self.index.current()
        pending = wallet.pending()
        budgets = [b for b in view['budgets'] if b['id'] == self.budget_id]
        need(len(budgets) == 1, 'selected shared budget missing from explorer')
        result = {'stage': label, 'wallet_pending_units': sum(pending['pending_budget_units'].values()),
                  'explorer_spent_units': int(budgets[0]['spent']),
                  'wallet_state_height': pending['state_height'], 'explorer_state_height': view['state_height'],
                  'explorer_anchor_hash': view['anchor_hash'], 'view_sha256': hashlib.sha256(encode(view)).hexdigest(),
                  'wallet_pending_debits_included': view['wallet_pending_debits_included']}
        self.report['stages'].append(result); self.persist()
        self.checked(label + ': read-only explorer and wallet maintain separate accounting',
                     result['wallet_pending_units'] == expected_pending and
                     result['explorer_spent_units'] == expected_spent and
                     result['wallet_pending_debits_included'] is False and
                     list(wallet.db.iterdump()) == before, result)
        save(self.output / (label + '-view.json'), view)
        save(self.output / (label + '-evidence.json'), self.index.evidence())
        return view

    def start(self, wallet, witness):
        # This header was already verified by CertifiedWallet under the runner's
        # separately generated public genesis. The endpoint cannot replace trust.
        before = list(wallet.db.iterdump())
        evidence = {'schema': 1, 'state': witness['state'], 'state_commit': witness['state_commit'],
                    'headers': [witness['state_commit']], 'blocks': []}
        result = self.index.ingest(evidence,
            initial_header_hash=header_hash(witness['state_commit']['header']).hex())
        self.observe('initial-wallet-anchor', result)
        need(list(wallet.db.iterdump()) == before, 'index initialization mutated wallet')
        return self._stage('both-signed', wallet, 100, 0, reload=True)

    def receipt(self, label, wallet, raw, packet, *, expected_pending, expected_spent):
        need(label in ('raven', 'atlas'), 'unexpected payment selection')
        before = list(wallet.db.iterdump())
        txid = hashlib.sha256(DOMAIN + canonical(parse_wire(raw)['body'])).hexdigest()
        verify_packet(packet, self.trust, expected_txids=[txid])
        transaction = packet['transactions'][0]
        inclusion = int(transaction['commit']['header']['height'])
        final = int(packet['state_commit']['header']['height'])
        need(0 <= final-inclusion-1 <= 64, 'receipt archive ancestry gap exceeds supported bound')
        links = [self.rpc('commit', {'height': str(h)})['signed_header'] for h in range(inclusion+1, final)]
        pin = header_hash(packet['state_commit']['header']).hex()
        capsule = pack_receipt(packet, self.genesis, self.genesis_hash,
            expected_transaction=raw, expected_header_hash=pin, continuation=links)
        archived = self.archive.put(capsule, expected_transaction=raw, expected_header_hash=pin)
        verified = verify_capsule(capsule, self.genesis, self.genesis_hash,
                                  expected_transaction=raw, expected_header_hash=pin)
        self.observe(label + '-archive-return', archived)
        save(self.output / (label + '-receipt-packet.json'), packet)
        save(self.output / (label + '-capsule.json'), capsule)
        save(self.output / (label + '-original.tx'), raw)
        view = self._stage(label + '-before-reconcile', wallet, expected_pending, expected_spent, reload=True)
        indexed = [t for t in view['transactions'] if t['id'] == txid]
        self.checked(label + ': explorer and archive bind the exact live receipt without releasing a hold',
            len(indexed) == 1 and indexed[0]['record'] == verified['receipt'] and
            indexed[0]['wire_hash'] == hashlib.sha256(raw).hexdigest() and
            indexed[0]['block_inclusion_verified'] is True and
            list(wallet.db.iterdump()) == before,
            {'native_txid': txid, 'receipt_height': inclusion, 'archive_kind': verified['proof_kind'],
             'indexed_body_verified': bool(indexed and indexed[0]['block_inclusion_verified'])})
        record = {'label': label, 'txid': txid, 'wire_sha256': hashlib.sha256(raw).hexdigest(),
                  'receipt_sha256': verified['receipt_sha256'], 'inclusion_height': inclusion,
                  'header_hash': pin, 'evidence_id': archived['evidence_id'],
                  'proof_kind': verified['proof_kind']}
        self.report['payments'].append(record); self.receipts.append((record, bytes(raw)))
        self.persist()

    def reconciled(self, label, wallet, expected_pending, expected_spent):
        self._stage(label + '-reconciled', wallet, expected_pending, expected_spent)
        # Actual close/reopen, not another in-memory object around the same handle.
        self.index.close(); self.archive.close()
        self.index = ExplorerIndex(self.work / 'explorer.sqlite', self.genesis, self.genesis_hash)
        self.archive = ReceiptArchive(self.work / 'receipts.sqlite', self.genesis, self.genesis_hash)
        self.checked(label + ': reopened derived stores preserve both indexed and archived payment',
                     self.index.current() is not None and all(
                         self.archive.lookup(raw)['status'] == 'available' for _, raw in self.receipts))

    def finish(self, wallet):
        expected = [(100, 0), (100, 60), (40, 60), (40, 100), (0, 100)]
        self.checked('integrated product stages match signed obligations and recorded spending',
                     [(s['wallet_pending_units'], s['explorer_spent_units']) for s in self.report['stages']] == expected,
                     self.report['stages'])
        need(len(self.receipts) == 2, 'product journey did not preserve both receipts')
        before = list(wallet.db.iterdump())
        view = self._refresh('final')
        checks = []
        for record, raw in self.receipts:
            wanted = record['inclusion_height']
            response = self.rpc('abci_query', {'path': '/block/' + str(wanted), 'prove': False})['response']
            import base64
            payload = json.loads(base64.b64decode(response['value'], validate=True))
            self.observe(record['label'] + '-pruned-block-response', {'code': int(response['code']), 'value': payload})
            need(int(response['code']) == 2 and payload['status'] == 'pruned_local_block_results' and
                 payload['historical_transaction_absence_proven'] is False, 'old payment block was not explicitly pruned')
            capsule = self.archive.export(record['evidence_id'])
            verified = verify_capsule(capsule, self.genesis, self.genesis_hash,
                                      expected_transaction=raw, expected_header_hash=record['header_hash'])
            indexed = next(t for t in view['transactions'] if t['id'] == record['txid'])
            need(indexed['record'] == verified['receipt'] and indexed['block_inclusion_verified'] is True,
                 'retained archive/explorer receipt differs after source-local pruning')
            checks.append({'native_txid': record['txid'], 'pruned_block': wanted,
                           'exact_archived_receipt_verified': True, 'index_retains_verified_inclusion': True})
        self.checked('old local payment metadata pruned while exact explorer and archive evidence remain',
                     len(checks) == 2 and list(wallet.db.iterdump()) == before, checks)
        save(self.output / 'explorer-final.html', render(view))
        save(self.output / 'explorer-final-view.json', view)
        save(self.output / 'explorer-final-evidence.json', self.index.evidence())
        self.report.update(status='passed', verification_after_local_pruning=checks,
                           final_state_height=view['state_height'], final_app_hash=view['app_hash'])
        self.persist()
        return self.report

    def close(self):
        for name in ('index', 'archive'):
            value = getattr(self, name, None)
            if value is not None:
                value.close(); setattr(self, name, None)
