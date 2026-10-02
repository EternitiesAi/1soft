"""Integrated local fixture journey; NOT a CometBFT run or a user-facing wallet.

Uses existing production-path APIs and existing disposable native/HTTP fixtures.
Deterministic committee signatures do not establish consensus or live provenance.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

from block_application import BlockApplication, encode
from certified_wallet import CertifiedWallet
from commit_verifier import header_hash
from decision_delivery import DecisionDelivery
from delivery_fixture import Scenario, IDS
from explorer_index import ExplorerIndex
from explorer_rpc import refresh as refresh_explorer
from native_core import canonical
from receipt_archive import ReceiptArchive
from receipt_capsule import pack_receipt, verify_capsule
from state_sync import OFFER_ACCEPT, APPLY_ACCEPT


def require(ok, message):
    if not ok: raise AssertionError(message)


def run_journey(compact=False):
    c = Scenario(compact=compact)
    index = archive = target = None
    stages = []; capsules = []; decisions = []
    genesis_hash = c.policy['genesis_sha256']
    try:
        # Exercise the actual opt-in retention feature in the combined journey.
        c.app.close()
        c.app = BlockApplication(c.root/'app.sqlite', expected_genesis=c.genesis, block_history_keep=2)
        decisions.append(c.sign())
        try:
            c.sign(who=3, units=39)
        except ValueError:
            pass
        else:
            raise AssertionError('shared budget overcommit was accepted')
        decisions.append(c.sign(who=3, units=38))
        require(c.holds() == 100, 'signed payment fees not fully reserved')
        for key in c.root.glob('*.pem'): key.unlink()
        require(not list(c.root.glob('*.pem')), 'fixture vault files not removed')

        index_path = c.root/'explorer.sqlite'; archive_path = c.root/'archive.sqlite'
        index = ExplorerIndex(index_path, c.raw, genesis_hash, create=True, profile='synthetic-fixture')
        archive = ReceiptArchive(archive_path, c.raw, genesis_hash, create=True)
        def record(name):
            view = index.current()
            require(view is not None, 'explorer state missing')
            require(view['wallet_pending_debits_included'] is False, 'explorer claimed wallet holds')
            stages.append({'stage': name, 'wallet_pending_units': c.holds(),
                'explorer_spent_units': int(view['budgets'][0]['spent']),
                'explorer_state_height': view['state_height'],
                'submissions': len(c.seen)})
        def delivery(url, create=False):
            return DecisionDelivery(c.wallet_path, c.delivery_path, c.raw, c.policy, url,
                                    create=create, clock=lambda: c.clock)

        with c.rpc() as url, patch('certified_wallet._load_vault', side_effect=AssertionError('no key unlock after signing')):
            refresh_explorer(index, url, initial_header_hash=header_hash(c.exposed['state_commit']['header']).hex(),
                             clock=lambda: c.clock)
            record('two_payments_signed')
            for n, (signed, role) in enumerate(zip(decisions, ('raven', 'atlas'))):
                selection = {'account': IDS[0], 'grant_id': role}; decision = signed['decision_id']
                with delivery(url, create=n == 0) as d:
                    queued = d.queue(decision, **selection)
                    sent = d.send(decision, queued['delivery_confirmation'], **selection)
                    require(sent['transport_status'] == 'unresolved', 'actual fixture TCP reply loss not observed')
                # Reopen both the wallet connection and delivery adapter. Recovery
                # requests only evidence, never another submission or signature.
                c.wallet.close()
                c.wallet = CertifiedWallet(c.wallet_path, c.raw, c.policy, clock=lambda: c.clock)
                with delivery(url) as d:
                    count = len(c.seen)
                    found = d.refresh(decision, **selection)
                    require(found['exact_transport_receipt_verified'], 'exact receipt not collected')
                    require(len(c.seen) == count, 'receipt recovery resent payment')
                    packet = json.loads(d.export_receipt(decision, **selection))
                    raw = canonical(signed['result'])
                    pin = header_hash(packet['state_commit']['header']).hex()
                    included = int(packet['transactions'][0]['commit']['header']['height'])
                    final = int(packet['state_commit']['header']['height'])
                    capsule = pack_receipt(packet, c.raw, genesis_hash, expected_transaction=raw,
                        expected_header_hash=pin, continuation=[c.headers[h] for h in range(included+1, final)])
                    held = c.holds(); receipt = archive.put(capsule, expected_transaction=raw, expected_header_hash=pin)
                    refresh_explorer(index, url, clock=lambda: c.clock)
                    require(c.holds() == held, 'archive/explorer changed financial reservation')
                    record(role + '_recorded_before_wallet_sync')
                    answer = d.reconcile(decision, continuation=c.continuation(), **selection)
                    require(answer['wallet_obligation_status'] == 'recorded', 'wallet did not reconcile')
                    capsules.append({'id': receipt['evidence_id'], 'raw': raw, 'pin': pin})
                    record(role + '_reconciled')
                index.close(); index = ExplorerIndex(index_path, c.raw, genesis_hash)
                archive.close(); archive = ReceiptArchive(archive_path, c.raw, genesis_hash)
            with delivery(url) as d:
                before = c.holds()
                again = d.reconcile(decisions[0]['decision_id'], account=IDS[0], grant_id='raven')
                require(again['reconciliation_outcome'] == 'already_recorded', 'older receipt did not converge')
                require(before == c.holds() == 0, 'revisiting old receipt changed holds')
        require(c.seen == [canonical(d['result']) for d in decisions], 'not exactly one submission of each original payment')
        expected = [(100, 0), (100, 60), (40, 60), (40, 100), (0, 100)]
        require([(s['wallet_pending_units'], s['explorer_spent_units']) for s in stages] == expected,
                'cross-component accounting stages differ')
        view = index.current()
        require(int(next(a for a in view['accounts'] if a['id'] == IDS[0])['balance']) == 892,
                'payer balance differs from actual setup and fees')
        require(len(view['transactions']) == 6, 'explorer duplicated or omitted a native receipt')
        require(c.app.query('/block/3')['code'] == 2, 'old local result was not pruned')
        require(all(t['block_inclusion_verified'] for t in view['transactions']), 'collected body coverage missing')

        # A fresh application reconstructs the snapshot and follows one subsequent
        # empty block. This is application testing, not state-sync engine voting.
        target = BlockApplication(c.root/'observer.sqlite', expected_genesis=c.genesis, block_history_keep=2)
        descriptor = c.app.list_snapshots()[0]
        require(target.offer_snapshot(descriptor, bytes.fromhex(c.app.app_hash)) == OFFER_ACCEPT, 'snapshot offer refused')
        for i in range(descriptor['chunks']):
            result = target.apply_snapshot_chunk(i, c.app.load_snapshot_chunk(descriptor['height'], 1, i), 'local-fixture')
            require(result['result'] == APPLY_ACCEPT, 'snapshot not applied')
        marker = target.db.execute('SELECT height,app_hash FROM state_sync_marker').fetchone()
        require(target.query('/state')['value'] == c.app.query('/state')['value'], 'snapshot state differs')
        require(target.check_tx(c.seen[0])['code'] != 0, 'snapshot lost replay protection')
        c.block([])
        h = c.app.height
        target.finalize_block([], h, header_hash(c.headers[h]['header'])); target.commit()
        require(target.query('/state')['value'] == c.app.query('/state')['value'], 'post-snapshot continuation differs')
        require(target.db.execute('SELECT height,app_hash FROM state_sync_marker').fetchone() == marker,
                'bootstrap provenance was lost')
        c.app.close()
        for capsule in capsules:
            require(archive.lookup(capsule['raw'])['status'] == 'available', 'archived receipt disappeared')
            verified = verify_capsule(archive.export(capsule['id']), c.raw, genesis_hash,
                                      expected_transaction=capsule['raw'], expected_header_hash=capsule['pin'])
            require(not verified['wallet_reservations_changed'], 'archive implies authority')
        return {'schema': 1, 'status': 'passed', 'commitment': 'smt-v1' if compact else 'legacy-flat-v1',
            'stages': stages, 'submission_count': len(c.seen), 'original_signed_bytes_preserved': True,
            'old_local_block_result_pruned': True, 'recorded_budget_spend': 100,
            'final_wallet_pending': c.holds(), 'payer_balance': 892, 'archived_receipts': len(capsules),
            'snapshot_height': marker[0], 'observer_final_height': target.height,
            'observer_app_hash': target.app_hash, 'native_receipts': len(target.native['receipts']),
            'fixture_committee': True, 'actual_loopback_reply_drop': True,
            'consensus_executed': False, 'real_funds': False}
    finally:
        for resource in (index, archive, target):
            if resource is not None: resource.close()
        c.close()
