"""Deliver an existing CertifiedWallet decision through the existing dispatcher.

No key, new signature, new reservation store, raw-envelope import, public endpoint
or automatic resend. The wallet and dispatch databases remain independent owners:
receipt verification is not wallet reconciliation. A lost response stays unknown.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import os
from pathlib import Path
import re
import sqlite3
import time
from typing import Callable

from account_view import open_readonly, _policy, _project
from block_application import restore
from certified_wallet import CertifiedWallet, MAX_EVIDENCE, nanos
from commit_verifier import encode, load_json
from native_core import FEE_ACCOUNT, canonical, identifier, require
from payment_rpc import endpoint_port
from payment_transport import DispatchJournal, MAX_ATTEMPTS
from wallet_obligations import checked_decision, inventory

DELIVERY_DOMAIN = b'1soft/wallet-decision-delivery/v1\x00'
DISPATCH_COLUMNS = {
    'configuration': ('id', 'value', 'clock_ns'),
    'payments': ('txid', 'slot', 'raw', 'signer', 'wire_hash', 'confirmation', 'status',
                 'attempts', 'proof', 'proof_hash'),
    'events': ('id', 'txid', 'event', 'detail'),
}


def _hex(value: str) -> str:
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None,
            'an exact existing decision identifier is required')
    return value


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class DecisionDelivery:
    """Explicit account/role plus one immutable signing decision, not a signer.

    The caller supplies independently selected genesis/policy, one existing wallet
    and one dedicated existing-or-new dispatch journal. Other workspaces and raw
    exported signatures remain outside local dispatch/replay coordination.
    """
    def __init__(self, wallet_journal: Path, genesis_bytes: bytes, policy: dict, *,
                 dispatch_journal: Path, endpoint: str, account: str,
                 decision_id: str, grant_id: str = '',
                 clock: Callable[[], int] = time.time_ns):
        identifier(account)
        require(account != FEE_ACCOUNT, 'system account is not a payer')
        require(type(grant_id) is str, 'grant label must be explicit text')
        if grant_id:
            identifier(grant_id)
        endpoint_port(endpoint)
        self.genesis_bytes = genesis_bytes
        self.policy = load_json(encode(policy), max_bytes=16384)
        self.trust, self.policy_id, self.deadline = _policy(genesis_bytes, self.policy)
        self.genesis = load_json(genesis_bytes, max_bytes=1024*1024)['app_state']
        self.wallet_path = Path(os.path.abspath(wallet_journal))
        self.dispatch_path = Path(os.path.abspath(dispatch_journal))
        protected = {str(self.wallet_path) + suffix for suffix in ('', '-wal', '-shm', '-journal')}
        require(str(self.dispatch_path) not in protected and
                str(self.dispatch_path) + '.dispatch-lock' not in protected,
                'dispatch journal must be separate from wallet and its sidecars')
        if self.wallet_path.exists() and self.dispatch_path.exists():
            require(not os.path.samefile(self.wallet_path, self.dispatch_path),
                    'dispatch journal aliases the wallet')
        self.endpoint = endpoint
        self.account, self.grant_id = account, grant_id
        self.decision_id, self.clock = _hex(decision_id), clock

    def _source(self, *, for_send: bool = False) -> dict:
        """Capture state, decision and complete holds in one read-only snapshot."""
        now = self.clock()
        require(type(now) is int and 0 <= now <= 2**63-1, 'invalid local clock')
        db = open_readonly(self.wallet_path)
        ledger = None
        try:
            db.execute('BEGIN')
            view = _project(db, self.genesis_bytes, self.policy, self.account, now, 1)
            row = db.execute('SELECT id,slot,review,result,result_hash FROM decisions WHERE id=?',
                             (self.decision_id,)).fetchone()
            require(row is not None, 'signed decision not found; do not create a replacement payment')
            item = checked_decision(row, self.genesis, self.policy_id)
            body = item['body']
            require(item['mode'] == 'sign' and body['op']['type'] == 'transfer' and
                    body['sender'] == self.account and body['grant_id'] == self.grant_id,
                    'decision is not a transfer for the explicitly selected payer and role')
            witness_row = db.execute('SELECT witness FROM wallet_evidence WHERE id=1').fetchone()
            witness = load_json(witness_row[0].encode(), max_bytes=MAX_EVIDENCE)
            ledger = restore(witness['state']['genesis'], witness['state']['native'])
            summary = inventory(db, self.policy_id, ledger, witness['state']['height'])
            selected = next((e for e in summary['entries'] if e['decision_id'] == self.decision_id), None)
            require(selected is not None, 'decision absent from verified obligation inventory')
            if for_send:
                require(view['observation']['within_local_time_and_frontier_policy'],
                        'saved state is not current under local policy; refresh before sending')
                require(selected['status'] == 'pending', 'decision is already recorded or expired; no send')
                # Validate original bytes in a disposable native state. This is NOT
                # another signature or double charging the local reservation.
                ledger.apply(item['result'], height=witness['state']['height'] + 1)
            db.execute('ROLLBACK')
            return {'view': view, 'item': item, 'obligation': selected,
                    'inventory_digest': summary['digest'], 'raw': canonical(item['result']),
                    'clock_ns': now}
        finally:
            if ledger is not None:
                ledger.close()
            if db.in_transaction:
                db.execute('ROLLBACK')
            db.close()

    def _network_policy(self, source: dict, *, require_fresh: bool = False) -> None:
        blockers = source['view']['observation']['blockers']
        require('policy_expired' not in blockers and 'local_clock_rollback' not in blockers,
                'wallet trust expired or clock regressed; no network action')
        now = self.clock()
        require(type(now) is int and source['clock_ns'] <= now < self.deadline,
                'trust expired or clock regressed during delivery checks')
        if require_fresh:
            stamp = nanos(source['view']['state']['header_time_utc'])
            require(now - stamp <= self.policy['maximum_age_seconds'] * 10**9 and
                    stamp <= now + self.policy['future_skew_seconds'] * 10**9,
                    'saved state aged out before submission; refresh and review again')

    def _dispatch_exists(self) -> bool:
        # A dangling link is not treated as a new database location.
        return self.dispatch_path.exists() or self.dispatch_path.is_symlink()

    def _dispatch_schema(self) -> None:
        """Reject a wallet/unknown database before the legacy constructor writes."""
        db = open_readonly(self.dispatch_path)
        try:
            objects = db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
            require({x[1] for x in objects} == set(DISPATCH_COLUMNS) and
                    all(x[0] == 'table' and type(x[2]) is str and 'VIRTUAL' not in x[2].upper()
                        for x in objects),
                    'not a dedicated supported dispatch journal; no implicit migration')
            for name, expected in DISPATCH_COLUMNS.items():
                actual = tuple(x[1] for x in db.execute('PRAGMA table_info("' + name + '")'))
                require(actual == expected, 'dispatch columns differ')
            rows = db.execute('SELECT id,value,clock_ns FROM configuration').fetchall()
            require(len(rows) == 1 and rows[0][0] == 1 and type(rows[0][2]) is int and
                    0 <= rows[0][2] <= 2**63-1, 'dispatch configuration missing or inconsistent')
            expected_config = encode({'schema': 1, 'genesis_sha256': self.policy['genesis_sha256'],
                                      'endpoint': self.endpoint,
                                      'trust_expires_utc': self.policy['trust_expires_utc']}).decode()
            require(rows[0][1] == expected_config, 'dispatch configuration differs from selected policy')
        finally:
            db.close()

    @contextmanager
    def _dispatcher(self, *, create: bool = False):
        if self._dispatch_exists():
            self._dispatch_schema()
        else:
            require(create, 'payment is not staged in this dispatch journal')
        with DispatchJournal(self.dispatch_path, self.genesis_bytes, self.policy['genesis_sha256'],
                             self.endpoint, self.policy['trust_expires_utc'], clock=self.clock) as journal:
            yield journal

    def _queued(self, journal, source: dict) -> dict:
        status = journal.status(source['item']['native_txid'])
        require(journal.export(source['item']['native_txid']) == source['raw'],
                'dispatcher bytes differ from the original wallet decision')
        return status

    def _review(self, journal, source: dict, replay: bool) -> dict:
        require(type(replay) is bool, 'replay must be an explicit boolean')
        dispatch = self._queued(journal, source)
        require(not dispatch['receipt_verified'], 'receipt already verified; reconcile instead of resending')
        require((dispatch['status'] == 'queued') != replay,
                'first send and replay are distinct; review the correct operation')
        require(dispatch['attempts'] < MAX_ATTEMPTS, 'existing dispatch retry limit reached')
        body = source['item']['body']
        plan = {'schema': 1, 'kind': '1soft-existing-decision-delivery',
                'decision_id': self.decision_id, 'native_txid': source['item']['native_txid'],
                'wire_sha256': _sha(source['raw']), 'wallet_policy_sha256': self.policy_id,
                'wallet_path_binding': _sha(os.fsencode(str(self.wallet_path))),
                'dispatch_path_binding': _sha(os.fsencode(str(self.dispatch_path))),
                'account': self.account, 'grant_id': self.grant_id,
                'signer_public_key': source['item']['signer'], 'recipient': body['op']['to'],
                'amount_units': body['op']['units'], 'fee_units': self.genesis['fee'],
                'total_debit_units': source['item']['debit'], 'asset': self.genesis['asset'],
                'chain_id': self.trust.chain_id, 'native_genesis_hash': self.trust.native_genesis_hash,
                'valid_until_height': body['valid_until'], 'nonce': body['nonce'],
                'endpoint': self.endpoint, 'operation': 'replay' if replay else 'send',
                'next_attempt': dispatch['attempts'] + 1,
                'dispatch_confirmation': dispatch['dispatch_confirmation'],
                'wallet_header_hash': source['view']['state']['header_hash'],
                'wallet_state_height': source['view']['state']['application_height'],
                'local_inventory_digest': source['inventory_digest'],
                'trust_expires_utc': self.policy['trust_expires_utc']}
        return {**plan, 'confirmation': _sha(DELIVERY_DOMAIN + encode(plan)),
                'status': 'existing-signature-staged-not-sent', 'new_signature_created': False,
                'new_reservation_created': False, 'latest_state_guaranteed': False}

    def review(self, *, replay: bool = False) -> dict:
        """Stage only a previously signed wallet decision; never submit on review."""
        require(type(replay) is bool, 'replay must be an explicit boolean')
        source = self._source(for_send=True)
        self._network_policy(source, require_fresh=True)
        with self._dispatcher(create=not replay) as journal:
            if not replay:
                journal.queue(source['raw'], source['item']['signer'])
            return self._review(journal, source, replay)

    def send(self, confirmation: str, *, replay: bool = False) -> dict:
        """Recheck source and exact reviewed operation, then delegate one attempt.

        No lock is held on the wallet during HTTP. State may change after capture;
        this cannot revoke signed bytes elsewhere or guarantee latest chain state.
        The existing dispatcher commits the attempt before opening a socket.
        """
        _hex(confirmation)
        require(type(replay) is bool, 'replay must be an explicit boolean')
        # No new database is created here. Review is the explicit staging step.
        with self._dispatcher() as journal:
            source = self._source(for_send=True)
            plan = self._review(journal, source, replay)
            require(hmac.compare_digest(confirmation, plan['confirmation']),
                    'delivery context changed or confirmation differs; review again')
            self._network_policy(source, require_fresh=True)
            out = journal.dispatch(source['item']['native_txid'], plan['dispatch_confirmation'], replay=replay)
            return self._combined(source, out)

    def _combined(self, source: dict, dispatch: dict) -> dict:
        """Two records, explicitly not one atomic wallet/network snapshot."""
        return {'schema': 1, 'decision_id': self.decision_id, 'account': self.account,
                'grant_id': self.grant_id, 'native_txid': source['item']['native_txid'],
                'wire_sha256': _sha(source['raw']), 'endpoint': self.endpoint,
                'delivery_status': dispatch['status'], 'attempts': dispatch['attempts'],
                'receipt_verified': dispatch['receipt_verified'],
                'wallet_obligation_status': source['obligation']['status'],
                'wallet_state_height': source['view']['state']['application_height'],
                'wallet_pending_account_units': source['view']['funds']['pending_debit_units'],
                'wallet_policy_blockers': source['view']['observation']['blockers'],
                'wallet_reconciled': source['obligation']['status'] == 'recorded',
                'wallet_and_dispatch_read_atomically': False,
                'new_signature_created': False, 'new_reservation_created': False,
                'latest_state_guaranteed': False, 'live_network_provenance_established': False}

    def status(self) -> dict:
        """Inspect historical wallet/dispatch evidence; never query RPC or sync."""
        source = self._source()
        if not self._dispatch_exists():
            return self._combined(source, {'status': 'not_staged', 'attempts': 0, 'receipt_verified': False})
        with self._dispatcher() as journal:
            if journal.db.execute('SELECT 1 FROM payments WHERE txid=?',
                                  (source['item']['native_txid'],)).fetchone() is None:
                return self._combined(source, {'status': 'not_staged', 'attempts': 0, 'receipt_verified': False})
            return self._combined(source, self._queued(journal, source))

    def refresh(self, *, read_attempts: int = 1) -> dict:
        """Collect a receipt without sending or modifying wallet reservations."""
        from receipt_collector import attempts
        attempts(read_attempts)
        source = self._source()
        self._network_policy(source)
        with self._dispatcher() as journal:
            self._queued(journal, source)
            result = journal.refresh_receipt(source['item']['native_txid'], read_attempts=read_attempts)
            return {**self._combined(source, result), 'collection_status': result['collection_status'],
                    'read_requests': result['read_requests'], 'wallet_sync_performed': False}

    def reconcile(self, *, continuation: list | None = None) -> dict:
        """Explicitly pass the saved receipt state through the existing wallet sync.

        No RPC, broadcast or signing. If ancestry/freshness prevents acceptance,
        preserve verified receipt AND local hold. Use the existing catch-up path
        for long gaps; this method never resets or renews the wallet policy.
        """
        source = self._source()
        self._network_policy(source)
        with self._dispatcher() as journal:
            dispatch = self._queued(journal, source)
            if source['obligation']['status'] == 'recorded':
                return {**self._combined(source, dispatch), 'reconciliation': 'already_recorded',
                        'wallet_sync_performed': False}
            require(dispatch['receipt_verified'], 'no verified receipt to reconcile')
            # A newer catch-up journal must not be advanced by an older wallet
            # implementation that does not own its progress schema. Defer to the
            # installed catch-up path rather than clearing/ignoring that frontier.
            if 'newer_headers_need_state_sync' in source['view']['observation']['blockers']:
                return {**self._combined(source, dispatch),
                        'reconciliation': 'wallet_sync_required', 'wallet_sync_performed': False}
            packet = load_json(journal.export_receipt(source['item']['native_txid']))
            witness = {k: packet[k] for k in ('schema', 'state', 'state_commit')}
            # A receipt may already contain every intermediate signed header
            # needed for a short gap. Use only a complete consecutive selection;
            # the wallet still validates signatures and full predecessor IDs.
            links = continuation
            if links is None:
                start = source['view']['state']['witness_header_height']
                target = int(packet['state_commit']['header']['height'])
                available = {int(t['commit']['header']['height']): t['commit']
                             for t in packet['transactions']}
                if 0 < target - start <= 65 and all(h in available for h in range(start + 1, target)):
                    links = [available[h] for h in range(start + 1, target)]
            wallet = CertifiedWallet(self.wallet_path, self.genesis_bytes, self.policy, clock=self.clock)
            try:
                try:
                    wallet.sync(witness, continuation=links)
                except ValueError:
                    return {**self._combined(source, dispatch),
                            'reconciliation': 'wallet_sync_required', 'wallet_sync_performed': False}
            finally:
                wallet.close()
            updated = self._source()
            require(updated['obligation']['status'] == 'recorded',
                    'post-sync wallet did not retain the exact receipt')
            return {**self._combined(updated, dispatch), 'reconciliation': 'recorded',
                    'wallet_sync_performed': True}

    def export_receipt(self) -> bytes:
        """Historical evidence export; no policy renewal, clock check or network."""
        source = self._source()
        with self._dispatcher() as journal:
            self._queued(journal, source)
            return journal.export_receipt(source['item']['native_txid'])
