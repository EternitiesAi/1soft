"""Submit an existing CertifiedWallet decision through the native dispatcher.

No key access, signing, replacement payment, second spending journal or transport
implementation. All outgoing bytes come from the selected signed wallet decision.
Transport evidence and wallet reconciliation remain separate, recoverable effects.
A trusted local filesystem, clock, static validators and shared wallet are assumed.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import sqlite3
import time
from typing import Callable

from account_view import open_readonly, _policy, _schema, _limits, _project
from block_application import restore
from certified_wallet import CertifiedWallet, MAX_EVIDENCE, nanos
from commit_verifier import encode, load_json
from native_core import FEE_ACCOUNT, Reject, canonical, identifier, require
from payment_rpc import endpoint_port
from payment_transport import DispatchJournal
from wallet_obligations import checked_decision

CONFIRM_DOMAIN = b'1soft/decision-delivery/v1\x00'
DISPATCH_TABLES = {
    'configuration': ('id', 'value', 'clock_ns'),
    'payments': ('txid', 'slot', 'raw', 'signer', 'wire_hash', 'confirmation',
                 'status', 'attempts', 'proof', 'proof_hash'),
    'events': ('id', 'txid', 'event', 'detail'),
}


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _id(value: str) -> str:
    require(type(value) is str and len(value) == 64 and
            all(c in '0123456789abcdef' for c in value), 'invalid wallet decision ID')
    return value


def _selection(account: str, grant_id: str) -> None:
    identifier(account)
    require(account != FEE_ACCOUNT, 'system account cannot submit payments')
    require(type(grant_id) is str, 'explicit grant role must be text')
    if grant_id:
        identifier(grant_id)


def _same_path_or_file(left: Path, right: Path) -> bool:
    if left.resolve(strict=False) == right.resolve(strict=False):
        return True
    return left.exists() and right.exists() and os.path.samefile(left, right)


def _dispatch_file(path: Path, *, create: bool, expected_config: str) -> None:
    """Refuse wrong stores BEFORE the legacy dispatcher can run schema creation."""
    if not path.exists() and not path.is_symlink():
        require(create, 'delivery journal absent; queue explicitly to create it')
        return
    db = open_readonly(path)
    try:
        objects = db.execute("SELECT type,name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        require(all(kind == 'table' and name in DISPATCH_TABLES for kind, name in objects),
                'not a dedicated native dispatch journal; no implicit migration')
        tables = {name for _, name in objects}
        require(tables in (set(), set(DISPATCH_TABLES)), 'partial dispatch schema requires investigation')
        for name in tables:
            actual = tuple(r[1] for r in db.execute('PRAGMA table_info("' + name + '")'))
            require(actual == DISPATCH_TABLES[name], 'dispatch journal columns differ')
        if tables:
            row = db.execute('SELECT value FROM configuration WHERE id=1').fetchone()
            require(row is not None and type(row[0]) is str and row[0] == expected_config,
                    'dispatch configuration is missing or differs')
        else:
            require(create, 'empty delivery journal; queue explicitly to initialize it')
    finally:
        db.close()


class DecisionDelivery:
    """One explicit local session. No loops or automatic send/replay/sync.

    SQLite read snapshots protect each wallet inspection; the existing dispatcher
    lock excludes a second dispatcher using its store. There is intentionally no
    cross-database atomicity or wallet lock held during a network request. Native
    execution must still reject stale counters/permissions. Other workspaces,
    raw signed exports and copied journals remain outside local coordination.
    """
    def __init__(self, wallet_journal: Path, delivery_journal: Path,
                 genesis_bytes: bytes, policy: dict, endpoint: str, *,
                 create: bool = False, clock: Callable[[], int] = time.time_ns):
        require(type(create) is bool, 'create must be an explicit boolean')
        endpoint_port(endpoint)
        self.wallet_path = Path(os.path.abspath(wallet_journal))
        self.delivery_path = Path(os.path.abspath(delivery_journal))
        require(self.wallet_path != self.delivery_path, 'wallet and delivery journals must be different')
        sidecars = (Path(str(self.wallet_path) + suffix) for suffix in ('-wal', '-shm', '-journal'))
        require(not any(_same_path_or_file(self.delivery_path, sidecar) for sidecar in sidecars),
                'delivery journal cannot alias a wallet SQLite sidecar')
        if self.wallet_path.exists() and self.delivery_path.exists():
            require(not os.path.samefile(self.wallet_path, self.delivery_path),
                    'wallet and delivery journals refer to the same file')
        require(type(genesis_bytes) is bytes and len(genesis_bytes) <= 1024*1024,
                'bounded native genesis bytes required')
        self.genesis_bytes = genesis_bytes
        self.policy = load_json(encode(policy), max_bytes=16384)
        self.trust, self.policy_id, _ = _policy(self.genesis_bytes, self.policy)
        self.genesis = load_json(self.genesis_bytes, max_bytes=1024*1024)['app_state']
        self.clock = clock
        # An existing supported wallet is mandatory even for first-time queueing.
        db = open_readonly(self.wallet_path)
        try:
            db.execute('BEGIN'); _limits(db, _schema(db))
            checkpoint = db.execute('SELECT policy_id FROM checkpoint WHERE id=1').fetchone()
            require(checkpoint is not None and checkpoint[0] == self.policy_id, 'source wallet policy differs')
        finally:
            if db.in_transaction: db.execute('ROLLBACK')
            db.close()
        dispatch_config = encode({'schema': 1, 'genesis_sha256': self.policy['genesis_sha256'],
                                  'endpoint': endpoint,
                                  'trust_expires_utc': self.policy['trust_expires_utc']}).decode()
        _dispatch_file(self.delivery_path, create=create, expected_config=dispatch_config)
        self.dispatch = DispatchJournal(self.delivery_path, self.genesis_bytes,
            self.policy['genesis_sha256'], endpoint, self.policy['trust_expires_utc'], clock=clock)
        # Path binding is local routing consent, not an uncopyable wallet identity.
        self.route = {'schema': 1, 'source_policy_sha256': self.policy_id,
                      'source_location_sha256': _hash(os.fsencode(self.wallet_path)),
                      'delivery_location_sha256': _hash(os.fsencode(self.delivery_path)),
                      'dispatch_policy': self.dispatch.config}

    def close(self) -> None:
        self.dispatch.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    @contextmanager
    def _source(self, decision_id: str, account: str, grant_id: str, *, fresh: bool = False):
        """Read the EXACT selected decision, never a truncated report's lookup."""
        _id(decision_id); _selection(account, grant_id)
        db = open_readonly(self.wallet_path)
        try:
            db.execute('BEGIN'); _limits(db, _schema(db))
            checkpoint = db.execute('SELECT policy_id FROM checkpoint WHERE id=1').fetchone()
            require(checkpoint is not None and checkpoint[0] == self.policy_id, 'source wallet policy differs')
            row = db.execute('SELECT id,slot,review,result,result_hash FROM decisions WHERE id=?',
                             (decision_id,)).fetchone()
            require(row is not None, 'recorded signing decision required; no arbitrary envelope import')
            item = checked_decision(row, self.genesis, self.policy_id)
            body = item['body']
            require(item['mode'] == 'sign' and body['op']['type'] == 'transfer',
                    'only a recorded outgoing native transfer can be delivered')
            require(body['sender'] == account and body['grant_id'] == grant_id,
                    'wallet decision does not match explicit payer and grant role')
            # Full snapshot + ALL local obligations are verified inside this same
            # transaction. The one-item display limit is never used for selection.
            now = self.clock()
            require(type(now) is int and 0 <= now <= 2**63-1, 'invalid delivery clock')
            view = _project(db, self.genesis_bytes, self.policy, account, now, 1)
            saved = db.execute('SELECT witness FROM wallet_evidence WHERE id=1').fetchone()
            witness = load_json(saved[0].encode(), max_bytes=MAX_EVIDENCE)
            ledger = restore(witness['state']['genesis'], witness['state']['native'])
            try:
                height = witness['state']['height']
                recorded_row = ledger.db.execute(
                    'SELECT txid,sequence,previous,record,hash FROM receipts WHERE txid=?',
                    (item['native_txid'],)).fetchone()
                recorded = recorded_row is not None
                status = 'recorded' if recorded else ('expired_absent' if height > body['valid_until'] else 'pending')
                if fresh:
                    require(view['observation']['within_local_time_and_frontier_policy'],
                            'wallet evidence is outside local time/frontier policy; sync before sending')
                    require(status == 'pending', 'decision is already recorded or expired; no send')
                    # Rechecks the already-recorded signature at this checkpoint,
                    # but spends ONLY in a disposable validation copy. No unlock.
                    ledger.apply(item['result'], height=height + 1)
                    after = self.clock()
                    require(type(after) is int and now <= after <= 2**63-1,
                            'delivery clock moved backwards during verification')
                    require(after < nanos(self.policy['trust_expires_utc']) and
                            after - nanos(witness['state_commit']['header']['time']) <=
                            self.policy['maximum_age_seconds'] * 10**9,
                            'wallet evidence expired during delivery verification')
                selected = {**item, 'wire': canonical(item['result']),
                            'wallet_status': status, 'view': view,
                            'wallet_receipt_row': None if recorded_row is None else list(recorded_row)}
            finally:
                ledger.close()
            db.execute('ROLLBACK')
            yield selected
        finally:
            if db.in_transaction: db.execute('ROLLBACK')
            db.close()

    def _transport(self, selected: dict) -> dict | None:
        exists = self.dispatch.db.execute('SELECT 1 FROM payments WHERE txid=?',
                                          (selected['native_txid'],)).fetchone()
        if exists is None:
            return None
        report = self.dispatch.status(selected['native_txid'])
        require(self.dispatch.export(selected['native_txid']) == selected['wire'],
                'transport bytes differ from selected wallet signature')
        return report

    def _confirmation(self, selected: dict, transport: dict) -> str:
        return _hash(CONFIRM_DOMAIN + encode({'route': self.route,
            'decision_id': selected['decision_id'], 'account': selected['body']['sender'],
            'grant_id': selected['body']['grant_id'], 'native_txid': selected['native_txid'],
            'wire_sha256': _hash(selected['wire']),
            'dispatch_confirmation': transport['dispatch_confirmation']}))

    def _report(self, selected: dict, transport: dict | None) -> dict:
        verified = transport is not None and transport['receipt_verified']
        return {'schema': 1, 'decision_id': selected['decision_id'],
            'native_txid': selected['native_txid'], 'wire_sha256': _hash(selected['wire']),
            'account': selected['body']['sender'], 'grant_id': selected['body']['grant_id'],
            'recipient': selected['body']['op']['to'], 'amount_units': selected['body']['op']['units'],
            'wallet_obligation_status': selected['wallet_status'],
            'wallet_state_height': selected['view']['state']['application_height'],
            'wallet_time_frontier_blockers': selected['view']['observation']['blockers'],
            'transport_status': 'not_queued' if transport is None else transport['status'],
            'submission_attempts': 0 if transport is None else transport['attempts'],
            'exact_transport_receipt_verified': verified,
            'wallet_reconciliation_needed': verified and selected['wallet_status'] != 'recorded',
            'delivery_confirmation': None if transport is None else self._confirmation(selected, transport),
            'signing_performed': False, 'latest_state_guaranteed': False,
            'scope': 'selected wallet decision and one local dispatch journal; not global idempotency'}

    def queue(self, decision_id: str, *, account: str, grant_id: str = '') -> dict:
        with self._source(decision_id, account, grant_id, fresh=True) as selected:
            self.dispatch.queue(selected['wire'], selected['signer'])
            return self._report(selected, self._transport(selected))

    def status(self, decision_id: str, *, account: str, grant_id: str = '') -> dict:
        with self._source(decision_id, account, grant_id) as selected:
            return self._report(selected, self._transport(selected))

    def send(self, decision_id: str, confirmation: str, *, account: str,
             grant_id: str = '', replay: bool = False) -> dict:
        with self._source(decision_id, account, grant_id, fresh=True) as selected:
            transport = self._transport(selected)
            require(transport is not None, 'queue the selected decision before sending')
            require(type(confirmation) is str and confirmation == self._confirmation(selected, transport),
                    'exact decision/role/route confirmation required')
            self.dispatch.dispatch(selected['native_txid'], transport['dispatch_confirmation'], replay=replay)
        # Re-read the wallet because another process may have synced during HTTP.
        return self.status(decision_id, account=account, grant_id=grant_id)

    def refresh(self, decision_id: str, *, account: str, grant_id: str = '',
                read_attempts: int = 1) -> dict:
        with self._source(decision_id, account, grant_id) as selected:
            require(self._transport(selected) is not None, 'queued decision required for receipt refresh')
            result = self.dispatch.refresh_receipt(selected['native_txid'], read_attempts=read_attempts)
        # No writer for the financial wallet: collection never retires its hold.
        return {**self.status(decision_id, account=account, grant_id=grant_id),
                'collection_status': result['collection_status'], 'read_requests': result['read_requests'],
                'wallet_sync_performed': False}

    def _recorded_confirmation(self, selected: dict, packet: dict) -> dict | None:
        """Confirm an existing recording, not permission to import another state.

        Both sources have already been independently reverified: the wallet's
        full snapshot/obligations and the dispatcher's exact transaction proof.
        Matching a txid alone is insufficient. The complete immutable receipt
        row (including execution height, sequence and state hash) must agree.
        This is a historical observation; it does not refresh policy or ancestry.
        """
        if selected['wallet_status'] != 'recorded':
            return None
        rows = [row for row in packet['state']['native']['receipts']
                if row[0] == selected['native_txid']]
        require(len(rows) == 1 and encode(rows[0]) == encode(selected['wallet_receipt_row']),
                'collected receipt conflicts with the wallet execution record')
        return {**self._report(selected, self._transport(selected)),
                'reconciliation_outcome': 'already_recorded',
                'wallet_sync_performed': False, 'network_requested': False,
                'receipt_state_height': packet['state']['height'],
                'state_witness_imported': False}

    def reconcile(self, decision_id: str, *, account: str, grant_id: str = '',
                  continuation: list | None = None) -> dict:
        """Reconcile once, or verify that this exact receipt is already recorded.

        An older/duplicate receipt never rolls the wallet back. Receipt proof is
        still mandatory even for an already-recorded payment. A no-op neither
        imports the supplied checkpoint/continuation nor refreshes permission.
        Pending payments use the unchanged fresh, ancestry-checked wallet sync.
        """
        with self._source(decision_id, account, grant_id) as selected:
            require(self._transport(selected) is not None, 'queued decision required')
            packet = load_json(self.dispatch.export_receipt(selected['native_txid']))
            already = self._recorded_confirmation(selected, packet)
            if already is not None:
                return already
        witness = {'schema': 1, 'state': packet['state'], 'state_commit': packet['state_commit']}
        wallet = CertifiedWallet(self.wallet_path, self.genesis_bytes, self.policy, clock=self.clock)
        try:
            try:
                wallet.sync(witness, continuation=continuation)
            except Reject:
                # Another wallet connection may have recorded this payment after
                # the first read. Recheck ONCE, without retrying sync or ignoring
                # missing/conflicting evidence. SQLite/I/O faults still propagate.
                with self._source(decision_id, account, grant_id) as current:
                    already = self._recorded_confirmation(current, packet)
                    if already is not None:
                        return already
                raise
        finally:
            wallet.close()
        return {**self.status(decision_id, account=account, grant_id=grant_id),
                'reconciliation_outcome': 'state_synchronized',
                'wallet_sync_performed': True, 'network_requested': False,
                'receipt_state_height': packet['state']['height'],
                'state_witness_imported': True}

    def export_receipt(self, decision_id: str, *, account: str, grant_id: str = '') -> bytes:
        with self._source(decision_id, account, grant_id) as selected:
            require(self._transport(selected) is not None, 'queued decision required')
            return self.dispatch.export_receipt(selected['native_txid'])
