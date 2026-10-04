"""Authenticated receipt classification and replay-safe local audit evidence.

The standalone journal is not a wallet reservation or release authority. Wallet
callers own authentication, local-signature validation and their hold transaction.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from compact_verifier import verify_compact_witness
from commit_verifier import (MAX_TX_BYTES, encode, ensure, load_json, sha,
                             verify_native_signatures)
from native_core import DOMAIN, canonical, pubkey
from wallet_obligations import classify_authenticated_receipt


def _txid(wire: bytes, trust: Any) -> tuple[str, dict]:
    ensure(type(wire) is bytes, 'wire must be bytes')
    envelope = load_json(wire, max_bytes=MAX_TX_BYTES)
    ensure(type(envelope) is dict and set(envelope) == {'body', 'signature'} and
           canonical(envelope) == wire, 'invalid or noncanonical native wire')
    body = envelope['body']
    ensure(type(body) is dict and body.get('chain_id') == trust.chain_id and
           body.get('genesis_hash') == trust.native_genesis_hash,
           'wire belongs to another chain')
    return sha(DOMAIN + canonical(body)).hex(), envelope


def _journal(conn: sqlite3.Connection) -> None:
    """Create or validate the audit schema inside the active audit transaction."""
    conn.execute('CREATE TABLE IF NOT EXISTS authenticated_reconciliations ('
                 'txid TEXT PRIMARY KEY, status TEXT NOT NULL, state_height INTEGER NOT NULL, '
                 'checkpoint_hash TEXT NOT NULL, evidence_hash TEXT NOT NULL)')
    columns = [tuple(row) for row in conn.execute('PRAGMA table_info(authenticated_reconciliations)')]
    expected = [
        (0, 'txid', 'TEXT', 0, None, 1),
        (1, 'status', 'TEXT', 1, None, 0),
        (2, 'state_height', 'INTEGER', 1, None, 0),
        (3, 'checkpoint_hash', 'TEXT', 1, None, 0),
        (4, 'evidence_hash', 'TEXT', 1, None, 0),
    ]
    ensure(columns == expected, 'incompatible authenticated reconciliation journal schema')


def reconcile_obligation(witness: dict, signed_header: dict, trust: Any, *,
                         local_wire: bytes, expected_signer: str,
                         journal: sqlite3.Connection) -> dict:
    """Record authenticated audit evidence atomically, without changing wallet holds.

    Exact checkpoint replay is idempotent. A different durable result, including
    a newer checkpoint for the same wire, requires separate policy and is refused.
    """
    ensure(not journal.in_transaction, 'journal connection already in transaction')
    pubkey(expected_signer)
    txid, envelope = _txid(local_wire, trust)
    verified = verify_compact_witness(
        witness, signed_header, trust, expected_queries=[('receipts', txid)])
    verify_native_signatures(
        envelope, expected_signer, protocol_version=witness['genesis']['protocol_version'])
    height = verified['state_height']
    status = classify_authenticated_receipt(
        verified['records'][0]['row'], local_envelope=envelope,
        expected_signer=expected_signer, state_height=height)
    ensure(status != 'pending', 'authenticated checkpoint is not past validity')
    evidence = {'txid': txid, 'status': status, 'state_height': height,
                'checkpoint_hash': verified['header_hash']}
    evidence_hash = sha(encode(evidence)).hex()
    expected = (txid, status, height, verified['header_hash'], evidence_hash)
    try:
        journal.execute('BEGIN IMMEDIATE')
        _journal(journal)
        existing = journal.execute(
            'SELECT txid,status,state_height,checkpoint_hash,evidence_hash '
            'FROM authenticated_reconciliations WHERE txid=?', (txid,)).fetchone()
        replayed = existing is not None
        if replayed:
            ensure(tuple(existing) == expected, 'reconciliation conflicts with durable result')
        else:
            journal.execute('INSERT INTO authenticated_reconciliations '
                            '(txid,status,state_height,checkpoint_hash,evidence_hash) '
                            'VALUES (?,?,?,?,?)', expected)
        # Close the explicit transaction even when Python autocommit=True.
        journal.execute('COMMIT')
        return {**evidence, 'recorded': True, 'replayed': replayed}
    except BaseException:
        if journal.in_transaction:
            journal.execute('ROLLBACK')
        raise
