"""Read-only verification of selected state records and native receipt proofs.

Uses the existing pinned static-validator verifier; never trusts an RPC-supplied
validator list. A commitment authenticates records at a historical height, not
freshness, valid behavior by a dishonest quorum, operator independence or money
outside this chain. This module does not unlock, sign, submit or cancel payments.
"""
from __future__ import annotations

import json

from commit_verifier import (encode, exact, ensure, load_json, sha,
    verify_signed_header, verify_block_transactions, verify_native_signatures, MAX_TX_BYTES)
from native_core import DOMAIN, canonical, identifier, integer, pubkey
from offline_signer import review_intent
from state_tree import (COLUMNS, MODE, MAX_QUERIES, MAX_WITNESS_BYTES,
                        bind_root, enabled, selector, unhex, verify_proof)


def verify_compact_witness(witness: dict, signed_header: dict, trust, *, expected_queries: list) -> dict:
    """Require an exact caller-selected query set, including absence claims."""
    ensure(len(encode(witness)) <= MAX_WITNESS_BYTES, 'compact witness too large')
    exact(witness, {'schema','commitment','genesis','height','root','app_hash','entries'}, 'compact witness')
    ensure(type(witness['schema']) is int and witness['schema'] == 1 and
           witness['commitment'] == MODE, 'unknown compact witness version')
    ensure(enabled(witness['genesis']), 'SMT not pinned by genesis')
    genesis_hash = sha(encode(witness['genesis'])).hex()
    ensure(genesis_hash == trust.native_genesis_hash and
           witness['genesis']['chain_id'] == trust.chain_id, 'compact genesis mismatch')
    height = witness['height']
    root = unhex(witness['root'])
    app_hash = bind_root(genesis_hash, height, root)
    ensure(witness['app_hash'] == app_hash, 'compact application hash mismatch')
    cert = verify_signed_header(signed_header, trust, expected_height=height + 1)
    ensure(cert['app_hash'] == app_hash, 'root not anchored by the next signed header')
    ensure(type(expected_queries) is list and 1 <= len(expected_queries) <= MAX_QUERIES,
           'explicit nonempty query set required')
    queries = []
    for item in expected_queries:
        ensure(type(item) in (list, tuple) and len(item) == 2, 'invalid expected query')
        queries.append(selector(*item))
    ensure(len(set(queries)) == len(queries), 'duplicate expected query')
    entries = witness['entries']
    ensure(type(entries) is list and len(entries) == len(queries), 'incomplete or extra proof entries')
    index = {}
    for entry in entries:
        ensure(type(entry) is dict, 'invalid proof entry')
        key = selector(entry.get('table'), entry.get('key'))
        ensure(key not in index, 'duplicate proof entry')
        index[key] = entry
    ensure(set(index) == set(queries), 'proof set differs from the caller request')
    records = []
    for table, key in queries:
        row = verify_proof(root, table, key, index[(table, key)])
        records.append({'table':table, 'key':key, 'exists':row is not None, 'row':row})
    return {'status':'verified', 'state_height':height, 'header_height':cert['height'],
        'state_app_hash':app_hash, 'header_hash':cert['block_hash'],
        'root':root.hex(), 'signed_power':cert['signed_power'], 'total_power':cert['total_power'],
        'records':records, 'scope':'selected records under pinned static-validator trust',
        'latest_state_guaranteed':False, 'live_network_provenance_established':False,
        'proof_format':'1soft-smt-v1; not ICS23/IBC', 'whole_ledger_downloaded':False}


def _index(result: dict) -> dict:
    return {(r['table'], r['key']):r['row'] for r in result['records']}


def _present(records: dict, table: str, key: str) -> dict:
    row = records[(table, key)]
    ensure(row is not None, 'required record is absent at the witnessed height')
    return dict(zip(COLUMNS[table], row))


def _allowlist(raw: str) -> list[str]:
    values = load_json(raw.encode(), max_bytes=16_384)
    ensure(type(values) is list and 1 <= len(values) <= 64, 'invalid witnessed recipients')
    for value in values:
        identifier(value)
    ensure(len(set(values)) == len(values), 'duplicate witnessed recipient')
    return values


def review_compact_transfer(witness: dict, signed_header: dict, trust, body: dict, signer: str) -> dict:
    """Historical transfer preflight only, never a signature approval or freshness check.

    An agent transfer needs six rows: owner, recipient, native clock, grant,
    grant-to-budget link, and budget. The server may hint the parent budget ID,
    but that link and every row are proven under the SAME authenticated root.
    Aggregate invariants are enforced by the chain, not reexecuted by this client.
    """
    base = review_intent(witness['genesis'], body, signer)
    body = base['body']
    ensure(body['op']['type'] == 'transfer', 'compact preflight supports transfers only')
    sender, recipient = body['sender'], body['op']['to']
    queries = [('accounts',sender), ('accounts',recipient), ('meta','height')]
    grant_id = body['grant_id']
    budget_key = None
    if grant_id:
        grant_key = sender + '::' + grant_id  # compact mode is explicitly protocol 3
        entries = witness.get('entries')
        ensure(type(entries) is list, 'invalid compact entries')
        links = [p.get('value') for p in entries if type(p) is dict and
                 p.get('table') == 'grant_budgets' and p.get('key') == grant_key]
        ensure(len(links) == 1 and type(links[0]) is list and len(links[0]) == 2,
               'missing grant budget lookup hint')
        budget_key = links[0][1]
        selector('budgets', budget_key)
        queries += [('grants',grant_key), ('grant_budgets',grant_key), ('budgets',budget_key)]
    verified = verify_compact_witness(witness, signed_header, trust, expected_queries=queries)
    rows = _index(verified)
    owner = _present(rows, 'accounts', sender)
    receiving = _present(rows, 'accounts', recipient)
    for account in (owner, receiving):
        pubkey(account['public_key'])
        for field in ('nonce','epoch','balance'):
            integer(account[field])
    clock = _present(rows, 'meta', 'height')['v']
    ensure(type(clock) is str and clock.isascii() and clock.isdecimal() and
           str(int(clock)) == clock and int(clock) <= verified['state_height'], 'invalid witnessed native clock')
    at_height = verified['state_height'] + 1
    ensure(body['valid_until'] >= at_height, 'payment expired at authenticated snapshot')
    required = base['proposed_account_debit_units']
    ensure(owner['balance'] >= required, 'insufficient authenticated account balance')
    grant = budget = None
    if grant_id:
        grant = _present(rows, 'grants', grant_key)
        link = _present(rows, 'grant_budgets', grant_key)
        budget = _present(rows, 'budgets', budget_key)
        ensure(link['budget_id'] == budget['id'], 'budget link mismatch')
        for item in (grant, budget):
            for field in ('epoch','cap','spent','expires','revoked'):
                integer(item[field])
            ensure(item['owner'] == sender and item['epoch'] == owner['epoch'] and
                   item['revoked'] == 0 and item['expires'] >= at_height, 'inactive authenticated permission')
            ensure(item['spent'] + required <= item['cap'], 'authenticated agent or shared budget exceeded')
            ensure(recipient in _allowlist(item['recipients']), 'recipient outside authenticated permission')
        integer(grant['nonce']); pubkey(grant['public_key'])
        ensure(grant['cap'] <= budget['cap'] and grant['expires'] <= budget['expires'] and
               set(_allowlist(grant['recipients'])) <= set(_allowlist(budget['recipients'])),
               'grant exceeds its authenticated parent budget')
    authority = grant if grant is not None else owner
    ensure(authority['public_key'] == signer and authority['nonce'] == body['nonce'],
           'signer or nonce differs from authenticated authority')
    return {'status':'eligible-at-witnessed-height', 'state_height':verified['state_height'],
        'state_app_hash':verified['state_app_hash'], 'account_balance_units':owner['balance'],
        'required_units_including_fee':required,
        'grant_remaining_units':None if grant is None else grant['cap']-grant['spent'],
        'shared_budget_remaining_units':None if budget is None else budget['cap']-budget['spent'],
        'record_count':len(queries), 'authority_at_snapshot_verified':True,
        'latest_state_guaranteed':False, 'signed':False, 'broadcast':False,
        'warning':'Historical permission check only; apply a freshness/checkpoint policy before signing.'}


def verify_compact_receipt(witness: dict, signed_header: dict, trust, *,
                           expected_transaction: bytes, block: dict, commit: dict) -> dict:
    """Bind exact caller-supplied signed bytes to inclusion AND an execution record."""
    envelope = load_json(expected_transaction, max_bytes=MAX_TX_BYTES)
    exact(envelope, {'body','signature'}, 'native envelope')
    ensure(canonical(envelope) == expected_transaction, 'noncanonical requested transaction')
    body = envelope['body']
    ensure(type(body) is dict and body.get('chain_id') == trust.chain_id and
           body.get('genesis_hash') == trust.native_genesis_hash, 'transaction belongs to another genesis')
    txid = sha(DOMAIN + canonical(body)).hex()
    state = verify_compact_witness(witness, signed_header, trust,
                                   expected_queries=[('receipts',txid)])
    row = state['records'][0]['row']
    ensure(row is not None, 'no execution receipt at the authenticated height')
    included = verify_block_transactions(block, commit, trust, expected_tx=expected_transaction)
    ensure(included['height'] <= state['state_height'], 'transaction later than witnessed state')
    record = load_json(row[3].encode(), max_bytes=MAX_TX_BYTES)
    ensure(type(record) is dict and record.get('txid') == txid and record.get('envelope') == envelope,
           'receipt differs from exact requested transaction')
    ensure(type(record.get('height')) is int and record['height'] == included['height'],
           'receipt/block height mismatch')
    ensure(sha(encode(record)).hex() == row[4], 'receipt record digest mismatch')
    verify_native_signatures(envelope, record.get('signer_public_key'),
                             protocol_version=witness['genesis']['protocol_version'])
    return {'status':'verified', 'native_txid':txid, 'wire_sha256':sha(expected_transaction).hex(),
        'block_height':included['height'], 'state_height':state['state_height'],
        'scope':'exact included transaction and committed execution receipt',
        'whole_ledger_downloaded':False, 'latest_state_guaranteed':False,
        'live_network_provenance_established':False, 'external_settlement_verified':False}
