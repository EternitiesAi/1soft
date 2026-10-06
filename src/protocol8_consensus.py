"""Finite P8 recipient consensus state and deterministic ordered execution.

Bootstrap identity is acyclic; the complete externally pinned genesis is bound
separately by AppHash. This module does not migrate any earlier protocol.
"""
from __future__ import annotations
import copy
import hashlib
import re
from protocol5_encoding import decode_canonical_json, comet_validator_set, EncodingError
import protocol8_transfer as native

StateError = native.Invalid
Unavailable = native.Unavailable
class CapacityError(StateError): pass
need = native.need
canonical = native.canonical
digest = native.sha
PROFILE_SHA256 = native.PROFILE_SHA256
MAX_HEIGHT = 64
MAX_HISTORY = 32
MAX_TX_BYTES = 4096
MAX_STATE_BYTES = 524288
GENESIS_FORMAT = '1soft/protocol8-recipient-consensus/genesis/v1'
STATE_FORMAT = '1soft/protocol8-recipient-consensus/state/v1'
BOOTSTRAP_DOMAIN = b'1soft/protocol8-recipient-consensus/bootstrap/v1\0'
APPHASH_DOMAIN = b'1soft/protocol8-recipient-consensus/apphash/v1\0'
GENESIS_KEYS = {'format', 'protocol_version', 'chain_id', 'profile_sha256',
                'worker_sha256', 'kat_sha256', 'validators', 'pool_id',
                'asset', 'mission', 'fee', 'network', 'notes'}
LOGS = {0:'', 1:'malformed P8 recipient transaction', 2:'P8 context differs',
        3:'P8 execution window differs', 4:'P8 note anchor differs',
        5:'P8 consumed note, intent or output', 6:'invalid P8 recipient proof',
        7:'P8 development capacity exceeded'}

def hex32(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None,
         'P8 canonical digest')
    return bytes.fromhex(value)

def closed_json(raw, bound):
    try: return decode_canonical_json(raw, max_bytes=bound)
    except EncodingError as e: raise StateError('P8 canonical JSON required') from e

def genesis_shape(raw):
    g = closed_json(raw, 16384)
    need(type(g) is dict and set(g) == GENESIS_KEYS, 'closed P8 genesis')
    need(g['format'] == GENESIS_FORMAT and type(g['protocol_version']) is int and
         g['protocol_version'] == 8, 'fresh P8 genesis required')
    need(type(g['chain_id']) is str and re.fullmatch('[a-zA-Z0-9_-]{1,50}', g['chain_id'])
         is not None, 'P8 chain identity')
    need(g['profile_sha256'] == PROFILE_SHA256, 'P8 frozen native profile differs')
    for key in ('worker_sha256', 'kat_sha256', 'pool_id'):
        hex32(g[key]); need(g[key] != native.ZERO, 'P8 nonzero digest')
    for key in ('network', 'asset', 'mission'):
        native.field(g[key]); need(g[key] != native.ZERO, 'P8 nonzero context')
    native.u64(g['fee']); need(g['fee'] > 0, 'P8 positive fee')
    notes = g['notes']
    need(type(notes) is list and 1 <= len(notes) <= 16, 'P8 bounded initial notes')
    for note in notes:
        need(type(note) is dict and set(note) == {'kind', 'commitment'} and
             note['kind'] == 'p8-recipient-v1', 'typed P8 genesis note')
        native.field(note['commitment']); need(note['commitment'] != native.ZERO,
                                              'P8 nonzero initial note')
    need(len({n['commitment'] for n in notes}) == len(notes), 'P8 duplicate initial note')
    vals = g['validators']
    need(type(vals) is list and len(vals) == 4, 'four P8 validators required')
    for row in vals:
        need(type(row) is dict and set(row) == {'public_key', 'power'}, 'P8 validator shape')
        hex32(row['public_key']); need(row['public_key'] != native.ZERO and
             type(row['power']) is int and 1 <= row['power'] <= 1000000, 'P8 validator entry')
    keys = [r['public_key'] for r in vals]
    need(keys == sorted(keys) and len(set(keys)) == 4 and
         len({r['power'] for r in vals}) == 1, 'P8 immutable equal-power roster')
    comet_validator_set(vals)
    return g

def bootstrap_core(g):
    # Notes/network/KAT depend on this core; exact full genesis remains externally
    # pinned and is included in every AppHash. A fresh pool_id separates issuance.
    return {'format':'1soft/protocol8-recipient-consensus/bootstrap/v1',
            **{k:g[k] for k in ('protocol_version', 'chain_id', 'validators',
                               'profile_sha256', 'worker_sha256', 'pool_id',
                               'asset', 'mission', 'fee')}}

def bootstrap_digest(g): return digest(BOOTSTRAP_DOMAIN + canonical(bootstrap_core(g)))

def genesis_document(raw, worker):
    g = genesis_shape(raw)
    from protocol8_worker import Worker
    need(isinstance(worker, Worker) and worker.sha256 == g['worker_sha256'] and
         worker.kat_sha256 == g['kat_sha256'], 'P8 actual worker/genesis pins differ')
    worker.guard()
    network = worker.network_domain(bytes.fromhex(bootstrap_digest(g)))
    need(g['network'] == network and worker.kat_statement[1] == network,
         'P8 acyclic proof network differs')
    need(worker.kat_statement[2] == g['asset'] and worker.kat_statement[3] == g['mission'] and
         native.integer(worker.kat_statement[9]) == g['fee'] and
         worker.kat_statement[4] == worker.root([n['commitment'] for n in g['notes']]),
         'P8 known-answer initial context differs')
    return g

def initial_state(g, worker):
    genesis_document(canonical(g), worker)
    ledger = native.initial_state(network=g['network'], asset=g['asset'], mission=g['mission'],
                                  fee=g['fee'], notes=g['notes'], worker=worker)
    return {'format':STATE_FORMAT, 'version':8, 'ledger':ledger, 'blocks':[]}

def result(code, data=''): return {'code':code, 'log':LOGS[code], 'data':data}

def _payment(g, ledger, raw, height, worker):
    try: p = native.parse(raw)
    except StateError: return ledger, result(1)
    if (p[1], p[2], p[3]) != (g['network'], g['asset'], g['mission']):
        return ledger, result(2)
    if not native.integer(p[7]) <= height < native.integer(p[8]):
        return ledger, result(3)
    if native.integer(p[9]) != g['fee']: return ledger, result(2)
    if p[4] not in ledger['anchors']: return ledger, result(4)
    notes = [n['commitment'] for n in ledger['notes']]
    if (p[5] in ledger['nullifiers'] or p[6] in ledger['requests'] or
            p[10] in notes or p[11] in notes): return ledger, result(5)
    if len(notes) + 2 > 16 or ledger['fees'] + g['fee'] > native.MAX:
        return ledger, result(7)
    if not worker.verify(raw, g['network']): return ledger, result(6)
    # Prefix authority is supplied only by replayed application state. Public
    # execute_block() below replays any externally supplied state first.
    successor = native._apply(ledger, raw, height, worker)
    return successor, result(0, native.txid(raw))

def _execute(g, state, txs, height, worker):
    # Internal transition only: callers provide a prefix authenticated by replay.
    need(type(state) is dict and set(state) == {'format', 'version', 'ledger', 'blocks'} and
         state['format'] == STATE_FORMAT and type(state['version']) is int and
         state['version'] == 8 and type(state['blocks']) is list, 'P8 state shape')
    need(type(height) is int and height == len(state['blocks']) + 1 and
         1 <= height <= MAX_HEIGHT, 'P8 sequential execution height')
    need(type(txs) is list and len(txs) <= 2 and all(type(r) is bytes and
         len(r) <= MAX_TX_BYTES for r in txs), 'P8 block container')
    need(all(type(b) is dict and set(b) == {'height', 'transactions', 'results'} and
             type(b['transactions']) is list for b in state['blocks']), 'P8 prefix shape')
    if sum(len(b['transactions']) for b in state['blocks']) + len(txs) > MAX_HISTORY:
        raise CapacityError('P8 retained transaction capacity')
    s = copy.deepcopy(state)
    native.shape(s['ledger'], worker)
    need((s['ledger']['network'], s['ledger']['asset'], s['ledger']['mission'], s['ledger']['fee']) ==
         (g['network'], g['asset'], g['mission'], g['fee']), 'P8 state context differs')
    results = []
    for raw in txs:
        s['ledger'], value = _payment(g, s['ledger'], raw, height, worker)
        results.append(value)
    s['blocks'].append({'height':height, 'transactions':[r.hex() for r in txs], 'results':results})
    if len(canonical(s)) > MAX_STATE_BYTES: raise CapacityError('P8 state byte capacity')
    return s, results

def replay(g, state, height, worker):
    genesis_document(canonical(g), worker)
    need(type(state) is dict and set(state) == {'format', 'version', 'ledger', 'blocks'} and
         type(state['blocks']) is list and type(height) is int and
         0 <= height <= MAX_HEIGHT and len(state['blocks']) == height, 'P8 replay height/shape')
    actual = initial_state(g, worker)
    for h, b in enumerate(state['blocks'], 1):
        need(type(b) is dict and set(b) == {'height', 'transactions', 'results'} and
             type(b['height']) is int and b['height'] == h and
             type(b['transactions']) is list and len(b['transactions']) <= 2,
             'P8 replay block shape')
        txs = []
        for raw in b['transactions']:
            need(type(raw) is str and len(raw) <= MAX_TX_BYTES * 2 and len(raw) % 2 == 0 and
                 re.fullmatch('[0-9a-f]*', raw) is not None, 'canonical P8 retained wire')
            txs.append(bytes.fromhex(raw))
        actual, _ = _execute(g, actual, txs, h, worker)
    need(canonical(actual) == canonical(state), 'P8 replayed state/history differs')
    return actual

def execute_block(g, state, txs, height, worker):
    need(type(state) is dict and set(state) == {'format', 'version', 'ledger', 'blocks'} and
         type(state['blocks']) is list, 'P8 execution state shape')
    replay(g, state, len(state['blocks']), worker)
    return _execute(g, state, txs, height, worker)

def application_hash(g, height, state):
    need(type(height) is int and 0 <= height <= MAX_HEIGHT and
         len(canonical(state)) <= MAX_STATE_BYTES, 'P8 AppHash bound')
    return digest(APPHASH_DOMAIN + canonical({'genesis_sha256':digest(canonical(g)),
                                              'height':height, 'state':state}))
