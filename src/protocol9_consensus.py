"""Fresh consensus identity for segmented, frozen relation-8 recipient proofs."""
import re
import protocol8_transfer as n
from protocol5_encoding import decode_canonical_json, comet_validator_set, EncodingError
from protocol8_worker import Worker

GENESIS_FORMAT = '1soft/segmented-recipient-consensus/genesis/v1'
BOOTSTRAP_DOMAIN = b'1soft/segmented-recipient-consensus/bootstrap/v1\0'
APPHASH_DOMAIN = b'1soft/segmented-recipient-consensus/apphash/v1\0'
HISTORY_DOMAIN = b'1soft/segmented-recipient-consensus/history/v1\0'
MAX_HEIGHT = 2**63 - 1
MAX_TX_BYTES = 4096
MAX_BLOCK_TXS = 2
MAX_REQUEST_BYTES = 32768
MAX_CHECKPOINT_BYTES = 4096
KEYS = {'format','protocol_version','chain_id','profile_sha256','worker_sha256',
        'kat_sha256','validators','pool_id','network','asset','mission','fee','notes'}

def closed(raw, bound):
    try: return decode_canonical_json(raw, max_bytes=bound)
    except EncodingError as e: raise n.Invalid('P9 canonical JSON required') from e

def genesis_shape(raw):
    g = closed(raw, 16384)
    n.need(type(g) is dict and set(g) == KEYS and g['format'] == GENESIS_FORMAT and
           type(g['protocol_version']) is int and g['protocol_version'] == 9,
           'fresh segmented genesis required')
    n.need(type(g['chain_id']) is str and re.fullmatch('[a-zA-Z0-9_-]{1,50}',g['chain_id']) is not None,
           'P9 chain identity')
    n.need(g['profile_sha256'] == n.PROFILE_SHA256, 'P9 frozen relation8 profile differs')
    for name in ('worker_sha256','kat_sha256','pool_id'):
        n.need(type(g[name]) is str and re.fullmatch('[0-9a-f]{64}',g[name]) is not None and
               g[name] != n.ZERO, 'P9 nonzero digest')
    for name in ('network','asset','mission'):
        n.field(g[name]); n.need(g[name] != n.ZERO, 'P9 nonzero context')
    n.need(n.u64(g['fee']) > 0, 'P9 positive fee')
    notes = g['notes']
    n.need(type(notes) is list and 1 <= len(notes) <= 16, 'P9 initial segment bound')
    for row in notes:
        n.need(type(row) is dict and set(row) == {'kind','commitment'} and
               row['kind'] == 'p8-recipient-v1', 'P9 typed relation8 note')
        n.field(row['commitment']); n.need(row['commitment'] != n.ZERO, 'P9 initial note')
    n.need(len({row['commitment'] for row in notes}) == len(notes), 'P9 duplicate genesis note')
    vals = g['validators']
    n.need(type(vals) is list and len(vals) == 4, 'P9 static four-validator roster')
    for row in vals:
        n.need(type(row) is dict and set(row) == {'public_key','power'} and
               type(row['public_key']) is str and re.fullmatch('[0-9a-f]{64}',row['public_key']) is not None and
               row['public_key'] != n.ZERO and type(row['power']) is int and
               1 <= row['power'] <= 1000000, 'P9 validator entry')
    keys = [row['public_key'] for row in vals]
    n.need(keys == sorted(keys) and len(set(keys)) == 4 and
           len({row['power'] for row in vals}) == 1, 'P9 static equal-power roster')
    comet_validator_set(vals)
    return g

def bootstrap_digest(g):
    core = {'format':'1soft/segmented-recipient-consensus/bootstrap/v1',
            **{k:g[k] for k in ('protocol_version','chain_id','validators','profile_sha256',
                                'worker_sha256','pool_id','asset','mission','fee')}}
    return n.sha(BOOTSTRAP_DOMAIN + n.canonical(core))

def genesis_document(raw, worker):
    g = genesis_shape(raw)
    n.need(isinstance(worker, Worker) and worker.sha256 == g['worker_sha256'] and
           worker.kat_sha256 == g['kat_sha256'], 'P9 actual worker pins differ')
    worker.guard()
    n.need(worker.network_domain(bytes.fromhex(bootstrap_digest(g))) == g['network'],
           'P9 proof domain differs')
    p = worker.kat_statement
    n.need(p[1:4] == [g['network'],g['asset'],g['mission']] and n.integer(p[9]) == g['fee'] and
           p[4] == worker.root([row['commitment'] for row in g['notes']]), 'P9 known-answer context differs')
    return g

def application_hash(g, checkpoint):
    n.need(len(n.canonical(checkpoint)) <= MAX_CHECKPOINT_BYTES, 'P9 compact checkpoint bound')
    return n.sha(APPHASH_DOMAIN + n.canonical({'genesis_sha256':n.sha(n.canonical(g)),
                                              'checkpoint':checkpoint}))

LOGS = {0:'',1:'malformed recipient transaction',2:'recipient context differs',
        3:'recipient execution window differs',4:'recipient segment anchor differs',
        5:'consumed note, intent or output',6:'invalid recipient proof',7:'ledger integer capacity exceeded'}
def result(code, data=''): return {'code':code,'log':LOGS[code],'data':data}
