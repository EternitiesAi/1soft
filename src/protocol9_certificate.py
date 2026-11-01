"""Bounded P9 full-history authentication; no compact witness or freshness.

v2 carries only the blocks that hold attempts. An empty block changes nothing but the height and the history hash, so
the verifier rebuilds it (Store.skip_empty) and the signed checkpoint still binds every height. v1 listed every block,
and since the app hash moves with the height the engine never stops making them: a ledger outgrew v1's 4096 blocks
in about an hour while idle.

Only the external genesis and signed next header are trust inputs. Derived
indexes are reconstructed with the pinned native worker, never supplied by RPC.
"""
import hashlib, os, sqlite3, stat
from pathlib import Path
import protocol8_transfer as n
from protocol9_consensus import genesis_document, application_hash, closed, MAX_TX_BYTES
from protocol9_store import Store, schema
from commit_verifier import TrustAnchor, Validator, merkle_root, verify_signed_header

FORMAT='1soft/protocol9-sparse-history/v2'
MAX_BLOCKS=4096            # blocks that carry attempts
MAX_HISTORY_HEIGHT=2**20   # heights replayed, empty ones included (~10 days at 500 ms blocks)
MAX_ATTEMPTS=512
MAX_PACKET_BYTES=6*1024**2

def trust(raw_genesis,worker):
    g=genesis_document(raw_genesis,worker)
    vals=[Validator(hashlib.sha256(bytes.fromhex(r['public_key'])).digest()[:20],bytes.fromhex(r['public_key']),r['power']) for r in g['validators']]
    vals.sort(key=lambda v:(-v.power,v.address));frozen=tuple(vals)
    return TrustAnchor(g['chain_id'],frozen,merkle_root([v.encoded() for v in frozen]),n.sha(raw_genesis),sum(v.power for v in frozen))

def _shape(witness):
    n.need(type(witness) is dict and set(witness)=={'format','genesis','height','app_hash','checkpoint','blocks'} and witness['format']==FORMAT,'P9 closed complete history')
    h=witness['height'];blocks=witness['blocks']
    n.need(type(witness['checkpoint']) is dict and witness['checkpoint'].get('height')==h,'P9 client checkpoint height')
    n.need(type(h) is int and 0<=h<=MAX_HISTORY_HEIGHT and type(blocks) is list and len(blocks)<=MAX_BLOCKS,'P9 client history height bound')
    count=0;last=0
    for b in blocks:
        n.need(type(b) is dict and set(b)=={'height','transactions'} and type(b['height']) is int and last<b['height']<=h,'P9 sequential client history')
        last=b['height'];rows=b['transactions'];n.need(type(rows) is list and 1<=len(rows)<=2,'P9 client block attempt bound')
        count+=len(rows);n.need(count<=MAX_ATTEMPTS,'P9 client attempt bound')
        for wire in rows:n.need(type(wire) is str and len(wire)%2==0 and len(wire)<=2*MAX_TX_BYTES and all(c in '0123456789abcdef' for c in wire),'P9 client wire bound')
    n.need(len(n.canonical(witness))<=MAX_PACKET_BYTES,'P9 client packet byte bound')
    return h

def verify_history(witness,signed_header,raw_genesis,worker):
    h=_shape(witness);g=genesis_document(raw_genesis,worker)
    n.need(n.canonical(witness['genesis'])==raw_genesis,'P9 external full genesis differs')
    n.need(len(n.canonical(signed_header))<=16384,'P9 signed header byte bound')
    # Authenticate the claimed checkpoint before spending native replay work.
    cert=verify_signed_header(signed_header,trust(raw_genesis,worker),expected_height=h+1)
    n.need(cert['app_hash']==witness['app_hash'] and application_hash(g,witness['checkpoint'])==witness['app_hash'],'P9 checkpoint not bound by signed next header')
    db=sqlite3.connect(':memory:')
    try:
        schema(db,create=True);store=Store(db,g,worker);checkpoint=store.initial()
        for b in witness['blocks']:
            checkpoint=store.skip_empty(checkpoint,b['height']-1)
            checkpoint,_,_=store.advance(checkpoint,[bytes.fromhex(w) for w in b['transactions']],b['height'])
        checkpoint=store.skip_empty(checkpoint,h)
        n.need(checkpoint==witness['checkpoint'] and application_hash(g,checkpoint)==witness['app_hash'],'P9 replayed checkpoint differs')
        notes=[{'commitment':v,'segment':s,'position':p,'height':height} for v,s,p,height in db.execute('SELECT commitment,segment,position,height FROM p9_notes ORDER BY seq')]
        receipts=[]
        for ident,height,raw in db.execute('SELECT txid,height,wire FROM p9_receipts ORDER BY seq'):
            raw=bytes(raw);receipts.append({'txid':ident,'height':height,'raw':raw.hex(),'statement':n.parse(raw)})
        ledger={'notes':notes,'anchors':[r[0] for r in db.execute('SELECT root FROM p9_roots ORDER BY segment,count')],
            'nullifiers':[r[0] for r in db.execute('SELECT nullifier FROM p9_nullifiers ORDER BY nullifier')],
            'requests':[r[0] for r in db.execute('SELECT request FROM p9_requests ORDER BY request')],'receipts':receipts}
        return ({**cert,'state_height':h,'header_height':h+1,'genesis_sha256':n.sha(raw_genesis),'profile_sha256':g['profile_sha256'],
                 'claim':'AS-OF P9 complete bounded native history under externally pinned static quorum; no freshness or compact proof'},ledger)
    finally:db.close()

def export_history(path):
    """Read a bounded consistent public packet from an owner-held P9 database.

    This is a transport/export operation, not authentication. The caller must
    obtain a signed h+1 header and invoke verify_history against external pins.
    No application writer lock or consensus control API is exposed.
    """
    path=Path(os.path.abspath(path));n.need(os.name=='posix','P9 POSIX exporter required')
    for parent in (path.parent,*path.parent.parents):n.need(not parent.is_symlink(),'P9 exporter symlink parent')
    d=path.parent.lstat();s=path.lstat()
    n.need(stat.S_ISDIR(d.st_mode) and d.st_uid==os.geteuid() and stat.S_IMODE(d.st_mode)==0o700,'P9 exporter private parent')
    n.need(stat.S_ISREG(s.st_mode) and s.st_uid==os.geteuid() and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,'P9 exporter owner database')
    db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=5)
    try:
        db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
        row=db.execute('SELECT genesis,checkpoint,app_hash FROM p9_checkpoint WHERE id=1').fetchone()
        n.need(row is not None,'P9 exporter checkpoint absent')
        g=closed(bytes(row[0]),16384);checkpoint=closed(bytes(row[1]),4096);h=checkpoint.get('height') if type(checkpoint) is dict else None
        n.need(type(h) is int and 0<=h<=MAX_HISTORY_HEIGHT,'P9 export history capacity')
        blocks=[];count=0
        for height,raw in db.execute('SELECT height,txs FROM p9_blocks WHERE txs!=? ORDER BY height LIMIT ?',(n.canonical([]),MAX_BLOCKS+1)):
            txs=closed(bytes(raw),2*MAX_TX_BYTES*2+128)
            n.need(type(txs) is list and len(txs)<=2,'P9 export attempt container')
            if not txs:continue  # an empty block stored in another spelling of []; the verifier rebuilds it either way
            count+=len(txs);n.need(count<=MAX_ATTEMPTS and len(blocks)<MAX_BLOCKS,'P9 export capacity')
            blocks.append({'height':height,'transactions':txs})
        witness={'format':FORMAT,'genesis':g,'height':h,'app_hash':row[2],'checkpoint':checkpoint,'blocks':blocks};_shape(witness)
        after=path.lstat();n.need((s.st_dev,s.st_ino)==(after.st_dev,after.st_ino),'P9 exporter database replaced')
        return witness
    finally:db.close()
