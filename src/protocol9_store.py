"""Indexed segmented ledger; block execution never loads historical blocks."""
import copy
import sqlite3
from itertools import zip_longest
import protocol8_transfer as n
from protocol9_consensus import (HISTORY_DOMAIN, MAX_HEIGHT, MAX_TX_BYTES,
                                MAX_BLOCK_TXS, application_hash, result)

SCHEMA = {
    'p9_checkpoint':'CREATE TABLE p9_checkpoint (id INTEGER PRIMARY KEY CHECK(id=1), genesis BLOB NOT NULL, checkpoint BLOB NOT NULL, app_hash TEXT NOT NULL)',
    'p9_notes':'CREATE TABLE p9_notes (seq INTEGER PRIMARY KEY, commitment TEXT NOT NULL UNIQUE, segment INTEGER NOT NULL, position INTEGER NOT NULL, height INTEGER NOT NULL, UNIQUE(segment,position))',
    'p9_roots':'CREATE TABLE p9_roots (root TEXT PRIMARY KEY, segment INTEGER NOT NULL, count INTEGER NOT NULL, height INTEGER NOT NULL)',
    'p9_nullifiers':'CREATE TABLE p9_nullifiers (nullifier TEXT PRIMARY KEY, txid TEXT NOT NULL)',
    'p9_requests':'CREATE TABLE p9_requests (request TEXT PRIMARY KEY, txid TEXT NOT NULL)',
    'p9_receipts':'CREATE TABLE p9_receipts (seq INTEGER PRIMARY KEY, txid TEXT NOT NULL UNIQUE, height INTEGER NOT NULL, wire BLOB NOT NULL)',
    'p9_blocks':'CREATE TABLE p9_blocks (height INTEGER PRIMARY KEY, block_hash TEXT NOT NULL, identity TEXT NOT NULL, txs BLOB NOT NULL, value BLOB NOT NULL, response BLOB NOT NULL, request_wire BLOB NOT NULL)',
}
INDEX_TABLES = ('p9_notes','p9_roots','p9_nullifiers','p9_requests','p9_receipts')
ORDER = {'p9_notes':'seq','p9_roots':'root','p9_nullifiers':'nullifier',
         'p9_requests':'request','p9_receipts':'seq'}

def schema(db, *, create=False):
    rows = db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    if not rows and create:
        db.execute('BEGIN IMMEDIATE')
        try:
            for sql in SCHEMA.values(): db.execute(sql)
            db.execute('COMMIT')
        except BaseException:
            db.execute('ROLLBACK'); raise
        rows = db.execute("SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    n.need(len(rows) == len(SCHEMA) and all(t == 'table' and name in SCHEMA and
           ' '.join(sql.split()) == ' '.join(SCHEMA[name].split()) for t,name,sql in rows), 'P9 exact schema differs')

class Store:
    def __init__(self, db, g, worker):
        self.db, self.g, self.worker = db, g, worker

    def initial(self):
        notes = [row['commitment'] for row in self.g['notes']]
        for i, commitment in enumerate(notes):
            self.db.execute('INSERT INTO p9_notes VALUES (?,?,?,?,?)',(i,commitment,0,i,0))
        self.db.execute('INSERT INTO p9_roots VALUES (?,?,?,?)',(self.worker.root(notes),0,len(notes),0))
        return {'format':'1soft/segmented-recipient-checkpoint/v1','height':0,'segment':0,
                'active_notes':notes,'notes_count':len(notes),'accepted_count':0,'attempt_count':0,'fees':0,
                'history_sha256':n.sha(HISTORY_DOMAIN + n.canonical({'genesis_sha256':n.sha(n.canonical(self.g))}))}

    def _has(self, table, column, value):
        # Table/column are internal constants, never caller-controlled SQL.
        return self.db.execute('SELECT 1 FROM '+table+' WHERE '+column+'=?',(value,)).fetchone() is not None

    def _append_outputs(self, c, outputs, height):
        for i, commitment in enumerate(outputs):
            if len(c['active_notes']) == 16:
                c['segment'] += 1; c['active_notes'] = []
            position = len(c['active_notes'])
            self.db.execute('INSERT INTO p9_notes VALUES (?,?,?,?,?)',
                            (c['notes_count'],commitment,c['segment'],position,height))
            c['notes_count'] += 1; c['active_notes'].append(commitment)
            if len(c['active_notes']) == 16 or i == len(outputs)-1:
                root = self.worker.root(c['active_notes'])
                self.db.execute('INSERT INTO p9_roots VALUES (?,?,?,?)',
                                (root,c['segment'],len(c['active_notes']),height))

    def _payment(self, c, raw, height):
        try: p = n.parse(raw)
        except n.Invalid: return result(1)
        if p[1:4] != [self.g['network'],self.g['asset'],self.g['mission']] or n.integer(p[9]) != self.g['fee']:
            return result(2)
        if not n.integer(p[7]) <= height < n.integer(p[8]): return result(3)
        if not self._has('p9_roots','root',p[4]): return result(4)
        if (self._has('p9_nullifiers','nullifier',p[5]) or self._has('p9_requests','request',p[6]) or
            any(self._has('p9_notes','commitment',v) for v in p[10:12])): return result(5)
        if c['fees'] + self.g['fee'] > n.MAX or c['notes_count'] + 2 > MAX_HEIGHT:
            return result(7)
        if not self.worker.verify(raw,self.g['network']): return result(6)
        ident = n.txid(raw)
        self._append_outputs(c,p[10:12],height)
        self.db.execute('INSERT INTO p9_nullifiers VALUES (?,?)',(p[5],ident))
        self.db.execute('INSERT INTO p9_requests VALUES (?,?)',(p[6],ident))
        self.db.execute('INSERT INTO p9_receipts VALUES (?,?,?,?)',(c['accepted_count'],ident,height,raw))
        c['accepted_count'] += 1; c['fees'] += self.g['fee']
        return result(0,ident)

    def advance(self, checkpoint, txs, height):
        n.need(type(height) is int and height == checkpoint['height']+1 and 1 <= height <= MAX_HEIGHT,
               'P9 sequential signed64 height required')
        n.need(type(txs) is list and len(txs) <= MAX_BLOCK_TXS and
               all(type(raw) is bytes and len(raw) <= MAX_TX_BYTES for raw in txs), 'P9 block container')
        n.need(checkpoint['attempt_count'] + len(txs) <= MAX_HEIGHT, 'P9 attempt counter overflow')
        c = copy.deepcopy(checkpoint)
        results = [self._payment(c,raw,height) for raw in txs]
        c['height'] = height; c['attempt_count'] += len(txs)
        c['history_sha256'] = n.sha(HISTORY_DOMAIN + bytes.fromhex(checkpoint['history_sha256']) +
            n.canonical({'height':height,'transactions':[raw.hex() for raw in txs],'results':results}))
        return c, results, application_hash(self.g,c)

def compare_indexes(actual, replayed):
    missing = object()
    for table in INDEX_TABLES:
        sql = 'SELECT * FROM '+table+' ORDER BY '+ORDER[table]
        for a,b in zip_longest(actual.execute(sql),replayed.execute(sql),fillvalue=missing):
            n.need(a == b, 'P9 replayed index differs: '+table)
