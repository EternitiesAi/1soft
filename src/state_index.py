"""Persistent compressed SMT proof index, derived from committed native state.

Local storage only: identical v0.13 roots and proof bytes; no monetary/version
change. The caller owns the SQLite transaction. A failed operation rolls back
its savepoint, never commits the caller's work. Only changed keys rewrite their
compressed paths. Snapshot diffing and native execution still scan full state.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import sqlite3
from typing import Any

from state_tree import (COLUMNS, EMPTY, MAX_ROWS, MAX_QUERIES, MAX_WITNESS_BYTES,
                        MODE, ProofError, bind_root, branch, encoded, enabled,
                        hash32, leaf, lift, need, path_hash, row_bytes, selector,
                        unhex, verify_proof)

SCHEMA = 1


def prefix(path: int, depth: int) -> int:
    return (path >> (256 - depth)) << (256 - depth)


def location(depth: int, path: int) -> str:
    need(type(depth) is int and 0 <= depth <= 256, 'invalid index depth')
    need(type(path) is int and 0 <= path < 2**256, 'invalid index path')
    need(prefix(path, depth) == path, 'index path is not a canonical prefix')
    return f'{depth:03d}:{path:064x}'


@dataclass(frozen=True)
class Node:
    depth: int
    path: int
    root: bytes
    left: str | None = None
    right: str | None = None
    table: str | None = None
    key: str | None = None
    value: bytes | None = None

    @property
    def ref(self) -> str:
        return location(self.depth, self.path)


@dataclass
class Work:
    """Per-operation algorithm counts, not wall-clock/network performance."""
    reads: int = 0
    writes: int = 0
    deletes: int = 0
    changed_records: int = 0


class StateIndex:
    def __init__(self, db: sqlite3.Connection):
        self.db = db
        self.work = Work()
        # Do not use executescript: it implicitly commits an existing transaction.
        self.db.execute('''CREATE TABLE IF NOT EXISTS proof_nodes (
            location TEXT PRIMARY KEY, depth INTEGER NOT NULL, path BLOB NOT NULL,
            root BLOB NOT NULL, left_ref TEXT, right_ref TEXT,
            table_name TEXT, record_key TEXT, value BLOB)''')
        self.db.execute('''CREATE TABLE IF NOT EXISTS proof_checkpoint (
            id INTEGER PRIMARY KEY CHECK(id=1), schema_version INTEGER NOT NULL,
            genesis_hash TEXT NOT NULL, height INTEGER NOT NULL, app_hash TEXT NOT NULL,
            root_ref TEXT, root BLOB NOT NULL, record_count INTEGER NOT NULL)''')

    @contextmanager
    def _savepoint(self):
        need(self.db.in_transaction, 'index updates require a caller-owned transaction')
        self.db.execute('SAVEPOINT one_soft_proof_index')
        self.work = Work()
        try:
            yield
            self.db.execute('RELEASE one_soft_proof_index')
        except BaseException:
            self.db.execute('ROLLBACK TO one_soft_proof_index')
            self.db.execute('RELEASE one_soft_proof_index')
            raise

    def checkpoint(self) -> dict | None:
        row = self.db.execute('''SELECT schema_version,genesis_hash,height,app_hash,
                                root_ref,root,record_count FROM proof_checkpoint WHERE id=1''').fetchone()
        if row is None:
            return None
        schema, genesis, height, app_hash, ref, root, count = row
        need(type(schema) is int and schema == SCHEMA, 'unsupported proof-index schema')
        unhex(genesis); unhex(app_hash)
        need(type(height) is int and 0 <= height <= 2**63-2, 'invalid index checkpoint height')
        need(type(count) is int and 0 <= count <= MAX_ROWS, 'invalid indexed record count')
        need(type(root) is bytes and len(root) == 32, 'invalid checkpoint tree root')
        need(bind_root(genesis, height, root) == app_hash, 'index checkpoint binding mismatch')
        need((ref is None) == (count == 0), 'empty index metadata mismatch')
        if ref is None:
            need(root == EMPTY[256], 'empty index root mismatch')
        else:
            node = self._read(ref)
            need(lift(node.root, node.depth, 0, node.path) == root, 'index root node mismatch')
        return {'genesis_hash': genesis, 'height': height, 'app_hash': app_hash,
                'root_ref': ref, 'root': root, 'record_count': count}

    def assert_checkpoint(self, genesis: str, height: int, app_hash: str) -> dict:
        meta = self.checkpoint()
        need(meta is not None and meta['genesis_hash'] == genesis and meta['height'] == height
             and meta['app_hash'] == app_hash, 'proof index does not match committed state')
        return meta

    def _read(self, ref: str) -> Node:
        need(type(ref) is str and len(ref) == 68, 'invalid node locator')
        row = self.db.execute('''SELECT depth,path,root,left_ref,right_ref,table_name,record_key,value
                                FROM proof_nodes WHERE location=?''', (ref,)).fetchone()
        self.work.reads += 1
        need(row is not None, 'missing proof index node')
        depth, raw_path, root, left_ref, right_ref, table, key, value = row
        need(type(raw_path) is bytes and len(raw_path) == 32, 'invalid stored path')
        path = int.from_bytes(raw_path, 'big')
        need(location(depth, path) == ref, 'node location mismatch')
        need(type(root) is bytes and len(root) == 32, 'invalid node hash')
        if depth == 256:
            need(left_ref is None and right_ref is None and type(value) is bytes,
                 'invalid index leaf')
            try:
                parsed = json.loads(value)
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise ProofError('invalid indexed row JSON') from exc
            need(row_bytes(table, key, parsed) == value, 'noncanonical indexed row')
            need(path_hash(table, key) == raw_path, 'indexed key/path mismatch')
            need(leaf(raw_path, value) == root, 'indexed leaf hash mismatch')
        else:
            need(table is None and key is None and value is None and type(left_ref) is str
                 and type(right_ref) is str and left_ref != right_ref,
                 'invalid index branch')
        return Node(depth, path, root, left_ref, right_ref, table, key, value)

    def _write(self, node: Node) -> Node:
        self.db.execute('''INSERT OR REPLACE INTO proof_nodes VALUES (?,?,?,?,?,?,?,?,?)''',
            (node.ref, node.depth, node.path.to_bytes(32, 'big'), node.root,
             node.left, node.right, node.table, node.key, node.value))
        self.work.writes += 1
        return node

    def _delete(self, node: Node):
        changed = self.db.execute('DELETE FROM proof_nodes WHERE location=?', (node.ref,))
        need(changed.rowcount == 1, 'proof node disappeared')
        self.work.deletes += 1

    def _children(self, parent: Node) -> tuple[Node, Node]:
        need(parent.depth < 256, 'leaf has no children')
        left, right = self._read(parent.left), self._read(parent.right)
        for child, bit in ((left, 0), (right, 1)):
            need(child.depth > parent.depth and prefix(child.path, parent.depth) == parent.path
                 and ((child.path >> (255-parent.depth)) & 1) == bit,
                 'invalid child prefix or direction')
        actual = branch(lift(left.root, left.depth, parent.depth+1, left.path),
                        lift(right.root, right.depth, parent.depth+1, right.path))
        need(actual == parent.root, 'index branch hash mismatch')
        return left, right

    def _join(self, depth: int, left: Node, right: Node) -> Node:
        need(depth < left.depth and depth < right.depth, 'invalid split depth')
        need(prefix(left.path, depth) == prefix(right.path, depth)
             and ((left.path >> (255-depth)) & 1) == 0
             and ((right.path >> (255-depth)) & 1) == 1, 'invalid split children')
        root = branch(lift(left.root, left.depth, depth+1, left.path),
                      lift(right.root, right.depth, depth+1, right.path))
        return self._write(Node(depth, prefix(left.path, depth), root, left.ref, right.ref))

    def _edit(self, current: Node | None, pos: int, table: str, key: str,
              value: bytes | None) -> tuple[Node | None, int]:
        """Insert, replace or remove a leaf; recursively rewrite its ancestors."""
        if current is None:
            if value is None:
                return None, 0
            return self._write(Node(256, pos, leaf(pos.to_bytes(32, 'big'), value),
                                    table=table, key=key, value=value)), 1
        common = 256 - (current.path ^ pos).bit_length()
        if common < current.depth:
            if value is None:
                return current, 0
            new = self._write(Node(256, pos, leaf(pos.to_bytes(32, 'big'), value),
                                   table=table, key=key, value=value))
            if (pos >> (255-common)) & 1:
                return self._join(common, current, new), 1
            return self._join(common, new, current), 1
        if current.depth == 256:
            need(current.table == table and current.key == key, 'state-path collision')
            if value is None:
                self._delete(current)
                return None, -1
            if current.value == value:
                return current, 0
            return self._write(Node(256, pos, leaf(pos.to_bytes(32,'big'), value),
                                    table=table, key=key, value=value)), 0
        left, right = self._children(current)
        if (pos >> (255-current.depth)) & 1:
            edited, count = self._edit(right, pos, table, key, value)
            if edited is None:
                self._delete(current)
                return left, count
            if edited == right:
                return current, count
            return self._join(current.depth, left, edited), count
        edited, count = self._edit(left, pos, table, key, value)
        if edited is None:
            self._delete(current)
            return right, count
        if edited == left:
            return current, count
        return self._join(current.depth, edited, right), count

    @staticmethod
    def rows(state: dict) -> dict[tuple[str,str], bytes]:
        need(type(state) is dict and set(state) == set(COLUMNS), 'invalid index snapshot tables')
        need(all(type(v) is list for v in state.values()), 'invalid index snapshot rows')
        need(sum(len(v) for v in state.values()) <= MAX_ROWS, 'index snapshot exceeds row bound')
        result = {}
        for table, rows in state.items():
            for row in rows:
                need(type(row) is list and len(row) > 0, 'invalid index record')
                raw = row_bytes(table, row[0], row)
                pair = (table, row[0])
                need(pair not in result, 'duplicate index record')
                result[pair] = raw
        return result

    def initialize(self, genesis: str, height: int, state: dict, expected_app_hash: str) -> Work:
        """One-time derived-index construction. Never repairs a corrupt existing index."""
        with self._savepoint():
            need(self.checkpoint() is None, 'proof index is already initialized')
            need(self.db.execute('SELECT count(*) FROM proof_nodes').fetchone()[0] == 0,
                 'orphaned proof nodes require explicit investigation')
            rows = self.rows(state)
            root = None
            for (table, key), value in sorted(rows.items()):
                root, _ = self._edit(root, int.from_bytes(path_hash(table,key),'big'), table,key,value)
            self.work.changed_records = len(rows)
            self._checkpoint(genesis, height, root, len(rows), expected_app_hash)
        return self.work

    def advance(self, genesis: str, old_height: int, old_app_hash: str,
                height: int, before: dict, after: dict, expected_app_hash: str) -> Work:
        with self._savepoint():
            meta = self.assert_checkpoint(genesis, old_height, old_app_hash)
            need(type(height) is int and height == old_height+1, 'index height must advance by one')
            old_rows, new_rows = self.rows(before), self.rows(after)
            need(len(old_rows) == meta['record_count'], 'previous index count mismatch')
            root = self._read(meta['root_ref']) if meta['root_ref'] else None
            count = meta['record_count']
            for table, key in sorted(old_rows.keys() | new_rows.keys()):
                old, new = old_rows.get((table,key)), new_rows.get((table,key))
                if old == new:
                    continue
                # Authenticate the previous affected row against the current root,
                # instead of relying only on the caller's claimed old value.
                current_root = lift(root.root,root.depth,0,root.path) if root else EMPTY[256]
                proof = self._proof(root, table, key)
                actual = verify_proof(current_root,table,key,proof)
                need((None if actual is None else row_bytes(table,key,actual)) == old,
                     'delta does not start from the indexed row')
                root, delta = self._edit(root,int.from_bytes(path_hash(table,key),'big'),table,key,new)
                count += delta
                self.work.changed_records += 1
            need(count == len(new_rows), 'updated index count mismatch')
            self._checkpoint(genesis,height,root,count,expected_app_hash)
        return self.work

    def _checkpoint(self, genesis: str, height: int, node: Node | None,
                    count: int, expected: str):
        unhex(expected)
        root = lift(node.root,node.depth,0,node.path) if node else EMPTY[256]
        actual = bind_root(genesis,height,root)
        need(actual == expected, 'incremental root differs from finalized application hash')
        need(self.db.execute('SELECT count(*) FROM proof_nodes').fetchone()[0] == max(0,2*count-1),
             'proof index retained missing or orphaned nodes')
        self.db.execute('INSERT OR REPLACE INTO proof_checkpoint VALUES (1,?,?,?,?,?,?,?)',
                        (SCHEMA,genesis,height,actual,node.ref if node else None,root,count))

    def _proof(self, node: Node | None, table: str, key: str) -> dict:
        selector(table,key)
        pos = int.from_bytes(path_hash(table,key),'big')
        siblings = {}
        value = None
        while node is not None:
            common = 256 - (pos ^ node.path).bit_length()
            if common < node.depth:
                siblings[255-common] = lift(node.root,node.depth,common+1,node.path)
                break
            if node.depth == 256:
                need(node.table == table and node.key == key, 'state-path collision in proof')
                value = json.loads(node.value)
                break
            left,right = self._children(node)
            goes_right = (pos >> (255-node.depth)) & 1
            sibling = left if goes_right else right
            siblings[255-node.depth] = lift(sibling.root,sibling.depth,node.depth+1,sibling.path)
            node = right if goes_right else left
        mask = sum(1 << h for h in siblings)
        return {'table':table,'key':key,'value':value,'mask':f'{mask:064x}',
                'siblings':[siblings[h].hex() for h in sorted(siblings)]}

    def witness(self, genesis: dict, height: int, app_hash: str, queries: list) -> dict:
        need(enabled(genesis), 'index proofs require SMT genesis')
        need(type(queries) is list and 1 <= len(queries) <= MAX_QUERIES, 'invalid proof request count')
        parsed = [selector(*q) for q in queries if type(q) in (tuple,list) and len(q)==2]
        need(len(parsed)==len(queries) and len(set(parsed))==len(parsed), 'invalid or duplicate proof request')
        self.work = Work()
        meta = self.assert_checkpoint(hash32(encoded(genesis)).hex(),height,app_hash)
        root = self._read(meta['root_ref']) if meta['root_ref'] else None
        entries = [self._proof(root,*q) for q in parsed]
        # Detect corrupt cached data before serving it, not only in the client.
        for (table,key), proof in zip(parsed, entries):
            verify_proof(meta['root'],table,key,proof)
        result = {'schema':1,'commitment':MODE,'genesis':genesis,'height':height,
                  'root':meta['root'].hex(),'app_hash':app_hash,'entries':entries}
        need(len(encoded(result))<=MAX_WITNESS_BYTES, 'compact witness exceeds bound')
        return result

    def audit(self, genesis: str, height: int, app_hash: str) -> dict:
        """Startup/full maintenance check of every reachable node and no extras."""
        self.work = Work()
        meta = self.assert_checkpoint(genesis,height,app_hash)
        seen = set()
        records = 0
        def walk(node: Node):
            nonlocal records
            need(node.ref not in seen, 'index cycle or shared child')
            seen.add(node.ref)
            if node.depth == 256:
                records += 1
            else:
                left,right = self._children(node)
                walk(left);walk(right)
        if meta['root_ref']:
            walk(self._read(meta['root_ref']))
        count = self.db.execute('SELECT count(*) FROM proof_nodes').fetchone()[0]
        need(len(seen) == count == max(0,2*records-1) and records==meta['record_count'],
             'index contains unreachable or missing records')
        return {'records':records,'nodes':count,'app_hash':app_hash,'height':height}
