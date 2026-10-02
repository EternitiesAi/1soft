"""Sparse-Merkle state commitments for an explicit fresh-genesis experiment.

SHA-256, 256-bit paths, domain-separated leaves/branches and compressed proofs.
This project format is NOT ICS23, IBC, or a new cryptographic primitive. Tree
construction retains O(n) compressed nodes, but hashes skipped paths and rebuilds
from the full local snapshot. It is not an incremental production state store.
"""
from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

MODE = 'smt-v1'
MAX_ROWS = 20_000
MAX_KEY_BYTES = 512
MAX_VALUE_BYTES = 32_768
MAX_WITNESS_BYTES = 1_048_576
MAX_QUERIES = 16
COLUMNS = {
    'meta': ('k', 'v'),
    'accounts': ('id', 'public_key', 'nonce', 'epoch', 'balance'),
    'grants': ('id','owner','public_key','epoch','nonce','cap','spent','expires','recipients','revoked'),
    'receipts': ('txid','sequence','previous','record','hash'),
    'budgets': ('id','owner','epoch','cap','spent','expires','recipients','revoked'),
    'grant_budgets': ('grant_id','budget_id'),
}
KEY_DOMAIN = b'1soft/state-key/v1\x00'
ROOT_DOMAIN = b'1soft/application-smt/v1\x00'
HEX64 = re.compile('[0-9a-f]{64}\\Z')


class ProofError(ValueError):
    pass


def need(condition: bool, reason: str) -> None:
    if not condition:
        raise ProofError(reason)


def encoded(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, RecursionError) as exc:
        raise ProofError('invalid proof JSON') from exc


def hash32(raw: bytes) -> bytes:
    return hashlib.sha256(raw).digest()


def unhex(text: str) -> bytes:
    need(type(text) is str and HEX64.fullmatch(text) is not None, 'noncanonical digest')
    return bytes.fromhex(text)


def selector(table: str, key: str) -> tuple[str, str]:
    need(type(table) is str and table in COLUMNS, 'unknown state table')
    need(type(key) is str and 0 < len(key) <= MAX_KEY_BYTES and key.isascii()
         and all(32 <= ord(c) <= 126 for c in key), 'invalid state key')
    return table, key


def path_hash(table: str, key: str) -> bytes:
    selector(table, key)
    return hash32(KEY_DOMAIN + encoded([table, key]))


def row_bytes(table: str, key: str, row: Any) -> bytes:
    selector(table, key)
    need(type(row) is list and len(row) == len(COLUMNS[table]) and row[0] == key,
         'row does not match requested state key')
    # No implementation-dependent floats, booleans, containers or null cells.
    need(all(type(v) in (str, int) for v in row), 'invalid state cell type')
    raw = encoded(row)
    need(len(raw) <= MAX_VALUE_BYTES, 'state row exceeds proof bound')
    return raw


def leaf(path: bytes, value: bytes) -> bytes:
    return hash32(b'\x00' + path + hash32(value))


def branch(left: bytes, right: bytes) -> bytes:
    return hash32(b'\x01' + left + right)


# EMPTY[h] is the hash of an empty subtree of height h; leaves are height 0.
EMPTY = [hash32(b'\x02')]
for _ in range(256):
    EMPTY.append(branch(EMPTY[-1], EMPTY[-1]))
EMPTY = tuple(EMPTY)


def bind_root(genesis_hash: str, height: int, root: bytes) -> str:
    need(type(height) is int and 0 <= height <= 2**63 - 2, 'invalid state height')
    need(type(root) is bytes and len(root) == 32, 'invalid state root')
    return hash32(ROOT_DOMAIN + unhex(genesis_hash) + height.to_bytes(8, 'big') + root).hex()


def enabled(genesis: dict) -> bool:
    # NativeLedger validates allowed optional genesis fields. This function must
    # not silently fall back for an unknown advertised commitment scheme.
    need(type(genesis) is dict, 'invalid genesis')
    if 'state_commitment' not in genesis:
        return False
    need(genesis['state_commitment'] == MODE and type(genesis.get('protocol_version')) is int
         and genesis['protocol_version'] == 3, 'unsupported commitment genesis')
    return True


@dataclass(frozen=True, slots=True)
class _Node:
    depth: int
    path: int
    root: bytes
    left: '_Node | None' = None
    right: '_Node | None' = None


def lift(root: bytes, depth: int, target: int, path: int) -> bytes:
    """Expand a compressed unary path with the specified side at every level."""
    for parent in range(depth - 1, target - 1, -1):
        empty = EMPTY[255 - parent]
        root = branch(empty, root) if (path >> (255 - parent)) & 1 else branch(root, empty)
    return root


class StateTree:
    def __init__(self, state: dict):
        need(type(state) is dict and set(state) == set(COLUMNS), 'invalid SMT snapshot tables')
        need(all(type(rows) is list for rows in state.values()), 'invalid state row lists')
        need(sum(len(rows) for rows in state.values()) <= MAX_ROWS, 'SMT row bound exceeded')
        self._rows: dict[int, tuple[str, str, bytes]] = {}
        for table, rows in state.items():
            for row in rows:
                need(type(row) is list and bool(row), 'invalid state row')
                key = row[0]
                raw = row_bytes(table, key, row)
                pos = int.from_bytes(path_hash(table, key), 'big')
                # Covers duplicate logical keys and the extremely unlikely hash collision.
                need(pos not in self._rows, 'duplicate state key or path collision')
                self._rows[pos] = (table, key, raw)
        self._positions = sorted(self._rows)
        self._node = self._build(0, len(self._positions)) if self._positions else None
        self.root = (lift(self._node.root, self._node.depth, 0, self._node.path)
                     if self._node else EMPTY[256])

    def _build(self, start: int, stop: int) -> _Node:
        first, last = self._positions[start], self._positions[stop - 1]
        if stop - start == 1:
            return _Node(256, first, leaf(first.to_bytes(32, 'big'), self._rows[first][2]))
        depth = 256 - (first ^ last).bit_length()
        remain = 256 - depth
        boundary = (first >> remain << remain) | (1 << (remain - 1))
        middle = bisect_left(self._positions, boundary, start, stop)
        need(start < middle < stop, 'invalid tree split')
        left, right = self._build(start, middle), self._build(middle, stop)
        lh = lift(left.root, left.depth, depth + 1, left.path)
        rh = lift(right.root, right.depth, depth + 1, right.path)
        return _Node(depth, first, branch(lh, rh), left, right)

    def proof(self, table: str, key: str) -> dict:
        wanted = int.from_bytes(path_hash(table, key), 'big')
        node = self._node
        siblings: dict[int, bytes] = {}
        value = None
        while node is not None:
            common = 256 - (wanted ^ node.path).bit_length()
            if common < node.depth:
                # Query diverges along a compressed empty edge. Supply the whole
                # occupied sibling subtree, rooted immediately below divergence.
                siblings[255 - common] = lift(node.root, node.depth, common + 1, node.path)
                break
            if node.depth == 256:
                value = json.loads(self._rows[wanted][2])
                break
            right = (wanted >> (255 - node.depth)) & 1
            sibling = node.left if right else node.right
            need(sibling is not None, 'invalid internal tree')
            siblings[255 - node.depth] = lift(sibling.root, sibling.depth, node.depth + 1, sibling.path)
            node = node.right if right else node.left
        mask = sum(1 << height for height in siblings)
        return {'table': table, 'key': key, 'value': value, 'mask': f'{mask:064x}',
                'siblings': [siblings[h].hex() for h in sorted(siblings)]}


def verify_proof(root: bytes, table: str, key: str, proof: dict) -> list | None:
    """The caller supplies the expected key and trusted root, not the server."""
    selector(table, key)
    need(type(root) is bytes and len(root) == 32, 'invalid expected root')
    need(type(proof) is dict and set(proof) == {'table','key','value','mask','siblings'},
         'invalid compact proof fields')
    need(proof['table'] == table and proof['key'] == key, 'proof changed the requested key')
    path = path_hash(table, key)
    pos = int.from_bytes(path, 'big')
    cur = EMPTY[0] if proof['value'] is None else leaf(path, row_bytes(table, key, proof['value']))
    mask = int.from_bytes(unhex(proof['mask']), 'big')
    need(type(proof['siblings']) is list and len(proof['siblings']) == mask.bit_count(),
         'proof bitmap/sibling count mismatch')
    supplied = iter(proof['siblings'])
    for height in range(256):
        sibling = unhex(next(supplied)) if (mask >> height) & 1 else EMPTY[height]
        if (mask >> height) & 1:
            need(sibling != EMPTY[height], 'redundant empty sibling is noncanonical')
        cur = branch(sibling, cur) if (pos >> height) & 1 else branch(cur, sibling)
    need(cur == root, 'Merkle proof does not reach the committed root')
    return None if proof['value'] is None else json.loads(row_bytes(table, key, proof['value']))


def make_witness(genesis: dict, height: int, state: dict, queries: list[tuple[str,str]]) -> dict:
    need(enabled(genesis), 'compact proofs require explicit SMT genesis')
    need(type(queries) is list and 1 <= len(queries) <= MAX_QUERIES, 'invalid proof request count')
    parsed = [selector(*q) for q in queries if type(q) in (tuple, list) and len(q) == 2]
    need(len(parsed) == len(queries) and len(set(parsed)) == len(parsed), 'invalid or duplicate proof request')
    tree = StateTree(state)
    witness = {'schema':1, 'commitment':MODE, 'genesis':genesis, 'height':height,
        'root':tree.root.hex(), 'app_hash':bind_root(hash32(encoded(genesis)).hex(), height, tree.root),
        'entries':[tree.proof(*q) for q in parsed]}
    need(len(encoded(witness)) <= MAX_WITNESS_BYTES, 'compact witness exceeds bound')
    return witness
