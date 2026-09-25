"""Bounded process-local CheckTx result reuse, never consensus or mempool state.

Exact signed bytes and a committed genesis/height/AppHash select an answer.
The caller serializes access under its application lock. An entry means only that
an admission check returned this answer at that checkpoint; it does not reserve
funds, establish inclusion, or replace proposal/finalization execution.
"""
from __future__ import annotations
from collections import OrderedDict
from dataclasses import dataclass
import re

@dataclass(frozen=True)
class AdmissionLimits:
    max_entries: int = 512
    max_payload_bytes: int = 4 * 1024 * 1024
    max_entry_bytes: int = 24 * 1024

    def __post_init__(self):
        for value, limit in ((self.max_entries, 4096), (self.max_payload_bytes, 64*1024*1024),
                             (self.max_entry_bytes, 64*1024)):
            if type(value) is not int or not 1 <= value <= limit:
                raise ValueError('invalid local admission-cache limit')

class AdmissionCache:
    """Exact-byte LRU with entry-count and retained-payload ceilings.

    Size accounting covers raw transactions and UTF-8 result strings. Python
    object overhead is NOT included: count also limits it but this is not an RSS
    cap. There is no disk format, peer-supplied cache, TTL or automatic trust.
    """
    def __init__(self, limits: AdmissionLimits | None = None):
        self.limits = limits if limits is not None else AdmissionLimits()
        if type(self.limits) is not AdmissionLimits:
            raise ValueError('AdmissionLimits required')
        self._point: tuple[str, int, str] | None = None
        self._entries: OrderedDict[bytes, tuple[tuple[int, str, str], int]] = OrderedDict()
        self._size = 0
        self.hits = self.misses = self.evictions = self.resets = self.skipped = 0

    def bind(self, genesis: str, height: int, app_hash: str):
        if type(height) is not int or not 0 <= height <= 2**63-2 or not all(
            type(v) is str and re.fullmatch('[0-9a-f]{64}', v) for v in (genesis, app_hash)):
            raise ValueError('invalid admission checkpoint')
        point = (genesis, height, app_hash)
        if self._point != point:
            self.clear()
            self._point = point
            self.resets += 1

    def clear(self):
        self._entries.clear()
        self._size = 0
        self._point = None

    def get(self, raw: bytes) -> dict | None:
        if self._point is None:
            raise RuntimeError('admission cache has no committed checkpoint')
        if type(raw) is not bytes:
            raise TypeError('cache keys must be immutable bytes')
        value = self._entries.get(raw)
        if value is None:
            self.misses += 1
            return None
        self.hits += 1
        self._entries.move_to_end(raw)
        answer, _ = value
        # Do not leak a mutable stored answer to an ABCI caller.
        return dict(zip(('code', 'log', 'data'), answer))

    def put(self, raw: bytes, result: dict):
        if self._point is None:
            raise RuntimeError('admission cache has no committed checkpoint')
        if type(raw) is not bytes or type(result) is not dict or set(result) != {'code','log','data'}:
            raise ValueError('invalid admission result')
        code, log, data = result['code'], result['log'], result['data']
        if type(code) is not int or code not in (0,1) or type(log) is not str or type(data) is not str:
            raise ValueError('only completed native admission results may be retained')
        if (code == 0 and (log != '' or re.fullmatch('[0-9a-f]{64}', data) is None)) or (code == 1 and data != ''):
            raise ValueError('inconsistent native admission result')
        weight = len(raw) + len(log.encode('utf-8')) + len(data.encode('utf-8')) + 1
        if weight > min(self.limits.max_entry_bytes, self.limits.max_payload_bytes):
            self.skipped += 1
            return
        old = self._entries.pop(raw, None)
        if old is not None:
            self._size -= old[1]
        while self._entries and (len(self._entries) >= self.limits.max_entries or
                                  self._size + weight > self.limits.max_payload_bytes):
            _, (_, cost) = self._entries.popitem(last=False)
            self._size -= cost
            self.evictions += 1
        self._entries[raw] = ((code, log, data), weight)
        self._size += weight

    def stats(self):
        return {'entries':len(self._entries), 'retained_payload_bytes':self._size,
                'max_entries':self.limits.max_entries,'max_payload_bytes':self.limits.max_payload_bytes,
                'hits':self.hits,'misses':self.misses,'evictions':self.evictions,
                'resets':self.resets,'oversize_not_cached':self.skipped,
                'scope':'local CheckTx reuse only; no balance reservation or consensus result'}
