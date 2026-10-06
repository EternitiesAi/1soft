"""Bounded P8 public transfer kernel; no consensus, wallet dispatch or P7 migration.

The caller must authenticate the externally supplied genesis and height. Public
apply() replays every prior receipt from that genesis before admission. shape()
checks structure, while replay() checks the native proof and state provenance.
state_hash() is a deterministic local digest, never a certificate or AppHash.
"""
from __future__ import annotations
import copy, hashlib, json, os, re, subprocess, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / 'tools/recipient-transfer/PROFILE_V1.json'
PROFILE = json.loads(PROFILE_PATH.read_bytes())
PROFILE_SHA256 = hashlib.sha256(PROFILE_PATH.read_bytes()).hexdigest()
MODULUS = 28948022309329048855892746252171976963363056481941560715954676764349967630337
ZERO = '00' * 32
MAX = 2 ** 64 - 1

class Invalid(ValueError):
    pass

class Unavailable(RuntimeError):
    pass

def need(ok, msg):
    if not ok:
        raise Invalid(msg)

def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()

def sha(b):
    return hashlib.sha256(b).hexdigest()

def field(v):
    need(type(v) is str and re.fullmatch('[0-9a-f]{64}', v) is not None, 'canonical field')
    b = bytes.fromhex(v)
    need(int.from_bytes(b, 'little') < MODULUS, 'field range')
    return b

def u64(v):
    need(type(v) is int and 0 <= v <= MAX, 'canonical u64')
    return v

def integer(v):
    return u64(int.from_bytes(field(v), 'little'))

def parse(raw):
    need(type(raw) is bytes and len(raw) == PROFILE['wire_bytes'] and (raw[:8] == b'1SRCT008'), 'P8 exact wire')
    p = [raw[8 + i * 32:8 + (i + 1) * 32].hex() for i in range(13)]
    for f in p:
        field(f)
        need(f != ZERO, 'nonzero public')
    need(integer(p[0]) == 8 and 1 <= integer(p[7]) < integer(p[8]) and (integer(p[9]) > 0) and (p[10] != p[11]), 'P8 public syntax')
    return p

def txid(raw):
    parse(raw)
    return sha(b'1soft/P8-recipient-transfer/tx/v1\x00' + raw)

class Worker:

    def __init__(self, path, expected_sha256):
        self.path = Path(path)
        need(not self.path.is_symlink() and self.path.is_file() and (0 < self.path.stat().st_size <= 16 * 1024 * 1024), 'bounded worker')
        self.identity = {'bytes': self.path.stat().st_size, 'sha256': sha(self.path.read_bytes())}
        need(self.identity['sha256'] == expected_sha256, 'worker pin')
        self.runs = []

    def call(self, op, raw, timeout=45):
        need(op in ('verify', 'note-root', 'inspect') and type(raw) is bytes and (len(raw) <= PROFILE['wire_bytes'] + 33), 'bounded operation')
        need(not self.path.is_symlink() and self.path.is_file() and (self.path.stat().st_size == self.identity['bytes']) and (sha(self.path.read_bytes()) == self.identity['sha256']), 'worker changed')

        def limits():
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_AS, (2 * 1024 ** 3, 2 * 1024 ** 3))
            resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
        process = None
        started = time.monotonic()
        ticks = None
        timed_out = False
        try:
            process = subprocess.Popen([str(self.path), op], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={}, preexec_fn=limits if os.name == 'posix' else None)
            if os.name == 'posix':
                try:
                    ticks = Path(f'/proc/{process.pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
                except OSError:
                    pass
            try:
                out, err = process.communicate(raw, timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                process.kill()
                out, err = process.communicate()
                raise Unavailable('P8 worker timeout')
        except OSError as e:
            raise Unavailable('P8 worker unavailable') from e
        finally:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
                self.runs.append({'operation': op, 'pid': process.pid, 'start_ticks': ticks, 'exit_code': process.returncode, 'input_bytes': len(raw), 'output_bytes': len(out) if 'out' in locals() else 0, 'binary_sha256': self.identity['sha256'], 'elapsed_seconds': round(time.monotonic() - started, 6), 'timed_out': timed_out, 'process_reaped': process.poll() is not None, 'resource_limits': {'cpu_seconds': 45, 'address_space_bytes': 2 * 1024 ** 3, 'core_bytes': 0} if os.name == 'posix' else None})
        if process.returncode or err or len(out) > 1024:
            raise Unavailable('P8 worker failed')
        return out

    def verify(self, raw, network):
        parse(raw)
        reply = self.call('verify', field(network) + raw)
        if reply == b'OK\n':
            return True
        if reply == b'INVALID\n':
            return False
        raise Unavailable('P8 closed worker response')

    def root(self, notes):
        need(type(notes) is list and 1 <= len(notes) <= 16, 'bounded notes')
        for n in notes:
            field(n)
            need(n != ZERO, 'nonzero note')
        need(len(set(notes)) == len(notes), 'duplicate note')
        out = self.call('note-root', b''.join((field(n) for n in notes)))
        need(len(out) == 32, 'root response')
        field(out.hex())
        return out.hex()

def initial_state(*, network, asset, mission, fee, notes, worker):
    for v in (network, asset, mission):
        field(v)
        need(v != ZERO, 'nonzero context')
    u64(fee)
    need(fee > 0, 'positive fee')
    need(type(notes) is list and all((type(v) is dict and set(v) == {'kind', 'commitment'} and (v['kind'] == 'p8-recipient-v1') for v in notes)), 'typed P8 genesis notes')
    commitments = [v['commitment'] for v in notes]
    root = worker.root(commitments)
    return {'format': '1soft/P8-recipient-state/v1', 'profile_sha256': PROFILE_SHA256, 'worker_sha256': worker.identity['sha256'], 'network': network, 'asset': asset, 'mission': mission, 'fee': fee, 'notes': copy.deepcopy(notes), 'anchors': [root], 'nullifiers': [], 'requests': [], 'fees': 0, 'receipts': []}

def shape(s, w):
    need(type(s) is dict and set(s) == {'format', 'profile_sha256', 'worker_sha256', 'network', 'asset', 'mission', 'fee', 'notes', 'anchors', 'nullifiers', 'requests', 'fees', 'receipts'}, 'closed P8 state')
    need(s['format'] == '1soft/P8-recipient-state/v1' and s['profile_sha256'] == PROFILE_SHA256 and (s['worker_sha256'] == w.identity['sha256']), 'P8 state pins')
    for v in (s['network'], s['asset'], s['mission']):
        field(v)
        need(v != ZERO, 'nonzero context')
    u64(s['fee'])
    u64(s['fees'])
    need(s['fee'] > 0, 'positive fee')
    need(type(s['notes']) is list and 1 <= len(s['notes']) <= 16 and all((type(v) is dict and set(v) == {'kind', 'commitment'} and (v['kind'] == 'p8-recipient-v1') for v in s['notes'])), 'typed P8 notes')
    ns = [v['commitment'] for v in s['notes']]
    for n in ns:
        field(n)
        need(n != ZERO, 'nonzero note')
    need(len(set(ns)) == len(ns), 'duplicate note')
    for name in ('anchors', 'nullifiers', 'requests'):
        xs = s[name]
        need(type(xs) is list and len(xs) <= 33, 'bounded state index')
        for f in xs:
            field(f)
            need(f != ZERO, 'nonzero state index')
        need(len(set(xs)) == len(xs), 'duplicate state index')
    need(type(s['receipts']) is list and len(s['receipts']) <= 32, 'bounded P8 receipts')
    for r in s['receipts']:
        need(type(r) is dict and set(r) == {'txid', 'raw', 'height', 'statement', 'note_root_after'}, 'closed replay receipt')
        need(type(r['txid']) is str and re.fullmatch('[0-9a-f]{64}', r['txid']) is not None, 'canonical txid')
        need(type(r['raw']) is str and len(r['raw']) == PROFILE['wire_bytes'] * 2 and (re.fullmatch('[0-9a-f]+', r['raw']) is not None), 'canonical replay wire')
        u64(r['height'])
        field(r['note_root_after'])
        need(r['note_root_after'] != ZERO, 'nonzero receipt root')
        need(type(r['statement']) is list and len(r['statement']) == 13, 'bounded statement')
        for f in r['statement']:
            field(f)
            need(f != ZERO, 'nonzero statement')
    need(len(s['anchors']) == len(s['receipts']) + 1 and len(s['receipts']) == len(s['nullifiers']) == len(s['requests']) and (s['fees'] == len(s['receipts']) * s['fee']), 'consistent P8 accounting')
    return ns

def _apply(s, raw, height, worker):
    ns = shape(s, worker)
    u64(height)
    p = parse(raw)
    need(not s['receipts'] or height >= s['receipts'][-1]['height'], 'P8 height regression')
    need((p[1], p[2], p[3]) == (s['network'], s['asset'], s['mission']), 'P8 context mismatch')
    need(p[4] in s['anchors'], 'P8 unknown note root')
    need(integer(p[7]) <= height < integer(p[8]) and integer(p[9]) == s['fee'], 'P8 height or fee')
    need(p[5] not in s['nullifiers'] and p[6] not in s['requests'], 'P8 note or intent already consumed')
    need(p[10] not in ns and p[11] not in ns and (len(ns) + 2 <= 16) and (len(s['receipts']) < 32) and (s['fees'] + s['fee'] <= MAX), 'P8 output conflict or capacity')
    need(worker.verify(raw, s['network']), 'P8 native proof invalid')
    out = copy.deepcopy(s)
    out['notes'].extend(({'kind': 'p8-recipient-v1', 'commitment': f} for f in p[10:12]))
    out['nullifiers'].append(p[5])
    out['requests'].append(p[6])
    out['fees'] += s['fee']
    root = worker.root(ns + p[10:12])
    out['anchors'].append(root)
    out['receipts'].append({'txid': txid(raw), 'raw': raw.hex(), 'height': height, 'statement': p, 'note_root_after': root})
    return out

def replay(genesis, state, worker):
    shape(genesis, worker)
    need(not genesis['receipts'] and (not genesis['nullifiers']) and (not genesis['requests']) and (genesis['fees'] == 0) and (len(genesis['anchors']) == 1) and (genesis['anchors'][0] == worker.root([n['commitment'] for n in genesis['notes']])), 'P8 genesis source')
    out = copy.deepcopy(genesis)
    shape(state, worker)
    for r in state['receipts']:
        need(type(r) is dict and set(r) == {'txid', 'raw', 'height', 'statement', 'note_root_after'} and (type(r['raw']) is str) and (len(r['raw']) == PROFILE['wire_bytes'] * 2), 'closed replay receipt')
        try:
            raw = bytes.fromhex(r['raw'])
        except ValueError as e:
            raise Invalid('replay wire') from e
        out = _apply(out, raw, r['height'], worker)
    need(canonical(out) == canonical(state), 'P8 replay state mismatch')
    return out

def apply(genesis, state, raw, height, worker):
    validated = replay(genesis, state, worker)
    return _apply(validated, raw, height, worker)

def state_hash(s):
    return sha(b'1soft/P8-recipient-state/v1\x00' + canonical(s))
