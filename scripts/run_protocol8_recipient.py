"""Clean-source, synthetic, offline native P8 proof/state gate. Not consensus."""
from __future__ import annotations
import argparse, copy, hashlib, json, os, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src import protocol8_transfer as p
CHECKS = ('profile_identity', 'first_native_proof', 'second_native_proof', 'randomized_proof_distinct', 'valid_competing_intent', 'wrong_network_refused', 'public_mutation_refused', 'proof_mutation_refused', 'trailing_wire_refused', 'truncated_wire_refused', 'recipient_receive', 'recipient_respend', 'public_state_replay', 'spent_nullifier_refused', 'consumed_intent_refused', 'unknown_root_refused', 'wrong_fee_refused', 'wrong_height_refused', 'wrong_context_refused', 'forged_snapshot_refused', 'legacy_wire_refused', 'legacy_note_refused', 'private_request_refusals', 'processes_reaped')
CLAIMS = {'native_recipient_proof': True, 'bounded_public_state_kernel': True, 'consensus_qualified': False, 'cometbft_exercised': False, 'authenticated_genesis_or_height': False, 'custody_qualified': False, 'p7_migration': False, 'production_ready': False, 'real_funds': False, 'recipient_identity': False, 'hostile_host_privacy': False}

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('prover', 'fixture', 'verifier', 'output'):
        ap.add_argument('--' + name, type=Path, required=True)
    for name in ('prover', 'fixture', 'verifier'):
        ap.add_argument('--' + name + '-sha256', required=True)
    args = ap.parse_args()
    p.need(not args.output.exists(), 'refuse output overwrite')
    p.need(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT) == b'', 'clean source required')
    source = {'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(), 'tree': subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=ROOT).decode().strip(), 'clean': True}
    manifest = json.loads((ROOT / 'SOURCE_MANIFEST.json').read_bytes())
    source['runtime_files'] = [e for e in manifest['files'] if e['path'].startswith(('src/', 'scripts/', 'tests/', 'tools/recipient-transfer/', 'tools/shielded-consensus/halo2/'))]
    source['source_manifest_sha256'] = p.sha((ROOT / 'SOURCE_MANIFEST.json').read_bytes())
    for e in source['runtime_files']:
        p.need(p.sha((ROOT / e['path']).read_bytes()) == e['sha256'], 'source inventory before run')
    identities = {}
    processes = []
    checks = {}
    details = {}
    for name in ('prover', 'fixture', 'verifier'):
        path = getattr(args, name)
        digest = getattr(args, name + '_sha256')
        p.need(path.is_file() and (not path.is_symlink()) and (0 < path.stat().st_size <= 16 * 1024 ** 2) and (p.sha(path.read_bytes()) == digest), 'binary pin')
        identities[name] = {'sha256': digest, 'bytes': path.stat().st_size}
    worker = p.Worker(args.verifier, args.verifier_sha256)

    def emit(v):
        print(json.dumps(v, sort_keys=True), flush=True)

    def run(name, op, raw, allowed_exit=0):
        path = getattr(args, name)
        p.need(p.sha(path.read_bytes()) == identities[name]['sha256'], 'binary changed')

        def limits():
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_AS, (2 * 1024 ** 3, 2 * 1024 ** 3))
            resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
        start = time.monotonic()
        proc = subprocess.Popen([str(path)] + ([op] if op else []), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={}, preexec_fn=limits)
        try:
            ticks = Path(f'/proc/{proc.pid}/stat').read_text().rsplit(')', 1)[1].split()[19]
        except OSError:
            ticks = None
        timed_out = False
        try:
            out, err = proc.communicate(raw, timeout=100)
        except subprocess.TimeoutExpired:
            timed_out = True
            proc.kill()
            out, err = proc.communicate()
            raise p.Unavailable('bounded native gate timeout')
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
            row = {'binary': name, 'operation': op or 'prove', 'pid': proc.pid, 'start_ticks': ticks, 'exit_code': proc.returncode, 'input_bytes': len(raw), 'output_bytes': len(out) if 'out' in locals() else 0, 'binary_sha256': identities[name]['sha256'], 'elapsed_seconds': round(time.monotonic() - start, 6), 'timed_out': timed_out, 'process_reaped': proc.poll() is not None, 'resource_limits': {'cpu_seconds': 90, 'address_space_bytes': 2 * 1024 ** 3, 'core_bytes': 0}}
            processes.append(row)
            emit({'process': row})
        p.need(proc.returncode == allowed_exit and len(out) <= 4096, 'native exit or output bound')
        p.need(err == (b'P8 recipient prover refused\n' if allowed_exit == 1 else b''), 'closed native diagnostics')
        return out

    def passed(name, ok=True):
        p.need(ok, 'gate failed: ' + name)
        checks[name] = 'passed'
        emit({'check': name, 'status': 'passed'})

    def refuse(name, operation):
        try:
            operation()
        except p.Invalid as e:
            details[name] = str(e)
            passed(name)
            return
        raise p.Invalid('expected refusal: ' + name)
    bootstrap = hashlib.sha256(b'1soft/P8/qualified-synthetic-recipient/20261006').digest()
    inspect = json.loads(worker.call('inspect', b''))
    passed('profile_identity', inspect == {'parameter_sha256': p.PROFILE['parameter_sha256'], 'verifying_key_sha256': p.PROFILE['verifying_key_sha256']})
    wires = []
    requests = []
    for name in ('first', 'second'):
        raw = bytearray(run('fixture', name, bootstrap))
        p.need(len(raw) == p.PROFILE['request_bytes'], 'private request size')
        requests.append(raw)
        wire = run('prover', None, raw)
        p.parse(wire)
        wires.append(wire)
        passed(name + '_native_proof', len(wire) == 3560 and len(wire[424:]) == 3136)
    first, second = wires
    fields = p.parse(first)
    network = fields[1]
    randomized = run('prover', None, requests[0])
    passed('randomized_proof_distinct', randomized != first and p.parse(randomized) == fields and worker.verify(randomized, network))
    competing_request = bytearray(run('fixture', 'competing', bootstrap))
    competing = run('prover', None, competing_request)
    competing_request[:] = b'\x00' * len(competing_request)
    cp = p.parse(competing)
    passed('valid_competing_intent', worker.verify(competing, network) and cp[:6] == fields[:6] and (cp[6] != fields[6]) and (cp[10] != fields[10]) and (cp[11] != fields[11]))
    note = run('fixture', 'genesis-note', bootstrap)
    p.need(len(note) == 32, 'genesis note bound')
    genesis = p.initial_state(network=network, asset=fields[2], mission=fields[3], fee=1, notes=[{'kind': 'p8-recipient-v1', 'commitment': note.hex()}], worker=worker)
    state1 = p.apply(genesis, genesis, first, 2, worker)
    passed('recipient_receive', state1['notes'][1]['commitment'] == fields[10] and state1['fees'] == 1)
    state2 = p.apply(genesis, state1, second, 3, worker)
    passed('recipient_respend', len(state2['notes']) == 5 and state2['fees'] == 2)
    passed('public_state_replay', p.replay(genesis, state2, worker) == state2)
    wrong = ((int.from_bytes(bytes.fromhex(network), 'little') + 1) % p.MODULUS).to_bytes(32, 'little').hex()
    passed('wrong_network_refused', not worker.verify(first, wrong))
    changed = bytearray(first)
    changed[8 + 6 * 32] ^= 1
    passed('public_mutation_refused', not worker.verify(bytes(changed), network))
    changed = bytearray(first)
    changed[-1] ^= 1
    passed('proof_mutation_refused', not worker.verify(bytes(changed), network))
    passed('trailing_wire_refused', worker.call('verify', bytes.fromhex(network) + first + b'x') == b'INVALID\n')
    passed('truncated_wire_refused', worker.call('verify', bytes.fromhex(network) + first[:-1]) == b'INVALID\n')

    def mutate(index, value):
        raw = bytearray(first)
        raw[8 + 32 * index:8 + 32 * (index + 1)] = value.to_bytes(32, 'little')
        return bytes(raw)
    refuse('spent_nullifier_refused', lambda: p.apply(genesis, state1, competing, 3, worker))
    refuse('consumed_intent_refused', lambda: p.apply(genesis, state1, mutate(5, 90), 3, worker))
    refuse('unknown_root_refused', lambda: p.apply(genesis, genesis, mutate(4, 90), 2, worker))
    refuse('wrong_fee_refused', lambda: p.apply(genesis, genesis, mutate(9, 2), 2, worker))
    refuse('wrong_height_refused', lambda: p.apply(genesis, genesis, first, 8, worker))
    refuse('wrong_context_refused', lambda: p.apply(genesis, genesis, mutate(2, 90), 2, worker))
    forged = copy.deepcopy(state1)
    forged['receipts'][0]['txid'] = 'ef' * 32
    refuse('forged_snapshot_refused', lambda: p.apply(genesis, forged, second, 3, worker))
    refuse('legacy_wire_refused', lambda: p.apply(genesis, genesis, b'1SOFT007' + first[8:], 2, worker))
    refuse('legacy_note_refused', lambda: p.initial_state(network=network, asset=fields[2], mission=fields[3], fee=1, notes=[{'kind': 'p7-merchant', 'commitment': note.hex()}], worker=worker))
    refusal_rows = []
    for name, offset in (('magic', 0), ('profile', 8), ('parameters', 40), ('verifying_key', 72), ('bootstrap', 104), ('wrong_recipient_key', 136 + 13 * 32)):
        raw = bytearray(requests[1])
        raw[offset] ^= 1
        out = run('prover', None, raw, 1)
        p.need(not out, 'no private refusal output')
        refusal_rows.append(name)
        raw[:] = b'\x00' * len(raw)
    for name, raw in (('truncated', requests[0][:-1]), ('trailing', requests[0] + b'x')):
        out = run('prover', None, raw, 1)
        p.need(not out, 'no refusal output')
        refusal_rows.append(name)
        raw[:] = b'\x00' * len(raw)
    raw = bytearray(requests[0])
    raw[136 + (13 + 2) * 32:136 + (13 + 3) * 32] = (2 ** 64).to_bytes(32, 'little')
    p.need(not run('prover', None, raw, 1), 'overflow output')
    refusal_rows.append('u64_overflow')
    raw[:] = b'\x00' * len(raw)
    for raw in requests:
        raw[:] = b'\x00' * len(raw)
    details['private_request_refusals'] = refusal_rows
    passed('private_request_refusals', len(refusal_rows) == 9)
    processes.extend((dict(row, binary='verifier') for row in worker.runs))
    passed('processes_reaped', all((row['process_reaped'] and (not row['timed_out']) and (row['start_ticks'] is not None) for row in processes)))
    p.need(set(checks) == set(CHECKS), 'complete check membership')
    for e in source['runtime_files']:
        p.need((ROOT / e['path']).stat().st_size == e['bytes'] and p.sha((ROOT / e['path']).read_bytes()) == e['sha256'], 'runtime source changed')
    report = {'format': '1soft/P8-recipient-native-run/v1', 'status': 'passed', 'scope': 'native recipient proof and bounded public state only', 'source': source, 'profile_sha256': p.PROFILE_SHA256, 'profile': p.PROFILE, 'binary_identities': identities, 'bootstrap_hex': bootstrap.hex(), 'genesis': genesis, 'genesis_sha256': p.sha(p.canonical(genesis)), 'final_state': state2, 'state_sha256': p.state_hash(state2), 'public_wires': [first.hex(), second.hex(), randomized.hex(), competing.hex()], 'public_wire_sha256': [p.sha(w) for w in (first, second, randomized, competing)], 'checks': checks, 'details': details, 'processes': processes, 'claims': CLAIMS}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('xb') as f:
        f.write(json.dumps(report, sort_keys=True, indent=2).encode() + b'\n')
    emit({'status': 'passed', 'report_sha256': p.sha(args.output.read_bytes()), 'checks': len(checks), 'native_processes': len(processes), 'scope': report['scope']})
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
