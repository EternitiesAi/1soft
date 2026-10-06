"""Strict public replay of P8 native evidence with caller-supplied trust pins."""
from __future__ import annotations
import argparse, copy, json, re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src import protocol8_transfer as p
from scripts.run_protocol8_recipient import CHECKS, CLAIMS
KEYS = {'format', 'status', 'scope', 'source', 'profile_sha256', 'profile', 'binary_identities', 'bootstrap_hex', 'genesis', 'genesis_sha256', 'final_state', 'state_sha256', 'public_wires', 'public_wire_sha256', 'checks', 'details', 'processes', 'claims'}

def validate_shape(r, genesis_sha256, verifier_sha256):
    p.need(type(r) is dict and set(r) == KEYS, 'closed report')
    p.need(r['format'] == '1soft/P8-recipient-native-run/v1' and r['status'] == 'passed' and (r['scope'] == 'native recipient proof and bounded public state only'), 'report scope')
    p.need(r['claims'] == CLAIMS and all((type(v) is bool for v in r['claims'].values())), 'claims cannot expand')
    p.need(p.canonical(r['profile']) == p.canonical(p.PROFILE) and r['profile_sha256'] == p.PROFILE_SHA256, 'profile pins')
    p.need(type(r['checks']) is dict and set(r['checks']) == set(CHECKS) and all((v == 'passed' for v in r['checks'].values())), 'all checks required')
    p.need(r['genesis_sha256'] == genesis_sha256 and p.sha(p.canonical(r['genesis'])) == genesis_sha256, 'external genesis pin')
    p.need(type(r['binary_identities']) is dict and set(r['binary_identities']) == {'prover', 'fixture', 'verifier'}, 'binary inventory')
    for identity in r['binary_identities'].values():
        p.need(type(identity) is dict and set(identity) == {'sha256', 'bytes'} and (type(identity['sha256']) is str) and (re.fullmatch('[0-9a-f]{64}', identity['sha256']) is not None) and (type(identity['bytes']) is int) and (0 < identity['bytes'] <= 16 * 1024 ** 2), 'binary identity')
    p.need(r['binary_identities']['verifier']['sha256'] == verifier_sha256, 'external verifier pin')
    p.need(type(r['source']) is dict and set(r['source']) == {'commit', 'tree', 'clean', 'runtime_files', 'source_manifest_sha256'} and (r['source']['clean'] is True), 'source receipt')
    for name, n in (('commit', 40), ('tree', 40), ('source_manifest_sha256', 64)):
        p.need(type(r['source'][name]) is str and re.fullmatch('[0-9a-f]{' + str(n) + '}', r['source'][name]) is not None, 'source hash')
    es = r['source']['runtime_files']
    p.need(type(es) is list and 1 <= len(es) <= 2048, 'runtime inventory')
    names = set()
    for e in es:
        p.need(type(e) is dict and set(e) == {'path', 'bytes', 'sha256'} and (type(e['path']) is str) and e['path'].startswith(('src/', 'scripts/', 'tests/', 'tools/recipient-transfer/', 'tools/shielded-consensus/halo2/')) and (chr(92) not in e['path']) and (':' not in e['path']) and all((s not in ('', '.', '..') for s in e['path'].split('/'))) and (e['path'] not in names), 'runtime path')
        names.add(e['path'])
        p.need(type(e['bytes']) is int and 0 <= e['bytes'] <= 16 * 1024 ** 2 and (type(e['sha256']) is str) and (re.fullmatch('[0-9a-f]{64}', e['sha256']) is not None), 'runtime metadata')
        path = ROOT / e['path']
        p.need(path.is_file() and (not path.is_symlink()) and (path.stat().st_size == e['bytes']) and (p.sha(path.read_bytes()) == e['sha256']), 'runtime source pin')
    expected = [e for e in json.loads((ROOT / 'SOURCE_MANIFEST.json').read_bytes())['files'] if e['path'].startswith(('src/', 'scripts/', 'tests/', 'tools/recipient-transfer/', 'tools/shielded-consensus/halo2/'))]
    p.need(es == expected, 'complete runtime membership')
    p.need({'src/protocol8_transfer.py', 'scripts/run_protocol8_recipient.py', 'scripts/check_protocol8_recipient_report.py', 'tools/recipient-transfer/PROFILE_V1.json', 'tools/recipient-transfer/halo2/src/circuit.rs', 'tools/recipient-transfer/halo2/src/verifier.rs'}.issubset(names), 'mandatory runtime sources')
    p.need(type(r['bootstrap_hex']) is str and re.fullmatch('[0-9a-f]{64}', r['bootstrap_hex']) is not None, 'bootstrap syntax')
    p.need(type(r['public_wires']) is list and len(r['public_wires']) == 4 and (type(r['public_wire_sha256']) is list) and (len(r['public_wire_sha256']) == 4), 'public wire membership')
    wires = []
    for raw, digest in zip(r['public_wires'], r['public_wire_sha256']):
        p.need(type(raw) is str and len(raw) == p.PROFILE['wire_bytes'] * 2 and (re.fullmatch('[0-9a-f]+', raw) is not None), 'canonical wire')
        b = bytes.fromhex(raw)
        p.parse(b)
        p.need(p.sha(b) == digest, 'wire hash')
        wires.append(b)
    p.need(wires[0] != wires[2] and p.parse(wires[0]) == p.parse(wires[2]), 'randomized transcript')
    cp, fp = (p.parse(wires[3]), p.parse(wires[0]))
    p.need(cp[:6] == fp[:6] and cp[6] != fp[6] and (cp[10] != fp[10]) and (cp[11] != fp[11]), 'valid competing statement')
    p.need(type(r['details']) is dict and set(r['details']) == {'spent_nullifier_refused', 'consumed_intent_refused', 'unknown_root_refused', 'wrong_fee_refused', 'wrong_height_refused', 'wrong_context_refused', 'forged_snapshot_refused', 'legacy_wire_refused', 'legacy_note_refused', 'private_request_refusals'}, 'detail membership')
    p.need(r['details']['private_request_refusals'] == ['magic', 'profile', 'parameters', 'verifying_key', 'bootstrap', 'wrong_recipient_key', 'truncated', 'trailing', 'u64_overflow'], 'all private refusal cases')
    rows = r['processes']
    p.need(type(rows) is list and 25 <= len(rows) <= 128, 'bounded process receipt')
    rowkeys = {'binary', 'operation', 'pid', 'start_ticks', 'exit_code', 'input_bytes', 'output_bytes', 'binary_sha256', 'elapsed_seconds', 'timed_out', 'process_reaped', 'resource_limits'}
    seen = set()
    for row in rows:
        p.need(type(row) is dict and set(row) == rowkeys and (row['binary'] in r['binary_identities']) and (row['binary_sha256'] == r['binary_identities'][row['binary']]['sha256']), 'process identity')
        p.need(row['process_reaped'] is True and row['timed_out'] is False and (type(row['pid']) is int) and (row['pid'] > 0) and (type(row['start_ticks']) is str) and row['start_ticks'].isdigit(), 'process lifecycle')
        key = (row['pid'], row['start_ticks'])
        p.need(key not in seen, 'duplicate process receipt')
        seen.add(key)
        for name in ('input_bytes', 'output_bytes'):
            p.need(type(row[name]) is int and 0 <= row[name] <= 4096, 'bounded process bytes')
        p.need(type(row['elapsed_seconds']) in (int, float) and 0 <= row['elapsed_seconds'] <= 101, 'bounded elapsed')
        p.need(type(row['exit_code']) is int and row['exit_code'] in (0, 1), 'bounded exit')
        p.need(row['resource_limits'] == {'cpu_seconds': 45 if row['binary'] == 'verifier' else 90, 'address_space_bytes': 2 * 1024 ** 3, 'core_bytes': 0}, 'process limits')
    allowed = {'prover': {'prove'}, 'fixture': {'first', 'second', 'competing', 'genesis-note'}, 'verifier': {'inspect', 'verify', 'note-root'}}
    for row in rows:
        p.need(type(row['operation']) is str and row['operation'] in allowed[row['binary']], 'closed operation')
    return wires

def verify(r, genesis_sha256, verifier, verifier_sha256):
    wires = validate_shape(r, genesis_sha256, verifier_sha256)
    worker = p.Worker(verifier, verifier_sha256)
    for wire in wires:
        p.need(worker.verify(wire, r['genesis']['network']), 'native public proof replay')
    state = p.replay(r['genesis'], r['final_state'], worker)
    p.need(p.state_hash(state) == r['state_sha256'] and len(state['receipts']) == 2 and (len(state['notes']) == 5) and (state['fees'] == 2), 'exact final state')
    p.need([v['raw'] for v in state['receipts']] == r['public_wires'][:2], 'receipt wire provenance')
    first_state = p.apply(r['genesis'], r['genesis'], wires[0], 2, worker)
    try:
        p.apply(r['genesis'], first_state, wires[3], 3, worker)
    except p.Invalid as e:
        p.need(str(e) == 'P8 note or intent already consumed', 'exact competing refusal')
    else:
        raise p.Invalid('valid competing spend accepted')
    return {'status': 'passed', 'scope': r['scope'], 'public_proofs_verified': 4, 'valid_competing_spend_refused': True, 'state_receipts_replayed': 2, 'state_sha256': r['state_sha256'], 'runtime_files_matched': len(r['source']['runtime_files']), 'verification_processes': worker.runs, 'claims': CLAIMS}

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('report', type=Path)
    ap.add_argument('--verifier', type=Path, required=True)
    ap.add_argument('--verifier-sha256', required=True)
    ap.add_argument('--genesis-sha256', required=True)
    args = ap.parse_args()
    p.need(args.report.stat().st_size <= 1024 ** 2, 'bounded report')

    def pairs(items):
        result = {}
        for k, v in items:
            p.need(k not in result, 'duplicate report field')
            result[k] = v
        return result
    r = json.loads(args.report.read_bytes(), object_pairs_hook=pairs, parse_constant=lambda v: (_ for _ in ()).throw(p.Invalid('nonfinite JSON')))
    print(json.dumps(verify(r, args.genesis_sha256, args.verifier, args.verifier_sha256), indent=2))
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
