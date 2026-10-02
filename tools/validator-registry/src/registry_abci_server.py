"""Private test-only ABCI socket for the isolated validator registry.

No native money state, wallet, public RPC, or production authority is served here.
The real engine gate must still prove that CometBFT uses the emitted updates.
"""
from __future__ import annotations

import hashlib
import json
import logging
import socketserver
import threading
from pathlib import Path

from abci_wire import MAX_FRAME
from commit_verifier import encode
from registry_abci_wire import Request, Response, read_frame, write_frame
from registry_application import RegistryApplication, encode_txs
from registry_rules import APP_VERSION, MAX_BLOCK_TXS, RegistryReject, require
from registry_wire import encode_finalize
from validator_sets import ValidatorSet


def _updates(rows, output):
    for row in rows:
        update = output.add()
        update.pub_key.ed25519 = bytes.fromhex(row['public_key'])
        update.power = row['power']


def _request_roster(rows):
    parsed = []
    for row in rows:
        key = bytes(row.pub_key.ed25519)
        require(len(key) == 32, 'unsupported initial validator key')
        parsed.append({'public_key': key.hex(), 'power': row.power})
    roster = {row['public_key']: row['power'] for row in parsed}
    require(len(roster) == len(parsed), 'duplicate initial validator key')
    return roster


def _unique_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate engine genesis key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def _last_commit_matches(request, state, height):
    if height == 1:
        require(len(request.decided_last_commit.votes) == 0, 'height-one last commit must be empty')
        return
    expected = {v.address: v.power for v in ValidatorSet.parse(state['active_validators']).validators}
    observed = {}
    for vote in request.decided_last_commit.votes:
        address = bytes(vote.validator.address)
        require(len(address) == 20 and address not in observed, 'invalid last-commit validator address')
        require(vote.validator.power > 0, 'invalid last-commit voting power')
        observed[address] = vote.validator.power
    require(observed == expected, 'last-commit roster differs from committed registry')


def _prepare(app, candidates, height, max_bytes):
    require(type(max_bytes) is int and max_bytes >= 0, 'invalid proposal byte limit')
    state = app.state()
    accepted = []
    used = 0
    for raw in candidates:
        if len(accepted) == MAX_BLOCK_TXS:
            break
        if used + len(raw) > max_bytes:
            continue
        trial = accepted + [bytes(raw)]
        try:
            _, result = app.rules.transition(state, trial, height)
        except ValueError:
            continue
        if all(row['code'] == 0 for row in result['tx_results']):
            accepted = trial
            used += len(raw)
    return accepted


def dispatch(app: RegistryApplication, request, observer=None):
    method = request.WhichOneof('value')
    response = Response()
    if method is None:
        response.exception.error = 'unsupported registry ABCI request'
        return response
    req = getattr(request, method)
    out = getattr(response, method)
    out.SetInParent()
    try:
        if method == 'echo':
            out.message = req.message
        elif method == 'flush':
            pass
        elif method == 'info':
            info = app.info()
            out.data = info['name']
            out.version = '0.38.25-registry-development'
            out.app_version = APP_VERSION
            out.last_block_height = info['height']
            out.last_block_app_hash = bytes.fromhex(info['app_hash']) if info['height'] else b''
        elif method == 'init_chain':
            require(req.chain_id == app.rules.genesis['chain_id'], 'engine chain differs from registry genesis')
            require(req.initial_height in (0, 1), 'unsupported initial height')
            require(encode(_unique_json(bytes(req.app_state_bytes))) == encode(app.rules.genesis),
                    'engine registry genesis differs')
            expected = {row['public_key']: row['power'] for row in app.rules.genesis['validators']}
            require(_request_roster(req.validators) == expected, 'engine initial roster differs from registry genesis')
            require(app.info()['height'] == 0, 'InitChain after registry advanced')
            out.app_hash = bytes.fromhex(app.info()['app_hash'])
        elif method == 'check_tx':
            result = app.check_tx(bytes(req.tx))
            out.code = result['code']
            out.log = result['log']
            out.data = result['data'].encode('ascii')
            if out.code:
                out.codespace = 'one-registry-development'
        elif method == 'prepare_proposal':
            out.txs.extend(_prepare(app, list(req.txs), req.height, req.max_tx_bytes))
        elif method == 'process_proposal':
            out.status = 1 if app.process_proposal(list(req.txs), req.height) else 2
        elif method == 'finalize_block':
            state = app.state()
            require(req.height == state['height'] + 1, 'registry finalize height differs')
            _last_commit_matches(req, state, req.height)
            candidate, expected = app.rules.transition(state, list(req.txs), req.height)
            require(len(req.next_validators_hash) == 32 and
                    bytes(req.next_validators_hash).hex() == expected['next_validators_hash'],
                    'engine next-validator commitment differs')
            result = app.finalize_block(list(req.txs), req.height, bytes(req.hash))
            require(encode(result) == encode(expected), 'finalized registry result differs from prior validation')
            out.app_hash = bytes.fromhex(result['app_hash'])
            for row in result['tx_results']:
                out.tx_results.add(code=row['code'], data=row['data'].encode('ascii'), log=row['log'])
            _updates(result['validator_updates'], out.validator_updates)
            require(out.SerializeToString(deterministic=True) == encode_finalize(result),
                    'registry ABCI response differs from pinned codec')
            if observer is not None:
                observer({'height': req.height,
                          'next_validators_hash': bytes(req.next_validators_hash).hex(),
                          'votes': [{'address': bytes(v.validator.address).hex(),
                                     'power': v.validator.power,
                                     'block_id_flag': v.block_id_flag}
                                    for v in req.decided_last_commit.votes],
                          'response_sha256': hashlib.sha256(
                              out.SerializeToString(deterministic=True)).hexdigest()})
        elif method == 'commit':
            app.commit()
        elif method == 'query':
            if req.data or req.prove or req.path != '/registry-state' or req.height not in (0, app.info()['height']):
                out.code = 1
                out.log = 'unsupported registry query'
            else:
                out.value = encode(app.state())
            out.height = app.info()['height']
        elif method == 'list_snapshots':
            pass  # Registry snapshots are not ABCI state-sync snapshots.
        elif method == 'offer_snapshot':
            out.result = 3  # REJECT; this adapter has no state-sync installation.
        elif method == 'load_snapshot_chunk':
            pass
        elif method == 'apply_snapshot_chunk':
            out.result = 5  # REJECT_SNAPSHOT (3 is RETRY in CometBFT v0.38.25).
        elif method == 'extend_vote':
            pass
        elif method == 'verify_vote_extension':
            out.status = 1 if not req.vote_extension else 2
        else:
            raise RegistryReject('unsupported registry ABCI request')
    except RegistryReject as exc:
        response = Response()
        response.exception.error = str(exc)
    return response


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        stream = self.request.makefile('rwb', buffering=0)
        try:
            while True:
                try:
                    raw = read_frame(stream)
                except (ConnectionError, OSError):
                    return
                if raw is None:
                    return
                request = Request.FromString(raw)
                response = dispatch(self.server.app, request, self.server.observe)
                require(response.ByteSize() <= MAX_FRAME, 'registry ABCI response too large')
                try:
                    write_frame(stream, response)
                except (ConnectionError, OSError):
                    return
                if response.WhichOneof('value') == 'exception':
                    self.server.fail()
                    return
        except BaseException:
            logging.exception('registry ABCI connection failed')
            self.server.fail()
            return
        finally:
            stream.close()


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, path: str | Path, app: RegistryApplication, observations: str | Path | None = None):
        socket = Path(path)
        require(socket.parent.is_dir() and socket.parent.stat().st_mode & 0o077 == 0,
                'registry ABCI socket directory must be private')
        require(not socket.exists() and not socket.is_symlink(), 'registry ABCI socket already exists')
        self.app = app
        self.failed = False
        self.failure_lock = threading.Lock()
        self.observations = Path(observations) if observations is not None else None
        self.observation_lock = threading.Lock()
        super().__init__(str(socket), Handler)
        socket.chmod(0o600)

    def fail(self):
        with self.failure_lock:
            if self.failed:
                return
            self.failed = True
        threading.Thread(target=self.shutdown, name='registry-abci-fail-stop', daemon=True).start()

    def observe(self, row):
        if self.observations is None:
            return
        with self.observation_lock:
            with self.observations.open('a', encoding='utf8') as handle:
                handle.write(json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n')
