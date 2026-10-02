"""Private ABCI++ dispatcher for fresh-genesis protocol 4 only."""
from __future__ import annotations

from commit_verifier import load_json
from native_core import Reject, require
from protocol4_abci_wire import Request, Response
from protocol4_application import Protocol4Application


def _initial_validators(rows):
    result = []
    for row in rows:
        key = bytes(row.pub_key.ed25519)
        require(len(key) == 32 and row.power > 0,
                'unsupported protocol-4 initial validator')
        result.append({'public_key': key.hex(), 'power': row.power})
    return result


def _last_commit(rows):
    result = []
    for vote in rows:
        address = bytes(vote.validator.address)
        require(len(address) == 20, 'invalid protocol-4 last-commit address')
        result.append({'address': address.hex(), 'power': vote.validator.power,
                       'block_id_flag': vote.block_id_flag})
    return result


def dispatch(app: Protocol4Application, request):
    method = request.WhichOneof('value')
    if method is None:
        raise Reject('unsupported protocol-4 ABCI request')
    req = getattr(request, method)
    response = Response()
    out = getattr(response, method)
    out.SetInParent()
    if method == 'echo':
        out.message = req.message
    elif method == 'flush':
        pass
    elif method == 'info':
        info = app.info()
        out.data = info['name']
        out.version = '0.38.25-protocol4-development'
        out.app_version = info['version']
        out.last_block_height = info['height']
        if info['height']:
            out.last_block_app_hash = bytes.fromhex(info['app_hash'])
    elif method == 'init_chain':
        genesis = load_json(bytes(req.app_state_bytes), max_bytes=131_072)
        out.app_hash = bytes.fromhex(app.init_chain(
            req.chain_id, genesis, _initial_validators(req.validators), req.initial_height))
        # Empty ResponseInitChain.validators retains the engine's exact genesis set.
    elif method == 'check_tx':
        result = app.check_tx(bytes(req.tx))
        out.code = result['code']
        out.log = result['log']
        out.data = result['data'].encode('ascii')
        if out.code:
            out.codespace = 'one-protocol4-development'
    elif method == 'prepare_proposal':
        out.txs.extend(app.prepare_proposal(list(req.txs), req.height, req.max_tx_bytes))
    elif method == 'process_proposal':
        out.status = 1 if app.process_proposal(
            list(req.txs), req.height, bytes(req.next_validators_hash)) else 2
    elif method == 'finalize_block':
        _, wire = app.finalize_block(
            list(req.txs), req.height, bytes(req.hash), bytes(req.next_validators_hash),
            _last_commit(req.decided_last_commit.votes),
            req.SerializeToString(deterministic=True))
        out.ParseFromString(wire)
    elif method == 'commit':
        app.commit()
    elif method == 'query':
        if len(req.path) > 512 or req.data:
            out.code = 1
            out.log = 'unsupported protocol-4 query input'
            out.height = app.height
        else:
            result = app.query(req.path, req.height, req.prove)
            out.code = result['code']
            out.log = result['log']
            out.value = result['value']
            out.height = result['height']
        if out.code:
            out.codespace = 'one-protocol4-development'
    elif method == 'list_snapshots':
        for item in app.list_snapshots():
            snap = out.snapshots.add()
            snap.height, snap.format, snap.chunks = (
                item['height'], item['format'], item['chunks'])
            snap.hash, snap.metadata = item['hash'], item['metadata']
    elif method == 'offer_snapshot':
        offered = {'height': req.snapshot.height, 'format': req.snapshot.format,
                   'chunks': req.snapshot.chunks, 'hash': bytes(req.snapshot.hash),
                   'metadata': bytes(req.snapshot.metadata)}
        out.result = app.offer_snapshot(offered, bytes(req.app_hash))
    elif method == 'load_snapshot_chunk':
        out.chunk = app.load_snapshot_chunk(req.height, req.format, req.chunk)
    elif method == 'apply_snapshot_chunk':
        result = app.apply_snapshot_chunk(req.index, bytes(req.chunk), req.sender)
        out.result = result['result']
        out.refetch_chunks.extend(result['refetch_chunks'])
        out.reject_senders.extend(result['reject_senders'])
    elif method == 'extend_vote':
        pass
    elif method == 'verify_vote_extension':
        out.status = 1 if not req.vote_extension else 2
    else:
        raise Reject('unsupported protocol-4 ABCI method')
    return response
