"""Private ABCI++ dispatcher for fresh-genesis protocol 5 only."""
from __future__ import annotations


from protocol5_application import Protocol5Application, Protocol5Error, _need
from protocol5_abci_wire import Request, Response


def _initial_validators(rows):
    result = []
    for row in rows:
        key = bytes(row.pub_key.ed25519)
        _need(len(key) == 32 and row.power > 0,
                'unsupported protocol-5 initial validator')
        result.append({'public_key': key.hex(), 'power': row.power})
    return result


def _last_commit(rows):
    result = []
    for vote in rows:
        address = bytes(vote.validator.address)
        _need(len(address) == 20, 'invalid protocol-5 last-commit address')
        result.append({'address': address.hex(), 'power': vote.validator.power,
                       'block_id_flag': vote.block_id_flag})
    return result


def dispatch(app: Protocol5Application, request):
    method = request.WhichOneof('value')
    if method is None:
        raise Protocol5Error('unsupported protocol-5 ABCI request')
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
        out.version = '0.38.25-protocol5-development'
        out.app_version = info['version']
        out.last_block_height = info['height']
        if info['height']:
            out.last_block_app_hash = bytes.fromhex(info['app_hash'])
    elif method == 'init_chain':
        genesis = bytes(req.app_state_bytes)
        out.app_hash = bytes.fromhex(app.init_chain(
            req.chain_id, genesis, _initial_validators(req.validators), req.initial_height))
        # Empty ResponseInitChain.validators retains the engine's exact genesis set.
    elif method == 'check_tx':
        result = app.check_tx(bytes(req.tx))
        out.code = result['code']
        out.log = result['log']
        out.data = result['data'].encode('ascii')
        if out.code:
            out.codespace = 'one-shielded-development'
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
            out.log = 'unsupported protocol-5 query input'
            out.height = app.height
        else:
            result = app.query(req.path, req.height, req.prove)
            out.code = result['code']
            out.log = result['log']
            out.value = result['value']
            out.height = result['height']
        if out.code:
            out.codespace = 'one-shielded-development'
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
        raise Protocol5Error('unsupported protocol-5 ABCI method')
    return response
