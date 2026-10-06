"""P8 dispatcher using unchanged CometBFT 0.38 protobuf wire fields."""
from protocol5_abci_wire import Request,Response
from protocol8_consensus import need
def dispatch(app,request):
    method=request.WhichOneof('value');need(method is not None,'unsupported P8 request')
    req=getattr(request,method);response=Response();out=getattr(response,method);out.SetInParent()
    if method=='echo':out.message=req.message
    elif method=='flush':pass
    elif method=='info':
        v=app.info();out.data=v['name'];out.version='0.38.25-protocol8-development';out.app_version=8;out.last_block_height=v['height']
        if v['height']:out.last_block_app_hash=bytes.fromhex(v['app_hash'])
    elif method=='init_chain':
        rows=[]
        for v in req.validators:
            key=bytes(v.pub_key.ed25519);need(len(key)==32 and v.power>0,'P8 initial validator')
            rows.append({'public_key':key.hex(),'power':v.power})
        out.app_hash=bytes.fromhex(app.init_chain(req.chain_id,bytes(req.app_state_bytes),rows,req.initial_height))
    elif method=='check_tx':
        r=app.check_tx(bytes(req.tx));out.code=r['code'];out.log=r['log'];out.data=r['data'].encode('ascii')
        if out.code:out.codespace='one-protocol8-recipient-consensus-development'
    elif method=='prepare_proposal':out.txs.extend(app.prepare_proposal(list(req.txs),req.height,req.max_tx_bytes))
    elif method=='process_proposal':out.status=1 if app.process_proposal(list(req.txs),req.height,bytes(req.next_validators_hash)) else 2
    elif method=='finalize_block':
        votes=[{'address':bytes(v.validator.address).hex(),'power':v.validator.power,'block_id_flag':v.block_id_flag} for v in req.decided_last_commit.votes]
        _,wire=app.finalize_block(list(req.txs),req.height,bytes(req.hash),bytes(req.next_validators_hash),votes,req.SerializeToString(deterministic=True));out.ParseFromString(wire)
    elif method=='commit':app.commit()
    elif method=='query':
        r={'code':1,'height':app.height,'value':b'','log':'unsupported P8 query'} if len(req.path)>512 or req.data else app.query(req.path,req.height,req.prove)
        out.code=r['code'];out.height=r['height'];out.value=r['value'];out.log=r['log']
    elif method=='list_snapshots':pass
    elif method=='offer_snapshot':out.result=3
    elif method=='load_snapshot_chunk':out.chunk=b''
    elif method=='apply_snapshot_chunk':out.result=2
    elif method=='extend_vote':pass
    elif method=='verify_vote_extension':out.status=1 if not req.vote_extension else 2
    else:raise ValueError('unsupported P8 ABCI request')
    return response
