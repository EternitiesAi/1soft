"""P8 recovery-only snapshot dispatch; other fields use the frozen dispatcher."""
from protocol5_abci_wire import Request, Response
from protocol8_abci_server import dispatch as lifecycle_dispatch

def dispatch(app,request):
    method=request.WhichOneof('value')
    if method not in ('list_snapshots','offer_snapshot','load_snapshot_chunk','apply_snapshot_chunk'):
        return lifecycle_dispatch(app,request)
    req=getattr(request,method);response=Response();out=getattr(response,method);out.SetInParent()
    if method=='list_snapshots':
        for d in app.list_snapshots():
            s=out.snapshots.add();s.height=d['height'];s.format=d['format'];s.chunks=d['chunks'];s.hash=d['hash'];s.metadata=d['metadata']
    elif method=='offer_snapshot':
        s=req.snapshot
        out.result=app.offer_snapshot({'height':s.height,'format':s.format,'chunks':s.chunks,'hash':bytes(s.hash),'metadata':bytes(s.metadata)},bytes(req.app_hash))
    elif method=='load_snapshot_chunk':out.chunk=app.load_snapshot_chunk(req.height,req.format,req.chunk)
    else:
        r=app.apply_snapshot_chunk(req.index,bytes(req.chunk),req.sender)
        out.result=r['result'];out.refetch_chunks.extend(r['refetch_chunks']);out.reject_senders.extend(r['reject_senders'])
    return response
