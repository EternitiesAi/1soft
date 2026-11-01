"""Closed one-copy history storage; no authentication or supplied-index trust.

Every unpacked observation must still undergo full signed native replay.
Only the unused last slot can be replaced; earlier slot numbers never change.
"""
import copy
import protocol8_transfer as n
from protocol9_certificate import FORMAT, _shape
MAX_OBSERVATIONS=8
REF_FIELDS={'height','app_hash','checkpoint','signed_header','certificate'}

def pack(observations,genesis):
    n.need(type(observations) is list and len(observations)<=MAX_OBSERVATIONS,'P9 history observation bound')
    if not observations:return None,[]
    refs=[];previous=None
    for o in observations:
        n.need(type(o) is dict and set(o)=={'witness','signed_header','certificate'},'P9 history closed observation')
        w=o['witness'];_shape(w)
        n.need(w['genesis']==genesis,'P9 history full genesis differs')
        n.need(type(o['signed_header']) is dict and type(o['certificate']) is dict,'P9 history signed metadata shape')
        if previous is not None:
            k=len(previous['blocks'])  # v2 lists only blocks with attempts: the old ones, then only newer heights
            n.need(w['height']>previous['height'] and w['blocks'][:k]==previous['blocks'] and
                   all(b['height']>previous['height'] for b in w['blocks'][k:]),'P9 history divergent prefix')
        refs.append({**{k:copy.deepcopy(w[k]) for k in ('height','app_hash','checkpoint')},
            'signed_header':copy.deepcopy(o['signed_header']),'certificate':copy.deepcopy(o['certificate'])})
        previous=w
    return {'genesis':copy.deepcopy(genesis),'blocks':copy.deepcopy(previous['blocks'])},refs

def unpack(history,refs):
    n.need(type(refs) is list and len(refs)<=MAX_OBSERVATIONS,'P9 history reference bound')
    if not refs:
        n.need(history is None,'P9 empty history differs');return []
    n.need(type(history) is dict and set(history)=={'genesis','blocks'} and type(history['blocks']) is list,'P9 closed stored history')
    observations=[];previous=-1
    for r in refs:
        n.need(type(r) is dict and set(r)==REF_FIELDS,'P9 closed history reference')
        h=r['height'];n.need(type(h) is int and previous<h,'P9 history prefix height')
        n.need(all(type(b) is dict and type(b.get('height')) is int for b in history['blocks']),'P9 closed stored history')
        w={'format':FORMAT,'genesis':copy.deepcopy(history['genesis']),'blocks':copy.deepcopy([b for b in history['blocks'] if b['height']<=h]),
            **{k:copy.deepcopy(r[k]) for k in ('height','app_hash','checkpoint')}}
        _shape(w)
        n.need(type(r['signed_header']) is dict and type(r['certificate']) is dict,'P9 history signed metadata shape')
        observations.append({'witness':w,'signed_header':copy.deepcopy(r['signed_header']),'certificate':copy.deepcopy(r['certificate'])})
        previous=h
    n.need(not history['blocks'] or history['blocks'][-1]['height']<=previous,'P9 trailing unobserved history refused')
    return observations

def retain(observations,obligations,new):
    n.need(type(observations) is list and len(observations)<=MAX_OBSERVATIONS and type(obligations) is list,'P9 retained history bound')
    pinned=set()
    def pin(index):
        n.need(type(index) is int and 0<=index<len(observations),'P9 required observation index');pinned.add(index)
    for row in obligations:
        n.need(type(row) is dict and 'observation' in row and 'result' in row,'P9 required observation dependency')
        pin(row['observation'])
        if row['result'] is not None:
            n.need(type(row['result']) is dict and 'observation' in row['result'],'P9 required completion dependency')
            pin(row['result']['observation'])
    retained=copy.deepcopy(observations)
    if retained and len(retained)-1 not in pinned:retained[-1]=copy.deepcopy(new)
    else:
        n.need(len(retained)<MAX_OBSERVATIONS,'P9 required observation capacity')
        retained.append(copy.deepcopy(new))
    return retained
