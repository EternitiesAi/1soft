"""Bounded local owner admission/preparation; frozen P7 consensus stays exact-height."""
import copy
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from protocol7_treasury import (COMMAND_MAGIC,COMMAND_DOMAIN,MAX_HEIGHT,Unavailable,need,packet,hexbytes,canonical,result,replay,_owner_check,_payment)
FUTURE_OWNER_HEIGHTS=8
def preflight(g,state,raw,earliest_height,worker):
    """Advisory AS-OF signature/CAS check. No fake blocks or committed successor."""
    need(type(earliest_height) is int and len(state['blocks'])<earliest_height<=MAX_HEIGHT,'P7 bounded future preflight height')
    replay(g,state,len(state['blocks']),worker)
    if type(raw) is not bytes or len(raw)>8192:return result(1)
    if raw[:8]!=COMMAND_MAGIC:
        return _payment(g,copy.deepcopy(state),raw,earliest_height,0,worker)
    try:v=packet(raw)
    except (ValueError,TypeError,KeyError):return result(1)
    b=v['body']
    if not earliest_height<=b['height']<=min(MAX_HEIGHT,earliest_height+FUTURE_OWNER_HEIGHTS-1):return result(3)
    try:_owner_check(g,state['treasury'],b,b['height'],worker)
    except Unavailable:raise
    except ValueError:return result(2)
    try:Ed25519PublicKey.from_public_bytes(hexbytes(state['treasury']['owner_key'],32)).verify(hexbytes(v['signature'],64),COMMAND_DOMAIN+canonical(b))
    except InvalidSignature:return result(8)
    if len(state['receipts'])>=32:return result(7)
    return result(0)
