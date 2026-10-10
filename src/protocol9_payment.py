"""Explicit single-send P9 caller. Acknowledgment never establishes execution."""
import protocol8_payment as transport
import protocol8_transfer as n
from protocol9_wallet import RecipientWallet

def send_once(wallet,txid,endpoint):
    n.need(isinstance(wallet,RecipientWallet),'P9 actual protected wallet required')
    transport.endpoint_port(endpoint)
    wire=wallet.export(txid)
    # Atomic authenticated wallet marker wins even if a caller dies before I/O,
    # loses its reply, or has a concurrent caller. No new monetary journal.
    wallet.mark_attempt(txid)
    outcome=transport.dispatch(endpoint,wire)
    return {'format':'1soft/protocol9-single-send/v1','txid':txid,'wire_sha256':n.sha(wire),
        'attempts':1,**outcome,'settlement_established':False,'automatic_retry':False}
