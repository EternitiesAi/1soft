"""Private development proof adapter for fresh P9 bootstrap, frozen P8 circuit."""
import protocol8_transfer as n
from protocol8_notes import PrivateProcess, opening, num
from protocol9_consensus import bootstrap_digest

def statement(request, g):
    n.need(type(request) is bytes and len(request) == 1160, 'P9 private request size')
    prefix = b'1SRCP008'+bytes.fromhex(n.PROFILE_SHA256)+bytes.fromhex(n.PROFILE['parameter_sha256'])+bytes.fromhex(n.PROFILE['verifying_key_sha256'])+bytes.fromhex(bootstrap_digest(g))
    n.need(request[:136] == prefix, 'P9 bootstrap/profile request pins')
    fs = [request[i:i+32].hex() for i in range(136,1160,32)]
    for v in fs: n.field(v)
    p,w = fs[:13],fs[13:]
    n.parse(b'1SRCT008'+b''.join(n.field(v) for v in p)+bytes(3136))
    n.need(p[1:4] == [g['network'],g['asset'],g['mission']], 'P9 request context')
    return p,w

class NoteController(PrivateProcess):
    def __init__(self, binary, sha256, *, g, worker):
        super().__init__(binary,sha256); self.g = g; self.worker = worker
    def key(self, secret):
        n.field(secret); n.need(secret != n.ZERO, 'P9 nonzero secret')
        out = self.call('key',n.field(secret),32).hex(); n.field(out)
        n.need(out != n.ZERO, 'P9 nonzero recipient key'); return out
    def base(self, o, secret, notes):
        opening(o); n.field(secret); n.need(secret != n.ZERO, 'P9 nonzero recipient secret')
        root = self.worker.root(notes)
        raw = bytes.fromhex(bootstrap_digest(self.g))+b''.join(n.field(v) for v in
            (self.g['asset'],self.g['mission'],o['origin'],num(o['value']),num(o['expiry']),o['note_secret'],o['blind'],secret))
        return raw+bytes([len(notes)])+b''.join(n.field(v) for v in notes),root
    def inspect(self, o, secret, notes):
        raw,root = self.base(o,secret,notes); out = self.call('inspect-note',raw,258)
        fs = [out[i:i+32].hex() for i in range(0,128,32)]
        path = [out[i:i+32].hex() for i in range(130,258,32)]
        for v in fs+path: n.field(v)
        position = int.from_bytes(out[128:130],'little')
        n.need(position < len(notes) and fs[0] == notes[position] and fs[1] == self.key(secret) and
               fs[3] == root, 'P9 native opening/path mismatch')
        return {'commitment':fs[0],'recipient_key':fs[1],'nullifier':fs[2],'root':root,'position':position,'path':path}
    def construct(self, o, secret, notes, *, request, valid_from, valid_until, destination,
                  payment, payment_expiry, payment_secret, payment_blind, change_secret, change_blind):
        projection = self.inspect(o,secret,notes); base,_ = self.base(o,secret,notes)
        vs = [request,num(valid_from),num(valid_until),num(self.g['fee']),destination,num(payment),num(payment_expiry),
              payment_secret,payment_blind,change_secret,change_blind]
        for v in vs: n.field(v); n.need(v != n.ZERO, 'P9 nonzero preparation field')
        out = self.call('construct',base+b''.join(n.field(v) for v in vs),1192)
        req,origin = out[:1160],out[1160:].hex(); p,w = statement(req,self.g)
        expected = [secret,o['origin'],num(o['value']),num(o['expiry']),o['note_secret'],o['blind'],num(projection['position']),
                    *projection['path'],destination,num(payment),num(payment_expiry),payment_secret,payment_blind,
                    num(o['value']-payment-self.g['fee']),change_secret,change_blind]
        n.field(origin); n.need(origin != n.ZERO and w == expected and
            p[4:10] == [projection['root'],projection['nullifier'],request,num(valid_from),num(valid_until),num(self.g['fee'])],
            'P9 constructed request differs from explicit intent')
        return req,origin

class Prover(PrivateProcess):
    def __init__(self,binary,sha256,*,g,worker):
        super().__init__(binary,sha256); self.g = g; self.worker = worker
    def produce(self,request):
        p,_ = statement(request,self.g); raw = self.call('prove',request,3560)
        n.need(n.parse(raw) == p and self.worker.verify(raw,self.g['network']), 'P9 invalid or different returned proof')
        return raw
