"""Separate measured private P8 prover; never dispatches a transaction."""
import protocol8_transfer as n
from protocol8_consensus import genesis_document
from protocol8_notes import PrivateProcess,statement
class Prover(PrivateProcess):
    def __init__(self,binary,sha256,*,expected_genesis,worker):
        super().__init__(binary,sha256);self.g=genesis_document(expected_genesis,worker);self.worker=worker
    def produce(self,request):
        p,_=statement(request,self.g)
        raw=self.call('prove',request,3560)
        n.need(n.parse(raw)==p and self.worker.verify(raw,self.g['network']),'P8 prover returned different statement or invalid proof')
        return raw
