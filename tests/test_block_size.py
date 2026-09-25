"""Consensus block limits include protobuf Data.txs framing, not only payloads."""
import unittest
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from native_core import Reject
from block_application import BlockApplication, MAX_BLOCK_BYTES, MAX_TX_BYTES
from test_block_application import fixture, signed


def reference_size(txs):
    fd=descriptor_pb2.FileDescriptorProto(name='test_data.proto',syntax='proto3')
    msg=fd.message_type.add(name='Data')
    msg.field.add(name='txs',number=1,type=12,label=3)
    pool=descriptor_pool.DescriptorPool();pool.Add(fd)
    Data=message_factory.GetMessageClass(pool.FindMessageTypeByName('Data'))
    return len(Data(txs=txs).SerializeToString())

class BlockSizeTests(unittest.TestCase):
    def test_prepare_must_include_serialization_overhead(self):
        owner,_,_,g=fixture(); app=BlockApplication(':memory:');app.init_chain(g['chain_id'],g)
        raw=signed(g,owner)
        try:
            self.assertEqual(app.prepare_proposal([raw],1,len(raw)),[])
            self.assertEqual(app.prepare_proposal([raw],1,reference_size([raw])),[raw])
        finally:app.close()

    def test_framing_can_push_block_past_limit(self):
        txs=[b'x'*MAX_TX_BYTES]*64
        self.assertEqual(sum(map(len,txs)),MAX_BLOCK_BYTES)
        self.assertGreater(reference_size(txs),MAX_BLOCK_BYTES)
        with self.assertRaises(Reject):BlockApplication._bounds(txs)

    def test_sizes_match_independent_protobuf_runtime(self):
        from block_application import transaction_data_size
        for sizes in ([],[0],[1],[127],[128],[16383],[16384],[0,127,128,8192]):
            with self.subTest(sizes=sizes):
                txs=[b'x'*n for n in sizes]
                self.assertEqual(transaction_data_size(txs),reference_size(txs))

    def test_wrong_input_types_rejected(self):
        from block_application import transaction_data_size
        for txs in (None, b'x', [bytearray(b'x')], [1]):
            with self.subTest(txs=txs), self.assertRaises(Reject):transaction_data_size(txs)
