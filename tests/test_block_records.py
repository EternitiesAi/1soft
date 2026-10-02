import json
import unittest
from block_application import BlockApplication
from test_block_application import fixture,signed

class BlockRecordTests(unittest.TestCase):
    def setUp(self):
        self.owner,_,_,self.g=fixture()
        self.app=BlockApplication(':memory:');self.app.init_chain(self.g['chain_id'],self.g)
    def tearDown(self):self.app.close()
    def test_only_committed_record_visible(self):
        self.app.finalize_block([signed(self.g,self.owner)],1,b'1'*32)
        self.assertEqual(self.app.query('/block/1')['code'],1)
        self.app.commit();result=self.app.query('/block/1')
        self.assertEqual(result['code'],0)
        record=json.loads(result['value'])
        self.assertEqual(record['app_hash'],self.app.app_hash)
        self.assertEqual(record['block_hash'],(b'1'*32).hex())
        self.assertEqual(record['tx_results'][0]['code'],0)
    def test_record_survives_later_height(self):
        self.app.finalize_block([],1,b'1'*32);self.app.commit()
        first=self.app.query('/block/1')['value']
        self.app.finalize_block([],2,b'2'*32);self.app.commit()
        self.assertEqual(first,self.app.query('/block/1')['value'])
    def test_invalid_height_paths(self):
        for path in ('/block/','/block/0','/block/01','/block/-1','/block/1/','/block/١','/block/100000000000000000000'):
            with self.subTest(path=path):self.assertEqual(self.app.query(path)['code'],1)
    def test_proof_request_still_rejected(self):
        self.app.finalize_block([],1,b'1'*32);self.app.commit()
        self.assertEqual(self.app.query('/block/1',prove=True)['code'],1)
