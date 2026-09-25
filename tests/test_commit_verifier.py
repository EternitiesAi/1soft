# Fixed upstream test vectors are attributed in third_party/COMETBFT-ATTRIBUTION.md.
import base64
from copy import deepcopy
import json
import unittest
from commit_verifier import (VerificationError, encode, load_json, sha, merkle_root, header_hash,
    vote_sign_bytes, ZERO_TIME, pinned_genesis, trust_from_genesis, verify_signed_header,
    verify_state_witness, verify_block_transactions, verify_packet, number, timestamp, MAX_POWER)
from certificate_fixture import packet_fixture, make_commit, make_header


class GoldenVectors(unittest.TestCase):
    """Constants independently transcribed from upstream v0.38.25 tests."""
    def test_upstream_header_hash(self):
        h={'version':{'block':'1','app':'2'},'chain_id':'chainId','height':'3',
           'time':'2019-10-13T16:14:44Z','last_block_id':{'hash':'00'*32,'parts':{'total':6,'hash':'00'*32}},
           'proposer_address':sha(b'proposer_address')[:20].hex()}
        for key in ('last_commit_hash','data_hash','validators_hash','next_validators_hash',
                    'consensus_hash','app_hash','last_results_hash','evidence_hash'):
            h[key]=sha(key.encode()).hex()
        self.assertEqual(header_hash(h).hex().upper(),
                         'F740121F553B5418C3EFBD343C2DBFE9E007BB67B0D020A0741374BAB65242A4')

    def test_upstream_vote_bytes(self):
        # types/vote_test.go TestVoteSignBytesTestVectors, cases 0..4.
        cases=[('',0,0,0,'0d2a0b088092b8c398feffffff01'),
          ('',1,1,2,'2108021101000000000000001901000000000000002a0b088092b8c398feffffff01'),
          ('',1,1,1,'2108011101000000000000001901000000000000002a0b088092b8c398feffffff01'),
          ('',1,1,0,'1f1101000000000000001901000000000000002a0b088092b8c398feffffff01'),
          ('test_chain_id',1,1,0,'2e1101000000000000001901000000000000002a0b088092b8c398feffffff01320d746573745f636861696e5f6964')]
        for chain,h,r,t,expected in cases:
            with self.subTest(chain=chain,type=t,height=h):
                self.assertEqual(vote_sign_bytes(chain,h,r,None,ZERO_TIME,vote_type=t).hex(),expected)

    def test_merkle_domains_and_unbalanced_split(self):
        h=lambda x:sha(b'\x00'+x)
        self.assertEqual(merkle_root([]),sha(b''))
        self.assertEqual(merkle_root([b'a']),h(b'a'))
        self.assertEqual(merkle_root([b'a',b'b',b'c']),sha(b'\x01'+sha(b'\x01'+h(b'a')+h(b'b'))+h(b'c')))

    def test_timestamp_nanoseconds_preserved(self):
        t=timestamp('2026-09-24T12:00:00.123456789Z')
        self.assertEqual(t.nanos,123456789)

    def test_epoch_timestamp_field_is_present(self):
        wire=vote_sign_bytes('',1,0,None,'1970-01-01T00:00:00Z')
        self.assertTrue(wire.endswith(bytes.fromhex('2a00')))


class CommitVerifierTests(unittest.TestCase):
    def setUp(self):
        self.genesis,self.trust,self.keys,self.packet=packet_fixture()
        self.cert=self.packet['state_commit']

    def reject(self,fn,*args,**kwargs):
        with self.assertRaises(VerificationError):fn(*args,**kwargs)

    def test_four_valid_signatures(self):
        r=verify_signed_header(self.cert,self.trust)
        self.assertEqual((r['signed_power'],r['total_power']),(40,40))

    def test_three_of_four_valid(self):
        c=make_commit(self.cert['header'],self.trust,self.keys,[2,2,2,1])
        self.assertEqual(verify_signed_header(c,self.trust)['signed_power'],30)

    def test_two_of_four_rejected(self):
        c=make_commit(self.cert['header'],self.trust,self.keys,[2,2,1,1])
        self.reject(verify_signed_header,c,self.trust)

    def test_exactly_two_thirds_rejected(self):
        _,trust,keys,p=packet_fixture((10,10,10))
        c=make_commit(p['state_commit']['header'],trust,keys,[2,2,1])
        self.reject(verify_signed_header,c,trust)

    def test_power_not_signer_headcount(self):
        _,trust,keys,p=packet_fixture((70,10,10,10))
        c=make_commit(p['state_commit']['header'],trust,keys,[2,1,1,1])
        self.assertEqual(verify_signed_header(c,trust)['signed_power'],70)
        c=make_commit(p['state_commit']['header'],trust,keys,[1,2,2,2])
        self.reject(verify_signed_header,c,trust)

    def test_signed_nil_vote_not_counted(self):
        c=make_commit(self.cert['header'],self.trust,self.keys,[2,2,3,3])
        self.reject(verify_signed_header,c,self.trust)

    def test_three_commits_and_valid_nil(self):
        c=make_commit(self.cert['header'],self.trust,self.keys,[2,2,2,3])
        self.assertEqual(verify_signed_header(c,self.trust)['signed_power'],30)

    def test_invalid_tail_signature_after_quorum_rejected(self):
        self.cert['commit']['signatures'][-1]['signature']=base64.b64encode(bytes(64)).decode()
        self.reject(verify_signed_header,self.cert,self.trust)

    def test_duplicate_signer_slot_rejected(self):
        self.cert['commit']['signatures'][1]=deepcopy(self.cert['commit']['signatures'][0])
        self.reject(verify_signed_header,self.cert,self.trust)

    def test_reordered_slots_rejected(self):
        self.cert['commit']['signatures'].reverse()
        self.reject(verify_signed_header,self.cert,self.trust)

    def test_missing_and_extra_slots_rejected(self):
        for delta in (-1,1):
            c=deepcopy(self.cert)
            if delta<0:c['commit']['signatures'].pop()
            else:c['commit']['signatures'].append(c['commit']['signatures'][0])
            self.reject(verify_signed_header,c,self.trust)

    def test_wrong_chain_even_with_fresh_signatures_rejected(self):
        h=deepcopy(self.cert['header']);h['chain_id']='other'
        c=make_commit(h,self.trust,self.keys)
        self.reject(verify_signed_header,c,self.trust)

    def test_header_hash_tamper_rejected(self):
        self.cert['header']['app_hash']='ab'*32
        self.reject(verify_signed_header,self.cert,self.trust)

    def test_commit_block_hash_tamper_rejected(self):
        self.cert['commit']['block_id']['hash']='ab'*32
        self.reject(verify_signed_header,self.cert,self.trust)

    def test_commit_part_set_tamper_rejected(self):
        self.cert['commit']['block_id']['parts']['total']=2
        self.reject(verify_signed_header,self.cert,self.trust)

    def test_commit_height_mismatch(self):
        self.cert['commit']['height']='3'
        self.reject(verify_signed_header,self.cert,self.trust)

    def test_wrong_round_rejected(self):
        self.cert['commit']['round']=1
        self.reject(verify_signed_header,self.cert,self.trust)

    def test_nonzero_round_valid(self):
        c=make_commit(self.cert['header'],self.trust,self.keys,round_=4)
        self.assertEqual(verify_signed_header(c,self.trust)['signed_power'],40)

    def test_timestamp_signature_tamper(self):
        self.cert['commit']['signatures'][0]['timestamp']='2026-09-24T12:00:00.123456788Z'
        self.reject(verify_signed_header,self.cert,self.trust)

    def test_validator_change_rejected_even_if_signed(self):
        h=deepcopy(self.cert['header']);h['next_validators_hash']='ab'*32
        c=make_commit(h,self.trust,self.keys)
        self.reject(verify_signed_header,c,self.trust)

    def test_validator_hash_mismatch_even_if_signed(self):
        h=deepcopy(self.cert['header']);h['validators_hash']='ab'*32
        c=make_commit(h,self.trust,self.keys)
        self.reject(verify_signed_header,c,self.trust)

    def test_unknown_proposer_rejected(self):
        h=deepcopy(self.cert['header']);h['proposer_address']='ab'*20
        self.reject(verify_signed_header,make_commit(h,self.trust,self.keys),self.trust)

    def test_expected_height_rejects_stale_certificate(self):
        self.reject(verify_signed_header,self.cert,self.trust,expected_height=3)
        self.assertEqual(verify_signed_header(self.cert,self.trust,expected_height=2)['height'],2)

    def test_absent_signature_cannot_carry_data(self):
        c=make_commit(self.cert['header'],self.trust,self.keys,[2,2,2,1])
        c['commit']['signatures'][-1]['signature']=self.cert['commit']['signatures'][0]['signature']
        self.reject(verify_signed_header,c,self.trust)

    def test_absent_timestamp_must_be_zero(self):
        c=make_commit(self.cert['header'],self.trust,self.keys,[2,2,2,1])
        c['commit']['signatures'][-1]['timestamp']='2026-09-24T00:00:00Z'
        self.reject(verify_signed_header,c,self.trust)

    def test_full_packet_valid(self):
        r=verify_packet(self.packet,self.trust)
        self.assertEqual(r['status'],'verified');self.assertEqual(len(r['transactions']),1)
        self.assertIn('live network execution provenance',r['not_established'])

    def test_full_state_tampering(self):
        self.packet['state']['native']['accounts'][0][4]+=1
        self.reject(verify_packet,self.packet,self.trust)

    def test_state_recomputed_root_without_new_commit_rejected(self):
        state=self.packet['state'];state['native']['accounts'][0][4]+=1
        material={'domain':'ETERNITIES/ABCI-STATE/v1','genesis':self.trust.native_genesis_hash,
                  'height':state['height'],'native':state['native']}
        state['app_hash']=sha(encode(material)).hex()
        self.reject(verify_packet,self.packet,self.trust)

    def test_same_height_header_does_not_authenticate_post_state(self):
        self.reject(verify_state_witness,self.packet['state'],self.packet['transactions'][0]['commit'],self.trust)

    def test_inclusion_without_execution_receipt_not_success(self):
        # A valid cryptographic inclusion check by itself reports ONLY inclusion.
        item=self.packet['transactions'][0]
        r=verify_block_transactions(item['block'],item['commit'],self.trust)
        self.assertIn('not execution success',r['claim'])

    def test_transaction_list_tamper(self):
        self.packet['transactions'][0]['block']['block']['data']['txs'][0]=base64.b64encode(b'forged').decode()
        self.reject(verify_packet,self.packet,self.trust)

    def test_transaction_target_tamper(self):
        self.packet['transactions'][0]['tx']=base64.b64encode(b'forged').decode()
        self.reject(verify_packet,self.packet,self.trust)

    def test_block_id_tamper(self):
        self.packet['transactions'][0]['block']['block_id']=deepcopy(self.packet['transactions'][0]['block']['block_id'])
        self.packet['transactions'][0]['block']['block_id']['parts']['hash']='00'*32
        self.reject(verify_packet,self.packet,self.trust)

    def test_duplicate_transaction_witness_rejected(self):
        self.packet['transactions'].append(deepcopy(self.packet['transactions'][0]))
        self.reject(verify_packet,self.packet,self.trust)

    def test_schema_bool_rejected(self):
        self.packet['schema']=True;self.reject(verify_packet,self.packet,self.trust)

    def test_state_height_bool_rejected(self):
        self.packet['state']['height']=True;self.reject(verify_packet,self.packet,self.trust)

    def test_packet_roundtrip(self):
        r=verify_packet(load_json(encode(self.packet)),self.trust)
        self.assertEqual(r['state']['state_height'],1)

    def test_pinned_genesis_digest(self):
        raw=encode(self.genesis)
        self.assertEqual(pinned_genesis(raw,sha(raw).hex()),self.trust)
        self.reject(pinned_genesis,raw,'00'*32)

    def test_mutated_genesis_does_not_share_pin(self):
        raw=encode(self.genesis);self.genesis['validators'][0]['power']='11'
        self.reject(pinned_genesis,encode(self.genesis),sha(raw).hex())

    def test_unordered_genesis_sorts_by_power_and_address(self):
        g=deepcopy(self.genesis);g['validators'].reverse()
        self.assertEqual(trust_from_genesis(g),self.trust)

    def test_genesis_duplicate_validator_rejected(self):
        self.genesis['validators'][1]=deepcopy(self.genesis['validators'][0])
        self.reject(trust_from_genesis,self.genesis)

    def test_genesis_unsupported_key_rejected(self):
        self.genesis['validators'][0]['pub_key']['type']='tendermint/PubKeySecp256k1'
        self.reject(trust_from_genesis,self.genesis)

    def test_genesis_key_address_mismatch(self):
        self.genesis['validators'][0]['address']='00'*20
        self.reject(trust_from_genesis,self.genesis)

    def test_genesis_power_overflow(self):
        for v in self.genesis['validators']:v['power']=str(MAX_POWER)
        self.reject(trust_from_genesis,self.genesis)

    def test_genesis_chain_mismatch(self):
        self.genesis['app_state']['chain_id']='other';self.reject(trust_from_genesis,self.genesis)

    def test_genesis_zero_negative_bool_power_rejected(self):
        for value in ('0','-1',True):
            g=deepcopy(self.genesis);g['validators'][0]['power']=value
            self.reject(trust_from_genesis,g)

    def test_unknown_fields_rejected(self):
        self.cert['header']['fake']=1;self.reject(verify_signed_header,self.cert,self.trust)

    def test_invalid_timestamp_forms(self):
        for value in ('2026-09-24T12:00:00.1234567890Z','2026-02-30T00:00:00Z','2026-09-24','NaN',None):
            with self.subTest(value=value):self.reject(timestamp,value)

    def test_strict_integer_forms(self):
        for value in (True,1.0,'1.0','01','+1','-1',str(2**64)):
            with self.subTest(value=value):self.reject(number,value)

    def test_duplicate_json_and_floats_rejected(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":1.0}',b'{"x":NaN}',b'['):
            with self.subTest(raw=raw):self.reject(load_json,raw)

    def test_packet_size_limit(self):
        self.reject(load_json,b'{}',max_bytes=1)

    def test_expected_transaction_intent_bound(self):
        txid=self.packet['state']['native']['receipts'][0][0]
        r=verify_packet(self.packet,self.trust,expected_txids=[txid])
        self.assertTrue(r['requested_transactions_bound'])
        self.reject(verify_packet,self.packet,self.trust,expected_txids=['00'*32])

    def test_omitted_requested_transaction_rejected(self):
        txid=self.packet['state']['native']['receipts'][0][0]
        self.packet['transactions']=[]
        self.reject(verify_packet,self.packet,self.trust,expected_txids=[txid])

    def test_duplicate_expected_id_rejected(self):
        txid=self.packet['state']['native']['receipts'][0][0]
        self.reject(verify_packet,self.packet,self.trust,expected_txids=[txid,txid])

    def test_invalid_requested_transaction_list(self):
        for wanted in ('00'*32,[],[True],['bad']):
            self.reject(verify_packet,self.packet,self.trust,expected_txids=wanted)

    def test_initial_height_unsupported(self):
        self.genesis['initial_height']='2';self.reject(trust_from_genesis,self.genesis)

    def test_same_height_even_with_matching_hash_and_new_signatures_rejected(self):
        state=self.packet['state']
        wrong=make_header(self.trust,1,state['app_hash'])
        c=make_commit(wrong,self.trust,self.keys)
        self.reject(verify_state_witness,state,c,self.trust)
