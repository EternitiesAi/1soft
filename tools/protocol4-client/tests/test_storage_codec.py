"""Strict framed proof decoding refuses corruption and bounds output before inflation."""
import importlib
import importlib.util
import unittest
from unittest.mock import patch
import zlib

from p4_evidence import MAX_EVIDENCE_BYTES


class StorageCodecTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('p4_storage_codec'), 'missing bounded storage codec')
        self.codec=importlib.import_module('p4_storage_codec')
    def frame(self,codec,original,encoded):
        return self.codec.MAGIC+bytes([codec])+original.to_bytes(4,'big')+encoded
    def test_compressible_original_bytes_round_trip_with_exact_frame(self):
        raw=b'{"proof":"'+b'a'*4096+b'"}'
        framed=self.codec.encode_payload(raw)
        self.assertEqual(len(self.codec.MAGIC),10);self.assertEqual(self.codec.FRAME_BYTES,15)
        self.assertEqual(framed[:10],self.codec.MAGIC);self.assertEqual(framed[10],1)
        self.assertEqual(int.from_bytes(framed[11:15],'big'),len(raw))
        self.assertEqual(framed[15:],zlib.compress(raw,level=6,wbits=15))
        self.assertEqual(self.codec.decode_payload(framed),raw)
    def test_incompressible_small_payload_uses_raw_fallback(self):
        raw=b'{}';framed=self.codec.encode_payload(raw)
        self.assertEqual(framed,self.frame(0,len(raw),raw))
        self.assertEqual(self.codec.decode_payload(framed),raw)
    def test_input_exact_type_and_original_bounds(self):
        for raw in ('{}',bytearray(b'{}'),memoryview(b'{}'),b'',b'x'*(MAX_EVIDENCE_BYTES+1)):
            with self.subTest(type=type(raw).__name__):
                with self.assertRaises(ValueError):self.codec.encode_payload(raw)
        for framed in ('bad',bytearray(b'bad'),memoryview(b'bad'),b'',b'bad'*4):
            with self.assertRaises(ValueError):self.codec.decode_payload(framed)
    def test_declared_original_bound_checked_before_decoder_creation(self):
        for original in (0,MAX_EVIDENCE_BYTES+1,2**32-1):
            with patch('p4_storage_codec.zlib.decompressobj',side_effect=AssertionError('decoder used')):
                with self.assertRaises(ValueError):self.codec.decode_payload(self.frame(1,original,b'x'))
    def test_raw_length_unknown_codec_magic_and_encoded_bounds(self):
        frames=[self.frame(0,2,b'x'),self.frame(0,2,b'xxx'),self.frame(2,2,b'{}'),
                b'wrongmagic'+self.frame(0,2,b'{}')[10:],self.frame(1,2,b'xx'),self.frame(1,5,b'')]
        for framed in frames:
            with self.subTest(frame_bytes=len(framed)):
                with self.assertRaises(ValueError):self.codec.decode_payload(framed)
    def test_inflated_output_declared_shorter_or_longer_is_rejected(self):
        packed=zlib.compress(b'a'*10000,level=6,wbits=15)
        for declared in (500,10001):
            with self.assertRaises(ValueError):self.codec.decode_payload(self.frame(1,declared,packed))
    def test_inflation_decoder_has_exact_original_plus_one_output_cap(self):
        real=zlib.decompressobj;calls=[]
        class Bounded:
            def __init__(self,*args,**kw):self.inner=real(*args,**kw)
            def decompress(self,raw,max_length):
                calls.append(max_length);return self.inner.decompress(raw,max_length)
            def __getattr__(self,name):return getattr(self.inner,name)
        with patch('p4_storage_codec.zlib.decompressobj',side_effect=Bounded):
            with self.assertRaises(ValueError):
                self.codec.decode_payload(self.frame(1,500,zlib.compress(b'a'*10000)))
        self.assertEqual(calls,[501])
    def test_truncated_corrupt_tail_and_concatenated_streams_refused(self):
        raw=b'a'*1000;packed=zlib.compress(raw,level=6,wbits=15)
        changed=bytearray(packed);changed[-1]^=1
        for encoded in (packed[:-1],bytes(changed),packed+b'junk',packed+packed):
            with self.assertRaises(ValueError):self.codec.decode_payload(self.frame(1,len(raw),encoded))
    def test_dictionary_nonstandard_window_and_level_refused(self):
        raw=b'a'*1000
        streams=[zlib.compress(raw,level=1,wbits=15),zlib.compress(raw,level=9,wbits=15),
                 zlib.compress(raw,level=6,wbits=14)]
        obj=zlib.compressobj(level=6,wbits=15,zdict=b'a'*100)
        streams.append(obj.compress(raw)+obj.flush())
        for encoded in streams:
            with self.assertRaises(ValueError):self.codec.decode_payload(self.frame(1,len(raw),encoded))
    def test_exact_sixteen_mib_original_is_decoded_losslessly(self):
        raw=b'a'*MAX_EVIDENCE_BYTES
        self.assertEqual(self.codec.decode_payload(self.codec.encode_payload(raw)),raw)


if __name__=='__main__':unittest.main()
