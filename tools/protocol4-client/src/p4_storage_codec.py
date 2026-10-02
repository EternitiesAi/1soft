"""Bounded lossless framing of original P4 proof bytes; framing is not authority."""
from __future__ import annotations

import zlib

from p4_evidence import MAX_EVIDENCE_BYTES, need

MAGIC = b'1SP4PROOF2'
FRAME_BYTES = 15
RAW = 0
ZLIB = 1


def encode_payload(raw):
    """Use standard level6/window15 zlib only when it saves original payload bytes."""
    need(type(raw) is bytes and 0 < len(raw) <= MAX_EVIDENCE_BYTES,
         'bounded original proof bytes required')
    compressed = zlib.compress(raw, level=6, wbits=15)
    codec, encoded = (ZLIB, compressed) if len(compressed) < len(raw) else (RAW, raw)
    return MAGIC + bytes([codec]) + len(raw).to_bytes(4, 'big') + encoded


def decode_payload(framed):
    """Reject malformed framing without allocating more than original length+1."""
    need(type(framed) is bytes and FRAME_BYTES <= len(framed) <= MAX_EVIDENCE_BYTES+FRAME_BYTES,
         'bounded framed proof bytes required')
    need(framed[:10] == MAGIC, 'unsupported proof frame')
    codec = framed[10]
    original = int.from_bytes(framed[11:15], 'big')
    need(0 < original <= MAX_EVIDENCE_BYTES, 'framed original proof exceeds bound')
    encoded = framed[FRAME_BYTES:]
    if codec == RAW:
        need(len(encoded) == original, 'raw proof length differs')
        return encoded
    need(codec == ZLIB and 0 < len(encoded) < original,
         'unsupported codec or compressed proof length')
    # Standard zlib level6/window15 has CMF/FLG 78 9c, with no preset dictionary.
    need(encoded[:2] == b'\x78\x9c', 'unsupported zlib window, level or dictionary')
    try:
        decoder = zlib.decompressobj(wbits=15)
        raw = decoder.decompress(encoded, original+1)
    except zlib.error as error:
        raise ValueError('invalid compressed proof') from error
    need(len(raw) == original and decoder.eof and not decoder.unused_data and
         not decoder.unconsumed_tail, 'compressed proof length, end or trailing data differs')
    return raw
