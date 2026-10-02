"""Complete compressed backups of real disposable journals; no engine or network."""
import hashlib
import importlib
import io
import json
import os
import struct
import unittest
import zlib
from unittest.mock import patch

import test_custody as helpers

PASSWORD = helpers.BACKUP_PASSWORD


def owned_setup(test):
    temporary = helpers.tempfile.TemporaryDirectory
    with patch.object(helpers.tempfile, 'TemporaryDirectory',
                      side_effect=lambda: temporary(dir='/home/xnuonux', prefix='1soft-compressed-unit-')):
        helpers.CustodyTests.setUp(test)


class CompressedBackupTests(unittest.TestCase):
    setUp = owned_setup
    sign = helpers.CustodyTests.sign
    select = helpers.CustodyTests.select
    claim = helpers.CustodyTests.claim
    rows = helpers.CustodyTests.rows

    def compressed(self):
        try: return importlib.import_module('p4_custody_compressed')
        except ModuleNotFoundError as exc:
            self.fail('compressed envelope codec is missing: '+str(exc))

    def envelope(self):
        import p4_custody_stream as stream
        codec = self.compressed()
        with stream.capture_pair(self.d) as pair:
            return b''.join(codec.sealed_parts(pair, PASSWORD, {}))

    def authenticated_frames(self, raw):
        """Inspect/reseal only public synthetic test envelopes to reach decoder refusals."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        n = int.from_bytes(raw[10:14], 'big'); header = raw[14:14+n]
        h = json.loads(header); prefix = bytes.fromhex(h['nonce_prefix'])
        cipher = AESGCM(Scrypt(salt=bytes.fromhex(h['salt']), length=32,
                             n=32768, r=8, p=1).derive(PASSWORD))
        frames = []; offset = 14+n
        while offset < len(raw):
            kind, codec, size, ct_size = struct.unpack('>cBII', raw[offset:offset+10])
            index = len(frames); ct = raw[offset+10:offset+10+ct_size]
            aad = raw[:10]+header+kind+struct.pack('>IBII', index, codec, size, ct_size-16)
            data = cipher.decrypt(prefix+struct.pack('>I', index), ct, aad)
            frames.append([kind, codec, size, data]); offset += 10+ct_size
        def rebuild(values):
            result = [raw[:14+n]]
            for index, (kind, codec, size, data) in enumerate(values):
                aad = raw[:10]+header+kind+struct.pack('>IBII', index, codec, size, len(data))
                ct = cipher.encrypt(prefix+struct.pack('>I', index), data, aad)
                result.append(struct.pack('>cBII', kind, codec, size, len(ct))+ct)
            return b''.join(result)
        return frames, rebuild

    def refuses(self, raw, message=None):
        self.bp.write_bytes(raw); self.bp.chmod(0o600)
        context = self.assertRaisesRegex(ValueError, message) if message else self.assertRaises(ValueError)
        with context:
            self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy, PASSWORD)
        self.assertFalse(self.ap.exists())

    def test_explicit_v3_roundtrips_original_claim_hold_and_recovery_only_archive(self):
        self.claim()
        before = self.rows()
        original = self.w.recover(self.raven, **self.select())
        try:
            result = self.api.backup(self.d, self.bp, PASSWORD, format_version=3)
        except ValueError as exc:
            self.fail('explicit compressed v3 is unavailable: '+str(exc))
        self.assertEqual(result['backup_format_version'], 3)
        result = self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy, PASSWORD)
        self.assertEqual(result['backup_format_version'], 3)
        with self.api.RecoveryArchive(self.ap, self.c.genesis, self.c.policy) as archive:
            view = archive.inspect()
            self.assertEqual(view['pending_debit_units'], '100')
            claim = next(d for d in view['decisions'] if d['id'] == self.raven)
            self.assertTrue(claim['attempt_recorded'])
            self.assertEqual(claim['transport_observation'], 'unresolved')
            self.assertFalse(claim['safe_to_resend'])
            self.assertEqual(archive.recover(self.raven, **self.select()), original)
            for flag in ('signing_enabled', 'dispatch_enabled', 'trust_policy_renewed',
                         'current_spending_authority', 'automatic_resend'):
                self.assertFalse(view[flag], flag)
        self.assertEqual(self.rows(), before)

    def test_same_frozen_capture_has_exact_v2_stream_manifest_and_snapshot_id(self):
        import p4_custody_stream as stream
        codec = self.compressed(); before = self.rows()
        with stream.capture_pair(self.d) as pair:
            original = tuple(stream.plain_chunks(pair)); v2 = {}; v3 = {}
            a = b''.join(stream.sealed_parts(pair, PASSWORD, v2))
            b = b''.join(codec.sealed_parts(pair, PASSWORD, v3))
            decoded, manifest = codec.unseal(io.BytesIO(b), PASSWORD)
            self.assertEqual(decoded, original)
            self.assertEqual(v3['manifest'], v2['manifest'])
            self.assertEqual(v3['snapshot_id'], v2['snapshot_id'])
            self.assertEqual(manifest, v2['manifest'])
            self.assertLess(len(b), len(a), 'actual complete journal backup did not shrink')
            with stream.stream_pair(decoded) as recovered:
                for source, table, _, _ in stream.TABLES:
                    self.assertEqual(tuple(pair[source].execute('SELECT * FROM '+table+' ORDER BY 1')),
                                     tuple(recovered[source].execute('SELECT * FROM '+table+' ORDER BY 1')))
        self.assertEqual(self.rows(), before)

    def test_raw_fallback_preserves_incompressible_full_size_chunk(self):
        codec = self.compressed(); raw = os.urandom(1024*1024)
        kind, encoded = codec.encode_chunk(raw)
        self.assertEqual(kind, 0); self.assertEqual(encoded, raw)
        self.assertEqual(codec.decode_chunk(kind, encoded, len(raw)), raw)

    def test_identical_frozen_pair_has_fresh_encryption_and_same_snapshot_identity(self):
        import p4_custody_stream as stream
        codec = self.compressed()
        with stream.capture_pair(self.d) as pair:
            a = {}; b = {}
            first = b''.join(codec.sealed_parts(pair,PASSWORD,a))
            second = b''.join(codec.sealed_parts(pair,PASSWORD,b))
        def header(raw): return json.loads(raw[14:14+int.from_bytes(raw[10:14],'big')])
        left, right = header(first), header(second)
        self.assertNotEqual(left['salt'],right['salt'])
        self.assertNotEqual(left['nonce_prefix'],right['nonce_prefix'])
        self.assertNotEqual(first,second)
        self.assertEqual(a['manifest'],b['manifest'])
        self.assertEqual(a['snapshot_id'],b['snapshot_id'])

    def test_compressed_chunk_roundtrips_and_stops_at_declared_output_limit(self):
        codec = self.compressed(); raw = b'bounded complete journal evidence\n' * 10000
        kind, encoded = codec.encode_chunk(raw)
        self.assertEqual(kind, 1); self.assertLess(len(encoded), len(raw))
        self.assertEqual(codec.decode_chunk(kind, encoded, len(raw)), raw)
        with self.assertRaisesRegex(ValueError, 'length|output'):
            codec.decode_chunk(kind, zlib.compress(raw+b'x'), len(raw))

    def test_maximum_chunk_output_overflow_is_refused(self):
        codec = self.compressed()
        with self.assertRaisesRegex(ValueError, 'length|output'):
            codec.decode_chunk(1, zlib.compress(b'x'*(1024*1024+1)), 1024*1024)

    def test_zlib_eof_tails_concatenation_and_dictionary_refuse(self):
        codec = self.compressed(); raw = b'exact evidence line\n'*1000
        good = zlib.compress(raw)
        obj = zlib.compressobj(zdict=b'exact evidence line\n')
        dictionary = obj.compress(raw)+obj.flush()
        for candidate in (good[:-1], good+b'tail', good+good, dictionary):
            with self.subTest(encoded_bytes=len(candidate)), self.assertRaises(ValueError):
                codec.decode_chunk(1, candidate, len(raw))

    def test_raw_lengths_unknown_codecs_and_invalid_exact_types_refuse(self):
        codec = self.compressed()
        for kind, encoded, size in ((0,b'x',2),(0,b'xx',1),(2,b'x',1),
                                     (True,b'x',1),(1,b'x',True),(0,b'',0),
                                     (0,b'x',1024*1024+1),(0,'x',1)):
            with self.subTest(codec=kind, size=size), self.assertRaises(ValueError):
                codec.decode_chunk(kind, encoded, size)

    def test_authenticated_compressed_tails_overflow_and_short_output_refuse_no_publication(self):
        frames, rebuild = self.authenticated_frames(self.envelope())
        self.assertEqual(frames[0][1], 1)
        original = frames[0][3]; size = frames[0][2]
        for candidate in (original+b'tail', original+original, original[:-1],
                          zlib.compress(b'x'*(size+1)), zlib.compress(b'x'*(size-1))):
            changed = [list(f) for f in frames]; changed[0][3] = candidate
            self.refuses(rebuild(changed), 'compressed|decompress|output|length')

    def test_authenticated_raw_fallback_and_final_manifest_are_exact(self):
        codec = self.compressed(); frames, rebuild = self.authenticated_frames(self.envelope())
        plain = codec.decode_chunk(frames[0][1], frames[0][3], frames[0][2])
        frames[0][1], frames[0][3] = 0, plain
        decoded, _ = codec.unseal(io.BytesIO(rebuild(frames)), PASSWORD)
        self.assertEqual(b''.join(decoded), plain)
        frames[0][3] += b'x'
        self.refuses(rebuild(frames), 'length')

    def test_wrong_password_tamper_truncation_append_and_frame_mixing_refuse(self):
        codec = self.compressed(); raw = self.envelope()
        self.bp.write_bytes(raw); self.bp.chmod(0o600)
        with self.assertRaises(ValueError):
            self.api.restore_backup(self.bp, self.ap, self.c.genesis, self.c.policy, b'wrong fixture password')
        other = self.envelope(); n = 14+int.from_bytes(raw[10:14], 'big')
        m = 14+int.from_bytes(other[10:14], 'big')
        length = int.from_bytes(raw[n+6:n+10], 'big')
        other_length = int.from_bytes(other[m+6:m+10], 'big')
        mixed = raw[:n]+other[m:m+10+other_length]+raw[n+10+length:]
        damaged = bytearray(raw); damaged[n+10] ^= 1
        for candidate in (bytes(damaged), raw[:-1], raw+b'x', mixed,
                          raw[:n]+raw[n+10+length:],
                          raw[:n]+raw[n:n+10+length]+raw[n:]):
            self.refuses(candidate)
        self.assertFalse(self.ap.exists())

    def test_codec_plaintext_length_and_frame_kind_are_authenticated(self):
        raw = self.envelope(); n = 14+int.from_bytes(raw[10:14], 'big')
        for offset in (n, n+1, n+5):
            changed = bytearray(raw); changed[offset] ^= 1
            self.refuses(bytes(changed))

    def test_inflated_lengths_refuse_before_large_read_or_decryption(self):
        codec = self.compressed(); raw = self.envelope()
        n = 14+int.from_bytes(raw[10:14], 'big')
        class BoundedRead(io.BytesIO):
            def read(inner, size=-1):
                self.assertLessEqual(size, 1024*1024+16, 'declared attacker allocation reached read')
                return super().read(size)
        for offset in (n+2, n+6):
            changed = bytearray(raw); changed[offset:offset+4] = struct.pack('>I',2**31)
            with self.assertRaises(ValueError): codec.unseal(BoundedRead(changed), PASSWORD)

    def test_unsupported_header_parameters_refuse_before_kdf(self):
        codec = self.compressed(); raw = self.envelope(); end = 14+int.from_bytes(raw[10:14], 'big')
        header = json.loads(raw[14:end])
        for field, value in (('schema',True),('schema',4),('codec','gzip'),
                             ('compression_level',9),('window_bits',-15),('chunk_bytes',True),
                             ('nonce_prefix','Z'*16),('kdf',{'name':'scrypt','n':2**30})):
            h = dict(header); h[field] = value; encoded = helpers.encode(h)
            changed = raw[:10]+struct.pack('>I',len(encoded))+encoded+raw[end:]
            with patch.object(codec,'Scrypt',side_effect=AssertionError('unsupported KDF reached')):
                self.refuses(changed)

    def test_authenticated_false_final_commitment_refuses(self):
        frames, rebuild = self.authenticated_frames(self.envelope())
        original = json.loads(frames[-1][3])
        for field, value in (('schema',True),('chunks',0),('stream_bytes',True),
                             ('stream_sha256','0'*64),('row_counts',[0]*7),('blob_bytes',[0]*7)):
            manifest = dict(original); manifest[field] = value; data = helpers.encode(manifest)
            changed = [list(f) for f in frames]; changed[-1][2:] = [len(data),data]
            self.refuses(rebuild(changed), 'commitment|manifest')

    def test_authenticated_altered_original_signature_fails_historical_auditor(self):
        import p4_custody_stream as stream
        codec = self.compressed(); before = self.rows()
        with stream.capture_pair(self.d) as pair:
            raw = pair[0].execute('SELECT payload FROM decisions WHERE decision_id=?',(self.raven,)).fetchone()[0]
            decision = json.loads(raw); packet = json.loads(bytes.fromhex(decision['wire_hex']))
            packet['signature'] = '0'*128; decision['wire_hex'] = helpers.encode(packet).hex()
            pair[0].execute('UPDATE decisions SET payload=? WHERE decision_id=?',
                            (helpers.encode(decision),self.raven))
            candidate = b''.join(codec.sealed_parts(pair,PASSWORD,{}))
        self.refuses(candidate)
        self.assertEqual(self.rows(), before)

    def test_historical_receipt_original_clocks_and_active_constructor_refusal(self):
        import p4_custody_stream as stream
        self.compressed()
        wire = self.w.recover(self.raven, **self.select()); self.c.block([wire])
        evidence = self.c.evidence(); self.d.import_receipt(self.raven,evidence,**self.select())
        self.w.sync(evidence,expected_revision=self.w.status()['revision'])
        self.c.now += 7200*10**9
        before = self.rows(); self.api.backup(self.d,self.bp,PASSWORD,format_version=3)
        self.api.restore_backup(self.bp,self.ap,self.c.genesis,self.c.policy,PASSWORD)
        with self.api.RecoveryArchive(self.ap,self.c.genesis,self.c.policy) as archive:
            view = archive.inspect(); self.assertEqual(view['pending_debit_units'],'40')
            self.assertEqual(helpers.encode(archive.export_receipt(self.raven,**self.select())),helpers.encode(evidence))
            self.assertFalse(view['trust_policy_renewed'])
            with stream.stream_pair(archive._chunks) as pair:
                self.assertEqual(pair[2]['policy'],self.c.policy)
        with self.assertRaises(ValueError):
            helpers.P4Wallet(self.ap,self.c.genesis,self.c.policy,clock=self.c.clock)
        with self.assertRaises(ValueError):
            helpers.P4Delivery(self.wp,self.ap,self.c.genesis,self.c.policy,self.d.endpoint,clock=self.c.clock)
        changed = dict(self.c.policy); changed['trust_period_seconds'] = 7200
        with self.assertRaises(ValueError): self.api.RecoveryArchive(self.ap,self.c.genesis,changed)
        self.assertEqual(self.rows(),before)

    def test_v3_sidecar_existing_output_and_fsync_failures_preserve_source(self):
        self.compressed()
        before = self.rows()
        with patch('p4_custody.os.fsync',side_effect=OSError('fixture fsync failure')):
            with self.assertRaises(OSError): self.api.backup(self.d,self.bp,PASSWORD,format_version=3)
        self.assertFalse(self.bp.exists()); self.assertEqual(list(self.root.glob('.1soft-recovery-*.tmp')),[])
        for source in (self.wp,self.dp):
            with self.assertRaises(ValueError):
                self.api.backup(self.d,str(source)+'-journal',PASSWORD,format_version=3)
        self.api.backup(self.d,self.bp,PASSWORD,format_version=3)
        original = self.bp.read_bytes()
        with self.assertRaises(ValueError): self.api.backup(self.d,self.bp,PASSWORD,format_version=3)
        self.assertEqual(self.bp.read_bytes(),original); self.assertEqual(self.rows(),before)

    def test_authenticated_nonfinal_short_chunk_refuses(self):
        frames, rebuild = self.authenticated_frames(self.envelope())
        second = [b'D',0,1,b'x']
        self.refuses(rebuild([frames[0],second,frames[-1]]), 'nonfinal chunk length')

    def test_ordered_frames_cannot_be_reordered_or_duplicated(self):
        raw = self.envelope(); start = 14+int.from_bytes(raw[10:14],'big')
        first_end = start+10+int.from_bytes(raw[start+6:start+10],'big')
        first, final = raw[start:first_end], raw[first_end:]
        self.refuses(raw[:start]+final+first, 'authenticate')
        self.refuses(raw[:start]+first+first+final)

    def test_aggregate_stream_and_chunk_count_bounds_refuse_authenticated_expansion(self):
        codec = self.compressed()
        self.assertEqual(codec.MAX_CHUNKS,146)
        self.assertEqual(codec.MAX_STREAM_BYTES,152329575)
        frames, rebuild = self.authenticated_frames(self.envelope())
        compressed = zlib.compress(b'x'*(1024*1024))
        full = [b'D',1,1024*1024,compressed]
        remainder = 152329575-145*(1024*1024)
        # Bound violations are authenticated codec fixtures, not admitted journals.
        excessive = [full]*145+[[b'D',1,remainder+1,zlib.compress(b'x'*(remainder+1))]]+[frames[-1]]
        self.refuses(rebuild(excessive), 'stream exceeds bound')
        too_many = [full]*145+[[b'D',1,remainder,zlib.compress(b'x'*remainder)],
                              [b'D',0,1,b'x'],frames[-1]]
        self.refuses(rebuild(too_many), 'stream exceeds bound')

    def test_noncanonical_unknown_and_oversized_headers_refuse_before_kdf(self):
        codec = self.compressed(); raw = self.envelope(); end = 14+int.from_bytes(raw[10:14],'big')
        h = json.loads(raw[14:end]); unknown = dict(h); unknown['extra'] = 'refuse'
        for encoded in (json.dumps(h,indent=2).encode(),helpers.encode(unknown)):
            with patch.object(codec,'Scrypt',side_effect=AssertionError('bad header reached KDF')):
                self.refuses(raw[:10]+struct.pack('>I',len(encoded))+encoded+raw[end:])
        with patch.object(codec,'Scrypt',side_effect=AssertionError('oversized header reached KDF')):
            self.refuses(raw[:10]+struct.pack('>I',2**31)+raw[14:])


if __name__ == '__main__': unittest.main()
