"""Invoice confidentiality contract. No payment signatures, network or key storage."""
import base64
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
try:
    import invoice_privacy as module
except ModuleNotFoundError:
    module = None

KEY = bytes(range(32))
NONCE = bytes(range(12))
GENESIS = "a" * 64
REQUEST = "b" * 64
CONTENT = {"description": "Frame 01", "contact": "studio@example.test", "content": "One render"}
# External AESGCM fixture, generated from these literal bytes with cryptography 46.0.4.
AAD = b'{"algorithm":"AES-256-GCM","format":"1soft/private-invoice/v1","genesis_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","request_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","schema":1}'
PLAINTEXT = b'{"contact":"studio@example.test","content":"One render","description":"Frame 01"}'
FIXTURE = b'{"algorithm":"AES-256-GCM","ciphertext_b64":"PCC1dKuRo3j5Y62pwp0NCeq5x1GIGjIMVALL8XgadJAtMs2TwbV39gCGRc/H6U0YnDwO6T+kgfYd809qe5GcnoRVqRTx6wQnbjXHC8+/P8pFQjQ8BhZY1nGBDkPspQoa7A==","format":"1soft/private-invoice/v1","genesis_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","nonce_b64":"AAECAwQFBgcICQoL","request_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","schema":1}'


def serialize(value):
    """Adversarial fixture writer, separate from the production implementation."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()


def altered(field, value):
    envelope = json.loads(FIXTURE)
    envelope[field] = value
    return serialize(envelope)


def encrypted_plaintext(raw):
    envelope = json.loads(FIXTURE)
    envelope["ciphertext_b64"] = base64.b64encode(AESGCM(KEY).encrypt(NONCE, raw, AAD)).decode()
    return serialize(envelope)


class InvoicePrivacy(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(module, "invoice confidentiality implementation is missing")

    def encrypt(self, content=CONTENT, **overrides):
        args = {"key": KEY, "genesis_sha256": GENESIS, "request_sha256": REQUEST}
        args.update(overrides)
        return module.encrypt_invoice(content, **args)

    def decrypt(self, envelope=FIXTURE, **overrides):
        args = {"key": KEY, "genesis_sha256": GENESIS, "request_sha256": REQUEST}
        args.update(overrides)
        return module.decrypt_invoice(envelope, **args)

    def test_encrypt_matches_independent_context_bound_fixture(self):
        # Catches changing the AAD domain, omitting context or encoding noncanonical bytes.
        with patch("secrets.token_bytes", return_value=NONCE):
            self.assertEqual(self.encrypt(), FIXTURE)

    def test_decrypt_accepts_independent_fixture_and_returns_detached_content(self):
        # Catches failure to authenticate/decode the documented interoperable envelope.
        decoded = self.decrypt()
        self.assertEqual(decoded, CONTENT)
        decoded["description"] = "Changed"
        self.assertEqual(self.decrypt()["description"], "Frame 01")

    def test_ciphertext_and_tag_tampering_returns_no_plaintext(self):
        original = base64.b64decode(json.loads(FIXTURE)["ciphertext_b64"])
        for index in [0, len(original) - 1]:
            corrupted = bytearray(original)
            corrupted[index] ^= 1
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.decrypt(altered("ciphertext_b64", base64.b64encode(corrupted).decode()))

    def test_nonce_tampering_returns_no_plaintext(self):
        # Catches passing an ignored/constant nonce to decryption.
        with self.assertRaises(ValueError):
            self.decrypt(altered("nonce_b64", base64.b64encode(b"z" * 12).decode()))

    def test_wrong_key_returns_generic_error_without_secret_material(self):
        with self.assertRaises(ValueError) as raised:
            self.decrypt(key=b"x" * 32)
        message = str(raised.exception)
        for secret in ["Frame 01", "studio@example.test", "One render", KEY.hex()]:
            self.assertNotIn(secret, message)

    def test_expected_context_must_match_envelope(self):
        # Catches trusting a self-selected genesis or request digest from the envelope.
        for args in [{"genesis_sha256": "c" * 64}, {"request_sha256": "c" * 64}]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.decrypt(**args)

    def test_relabeling_context_cannot_reauthenticate_ciphertext(self):
        # Catches checking labels without actually including the labels in AEAD AAD.
        for field in ["genesis_sha256", "request_sha256"]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.decrypt(altered(field, "c" * 64), **{field: "c" * 64})

    def test_ciphertext_does_not_expose_invoice_or_key(self):
        raw = self.encrypt()
        for secret in ["Frame 01", "studio@example.test", "One render"]:
            self.assertNotIn(secret.encode(), raw)
        fields = json.loads(raw)
        self.assertEqual(set(fields), {"algorithm", "ciphertext_b64", "format", "genesis_sha256",
                                       "nonce_b64", "request_sha256", "schema"})
        self.assertNotIn(KEY, raw)
        self.assertEqual(self.decrypt(raw), CONTENT)

    def test_real_random_nonces_do_not_repeat_across_encryptions(self):
        # Catches replacing secure randomness with a fixed or request-derived nonce.
        envelopes = [self.encrypt() for _ in range(64)]
        self.assertEqual(len({json.loads(raw)["nonce_b64"] for raw in envelopes}), 64)
        for raw in envelopes:
            self.assertEqual(self.decrypt(raw), CONTENT)

    def test_caller_cannot_choose_nonce(self):
        # Catches introducing a public nonce override that permits accidental reuse.
        with self.assertRaises(TypeError):
            self.encrypt(nonce=NONCE)

    def test_testside_nonce_reuse_fixture_exposes_the_unsafe_repeat(self):
        # A characterization of the unavoidable RNG/caller trust boundary:
        # repeated (key, nonce) makes encryption deterministic, not safe/reusable.
        with patch("secrets.token_bytes", return_value=NONCE):
            self.assertEqual(self.encrypt(), self.encrypt())
        # This fixture does not claim cross-process reuse detection or offer a nonce API.

    def test_invalid_key_types_and_lengths_are_rejected(self):
        for key in [None, True, "", bytearray(KEY), memoryview(KEY), b"", b"x" * 16, b"x" * 31, b"x" * 33]:
            for call in [self.encrypt, self.decrypt]:
                with self.subTest(key_type=type(key).__name__, length=len(key) if hasattr(key, "__len__") else None,
                                  call=call.__name__), self.assertRaises(ValueError):
                    call(key=key)

    def test_context_is_exact_lowercase_sha256_text(self):
        for digest in [None, True, b"a" * 64, "a" * 63, "a" * 65, "A" * 64, "g" * 64, "é" * 64]:
            for field in ["genesis_sha256", "request_sha256"]:
                for call in [self.encrypt, self.decrypt]:
                    with self.subTest(field=field, call=call.__name__), self.assertRaises(ValueError):
                        call(**{field: digest})

    def test_content_fields_are_exact_strings_without_extra_authority(self):
        invalid = [None, [], PLAINTEXT, {}, {**CONTENT, "units": "100"}, {**CONTENT, "recipient": "other"},
                   {**CONTENT, "contact": None}, {**CONTENT, "content": True},
                   {**CONTENT, "description": {"nested": "data"}}]
        for content in invalid:
            with self.subTest(content_type=type(content).__name__), self.assertRaises(ValueError):
                self.encrypt(content)

    def test_utf8_and_individual_field_bounds_are_enforced(self):
        for field, size in [("description", 1024), ("contact", 512), ("content", 8192)]:
            accepted = {**CONTENT, field: "x" * size}
            self.assertEqual(self.decrypt(self.encrypt(accepted)), accepted)
            for bad in ["x" * (size + 1), "é" * (size // 2 + 1)]:
                with self.subTest(field=field), self.assertRaises(ValueError):
                    self.encrypt({**CONTENT, field: bad})
        for field in CONTENT:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.encrypt({**CONTENT, field: "\ud800"})

    def test_control_characters_are_rejected_except_content_newline_and_tab(self):
        content = {**CONTENT, "content": "Line 1\nLine 2\tindent"}
        self.assertEqual(self.decrypt(self.encrypt(content)), content)
        for field in CONTENT:
            for bad in ["bad\x00", "bad\x7f", "bad\r"]:
                with self.subTest(field=field), self.assertRaises(ValueError):
                    self.encrypt({**CONTENT, field: bad})
        for field in ["description", "contact"]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.encrypt({**CONTENT, field: "bad\n"})

    def test_ciphertext_input_must_be_bounded_canonical_bytes(self):
        values = [FIXTURE.decode(), bytearray(FIXTURE), memoryview(FIXTURE), b"",
                  FIXTURE + b" ", b" " + FIXTURE, b"\xff", b" " * 14001,
                  b"[" * 1500 + b"]" * 1500, json.dumps(json.loads(FIXTURE), indent=2).encode()]
        for value in values:
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                self.decrypt(value)

    def test_envelope_rejects_duplicates_unknown_fields_and_wrong_types(self):
        values = [FIXTURE.replace(b'"schema":1', b'"schema":1,"schema":1'),
                  altered("schema", True), altered("schema", 2), altered("schema", 1.0),
                  altered("format", "other"), altered("algorithm", "AES-128-GCM"),
                  altered("nonce_b64", []), altered("ciphertext_b64", 1),
                  serialize({**json.loads(FIXTURE), "paid": True})]
        missing = json.loads(FIXTURE)
        del missing["schema"]
        values.append(serialize(missing))
        for value in values:
            with self.subTest(), self.assertRaises(ValueError):
                self.decrypt(value)

    def test_base64_is_exact_padded_standard_encoding_with_valid_lengths(self):
        # Catches permissive decoders, nonzero padding bits and accepting truncated tags.
        for field in ["nonce_b64", "ciphertext_b64"]:
            current = json.loads(FIXTURE)[field]
            invalid = ["", "???", current + "\n", current + "=", current[:-1], "Zg==",
                       "-_8=", "Zg======", "Zh=="]
            for value in invalid:
                with self.subTest(field=field, value=value[:20]), self.assertRaises(ValueError):
                    self.decrypt(altered(field, value))
        with self.assertRaises(ValueError):
            self.decrypt(altered("ciphertext_b64", base64.b64encode(b"x" * 10017).decode()))

    def test_authenticated_plaintext_still_requires_canonical_exact_shape_and_bounds(self):
        # A key-holder can encrypt malformed data; authentication alone is insufficient.
        values = [PLAINTEXT + b" ", PLAINTEXT.replace(b'"contact":', b'"contact":null,"contact":'),
                  b'{"contact":"","content":"","description":1}',
                  b'{"contact":"","content":"","description":"","paid":true}',
                  b"\xff", b" " * 10001,
                  serialize({**CONTENT, "contact": "x" * 513}),
                  serialize({**CONTENT, "description": "bad\u0000"})]
        for value in values:
            with self.subTest(), self.assertRaises(ValueError):
                self.decrypt(encrypted_plaintext(value))

    def test_invalid_entropy_result_is_refused_without_returning_envelope(self):
        # Catches failure to enforce 96-bit nonce length if the trusted RNG is broken.
        for nonce in [b"", b"x" * 11, b"x" * 13, bytearray(NONCE)]:
            with patch("secrets.token_bytes", return_value=nonce), self.assertRaises(ValueError):
                self.encrypt()


    def validate(self, envelope=FIXTURE, **overrides):
        validator = getattr(module, "validate_envelope", None)
        self.assertTrue(callable(validator), "key-free envelope validation is missing")
        args = {"genesis_sha256": GENESIS, "request_sha256": REQUEST}
        args.update(overrides)
        return validator(envelope, **args)

    def test_key_free_validator_returns_exact_fixture_bytes(self):
        # Catches decoding/reconstructing or modifying the persisted ciphertext identity.
        self.assertEqual(self.validate(), FIXTURE)

    def test_key_free_validation_does_not_claim_ciphertext_authenticity(self):
        # An altered but well-shaped ciphertext is structurally valid until key-based AEAD.
        ciphertext = bytearray(base64.b64decode(json.loads(FIXTURE)["ciphertext_b64"]))
        ciphertext[0] ^= 1
        changed = altered("ciphertext_b64", base64.b64encode(ciphertext).decode())
        self.assertEqual(self.validate(changed), changed)
        with self.assertRaises(ValueError):
            self.decrypt(changed)

    def test_key_free_validator_requires_independently_expected_context(self):
        # Catches trusting context learned only from the packet during catalog recovery.
        for field in ["genesis_sha256", "request_sha256"]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(**{field: "c" * 64})
            for digest in [None, b"a" * 64, "A" * 64, "a" * 63]:
                with self.subTest(field=field, digest_type=type(digest).__name__), self.assertRaises(ValueError):
                    self.validate(**{field: digest})

    def test_key_free_validator_rejects_unknown_algorithm_format_schema_and_fields(self):
        # Catches catalog claims that accept context labels without a versioned AEAD shape.
        values = [altered("algorithm", "plaintext"), altered("format", "other"),
                  altered("schema", True), altered("schema", 1.0), altered("schema", 2),
                  serialize({"genesis_sha256": GENESIS, "request_sha256": REQUEST}),
                  serialize({**json.loads(FIXTURE), "description": "plain secret"})]
        for value in values:
            with self.subTest(), self.assertRaises(ValueError):
                self.validate(value)

    def test_key_free_validator_rejects_noncanonical_duplicate_and_nonbyte_inputs(self):
        values = [FIXTURE + b" ", FIXTURE.replace(b'"schema":1', b'"schema":1,"schema":1'),
                  json.dumps(json.loads(FIXTURE), indent=2).encode(),
                  FIXTURE.decode(), bytearray(FIXTURE), b" " * 14001, b"\xff"]
        for value in values:
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                self.validate(value)

    def test_key_free_validator_requires_exact_96_bit_nonce(self):
        for nonce in [b"", b"n" * 11, b"n" * 13]:
            with self.subTest(length=len(nonce)), self.assertRaises(ValueError):
                self.validate(altered("nonce_b64", base64.b64encode(nonce).decode()))
        for value in [[], "AAECAwQFBgcICQoL\n", "???", "é" * 16]:
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                self.validate(altered("nonce_b64", value))

    def test_key_free_validator_enforces_ciphertext_bounds_without_key_access(self):
        # Catches oversized work or truncated tags accepted on the storage inspection path.
        for size in [16, 10016]:
            raw = altered("ciphertext_b64", base64.b64encode(b"x" * size).decode())
            self.assertEqual(self.validate(raw), raw)
        for size in [0, 15, 10017]:
            with self.subTest(size=size), self.assertRaises(ValueError):
                self.validate(altered("ciphertext_b64", base64.b64encode(b"x" * size).decode()))

    def test_key_free_validator_requires_canonical_base64_padding_bits(self):
        # This alternate text decodes to the same full-length ciphertext; validate=True alone misses it.
        current = json.loads(FIXTURE)["ciphertext_b64"]
        noncanonical = current[:-3] + "B=="
        self.assertEqual(base64.b64decode(noncanonical), base64.b64decode(current))
        for value in [noncanonical, current + "=", current + "\n", current.rstrip("="),
                      "-_8=", 1, None]:
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ValueError):
                self.validate(altered("ciphertext_b64", value))


if __name__ == "__main__":
    unittest.main()

