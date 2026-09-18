"""
tests/test_encryption.py — AES-256-GCM Encryption Unit Tests
=============================================================
Tests the security.encryption module end-to-end.

Run with:
    cd backend
    pytest tests/test_encryption.py -v

Or as part of the full suite:
    pytest
"""

import os
import base64
import pytest

from security.encryption import AESCipher, encrypt_code, decrypt_code, NONCE_SIZE, TAG_SIZE, HEADER_SIZE


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def key():
    """Returns a fresh random 32-byte AES key for each test."""
    return AESCipher.generate_key()


@pytest.fixture
def cipher(key):
    """Returns an AESCipher instance with a random key."""
    return AESCipher(key)


# ---------------------------------------------------------------------------
# Key validation
# ---------------------------------------------------------------------------

class TestKeyValidation:

    def test_rejects_short_key(self):
        with pytest.raises(ValueError, match="32 bytes"):
            AESCipher(b"tooshort")

    def test_rejects_long_key(self):
        with pytest.raises(ValueError, match="32 bytes"):
            AESCipher(os.urandom(64))

    def test_rejects_string_key(self):
        with pytest.raises((ValueError, TypeError)):
            AESCipher("not bytes at all")  # type: ignore

    def test_accepts_32_byte_key(self, key):
        cipher = AESCipher(key)
        assert cipher is not None

    def test_generate_key_is_32_bytes(self):
        key = AESCipher.generate_key()
        assert len(key) == 32

    def test_generate_key_is_random(self):
        k1 = AESCipher.generate_key()
        k2 = AESCipher.generate_key()
        assert k1 != k2  # Astronomically unlikely to be equal

    def test_key_roundtrip_base64(self):
        key   = AESCipher.generate_key()
        b64   = AESCipher.key_to_base64(key)
        back  = AESCipher.key_from_base64(b64)
        assert back == key

    def test_key_from_base64_rejects_wrong_length(self):
        bad = base64.b64encode(b"tooshort").decode()
        with pytest.raises(ValueError):
            AESCipher.key_from_base64(bad)


# ---------------------------------------------------------------------------
# Basic encryption / decryption
# ---------------------------------------------------------------------------

class TestEncryptDecrypt:

    def test_encrypt_returns_bytes(self, cipher):
        result = cipher.encrypt(b"hello world")
        assert isinstance(result, bytes)

    def test_decrypt_recovers_plaintext(self, cipher):
        plaintext = b"The quick brown fox jumps over the lazy dog"
        blob = cipher.encrypt(plaintext)
        assert cipher.decrypt(blob) == plaintext

    def test_empty_string(self, cipher):
        blob = cipher.encrypt(b"")
        assert cipher.decrypt(blob) == b""

    def test_single_byte(self, cipher):
        blob = cipher.encrypt(b"\xff")
        assert cipher.decrypt(blob) == b"\xff"

    def test_binary_data(self, cipher):
        data = bytes(range(256))
        blob = cipher.encrypt(data)
        assert cipher.decrypt(blob) == data

    def test_large_payload(self, cipher):
        data = os.urandom(512 * 1024)   # 512 KB
        blob = cipher.encrypt(data)
        assert cipher.decrypt(blob) == data

    def test_unicode_source_code(self, cipher):
        source = "# 日本語コメント\ndef greet():\n    print('こんにちは')\n"
        blob = cipher.encrypt(source.encode("utf-8"))
        assert cipher.decrypt(blob).decode("utf-8") == source


# ---------------------------------------------------------------------------
# Nonce uniqueness (semantic security)
# ---------------------------------------------------------------------------

class TestNonceUniqueness:

    def test_same_plaintext_different_ciphertext(self, cipher):
        pt    = b"repeated message"
        blob1 = cipher.encrypt(pt)
        blob2 = cipher.encrypt(pt)
        assert blob1 != blob2  # Different nonces → different ciphertexts

    def test_nonce_extracted_correctly(self, cipher):
        blob  = cipher.encrypt(b"test")
        nonce = blob[:NONCE_SIZE]
        assert len(nonce) == NONCE_SIZE

    def test_header_size_constant(self):
        assert HEADER_SIZE == NONCE_SIZE + TAG_SIZE
        assert HEADER_SIZE == 32


# ---------------------------------------------------------------------------
# Tamper detection (GCM authentication tag)
# ---------------------------------------------------------------------------

class TestTamperDetection:

    def test_flip_ciphertext_byte_rejected(self, cipher):
        blob       = bytearray(cipher.encrypt(b"important data"))
        blob[HEADER_SIZE] ^= 0xFF   # Flip first ciphertext byte
        with pytest.raises(ValueError, match="authentication tag"):
            cipher.decrypt(bytes(blob))

    def test_flip_tag_byte_rejected(self, cipher):
        blob     = bytearray(cipher.encrypt(b"important data"))
        blob[NONCE_SIZE] ^= 0x01    # Flip first byte of the auth tag
        with pytest.raises(ValueError, match="authentication tag"):
            cipher.decrypt(bytes(blob))

    def test_truncated_ciphertext_rejected(self, cipher):
        blob = cipher.encrypt(b"hello")
        with pytest.raises(ValueError):
            cipher.decrypt(blob[:10])   # Way too short

    def test_wrong_key_rejected(self):
        key1   = AESCipher.generate_key()
        key2   = AESCipher.generate_key()
        blob   = AESCipher(key1).encrypt(b"secret")
        with pytest.raises(ValueError):
            AESCipher(key2).decrypt(blob)

    def test_empty_blob_rejected(self, cipher):
        with pytest.raises(ValueError):
            cipher.decrypt(b"")

    def test_blob_below_header_size_rejected(self, cipher):
        with pytest.raises(ValueError):
            cipher.decrypt(os.urandom(HEADER_SIZE - 1))


# ---------------------------------------------------------------------------
# String convenience methods
# ---------------------------------------------------------------------------

class TestStringMethods:

    def test_encrypt_string_roundtrip(self, cipher):
        text = "def login(user, pw):\n    return True"
        blob = cipher.encrypt_string(text)
        assert cipher.decrypt_string(blob) == text

    def test_encrypt_string_encoding(self, cipher):
        text = "café résumé naïve"
        blob = cipher.encrypt_string(text, encoding="utf-8")
        assert cipher.decrypt_string(blob, encoding="utf-8") == text

    def test_encrypt_string_returns_bytes(self, cipher):
        assert isinstance(cipher.encrypt_string("hello"), bytes)


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

class TestModuleHelpers:

    def test_encrypt_code_decrypt_code(self):
        key    = AESCipher.generate_key()
        source = "import os\nos.system('ls')\n"
        blob   = encrypt_code(source, key)
        assert decrypt_code(blob, key) == source

    def test_encrypt_code_different_outputs(self):
        key    = AESCipher.generate_key()
        source = "x = 1"
        b1 = encrypt_code(source, key)
        b2 = encrypt_code(source, key)
        assert b1 != b2  # Different nonces

    def test_overhead_is_header_size(self):
        key    = AESCipher.generate_key()
        source = "hello"
        blob   = encrypt_code(source, key)
        assert len(blob) == len(source.encode()) + HEADER_SIZE


# ---------------------------------------------------------------------------
# Self-test method
# ---------------------------------------------------------------------------

class TestSelfTest:

    def test_self_test_passes(self, cipher):
        assert cipher.self_test() is True
