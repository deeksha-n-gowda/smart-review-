"""
security/encryption.py — AES-256-GCM Encryption Helper
========================================================
Provides symmetric encryption for code snippets stored in the database.

Why AES-256-GCM?
    - AES-256 gives 256-bit key strength (considered quantum-resistant for now)
    - GCM (Galois/Counter Mode) provides both confidentiality AND integrity
      via an authentication tag — we know if the ciphertext was tampered with
    - Every encryption uses a fresh random 16-byte nonce, so encrypting the
      same file twice produces different ciphertexts (semantic security)

Wire format (stored in CodeFile.encrypted_source):
    [16 bytes: nonce] [16 bytes: GCM auth tag] [N bytes: ciphertext]
    Total overhead: 32 bytes per file

Usage:
    from security.encryption import AESCipher
    from django.conf import settings

    cipher = AESCipher(settings.AES_SECRET_KEY_BYTES)

    # Encrypt
    blob = cipher.encrypt(b"def hello(): pass")

    # Decrypt (returns original bytes)
    plaintext = cipher.decrypt(blob)

    # Convenience: work with strings
    blob = AESCipher.encrypt_string("SELECT * FROM users", settings.AES_SECRET_KEY_BYTES)
    text = AESCipher.decrypt_string(blob, settings.AES_SECRET_KEY_BYTES)

Dependencies:
    pycryptodome >= 3.20.0   (pip install pycryptodome)
    NOTE: It must be pycryptodome, NOT pycrypto — they have the same import
    path (Crypto.*) but pycryptodome is actively maintained and supports GCM.

Author: Capstone Project Team
"""

import os
import logging
from typing import Union

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

logger = logging.getLogger(__name__)

# --- Constants ---
NONCE_SIZE   = 16   # bytes — AES-GCM nonce (also called IV in some docs)
TAG_SIZE     = 16   # bytes — GCM authentication tag (MAC)
HEADER_SIZE  = NONCE_SIZE + TAG_SIZE  # 32 bytes of overhead per ciphertext


class AESCipher:
    """
    Stateless AES-256-GCM cipher wrapper.

    Thread-safe: A new AES cipher object is created for every encrypt/decrypt
    call, so this class can be shared across threads without issue.

    Args:
        key (bytes): A 32-byte (256-bit) symmetric key.

    Raises:
        ValueError: If the key is not exactly 32 bytes.
    """

    def __init__(self, key: bytes):
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError(
                f"AES key must be exactly 32 bytes (256-bit). Got {len(key) if isinstance(key, bytes) else type(key).__name__}."
            )
        self._key = key

    # ------------------------------------------------------------------
    # Core encrypt / decrypt
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypts plaintext bytes using AES-256-GCM with a fresh random nonce.

        Args:
            plaintext: The data to encrypt (e.g. source code as UTF-8 bytes).

        Returns:
            Bytes in the format: [nonce (16)] [tag (16)] [ciphertext (N)]

        Raises:
            TypeError: If plaintext is not bytes.
        """
        if not isinstance(plaintext, bytes):
            raise TypeError(f"plaintext must be bytes, not {type(plaintext).__name__}")

        # Generate a cryptographically secure random nonce for this message
        nonce = get_random_bytes(NONCE_SIZE)

        # Create a new AES-GCM cipher instance — never reuse nonces with the same key!
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)

        # Encrypt and finalize — digest() returns the 16-byte authentication tag
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        # Pack: nonce || tag || ciphertext
        blob = nonce + tag + ciphertext
        logger.debug(
            "AESCipher.encrypt: %d bytes plaintext → %d bytes ciphertext (overhead: %d bytes)",
            len(plaintext), len(blob), HEADER_SIZE
        )
        return blob

    def decrypt(self, blob: bytes) -> bytes:
        """
        Decrypts a blob produced by encrypt().

        Args:
            blob: Bytes in the format [nonce (16)] [tag (16)] [ciphertext (N)]

        Returns:
            The original plaintext bytes.

        Raises:
            ValueError: If the blob is too short to contain a valid header.
            ValueError: If the GCM authentication tag verification fails
                        (data was tampered with, or the wrong key was used).
        """
        if len(blob) < HEADER_SIZE:
            raise ValueError(
                f"Ciphertext blob is too short ({len(blob)} bytes). "
                f"Expected at least {HEADER_SIZE} bytes (nonce + tag)."
            )

        # Unpack the header
        nonce      = blob[:NONCE_SIZE]
        tag        = blob[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
        ciphertext = blob[NONCE_SIZE + TAG_SIZE:]

        # Re-create the cipher with the same nonce
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=nonce)

        try:
            # decrypt_and_verify raises ValueError if the tag doesn't match
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as e:
            # This happens when the key is wrong OR the data was tampered with.
            # We re-raise with a cleaner message — don't expose internal details.
            logger.error("AESCipher.decrypt: Authentication tag verification failed.")
            raise ValueError(
                "Decryption failed: authentication tag mismatch. "
                "The data may have been tampered with, or the wrong key was used."
            ) from e

        logger.debug("AESCipher.decrypt: %d bytes ciphertext → %d bytes plaintext", len(ciphertext), len(plaintext))
        return plaintext

    # ------------------------------------------------------------------
    # String convenience methods
    # ------------------------------------------------------------------

    def encrypt_string(self, text: str, encoding: str = "utf-8") -> bytes:
        """
        Convenience wrapper: encrypts a Python string.

        Args:
            text:     The string to encrypt.
            encoding: Character encoding to use (default: utf-8).

        Returns:
            Encrypted blob bytes.
        """
        return self.encrypt(text.encode(encoding))

    def decrypt_string(self, blob: bytes, encoding: str = "utf-8") -> str:
        """
        Convenience wrapper: decrypts a blob and returns a Python string.

        Args:
            blob:     The encrypted blob produced by encrypt_string().
            encoding: Character encoding used during encryption.

        Returns:
            The original plaintext string.
        """
        return self.decrypt(blob).decode(encoding)

    # ------------------------------------------------------------------
    # Static / class-level convenience methods
    # ------------------------------------------------------------------

    @staticmethod
    def generate_key() -> bytes:
        """
        Generates a cryptographically secure random 256-bit (32-byte) AES key.

        Usage (in a Django management command or setup script):
            key_bytes = AESCipher.generate_key()
            key_b64 = base64.b64encode(key_bytes).decode()
            print(f"AES_SECRET_KEY={key_b64}")

        Returns:
            32 random bytes suitable for use as an AES-256 key.
        """
        return get_random_bytes(32)

    @staticmethod
    def key_to_base64(key: bytes) -> str:
        """Encodes a key to base64 string for storage in .env files."""
        import base64
        return base64.b64encode(key).decode("ascii")

    @staticmethod
    def key_from_base64(b64_string: str) -> bytes:
        """Decodes a base64-encoded key back to bytes."""
        import base64
        key = base64.b64decode(b64_string)
        if len(key) != 32:
            raise ValueError(f"Decoded key is {len(key)} bytes; expected 32.")
        return key

    # ------------------------------------------------------------------
    # Self-test
    # ------------------------------------------------------------------

    def self_test(self) -> bool:
        """
        Runs a quick round-trip test to verify the cipher is working correctly.
        Useful in startup checks or management commands.

        Returns:
            True if the test passes.

        Raises:
            AssertionError: If something is broken.
        """
        test_message = b"The quick brown fox jumps over the lazy dog. \x00\x01\x02\xff"

        # Encrypt twice — should produce different ciphertexts (due to random nonce)
        blob1 = self.encrypt(test_message)
        blob2 = self.encrypt(test_message)
        assert blob1 != blob2, "Two encryptions of the same message produced identical output — nonce reuse!"

        # Decrypt both and verify
        assert self.decrypt(blob1) == test_message, "Decryption of blob1 failed!"
        assert self.decrypt(blob2) == test_message, "Decryption of blob2 failed!"

        # Tamper test — flipping a byte in the ciphertext should cause tag failure
        tampered = bytearray(blob1)
        tampered[HEADER_SIZE] ^= 0xFF   # Flip bits in the first ciphertext byte
        try:
            self.decrypt(bytes(tampered))
            raise AssertionError("Tampered ciphertext was accepted — GCM integrity check failed!")
        except ValueError:
            pass  # Expected: tampered data should raise ValueError

        logger.info("AESCipher self-test passed.")
        return True


# ---------------------------------------------------------------------------
# Module-level helpers (for quick usage without instantiation)
# ---------------------------------------------------------------------------

def encrypt_code(source_code: str, key: bytes) -> bytes:
    """
    Module-level shortcut to encrypt a source code string.

    Args:
        source_code: Raw source code as a string.
        key:         32-byte AES key.

    Returns:
        Encrypted blob bytes.
    """
    return AESCipher(key).encrypt_string(source_code)


def decrypt_code(blob: bytes, key: bytes) -> str:
    """
    Module-level shortcut to decrypt an encrypted code blob.

    Args:
        blob: Encrypted bytes from encrypt_code().
        key:  The same 32-byte AES key used during encryption.

    Returns:
        The original source code string.
    """
    return AESCipher(key).decrypt_string(blob)


# ---------------------------------------------------------------------------
# Quick CLI test — run directly: python encryption.py
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import base64

    print("=== AES-256-GCM Encryption Self-Test ===\n")

    # Generate a fresh key
    key = AESCipher.generate_key()
    key_b64 = AESCipher.key_to_base64(key)
    print(f"Generated key (base64): {key_b64}")
    print(f"Key length: {len(key)} bytes ({len(key) * 8} bits)\n")

    cipher = AESCipher(key)

    # Run self-test
    cipher.self_test()

    # Demo
    sample_code = '''
def login(username, password):
    # WARNING: SQL Injection vulnerability!
    query = "SELECT * FROM users WHERE name='" + username + "'"
    return db.execute(query)
'''.strip()

    print(f"Original ({len(sample_code)} bytes):\n{sample_code}\n")

    blob = cipher.encrypt_string(sample_code)
    print(f"Encrypted ({len(blob)} bytes, base64 preview):")
    print(base64.b64encode(blob[:48]).decode() + "...\n")

    recovered = cipher.decrypt_string(blob)
    print(f"Decrypted:\n{recovered}\n")

    assert recovered == sample_code, "Round-trip failed!"
    print("✓ Round-trip test passed.")
    print(f"✓ Overhead: {HEADER_SIZE} bytes (nonce: {NONCE_SIZE}, tag: {TAG_SIZE})")
    print("\nAdd this to your .env file:")
    print(f"AES_SECRET_KEY={key_b64}")
