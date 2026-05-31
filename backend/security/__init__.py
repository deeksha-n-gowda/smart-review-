"""
security/ — Security utilities for the AI Code Review Assistant.

Modules:
    encryption.py  — AES-256-GCM cipher for protecting code snippets.
"""

from .encryption import AESCipher, encrypt_code, decrypt_code

__all__ = ["AESCipher", "encrypt_code", "decrypt_code"]
