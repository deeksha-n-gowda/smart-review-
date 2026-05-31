"""
core/management/commands/generate_aes_key.py
============================================
Management command to generate a secure AES-256 key and print the
.env line ready to paste.

Usage:
    python manage.py generate_aes_key

Output:
    AES_SECRET_KEY=<base64-encoded-32-byte-key>

Optionally writes directly to .env:
    python manage.py generate_aes_key --write
"""

import base64
from pathlib import Path

from django.core.management.base import BaseCommand

from security.encryption import AESCipher


class Command(BaseCommand):
    help = "Generate a secure AES-256 key for the AES_SECRET_KEY .env variable."

    def add_arguments(self, parser):
        parser.add_argument(
            "--write",
            action="store_true",
            help="Append (or update) AES_SECRET_KEY in the project root .env file.",
        )
        parser.add_argument(
            "--test",
            action="store_true",
            help="After generating the key, run the cipher self-test to verify it works.",
        )

    def handle(self, *args, **options):
        # Generate a fresh 256-bit key
        key_bytes = AESCipher.generate_key()
        key_b64   = AESCipher.key_to_base64(key_bytes)

        self.stdout.write("\n" + self.style.SUCCESS("✓ Generated AES-256 key"))
        self.stdout.write(f"\n  Add this to your .env file:\n")
        self.stdout.write(self.style.WARNING(f"  AES_SECRET_KEY={key_b64}\n"))

        # Optional: run self-test with the new key
        if options["test"]:
            cipher = AESCipher(key_bytes)
            cipher.self_test()
            self.stdout.write(self.style.SUCCESS("✓ Self-test passed."))

        # Optional: write to .env automatically
        if options["write"]:
            # Look for .env two levels up from /backend/config/ → project root
            env_path = Path(__file__).resolve().parents[4] / ".env"
            env_line = f"AES_SECRET_KEY={key_b64}"

            if env_path.exists():
                content = env_path.read_text(encoding="utf-8")
                if "AES_SECRET_KEY=" in content:
                    # Replace existing key
                    lines = content.splitlines()
                    lines = [env_line if l.startswith("AES_SECRET_KEY=") else l for l in lines]
                    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    self.stdout.write(self.style.SUCCESS(f"✓ Updated AES_SECRET_KEY in {env_path}"))
                else:
                    # Append new key
                    with env_path.open("a", encoding="utf-8") as f:
                        f.write(f"\n{env_line}\n")
                    self.stdout.write(self.style.SUCCESS(f"✓ Appended AES_SECRET_KEY to {env_path}"))
            else:
                # Create .env from example
                example_path = env_path.parent / ".env.example"
                if example_path.exists():
                    content = example_path.read_text(encoding="utf-8")
                    content = content.replace("AES_SECRET_KEY=CHANGE_ME_32_BYTE_BASE64_KEY_HERE==", env_line)
                    env_path.write_text(content, encoding="utf-8")
                    self.stdout.write(self.style.SUCCESS(f"✓ Created .env from .env.example with key at {env_path}"))
                else:
                    env_path.write_text(f"{env_line}\n", encoding="utf-8")
                    self.stdout.write(self.style.SUCCESS(f"✓ Created .env with key at {env_path}"))
