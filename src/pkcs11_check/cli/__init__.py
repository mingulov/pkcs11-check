"""pkcs11-check CLI package."""

from pkcs11_check.cli._encoding import ensure_utf8_streams

# Runs before any command module creates its rich Console, so a Windows cp1252
# console does not crash on rich's Unicode marks. No-op off Windows. See _encoding.
ensure_utf8_streams()
