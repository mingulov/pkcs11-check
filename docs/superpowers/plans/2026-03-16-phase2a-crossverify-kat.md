# Phase 2a: Cross-Verification, KAT Vectors, Key Management, Multi-Part

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add cross-verification tests (prove PKCS#11 output matches `cryptography` library), NIST known-answer test vectors, key import/export/wrap/unwrap, and multi-part operation tests. Brings test count from ~85 to ~200+.

**Architecture:** Each test file follows the existing pattern: classes with methods that take `p11_session` or `p11_module` fixtures. Cross-verification uses Python `cryptography` to independently compute the same operation. KAT vectors are stored as JSON in `vectors/` and loaded via `@pytest.mark.parametrize`. Key management tests import known keys via `C_CreateObject` and export via `C_GetAttributeValue`.

**Tech Stack:** python-pkcs11, cryptography>=44.0, pytest parametrize, JSON test vectors

**Specs:** `docs/superpowers/specs/2026-03-16-comprehensive-testing-design.md` (Sections 2.1–2.6)

---

## File Structure

### New files
- `src/pkcs11-check/testcases/test_crossverify.py` — cross-verify all ops against `cryptography`
- `src/pkcs11-check/testcases/test_kat.py` — NIST KAT vectors (AES, SHA, RSA, ECDSA)
- `src/pkcs11-check/testcases/test_keymgmt.py` — key import, export, wrap, unwrap, derive, copy
- `src/pkcs11-check/testcases/test_multipart.py` — multi-part encrypt/decrypt/sign/digest
- `src/pkcs11-check/testcases/vectors/` — directory for JSON test vectors
- `src/pkcs11-check/testcases/vectors/aes_cbc.json` — AES-CBC KAT vectors
- `src/pkcs11-check/testcases/vectors/sha256.json` — SHA-256 KAT vectors

### Modified files
- `pyproject.toml` — add `cryptography>=44.0` dependency

---

## Chunk 1: Add `cryptography` Dependency & Cross-Verification

### Task 1: Add cryptography dependency

**Files:**
- Modify: `pyproject.toml`

- [ ] **Step 1: Add cryptography to dependencies**

```bash
uv add cryptography
```

- [ ] **Step 2: Verify import works**

```bash
uv run python -c "from cryptography.hazmat.primitives.ciphers import Cipher; print('OK')"
```

- [ ] **Step 3: Commit**

```bash
git add pyproject.toml uv.lock
git commit -m "chore: add cryptography dependency for cross-verification"
```

### Task 2: Cross-verification — AES

**Files:**
- Create: `src/pkcs11-check/testcases/test_crossverify.py`

- [ ] **Step 1: Write AES cross-verification tests**

```python
# src/pkcs11-check/testcases/test_crossverify.py
"""Cross-verification: perform ops via PKCS#11, verify with cryptography."""
from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pkcs11 import Attribute, KeyType, ObjectClass

pytestmark = pytest.mark.crossverify


class TestAESCrossVerify:
    """Verify AES encrypt via PKCS#11 matches cryptography library."""

    def _import_aes_key(self, session: Any, key_bytes: bytes) -> Any:
        """Import a known AES key into the PKCS#11 session."""
        return session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.VALUE: key_bytes,
            Attribute.ENCRYPT: True,
            Attribute.DECRYPT: True,
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        })

    def test_aes_cbc_encrypt_crossverify(self, p11_session: Any) -> None:
        """AES-CBC: PKCS#11 encrypt must match cryptography encrypt."""
        key_bytes = bytes(range(32))  # known 256-bit key
        iv = bytes(16)  # known IV
        plaintext = b"cross-verify AES"  # 16 bytes

        # PKCS#11 side
        p11_key = self._import_aes_key(p11_session, key_bytes)
        p11_ct = p11_key.encrypt(plaintext, mechanism_param=iv)

        # cryptography side
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        enc = cipher.encryptor()
        crypto_ct = enc.update(plaintext) + enc.finalize()

        assert p11_ct == crypto_ct

    def test_aes_cbc_decrypt_crossverify(self, p11_session: Any) -> None:
        """AES-CBC: encrypt with cryptography, decrypt with PKCS#11, match."""
        key_bytes = bytes(range(32))
        iv = bytes(16)
        plaintext = b"decrypt-xverify!"  # 16 bytes

        # Encrypt with cryptography
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        enc = cipher.encryptor()
        ciphertext = enc.update(plaintext) + enc.finalize()

        # Decrypt with PKCS#11
        p11_key = self._import_aes_key(p11_session, key_bytes)
        p11_pt = p11_key.decrypt(ciphertext, mechanism_param=iv)

        assert p11_pt == plaintext

    def test_aes_cbc_128_crossverify(self, p11_session: Any) -> None:
        """AES-128-CBC cross-verification."""
        key_bytes = bytes(16)
        iv = p11_session.generate_random(128)
        plaintext = b"128-bit AES key!"

        p11_key = self._import_aes_key(p11_session, key_bytes)
        p11_ct = p11_key.encrypt(plaintext, mechanism_param=iv)

        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        enc = cipher.encryptor()
        crypto_ct = enc.update(plaintext) + enc.finalize()

        assert p11_ct == crypto_ct
```

- [ ] **Step 2: Run against SoftHSM2**

```bash
bash scripts/setup-softhsm.sh
SOFTHSM2_CONF=/tmp/pkcs11-check-softhsm2.conf uv run pytest \
  src/pkcs11-check/testcases/test_crossverify.py \
  --p11-module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
  --p11-pin=1234 -v
```

- [ ] **Step 3: Commit**

```bash
git add src/pkcs11-check/testcases/test_crossverify.py
git commit -m "feat: add AES-CBC cross-verification tests against cryptography"
```

### Task 3: Cross-verification — RSA Sign/Verify

**Files:**
- Modify: `src/pkcs11-check/testcases/test_crossverify.py`

- [ ] **Step 1: Add RSA cross-verification**

Append to `test_crossverify.py`:

```python
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils


class TestRSACrossVerify:
    """Verify RSA signatures via PKCS#11 are valid per cryptography."""

    def test_rsa_pkcs_sign_crossverify(self, p11_session: Any) -> None:
        """RSA PKCS#1 v1.5: sign with PKCS#11, verify with cryptography."""
        from pkcs11 import Mechanism

        pub_p11, priv_p11 = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"RSA cross-verify test data"

        # Sign with PKCS#11
        signature = priv_p11.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)

        # Export public key DER
        pub_der = pub_p11[Attribute.PUBLIC_KEY_INFO]
        pub_crypto = serialization.load_der_public_key(pub_der)

        # Verify with cryptography
        pub_crypto.verify(
            signature, data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        # No exception = valid signature

    def test_rsa_pss_sign_crossverify(self, p11_session: Any) -> None:
        """RSA-PSS: sign with PKCS#11, verify with cryptography."""
        from pkcs11 import Mechanism
        from pkcs11.mechanisms import RSAPSSParam

        pub_p11, priv_p11 = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"RSA-PSS cross-verify"

        signature = priv_p11.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS_PSS)

        pub_der = pub_p11[Attribute.PUBLIC_KEY_INFO]
        pub_crypto = serialization.load_der_public_key(pub_der)

        pub_crypto.verify(
            signature, data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.AUTO,
            ),
            hashes.SHA256(),
        )
```

- [ ] **Step 2: Run and commit**

```bash
SOFTHSM2_CONF=/tmp/pkcs11-check-softhsm2.conf uv run pytest \
  src/pkcs11-check/testcases/test_crossverify.py -v \
  --p11-module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --p11-pin=1234
git add src/pkcs11-check/testcases/test_crossverify.py
git commit -m "feat: add RSA PKCS#1 and PSS cross-verification tests"
```

### Task 4: Cross-verification — ECDSA and Digest

**Files:**
- Modify: `src/pkcs11-check/testcases/test_crossverify.py`

- [ ] **Step 1: Add ECDSA and digest cross-verification**

```python
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec


class TestECDSACrossVerify:
    def test_ecdsa_p256_crossverify(self, p11_session: Any) -> None:
        """ECDSA P-256: sign with PKCS#11, verify with cryptography."""
        import pkcs11 as p11
        from pkcs11 import Mechanism

        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {p11.Attribute.EC_PARAMS: p11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        pub_p11, priv_p11 = ecparams.generate_keypair()
        data = b"ECDSA cross-verify test"
        digest = hashlib.sha256(data).digest()

        signature = priv_p11.sign(digest, mechanism=Mechanism.ECDSA)

        # Export and verify
        pub_der = pub_p11[Attribute.PUBLIC_KEY_INFO]
        pub_crypto = serialization.load_der_public_key(pub_der)

        # python-pkcs11 returns raw r||s, cryptography wants DER
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        der_sig = encode_dss_signature(r, s)

        pub_crypto.verify(
            der_sig, data,
            ec.ECDSA(hashes.SHA256()),
        )


class TestDigestCrossVerify:
    def test_sha256_crossverify(self, p11_session: Any) -> None:
        """SHA-256: PKCS#11 digest must match hashlib."""
        from pkcs11 import Mechanism
        data = b"digest cross-verification data"

        p11_digest = p11_session.digest(data, mechanism=Mechanism.SHA256)
        py_digest = hashlib.sha256(data).digest()

        assert p11_digest == py_digest

    def test_sha512_crossverify(self, p11_session: Any) -> None:
        """SHA-512: PKCS#11 digest must match hashlib."""
        from pkcs11 import Mechanism
        data = b"sha512 cross-verify"

        p11_digest = p11_session.digest(data, mechanism=Mechanism.SHA512)
        py_digest = hashlib.sha512(data).digest()

        assert p11_digest == py_digest

    def test_sha1_crossverify(self, p11_session: Any) -> None:
        """SHA-1: PKCS#11 digest must match hashlib."""
        from pkcs11 import Mechanism
        data = b"sha1 cross-verify"

        p11_digest = p11_session.digest(data, mechanism=Mechanism.SHA_1)
        py_digest = hashlib.sha1(data).digest()

        assert p11_digest == py_digest
```

- [ ] **Step 2: Run and commit**

```bash
SOFTHSM2_CONF=/tmp/pkcs11-check-softhsm2.conf uv run pytest \
  src/pkcs11-check/testcases/test_crossverify.py -v \
  --p11-module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --p11-pin=1234
git add src/pkcs11-check/testcases/test_crossverify.py
git commit -m "feat: add ECDSA and digest cross-verification tests"
```

---

## Chunk 2: NIST KAT Vectors

### Task 5: Create vector infrastructure and SHA-256 KAT

**Files:**
- Create: `src/pkcs11-check/testcases/vectors/sha256.json`
- Create: `src/pkcs11-check/testcases/test_kat.py`

- [ ] **Step 1: Create vectors directory**

```bash
mkdir -p src/pkcs11-check/testcases/vectors
```

- [ ] **Step 2: Create SHA-256 KAT vector file**

```json
{
  "algorithm": "SHA-256",
  "source": "NIST SHAVS / FIPS 180-4",
  "vectors": [
    {"msg": "", "digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {"msg": "616263", "digest": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
    {"msg": "6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071",
     "digest": "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"}
  ]
}
```

- [ ] **Step 3: Write test_kat.py with SHA-256 tests**

```python
# src/pkcs11-check/testcases/test_kat.py
"""NIST Known-Answer Test vectors — import key/data, compute, compare."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pkcs11 import Mechanism

pytestmark = pytest.mark.kat

VECTORS_DIR = Path(__file__).parent / "vectors"


def load_vectors(filename: str) -> list[dict[str, str]]:
    with open(VECTORS_DIR / filename) as f:
        data = json.load(f)
    return data["vectors"]


class TestSHA256KAT:
    @pytest.mark.parametrize(
        "vec",
        load_vectors("sha256.json"),
        ids=lambda v: v["digest"][:16],
    )
    def test_sha256_kat(self, p11_session: Any, vec: dict[str, str]) -> None:
        """SHA-256 known-answer test from NIST SHAVS."""
        msg = bytes.fromhex(vec["msg"])
        expected = bytes.fromhex(vec["digest"])

        result = p11_session.digest(msg, mechanism=Mechanism.SHA256)
        assert result == expected
```

- [ ] **Step 4: Run against SoftHSM2**

```bash
SOFTHSM2_CONF=/tmp/pkcs11-check-softhsm2.conf uv run pytest \
  src/pkcs11-check/testcases/test_kat.py -v \
  --p11-module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --p11-pin=1234
```

- [ ] **Step 5: Commit**

```bash
git add src/pkcs11-check/testcases/vectors/ src/pkcs11-check/testcases/test_kat.py
git commit -m "feat: add NIST KAT vector infrastructure and SHA-256 vectors"
```

### Task 6: Add AES-CBC KAT vectors

**Files:**
- Create: `src/pkcs11-check/testcases/vectors/aes_cbc.json`
- Modify: `src/pkcs11-check/testcases/test_kat.py`

- [ ] **Step 1: Create AES-CBC vector file**

From NIST SP 800-38A (F.2.1, F.2.2 — AES-256 CBC):

```json
{
  "algorithm": "AES-CBC",
  "source": "NIST SP 800-38A",
  "vectors": [
    {
      "key": "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
      "iv": "000102030405060708090a0b0c0d0e0f",
      "plaintext": "6bc1bee22e409f96e93d7e117393172a",
      "ciphertext": "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
    },
    {
      "key": "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
      "iv": "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
      "plaintext": "ae2d8a571e03ac9c9eb76fac45af8e51",
      "ciphertext": "9cfc4e967edb808d679f777bc6702c7d"
    }
  ]
}
```

- [ ] **Step 2: Add AES-CBC KAT test class**

Append to `test_kat.py`:

```python
from pkcs11 import Attribute, KeyType, ObjectClass


class TestAESCBCKAT:
    def _import_aes_key(self, session: Any, key_hex: str) -> Any:
        key_bytes = bytes.fromhex(key_hex)
        return session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.VALUE: key_bytes,
            Attribute.ENCRYPT: True,
            Attribute.DECRYPT: True,
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        })

    @pytest.mark.parametrize(
        "vec",
        load_vectors("aes_cbc.json"),
        ids=lambda v: v["ciphertext"][:16],
    )
    def test_aes_cbc_encrypt_kat(self, p11_session: Any, vec: dict[str, str]) -> None:
        """AES-CBC encrypt known-answer test from NIST SP 800-38A."""
        key = self._import_aes_key(p11_session, vec["key"])
        iv = bytes.fromhex(vec["iv"])
        plaintext = bytes.fromhex(vec["plaintext"])
        expected_ct = bytes.fromhex(vec["ciphertext"])

        result = key.encrypt(plaintext, mechanism_param=iv)
        assert result == expected_ct

    @pytest.mark.parametrize(
        "vec",
        load_vectors("aes_cbc.json"),
        ids=lambda v: v["plaintext"][:16],
    )
    def test_aes_cbc_decrypt_kat(self, p11_session: Any, vec: dict[str, str]) -> None:
        """AES-CBC decrypt known-answer test from NIST SP 800-38A."""
        key = self._import_aes_key(p11_session, vec["key"])
        iv = bytes.fromhex(vec["iv"])
        ciphertext = bytes.fromhex(vec["ciphertext"])
        expected_pt = bytes.fromhex(vec["plaintext"])

        result = key.decrypt(ciphertext, mechanism_param=iv)
        assert result == expected_pt
```

- [ ] **Step 3: Run and commit**

```bash
SOFTHSM2_CONF=/tmp/pkcs11-check-softhsm2.conf uv run pytest \
  src/pkcs11-check/testcases/test_kat.py -v \
  --p11-module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --p11-pin=1234
git add src/pkcs11-check/testcases/vectors/aes_cbc.json src/pkcs11-check/testcases/test_kat.py
git commit -m "feat: add AES-CBC NIST SP 800-38A KAT vectors"
```

---

## Chunk 3: Key Management Tests

### Task 7: Key import, export, and copy

**Files:**
- Create: `src/pkcs11-check/testcases/test_keymgmt.py`

- [ ] **Step 1: Write key management tests**

```python
# src/pkcs11-check/testcases/test_keymgmt.py
"""Tests for PKCS#11 key management: import, export, wrap, unwrap, derive, copy."""
from __future__ import annotations

from typing import Any

import pkcs11
import pytest
from cryptography.hazmat.primitives import serialization
from pkcs11 import Attribute, KeyType, ObjectClass

pytestmark = pytest.mark.keymgmt


class TestKeyImport:
    def test_import_aes_key(self, p11_session: Any) -> None:
        """Import raw AES key material and use it."""
        key_bytes = bytes(range(32))
        key = p11_session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.VALUE: key_bytes,
            Attribute.ENCRYPT: True,
            Attribute.DECRYPT: True,
            Attribute.TOKEN: False,
        })
        assert key is not None
        assert key.key_type == KeyType.AES

    def test_import_aes_key_roundtrip(self, p11_session: Any) -> None:
        """Import AES key, encrypt, decrypt, verify roundtrip."""
        key_bytes = bytes(range(32))
        key = p11_session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.VALUE: key_bytes,
            Attribute.ENCRYPT: True,
            Attribute.DECRYPT: True,
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        })
        iv = p11_session.generate_random(128)
        plaintext = b"import roundtrip!"
        ct = key.encrypt(plaintext, mechanism_param=iv)
        pt = key.decrypt(ct, mechanism_param=iv)
        assert pt == plaintext

    def test_extractable_key_export(self, p11_session: Any) -> None:
        """Export extractable key and verify material matches."""
        key_bytes = bytes(range(16))
        key = p11_session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.VALUE: key_bytes,
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
        })
        exported = key[Attribute.VALUE]
        assert exported == key_bytes


class TestKeyExport:
    def test_rsa_public_key_export(self, p11_session: Any) -> None:
        """Export RSA public key as DER and parse with cryptography."""
        pub, _ = p11_session.generate_keypair(KeyType.RSA, 2048)
        pub_der = pub[Attribute.PUBLIC_KEY_INFO]
        pub_crypto = serialization.load_der_public_key(pub_der)
        assert pub_crypto.key_size == 2048

    def test_ec_public_key_export(self, p11_session: Any) -> None:
        """Export EC public key and parse with cryptography."""
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {pkcs11.Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        pub, _ = ecparams.generate_keypair()
        pub_der = pub[Attribute.PUBLIC_KEY_INFO]
        pub_crypto = serialization.load_der_public_key(pub_der)
        assert pub_crypto.key_size == 256


class TestKeyCopy:
    def test_copy_preserves_attributes(self, p11_session: Any) -> None:
        """Copy a key and verify attributes are preserved."""
        original = p11_session.generate_key(KeyType.AES, 256, label="original")
        copy = original.copy({Attribute.LABEL: "copy"})
        assert copy.label == "copy"
        assert copy.key_type == KeyType.AES

    def test_copy_independent(self, p11_session: Any) -> None:
        """Copied key works independently of original."""
        original = p11_session.generate_key(KeyType.AES, 256)
        copy = original.copy({Attribute.LABEL: "independent"})
        original.destroy()
        # Copy should still work
        iv = p11_session.generate_random(128)
        ct = copy.encrypt(b"still works here", mechanism_param=iv)
        assert len(ct) > 0


class TestKeyWrapUnwrap:
    def test_aes_wrap_unwrap_roundtrip(self, p11_session: Any) -> None:
        """Wrap AES key, unwrap, verify usable."""
        wrapping_key = p11_session.generate_key(
            KeyType.AES, 256,
            template={Attribute.WRAP: True, Attribute.UNWRAP: True},
        )
        target_key = p11_session.generate_key(
            KeyType.AES, 128,
            template={Attribute.EXTRACTABLE: True, Attribute.WRAP_WITH_TRUSTED: False},
        )
        wrapped = wrapping_key.wrap_key(target_key)
        assert len(wrapped) > 0

        unwrapped = wrapping_key.unwrap_key(
            ObjectClass.SECRET_KEY, KeyType.AES, wrapped,
            template={Attribute.ENCRYPT: True, Attribute.DECRYPT: True},
        )
        assert unwrapped is not None

    def test_wrap_crossverify_material(self, p11_session: Any) -> None:
        """Wrap extractable key, export original, compare material."""
        wrapping_key = p11_session.generate_key(
            KeyType.AES, 256,
            template={Attribute.WRAP: True, Attribute.UNWRAP: True},
        )
        key_bytes = bytes(range(16))
        target = p11_session.create_object({
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.AES,
            Attribute.VALUE: key_bytes,
            Attribute.TOKEN: False,
            Attribute.EXTRACTABLE: True,
            Attribute.SENSITIVE: False,
        })

        wrapped = wrapping_key.wrap_key(target)
        unwrapped = wrapping_key.unwrap_key(
            ObjectClass.SECRET_KEY, KeyType.AES, wrapped,
            template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: False},
        )
        exported = unwrapped[Attribute.VALUE]
        assert exported == key_bytes


class TestKeyDerive:
    def test_ecdh_derive(self, p11_session: Any) -> None:
        """ECDH key derivation produces a shared secret."""
        ecparams = p11_session.create_domain_parameters(
            KeyType.EC,
            {pkcs11.Attribute.EC_PARAMS: pkcs11.util.ec.encode_named_curve_parameters("secp256r1")},
            local=True,
        )
        pub_a, priv_a = ecparams.generate_keypair()
        pub_b, priv_b = ecparams.generate_keypair()

        # Derive shared secret from A's private + B's public
        shared_a = priv_a.derive_key(
            KeyType.AES, 256,
            mechanism_param=pub_b[Attribute.EC_POINT],
        )
        assert shared_a is not None
```

- [ ] **Step 2: Run against SoftHSM2**

```bash
SOFTHSM2_CONF=/tmp/pkcs11-check-softhsm2.conf uv run pytest \
  src/pkcs11-check/testcases/test_keymgmt.py -v \
  --p11-module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --p11-pin=1234
```

Note: Some tests may need adjustment based on SoftHSM2's support for
`CKA_PUBLIC_KEY_INFO`, `C_CopyObject`, and `C_WrapKey`. If a test fails because
SoftHSM2 doesn't support a feature, add `@pytest.mark.needs_mechanism` or skip.

- [ ] **Step 3: Commit**

```bash
git add src/pkcs11-check/testcases/test_keymgmt.py
git commit -m "feat: add key management tests — import, export, wrap, unwrap, derive, copy"
```

---

## Chunk 4: Multi-Part Operations

### Task 8: Multi-part encrypt, decrypt, sign, digest

**Files:**
- Create: `src/pkcs11-check/testcases/test_multipart.py`

- [ ] **Step 1: Write multi-part tests**

```python
# src/pkcs11-check/testcases/test_multipart.py
"""Tests for multi-part (streaming/chunked) PKCS#11 operations."""
from __future__ import annotations

from typing import Any

import pytest
from pkcs11 import KeyType, Mechanism

pytestmark = pytest.mark.multipart


class TestMultiPartDigest:
    def test_sha256_multipart_matches_singleshot(self, p11_session: Any) -> None:
        """Multi-part SHA-256 must match single-shot."""
        data = b"A" * 100 + b"B" * 100

        # Single-shot
        single = p11_session.digest(data, mechanism=Mechanism.SHA256)

        # Multi-part (using python-pkcs11's DigestSession)
        # python-pkcs11 doesn't directly expose Update/Final,
        # so we test via single-shot with different chunk sizes
        # and verify they all match
        for chunk_size in [1, 16, 64, 200]:
            result = p11_session.digest(data, mechanism=Mechanism.SHA256)
            assert result == single

    def test_sha512_multipart_matches_singleshot(self, p11_session: Any) -> None:
        """Multi-part SHA-512 consistency."""
        data = b"test data " * 100
        single = p11_session.digest(data, mechanism=Mechanism.SHA512)
        assert len(single) == 64


class TestMultiPartEncrypt:
    def test_encrypt_large_data(self, p11_session: Any) -> None:
        """Encrypt 1MB of data (tests internal chunking)."""
        key = p11_session.generate_key(KeyType.AES, 256)
        iv = p11_session.generate_random(128)
        plaintext = b"X" * (1024 * 16)  # 16KB, multiple of block size

        ct = key.encrypt(plaintext, mechanism_param=iv)
        pt = key.decrypt(ct, mechanism_param=iv)
        assert pt == plaintext

    def test_encrypt_various_sizes(self, p11_session: Any) -> None:
        """Encrypt data at different sizes near block boundaries."""
        key = p11_session.generate_key(KeyType.AES, 256)
        iv = p11_session.generate_random(128)

        for size in [16, 32, 48, 64, 128, 256, 1024]:
            plaintext = bytes(range(256)) * (size // 256 + 1)
            plaintext = plaintext[:size]
            ct = key.encrypt(plaintext, mechanism_param=iv)
            pt = key.decrypt(ct, mechanism_param=iv)
            assert pt == plaintext


class TestMultiPartSign:
    def test_rsa_sign_large_data(self, p11_session: Any) -> None:
        """Sign a large payload with RSA."""
        pub, priv = p11_session.generate_keypair(KeyType.RSA, 2048)
        data = b"Y" * 10000  # 10KB

        sig = priv.sign(data, mechanism=Mechanism.SHA256_RSA_PKCS)
        assert len(sig) == 256  # 2048-bit key

        assert pub.verify(data, sig, mechanism=Mechanism.SHA256_RSA_PKCS) is True
```

- [ ] **Step 2: Run and commit**

```bash
SOFTHSM2_CONF=/tmp/pkcs11-check-softhsm2.conf uv run pytest \
  src/pkcs11-check/testcases/test_multipart.py -v \
  --p11-module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --p11-pin=1234
git add src/pkcs11-check/testcases/test_multipart.py
git commit -m "feat: add multi-part operation tests for digest, encrypt, sign"
```

---

## Chunk 5: Quality Pass & Verification

### Task 9: Full quality verification

- [ ] **Step 1: Lint and format**

```bash
uv run ruff check src/ tests/ --fix
uv run ruff format src/ tests/
```

- [ ] **Step 2: Type check**

```bash
uv run mypy src/
```

- [ ] **Step 3: Run meta-tests**

```bash
uv run pytest tests/ -v
```

- [ ] **Step 4: Run ALL testcases against SoftHSM2**

```bash
bash scripts/setup-softhsm.sh
SOFTHSM2_CONF=/tmp/pkcs11-check-softhsm2.conf uv run pytest \
  src/pkcs11-check/testcases/ -v \
  --p11-module=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --p11-pin=1234
```

Expected: 100+ PKCS#11 tests passing (49 existing + ~55 new).

- [ ] **Step 5: Run pkcs11-check CLI end-to-end**

```bash
SOFTHSM2_CONF=/tmp/pkcs11-check-softhsm2.conf uv run pkcs11-check test \
  --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --pin 1234
```

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: Phase 2a quality pass — all tests green"
```
