# Mechanism-Driven Parametrized Tests — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Use **Sonnet 4.6** for implementation tasks, **Opus 4.6** for review tasks.

**Goal:** Build a mechanism-driven test system that covers all 480 CKM_* mechanisms from PKCS#11 v3.2 with ~2,500+ parametrized tests.

**Architecture:** Four phases: (A) infrastructure — MechConfig dataclass, mechanism catalog, pytest integration, markers; (B) registry population — all 480 entries + vector generator + JSON data; (C) 16 operation test files; (D) Docker verification across all modules.

**Tech Stack:** Python 3.11+, pytest, pkcs11_check.raw, collections.Counter, cryptography (for vector generation)

**Spec:** `docs/superpowers/specs/2026-03-27-mechanism-driven-parametrized-tests-design.md` (rev 5)

---

## Phase A: Infrastructure (Tasks 1-5)

### Task 1: Create MechConfig Dataclass and Registry Module

**Goal:** Create the mechanism registry module with the MechConfig dataclass and empty registry dict.

**Files:**
- Create: `src/pkcs11_check/testcases/mechanism_registry.py`

- [ ] **Step 1:** Create the registry module with the MechConfig dataclass

```python
"""Mechanism registry for mechanism-driven parametrized tests.

Maps CKM_* mechanism IDs to test configurations. Covers all 480 mechanisms
from the OASIS PKCS#11 v3.2 standard.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class MechConfig:
    """Configuration for testing a specific PKCS#11 mechanism."""

    key_type: int | None = None
    keygen_mech: int | None = None
    key_sizes: tuple[int, ...] = ()
    is_keypair: bool = False
    is_param_gen: bool = False
    param_packer: str | None = None
    param_factory: str | None = None
    block_size: int | None = None
    vector_file: str | None = None
    input_constraint: str = "any"
    multi_part_supported: bool = True
    param_required: bool = False
    auth_tag_included: bool = False
    deterministic: bool = True
    message_based: bool = False
    expected_flags: int = 0
    notes: str = ""


# Registry: CKM int value → MechConfig
# Populated by _populate_registry() below
MECHANISM_REGISTRY: dict[int, MechConfig] = {}


def get_config(mech_id: int) -> MechConfig | None:
    """Look up mechanism config. Returns None for vendor-defined mechanisms."""
    return MECHANISM_REGISTRY.get(mech_id)
```

- [ ] **Step 2:** Lint
```bash
uv run ruff check src/pkcs11_check/testcases/mechanism_registry.py
```

- [ ] **Step 3:** Commit
```bash
git commit -m 'feat: create MechConfig dataclass and mechanism registry module'
```

---

### Task 2: Populate Registry — AES Family (28 mechanisms)

**Goal:** Add all AES mechanism entries to the registry.

**Files:**
- Modify: `src/pkcs11_check/testcases/mechanism_registry.py`

- [ ] **Step 1:** Add AES mechanism imports and entries

Import all CKM_AES_* and CKK_AES from types_std, then populate:

```python
from pkcs11_check.raw.types_std import (
    CKF_DECRYPT, CKF_ENCRYPT, CKF_GENERATE, CKF_SIGN, CKF_VERIFY,
    CKF_WRAP, CKF_UNWRAP, CKK_AES, CKK_AES_XTS,
    CKM_AES_KEY_GEN, CKM_AES_ECB, CKM_AES_CBC, CKM_AES_CBC_PAD,
    CKM_AES_CTR, CKM_AES_GCM, CKM_AES_CCM, CKM_AES_OFB,
    CKM_AES_CFB8, CKM_AES_CFB64, CKM_AES_CFB128, CKM_AES_CFB1,
    CKM_AES_CTS, CKM_AES_XTS, CKM_AES_MAC, CKM_AES_MAC_GENERAL,
    CKM_AES_CMAC, CKM_AES_CMAC_GENERAL, CKM_AES_XCBC_MAC,
    CKM_AES_XCBC_MAC_96, CKM_AES_GMAC,
    CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_PAD,
    CKM_AES_KEY_WRAP_KWP, CKM_AES_KEY_WRAP_PKCS7,
    CKM_AES_XTS_KEY_GEN,
)

_AES_SIZES = (128, 192, 256)
_AES_ENC_FLAGS = CKF_ENCRYPT | CKF_DECRYPT
_AES_MAC_FLAGS = CKF_SIGN | CKF_VERIFY
_AES_WRAP_FLAGS = CKF_WRAP | CKF_UNWRAP

MECHANISM_REGISTRY.update({
    CKM_AES_KEY_GEN: MechConfig(
        key_type=CKK_AES, keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES, expected_flags=CKF_GENERATE,
        notes="AES secret key generation",
    ),
    CKM_AES_ECB: MechConfig(
        key_type=CKK_AES, keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES, block_size=16,
        input_constraint="block_aligned", deterministic=True,
        expected_flags=_AES_ENC_FLAGS | _AES_WRAP_FLAGS,
        vector_file="aes_ecb.json",
    ),
    CKM_AES_CBC: MechConfig(
        key_type=CKK_AES, keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES, block_size=16,
        input_constraint="block_aligned", param_required=True,
        param_packer="mech_bytes", deterministic=False,
        expected_flags=_AES_ENC_FLAGS | _AES_WRAP_FLAGS,
        vector_file="aes_cbc.json",
    ),
    CKM_AES_CBC_PAD: MechConfig(
        key_type=CKK_AES, keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES, block_size=16,
        param_required=True, param_packer="mech_bytes",
        deterministic=False,
        expected_flags=_AES_ENC_FLAGS | _AES_WRAP_FLAGS,
        vector_file="aes_cbc_pad.json",
    ),
    CKM_AES_GCM: MechConfig(
        key_type=CKK_AES, keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES, param_required=True,
        param_packer="mech_gcm", auth_tag_included=True,
        multi_part_supported=False, deterministic=False,
        message_based=True,
        expected_flags=_AES_ENC_FLAGS | _AES_WRAP_FLAGS,
        vector_file="aes_gcm.json",
    ),
    CKM_AES_CCM: MechConfig(
        key_type=CKK_AES, keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES, param_required=True,
        param_packer="mech_ccm", auth_tag_included=True,
        multi_part_supported=False, deterministic=True,
        expected_flags=_AES_ENC_FLAGS | _AES_WRAP_FLAGS,
        vector_file="aes_ccm.json",
    ),
    CKM_AES_CTR: MechConfig(
        key_type=CKK_AES, keygen_mech=CKM_AES_KEY_GEN,
        key_sizes=_AES_SIZES, param_required=True,
        param_packer="mech_ctr",
        expected_flags=_AES_ENC_FLAGS | _AES_WRAP_FLAGS,
        vector_file="aes_ctr.json",
    ),
    # ... continue for all 28 AES mechanisms
})
```

Complete all 28 AES entries following this pattern. Reference OASIS spec `aes.md` and `additional_aes_mechanisms.md` for correct flags per mechanism.

- [ ] **Step 2:** Lint and commit
```bash
uv run ruff check src/pkcs11_check/testcases/mechanism_registry.py
git commit -m 'feat: populate AES mechanism registry (28 entries)'
```

---

### Task 3: Populate Registry — RSA, EC, Hash, HMAC Families (~120 mechanisms)

**Goal:** Add RSA (20+), EC/EdDSA/ECDH (25+), Hash/Digest (20+), HMAC (24+), HMAC keygen (12+) entries.

**Files:**
- Modify: `src/pkcs11_check/testcases/mechanism_registry.py`

- [ ] **Step 1:** Add RSA entries (key gen, PKCS, OAEP, PSS, hash-specific sign variants)

Follow the same pattern as AES. Key fields:
- `key_type=CKK_RSA`, `keygen_mech=CKM_RSA_PKCS_KEY_PAIR_GEN`, `is_keypair=True`
- `key_sizes=(2048, 3072, 4096)`
- RSA-OAEP: `param_packer="mech_oaep"`, `param_required=True`
- RSA-PSS: `param_packer="mech_pss"`, `param_required=True`
- Hash-specific (SHA256_RSA_PKCS etc.): `param_required=False`

- [ ] **Step 2:** Add EC entries (ECDSA, EdDSA, ECDH, key gens, Montgomery)

- `CKK_EC` for Weierstrass, `CKK_EC_EDWARDS` for Edwards, `CKK_EC_MONTGOMERY` for Montgomery
- ECDSA: `key_sizes=()` (curve-specific, not bit-size based)
- EdDSA: `param_packer="mech_eddsa"`, `param_required=True`
- ECDH: derive mechanism, `param_packer="mech_ecdh"`, `expected_flags=CKF_DERIVE`

- [ ] **Step 3:** Add Hash/Digest entries (SHA-1, SHA-2, SHA-3, BLAKE2, SHAKE)

- `key_type=None`, `keygen_mech=None`, `key_sizes=()`, `input_constraint="digest_only"`
- Each hash: `expected_flags=CKF_DIGEST`

- [ ] **Step 4:** Add HMAC entries (SHA*_HMAC, SHA*_HMAC_GENERAL, keygen)

- `key_type=CKK_GENERIC_SECRET` (or hash-specific CKK_SHA*_HMAC)
- HMAC: `expected_flags=CKF_SIGN | CKF_VERIFY`
- HMAC keygen: `expected_flags=CKF_GENERATE`

- [ ] **Step 5:** Lint and commit
```bash
git commit -m 'feat: populate RSA, EC, Hash, HMAC mechanism registry (~120 entries)'
```

---

### Task 4: Populate Registry — PQC, KDF, Protocol, Legacy (~330 mechanisms)

**Goal:** Add all remaining mechanisms: PQC (ML-KEM, ML-DSA, SLH-DSA, HSS, XMSS), KDF (HKDF, PBKDF2, SP800-108, TLS, WTLS, IKE), DSA, DH, DES/DES3, legacy (RC2, RC4, RC5, IDEA, CAST, CDMF, Skipjack, Baton, Juniper, etc.), and miscellaneous.

**Files:**
- Modify: `src/pkcs11_check/testcases/mechanism_registry.py`

- [ ] **Step 1:** Add PQC entries (~30 mechanisms)

ML-KEM, ML-DSA, SLH-DSA, HASH_ML_DSA (11 variants), HASH_SLH_DSA (11 variants), HSS, XMSS, XMSS-MT, ML_DSA_EXTERNAL_MU variants.

- [ ] **Step 2:** Add KDF/protocol entries (~50 mechanisms)

HKDF (3), PBKDF2 (1), SP800-108 (3), TLS (17), WTLS (6), SSL3 (6), IKE (4), X3DH (4), concatenation/extraction (5), PUB_KEY_FROM_PRIV_KEY (1).

- [ ] **Step 3:** Add DSA (16) + DH (8) + DES (12) + DES3 (10) entries

- [ ] **Step 4:** Add legacy cipher entries (~80 mechanisms)

RC2, RC4, RC5, IDEA, CAST variants, CDMF, Skipjack, Baton, Juniper, Blowfish, Twofish, Camellia, ARIA, SEED. Basic entries with key type and expected flags from OASIS spec headers.

- [ ] **Step 5:** Add remaining mechanisms (GOST, RIPEMD, MD2, MD5, PBE, OTP, CMS, KRB5, NULL, FORTEZZA, KEA)

- [ ] **Step 6:** Verify total count
```python
python3 -c "
from pkcs11_check.testcases.mechanism_registry import MECHANISM_REGISTRY
print(f'Registry entries: {len(MECHANISM_REGISTRY)}')
assert len(MECHANISM_REGISTRY) >= 470, f'Expected ~480, got {len(MECHANISM_REGISTRY)}'
"
```

- [ ] **Step 7:** Lint and commit
```bash
git commit -m 'feat: populate all 480 mechanism registry entries (PQC, KDF, protocol, legacy)'
```

---

### Task 5: Extend Preflight Manifest + Create Mechanism Catalog + pytest Integration

**Goal:** Extend the preflight subprocess to collect mechanism info, create the MechanismCatalog class, wire into pytest_generate_tests for parametrization.

**Files:**
- Modify: `src/pkcs11_check/core/preflight.py` (extend CapabilityManifest)
- Create: `src/pkcs11_check/testcases/mechanism_catalog.py` (MechanismCatalog class)
- Modify: `src/pkcs11_check/plugin.py` (add _ensure_mechanism_catalog, pytest_generate_tests)
- Modify: `src/pkcs11_check/markers.py` (add new markers)

- [ ] **Step 1:** Extend CapabilityManifest with mechanism_info

In `preflight.py`, add `mechanism_info: dict[str, dict]` field to `CapabilityManifest`. In `probe_capabilities()`, after getting mechanism list, call `C_GetMechanismInfo` for each and store `{mech_name: {"flags": flags, "min_key_size": min, "max_key_size": max}}`.

- [ ] **Step 2:** Create MechanismCatalog class

```python
# src/pkcs11_check/testcases/mechanism_catalog.py
"""Mechanism catalog for test parametrization."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any

from pkcs11_check.testcases.mechanism_registry import MechConfig, MECHANISM_REGISTRY


@dataclass
class MechEntry:
    mech_id: int
    mech_name: str
    info: dict[str, int]  # flags, min_key_size, max_key_size
    config: MechConfig | None

class MechanismCatalog:
    def __init__(self, entries: dict[int, MechEntry]) -> None:
        self._entries = entries

    @classmethod
    def from_manifest(cls, manifest: Any) -> MechanismCatalog:
        # Build from CapabilityManifest.mechanism_info
        ...

    def filter(self, flag: int, *, with_registry: bool = False) -> list[MechEntry]:
        """Return entries matching the given CKF_* flag."""
        ...

    def all_entries(self) -> list[MechEntry]:
        ...
```

- [ ] **Step 3:** Add `_ensure_mechanism_catalog` and `pytest_generate_tests` to plugin.py

```python
_MECHANISM_CATALOG_KEY: pytest.StashKey[Any] = pytest.StashKey()

def _ensure_mechanism_catalog(config: pytest.Config) -> Any:
    cached = config.stash.get(_MECHANISM_CATALOG_KEY, None)
    if cached is not None:
        return cached
    manifest = _ensure_manifest(config)
    if manifest is None:
        return None
    from pkcs11_check.testcases.mechanism_catalog import MechanismCatalog
    catalog = MechanismCatalog.from_manifest(manifest)
    config.stash[_MECHANISM_CATALOG_KEY] = catalog
    return catalog
```

- [ ] **Step 4:** Register new markers in markers.py

Add to `MARKER_DEFINITIONS`:
```python
MarkerDef("mechanism_coverage", "Mechanism-driven parametrized test"),
MarkerDef("negative", "Negative test (wrong key type, invalid params, missing perms)"),
MarkerDef("lifecycle", "Composite multi-step workflow test"),
MarkerDef("keygen", "Key generation test"),
MarkerDef("wrap", "Key wrap/unwrap test"),
MarkerDef("derive", "Key derivation test"),
MarkerDef("kem", "Key encapsulation/decapsulation test"),
MarkerDef("sign_recover", "Sign-recover/verify-recover test"),
MarkerDef("message_based", "v3.0 message-based operation test"),
MarkerDef("state_machine", "Operation state machine violation test"),
MarkerDef("flag_validation", "CKF_* flag correctness test"),
```

- [ ] **Step 5:** Run meta-tests
```bash
uv run python -m pytest tests/ -x -q --ignore=tests/test_raw_pack.py
```

- [ ] **Step 6:** Commit
```bash
git commit -m 'feat: mechanism catalog, preflight extension, pytest_generate_tests integration'
```

---

## Phase B: Vector Generation + JSON Data (Tasks 6-7)

### Task 6: Create Vector Generator Script

**Goal:** Script that generates KAT vectors using the `cryptography` library.

**Files:**
- Create: `scripts/generate_mechanism_vectors.py`
- Create: `src/pkcs11_check/testcases/data/mechanism_vectors/` directory

- [ ] **Step 1:** Create the generator script

```python
#!/usr/bin/env python3
"""Generate PKCS#11 mechanism KAT vectors using the cryptography library."""
# Usage: uv run python scripts/generate_mechanism_vectors.py --all
# Usage: uv run python scripts/generate_mechanism_vectors.py --family aes_gcm

import argparse, json, os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# ... import all needed crypto primitives

OUTPUT_DIR = Path("src/pkcs11_check/testcases/data/mechanism_vectors")

def generate_aes_ecb() -> dict: ...
def generate_aes_cbc() -> dict: ...
def generate_aes_gcm() -> dict: ...
# ... one function per mechanism family
```

- [ ] **Step 2:** Generate all vector files
```bash
uv run python scripts/generate_mechanism_vectors.py --all
```

- [ ] **Step 3:** Commit vectors
```bash
git add src/pkcs11_check/testcases/data/mechanism_vectors/
git commit -m 'feat: pre-generated KAT vectors for mechanism-driven tests'
```

### Task 7: Create Vector Loader

**Goal:** Helper that loads JSON vectors for parametrized tests.

**Files:**
- Create: `src/pkcs11_check/testcases/mechanism_vectors.py`

- [ ] **Step 1:** Create the vector loader

```python
"""Load mechanism KAT vectors from JSON files."""
import json
from pathlib import Path
from typing import Any

_VECTOR_DIR = Path(__file__).parent / "data" / "mechanism_vectors"

def load_vectors(filename: str) -> list[dict[str, Any]]:
    path = _VECTOR_DIR / filename
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    return data.get("vectors", [])

def load_positive_vectors(filename: str) -> list[dict[str, Any]]:
    return [v for v in load_vectors(filename) if v.get("type") == "positive"]

def load_negative_vectors(filename: str) -> list[dict[str, Any]]:
    return [v for v in load_vectors(filename) if v.get("type") == "negative"]
```

- [ ] **Step 2:** Commit
```bash
git commit -m 'feat: vector loader for mechanism KAT tests'
```

---

## Phase C: Operation Test Files (Tasks 8-23)

Each task creates one test file. All follow the same pattern: import registry, use mechanism_catalog fixture for parametrization, run operations per mechanism per key size.

### Task 8: test_mech_keygen.py — Key Generation Tests

**Files:**
- Create: `src/pkcs11_check/testcases/test_mech_keygen.py`

Tests per keygen mechanism × key size:
- Generate key, verify handle != 0
- Verify CKA_LOCAL = True
- Verify key type matches template
- Test at min and max key sizes from C_GetMechanismInfo

### Task 9: test_mech_encrypt.py — Encrypt/Decrypt Tests

Single-part encrypt/decrypt per mechanism × key size:
- Roundtrip, KAT vector, empty plaintext, block boundary, non-aligned negative, different-keys-different-output

### Task 10: test_mech_sign.py — Sign/Verify Tests

Sign/verify per mechanism × key size:
- Roundtrip, bit-flip verify, truncated sig, wrong key verify, empty message

### Task 11: test_mech_sign_recover.py — Sign-Recover/Verify-Recover

RSA PKCS, X9.31, raw RSA sign-recover roundtrip tests.

### Task 12: test_mech_digest.py — Digest Tests

Per hash mechanism: KAT vector, empty input, known strings, length check.

### Task 13: test_mech_wrap.py — Wrap/Unwrap Tests

Per wrap mechanism × key size: roundtrip, corruption, non-extractable, hybrid wraps.

### Task 14: test_mech_derive.py — Key Derivation Tests

ECDH, HKDF, PBKDF2, SP800-108, TLS chain tests.

### Task 15: test_mech_kem.py — Encapsulate/Decapsulate Tests

ML-KEM, RSA KEM, ECDH KEM roundtrip + corrupted ciphertext + wrong key.

### Task 16: test_mech_message.py — Message-Based Operations

v3.0 C_Message* APIs for AES-GCM, ChaCha20-Poly1305.

### Task 17: test_mech_multipart.py — Multi-Part Streaming

C_*Update/C_*Final for encrypt, sign, digest. Different chunking same result.

### Task 18: test_mech_attribute.py — Key Attribute Verification

CKA_LOCAL, CKA_KEY_GEN_MECHANISM, CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE after keygen/derive/unwrap.

### Task 19: test_mech_negative.py — Negative Tests

Wrong key type (25), invalid params (20), missing permissions (45).

### Task 20: test_mech_state.py — State Machine Violations

Operation state violations (50): double init, no init, cross-operation.

### Task 21: test_mech_flags.py — Flag Validation

Compare C_GetMechanismInfo flags against registry expected_flags for every mechanism.

### Task 22: test_mech_probe.py — Vendor Mechanism Probing

For vendor-defined mechanisms (>= CKM_VENDOR_DEFINED): call C_*Init, verify no crash.

### Task 23: test_mech_lifecycle.py — 11 Composite Patterns

KEM→use, ECDH→HKDF, wrap→unwrap→use, AEAD wrap AAD, RSA-AES hybrid, HKDF 2-phase, PBKDF2→AES, chained derivation, SP800-108 multi-key, TLS 1.2 chain, ECDH-AES key wrap.

---

## Phase D: Verification (Task 24)

### Task 24: End-to-End Docker Verification

- [ ] **Step 1:** Run SoftHSM2-main
```bash
bash docker/test.sh softhsm2-main
```
Verify: no test ERRORS, new mechanism_coverage tests appear, coverage improved.

- [ ] **Step 2:** Run Kryoptic-main
```bash
bash docker/test.sh kryoptic-main
```
Verify: no test ERRORS, mechanism tests run for all 168 advertised mechanisms.

- [ ] **Step 3:** Run NSS-PQC
```bash
bash docker/test.sh nss-pqc
```
Verify: no regressions, PQC mechanism tests run.

- [ ] **Step 4:** Check coverage.json improvements
```python
python3 -c "
import json
d = json.load(open('artifacts/kryoptic-main/coverage.json'))
mc = d['mechanism_coverage']
print(f'Invoked: {mc[\"invoked\"]}/{mc[\"available\"]}')
# Should be significantly higher than before
"
```

- [ ] **Step 5:** Commit verification notes
```bash
git commit --allow-empty -m 'chore: verified mechanism-driven tests across 3 modules'
```
