# Mechanism-Driven Parametrized Tests

**Date:** 2026-03-27
**Status:** Design, revision 2 (post gap analysis)

## Goal

Create a comprehensive, mechanism-driven test system that automatically tests every advertised PKCS#11 mechanism based on its CKF_* flags. Pre-generated known-answer test vectors verify correctness. Negative tests verify error handling. Multi-part streaming tests exercise C_*Update/C_*Final paths. Composite lifecycle tests exercise multi-step workflows. Mechanism flag validation catches module metadata bugs.

**Estimated tests per module:** ~1,300 for a full-featured module (Kryoptic 168 mechs), ~600 for a mid-range module (SoftHSM2 80 mechs).

## Architecture Overview

```
Layer 0: Mechanism Discovery (session-scoped, runs once)
    testcases/conftest.py — p11_mechanism_catalog fixture
    Calls C_GetMechanismList + C_GetMechanismInfo for all mechanisms
    Caches (mech_id, info, MechConfig) tuples for parametrization

Layer 1: Test Data (JSON vectors in repo, loaded dynamically)
    testcases/data/mechanism_vectors/*.json
    scripts/generate_mechanism_vectors.py

Layer 2: Mechanism Registry (declarative config, ~250 entries)
    testcases/mechanism_registry.py

Layer 3: Operation Tests (14 test files)
    testcases/test_mech_keygen.py       — CKF_GENERATE / CKF_GENERATE_KEY_PAIR
    testcases/test_mech_encrypt.py      — CKF_ENCRYPT + CKF_DECRYPT (single-part)
    testcases/test_mech_sign.py         — CKF_SIGN + CKF_VERIFY (single-part)
    testcases/test_mech_digest.py       — CKF_DIGEST
    testcases/test_mech_wrap.py         — CKF_WRAP + CKF_UNWRAP
    testcases/test_mech_derive.py       — CKF_DERIVE
    testcases/test_mech_kem.py          — CKF_ENCAPSULATE + CKF_DECAPSULATE
    testcases/test_mech_multipart.py    — C_*Update / C_*Final for all operations
    testcases/test_mech_attribute.py    — key attribute verification post-keygen/derive/unwrap
    testcases/test_mech_negative.py     — wrong key types, sizes, permissions, invalid params
    testcases/test_mech_state.py        — operation state machine violations
    testcases/test_mech_flags.py        — CKF_* flag validation against registry
    testcases/test_mech_probe.py        — unknown/vendor mechanisms: no-crash init
    testcases/test_mech_lifecycle.py    — 11 composite multi-step patterns
```

## Layer 0: Mechanism Discovery (Parametrization Strategy)

### Problem

`@pytest.mark.parametrize` runs at collection time before fixtures are available. But discovering mechanisms requires an active PKCS#11 session (`C_GetMechanismList`, `C_GetMechanismInfo`).

### Solution: Session-scoped catalog fixture + `pytest_generate_tests` hook

**Step 1:** A session-scoped fixture `p11_mechanism_catalog` in `testcases/conftest.py` probes the module once at session start:

```python
@pytest.fixture(scope="session")
def p11_mechanism_catalog(p11_module: P11Module) -> MechanismCatalog:
    """Discover all mechanisms and their info. Runs once per session."""
    raw = p11_module.raw
    slot_id = _get_slot_id(p11_module)
    mechs = get_mechanism_list(raw, slot_id)
    catalog = {}
    for mech_id in mechs:
        info = get_mechanism_info(raw, slot_id, mech_id)
        config = MECHANISM_REGISTRY.get(mech_id)
        catalog[mech_id] = MechEntry(mech_id, info, config)
    return MechanismCatalog(catalog)
```

**Step 2:** A `conftest.py` in the `testcases/` directory implements `pytest_generate_tests` to parametrize test functions based on the catalog:

```python
def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Parametrize mechanism-driven tests from the module's mechanism list."""
    if "mech_encrypt_param" in metafunc.fixturenames:
        catalog = metafunc.config.stash.get(_MECHANISM_CATALOG_KEY, None)
        if catalog is None:
            return
        params = catalog.filter(CKF_ENCRYPT, with_registry=True)
        metafunc.parametrize("mech_encrypt_param", params, ids=_make_ids(params))
```

**Step 3:** The catalog is populated during `pytest_collection_finish` (similar to how the preflight manifest works today), stored in `config.stash`, and consumed by `pytest_generate_tests`.

This avoids the collection-time vs runtime conflict because the preflight subprocess (which already runs during collection) can be extended to also collect mechanism info.

### Extending CapabilityManifest

Add `mechanism_info: dict[str, dict]` to `CapabilityManifest`:

```python
@dataclass
class CapabilityManifest:
    status: str
    module_path: str
    requested_interface: str
    interface_version: str | None
    slot_index: int
    slot_count: int | None
    mechanisms: list[str]
    mechanism_info: dict[str, dict] = field(default_factory=dict)  # NEW: {mech_name: {flags, min, max}}
    error: str | None = None
```

The preflight probe already calls `C_GetMechanismList`. Extending it to also call `C_GetMechanismInfo` for each mechanism adds ~1ms per mechanism (~0.2s for 200 mechanisms).

## Layer 1: Test Data

### Storage

Pre-generated KAT vectors in `src/pkcs11_check/testcases/data/mechanism_vectors/`. One JSON file per mechanism family. Files committed to repo. Adding a new JSON file automatically adds it to the next test run.

### Vector JSON Schema — Symmetric Keys

```json
{
  "mechanism": "CKM_AES_GCM",
  "family": "aes",
  "key_type": "CKK_AES",
  "source": "generated by scripts/generate_mechanism_vectors.py",
  "vectors": [
    {
      "id": "aes_gcm_128_basic",
      "type": "positive",
      "key_bits": 128,
      "key_hex": "000102030405060708090a0b0c0d0e0f",
      "params": {"iv_hex": "cafebabe...", "aad_hex": "", "tag_bits": 128},
      "plaintext_hex": "d9313225f88406e5...",
      "ciphertext_hex": "42831ec221777424...",
      "tag_hex": "e0e97c519b9b3cef..."
    }
  ]
}
```

### Vector JSON Schema — Asymmetric Keys

```json
{
  "mechanism": "CKM_RSA_PKCS_OAEP",
  "family": "rsa",
  "key_type": "CKK_RSA",
  "vectors": [
    {
      "id": "rsa_oaep_2048_sha256",
      "type": "positive",
      "key_bits": 2048,
      "key_components": {
        "n_hex": "...",
        "e_hex": "010001",
        "d_hex": "...",
        "p_hex": "...",
        "q_hex": "...",
        "dp_hex": "...",
        "dq_hex": "...",
        "qi_hex": "..."
      },
      "params": {"hash_mech": "CKM_SHA256", "mgf": "CKG_MGF1_SHA256"},
      "plaintext_hex": "...",
      "ciphertext_hex": "..."
    }
  ]
}
```

### Vector JSON Schema — EC Keys

```json
{
  "mechanism": "CKM_ECDSA",
  "family": "ec",
  "key_type": "CKK_EC",
  "vectors": [
    {
      "id": "ecdsa_p256_sha256",
      "type": "positive",
      "key_components": {
        "curve": "secp256r1",
        "curve_oid_hex": "06082a8648ce3d030107",
        "d_hex": "...",
        "x_hex": "...",
        "y_hex": "..."
      },
      "hash_hex": "...",
      "signature_hex": "..."
    }
  ]
}
```

### Vector JSON Schema — PQC Keys

```json
{
  "mechanism": "CKM_ML_DSA",
  "family": "pqc",
  "key_type": "CKK_ML_DSA",
  "vectors": [
    {
      "id": "ml_dsa_65_sign",
      "type": "positive",
      "key_components": {
        "parameter_set": "CKP_ML_DSA_65",
        "private_key_hex": "...",
        "public_key_hex": "..."
      },
      "message_hex": "...",
      "signature_hex": "..."
    }
  ]
}
```

### Negative Vector Schema

```json
{
  "id": "aes_gcm_wrong_key_type",
  "type": "negative",
  "category": "wrong_key_type",
  "description": "RSA key used with AES-GCM mechanism",
  "setup": {"use_key_type": "CKK_RSA", "mechanism": "CKM_AES_GCM"},
  "expected_errors": ["CKR_KEY_TYPE_INCONSISTENT", "CKR_MECHANISM_INVALID"]
}
```

### Mechanism Family Coverage (vector files)

| Family | File | Key sizes | Vectors |
|--------|------|-----------|---------|
| AES-ECB | `aes_ecb.json` | 128, 192, 256 | 3 positive + 2 negative |
| AES-CBC | `aes_cbc.json` | 128, 192, 256 | 3 positive + 2 negative |
| AES-CBC-PAD | `aes_cbc_pad.json` | 128, 192, 256 | 3 positive incl non-aligned |
| AES-CTR | `aes_ctr.json` | 128, 192, 256 | 3 positive |
| AES-GCM | `aes_gcm.json` | 128, 192, 256 | 3 positive + AAD variants + tag size variants |
| AES-CCM | `aes_ccm.json` | 128, 192, 256 | 3 positive + nonce size variants |
| AES-OFB | `aes_ofb.json` | 128, 192, 256 | 2 positive |
| AES-CFB128 | `aes_cfb128.json` | 128, 192, 256 | 2 positive |
| AES-XTS | `aes_xts.json` | 256, 512 (double) | 2 positive |
| AES-CMAC | `aes_cmac.json` | 128, 192, 256 | 3 positive (MAC only) |
| AES-KEY-WRAP | `aes_keywrap.json` | 128, 192, 256 | 2 positive per variant |
| RSA-PKCS | `rsa_pkcs.json` | 2048, 3072 | 2 encrypt + 2 sign |
| RSA-OAEP | `rsa_oaep.json` | 2048, 3072 | SHA-256/384/512 variants |
| RSA-PSS | `rsa_pss.json` | 2048, 3072 | SHA-256/384/512 + salt length variants |
| ECDSA | `ecdsa.json` | P-256, P-384, P-521 | 3 per curve |
| EdDSA | `eddsa.json` | Ed25519, Ed448 | 2 per curve |
| SHA family | `sha.json` | N/A | SHA-1/224/256/384/512 + SHA-512/224/256 |
| SHA-3 family | `sha3.json` | N/A | SHA3-224/256/384/512 |
| HMAC | `hmac.json` | SHA-256/384/512 | 2 per hash + HMAC-GENERAL variants |
| HKDF | `hkdf.json` | SHA-256, SHA-512 | extract-only, expand-only, both |
| PBKDF2 | `pbkdf2.json` | SHA-256 | 2 positive (deterministic) |
| ML-DSA | `ml_dsa.json` | 44, 65, 87 | 2 per param set |
| ML-KEM | `ml_kem.json` | 512, 768, 1024 | 2 per param set |
| SLH-DSA | `slh_dsa.json` | SHA2-128s, SHA2-128f | 1 per param set |
| ChaCha20-Poly1305 | `chacha20_poly1305.json` | 256 | 2 positive |
| DES3 | `des3.json` | 168 | 2 positive (ECB, CBC) |
| Negative matrix | `negative_cases.json` | mixed | All negative categories |

### Generator Script

`scripts/generate_mechanism_vectors.py` uses the `cryptography` Python library:

```bash
uv run python scripts/generate_mechanism_vectors.py --all
uv run python scripts/generate_mechanism_vectors.py --family aes_gcm
```

Uses fixed seeds for reproducibility. Idempotent.

## Layer 2: Mechanism Registry

### MechConfig Dataclass

```python
@dataclass(frozen=True)
class MechConfig:
    """Configuration for testing a specific mechanism."""
    key_type: int                          # CKK_AES, CKK_RSA, etc.
    keygen_mech: int                       # mechanism to generate the right key
    key_sizes: tuple[int, ...]             # valid key sizes in bits
    is_keypair: bool                       # True for asymmetric (C_GenerateKeyPair)
    param_packer: str | None               # "mech_gcm", "mech_pss", etc.
    param_factory: str | None              # function that creates default test params
    block_size: int | None                 # 16 for AES block modes, None for stream
    vector_file: str | None                # path to JSON vectors file
    input_constraint: str                  # "block_aligned", "any", "digest_only", "none"
    multi_part_supported: bool = True      # False for AEAD (GCM/CCM), raw ECDSA
    param_required: bool = False           # True if C_*Init needs non-NULL params
    auth_tag_included: bool = False        # True for GCM/CCM (ciphertext includes tag)
    deterministic: bool = True             # False for CBC with random IV, RSA-OAEP
    expected_flags: int = 0                # expected CKF_* flags for flag validation
    notes: str = ""
```

### Registry Size

~250 entries covering:
- AES (23 mechanisms: ECB, CBC, CBC-PAD, CTR, GCM, CCM, OFB, CFB variants, CTS, XTS, MAC, CMAC, XCBC-MAC, GMAC, key wraps, key gen)
- RSA (20+ mechanisms: PKCS, OAEP, PSS, X9.31, hash-specific sign variants, key gen)
- EC (15+ mechanisms: ECDSA, ECDSA-SHA*, EdDSA, XEdDSA, ECDH variants, key gens)
- Hash (20 mechanisms: SHA-1/2/3 family, SHA-512/t, BLAKE2)
- HMAC (24 mechanisms: 12 hash variants × standard + GENERAL)
- HMAC key gen (12 mechanisms)
- Key derivation by hash (12 mechanisms)
- HKDF (3 mechanisms)
- PBKDF2 (1 mechanism)
- SP800-108 (3 mechanisms)
- TLS/SSL (17 mechanisms)
- PQC (10+ mechanisms: ML-KEM, ML-DSA, SLH-DSA, HASH_ML_DSA variants, HASH_SLH_DSA variants)
- Stateful sigs (6 mechanisms: HSS, XMSS, XMSS-MT)
- DES3 (7 mechanisms)
- ChaCha20/Poly1305 (4 mechanisms)
- Camellia (8 mechanisms)
- ARIA (8 mechanisms)
- Legacy (probe-only: ~200 mechanisms)

### Fallback

Mechanisms not in the registry get probe tests (test_mech_probe.py): call `C_*Init`, verify no crash, verify valid CKR returned.

## Layer 3: Operation Tests (14 files)

### test_mech_keygen.py — Key Generation (~75 tests)

Per registered keygen mechanism × each key size:
- Generate key, verify handle != 0
- Verify `CKA_LOCAL = True`
- Verify `CKA_KEY_GEN_MECHANISM` matches the mechanism used
- Verify key type matches `CKA_KEY_TYPE`
- Test at exactly `min_key_size` and `max_key_size` from C_GetMechanismInfo (boundary)

### test_mech_encrypt.py — Single-Part Encrypt/Decrypt (~240 tests)

Per registered encrypt mechanism × each key size:
- **Roundtrip:** encrypt → decrypt → verify plaintext matches
- **KAT vectors:** encrypt with known key/input → verify output matches pre-generated vector
- **Empty plaintext:** 0 bytes (stream modes should succeed, ECB should fail)
- **Single byte:** 1 byte plaintext
- **Block boundary:** exactly 1 block, exactly 2 blocks
- **Non-aligned negative:** for block modes, non-aligned input → CKR_DATA_LEN_RANGE
- **Different keys produce different ciphertext** (for deterministic modes)

### test_mech_sign.py — Single-Part Sign/Verify (~200 tests)

Per registered sign mechanism × each key size:
- **Roundtrip:** sign → verify → True
- **KAT vectors:** sign with known key → verify signature matches (deterministic sigs only)
- **Wrong data verify:** sign data A, verify with data B → False
- **Bit-flip signature:** flip one bit in valid signature → verify returns False/CKR_SIGNATURE_INVALID
- **Truncated signature:** first N-1 bytes → CKR_SIGNATURE_LEN_RANGE
- **Wrong key verify:** sign with key A, verify with key B → False
- **Empty message:** where applicable

### test_mech_digest.py — Digest (~72 tests)

Per registered digest mechanism:
- **KAT vector:** hash known input → verify matches expected output
- **Empty input:** hash of empty string
- **Known test strings:** "abc", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
- **Length verification:** output length matches spec

### test_mech_wrap.py — Wrap/Unwrap (~46 tests)

Per registered wrap mechanism × key sizes:
- **Roundtrip:** generate key → encrypt data → wrap key → destroy → unwrap → decrypt → verify
- **Wrapped blob corruption:** flip bits → unwrap fails
- **Non-extractable target:** wrap key with CKA_EXTRACTABLE=False → CKR_KEY_UNEXTRACTABLE
- **Hybrid wraps:** RSA-AES, ECDH-AES (if supported)

### test_mech_derive.py — Key Derivation (~59 tests)

Per registered derive mechanism:
- **ECDH:** derive per curve × KDF variant, verify derived key is usable
- **HKDF:** extract-only, expand-only, extract+expand, salt variants
- **PBKDF2:** deterministic (same password → same key), derived key usable for AES
- **KAT vectors:** where available, verify derived key value matches expected

### test_mech_kem.py — Encapsulate/Decapsulate (~18 tests)

Per KEM mechanism × parameter set:
- **Roundtrip:** encapsulate → decapsulate → verify same shared secret
- **Derived key usable:** encapsulate to AES key → encrypt/decrypt works
- **Corrupted ciphertext:** bit-flip → decapsulate fails or produces different key
- **Wrong private key:** decapsulate with wrong key → different/failed result

### test_mech_multipart.py — Multi-Part Streaming (~120 tests)

Per mechanism with `multi_part_supported=True` × key sizes:
- **Streaming roundtrip:** C_EncryptInit → C_EncryptUpdate (chunks) → C_EncryptFinal → C_DecryptInit → C_DecryptUpdate → C_DecryptFinal → verify plaintext
- **Different chunking same result:** split data 3 ways, all produce same ciphertext
- **Sign streaming:** C_SignInit → C_SignUpdate → C_SignFinal → C_VerifyInit → C_VerifyUpdate → C_VerifyFinal
- **Digest streaming:** C_DigestInit → C_DigestUpdate → C_DigestFinal → compare with single-part

### test_mech_attribute.py — Key Attribute Verification (~45 tests)

After each keygen/derive/unwrap operation:
- **CKA_LOCAL:** True for generated, False for imported/derived/unwrapped
- **CKA_KEY_GEN_MECHANISM:** contains mechanism used for generation; CK_UNAVAILABLE_INFORMATION for imported
- **CKA_ALWAYS_SENSITIVE:** True if CKA_SENSITIVE has always been True since creation
- **CKA_NEVER_EXTRACTABLE:** True if CKA_EXTRACTABLE has always been False
- **CKA_COPYABLE/CKA_DESTROYABLE:** default values per spec
- **Key type matches template:** CKA_KEY_TYPE matches what was requested

### test_mech_negative.py — Negative Tests (~140 tests)

**Wrong key type (~25 pairs):**
Every major operation × incompatible key type:
- AES mechs with RSA/EC/generic keys
- RSA mechs with AES/EC keys
- EC mechs with RSA/AES keys
- HMAC mechs with AES keys (not generic secret)
- PQC mechs with wrong PQC/classical key types

**Invalid parameters (~20 cases):**
- AES-GCM: IV length 0, IV length 1, tag_bits=0, tag_bits=7 (non-standard)
- AES-CBC: IV length != 16
- AES-CTR: counter_bits=0, counter_bits=129
- RSA-PSS: salt_len > key_size, hash != mgf hash
- RSA-OAEP: hash=CKM_AES_ECB (not a hash)
- ECDH: NULL public data, kdf=0xFFFF
- HKDF: bExtract=False + bExpand=False
- AES-CCM: nonce_len=0, mac_len=0

**Missing permission flags (~45 tests):**
For each flag × applicable mechanisms:
- CKA_ENCRYPT=False → C_EncryptInit fails
- CKA_DECRYPT=False → C_DecryptInit fails
- CKA_SIGN=False → C_SignInit fails
- CKA_VERIFY=False → C_VerifyInit fails
- CKA_WRAP=False → C_WrapKey fails
- CKA_UNWRAP=False → C_UnwrapKey fails
- CKA_DERIVE=False → C_DeriveKey fails
- CKA_ENCAPSULATE=False → C_EncapsulateKey fails
- CKA_DECAPSULATE=False → C_DecapsulateKey fails

**State machine violations (~50 tests):**
Per mechanism family (AES, RSA, EC, HMAC, digest):
- C_Encrypt without C_EncryptInit → CKR_OPERATION_NOT_INITIALIZED
- C_EncryptInit twice → CKR_OPERATION_ACTIVE
- C_EncryptUpdate after C_Encrypt → CKR_OPERATION_NOT_INITIALIZED
- C_EncryptFinal without C_EncryptUpdate → varies
- C_DecryptUpdate with encrypt active → CKR_OPERATION_NOT_INITIALIZED

### test_mech_state.py — Operation State Machine (~50 tests)

Dedicated file for state machine tests (separated from negative tests for clarity):
- Init → operation active → complete → operation inactive
- Double init rejection
- Cross-operation rejection (encrypt active, try sign)
- Operation abort (C_EncryptInit then different C_*Init)
- C_GetOperationState / C_SetOperationState where supported

### test_mech_flags.py — Mechanism Flag Validation (~30 tests)

Per registered mechanism:
- Compare `C_GetMechanismInfo().flags` against `MechConfig.expected_flags`
- Flag CKF_ENCRYPT on digest-only mechanism → spec violation
- Flag CKF_SIGN missing on signature mechanism → spec violation
- Validate CKF_EC_* flags for EC mechanisms (CKF_EC_F_P, CKF_EC_OID, CKF_EC_UNCOMPRESS)
- Validate min_key_size ≤ max_key_size

### test_mech_probe.py — Unknown Mechanism Probing (~40 tests)

Per unregistered mechanism advertised by the module:
- Call C_*Init with mechanism + generic secret key
- Verify return is a valid CKR (not crash/segfault)
- Log the CKR for analysis
- If CKR_OK, attempt a simple operation and log result

### test_mech_lifecycle.py — 11 Composite Patterns (~22 tests)

1. **KEM→Use:** Encapsulate → AES key → encrypt → decapsulate → same key → decrypt
2. **ECDH→HKDF:** Derive shared secret → HKDF expand → AES encrypt
3. **Wrap→Unwrap→Use:** Generate → encrypt → wrap key → destroy → unwrap → decrypt
4. **AEAD Wrap with AAD:** Wrap with AAD → unwrap same AAD → use. Wrong AAD → fail.
5. **RSA-AES Hybrid Wrap:** Wrap large RSA key → unwrap → verify signature
6. **HKDF 2-Phase:** Extract-only → expand-only = extract+expand single call
7. **PBKDF2→AES:** Derive AES from password → encrypt → same password = same result
8. **Chained Derivation:** ECDH(CKD_NULL) → HKDF → AES key → encrypt
9. **SP800-108 Multi-Key:** Single derive → primary + additional keys → both usable
10. **TLS 1.2 Chain:** Pre-master → master → key material → MAC (4 steps)
11. **ECDH-AES Key Wrap:** EC agree + AES-KWP in one call → unwrap → verify

## Relationship to Existing Tests

The new `test_mech_*.py` files are **additive and complementary** to existing test files. Existing files remain and continue to work. The delineation:

- **Existing tests** (`test_encrypt.py`, `test_sign.py`, etc.) — hand-crafted tests for specific scenarios, module-specific edge cases, CVE regressions, security findings
- **New mechanism-driven tests** — systematic, auto-parametrized coverage of every advertised mechanism, ensuring no mechanism is untested

Over time, some existing tests may become redundant as the mechanism-driven system matures, but that cleanup is a separate future task.

## Test Count Estimation

| Category | Tests |
|----------|-------|
| Keygen + attribute check | 75 |
| Encrypt/decrypt + edge cases | 240 |
| Sign/verify + edge cases | 200 |
| Digest + known vectors | 72 |
| Wrap/unwrap + corruption | 46 |
| Derive chains | 59 |
| KEM roundtrip | 18 |
| Multi-part streaming | 120 |
| Attribute verification | 45 |
| Negative (all categories) | 140 |
| State machine violations | 50 |
| Flag validation | 30 |
| Probe (unknown mechs) | 40 |
| Lifecycle (11 patterns) | 22 |
| KAT vectors | 160 |
| **Total (full module)** | **~1,317** |

## Markers

- `@pytest.mark.mechanism_coverage` — all mechanism-driven tests
- `@pytest.mark.encrypt`, `@pytest.mark.sign`, `@pytest.mark.digest`, etc. — per operation
- `@pytest.mark.negative` — negative tests
- `@pytest.mark.lifecycle` — composite patterns
- `@pytest.mark.kat` — known-answer tests
- `@pytest.mark.multipart` — multi-part streaming tests
