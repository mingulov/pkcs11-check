# Test Migration Batch 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate all remaining ~170 test and helper files from python-pkcs11 fork imports to pkcs11_check.raw, completing the fork removal migration.

**Architecture:** Mechanical migration per file: replace fork enums/methods/exceptions with raw typed constants, recipe functions, and direct CKR value checks. `p11_raw_session` replaces `p11_session`. No test logic changes. No new xfails or skips.

**Tech Stack:** Python 3.11+, pytest, pkcs11_check.raw (types_std, pack, recipes, rv, der, ec, bootstrap)

**Prerequisites:** Sub-projects 1 (Raw Layer Completion) and 2 (Batch 1) from the fork-removal master plan are complete.

**References:**
- Master plan: `docs/superpowers/plans/2026-03-25-fork-removal-master-plan.md`
- Raw package: `src/pkcs11_check/raw/README.md`
- Raw architecture: `docs/superpowers/specs/2026-03-23-pkcs11-raw-architecture-design.md`
- CLAUDE.md has project rules, test patterns, error handling policy

**Helper files with fork imports (NOT blockers during migration):**
These files have `from pkcs11` imports but are NOT blocking prerequisites. Migrated tests use raw equivalents (e.g., `rs.has_mechanism()` instead of conftest's `has_mechanism()`), so these helpers continue serving unmigrated tests during the transition. Migrate them in Task 10 as cleanup:
- `src/pkcs11_check/testcases/conftest.py` — shared helpers (`has_mechanism`, `import_aes_key`, etc.)
- `src/pkcs11_check/testcases/_error_tuples.py` — error tuple definitions (verify: `grep "from pkcs11" src/pkcs11_check/testcases/_error_tuples.py`)
- `src/pkcs11_check/testcases/wycheproof/_key_decoders.py` — key import helpers
- `src/pkcs11_check/testcases/x509/conftest.py` — X.509 shared fixtures
- `src/pkcs11_check/testcases/ckr/_ckr_spec.py` — CKR spec tables (already listed in Task 10)

---

## Migration Pattern Reference

All tasks reference this section. Workers MUST follow these tables exactly.

### Import Replacement

| Old (fork) | New (raw) |
|---|---|
| `from pkcs11 import Attribute` | `from pkcs11_check.raw.types_std import CKA_CLASS, CKA_ENCRYPT, ...` (list only needed constants) |
| `from pkcs11 import KeyType` | `from pkcs11_check.raw.types_std import CKK_AES, CKK_RSA, ...` |
| `from pkcs11 import Mechanism` | `from pkcs11_check.raw.types_std import CKM_AES_KEY_GEN, CKM_RSA_PKCS, ...` |
| `from pkcs11 import ObjectClass` | `from pkcs11_check.raw.types_std import CKO_SECRET_KEY, CKO_DATA, ...` |
| `from pkcs11.constants import MLKemParameterSet` | `from pkcs11_check.raw.types_std import CKP_ML_KEM_768, ...` (verify names with grep) |
| `from pkcs11.constants import MLDsaParameterSet` | `from pkcs11_check.raw.types_std import CKP_ML_DSA_65, ...` (verify names with grep) |
| `from pkcs11.mechanisms import KDF` | `from pkcs11_check.raw.types_std import CKD_NULL, CKD_SHA1_KDF, ...` |
| `from pkcs11.mechanisms import MGF` | `from pkcs11_check.raw.types_std import CKG_MGF1_SHA1, CKG_MGF1_SHA256, ...` |
| `from pkcs11.util.ec import encode_named_curve_parameters` | `from pkcs11_check.raw.ec import encode_named_curve_parameters` |
| `from pkcs11.exceptions import *` | No import; use CKR value checks (see Error Handling below) |
| `from pkcs11_check.testcases.conftest import has_mechanism` | Use `rs.has_mechanism("NAME")` on RawSession |
| `from pkcs11_check.testcases.conftest import import_aes_key` | `from pkcs11_check.raw.recipes import import_secret_key` |
| `from pkcs11_check.testcases.conftest import extract_ec_point` | `from pkcs11_check.raw.der import decode_ec_point` |

### Fixture Replacement

| Old | New |
|---|---|
| `def test_x(self, p11_session, p11_module):` | `def test_x(self, p11_raw_session):` |
| `p11_session` | `rs = p11_raw_session` then use `rs.raw`, `rs.sh` |
| `p11_module` | `rs.raw` (RawPKCS11), `rs.slot_id`, `rs.mechanisms` |
| `has_mechanism(p11_module, "AES_ECB")` | `rs.has_mechanism("AES_ECB")` |
| `p11_config` | Keep as-is (still needed for PIN, module path) |
| `p11_interface_version` | Keep as-is (still needed for version checks) |

### Operation Replacement

| Old (fork) | New (raw) |
|---|---|
| `session.generate_key(KeyType.AES, 256, template={...})` | `gen_aes_key(rs.raw, rs.sh, 256, attrs={int(CKA_X): val, ...})` |
| `session.generate_keypair(KeyType.RSA, 2048)` | `gen_rsa_keypair(rs.raw, rs.sh, 2048)` |
| `session.generate_keypair(KeyType.EC, curve_params)` | `gen_ec_keypair(rs.raw, rs.sh, curve_oid)` |
| `key.encrypt(data, mechanism=Mechanism.X)` | `encrypt_single(rs.raw, rs.sh, key, CKM_X, data)` |
| `key.decrypt(data, mechanism=Mechanism.X)` | `decrypt_single(rs.raw, rs.sh, key, CKM_X, data)` |
| `key.sign(data, mechanism=Mechanism.X)` | `sign_single(rs.raw, rs.sh, key, CKM_X, data)` |
| `key.verify(data, sig, mechanism=Mechanism.X)` | `verify_single(rs.raw, rs.sh, key, CKM_X, data, sig)` |
| `session.digest(data, mechanism=Mechanism.X)` | `digest_single(rs.raw, rs.sh, CKM_X, data)` |
| `key.wrap_key(target, mechanism=Mechanism.X)` | `wrap_key(rs.raw, rs.sh, key, target, CKM_X)` |
| `key.unwrap_key(ObjectClass.SECRET_KEY, ...)` | `unwrap_key(rs.raw, rs.sh, key, wrapped, CKM_X, attrs=...)` |
| `base_key.derive_key(KeyType.AES, 256, ...)` | `derive_key(rs.raw, rs.sh, base_key, CKM_X, attrs=...)` |
| `key.destroy()` | `destroy_quietly(rs.raw, rs.sh, key)` |
| `session.get_objects(template)` | `find_objects(rs.raw, rs.sh, tmpl)` |
| `obj[Attribute.VALUE]` | `read_attributes(rs.raw, rs.sh, obj, [int(CKA_VALUE)])[int(CKA_VALUE)]` |
| `session.create_object(template)` | `create_object(rs.raw, rs.sh, attrs_dict)` |
| `session.copy_object(obj, template)` | `copy_object(rs.raw, rs.sh, obj, attrs_dict)` |
| `session.generate_random(16)` | `generate_random(rs.raw, rs.sh, 16)` |

### Mechanism Parameter Replacement

| Old (fork) | New (raw) |
|---|---|
| `mechanism_param=iv` (raw bytes for CBC) | `mech_param=mech_bytes(CKM_X, iv)` |
| GCM params object | `mech_param=mech_gcm(CKM_X, iv, aad_len=0, tag_bits=128)` |
| RSA-PSS params object | `mech_param=mech_pss(CKM_X, hash_mech=CKM_SHA256, mgf=CKG_MGF1_SHA256, salt_len=32)` |
| RSA-OAEP params object | `mech_param=mech_oaep(CKM_X, hash_mech=CKM_SHA256, mgf=CKG_MGF1_SHA256, source_data=None)` |
| ECDH derive params object | `mech_param=mech_ecdh(CKM_X, kdf=CKD_NULL, public_data=pub_bytes, shared_data=None)` |
| HKDF params object | `mech_param=mech_hkdf(CKM_X, hash_mech=CKM_SHA256, extract=True, expand=True, salt_type=1, salt=None, salt_key=0, info=None)` |
| EdDSA params object | `mech_param=mech_eddsa(CKM_X, context_data=None)` |
| ChaCha20 params object | `mech_param=mech_chacha20(CKM_X, nonce, counter=0)` |
| ChaCha20-Poly1305 params object | `mech_param=mech_chacha20_poly1305(CKM_X, nonce, aad=None)` |
| PBKDF2 params object | `mech_param=mech_pbkdf2(CKM_X, salt=salt_bytes, iterations=10000, prf=CKP_PKCS5_PBKD2_HMAC_SHA256, password=None)` |
| CTR params object | `mech_param=mech_ctr(CKM_X, bits=128)` |
| String data derivation params | `mech_param=mech_string_data(CKM_X, data)` |
| No parameter (simple mechanism) | `mech_param=None` (default) |

### Error Handling Replacement

Recipes (`encrypt_single`, `sign_single`, etc.) call `expect_rv()` which raises `AssertionError` on non-OK CKR. For **happy-path** tests, let exceptions propagate naturally (test fails on error).

For **error-path** tests that assert specific CKR codes, use raw C_* calls directly:

```python
# OLD: catch specific fork exception
try:
    key.encrypt(data, mechanism=Mechanism.AES_ECB)
except MechanismInvalid:
    pass  # expected

# NEW: raw call + CKR check
from pkcs11_check.raw.pack import mech_simple
from pkcs11_check.raw.types_std import CKR_MECHANISM_INVALID, CKR_MECHANISM_PARAM_INVALID
from ctypes import create_string_buffer, byref, c_ulong

rv = rs.raw.C_EncryptInit(rs.sh, mech_simple(CKM_AES_ECB).byref(), key)
assert int(rv) in {int(CKR_MECHANISM_INVALID), int(CKR_MECHANISM_PARAM_INVALID)}
```

For **generic error sets** (template/keygen failures), define acceptable CKR sets:

```python
_TEMPLATE_ERRORS = {int(c) for c in (
    CKR_ATTRIBUTE_TYPE_INVALID, CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_TEMPLATE_INCOMPLETE, CKR_TEMPLATE_INCONSISTENT, CKR_ARGUMENTS_BAD,
)}

try:
    gen_aes_key(rs.raw, rs.sh, 256, attrs={int(CKA_TOKEN): True})
except AssertionError as e:
    # expect_rv() raises AssertionError with CKR name in message
    assert any(ckr_name(int(c)) in str(e) for c in _TEMPLATE_ERRORS), f"Unexpected error: {e}"
```

### Template Building

```python
# OLD:
key = session.generate_key(KeyType.AES, 256, template={
    Attribute.ENCRYPT: True, Attribute.DECRYPT: True, Attribute.TOKEN: False
})

# NEW:
key = gen_aes_key(rs.raw, rs.sh, 256, attrs={
    int(CKA_ENCRYPT): True, int(CKA_DECRYPT): True, int(CKA_TOKEN): False,
})
```

For `create_object` and `find_objects` that need full templates:

```python
from pkcs11_check.raw.pack import attr_bytes, attr_ulong, attr_bool, template

tmpl = template(
    attr_ulong(CKA_CLASS, int(CKO_DATA)),
    attr_bytes(CKA_LABEL, b"my-label"),
    attr_bool(CKA_TOKEN, False),
)
h = create_object(rs.raw, rs.sh, tmpl)
```

### Object Cleanup

Always `try/finally` with `destroy_quietly`:

```python
key = gen_aes_key(rs.raw, rs.sh, 256)
try:
    # test logic
finally:
    destroy_quietly(rs.raw, rs.sh, key)
```

### Per-File Migration Procedure

For each file:

1. Read the file, identify all `from pkcs11` imports
2. Replace imports per tables above (import only what's needed)
3. Replace fixture `p11_session` with `p11_raw_session`, add `rs = p11_raw_session`
4. Replace all operations per operation table
5. Replace mechanism parameters per mech param table
6. Replace exception-based error handling with CKR checks
7. Ensure cleanup uses `destroy_quietly` in `finally`
8. Run: `uv run python -m pytest <file> -v --timeout=60 -x` with SoftHSM2
9. Fix any failures (adjust CKR sets, fix parameter formats)
10. Run: `uv run ruff check <file> && uv run ruff format <file>`
11. Commit: `git add <file> && git commit -m "refactor: migrate <filename> to pkcs11_check.raw"`

### Verification After Each Task

```bash
# Verify no fork imports remain in migrated files
grep -rn "from pkcs11 " <migrated_files>
grep -rn "from pkcs11\." <migrated_files>

# Run migrated tests
bash local-builds/test.sh softhsm2 <test_path> -v

# Lint + format
uv run ruff check src/pkcs11_check/testcases/ && uv run ruff format src/pkcs11_check/testcases/
```

---

## Task 1: Infrastructure Verification

**Goal:** Verify all raw equivalents exist before starting migrations. No code changes.

- [ ] **Step 1: Verify PQC constant names**

```bash
uv run python -c "from pkcs11_check.raw.types_std import CKP_ML_KEM_768; print('OK')"
uv run python -c "from pkcs11_check.raw.types_std import CKP_ML_DSA_65; print('OK')"
uv run python -c "from pkcs11_check.raw.types_std import CKP_SLH_DSA_SHA2_128S; print('OK')"
```

If any fail, grep for the actual names: `grep -n "ML_KEM\|ML_DSA\|SLH_DSA" src/pkcs11_check/raw/types_std.py`

- [ ] **Step 2: Verify KDF/MGF constant names**

```bash
uv run python -c "from pkcs11_check.raw.types_std import CKD_NULL, CKD_SHA1_KDF, CKD_SHA256_KDF; print('OK')"
uv run python -c "from pkcs11_check.raw.types_std import CKG_MGF1_SHA1, CKG_MGF1_SHA256, CKG_MGF1_SHA384, CKG_MGF1_SHA512; print('OK')"
```

- [ ] **Step 3: Verify TLS mechanism packer availability**

```bash
grep -n "mech_tls\|TLS12\|SSL3\|CK_TLS" src/pkcs11_check/raw/pack.py
```

If no TLS packers exist, note this: TLS/SSL/IKE KDF mechanisms are vendor extensions (not in PKCS#11 v3.2 standard). Protocol tests (test_tls12.py, test_ssl3.py, test_wtls.py) will need `mech_bytes()` with manually packed structs, or new packers added to pack.py as a prerequisite.

- [ ] **Step 4: Verify IKE/X3DH mechanism packer availability**

```bash
grep -n "mech_ike\|IKE\|X3DH\|CK_IKE\|CK_X3DH" src/pkcs11_check/raw/pack.py
```

Note any missing packers for Task 10.

- [ ] **Step 5: Verify DER helpers**

```bash
uv run python -c "
from pkcs11_check.raw.der import (
    ecdsa_sig_to_der, ecdsa_sig_from_der,
    ecdsa_sig_p1363_to_der, ecdsa_sig_der_to_p1363,
    encode_ec_point, decode_ec_point,
    encode_rsa_public_key_der, decode_rsa_public_key_der,
)
print('All DER helpers available')
"
```

- [ ] **Step 6: Verify recipe completeness**

```bash
uv run python -c "
from pkcs11_check.raw.recipes import (
    gen_aes_key, gen_rsa_keypair, gen_ec_keypair,
    encrypt_single, decrypt_single, sign_single, verify_single, digest_single,
    encrypt_multipart, decrypt_multipart, sign_multipart, verify_multipart, digest_multipart,
    wrap_key, unwrap_key, derive_key,
    import_secret_key, create_object, destroy_quietly, copy_object,
    find_objects, read_attributes, set_attributes, get_object_size,
    generate_random, seed_random,
    save_operation_state, restore_operation_state,
    init_token, init_pin, set_pin,
    get_mechanism_list,
    encapsulate_key, decapsulate_key,
    wrap_key_authenticated, unwrap_key_authenticated,
    message_encrypt, message_decrypt,
)
print('All recipes available')
"
```

- [ ] **Step 7: Document any gaps**

If any verification step fails, document the gap and what needs to be added before the affected task. Create the missing helper if it's small (< 20 lines), or note it as a blocker.

- [ ] **Step 8: Get definitive file count**

```bash
# Files still importing from fork
grep -rl "from pkcs11 " src/pkcs11_check/testcases/ | grep "\.py$" | wc -l
grep -rl "from pkcs11\." src/pkcs11_check/testcases/ | grep "\.py$" | wc -l

# Combined unique count
grep -rl "from pkcs11[ .]" src/pkcs11_check/testcases/ | grep "\.py$" | sort -u | wc -l
```

Record the number. This is the migration target.

---

## Task 2: Asymmetric Crypto (13 files)

**Goal:** Migrate EC, EdDSA, ECDH, RSA extended, and PQC tests.

**Files:**
- `src/pkcs11_check/testcases/test_ec_curves.py` (~115 lines)
- `src/pkcs11_check/testcases/test_ecdsa_extended.py` (~130 lines)
- `src/pkcs11_check/testcases/test_ecdh_extended.py` (~740 lines) — largest, uses KDF params
- `src/pkcs11_check/testcases/test_ecdh_known_answer.py` (~145 lines)
- `src/pkcs11_check/testcases/test_ec_import_export.py` (~145 lines)
- `src/pkcs11_check/testcases/test_eddsa.py` (~185 lines)
- `src/pkcs11_check/testcases/test_rsa_oaep.py` (~103 lines)
- `src/pkcs11_check/testcases/test_rsa_extended.py` (~486 lines) — PSS, OAEP, PKCS#1
- `src/pkcs11_check/testcases/test_rsa_key_import.py` (~164 lines)
- `src/pkcs11_check/testcases/test_kem.py` (~420 lines) — ML-KEM, v3.2
- `src/pkcs11_check/testcases/test_pqc_sign.py` (~242 lines) — ML-DSA, SLH-DSA
- `src/pkcs11_check/testcases/test_hash_ml_dsa.py` (~235 lines)
- `src/pkcs11_check/testcases/test_hash_slh_dsa.py` (~235 lines)

**Special notes:**

- **ECDH tests** use `pkcs11.mechanisms.KDF` enum — replace with `CKD_*` constants from types_std. The `mech_ecdh()` packer handles `CK_ECDH1_DERIVE_PARAMS`.
- **RSA-PSS/OAEP** use `pkcs11.mechanisms.MGF` enum — replace with `CKG_MGF1_*` constants. Use `mech_pss()` and `mech_oaep()` packers.
- **RSA key import** creates objects with raw key material (N, E, D, P, Q) — use `create_object()` with template of `attr_bytes(CKA_MODULUS, n_bytes)`, etc.
- **PQC tests** use `pkcs11.constants.MLKemParameterSet` etc. — replace with `CKP_*` constants (verify names in Task 1 Step 1). Use `encapsulate_key()`/`decapsulate_key()` recipes.
- **EdDSA** uses `mech_eddsa()` packer for context_data parameter.
- **EC curve encoding:** Replace `pkcs11.util.ec.encode_named_curve_parameters` with `pkcs11_check.raw.ec.encode_named_curve_parameters` (same function name, different module).
- **DER signature conversion:** Replace any `pkcs11.util.ec` signature helpers with `pkcs11_check.raw.der.ecdsa_sig_p1363_to_der()` etc.
- **Cross-verify with cryptography lib:** Some tests compare PKCS#11 results against Python `cryptography` library. The `cryptography` import stays unchanged — only PKCS#11 operations migrate.

**Suggested order:** Start with the simpler EC files (test_ec_curves, test_ecdsa_extended), then ECDH, then RSA, then PQC (most complex).

- [ ] **Step 1:** Read each file, noting fork imports and operations used
- [ ] **Step 2:** Migrate test_ec_curves.py — apply per-file procedure
- [ ] **Step 3:** Run `uv run python -m pytest src/pkcs11_check/testcases/test_ec_curves.py -v --timeout=60`
- [ ] **Step 4:** Migrate test_ecdsa_extended.py
- [ ] **Step 5:** Run tests for test_ecdsa_extended.py
- [ ] **Step 6:** Migrate test_ecdh_known_answer.py
- [ ] **Step 7:** Run tests
- [ ] **Step 8:** Migrate test_ecdh_extended.py (largest — has ECDH KDF params, use `mech_ecdh()`)
- [ ] **Step 9:** Run tests
- [ ] **Step 10:** Migrate test_ec_import_export.py
- [ ] **Step 11:** Run tests
- [ ] **Step 12:** Migrate test_eddsa.py (use `mech_eddsa()` packer)
- [ ] **Step 13:** Run tests
- [ ] **Step 14:** Commit EC/EdDSA batch: `git commit -m "refactor: migrate EC/EdDSA/ECDH tests to pkcs11_check.raw"`
- [ ] **Step 15:** Migrate test_rsa_oaep.py (use `mech_oaep()`)
- [ ] **Step 16:** Run tests
- [ ] **Step 17:** Migrate test_rsa_extended.py (use `mech_pss()`, `mech_oaep()`)
- [ ] **Step 18:** Run tests
- [ ] **Step 19:** Migrate test_rsa_key_import.py (use `create_object()` with RSA component attrs)
- [ ] **Step 20:** Run tests
- [ ] **Step 21:** Commit RSA batch: `git commit -m "refactor: migrate RSA extended tests to pkcs11_check.raw"`
- [ ] **Step 22:** Migrate test_kem.py (use `encapsulate_key()`, `decapsulate_key()`, PQC constants)
- [ ] **Step 23:** Run tests
- [ ] **Step 24:** Migrate test_pqc_sign.py
- [ ] **Step 25:** Run tests
- [ ] **Step 26:** Migrate test_hash_ml_dsa.py and test_hash_slh_dsa.py
- [ ] **Step 27:** Run tests
- [ ] **Step 28:** Commit PQC batch: `git commit -m "refactor: migrate PQC tests to pkcs11_check.raw"`
- [ ] **Step 29:** Verify no fork imports remain: `grep -rn "from pkcs11[ .]" src/pkcs11_check/testcases/test_ec* src/pkcs11_check/testcases/test_ecdh* src/pkcs11_check/testcases/test_eddsa* src/pkcs11_check/testcases/test_rsa* src/pkcs11_check/testcases/test_kem* src/pkcs11_check/testcases/test_pqc* src/pkcs11_check/testcases/test_hash_*`
- [ ] **Step 30:** Run full batch: `bash local-builds/test.sh softhsm2 -k "ec or rsa or pqc or kem or eddsa" -v`

---

## Task 3: Key Wrapping, Cross-verify, CVE, Stress (8 files)

**Goal:** Migrate the remaining explicitly-identified complex test categories.

**Files:**
- `src/pkcs11_check/testcases/test_authenticated_wrap.py` (~94 lines) — v3.2 authenticated wrap
- `src/pkcs11_check/testcases/test_rsa_key_wrapping.py` (~168 lines)
- `src/pkcs11_check/testcases/test_crossverify.py` (~330 lines) — cross-lib verification
- `src/pkcs11_check/testcases/test_crossverify_extended.py` (~215 lines)
- `src/pkcs11_check/testcases/test_cve_regression.py` (~438 lines) — 29 CVE tests
- `src/pkcs11_check/testcases/test_stress.py` (~157 lines)
- `src/pkcs11_check/testcases/test_concurrent_sessions.py` (~295 lines)
- `src/pkcs11_check/testcases/test_threading.py` (~97 lines)

**Special notes:**

- **Authenticated wrap** uses `wrap_key_authenticated()` / `unwrap_key_authenticated()` recipes (v3.2).
- **RSA key wrapping** uses `wrap_key()` / `unwrap_key()` recipes. The unwrap template needs `attr_ulong(CKA_CLASS, int(CKO_SECRET_KEY))` etc.
- **Cross-verify** tests compare PKCS#11 output against Python `cryptography` lib. Only the PKCS#11 side migrates. Uses DER signature conversion — replace with `pkcs11_check.raw.der` helpers.
- **CVE regression** is diverse: EC, RSA, AES, attributes, derivation across 29 CVEs. Migrate carefully, maintaining CVE references in docstrings.
- **Stress/threading** tests open multiple sessions and run concurrent operations. Replace `token.open()` with `open_session()` from bootstrap. Handle `CKR_USER_ALREADY_LOGGED_IN` directly (check rv) instead of catching `UserAlreadyLoggedIn` exception.
- **Concurrent sessions** may use thread pools — the `rs.raw` object is thread-safe but each thread needs its own session handle.

- [ ] **Step 1:** Migrate test_authenticated_wrap.py and test_rsa_key_wrapping.py
- [ ] **Step 2:** Run: `uv run python -m pytest src/pkcs11_check/testcases/test_authenticated_wrap.py src/pkcs11_check/testcases/test_rsa_key_wrapping.py -v`
- [ ] **Step 3:** Commit: `git commit -m "refactor: migrate key wrapping tests to pkcs11_check.raw"`
- [ ] **Step 4:** Migrate test_crossverify.py and test_crossverify_extended.py
- [ ] **Step 5:** Run tests
- [ ] **Step 6:** Commit: `git commit -m "refactor: migrate cross-verify tests to pkcs11_check.raw"`
- [ ] **Step 7:** Migrate test_cve_regression.py (read carefully — 29 diverse CVE scenarios)
- [ ] **Step 8:** Run: `uv run python -m pytest src/pkcs11_check/testcases/test_cve_regression.py -v`
- [ ] **Step 9:** Commit: `git commit -m "refactor: migrate CVE regression tests to pkcs11_check.raw"`
- [ ] **Step 10:** Migrate test_stress.py, test_concurrent_sessions.py, test_threading.py
- [ ] **Step 11:** Run: `bash local-builds/test.sh softhsm2 -m stress -v`
- [ ] **Step 12:** Commit: `git commit -m "refactor: migrate stress/threading tests to pkcs11_check.raw"`
- [ ] **Step 13:** Verify: `grep -rn "from pkcs11[ .]" src/pkcs11_check/testcases/test_authenticated_wrap.py src/pkcs11_check/testcases/test_rsa_key_wrapping.py src/pkcs11_check/testcases/test_crossverify*.py src/pkcs11_check/testcases/test_cve_regression.py src/pkcs11_check/testcases/test_stress.py src/pkcs11_check/testcases/test_concurrent_sessions.py src/pkcs11_check/testcases/test_threading.py`

---

## Task 4: Wycheproof Vector Tests (20 files)

**Goal:** Migrate all Wycheproof test files. These share a common base pattern.

**Files:**
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof.py` (~470 lines) — **base module, migrate FIRST**
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_aes.py` (~440 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdsa.py` (~360 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ecdh.py` (~250 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa.py` (~170 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_siggen.py` (~180 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_oaep.py` (~185 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_pss.py` (~180 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa_decrypt.py` (~110 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_dsa.py` (~125 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_ed25519.py` (~155 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_chacha.py` (~105 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_x25519.py` (~135 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_hmac.py` (~160 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_hkdf.py` (~125 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_pbkdf2.py` (~125 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_pbes2.py` (~130 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mlkem.py` (~125 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa.py` (~110 lines)
- `src/pkcs11_check/testcases/wycheproof/test_wycheproof_mldsa_sign.py` (~115 lines)

**Special notes:**

- **Migrate the base module first** (`test_wycheproof.py`). This likely defines shared helpers, base classes, or fixtures used by all other files. If it defines a conftest or shared import pattern, all other files depend on it.
- **Also check `wycheproof/conftest.py`** if it exists — may need migration too.
- **Vector loading** (JSON file parsing) does NOT use pkcs11 — leave unchanged.
- **Key import** is the critical path: vectors provide raw key bytes that must be imported via `create_object()` with appropriate template attributes (CKA_VALUE, CKA_KEY_TYPE, CKA_CLASS, etc.).
- **EC key import** for ECDSA/ECDH vectors: need `CKA_EC_PARAMS` (DER OID from `encode_named_curve_parameters()`) and `CKA_EC_POINT` (DER-encoded point from `encode_ec_point()` or raw bytes).
- **RSA key import** for RSA vectors: need `CKA_MODULUS`, `CKA_PUBLIC_EXPONENT`, etc.
- **ECDH vectors** use `mech_ecdh()` packer with KDF constants.
- **HKDF/PBKDF2/PBES2** vectors use `mech_hkdf()` and `mech_pbkdf2()` packers.
- **PQC Wycheproof** (ML-KEM, ML-DSA): same PQC constants as Task 2.
- **Batch by sub-category** for efficient commits: AES first, then RSA group, then EC group, then KDF group, then PQC group.

- [ ] **Step 1:** Read wycheproof/conftest.py (if exists) and test_wycheproof.py base module
- [ ] **Step 2:** Migrate wycheproof base infrastructure (conftest + test_wycheproof.py)
- [ ] **Step 3:** Run: `uv run python -m pytest src/pkcs11_check/testcases/wycheproof/test_wycheproof.py -v --timeout=120`
- [ ] **Step 4:** Migrate test_wycheproof_aes.py
- [ ] **Step 5:** Run tests for AES wycheproof
- [ ] **Step 6:** Commit: `git commit -m "refactor: migrate wycheproof base + AES to pkcs11_check.raw"`
- [ ] **Step 7:** Migrate RSA group (test_wycheproof_rsa*.py — 5 files)
- [ ] **Step 8:** Run: `uv run python -m pytest src/pkcs11_check/testcases/wycheproof/test_wycheproof_rsa*.py -v`
- [ ] **Step 9:** Commit: `git commit -m "refactor: migrate wycheproof RSA tests to pkcs11_check.raw"`
- [ ] **Step 10:** Migrate EC group (ecdsa, ecdh, ed25519, x25519, dsa, chacha — 6 files)
- [ ] **Step 11:** Run tests for EC group
- [ ] **Step 12:** Commit: `git commit -m "refactor: migrate wycheproof EC/EdDSA tests to pkcs11_check.raw"`
- [ ] **Step 13:** Migrate KDF group (hmac, hkdf, pbkdf2, pbes2 — 4 files)
- [ ] **Step 14:** Run tests for KDF group
- [ ] **Step 15:** Commit: `git commit -m "refactor: migrate wycheproof KDF/HMAC tests to pkcs11_check.raw"`
- [ ] **Step 16:** Migrate PQC group (mlkem, mldsa, mldsa_sign — 3 files)
- [ ] **Step 17:** Run tests for PQC group
- [ ] **Step 18:** Commit: `git commit -m "refactor: migrate wycheproof PQC tests to pkcs11_check.raw"`
- [ ] **Step 19:** Run full wycheproof suite: `bash local-builds/test.sh softhsm2 -m wycheproof -v`
- [ ] **Step 20:** Verify: `grep -rn "from pkcs11[ .]" src/pkcs11_check/testcases/wycheproof/`

---

## Task 5: Core Encryption & Signing (~15 files)

**Goal:** Migrate encryption mode tests and signing variant tests.

**Discovery — run at start of task:**
```bash
# Find encryption-related test files still using fork
grep -rl "from pkcs11[ .]" src/pkcs11_check/testcases/test_aes*.py \
  src/pkcs11_check/testcases/test_aead*.py \
  src/pkcs11_check/testcases/test_des*.py \
  src/pkcs11_check/testcases/test_seed*.py \
  src/pkcs11_check/testcases/test_aria*.py \
  src/pkcs11_check/testcases/test_gost*.py \
  src/pkcs11_check/testcases/test_blowfish*.py \
  src/pkcs11_check/testcases/test_twofish*.py \
  src/pkcs11_check/testcases/test_camellia*.py \
  src/pkcs11_check/testcases/test_salsa20*.py \
  src/pkcs11_check/testcases/test_chacha20*.py \
  src/pkcs11_check/testcases/test_sha3*.py \
  src/pkcs11_check/testcases/test_blake2*.py \
  2>/dev/null | sort -u
```

**Expected files (~15):**
- test_aes_modes.py — AES CBC/CTR/GCM/CCM mode tests
- test_aead.py — AEAD (GCM, CCM, ChaCha20-Poly1305)
- test_des.py — DES/3DES (legacy)
- test_seed.py, test_aria.py, test_gost.py — regional/legacy ciphers
- test_blowfish.py, test_twofish.py, test_camellia.py, test_salsa20.py — specialized ciphers
- test_sha3.py — SHA3 digest family
- test_blake2.py — BLAKE2 digest

**Special notes:**

- **AES modes** heavily use mechanism parameters: `mech_bytes()` for CBC IV, `mech_gcm()` for GCM, `mech_ctr()` for CTR.
- **AEAD tests** need `mech_gcm()` and `mech_chacha20_poly1305()` — both output ciphertext+tag or separate tag.
- **DES/3DES** use `CKM_DES3_*` mechanisms with 8-byte IVs via `mech_bytes()`.
- **Regional ciphers** (SEED, ARIA, GOST, etc.) — these may use CKM constants that need verification. Skip the file if the mechanism constants don't exist in types_std.
- **Note:** test_sign_recover.py is already migrated in Batch 1 — do NOT re-migrate.

- [ ] **Step 1:** Run discovery command, list actual files to migrate
- [ ] **Step 2:** Migrate simple cipher tests (DES, SEED, ARIA, etc.) — one at a time, test after each
- [ ] **Step 3:** Commit simple ciphers batch
- [ ] **Step 4:** Migrate AES mode tests (test_aes_modes.py, test_aead.py)
- [ ] **Step 5:** Run tests
- [ ] **Step 6:** Commit AES batch
- [ ] **Step 7:** Migrate specialized ciphers (blowfish, twofish, camellia, salsa20, chacha20)
- [ ] **Step 8:** Run tests
- [ ] **Step 9:** Commit specialized ciphers batch
- [ ] **Step 10:** Migrate signing/digest variants (sign_recover, sha3, blake2)
- [ ] **Step 11:** Run tests
- [ ] **Step 12:** Commit signing/digest batch
- [ ] **Step 13:** Verify: `grep -rn "from pkcs11[ .]" <all migrated files>`

---

## Task 6: Key Management & Derivation (~20 files)

**Goal:** Migrate key lifecycle, wrapping, flags, import/export, derivation, and KDF tests.

**Discovery:**
```bash
grep -rl "from pkcs11[ .]" src/pkcs11_check/testcases/test_key*.py \
  src/pkcs11_check/testcases/test_keymgmt*.py \
  src/pkcs11_check/testcases/test_domain*.py \
  src/pkcs11_check/testcases/test_kdf*.py \
  src/pkcs11_check/testcases/test_misc_kdf*.py \
  src/pkcs11_check/testcases/test_hkdf*.py \
  src/pkcs11_check/testcases/test_sp800*.py \
  src/pkcs11_check/testcases/test_pbe*.py \
  src/pkcs11_check/testcases/test_aes_kdf*.py \
  src/pkcs11_check/testcases/test_derive*.py \
  src/pkcs11_check/testcases/test_x942*.py \
  2>/dev/null | sort -u
```

**Expected files (~20):**
- test_keymgmt.py, test_key_import_export.py, test_key_sizes.py
- test_key_flags.py, test_key_usage_policy.py
- test_domain_params.py
- test_kdf.py, test_misc_kdf.py, test_hkdf_extended.py
- test_sp800_108_kdf.py, test_pbe.py, test_aes_kdf.py
- test_x942_dh.py — X9.42 Diffie-Hellman variant
- Plus any others found by discovery

**Special notes:**

- **Key import/export** tests create objects from raw bytes using `create_object()`. Template must include CKA_CLASS, CKA_KEY_TYPE, CKA_VALUE at minimum.
- **Key flags** tests check CKA_ENCRYPT, CKA_DECRYPT, CKA_SIGN, CKA_VERIFY, CKA_WRAP, CKA_UNWRAP permissions. Use `read_attributes()` to verify.
- **KDF tests** use `derive_key()` recipe with mechanism-specific params: `mech_hkdf()`, `mech_string_data()`, `mech_ecdh()`, `mech_pbkdf2()`.
- **SP800-108 KDF** may use `CKM_SP800_108_*` mechanisms — verify these exist in types_std.
- **Domain params** tests may use `CKO_DOMAIN_PARAMETERS` objects.

- [ ] **Step 1:** Run discovery, list files
- [ ] **Step 2:** Migrate key lifecycle/management files (keymgmt, key_sizes, key_flags, key_usage_policy)
- [ ] **Step 3:** Run tests, commit
- [ ] **Step 4:** Migrate key import/export and domain params
- [ ] **Step 5:** Run tests, commit
- [ ] **Step 6:** Migrate KDF/derivation files (kdf, misc_kdf, hkdf, sp800, pbe, aes_kdf)
- [ ] **Step 7:** Run tests, commit
- [ ] **Step 8:** Verify: `grep -rn "from pkcs11[ .]" <all migrated files>`

---

## Task 7: Object, Attribute & Certificate Tests (~20 files)

**Goal:** Migrate object CRUD, search, attribute, visibility, and X.509 tests.

**Discovery:**
```bash
grep -rl "from pkcs11[ .]" src/pkcs11_check/testcases/test_object*.py \
  src/pkcs11_check/testcases/test_search*.py \
  src/pkcs11_check/testcases/test_attribute*.py \
  src/pkcs11_check/testcases/test_set_attribute*.py \
  src/pkcs11_check/testcases/test_sensitivity*.py \
  src/pkcs11_check/testcases/test_trust*.py \
  src/pkcs11_check/testcases/test_validation*.py \
  src/pkcs11_check/testcases/test_data*.py \
  src/pkcs11_check/testcases/test_buffer*.py \
  src/pkcs11_check/testcases/x509/*.py \
  2>/dev/null | sort -u
```

**Expected files (~20):**
- test_object.py, test_object_search_patterns.py, test_object_visibility.py (some may be already migrated — verify)
- test_search.py
- test_attribute_enforcement.py, test_attribute_defaults.py, test_attribute_fuzz.py
- test_set_attribute.py, test_sensitivity.py
- test_object_size.py — if still unmigrated (was in Batch 1 scope, verify)
- test_trust_objects.py, test_validation_objects.py
- test_buffers.py — buffer handling tests
- x509/test_core_ops.py, x509/test_lifecycle.py, x509/test_search.py
- x509/test_attributes.py, x509/test_identity.py, x509/test_attribute_parity.py
- x509/test_limbo_import.py, x509/test_limbo_stress.py

**Special notes:**

- **Object visibility** (793 lines) is the largest — tests token vs session objects, public vs private. Uses `find_objects()` extensively.
- **Attribute fuzz** uses random attribute templates — may use `attr_auto()` packer for auto-type selection.
- **X.509 tests** import certificates as `CKO_CERTIFICATE` objects with DER-encoded attributes (CKA_VALUE, CKA_SUBJECT, CKA_ISSUER). Use `create_object()` with appropriate template.
- **X.509 conftest** — check `x509/conftest.py` for shared helpers that may need migration.
- **set_attributes** uses `set_attributes()` recipe.

- [ ] **Step 1:** Run discovery, check which files are already migrated
- [ ] **Step 2:** Migrate object CRUD/search tests
- [ ] **Step 3:** Run tests, commit
- [ ] **Step 4:** Migrate attribute enforcement/fuzz/sensitivity tests
- [ ] **Step 5:** Run tests, commit
- [ ] **Step 6:** Check x509/conftest.py, migrate if needed
- [ ] **Step 7:** Migrate X.509 certificate tests (8 files)
- [ ] **Step 8:** Run tests, commit
- [ ] **Step 9:** Verify: `grep -rn "from pkcs11[ .]" <all migrated files>`

---

## Task 8: Session & Access Control (~20 files)

**Goal:** Migrate session management, access control, PIN, and read-only session tests.

**Discovery:**
```bash
grep -rl "from pkcs11[ .]" src/pkcs11_check/testcases/test_session*.py \
  src/pkcs11_check/testcases/test_access*.py \
  src/pkcs11_check/testcases/test_pin*.py \
  src/pkcs11_check/testcases/test_so_pin*.py \
  src/pkcs11_check/testcases/test_ro_session*.py \
  src/pkcs11_check/testcases/test_mechanism*.py \
  src/pkcs11_check/testcases/test_token*.py \
  src/pkcs11_check/testcases/test_api_security*.py \
  2>/dev/null | sort -u
```

**Expected files (~20):**
- test_session_edge_cases.py, test_session_state_machine.py, test_session_exhaustion.py
- test_ro_session.py, test_ro_session_restrictions.py
- test_access.py, test_access_levels.py, test_access_control.py
- test_pin.py, test_so_pin.py
- test_mechanism.py
- test_token_info.py (if exists)
- test_api_security.py — API security tests
- Plus others from discovery

**Special notes:**

- **Session management** tests call `C_OpenSession`/`C_CloseSession` directly. Use `open_session()` from bootstrap, or raw `rs.raw.C_OpenSession()` for specific session type tests.
- **Session state machine** tests check session states (CKS_RO_PUBLIC_SESSION, CKS_RW_USER_FUNCTIONS, etc.) via `C_GetSessionInfo`. Use raw calls with `CK_SESSION_INFO` struct.
- **PIN tests** are marked `@destructive` — must remain marked. Use `init_pin()`, `set_pin()` recipes. Never log PIN values.
- **SO PIN tests** use `CKU_SO` for security officer login — use `login_user(rs.raw, sh, int(CKU_SO), so_pin)`.
- **Read-only sessions** open with `CKF_SERIAL_SESSION` only (no `CKF_RW_SESSION`). Use `open_session(rs.raw, slot_id, int(CKF_SERIAL_SESSION))`.
- **Access control** tests verify that operations fail appropriately based on session state (logged in vs not, RW vs RO).
- **Mechanism listing** tests enumerate and verify mechanisms via `get_mechanism_list()` recipe.

- [ ] **Step 1:** Run discovery, list files
- [ ] **Step 2:** Migrate mechanism listing tests
- [ ] **Step 3:** Run tests, commit
- [ ] **Step 4:** Migrate session management tests (edge cases, state machine, exhaustion)
- [ ] **Step 5:** Run tests, commit
- [ ] **Step 6:** Migrate RO session tests
- [ ] **Step 7:** Run tests, commit
- [ ] **Step 8:** Migrate access control tests
- [ ] **Step 9:** Run tests, commit
- [ ] **Step 10:** Migrate PIN tests (careful — @destructive)
- [ ] **Step 11:** Run tests, commit
- [ ] **Step 12:** Verify: `grep -rn "from pkcs11[ .]" <all migrated files>`

---

## Task 9: ACVP/CCTV Vectors & Security Tests (~20 files)

**Goal:** Migrate NIST ACVP vectors, CCTV vectors, and security tests.

**Discovery:**
```bash
grep -rl "from pkcs11[ .]" src/pkcs11_check/testcases/test_acvp*.py \
  src/pkcs11_check/testcases/test_cctv*.py \
  src/pkcs11_check/testcases/test_nist*.py \
  src/pkcs11_check/testcases/test_fuzz*.py \
  src/pkcs11_check/testcases/test_tookan*.py \
  src/pkcs11_check/testcases/test_padding_oracle*.py \
  src/pkcs11_check/testcases/test_nonce*.py \
  src/pkcs11_check/testcases/test_handle_reuse*.py \
  src/pkcs11_check/testcases/test_metamorphic*.py \
  src/pkcs11_check/testcases/test_stateful*.py \
  src/pkcs11_check/testcases/test_rng*.py \
  2>/dev/null | sort -u
```

**Expected files (~20):**
- test_acvp_aes.py, test_acvp_ecdsa.py, test_acvp_hmac.py
- test_acvp_sha3.py, test_acvp_eddsa.py, test_acvp_slhdsa.py
- test_cctv_*.py (multiple files)
- test_nist_*.py (NIST KAT files)
- test_fuzz.py, test_tookan.py, test_padding_oracle.py
- test_nonce_quality.py, test_handle_reuse.py
- test_metamorphic.py, test_stateful.py, test_rng_*.py

**Special notes:**

- **ACVP tests** are parametrized from NIST CAVP/ACVP JSON vectors. The vector loading is Python-only. Only the PKCS#11 operations need migration.
- **CCTV tests** — check for shared conftest or base modules.
- **Tookan tests** verify that modules reject weak key templates (CVE-2015-2141 style). These assert that creation FAILS — use error-path pattern.
- **Padding oracle** tests check that modules don't leak timing information. The PKCS#11 operations migrate normally.
- **Fuzz tests** may use Hypothesis — the property-based framework stays, only PKCS#11 calls migrate.
- **Handle reuse** tests destroy objects then try to reuse handles — error-path assertions needed.

- [ ] **Step 1:** Run discovery, list files
- [ ] **Step 2:** Migrate ACVP vector tests (6 files)
- [ ] **Step 3:** Run tests, commit
- [ ] **Step 4:** Migrate CCTV vector tests
- [ ] **Step 5:** Run tests, commit
- [ ] **Step 6:** Migrate security tests (tookan, padding_oracle, nonce, fuzz, handle_reuse, etc.)
- [ ] **Step 7:** Run tests, commit
- [ ] **Step 8:** Verify: `grep -rn "from pkcs11[ .]" <all migrated files>`

---

## Task 10: Protocol, CKR & Final Sweep (~35+ files)

**Goal:** Migrate protocol tests, remaining CKR non-raw files, and any files not covered by Tasks 2-9.

**Discovery — run AFTER Tasks 2-9 are complete:**
```bash
# Find ALL remaining files with fork imports
grep -rl "from pkcs11[ .]" src/pkcs11_check/testcases/ | grep "\.py$" | sort -u
```

This catches everything missed by prior tasks.

**Expected categories:**

**Protocol tests (~5 files):**
- test_tls12.py — TLS 1.2 key derivation (may need TLS packer — see Task 1 Step 3)
- test_ssl3.py — SSL 3.0 key derivation
- test_wtls.py — WTLS mechanisms
- test_ike.py — IKE key derivation
- test_x3dh.py — X3DH key agreement

**CKR non-raw files (~21 with fork imports — this is a full session's worth):**
- ckr/test_ckr_encrypt.py, ckr/test_ckr_decrypt.py, ckr/test_ckr_sign.py
- ckr/test_ckr_verify.py, ckr/test_ckr_digest.py, ckr/test_ckr_keygen.py
- ckr/test_ckr_wrap.py, ckr/test_ckr_derive.py, ckr/test_ckr_kem.py
- ckr/test_ckr_object.py, ckr/test_ckr_session.py, ckr/test_ckr_slot_token.py
- ckr/test_ckr_state.py, ckr/test_ckr_codes.py, ckr/test_ckr_dual.py
- ckr/test_ckr_fault_inject.py, ckr/test_ckr_priority.py, ckr/test_ckr_random.py
- ckr/test_ckr_spec_compliance.py, ckr/test_ckr_universal.py
- ckr/_ckr_spec.py (shared helper, not a test — migrate imports)
- Run discovery to confirm: `grep -rl "from pkcs11[ .]" src/pkcs11_check/testcases/ckr/ | sort`
- Note: ckr/test_ckr_general.py may already be raw-only — verify before migrating

**Other remaining files:** Any test files found by the discovery command above.

**Special notes:**

- **TLS tests** may need new mechanism packers if `mech_tls*` doesn't exist in pack.py. Options:
  1. Use `mech_bytes()` with manually packed `CK_TLS12_MASTER_KEY_DERIVE_PARAMS` struct
  2. Add new packers to pack.py first (coordinate with user)
  3. If too complex, defer these files and document as known remaining fork dependencies

- **CKR non-raw files** that still import fork enums: these tests check specific CKR return codes. They may already use raw for the actual C_* calls but import fork enums for template building. Replace fork enums with types_std constants.

- **Helper file cleanup** — after all test files are migrated, these helper files still have fork imports:
  - `testcases/conftest.py` — remove fork-dependent helpers that no test calls anymore; keep `get_pin_bytes()`, `mech_name()`
  - `testcases/_error_tuples.py` — verify if fork imports remain; rewrite to use CKR constants if so
  - `testcases/wycheproof/_key_decoders.py` — replace `pkcs11.util` imports with raw equivalents
  - `testcases/x509/conftest.py` — replace fork imports with raw equivalents
  - `testcases/ckr/_ckr_spec.py` — replace fork exception imports with CKR constants

- [ ] **Step 1:** Run discovery to get definitive remaining file list
- [ ] **Step 2:** Check TLS packer availability; if missing, decide approach (manual pack vs new packer)
- [ ] **Step 3:** Migrate protocol tests (or defer TLS if packer needed)
- [ ] **Step 4:** Run tests, commit
- [ ] **Step 5:** Migrate remaining CKR files
- [ ] **Step 6:** Run tests, commit
- [ ] **Step 7:** Migrate any remaining test files from discovery
- [ ] **Step 8:** Run tests, commit
- [ ] **Step 9:** Migrate helper/conftest files (conftest.py, _error_tuples.py, _key_decoders.py, x509/conftest.py)
- [ ] **Step 10:** Run tests, commit
- [ ] **Step 11:** Final verification — zero fork imports:

```bash
# MUST return empty
grep -rn "from pkcs11 " src/pkcs11_check/testcases/ | grep -v "pkcs11_check"
grep -rn "from pkcs11\." src/pkcs11_check/testcases/ | grep -v "pkcs11_check"

# Also check conftest files
grep -rn "from pkcs11[ .]" src/pkcs11_check/testcases/conftest.py \
  src/pkcs11_check/testcases/wycheproof/conftest.py \
  src/pkcs11_check/testcases/x509/conftest.py \
  src/pkcs11_check/testcases/ckr/conftest.py \
  2>/dev/null
```

- [ ] **Step 12:** Run full test suite: `bash local-builds/test.sh softhsm2 -v`
- [ ] **Step 13:** Run lint + type check:

```bash
uv run ruff check src/pkcs11_check/testcases/ && uv run ruff format --check src/pkcs11_check/testcases/
uv run mypy src/pkcs11_check/testcases/
```

- [ ] **Step 14:** Final commit: `git commit -m "refactor: complete test migration batch 2 — zero fork imports in testcases/"`
- [ ] **Step 15:** Update master plan progress tracking:

```bash
# In docs/superpowers/plans/2026-03-25-fork-removal-master-plan.md
# Change: - [ ] Sub-project 3: Test Migration Batch 2
# To:     - [x] Sub-project 3: Test Migration Batch 2 (date: N files migrated)
```

---

## Execution Notes

### Session sizing

Each task is designed for one agentic session (~2-4 hours). If a task is too large for one session, split at the commit boundaries (each commit point is a safe stopping point).

### Commit frequency

Commit after each logical batch within a task (as marked in the steps). Never leave uncommitted migration work across sessions.

### Test runner

Always test against SoftHSM2 via local-builds:
```bash
bash local-builds/test.sh softhsm2 <pytest-args>
```

For quick single-file validation:
```bash
P11TEST_MODULE=/usr/lib/softhsm/libsofthsm2.so P11TEST_PIN=1234 \
  uv run python -m pytest <file> -v --timeout=60 -x
```

### Handling test failures after migration

If a test fails after migration:
1. Compare the old and new code side-by-side
2. Check if the mechanism parameter format changed
3. Check if the CKR error handling is correct
4. Check if attribute types need int() casting: `int(CKA_ENCRYPT)` not bare `CKA_ENCRYPT`
5. Check if recipe function signatures match (parameter order)
6. **NEVER** add pytest.skip or pytest.xfail to hide failures — fix the migration

### Dual-import transition

During migration, some conftest helpers may still import from the fork. This is fine — they serve unmigrated files. After Task 10, clean up any fork-dependent conftest helpers that are no longer called.
