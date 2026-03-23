# PKCS#11 binding layer analysis and future options

**Date:** 2026-03-23
**Status:** Analysis / future reference

## Current state

pkcs11-check uses two PKCS#11 binding layers:

### 1. python-pkcs11 fork (primary)

Cython-based, used by ~95% of tests. Provides high-level API:
`session.generate_key()`, `key.encrypt()`, `key.sign()`, etc.

**Strengths:**
- Concise test code
- Handles struct packing for complex mechanism params (TLS, PSS, GCM, HKDF)
- Object-oriented key/session management
- 75K+ tests already written against this API

**Limitations for a testing tool:**
- Template injection: `generate_key()` adds default capabilities (ENCRYPT,
  DECRYPT, SIGN, etc.) based on internal tables. The test doesn't control
  exactly what goes to `C_GenerateKey`
- Missing key types: new types (Camellia, Twofish, etc.) need manual
  registration in `defaults.py` just to use `generate_key`
- Safety guards: strips `.encrypt()` / `.sign()` methods from key objects
  if `CKA_ENCRYPT=False` / `CKA_SIGN=False`, preventing tests of what
  happens when forbidden operations are attempted
- Mechanism magic: auto-selects mechanisms, auto-packs params
- Cython compilation: every fork change requires rebuilding C extension
- Hard to debug: stack traces show `??? ` for Cython frames

### 2. RawPKCS11 (ctypes, secondary)

Pure Python ctypes wrapper over the PKCS#11 function list. Used by CKR
tests and crash-safety tests (subprocess isolation).

**Strengths:**
- Direct access to all 68+ PKCS#11 C functions
- No template injection or capability filtering
- No compilation needed
- Can be used in subprocess for crash-safe testing
- Supports v2.40, v3.0, and v3.2 function lists

**Limitations:**
- Very verbose: building CK_ATTRIBUTE arrays, packing mechanism params,
  managing CK_ULONG pointers manually
- No convenience helpers for common patterns
- Error-prone for struct layout (alignment, padding)

## Problems encountered due to python-pkcs11 limitations

| Issue | Root cause | Workaround |
|---|---|---|
| Camellia keygen fails | KeyType.CAMELLIA not in defaults table | Added to defaults.py |
| CKR sign test needs wrong key type | python-pkcs11 strips .sign() from non-SIGN keys | Rewrote with RawPKCS11 subprocess |
| TLS negative attr tests invalid | python-pkcs11 strips .encrypt() from non-ENCRYPT keys | Rewrote with RawPKCS11 subprocess |
| AES-CTR test weakened | python-pkcs11 padded plaintext | Added explicit non-block-aligned test |
| SSL3 param crash | python-pkcs11 handler expected tuple, test passed bytes | Fixed test param format |
| Template not what test specified | generate_key adds CKA_SENSITIVE, CKA_PRIVATE silently | Explicit template= override |
| EC private scalar leading zero | python-pkcs11 decoder didn't strip DER sign byte | Fixed in _key_decoders.py |

## Future options

### Option A: Keep current approach (recommended short-term)

- python-pkcs11 for convenience tests (encrypt, sign, verify, keygen)
- RawPKCS11 for exact-control tests (CKR compliance, negative tests, crash tests)
- Fix python-pkcs11 issues in the fork as they come up
- Effort: ongoing, minimal per issue

### Option B: Thin wrapper over RawPKCS11

A middle layer that provides convenience without opinion:

```python
from pkcs11_check.p11 import Session

session = Session(module_path, slot=0, pin="1234")

# Passes YOUR template exactly, no defaults injected
key = session.generate_key(
    mechanism=CKM_AES_KEY_GEN,
    template={
        CKA_CLASS: CKO_SECRET_KEY,
        CKA_KEY_TYPE: CKK_AES,
        CKA_VALUE_LEN: 32,
        CKA_ENCRYPT: True,
        CKA_TOKEN: False,
    }
)

# Passes YOUR mechanism and params exactly
ct = session.encrypt(key, CKM_AES_ECB, data, param=None)
```

Properties:
- No template injection, no capability filtering, no method stripping
- Handles CK_ATTRIBUTE array packing and CK_RV checking
- Mechanism param struct packing as explicit helpers, not auto-detection
- Pure Python, no compilation
- Effort: weeks to build, months to migrate 75K tests

### Option C: Switch to pykcs11 or other binding

- pykcs11: mature, ctypes-based, but also has its own opinions
- Would require rewriting all tests against a different API
- No clear advantage over option B
- Effort: months

## Recommendation

Stay with **Option A** for now. The fork works for 95%+ of tests, and
RawPKCS11 covers the gaps. Track issues in this document as they arise.

Consider **Option B** as a future project if:
- The fork becomes unmaintainable (too many patches diverging from upstream)
- New mechanism families require extensive Cython changes
- The test count grows beyond what the current approach can handle cleanly

The thin wrapper (Option B) could be built incrementally - start with
keygen and encrypt, migrate tests file-by-file, keep python-pkcs11
available for tests that haven't been migrated.
