# python-pkcs11 Fork — Changes and Upstream Plan

Fork: `github.com/mingulov/python-pkcs11` (git submodule at `python-pkcs11/`)

## Summary

18 commits over upstream (`ecf10f7`), adding PKCS#11 v3.0/3.1/3.2 support:

- v3.0/3.1/3.2 interface negotiation via `C_GetInterface`
- Post-quantum cryptography: ML-KEM, ML-DSA, SLH-DSA
- KEM operations: `C_EncapsulateKey` / `C_DecapsulateKey`
- 50+ new mechanism and key type enums
- 4 parameter struct implementations
- Bug fixes (GCM IV restriction, attribute registry)

## Changes by Category

### Interface Negotiation (v3.0/3.1/3.2)
- `HasFuncList` holds `funclist` (v2.40), `funclist3` (v3.0), `funclist32` (v3.2)
- Auto-negotiation: tries v3.2 → v3.1 → v3.0 → v2.40 fallback
- `lib(so, interface="auto"|"3.2"|"3.0"|"2.40")` parameter
- `lib.interface_version` property returns negotiated version string
- `lib.get_interface_list()` wraps `C_GetInterfaceList` (v3.0+)
- Full `CK_FUNCTION_LIST_3_0` and `CK_FUNCTION_LIST_3_2` struct layouts in `.pxd`

### Post-Quantum Cryptography (PKCS#11 v3.2)
- **ML-KEM** (CRYSTALS-Kyber / FIPS 203): `CKK_ML_KEM`, `CKM_ML_KEM_KEY_PAIR_GEN`, `CKM_ML_KEM`
- **ML-DSA** (CRYSTALS-Dilithium / FIPS 204): `CKK_ML_DSA`, `CKM_ML_DSA_KEY_PAIR_GEN`, `CKM_ML_DSA`, `CKM_HASH_ML_DSA_*`
- **SLH-DSA** (SPHINCS+ / FIPS 205): `CKK_SLH_DSA`, `CKM_SLH_DSA_KEY_PAIR_GEN`, `CKM_SLH_DSA`, `CKM_HASH_SLH_DSA_*`
- Parameter set enums: `MLKemParameterSet`, `MLDsaParameterSet`, `SlhDsaParameterSet`
- `CKA_PARAMETER_SET` attribute for selecting PQC security levels
- `CKA_ENCAPSULATE` / `CKA_DECAPSULATE` capability attributes
- `encapsulate_key()` / `decapsulate_key()` methods on PublicKey/PrivateKey

### KEM Operations (`C_EncapsulateKey` / `C_DecapsulateKey`)
- Two-pass pattern: length query then data retrieval
- Returns `(ciphertext_bytes, derived_key_object)` tuple
- Requires v3.2 interface (`funclist32 != NULL`); raises `NotImplementedError` on v2.40

### New Mechanisms (50+)
- **Stream ciphers**: ChaCha20, Poly1305, Salsa20, ChaCha20-Poly1305, Salsa20-Poly1305
- **DSA/ECDSA SHA-3**: DSA_SHA3_224/256/384/512, ECDSA_SHA3_224/256/384/512
- **RSA SHA-3**: SHA3_224/256/384/512_RSA_PKCS, SHA3_224/256/384/512_RSA_PKCS_PSS
- **SHA-512 truncated**: SHA512_224, SHA512_256 (digest + HMAC)
- **AES**: AES-XTS, AES-CCM, AES-GMAC, ECDH-AES-KEY-WRAP
- **Key derivation**: SHA3 key derivation (0x397-0x39A)
- **Montgomery curves**: EC_MONTGOMERY_KEY_PAIR_GEN

### New Key Types
- CKK_CHACHA20, CKK_POLY1305, CKK_HKDF, CKK_AES_XTS
- CKK_EC_MONTGOMERY, CKK_ML_KEM, CKK_ML_DSA, CKK_SLH_DSA
- CKK_SHA512_224_HMAC, CKK_SHA512_256_HMAC, CKK_SHA512_T_HMAC

### Parameter Struct Implementations
1. **CK_CCM_PARAMS** — AES-CCM: `(data_len, nonce, aad, mac_length)` or dict
2. **CK_SALSA20_CHACHA20_POLY1305_PARAMS** — `(nonce, aad)` tuple
3. **CK_HKDF_PARAMS** — `(hash_mechanism, salt, info)` tuple or dict with extract/expand control
4. **SHA3 RSA-PSS routing** — SHA3_*_RSA_PKCS_PSS mechanisms added to PSS param handler

### Additional
- **CKO_PROFILE support**: `ProfileID` enum, `CKA_PROFILE_ID` attribute
- **GCM IV fix**: Removed incorrect 12-byte IV length restriction (NIST recommends, not mandates)
- **Attribute registry**: Handles v3.2 attributes in `make_object` for mixed-version compat
- **Safe `C_GetAttributeValue` hard-error handling**: only inspect returned `ulValueLen` on `CKR_OK`, `CKR_ATTRIBUTE_SENSITIVE`, `CKR_ATTRIBUTE_TYPE_INVALID`, or `CKR_BUFFER_TOO_SMALL`, per PKCS#11 spec. This hardens the wrapper when a module returns hard errors cleanly; it does not fix lower-level native shim bugs that crash before control returns to Python.

## Files Changed

| File | Lines | Purpose |
|------|-------|---------|
| `extern/pkcs11_v32.h` | +2771 | Full PKCS#11 v3.2 header |
| `pkcs11/_pkcs11.pxd` | +652 | C struct declarations (function lists, params) |
| `pkcs11/_pkcs11.pyx` | +365 | Cython implementation (interface negotiation, KEM, params) |
| `pkcs11/mechanisms.py` | +123 | Mechanism and key type enums |
| `pkcs11/constants.py` | +97 | Attribute, MechanismFlag, parameter set enums |
| `pkcs11/types.py` | +76 | Encapsulate/Decapsulate mixin types |
| `pkcs11/attributes.py` | +17 | Attribute registry for v3.2 attributes |
| `pkcs11/defaults.py` | +15 | Default mechanisms for PQC key types |
| Other | +19 | Header fixes, init, stubs, tests |

## Upstream PR Plan

1. **PR: GCM IV fix** — Remove incorrect length restriction + test update (2 commits)
2. **PR: v3.0 mechanism enums** — ChaCha20, SHA-3, SHA-512 truncated, AES-XTS, etc. (4 commits)
3. **PR: Parameter struct support** — CCM, ChaCha20-Poly1305, HKDF (3 commits)
4. **PR: v3.0/3.1/3.2 interface negotiation** — HasFuncList, C_GetInterface, fallback (3 commits)
5. **PR: PQC support** — ML-KEM/DSA/SLH-DSA, KEM operations, parameter sets (4 commits)
6. **PR: CKO_PROFILE and attribute registry** — ProfileID, v3.2 compat (2 commits)

## Verification

All mechanism/key type values verified against `extern/pkcs11t.h` and `extern/pkcs11_v32.h`.
Memory safety: all `PyMem_Malloc` structs freed in `__dealloc__`; pointer lifetimes safe.
Upstream tests: 132/134 passing (2 failures are pre-existing SO-PIN config issues).
