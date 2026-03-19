## Wycheproof Vector Coverage Gaps (Current)

Source checked: `src/pkcs11_check/testcases/data/wycheproof/testvectors_v1/*.json`.

Totals:
- Total vectors: `336`
- Covered by current Wycheproof tests: `252`
- Not covered: `84`

## 2026-03-19 coverage expansion

This repo now additionally covers:
- DSA P1363 vectors
- Broad ECDSA DER + P1363 vectors across brainpool, secp*k1, secp*r1, SHA-2, SHA-3, and SHAKE-prehash cases
- RSA PKCS#1 signature-generation verify vectors
- RSA three-prime OAEP vectors
- RSA-PSS parameterized and mixed-`mgfSha` vectors via `CKM_RSA_PKCS_PSS`
- ML-DSA sign vectors for 44/65/87, seed and non-seed forms
- ML-KEM decapsulation vectors for 512/768/1024, including semi-expanded decapsulation sets
- ECDH ASN.1 / PEM / WebCrypto vectors across secp*r1, secp256k1, brainpool, and binary-field curves
- X25519/X448 ASN.1 / PEM / JWK vectors via the same PKCS#11 derive path
- PBES2 vectors using `CKM_PKCS5_PBKD2` + `CKM_AES_CBC_PAD` composition rather than PBKDF2-only checks

The remaining uncovered set is now concentrated in:
- ML-KEM keygen/encaps vectors
- OAEP truncated SHA-512/* variants not mapped in the current binding
- RSA-PSS SHAKE variants
- Mechanism families still not present in PKCS#11 coverage (`FF1`, `AES-SIV`, `ARIA`, `Camellia`, `KMAC`, `SM4`, etc.)

## Important remaining semantic gap

The remaining ML-KEM Wycheproof files are not just "missing filenames".
`mlkem_*_keygen_seed_test.json` and `mlkem_*_encaps_test.json` are deterministic
known-answer vectors. The current PKCS#11 v3.2 KEM API exposed by the fork gives
usable `encapsulate_key()` / `decapsulate_key()` operations, but it does not
expose a deterministic seed or message override that would let the test suite
reproduce Wycheproof's exact expected `ek` / `dk` / `c` / `K` bytes.

That means adding those files naively would be misleading: the test would only
assert "operation succeeded", not "module matches the Wycheproof vector".
Those files should be added only if the binding/API grows an honest deterministic
test hook, or if the suite explicitly scopes them as structural-import smoke
tests rather than vector-conformance tests.

## Current actionable remainder

The large "just add filenames" bucket has already been consumed. The honest
remaining work is now small and specific:

- `rsa_pss_*shake*_test.json` requires SHAKE-based PKCS#11 PSS support in the
  binding and provider.
- `rsa_oaep_*sha512_224*` / `rsa_oaep_*sha512_256*` require truncated SHA-512
  OAEP constants and parameter plumbing in the fork.
- `mlkem_*_encaps_test.json` and `mlkem_*_keygen_seed_test.json` still need a
  deterministic test hook; without one, these would degrade into smoke tests.
- `hmac_sm3_test.json` needs explicit SM3 HMAC enums/mechanisms in the binding.

## Provider validation notes

Focused 2026-03-19 validation after the expansion:

- SoftHSM2 local: `test_wycheproof_ecdh.py` ran clean after a small test bug fix
  (`14506 passed, 3020 skipped, 32 xfailed`).
- SoftHSM2 Docker: validated on the focused batch. `test_wycheproof_ecdh.py`
  passed with `14506 passed, 3020 skipped, 32 xfailed`; `test_wycheproof_x25519.py`
  passed with `48 passed, 4128 skipped`; `test_wycheproof_rsa_pss.py` passed
  with `2067 passed, 435 xfailed`; `test_wycheproof_pbes2.py` skipped cleanly.
- Kryoptic local: `test_wycheproof_mlkem.py` exercises some ML-KEM vectors
  (`21 passed, 579 skipped`).
- Kryoptic Docker (`test-kryoptic` and `test-kryoptic-main`): `test_wycheproof_pbes2.py`
  passes, classical ECDH/X25519 coverage runs, but `test_wycheproof_mlkem.py`
  currently skips entirely (`600 skipped`), which suggests the Docker images are
  not exposing `CKM_ML_KEM` yet.

## Not covered and likely blocked by missing mechanisms

These need fork/API additions (mechanism constants or PKCS#11 support) before they are
practically useful as ready-to-run Wycheproof additions.

- `a128cbc_hs256_test.json`
- `a192cbc_hs384_test.json`
- `a256cbc_hs512_test.json`
- `aead_aes_siv_cmac_test.json`
- `aegis128L_test.json`
- `aegis128_test.json`
- `aegis256_test.json`
- `aes_eax_test.json`
- `aes_ff1_base10_test.json`
- `aes_ff1_base16_test.json`
- `aes_ff1_base26_test.json`
- `aes_ff1_base32_test.json`
- `aes_ff1_base36_test.json`
- `aes_ff1_base45_test.json`
- `aes_ff1_base62_test.json`
- `aes_ff1_base64_test.json`
- `aes_ff1_base85_test.json`
- `aes_ff1_radix10_test.json`
- `aes_ff1_radix16_test.json`
- `aes_ff1_radix255_test.json`
- `aes_ff1_radix256_test.json`
- `aes_ff1_radix26_test.json`
- `aes_ff1_radix32_test.json`
- `aes_ff1_radix36_test.json`
- `aes_ff1_radix45_test.json`
- `aes_ff1_radix62_test.json`
- `aes_ff1_radix64_test.json`
- `aes_ff1_radix65535_test.json`
- `aes_ff1_radix65536_test.json`
- `aes_ff1_radix85_test.json`
- `aes_gcm_siv_test.json`
- `aes_siv_cmac_test.json`
- `aria_cbc_pkcs5_test.json`
- `aria_ccm_test.json`
- `aria_cmac_test.json`
- `aria_gcm_test.json`
- `aria_kwp_test.json`
- `aria_wrap_test.json`
- `ascon128_test.json`
- `ascon128a_test.json`
- `ascon80pq_test.json`
- `camellia_cbc_pkcs5_test.json`
- `camellia_ccm_test.json`
- `camellia_cmac_test.json`
- `camellia_wrap_test.json`
- `ec_prime_order_curves_test.json`
- `hmac_sm3_test.json`
- `json_web_crypto_test.json`
- `json_web_encryption_test.json`
- `json_web_key_test.json`
- `json_web_signature_test.json`
- `kmac128_no_customization_test.json`
- `kmac256_no_customization_test.json`
- `morus1280_test.json`
- `morus640_test.json`
- `primality_test.json`
- `seed_ccm_test.json`
- `seed_gcm_test.json`
- `seed_wrap_test.json`
- `siphash_1_3_test.json`
- `siphash_2_4_test.json`
- `siphash_4_8_test.json`
- `siphashx_2_4_test.json`
- `siphashx_4_8_test.json`
- `sm4_ccm_test.json`
- `sm4_gcm_test.json`
- `vmac_128_test.json`
- `vmac_64_test.json`
- `xchacha20_poly1305_test.json`

## Quick refresh command

```bash
cd /home/user/src/m/pkcs11-check
ls src/pkcs11_check/testcases/data/wycheproof/testvectors_v1/*_test.json \
  | sed 's#^.*/##' | sort | wc -l
rg -h --no-filename -o '"[A-Za-z0-9_]+_test\\.json"' src/pkcs11_check/testcases/wycheproof/*.py \
  | tr -d '"' | sort -u > /tmp/wy_refs_explicit.txt
ls src/pkcs11_check/testcases/data/wycheproof/testvectors_v1/rsa_pss_*_test.json | sed 's#^.*/##' \
  | grep -vE 'params|shake|mgf1sha' | sort > /tmp/wy_refs_pss.txt
comm -23 <(ls src/pkcs11_check/testcases/data/wycheproof/testvectors_v1/*_test.json | sed 's#^.*/##' | sort) \
  <(sort -u /tmp/wy_refs_explicit.txt /tmp/wy_refs_pss.txt) > /tmp/wy_missing.txt
wc -l /tmp/wy_missing.txt
```
