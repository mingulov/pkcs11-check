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

## Not covered and likely addable with currently available mechanisms

These files are currently unused but can be exercised with existing fork mechanisms
(`RSA`, `ECDSA`, `ECDH1_DERIVE`, `DSA`, `ML_KEM`, `ML_DSA`, `X25519`, `X448`,
`PKCS5_PBKD2`, etc.). They still need fixture/loader work in tests.

### Mechanism-backed additions (`143` files)
- `dsa_2048_224_sha224_p1363_test.json`
- `dsa_2048_224_sha256_p1363_test.json`
- `dsa_2048_256_sha256_p1363_test.json`
- `dsa_3072_256_sha256_p1363_test.json`
- `ecdh_brainpoolP224r1_test.json`
- `ecdh_brainpoolP256r1_test.json`
- `ecdh_brainpoolP320r1_test.json`
- `ecdh_brainpoolP384r1_test.json`
- `ecdh_brainpoolP512r1_test.json`
- `ecdh_secp224r1_pem_test.json`
- `ecdh_secp224r1_test.json`
- `ecdh_secp256k1_test.json`
- `ecdh_secp256k1_webcrypto_test.json`
- `ecdh_secp256r1_pem_test.json`
- `ecdh_secp256r1_test.json`
- `ecdh_secp256r1_webcrypto_test.json`
- `ecdh_secp384r1_pem_test.json`
- `ecdh_secp384r1_test.json`
- `ecdh_secp384r1_webcrypto_test.json`
- `ecdh_secp521r1_pem_test.json`
- `ecdh_secp521r1_test.json`
- `ecdh_secp521r1_webcrypto_test.json`
- `ecdh_sect283k1_test.json`
- `ecdh_sect283r1_test.json`
- `ecdh_sect409k1_test.json`
- `ecdh_sect409r1_test.json`
- `ecdh_sect571k1_test.json`
- `ecdh_sect571r1_test.json`
- `ecdsa_brainpoolP224r1_sha224_p1363_test.json`
- `ecdsa_brainpoolP224r1_sha224_test.json`
- `ecdsa_brainpoolP224r1_sha3_224_test.json`
- `ecdsa_brainpoolP256r1_sha256_p1363_test.json`
- `ecdsa_brainpoolP256r1_sha256_test.json`
- `ecdsa_brainpoolP256r1_sha3_256_test.json`
- `ecdsa_brainpoolP320r1_sha384_p1363_test.json`
- `ecdsa_brainpoolP320r1_sha384_test.json`
- `ecdsa_brainpoolP320r1_sha3_384_test.json`
- `ecdsa_brainpoolP384r1_sha384_p1363_test.json`
- `ecdsa_brainpoolP384r1_sha384_test.json`
- `ecdsa_brainpoolP384r1_sha3_384_test.json`
- `ecdsa_brainpoolP512r1_sha3_512_test.json`
- `ecdsa_brainpoolP512r1_sha512_p1363_test.json`
- `ecdsa_brainpoolP512r1_sha512_test.json`
- `ecdsa_secp160k1_sha256_p1363_test.json`
- `ecdsa_secp160k1_sha256_test.json`
- `ecdsa_secp160r1_sha256_p1363_test.json`
- `ecdsa_secp160r1_sha256_test.json`
- `ecdsa_secp160r2_sha256_p1363_test.json`
- `ecdsa_secp160r2_sha256_test.json`
- `ecdsa_secp192k1_sha256_p1363_test.json`
- `ecdsa_secp192k1_sha256_test.json`
- `ecdsa_secp192r1_sha256_p1363_test.json`
- `ecdsa_secp192r1_sha256_test.json`
- `ecdsa_secp224k1_sha224_p1363_test.json`
- `ecdsa_secp224k1_sha224_test.json`
- `ecdsa_secp224k1_sha256_p1363_test.json`
- `ecdsa_secp224k1_sha256_test.json`
- `ecdsa_secp224r1_sha224_p1363_test.json`
- `ecdsa_secp224r1_sha256_p1363_test.json`
- `ecdsa_secp224r1_sha512_p1363_test.json`
- `ecdsa_secp224r1_shake128_p1363_test.json`
- `ecdsa_secp256k1_sha256_bitcoin_test.json`
- `ecdsa_secp256k1_sha256_p1363_test.json`
- `ecdsa_secp256k1_sha256_test.json`
- `ecdsa_secp256k1_sha3_256_test.json`
- `ecdsa_secp256k1_sha3_512_test.json`
- `ecdsa_secp256k1_sha512_p1363_test.json`
- `ecdsa_secp256k1_sha512_test.json`
- `ecdsa_secp256k1_shake128_p1363_test.json`
- `ecdsa_secp256k1_shake128_test.json`
- `ecdsa_secp256k1_shake256_p1363_test.json`
- `ecdsa_secp256k1_shake256_test.json`
- `ecdsa_secp256r1_sha256_p1363_test.json`
- `ecdsa_secp256r1_sha512_p1363_test.json`
- `ecdsa_secp256r1_shake128_p1363_test.json`
- `ecdsa_secp384r1_sha384_p1363_test.json`
- `ecdsa_secp384r1_sha512_p1363_test.json`
- `ecdsa_secp384r1_shake256_p1363_test.json`
- `ecdsa_secp521r1_sha512_p1363_test.json`
- `ecdsa_secp521r1_shake256_p1363_test.json`
- `mldsa_44_sign_noseed_test.json`
- `mldsa_44_sign_seed_test.json`
- `mldsa_65_sign_seed_test.json`
- `mldsa_87_sign_noseed_test.json`
- `mldsa_87_sign_seed_test.json`
- `mlkem_1024_encaps_test.json`
- `mlkem_1024_keygen_seed_test.json`
- `mlkem_1024_semi_expanded_decaps_test.json`
- `mlkem_1024_test.json`
- `mlkem_512_encaps_test.json`
- `mlkem_512_keygen_seed_test.json`
- `mlkem_512_semi_expanded_decaps_test.json`
- `mlkem_512_test.json`
- `mlkem_768_encaps_test.json`
- `mlkem_768_keygen_seed_test.json`
- `mlkem_768_semi_expanded_decaps_test.json`
- `pbes2_hmacsha1_aes_128_test.json`
- `pbes2_hmacsha1_aes_192_test.json`
- `pbes2_hmacsha1_aes_256_test.json`
- `pbes2_hmacsha224_aes_128_test.json`
- `pbes2_hmacsha224_aes_192_test.json`
- `pbes2_hmacsha224_aes_256_test.json`
- `pbes2_hmacsha256_aes_128_test.json`
- `pbes2_hmacsha256_aes_192_test.json`
- `pbes2_hmacsha256_aes_256_test.json`
- `pbes2_hmacsha384_aes_128_test.json`
- `pbes2_hmacsha384_aes_192_test.json`
- `pbes2_hmacsha384_aes_256_test.json`
- `pbes2_hmacsha512_aes_128_test.json`
- `pbes2_hmacsha512_aes_192_test.json`
- `pbes2_hmacsha512_aes_256_test.json`
- `rsa_oaep_2048_sha512_224_mgf1sha1_test.json`
- `rsa_oaep_2048_sha512_224_mgf1sha512_224_test.json`
- `rsa_oaep_3072_sha512_256_mgf1sha1_test.json`
- `rsa_oaep_3072_sha512_256_mgf1sha512_256_test.json`
- `rsa_pkcs1_1024_sig_gen_test.json`
- `rsa_pkcs1_1536_sig_gen_test.json`
- `rsa_pkcs1_2048_sig_gen_test.json`
- `rsa_pkcs1_3072_sig_gen_test.json`
- `rsa_pkcs1_4096_sig_gen_test.json`
- `rsa_pss_2048_sha1_mgf1_20_params_test.json`
- `rsa_pss_2048_sha256_mgf1_0_params_test.json`
- `rsa_pss_2048_sha256_mgf1_32_params_test.json`
- `rsa_pss_2048_sha256_mgf1sha1_20_test.json`
- `rsa_pss_2048_sha512_mgf1sha256_32_params_test.json`
- `rsa_pss_2048_shake128_test.json`
- `rsa_pss_2048_shake256_test.json`
- `rsa_pss_3072_sha256_mgf1_32_params_test.json`
- `rsa_pss_3072_shake128_test.json`
- `rsa_pss_3072_shake256_test.json`
- `rsa_pss_4096_sha512_mgf1_32_params_test.json`
- `rsa_pss_4096_sha512_mgf1_64_params_test.json`
- `rsa_pss_4096_shake256_test.json`
- `rsa_pss_misc_params_test.json`
- `rsa_three_primes_oaep_2048_sha1_mgf1sha1_test.json`
- `rsa_three_primes_oaep_3072_sha224_mgf1sha224_test.json`
- `rsa_three_primes_oaep_4096_sha256_mgf1sha256_test.json`
- `x25519_asn_test.json`
- `x25519_jwk_test.json`
- `x25519_pem_test.json`
- `x448_asn_test.json`
- `x448_jwk_test.json`
- `x448_pem_test.json`

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
