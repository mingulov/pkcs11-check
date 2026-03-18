# Test Coverage Report (Auto-Generated)

Generated from 84 test files, 591 test functions.

## Mechanism Coverage

65 mechanisms referenced across test files.

| Mechanism | Test Files |
|-----------|------------|
| AES_CBC | benchmark, crossverify_extended, large_objects, mechanism, mechanism_fuzz, multipart_streaming, vendor_extensions |
| AES_CBC_PAD | interface, key_flags |
| AES_CCM | wycheproof_aes |
| AES_CMAC | wycheproof_aes |
| AES_ECB | api_security, benchmark, buffers, ckr_codes, concurrent_sessions, crossverify, dh_key_agreement, encrypt, errors, fuzz, interop, kat, key_lifecycle, key_sizes, key_usage_policy, keymgmt, large_objects, mechanism_fuzz, metamorphic, multipart, multipart_streaming, resource, rsa_key_wrapping, stateful, stress, surface_audit, token_objects, vendor_extensions |
| AES_GCM | aead, crossverify_extended, interop, wycheproof |
| AES_GMAC | wycheproof_aes |
| AES_KEY_GEN | vendor_extensions |
| AES_KEY_WRAP | key_lifecycle, wycheproof_aes |
| AES_KEY_WRAP_PAD | wycheproof_aes |
| AES_XTS | wycheproof_aes |
| RSA_PKCS | encrypt, errors, mechanism, padding_oracle, rsa_key_wrapping, wycheproof_rsa_decrypt |
| RSA_PKCS_OAEP | crossverify_extended, encrypt, key_sizes, padding_oracle, rsa_key_wrapping, rsa_oaep, wycheproof_rsa_oaep |
| SHA1_RSA_PKCS | crossverify, interop, sign |
| SHA1_RSA_PKCS_PSS | wycheproof_rsa_pss |
| SHA224_RSA_PKCS | crossverify, wycheproof_rsa |
| SHA224_RSA_PKCS_PSS | wycheproof_rsa_pss |
| SHA256_RSA_PKCS | benchmark, buffers, crossverify, errors, fuzz, interop, key_lifecycle, key_sizes, mechanism_fuzz, metamorphic, multipart, multipart_streaming, object, resource, sign, stress, wycheproof, wycheproof_rsa |
| SHA256_RSA_PKCS_PSS | crossverify_extended, interop, sign, wycheproof_rsa_pss |
| SHA384_RSA_PKCS | crossverify, errors, interop, sign, wycheproof_rsa |
| SHA384_RSA_PKCS_PSS | wycheproof_rsa_pss |
| SHA3_224_RSA_PKCS | wycheproof_rsa |
| SHA3_224_RSA_PKCS_PSS | wycheproof_rsa_pss |
| SHA3_256_RSA_PKCS | wycheproof_rsa |
| SHA3_256_RSA_PKCS_PSS | wycheproof_rsa_pss |
| SHA3_384_RSA_PKCS | wycheproof_rsa |
| SHA3_384_RSA_PKCS_PSS | wycheproof_rsa_pss |
| SHA3_512_RSA_PKCS | wycheproof_rsa |
| SHA3_512_RSA_PKCS_PSS | wycheproof_rsa_pss |
| SHA512_RSA_PKCS | crossverify, interop, sign, wycheproof_rsa |
| SHA512_RSA_PKCS_PSS | wycheproof_rsa_pss |
| ECDSA | benchmark, crossverify, ec_curves, ec_import_export, fuzz, interop, key_lifecycle, nonce_quality, sign, wycheproof, wycheproof_ecdsa |
| EC_EDWARDS_KEY_PAIR_GEN | eddsa |
| SHA224 | crossverify, digest, kat, surface_audit, wycheproof_rsa_oaep, wycheproof_rsa_pss |
| SHA224_HMAC | wycheproof_hmac |
| SHA256 | benchmark, buffers, ckr_codes, crossverify, crossverify_extended, digest, errors, fuzz, interop, kat, kdf, mechanism_fuzz, metamorphic, multipart, multipart_streaming, resource, sign, stateful, stress, surface_audit, wycheproof_hkdf, wycheproof_rsa_oaep, wycheproof_rsa_pss |
| SHA256_HMAC | crossverify, fuzz, generic_secret, interop, kdf, multipart_streaming, sign, surface_audit, wycheproof, wycheproof_hmac |
| SHA384 | crossverify, digest, kat, surface_audit, wycheproof_hkdf, wycheproof_rsa_oaep, wycheproof_rsa_pss |
| SHA384_HMAC | wycheproof_hmac |
| SHA3_224 | sha3, wycheproof_rsa_pss |
| SHA3_224_HMAC | wycheproof_hmac |
| SHA3_256 | sha3, wycheproof_rsa_pss |
| SHA3_256_HMAC | wycheproof_hmac |
| SHA3_384 | sha3, wycheproof_rsa_pss |
| SHA3_384_HMAC | wycheproof_hmac |
| SHA3_512 | sha3, wycheproof_rsa_pss |
| SHA3_512_HMAC | wycheproof_hmac |
| SHA512 | crossverify, digest, fuzz, kat, metamorphic, multipart, multipart_streaming, surface_audit, wycheproof_hkdf, wycheproof_rsa_oaep, wycheproof_rsa_pss |
| SHA512_224_HMAC | wycheproof_hmac |
| SHA512_256_HMAC | wycheproof_hmac |
| SHA512_HMAC | generic_secret, kdf, wycheproof_hmac |
| SHA_1 | crossverify, digest, kat, metamorphic, surface_audit, wycheproof_hkdf, wycheproof_rsa_oaep, wycheproof_rsa_pss |
| SHA_1_HMAC | crossverify, interop, wycheproof_hmac |
| ECDH1_DERIVE | ecdh_known_answer, kdf, keymgmt, wycheproof_ecdh, wycheproof_x25519 |
| EDDSA | eddsa, wycheproof_ed25519 |
| ML_DSA | pqc_sign, wycheproof_mldsa |
| ML_DSA_KEY_PAIR_GEN | pqc_sign |
| ML_KEM_KEY_PAIR_GEN | kem |
| SLH_DSA | pqc_sign |
| SLH_DSA_KEY_PAIR_GEN | pqc_sign |
| HKDF_DERIVE | kdf, wycheproof_hkdf |
| PKCS5_PBKD2 | wycheproof_pbkdf2 |
| CHACHA20_POLY1305 | wycheproof_chacha |
| DSA_SHA224 | wycheproof_dsa |
| DSA_SHA256 | sign, wycheproof_dsa |

## Key Type Coverage

| Key Type | Test Files |
|----------|------------|
| AES | access, access_control, aead, api_security, benchmark, buffers, ckr_codes, concurrent_sessions, dh_key_agreement, duplicate_labels, encrypt, errors, fuzz, interface, interface_negotiation, kem, key_flags, key_lifecycle, key_sizes, key_usage_policy, keymgmt, large_objects, mechanism_fuzz, metamorphic, multipart, multipart_streaming, object, padding_oracle, pin, reinitialize, resource, rsa_key_wrapping, search, sensitivity, session_exhaustion, session_info, set_attribute, so_pin, stateful, stress, surface_audit, token_objects, wycheproof, wycheproof_aes |
| AES_XTS | wycheproof_aes |
| CHACHA20 | wycheproof_chacha |
| DH | dh_key_agreement |
| DSA | sign, wycheproof_dsa |
| EC | benchmark, crossverify, ec_curves, ec_import_export, ecdh_known_answer, fuzz, interop, kdf, key_lifecycle, keymgmt, keypair_consistency, nonce_quality, object, sign, wycheproof, wycheproof_ecdh, wycheproof_ecdsa |
| EC_EDWARDS | eddsa, wycheproof_ed25519 |
| EC_MONTGOMERY | wycheproof_x25519 |
| GENERIC_SECRET | crossverify, ecdh_known_answer, generic_secret, interop, kdf, kem, keymgmt, sign, surface_audit, wycheproof, wycheproof_aes, wycheproof_ecdh, wycheproof_hkdf, wycheproof_hmac, wycheproof_pbkdf2, wycheproof_x25519 |
| ML_DSA | pqc_sign, wycheproof_mldsa |
| ML_KEM | kem |
| RSA | access, api_security, benchmark, buffers, crossverify, crossverify_extended, encrypt, errors, fuzz, interop, key_flags, key_lifecycle, key_sizes, key_usage_policy, keymgmt, keypair_consistency, mechanism_fuzz, metamorphic, multipart, multipart_streaming, object, padding_oracle, resource, rsa_key_wrapping, rsa_oaep, search, sensitivity, set_attribute, sign, stress, surface_audit, wycheproof, wycheproof_rsa, wycheproof_rsa_decrypt, wycheproof_rsa_oaep, wycheproof_rsa_pss |
| SHA224_HMAC | wycheproof_hmac |
| SHA256_HMAC | crossverify, fuzz, generic_secret, kdf, multipart_streaming, wycheproof |
| SHA384_HMAC | wycheproof_hmac |
| SHA3_224_HMAC | wycheproof_hmac |
| SHA3_256_HMAC | wycheproof_hmac |
| SHA3_384_HMAC | wycheproof_hmac |
| SHA3_512_HMAC | wycheproof_hmac |
| SHA512_224_HMAC | wycheproof_hmac |
| SHA512_256_HMAC | wycheproof_hmac |
| SHA512_HMAC | generic_secret, kdf, wycheproof_hmac |
| SHA_1_HMAC | crossverify, wycheproof_hmac |
| SLH_DSA | pqc_sign |

## Test File Summary

| File | Tests | Markers |
|------|-------|---------|
| test_access | 8 | access |
| test_access_control | 6 | security |
| test_aead | 7 | crossverify |
| test_api_security | 12 | security |
| test_benchmark | 16 | benchmark |
| test_buffers | 21 | boundary |
| test_certificate_objects | 13 | keymgmt |
| test_ckr_codes | 7 | security |
| test_concurrent_sessions | 6 | security |
| test_crossverify | 21 | crossverify |
| test_crossverify_extended | 5 | crossverify |
| test_data_objects | 13 | keymgmt |
| test_dh_key_agreement | 6 | keymgmt |
| test_digest | 8 | full |
| test_duplicate_labels | 4 | keymgmt |
| test_ec_curves | 3 | crossverify |
| test_ec_import_export | 4 | keymgmt |
| test_ecdh_known_answer | 2 | crossverify |
| test_eddsa | 10 | crossverify |
| test_encrypt | 12 | full |
| test_errors | 17 | security |
| test_fuzz | 11 | fuzz |
| test_generic_secret | 4 | keymgmt |
| test_init | 9 | access |
| test_interface | 11 | requires_v30, requires_v32, smoke, v30, v32 |
| test_interface_negotiation | 6 | destructive, smoke |
| test_interop | 11 | interop |
| test_kat | 7 | kat |
| test_kdf | 8 | keymgmt, requires_v30 |
| test_kem | 14 | kat, keymgmt, pqc, requires_v32, v32 |
| test_key_flags | 9 | security |
| test_key_lifecycle | 6 | keymgmt |
| test_key_sizes | 6 | keymgmt |
| test_key_usage_policy | 8 | security |
| test_keymgmt | 10 | keymgmt |
| test_keypair_consistency | 6 | keymgmt |
| test_large_objects | 6 | security |
| test_mechanism | 8 | mechflags |
| test_mechanism_fuzz | 7 | security |
| test_metamorphic | 13 | metamorphic |
| test_multipart | 9 | multipart |
| test_multipart_streaming | 7 | multipart |
| test_nonce_quality | 4 | security |
| test_object | 16 | keymgmt |
| test_padding_oracle | 4 | security |
| test_pin | 7 | security |
| test_pqc_sign | 14 | pqc, requires_v32 |
| test_profiles | 4 | requires_v30 |
| test_reinitialize | 2 | access, destructive |
| test_resource | 9 | stress |
| test_rng | 9 | security |
| test_rsa_key_wrapping | 6 | keymgmt |
| test_rsa_oaep | 7 | crossverify |
| test_search | 9 | search |
| test_sensitivity | 8 | security |
| test_session_exhaustion | 2 | security |
| test_session_info | 4 | access |
| test_set_attribute | 7 | keymgmt |
| test_sha3 | 3 | crossverify |
| test_sign | 14 | full |
| test_slot | 6 | smoke |
| test_so_pin | 3 | destructive, security |
| test_stateful | 2 | fuzz, stateful |
| test_stress | 8 | stress |
| test_surface_audit | 18 | surface_audit |
| test_token_flags | 11 | access |
| test_token_objects | 6 | destructive, keymgmt |
| test_vendor_extensions | 4 | smoke |
| test_wycheproof | 6 | wycheproof |
| test_wycheproof_aes | 6 | wycheproof |
| test_wycheproof_chacha | 1 | requires_v30, wycheproof |
| test_wycheproof_dsa | 1 | wycheproof |
| test_wycheproof_ecdh | 1 | wycheproof |
| test_wycheproof_ecdsa | 1 | wycheproof |
| test_wycheproof_ed25519 | 2 | wycheproof |
| test_wycheproof_hkdf | 1 | requires_v30, wycheproof |
| test_wycheproof_hmac | 1 | wycheproof |
| test_wycheproof_mldsa | 1 | pqc, requires_v32, wycheproof |
| test_wycheproof_pbkdf2 | 1 | wycheproof |
| test_wycheproof_rsa | 1 | wycheproof |
| test_wycheproof_rsa_decrypt | 1 | wycheproof |
| test_wycheproof_rsa_oaep | 1 | wycheproof |
| test_wycheproof_rsa_pss | 1 | wycheproof |
| test_wycheproof_x25519 | 1 | wycheproof |

**Total: 84 files, 591 test functions**
