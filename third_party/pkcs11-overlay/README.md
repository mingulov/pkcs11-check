# PKCS#11 overlay (generator input)

`scripts/generate_raw_standard.py` parses the header in
`../pkcs11-headers/3.2/pkcs11.h` first, then every file listed in its
`OVERLAY_HEADERS` tuple from this directory. Overlay entries win over
the base header.

- `mu_additions.h`: ML-DSA ExternalMu mechanism pair
  (`CKM_ML_DSA_EXTERNAL_MU_GEN = 0x403B`,
  `CKM_ML_DSA_EXTERNAL_MU = 0x403C`) and `CK_MU_GEN_PARAMS`.
- `latchset_3_2_fixes.h`: `CK_X9_42_MQV_DERIVE_PARAMS` with pointer
  fields spelled `pOtherInfo`/`pPublicData`/`pPublicData2`.
