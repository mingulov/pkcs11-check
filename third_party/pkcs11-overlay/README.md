# Project-authored PKCS#11 overlay (generator input)

`scripts/generate_raw_standard.py` parses the verbatim public-domain header in
`../pkcs11-headers/3.2/pkcs11.h` first, then parses every file listed in its
`OVERLAY_HEADERS` tuple from this directory. Overlay entries **win** over the
base header (explicit `dict.update`, symbols and structs), so this directory
holds two things:

- `mu_additions.h`: the ML-DSA ExternalMu mechanism pair plus its parameter
  struct, allocated by the OASIS PKCS 11 TC for the v3.3 working draft.
- `latchset_3_2_fixes.h`: corrections of transcription mistakes in the
  latchset 3.2 header, matching the ratified OASIS v3.2 text.

## Provenance

No OASIS-copyrighted text is copied here. Mechanism names, numeric code
points, and struct field names are API facts re-typed from these sources:

- `mu_additions.h`: OASIS `oasis-tcs/pkcs11` identifier allocation
  `working/identifier_db/pkcs11v3.3/external_mu.result` @ `f633c72`
  (2026-02-11, TC issue #58): `CKM_ML_DSA_EXTERNAL_MU_GEN = 0x403B`,
  `CKM_ML_DSA_EXTERNAL_MU = 0x403C`. Field names of `CK_MU_GEN_PARAMS`
  follow the draft spec `working/doc/spec/ml_dsa.md` (the draft's `hKey,`
  typo is corrected to `hKey;`).
- `latchset_3_2_fixes.h`: `CK_X9_42_MQV_DERIVE_PARAMS` pointer fields are
  `pOtherInfo`/`pPublicData`/`pPublicData2` in the ratified OASIS v3.2
  `pkcs11t.h` (June 2026) and in the v3.3 working headers; latchset
  `c5e6199` misspells them without the `p` prefix.

Background: a pre-ratification v3.2 draft carried the ExternalMu pair at
`0x1E`/`0x22`. The ratified v3.2 OASIS Standard dropped them (leaving those
code points unassigned) and the TC re-allocated them at `0x403B`/`0x403C`
for v3.3. The `0x1E`/`0x22` values must not be reintroduced.

## License

These files are authored by the pkcs11-check project from the published
facts above and are distributed under the project's dual license
(MIT OR Apache-2.0). See `THIRD_PARTY_LICENSES.md`.
