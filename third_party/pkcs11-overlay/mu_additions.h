/* Project-authored PKCS#11 v3.3-draft additions: ML-DSA ExternalMu.
 *
 * Provenance (facts only; no OASIS text is copied here): OASIS
 * oasis-tcs/pkcs11 identifier allocation
 * working/identifier_db/pkcs11v3.3/external_mu.result @ f633c72
 * (2026-02-11, TC issue #58). Field names of CK_MU_GEN_PARAMS follow the
 * draft spec working/doc/spec/ml_dsa.md; the draft's `hKey,` typo is
 * corrected to `hKey;`. See README.md in this directory.
 *
 * License: MIT OR Apache-2.0 (project-authored).
 */

#define CKM_ML_DSA_EXTERNAL_MU_GEN 0x0000403BUL
#define CKM_ML_DSA_EXTERNAL_MU 0x0000403CUL

struct CK_MU_GEN_PARAMS {
    CK_OBJECT_HANDLE hKey;
    CK_BYTE_PTR pTR;
    CK_ULONG ulTRLen;
    CK_BYTE_PTR pctx;
    CK_ULONG ulctxLen;
};
