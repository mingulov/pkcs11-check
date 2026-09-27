/* ML-DSA ExternalMu mechanism pair and CK_MU_GEN_PARAMS struct.
 * Parsed by scripts/generate_raw_standard.py as a generator overlay.
 * See README.md in this directory.
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
