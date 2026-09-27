/* Corrected CK_X9_42_MQV_DERIVE_PARAMS: pointer fields WITH the `p` prefix
 * (pOtherInfo/pPublicData/pPublicData2); the base header misspells them.
 * Parsed by scripts/generate_raw_standard.py as a generator overlay.
 * See README.md in this directory.
 */

struct CK_X9_42_MQV_DERIVE_PARAMS {
    CK_X9_42_DH_KDF_TYPE kdf;
    CK_ULONG ulOtherInfoLen;
    CK_BYTE * pOtherInfo;
    CK_ULONG ulPublicDataLen;
    CK_BYTE * pPublicData;
    CK_ULONG ulPrivateDataLen;
    CK_OBJECT_HANDLE hPrivateData;
    CK_ULONG ulPublicDataLen2;
    CK_BYTE * pPublicData2;
    CK_OBJECT_HANDLE publicKey;
};
