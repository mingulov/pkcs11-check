/* Corrections to latchset/pkcs11-headers public-domain/3.2/pkcs11.h @ c5e6199.
 *
 * CK_X9_42_MQV_DERIVE_PARAMS carries its pointer fields WITH the `p` prefix
 * (pOtherInfo/pPublicData/pPublicData2) in the ratified OASIS v3.2 pkcs11t.h
 * and in the v3.3 working headers; latchset misspells them without the
 * prefix. The latchset text is public domain and the OASIS spellings are API
 * facts, so the corrected struct is re-typed here. See README.md.
 *
 * License: MIT OR Apache-2.0 (project-authored).
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
