/*
 * Reproducer test for SoftHSMv2: Ed25519 CKK_EC_EDWARDS CKA_EC_POINT encoding.
 *
 * Drop the method + helper below into src/lib/test/SignVerifyTests.cpp, and
 * register them in src/lib/test/SignVerifyTests.h:
 *
 *   // inside CPPUNIT_TEST_SUITE, in the #ifdef WITH_EDDSA block:
 *   CPPUNIT_TEST(testEdImportPublicKeyVerify);
 *
 *   // in the public: section, #ifdef WITH_EDDSA block:
 *   void testEdImportPublicKeyVerify();
 *
 *   // in the protected: section, #ifdef WITH_EDDSA block:
 *   CK_RV importEdPublicKeyAndVerify(CK_SESSION_HANDLE hSession,
 *                                    CK_BYTE_PTR ecPoint, CK_ULONG ecPointLen);
 *
 * What it shows
 * -------------
 * PKCS#11 v3.0 Current Mechanisms, Errata 01, sec. 2.1 defines the
 * CKK_EC_EDWARDS public-key CKA_EC_POINT as the *raw* RFC 8032 public-key
 * bytes in little-endian order -- NOT a DER OCTET STRING (unlike Weierstrass
 * CKK_EC, whose CKA_EC_POINT is a DER-encoded ANSI X9.62 point).
 *
 * Using RFC 8032 sec. 7.1 Ed25519 test vector 1, this imports the same public
 * key two ways and verifies the known-good signature with CKM_EDDSA:
 *   - DER OCTET STRING form (04 20 <32 bytes>) -> C_Verify == CKR_OK
 *   - raw 32-byte form (the PKCS#11 spec form) -> C_Verify == CKR_SIGNATURE_INVALID
 *
 * So the final CPPUNIT_ASSERT(rawRv == CKR_OK) currently FAILS, which is the
 * point: SoftHSM2 only verifies with the non-spec DER-wrapped form. Cause:
 * the EdDSA public-key path stores/expects a DER OCTET STRING
 * (DERUTIL::raw2Octet / octet2Raw in src/lib/crypto/OSSLEDPublicKey.cpp and
 * BotanEDPublicKey.cpp; SoftHSM.cpp imports CKA_EC_POINT directly into setA()).
 *
 * Verified against /usr/lib/softhsm/libsofthsm2.so and a local build of main
 * (679f33d) via a standalone ctypes probe: raw -> CKR_SIGNATURE_INVALID,
 * DER -> CKR_OK on both.
 */

#ifdef WITH_EDDSA
CK_RV SignVerifyTests::importEdPublicKeyAndVerify(CK_SESSION_HANDLE hSession,
                                                  CK_BYTE_PTR ecPoint, CK_ULONG ecPointLen)
{
	// RFC 8032, sec. 7.1, Ed25519 test 1 (empty message).
	CK_BYTE ecParams[]  = { 0x06, 0x03, 0x2b, 0x65, 0x70 };	// OID id-Ed25519 (1.3.101.112)
	CK_BYTE signature[] = {
		0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
		0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
		0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
		0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b
	};
	CK_BYTE emptyMsg[] = { 0x00 };	// valid pointer; the verified length is 0

	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
	CK_KEY_TYPE keyType = CKK_EC_EDWARDS;
	CK_BBOOL bTrue = CK_TRUE;
	CK_BBOOL bFalse = CK_FALSE;

	CK_ATTRIBUTE pubTemplate[] = {
		{ CKA_CLASS,     &pubClass, sizeof(pubClass) },
		{ CKA_KEY_TYPE,  &keyType,  sizeof(keyType)  },
		{ CKA_TOKEN,     &bFalse,   sizeof(bFalse)   },
		{ CKA_VERIFY,    &bTrue,    sizeof(bTrue)    },
		{ CKA_EC_PARAMS, ecParams,  sizeof(ecParams) },
		{ CKA_EC_POINT,  ecPoint,   ecPointLen       }
	};

	CK_OBJECT_HANDLE hPub = CK_INVALID_HANDLE;
	CK_RV rv = CRYPTOKI_F_PTR( C_CreateObject(hSession, pubTemplate,
		sizeof(pubTemplate) / sizeof(CK_ATTRIBUTE), &hPub) );
	if (rv != CKR_OK)
		return rv;	// import itself rejected

	CK_MECHANISM mechanism = { CKM_EDDSA, NULL_PTR, 0 };
	rv = CRYPTOKI_F_PTR( C_VerifyInit(hSession, &mechanism, hPub) );
	if (rv != CKR_OK)
	{
		CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPub) );
		return rv;
	}

	rv = CRYPTOKI_F_PTR( C_Verify(hSession, emptyMsg, 0, signature, sizeof(signature)) );
	CRYPTOKI_F_PTR( C_DestroyObject(hSession, hPub) );
	return rv;
}

void SignVerifyTests::testEdImportPublicKeyVerify()
{
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

	// Make sure we finalize any previous tests.
	CRYPTOKI_F_PTR( C_Finalize(NULL_PTR) );

	rv = CRYPTOKI_F_PTR( C_Initialize(NULL_PTR) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_OpenSession(m_initializedTokenSlotID,
		CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	rv = CRYPTOKI_F_PTR( C_Login(hSession, CKU_USER, m_userPin1, m_userPin1Length) );
	CPPUNIT_ASSERT(rv == CKR_OK);

	// RFC 8032 sec. 7.1 Ed25519 test 1 public key, the SAME key two ways:
	CK_BYTE pubRaw[] = {	// raw RFC 8032 bytes -- the PKCS#11 v3.0-curr errata01 sec.2.1 form
		0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
		0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
	};
	CK_BYTE pubDer[] = {	// DER OCTET STRING (04 20) wrapping the same 32 bytes
		0x04,0x20,
		0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
		0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a
	};

	// Sanity: the DER OCTET STRING form (what SoftHSM2 stores internally) verifies.
	// This confirms the vector, key, and signature are correct.
	CK_RV derRv = importEdPublicKeyAndVerify(hSession, pubDer, sizeof(pubDer));
	CPPUNIT_ASSERT(derRv == CKR_OK);

	// The spec form (raw RFC 8032 bytes) MUST also verify. It currently does not:
	// SoftHSM2 returns CKR_SIGNATURE_INVALID because the EdDSA public-key code
	// expects a DER OCTET STRING in CKA_EC_POINT. This assert reproduces the bug.
	CK_RV rawRv = importEdPublicKeyAndVerify(hSession, pubRaw, sizeof(pubRaw));
	CPPUNIT_ASSERT_EQUAL((CK_RV)CKR_OK, rawRv);
}
#endif
