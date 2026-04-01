/*
 * PKCS#11 Fault Injection Proxy — Full Intercepting Version
 *
 * Wraps a real PKCS#11 module. Can inject specific CKR error codes
 * on specific functions by setting environment variables.
 *
 * Environment variables:
 *   PKCS11_REAL_MODULE     — path to the real .so (required)
 *   PKCS11_INJECT_FUNCTION — function name to inject on (e.g., "C_Encrypt")
 *   PKCS11_INJECT_ERROR    — CKR code to return (hex, e.g., "0x00000032")
 *
 * All 68 v2.40 functions are wrapped. If injection matches, the injected
 * CKR is returned without calling the real function.
 */

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_RV;
typedef void *CK_VOID_PTR;
typedef unsigned char CK_BYTE;

#define CKR_OK 0x00000000

/* Forward declare the real function list type */
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR *CK_FUNCTION_LIST_PTR_PTR;
typedef CK_RV (*C_GetFunctionList_t)(CK_FUNCTION_LIST_PTR_PTR);

/* Global state */
static void *real_lib = NULL;
static CK_FUNCTION_LIST_PTR real_funcs = NULL;
static const char *inject_function = NULL;
static CK_RV inject_error = 0;
static int injection_armed = 0;
/* Proxy function list — sized for version + 68 function pointers */
static char proxy_funcs_buf[sizeof(void*) + 68 * sizeof(void*)];
static CK_FUNCTION_LIST_PTR proxy_funcs_ptr = (CK_FUNCTION_LIST_PTR)proxy_funcs_buf;

static int should_inject(const char *func_name) {
    if (!injection_armed || !inject_function) return 0;
    return strcmp(func_name, inject_function) == 0;
}

/*
 * We need the CK_FUNCTION_LIST struct layout to build our proxy.
 * Rather than include pkcs11.h (complex), we cast function pointers
 * at known offsets. The struct starts with CK_VERSION (2 bytes padded),
 * then 68 function pointers in pkcs11f.h order.
 */

/* Helper: read a function pointer from the real function list at index */
typedef CK_RV (*generic_func_t)();
static generic_func_t get_real_func(int index) {
    /* CK_VERSION at offset 0 (padded to pointer), then function pointers */
    void **ptrs = (void **)((char *)real_funcs + sizeof(void *));
    return (generic_func_t)ptrs[index];
}

/* Load real module */
static CK_RV ensure_loaded(void) {
    if (real_funcs) return CKR_OK;

    const char *mod_path = getenv("PKCS11_REAL_MODULE");
    if (!mod_path) {
        fprintf(stderr, "fault-proxy: PKCS11_REAL_MODULE not set\n");
        return 0x00000006;
    }

    real_lib = dlopen(mod_path, RTLD_NOW);
    if (!real_lib) {
        fprintf(stderr, "fault-proxy: dlopen(%s): %s\n", mod_path, dlerror());
        return 0x00000006;
    }

    C_GetFunctionList_t gfl = dlsym(real_lib, "C_GetFunctionList");
    if (!gfl) return 0x00000006;

    CK_RV rv = gfl(&real_funcs);
    if (rv != CKR_OK) return rv;

    inject_function = getenv("PKCS11_INJECT_FUNCTION");
    const char *err_str = getenv("PKCS11_INJECT_ERROR");
    if (inject_function && err_str) {
        inject_error = (CK_RV)strtoul(err_str, NULL, 0);
        injection_armed = 1;
    }

    return CKR_OK;
}

/*
 * Macro to generate a proxy function that checks injection before delegating.
 * We use variadic approach: each proxy stores args, checks injection, then
 * calls the real function via the function list at the correct index.
 *
 * For simplicity, we define each function with its real signature using
 * generic void* args and pass through to the real function at the right index.
 */

#define PROXY_FUNC_0(name, idx) \
    static CK_RV proxy_##name(void) { \
        if (should_inject(#name)) return inject_error; \
        return get_real_func(idx)(); \
    }

#define PROXY_FUNC_1(name, idx, t1) \
    static CK_RV proxy_##name(t1 a1) { \
        if (should_inject(#name)) return inject_error; \
        typedef CK_RV (*fn_t)(t1); \
        return ((fn_t)get_real_func(idx))(a1); \
    }

#define PROXY_FUNC_2(name, idx, t1, t2) \
    static CK_RV proxy_##name(t1 a1, t2 a2) { \
        if (should_inject(#name)) return inject_error; \
        typedef CK_RV (*fn_t)(t1, t2); \
        return ((fn_t)get_real_func(idx))(a1, a2); \
    }

#define PROXY_FUNC_3(name, idx, t1, t2, t3) \
    static CK_RV proxy_##name(t1 a1, t2 a2, t3 a3) { \
        if (should_inject(#name)) return inject_error; \
        typedef CK_RV (*fn_t)(t1, t2, t3); \
        return ((fn_t)get_real_func(idx))(a1, a2, a3); \
    }

#define PROXY_FUNC_4(name, idx, t1, t2, t3, t4) \
    static CK_RV proxy_##name(t1 a1, t2 a2, t3 a3, t4 a4) { \
        if (should_inject(#name)) return inject_error; \
        typedef CK_RV (*fn_t)(t1, t2, t3, t4); \
        return ((fn_t)get_real_func(idx))(a1, a2, a3, a4); \
    }

#define PROXY_FUNC_5(name, idx, t1, t2, t3, t4, t5) \
    static CK_RV proxy_##name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5) { \
        if (should_inject(#name)) return inject_error; \
        typedef CK_RV (*fn_t)(t1, t2, t3, t4, t5); \
        return ((fn_t)get_real_func(idx))(a1, a2, a3, a4, a5); \
    }

#define PROXY_FUNC_6(name, idx, t1, t2, t3, t4, t5, t6) \
    static CK_RV proxy_##name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6) { \
        if (should_inject(#name)) return inject_error; \
        typedef CK_RV (*fn_t)(t1, t2, t3, t4, t5, t6); \
        return ((fn_t)get_real_func(idx))(a1, a2, a3, a4, a5, a6); \
    }

#define PROXY_FUNC_7(name, idx, t1, t2, t3, t4, t5, t6, t7) \
    static CK_RV proxy_##name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6, t7 a7) { \
        if (should_inject(#name)) return inject_error; \
        typedef CK_RV (*fn_t)(t1, t2, t3, t4, t5, t6, t7); \
        return ((fn_t)get_real_func(idx))(a1, a2, a3, a4, a5, a6, a7); \
    }

#define PROXY_FUNC_8(name, idx, t1, t2, t3, t4, t5, t6, t7, t8) \
    static CK_RV proxy_##name(t1 a1, t2 a2, t3 a3, t4 a4, t5 a5, t6 a6, t7 a7, t8 a8) { \
        if (should_inject(#name)) return inject_error; \
        typedef CK_RV (*fn_t)(t1, t2, t3, t4, t5, t6, t7, t8); \
        return ((fn_t)get_real_func(idx))(a1, a2, a3, a4, a5, a6, a7, a8); \
    }

/* Use CK_ULONG for all params since they're all pointer-sized or smaller */
typedef CK_ULONG U;
typedef void* P;

/* Define all 68 proxy functions */
PROXY_FUNC_1(C_Initialize, 0, P)
PROXY_FUNC_1(C_Finalize, 1, P)
PROXY_FUNC_1(C_GetInfo, 2, P)
/* C_GetFunctionList (3) — handled separately */
PROXY_FUNC_3(C_GetSlotList, 4, U, P, P)
PROXY_FUNC_2(C_GetSlotInfo, 5, U, P)
PROXY_FUNC_2(C_GetTokenInfo, 6, U, P)
PROXY_FUNC_3(C_GetMechanismList, 7, U, P, P)
PROXY_FUNC_3(C_GetMechanismInfo, 8, U, U, P)
PROXY_FUNC_4(C_InitToken, 9, U, P, U, P)
PROXY_FUNC_3(C_InitPIN, 10, U, P, U)
PROXY_FUNC_5(C_SetPIN, 11, U, P, U, P, U)
PROXY_FUNC_5(C_OpenSession, 12, U, U, P, P, P)
PROXY_FUNC_1(C_CloseSession, 13, U)
PROXY_FUNC_1(C_CloseAllSessions, 14, U)
PROXY_FUNC_2(C_GetSessionInfo, 15, U, P)
PROXY_FUNC_3(C_GetOperationState, 16, U, P, P)
PROXY_FUNC_5(C_SetOperationState, 17, U, P, U, U, U)
PROXY_FUNC_4(C_Login, 18, U, U, P, U)
PROXY_FUNC_1(C_Logout, 19, U)
PROXY_FUNC_4(C_CreateObject, 20, U, P, U, P)
PROXY_FUNC_5(C_CopyObject, 21, U, U, P, U, P)
PROXY_FUNC_2(C_DestroyObject, 22, U, U)
PROXY_FUNC_3(C_GetObjectSize, 23, U, U, P)
PROXY_FUNC_4(C_GetAttributeValue, 24, U, U, P, U)
PROXY_FUNC_4(C_SetAttributeValue, 25, U, U, P, U)
PROXY_FUNC_3(C_FindObjectsInit, 26, U, P, U)
PROXY_FUNC_4(C_FindObjects, 27, U, P, U, P)
PROXY_FUNC_1(C_FindObjectsFinal, 28, U)
PROXY_FUNC_3(C_EncryptInit, 29, U, P, U)
PROXY_FUNC_5(C_Encrypt, 30, U, P, U, P, P)
PROXY_FUNC_5(C_EncryptUpdate, 31, U, P, U, P, P)
PROXY_FUNC_3(C_EncryptFinal, 32, U, P, P)
PROXY_FUNC_3(C_DecryptInit, 33, U, P, U)
PROXY_FUNC_5(C_Decrypt, 34, U, P, U, P, P)
PROXY_FUNC_5(C_DecryptUpdate, 35, U, P, U, P, P)
PROXY_FUNC_3(C_DecryptFinal, 36, U, P, P)
PROXY_FUNC_2(C_DigestInit, 37, U, P)
PROXY_FUNC_5(C_Digest, 38, U, P, U, P, P)
PROXY_FUNC_3(C_DigestUpdate, 39, U, P, U)
PROXY_FUNC_2(C_DigestKey, 40, U, U)
PROXY_FUNC_3(C_DigestFinal, 41, U, P, P)
PROXY_FUNC_3(C_SignInit, 42, U, P, U)
PROXY_FUNC_5(C_Sign, 43, U, P, U, P, P)
PROXY_FUNC_3(C_SignUpdate, 44, U, P, U)
PROXY_FUNC_3(C_SignFinal, 45, U, P, P)
PROXY_FUNC_3(C_SignRecoverInit, 46, U, P, U)
PROXY_FUNC_5(C_SignRecover, 47, U, P, U, P, P)
PROXY_FUNC_3(C_VerifyInit, 48, U, P, U)
PROXY_FUNC_5(C_Verify, 49, U, P, U, P, U)
PROXY_FUNC_3(C_VerifyUpdate, 50, U, P, U)
PROXY_FUNC_3(C_VerifyFinal, 51, U, P, U)
PROXY_FUNC_3(C_VerifyRecoverInit, 52, U, P, U)
PROXY_FUNC_5(C_VerifyRecover, 53, U, P, U, P, P)
PROXY_FUNC_5(C_DigestEncryptUpdate, 54, U, P, U, P, P)
PROXY_FUNC_5(C_DecryptDigestUpdate, 55, U, P, U, P, P)
PROXY_FUNC_5(C_SignEncryptUpdate, 56, U, P, U, P, P)
PROXY_FUNC_5(C_DecryptVerifyUpdate, 57, U, P, U, P, P)
PROXY_FUNC_5(C_GenerateKey, 58, U, P, P, U, P)
PROXY_FUNC_8(C_GenerateKeyPair, 59, U, P, P, U, P, U, P, P)
PROXY_FUNC_6(C_WrapKey, 60, U, P, U, U, P, P)
PROXY_FUNC_8(C_UnwrapKey, 61, U, P, U, P, U, P, U, P)
PROXY_FUNC_6(C_DeriveKey, 62, U, P, U, P, U, P)
PROXY_FUNC_3(C_SeedRandom, 63, U, P, U)
PROXY_FUNC_3(C_GenerateRandom, 64, U, P, U)
PROXY_FUNC_1(C_GetFunctionStatus, 65, U)
PROXY_FUNC_1(C_CancelFunction, 66, U)
PROXY_FUNC_3(C_WaitForSlotEvent, 67, U, P, P)

/* Build the proxy function list */
static void build_proxy_funcs(void) {
    /* Copy version from real */
    memcpy(proxy_funcs_buf, real_funcs, sizeof(void *)); /* CK_VERSION */

    /* Set all function pointers to our proxies */
    void **ptrs = (void **)((char *)proxy_funcs_buf + sizeof(void *));
    ptrs[0] = proxy_C_Initialize;
    ptrs[1] = proxy_C_Finalize;
    ptrs[2] = proxy_C_GetInfo;
    ptrs[3] = NULL; /* C_GetFunctionList — handled by export */
    ptrs[4] = proxy_C_GetSlotList;
    ptrs[5] = proxy_C_GetSlotInfo;
    ptrs[6] = proxy_C_GetTokenInfo;
    ptrs[7] = proxy_C_GetMechanismList;
    ptrs[8] = proxy_C_GetMechanismInfo;
    ptrs[9] = proxy_C_InitToken;
    ptrs[10] = proxy_C_InitPIN;
    ptrs[11] = proxy_C_SetPIN;
    ptrs[12] = proxy_C_OpenSession;
    ptrs[13] = proxy_C_CloseSession;
    ptrs[14] = proxy_C_CloseAllSessions;
    ptrs[15] = proxy_C_GetSessionInfo;
    ptrs[16] = proxy_C_GetOperationState;
    ptrs[17] = proxy_C_SetOperationState;
    ptrs[18] = proxy_C_Login;
    ptrs[19] = proxy_C_Logout;
    ptrs[20] = proxy_C_CreateObject;
    ptrs[21] = proxy_C_CopyObject;
    ptrs[22] = proxy_C_DestroyObject;
    ptrs[23] = proxy_C_GetObjectSize;
    ptrs[24] = proxy_C_GetAttributeValue;
    ptrs[25] = proxy_C_SetAttributeValue;
    ptrs[26] = proxy_C_FindObjectsInit;
    ptrs[27] = proxy_C_FindObjects;
    ptrs[28] = proxy_C_FindObjectsFinal;
    ptrs[29] = proxy_C_EncryptInit;
    ptrs[30] = proxy_C_Encrypt;
    ptrs[31] = proxy_C_EncryptUpdate;
    ptrs[32] = proxy_C_EncryptFinal;
    ptrs[33] = proxy_C_DecryptInit;
    ptrs[34] = proxy_C_Decrypt;
    ptrs[35] = proxy_C_DecryptUpdate;
    ptrs[36] = proxy_C_DecryptFinal;
    ptrs[37] = proxy_C_DigestInit;
    ptrs[38] = proxy_C_Digest;
    ptrs[39] = proxy_C_DigestUpdate;
    ptrs[40] = proxy_C_DigestKey;
    ptrs[41] = proxy_C_DigestFinal;
    ptrs[42] = proxy_C_SignInit;
    ptrs[43] = proxy_C_Sign;
    ptrs[44] = proxy_C_SignUpdate;
    ptrs[45] = proxy_C_SignFinal;
    ptrs[46] = proxy_C_SignRecoverInit;
    ptrs[47] = proxy_C_SignRecover;
    ptrs[48] = proxy_C_VerifyInit;
    ptrs[49] = proxy_C_Verify;
    ptrs[50] = proxy_C_VerifyUpdate;
    ptrs[51] = proxy_C_VerifyFinal;
    ptrs[52] = proxy_C_VerifyRecoverInit;
    ptrs[53] = proxy_C_VerifyRecover;
    ptrs[54] = proxy_C_DigestEncryptUpdate;
    ptrs[55] = proxy_C_DecryptDigestUpdate;
    ptrs[56] = proxy_C_SignEncryptUpdate;
    ptrs[57] = proxy_C_DecryptVerifyUpdate;
    ptrs[58] = proxy_C_GenerateKey;
    ptrs[59] = proxy_C_GenerateKeyPair;
    ptrs[60] = proxy_C_WrapKey;
    ptrs[61] = proxy_C_UnwrapKey;
    ptrs[62] = proxy_C_DeriveKey;
    ptrs[63] = proxy_C_SeedRandom;
    ptrs[64] = proxy_C_GenerateRandom;
    ptrs[65] = proxy_C_GetFunctionStatus;
    ptrs[66] = proxy_C_CancelFunction;
    ptrs[67] = proxy_C_WaitForSlotEvent;
}

/* The only exported function */
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    CK_RV rv = ensure_loaded();
    if (rv != CKR_OK) return rv;
    build_proxy_funcs();
    *ppFunctionList = proxy_funcs_ptr;
    return CKR_OK;
}
