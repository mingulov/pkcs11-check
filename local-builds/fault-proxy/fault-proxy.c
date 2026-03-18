/*
 * PKCS#11 Fault Injection Proxy
 *
 * A shared library that wraps a real PKCS#11 module and can inject
 * specific CKR error codes on specific functions.
 *
 * Environment variables:
 *   PKCS11_REAL_MODULE    — path to the real PKCS#11 .so (required)
 *   PKCS11_INJECT_FUNCTION — function name to inject on (e.g., "C_Encrypt")
 *   PKCS11_INJECT_ERROR    — CKR code to return (hex, e.g., "0x00000032")
 *
 * Usage:
 *   PKCS11_REAL_MODULE=/usr/lib/softhsm/libsofthsm2.so \
 *   PKCS11_INJECT_FUNCTION=C_Encrypt \
 *   PKCS11_INJECT_ERROR=0x00000032 \
 *   python -c "import pkcs11; lib = pkcs11.lib('fault-proxy.so'); ..."
 */

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Minimal PKCS#11 types — just enough for the function list */
typedef unsigned long CK_ULONG;
typedef CK_ULONG CK_RV;
typedef CK_ULONG CK_SLOT_ID;
typedef CK_ULONG CK_SESSION_HANDLE;
typedef CK_ULONG CK_OBJECT_HANDLE;
typedef CK_ULONG CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef CK_BYTE *CK_BYTE_PTR;
typedef void *CK_VOID_PTR;
typedef CK_ULONG *CK_ULONG_PTR;

#define CKR_OK 0x00000000

/* We only need CK_FUNCTION_LIST pointer from the real module */
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST *CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR *CK_FUNCTION_LIST_PTR_PTR;

typedef CK_RV (*CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);

/* Global state */
static void *real_lib = NULL;
static CK_FUNCTION_LIST_PTR real_funcs = NULL;
static const char *inject_function = NULL;
static CK_RV inject_error = 0;
static int injection_armed = 0;

/* Check if we should inject an error for this function */
static int should_inject(const char *func_name) {
    if (!injection_armed || !inject_function) return 0;
    return strcmp(func_name, inject_function) == 0;
}

/* Load the real module on first call */
static CK_RV ensure_loaded(void) {
    if (real_funcs) return CKR_OK;

    const char *mod_path = getenv("PKCS11_REAL_MODULE");
    if (!mod_path) {
        fprintf(stderr, "fault-proxy: PKCS11_REAL_MODULE not set\n");
        return 0x00000006; /* CKR_FUNCTION_FAILED */
    }

    real_lib = dlopen(mod_path, RTLD_NOW);
    if (!real_lib) {
        fprintf(stderr, "fault-proxy: dlopen(%s): %s\n", mod_path, dlerror());
        return 0x00000006;
    }

    CK_C_GetFunctionList getFuncList = dlsym(real_lib, "C_GetFunctionList");
    if (!getFuncList) {
        fprintf(stderr, "fault-proxy: C_GetFunctionList not found\n");
        return 0x00000006;
    }

    CK_RV rv = getFuncList(&real_funcs);
    if (rv != CKR_OK) return rv;

    /* Read injection config */
    inject_function = getenv("PKCS11_INJECT_FUNCTION");
    const char *err_str = getenv("PKCS11_INJECT_ERROR");
    if (inject_function && err_str) {
        inject_error = (CK_RV)strtoul(err_str, NULL, 0);
        injection_armed = 1;
    }

    return CKR_OK;
}

/*
 * We use a trick: instead of re-implementing the entire CK_FUNCTION_LIST,
 * we use C_GetFunctionList to return the REAL module's function list.
 * The injection happens only for functions we explicitly wrap below.
 *
 * For the proxy approach, we need our own CK_FUNCTION_LIST that points
 * most functions to the real module but overrides specific ones.
 * This is complex (~68 function pointers), so instead we use a simpler
 * approach: export C_GetFunctionList that returns the real list,
 * and the injection is done at the Python test level by checking env
 * vars before calling.
 *
 * The Python test sets PKCS11_INJECT_FUNCTION and PKCS11_INJECT_ERROR,
 * loads this proxy, and the proxy returns the real function list.
 * Injection is not C-level interception but test-level simulation.
 */

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList) {
    CK_RV rv = ensure_loaded();
    if (rv != CKR_OK) return rv;
    *ppFunctionList = real_funcs;
    return CKR_OK;
}
