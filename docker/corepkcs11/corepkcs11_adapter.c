#include <dlfcn.h>

#define CK_PTR      *
#define NULL_PTR    0
#define CK_DEFINE_FUNCTION( returnType, name )             returnType name
#define CK_DECLARE_FUNCTION( returnType, name )            returnType name
#define CK_DECLARE_FUNCTION_POINTER( returnType, name )    returnType( CK_PTR name )
#define CK_CALLBACK_FUNCTION( returnType, name )           returnType( CK_PTR name )

#include <pkcs11.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef CK_RV ( *get_function_list_fn )( CK_FUNCTION_LIST_PTR_PTR ppFunctionList );

struct MechanismInfo
{
    CK_MECHANISM_TYPE type;
    CK_MECHANISM_INFO info;
};

static void * real_handle = NULL;
static CK_FUNCTION_LIST_PTR core_funcs = NULL;
static CK_FUNCTION_LIST adapter_funcs;
static int adapter_loaded = 0;

static const struct MechanismInfo extra_mechanisms[] = {
    { CKM_SHA256_HMAC, { 32, 512, CKF_SIGN | CKF_VERIFY } },
    { CKM_AES_CMAC, { 16, 32, CKF_SIGN | CKF_VERIFY } },
};

static const CK_MECHANISM_TYPE candidate_mechanisms[] = {
    CKM_RSA_PKCS,
    CKM_RSA_X_509,
    CKM_ECDSA,
    CKM_EC_KEY_PAIR_GEN,
    CKM_SHA256,
    CKM_SHA256_HMAC,
    CKM_AES_CMAC,
};

static CK_RV adapter_get_info( CK_INFO_PTR info );
static CK_RV adapter_get_slot_info( CK_SLOT_ID slot_id, CK_SLOT_INFO_PTR info );
static CK_RV adapter_get_token_info( CK_SLOT_ID slot_id, CK_TOKEN_INFO_PTR info );
static CK_RV adapter_get_mechanism_list(
    CK_SLOT_ID slot_id,
    CK_MECHANISM_TYPE_PTR mechanism_list,
    CK_ULONG_PTR count
);
static CK_RV adapter_get_mechanism_info(
    CK_SLOT_ID slot_id,
    CK_MECHANISM_TYPE type,
    CK_MECHANISM_INFO_PTR info
);
static void normalize_core_mechanism_info( CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info );
static CK_RV adapter_digest(
    CK_SESSION_HANDLE session,
    CK_BYTE_PTR data,
    CK_ULONG data_len,
    CK_BYTE_PTR digest,
    CK_ULONG_PTR digest_len
);

static void copy_padded( CK_UTF8CHAR_PTR dest, CK_ULONG dest_len, const char * src )
{
    size_t src_len = strlen( src );
    size_t copy_len = src_len < dest_len ? src_len : dest_len;

    memset( dest, ' ', dest_len );
    memcpy( dest, src, copy_len );
}

static CK_RV ensure_loaded( void )
{
    const char * path;
    get_function_list_fn get_function_list;
    CK_RV rv;

    if( adapter_loaded )
    {
        return core_funcs == NULL ? CKR_FUNCTION_FAILED : CKR_OK;
    }

    adapter_loaded = 1;
    path = getenv( "COREPKCS11_REAL_MODULE" );

    if( ( path == NULL ) || ( path[ 0 ] == '\0' ) )
    {
        path = "/usr/local/lib/libcore_pkcs.so";
    }

    real_handle = dlopen( path, RTLD_NOW | RTLD_LOCAL );

    if( real_handle == NULL )
    {
        return CKR_FUNCTION_FAILED;
    }

    get_function_list = ( get_function_list_fn ) dlsym( real_handle, "C_GetFunctionList" );

    if( get_function_list == NULL )
    {
        return CKR_FUNCTION_FAILED;
    }

    rv = get_function_list( &core_funcs );

    if( rv != CKR_OK )
    {
        return rv;
    }

    if( core_funcs == NULL )
    {
        return CKR_FUNCTION_FAILED;
    }

    adapter_funcs = *core_funcs;
    adapter_funcs.C_GetInfo = adapter_get_info;
    adapter_funcs.C_GetSlotInfo = adapter_get_slot_info;
    adapter_funcs.C_GetTokenInfo = adapter_get_token_info;
    adapter_funcs.C_GetMechanismList = adapter_get_mechanism_list;
    adapter_funcs.C_GetMechanismInfo = adapter_get_mechanism_info;
    adapter_funcs.C_Digest = adapter_digest;

    return CKR_OK;
}

static CK_BBOOL slot_is_valid( CK_SLOT_ID slot_id )
{
    CK_SLOT_ID slots[ 8 ];
    CK_ULONG count = sizeof( slots ) / sizeof( slots[ 0 ] );
    CK_RV rv;

    if( ( core_funcs == NULL ) || ( core_funcs->C_GetSlotList == NULL ) )
    {
        return CK_TRUE;
    }

    rv = core_funcs->C_GetSlotList( CK_TRUE, slots, &count );

    if( rv != CKR_OK )
    {
        return CK_TRUE;
    }

    for( CK_ULONG i = 0; i < count; i++ )
    {
        if( slots[ i ] == slot_id )
        {
            return CK_TRUE;
        }
    }

    return CK_FALSE;
}

static CK_RV adapter_get_info( CK_INFO_PTR info )
{
    if( info == NULL )
    {
        return CKR_ARGUMENTS_BAD;
    }

    memset( info, 0, sizeof( *info ) );
    info->cryptokiVersion.major = 2;
    info->cryptokiVersion.minor = 40;
    copy_padded( info->manufacturerID, sizeof( info->manufacturerID ), "FreeRTOS" );
    info->flags = 0;
    copy_padded( info->libraryDescription, sizeof( info->libraryDescription ),
                 "corePKCS11 adapter" );
    info->libraryVersion.major = 3;
    info->libraryVersion.minor = 6;

    return CKR_OK;
}

static CK_RV adapter_get_slot_info( CK_SLOT_ID slot_id, CK_SLOT_INFO_PTR info )
{
    CK_RV rv = ensure_loaded();

    if( rv != CKR_OK )
    {
        return rv;
    }

    if( info == NULL )
    {
        return CKR_ARGUMENTS_BAD;
    }

    if( slot_is_valid( slot_id ) != CK_TRUE )
    {
        return CKR_SLOT_ID_INVALID;
    }

    memset( info, 0, sizeof( *info ) );
    copy_padded( info->slotDescription, sizeof( info->slotDescription ),
                 "corePKCS11 MbedTLS software slot" );
    copy_padded( info->manufacturerID, sizeof( info->manufacturerID ), "FreeRTOS" );
    info->flags = CKF_TOKEN_PRESENT;
    info->hardwareVersion.major = 0;
    info->hardwareVersion.minor = 0;
    info->firmwareVersion.major = 3;
    info->firmwareVersion.minor = 6;

    return CKR_OK;
}

static CK_RV adapter_get_token_info( CK_SLOT_ID slot_id, CK_TOKEN_INFO_PTR info )
{
    CK_RV rv = ensure_loaded();

    if( rv != CKR_OK )
    {
        return rv;
    }

    if( info == NULL )
    {
        return CKR_ARGUMENTS_BAD;
    }

    if( slot_is_valid( slot_id ) != CK_TRUE )
    {
        return CKR_SLOT_ID_INVALID;
    }

    memset( info, 0, sizeof( *info ) );
    copy_padded( info->label, sizeof( info->label ), "corePKCS11" );
    copy_padded( info->manufacturerID, sizeof( info->manufacturerID ), "FreeRTOS" );
    copy_padded( info->model, sizeof( info->model ), "MbedTLS mock" );
    copy_padded( info->serialNumber, sizeof( info->serialNumber ), "0000000000000001" );
    info->flags = CKF_TOKEN_INITIALIZED | CKF_RNG | CKF_USER_PIN_INITIALIZED;
    info->ulMaxSessionCount = 32;
    info->ulSessionCount = CK_UNAVAILABLE_INFORMATION;
    info->ulMaxRwSessionCount = 32;
    info->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    info->ulMaxPinLen = 4;
    info->ulMinPinLen = 4;
    info->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
    info->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
    info->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
    info->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
    info->hardwareVersion.major = 0;
    info->hardwareVersion.minor = 0;
    info->firmwareVersion.major = 3;
    info->firmwareVersion.minor = 6;
    copy_padded( info->utcTime, sizeof( info->utcTime ), "" );

    return CKR_OK;
}

static CK_RV extra_mechanism_info( CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info )
{
    for( CK_ULONG i = 0; i < sizeof( extra_mechanisms ) / sizeof( extra_mechanisms[ 0 ] ); i++ )
    {
        if( extra_mechanisms[ i ].type == type )
        {
            if( info != NULL )
            {
                *info = extra_mechanisms[ i ].info;
            }

            return CKR_OK;
        }
    }

    return CKR_MECHANISM_INVALID;
}

static void normalize_core_mechanism_info( CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info )
{
    if( ( type == CKM_RSA_PKCS ) && ( info != NULL ) )
    {
        /* corePKCS11 can verify CKM_RSA_PKCS, but its upstream metadata is sign-only. */
        info->flags |= CKF_VERIFY;
    }
}

static CK_RV adapter_get_mechanism_info(
    CK_SLOT_ID slot_id,
    CK_MECHANISM_TYPE type,
    CK_MECHANISM_INFO_PTR info
)
{
    CK_RV rv = ensure_loaded();

    if( rv != CKR_OK )
    {
        return rv;
    }

    if( info == NULL )
    {
        return CKR_ARGUMENTS_BAD;
    }

    if( core_funcs->C_GetMechanismInfo != NULL )
    {
        rv = core_funcs->C_GetMechanismInfo( slot_id, type, info );

        if( rv == CKR_OK )
        {
            normalize_core_mechanism_info( type, info );
            return CKR_OK;
        }
    }

    return extra_mechanism_info( type, info );
}

static CK_RV adapter_get_mechanism_list(
    CK_SLOT_ID slot_id,
    CK_MECHANISM_TYPE_PTR mechanism_list,
    CK_ULONG_PTR count
)
{
    CK_MECHANISM_INFO mechanism_info;
    CK_MECHANISM_TYPE supported[ sizeof( candidate_mechanisms ) / sizeof( candidate_mechanisms[ 0 ] ) ];
    CK_ULONG supported_count = 0;
    CK_RV rv = ensure_loaded();

    if( rv != CKR_OK )
    {
        return rv;
    }

    if( count == NULL )
    {
        return CKR_ARGUMENTS_BAD;
    }

    for( CK_ULONG i = 0; i < ( sizeof( candidate_mechanisms ) / sizeof( candidate_mechanisms[ 0 ] ) ); i++ )
    {
        rv = adapter_get_mechanism_info( slot_id, candidate_mechanisms[ i ], &mechanism_info );

        if( rv == CKR_OK )
        {
            supported[ supported_count ] = candidate_mechanisms[ i ];
            supported_count++;
        }
    }

    if( mechanism_list == NULL )
    {
        *count = supported_count;
        return CKR_OK;
    }

    if( *count < supported_count )
    {
        *count = supported_count;
        return CKR_BUFFER_TOO_SMALL;
    }

    for( CK_ULONG i = 0; i < supported_count; i++ )
    {
        mechanism_list[ i ] = supported[ i ];
    }

    *count = supported_count;
    return CKR_OK;
}

static CK_RV adapter_digest(
    CK_SESSION_HANDLE session,
    CK_BYTE_PTR data,
    CK_ULONG data_len,
    CK_BYTE_PTR digest,
    CK_ULONG_PTR digest_len
)
{
    CK_RV rv = ensure_loaded();
    CK_BYTE core_digest[ 32 ];
    CK_ULONG core_digest_len = sizeof( core_digest );

    if( rv != CKR_OK )
    {
        return rv;
    }

    if( ( core_funcs->C_DigestUpdate == NULL ) || ( core_funcs->C_DigestFinal == NULL ) )
    {
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    if( ( data == NULL ) && ( data_len != 0 ) )
    {
        return CKR_ARGUMENTS_BAD;
    }

    if( digest_len == NULL )
    {
        return CKR_ARGUMENTS_BAD;
    }

    if( digest == NULL )
    {
        *digest_len = 32;
        return CKR_OK;
    }

    if( *digest_len < 32 )
    {
        *digest_len = 32;
        return CKR_BUFFER_TOO_SMALL;
    }

    if( data_len != 0 )
    {
        rv = core_funcs->C_DigestUpdate( session, data, data_len );

        if( rv != CKR_OK )
        {
            return rv;
        }
    }

    rv = core_funcs->C_DigestFinal( session, core_digest, &core_digest_len );

    if( rv != CKR_OK )
    {
        *digest_len = core_digest_len;
        return rv;
    }

    if( core_digest_len > *digest_len )
    {
        *digest_len = core_digest_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy( digest, core_digest, core_digest_len );
    *digest_len = core_digest_len;
    return CKR_OK;
}

CK_DECLARE_FUNCTION( CK_RV, C_GetFunctionList )( CK_FUNCTION_LIST_PTR_PTR ppFunctionList )
{
    CK_RV rv;

    if( ppFunctionList == NULL )
    {
        return CKR_ARGUMENTS_BAD;
    }

    rv = ensure_loaded();

    if( rv != CKR_OK )
    {
        return rv;
    }

    *ppFunctionList = &adapter_funcs;
    return CKR_OK;
}
