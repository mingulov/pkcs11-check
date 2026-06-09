/* Generic in-memory PKCS #11 PAL for the pkcs11-check corePKCS11 docker target.
 *
 * corePKCS11's stock posix PAL maps only the eight labels configured in
 * core_pkcs11_config.h to fixed files; C_CreateObject with any other CKA_LABEL
 * fails (PKCS11_PAL_SaveObject returns an invalid handle -> CKR_DEVICE_MEMORY),
 * which makes the module untestable as a general PKCS#11 provider. The PAL is
 * corePKCS11's designated porting point, so this target supplies one that stores
 * any label in memory. corePKCS11's own PKCS#11 logic (template parsing, P-256 /
 * SHA-256-only crypto, label requirement, token-only objects) is untouched and
 * still what the suite measures.
 *
 * Objects survive C_Finalize/C_Initialize within a process (token-object
 * semantics, like the file-based PALs); per-test-file subprocess isolation gives
 * each run a fresh store.
 */

/* PKCS 11 includes. */
#include "core_pkcs11_config.h"
#include "core_pkcs11_config_defaults.h"
#include "core_pkcs11.h"

/* C runtime includes. */
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define PAL_GENERIC_MAX_OBJECTS    ( 2U * ( ( size_t ) pkcs11configMAX_NUM_OBJECTS ) )

typedef struct PalEntry
{
    CK_BYTE * pucData;
    CK_ULONG ulDataSize;
    CK_BYTE pucLabel[ pkcs11configMAX_LABEL_LENGTH ];
    CK_ULONG ulLabelLen;
    CK_BBOOL xInUse;
    CK_BBOOL xIsPrivate;
} PalEntry_t;

static PalEntry_t xEntries[ PAL_GENERIC_MAX_OBJECTS ];
static pthread_mutex_t xPalMutex = PTHREAD_MUTEX_INITIALIZER;

/* The mbedTLS port stores public keys as SubjectPublicKeyInfo (first element of
 * the outer SEQUENCE is the AlgorithmIdentifier SEQUENCE, tag 0x30) and private
 * keys as PKCS#1 RSAPrivateKey / SEC1 ECPrivateKey (first element is the version
 * INTEGER, tag 0x02). X.509 certificates also lead with a SEQUENCE (tbs), i.e.
 * "not private". C_GetAttributeValue uses this flag to refuse CKA_VALUE reads on
 * private objects, so it must be honest. */
static CK_BBOOL prvDerLooksPrivate( const CK_BYTE * pucData,
                                    CK_ULONG ulDataSize )
{
    CK_ULONG ulIdx = 0;
    CK_ULONG ulLenBytes;

    if( ( pucData == NULL ) || ( ulDataSize < 4UL ) || ( pucData[ 0 ] != 0x30U ) )
    {
        return CK_FALSE;
    }

    ulIdx = 1;

    if( ( pucData[ ulIdx ] & 0x80U ) != 0U )
    {
        ulLenBytes = ( CK_ULONG ) ( pucData[ ulIdx ] & 0x7FU );
        ulIdx += 1UL + ulLenBytes;
    }
    else
    {
        ulIdx += 1UL;
    }

    if( ulIdx >= ulDataSize )
    {
        return CK_FALSE;
    }

    return ( pucData[ ulIdx ] == 0x02U ) ? CK_TRUE : CK_FALSE;
}

static CK_OBJECT_HANDLE prvFindLocked( const CK_BYTE * pucLabel,
                                       CK_ULONG ulLabelLen )
{
    size_t uxIdx;

    for( uxIdx = 0; uxIdx < PAL_GENERIC_MAX_OBJECTS; uxIdx++ )
    {
        if( ( xEntries[ uxIdx ].xInUse == CK_TRUE ) &&
            ( xEntries[ uxIdx ].ulLabelLen == ulLabelLen ) &&
            ( memcmp( xEntries[ uxIdx ].pucLabel, pucLabel, ulLabelLen ) == 0 ) )
        {
            return ( CK_OBJECT_HANDLE ) ( uxIdx + 1U );
        }
    }

    return CK_INVALID_HANDLE;
}

CK_RV PKCS11_PAL_Initialize( void )
{
    /* Objects deliberately persist across C_Finalize/C_Initialize cycles
     * (token-object semantics); the store is per-process. */
    return CKR_OK;
}

CK_OBJECT_HANDLE PKCS11_PAL_SaveObject( CK_ATTRIBUTE_PTR pxLabel,
                                        CK_BYTE_PTR pucData,
                                        CK_ULONG ulDataSize )
{
    CK_OBJECT_HANDLE xHandle = CK_INVALID_HANDLE;
    CK_BYTE * pucCopy = NULL;
    PalEntry_t * pxEntry = NULL;
    size_t uxIdx;

    if( ( pxLabel == NULL ) || ( pxLabel->pValue == NULL ) ||
        ( pxLabel->ulValueLen == 0UL ) ||
        ( pxLabel->ulValueLen > pkcs11configMAX_LABEL_LENGTH ) ||
        ( pucData == NULL ) || ( ulDataSize == 0UL ) )
    {
        return CK_INVALID_HANDLE;
    }

    pucCopy = malloc( ulDataSize );

    if( pucCopy == NULL )
    {
        return CK_INVALID_HANDLE;
    }

    memcpy( pucCopy, pucData, ulDataSize );

    pthread_mutex_lock( &xPalMutex );

    xHandle = prvFindLocked( pxLabel->pValue, pxLabel->ulValueLen );

    if( xHandle != CK_INVALID_HANDLE )
    {
        pxEntry = &xEntries[ xHandle - 1U ];
        free( pxEntry->pucData );
    }
    else
    {
        for( uxIdx = 0; uxIdx < PAL_GENERIC_MAX_OBJECTS; uxIdx++ )
        {
            if( xEntries[ uxIdx ].xInUse == CK_FALSE )
            {
                pxEntry = &xEntries[ uxIdx ];
                xHandle = ( CK_OBJECT_HANDLE ) ( uxIdx + 1U );
                break;
            }
        }
    }

    if( pxEntry != NULL )
    {
        pxEntry->pucData = pucCopy;
        pxEntry->ulDataSize = ulDataSize;
        memcpy( pxEntry->pucLabel, pxLabel->pValue, pxLabel->ulValueLen );
        pxEntry->ulLabelLen = pxLabel->ulValueLen;
        pxEntry->xIsPrivate = prvDerLooksPrivate( pucCopy, ulDataSize );
        pxEntry->xInUse = CK_TRUE;
    }
    else
    {
        free( pucCopy );
        xHandle = CK_INVALID_HANDLE;
    }

    pthread_mutex_unlock( &xPalMutex );

    return xHandle;
}

CK_OBJECT_HANDLE PKCS11_PAL_FindObject( CK_BYTE_PTR pxLabel,
                                        CK_ULONG usLength )
{
    CK_OBJECT_HANDLE xHandle;

    if( ( pxLabel == NULL ) || ( usLength == 0UL ) ||
        ( usLength > pkcs11configMAX_LABEL_LENGTH ) )
    {
        return CK_INVALID_HANDLE;
    }

    pthread_mutex_lock( &xPalMutex );
    xHandle = prvFindLocked( pxLabel, usLength );
    pthread_mutex_unlock( &xPalMutex );

    return xHandle;
}

CK_RV PKCS11_PAL_GetObjectValue( CK_OBJECT_HANDLE xHandle,
                                 CK_BYTE_PTR * ppucData,
                                 CK_ULONG_PTR pulDataSize,
                                 CK_BBOOL * pIsPrivate )
{
    CK_RV xResult = CKR_OBJECT_HANDLE_INVALID;
    PalEntry_t * pxEntry = NULL;
    CK_BYTE * pucCopy = NULL;

    if( ( ppucData == NULL ) || ( pulDataSize == NULL ) || ( pIsPrivate == NULL ) )
    {
        return CKR_ARGUMENTS_BAD;
    }

    pthread_mutex_lock( &xPalMutex );

    if( ( xHandle != CK_INVALID_HANDLE ) &&
        ( xHandle <= ( CK_OBJECT_HANDLE ) PAL_GENERIC_MAX_OBJECTS ) &&
        ( xEntries[ xHandle - 1U ].xInUse == CK_TRUE ) )
    {
        pxEntry = &xEntries[ xHandle - 1U ];
        pucCopy = malloc( pxEntry->ulDataSize );

        if( pucCopy == NULL )
        {
            xResult = CKR_HOST_MEMORY;
        }
        else
        {
            memcpy( pucCopy, pxEntry->pucData, pxEntry->ulDataSize );
            *ppucData = pucCopy;
            *pulDataSize = pxEntry->ulDataSize;
            *pIsPrivate = pxEntry->xIsPrivate;
            xResult = CKR_OK;
        }
    }

    pthread_mutex_unlock( &xPalMutex );

    return xResult;
}

void PKCS11_PAL_GetObjectValueCleanup( CK_BYTE_PTR pucData,
                                       CK_ULONG ulDataSize )
{
    ( void ) ulDataSize;
    free( pucData );
}

CK_RV PKCS11_PAL_DestroyObject( CK_OBJECT_HANDLE xHandle )
{
    CK_RV xResult = CKR_OBJECT_HANDLE_INVALID;
    PalEntry_t * pxEntry = NULL;

    pthread_mutex_lock( &xPalMutex );

    if( ( xHandle != CK_INVALID_HANDLE ) &&
        ( xHandle <= ( CK_OBJECT_HANDLE ) PAL_GENERIC_MAX_OBJECTS ) &&
        ( xEntries[ xHandle - 1U ].xInUse == CK_TRUE ) )
    {
        pxEntry = &xEntries[ xHandle - 1U ];
        free( pxEntry->pucData );
        memset( pxEntry, 0, sizeof( *pxEntry ) );
        xResult = CKR_OK;
    }

    pthread_mutex_unlock( &xPalMutex );

    return xResult;
}
