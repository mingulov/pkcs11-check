#ifndef COREPKCS11_CHECK_CONFIG_H
#define COREPKCS11_CHECK_CONFIG_H

#include <stddef.h>

void * pvPkcs11Malloc( size_t size );
void vPkcs11Free( void * ptr );

#define DISABLE_LOGGING
#ifndef LogError
    #define LogError( message )
#endif
#ifndef LogWarn
    #define LogWarn( message )
#endif
#ifndef LogInfo
    #define LogInfo( message )
#endif
#ifndef LogDebug
    #define LogDebug( message )
#endif

#define pkcs11configPKCS11_MALLOC                          pvPkcs11Malloc
#define pkcs11configPKCS11_FREE                            vPkcs11Free
#define pkcs11configPKCS11_DEFAULT_USER_PIN                "0000"

#define pkcs11configMAX_LABEL_LENGTH                       ( ( CK_ULONG ) 32 )
#define pkcs11configMAX_NUM_OBJECTS                        ( ( CK_ULONG ) 128 )
#define pkcs11configMAX_SESSIONS                           ( ( CK_ULONG ) 32 )

#define pkcs11configIMPORT_PRIVATE_KEYS_SUPPORTED          1
#define pkcs11configPAL_DESTROY_SUPPORTED                  0
#define pkcs11configOTA_SUPPORTED                          0
#define pkcs11configJITP_CODEVERIFY_ROOT_CERT_SUPPORTED    0

#define pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS       "Device Priv TLS Key"
#define pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS        "Device Pub TLS Key"
#define pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS       "Device Cert"
#define pkcs11configLABEL_HMAC_KEY                         "HMAC Key"
#define pkcs11configLABEL_CMAC_KEY                         "CMAC Key"
#define pkcs11configLABEL_CODE_VERIFICATION_KEY            "Code Verify Key"
#define pkcs11configLABEL_CLAIM_CERTIFICATE                "Claim Cert"
#define pkcs11configLABEL_CLAIM_PRIVATE_KEY                "Claim Key"
#define pkcs11configLABEL_JITP_CERTIFICATE                 "JITP Cert"
#define pkcs11configLABEL_ROOT_CERTIFICATE                 "Root Cert"

#endif
