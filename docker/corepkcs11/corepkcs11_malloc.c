#include <stddef.h>
#include <stdlib.h>

void * pvPkcs11Malloc( size_t size )
{
    return calloc( 1, size );
}

void vPkcs11Free( void * ptr )
{
    free( ptr );
}
