#include "hash.h"

// crearte hash structure
hash_context* hash_start()
{
    hash_context *hc = NULL;
    hc = malloc( sizeof(hash_context) );
    memset( hc, 0, sizeof(hash_context) );
    hc->context = malloc( sizeof(sha2_context) );
    sha2_starts( hc->context, 0 );
    hc->status = STATUS_START;
    return hc;
}

///////////////////////////////////////////////////////////////////////////////
//add new block of data to hash routine
void hash_update( hash_context *hc, char *buf, size_t len)
{
    if ((hc != NULL) && (buf != NULL))
    {
        if ( hc->status == STATUS_START )
        {
            sha2_update( hc->context, buf, len);
        } else
		{
			PRINT("HASH finished\n");
		}
    }
}

///////////////////////////////////////////////////////////////////////////////
//after this moment nothing will change hash value
//hash_update will not work
void hash_finish( hash_context *hc )
{
	int i;
    if ( hc != NULL )
    {
        if ( hc->status == STATUS_START)
        {
            sha2_finish( hc->context, hc->hash );
			for ( i = 0; i < 32; i++)
			{
				printf( "%02x" , (unsigned char)hc->hash[i] );
			}
			printf("\n");
            hc->status = STATUS_FINISH;
        } else
		{
			PRINT("HASH finished\n");
		}
    }
}


///////////////////////////////////////////////////////////////////////////////
void hash_destroy( hash_context *hc )
{
	if ( hc != NULL )
	{
		free( hc->context );
		hc->context = NULL;
		free( hc );
		hc = NULL;
	}
}


///////////////////////////////////////////////////////////////////////////////
void hash_print( hash_context *hc )
{
	int i;
	if ( hc != NULL )
	{
		printf("Hash : ");
		for (i=0; i<32; i++ )
		{
			printf("%02x",(unsigned char)hc->hash[i]);
		}
		printf("\n");
	}
}

