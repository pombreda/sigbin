#include "section.h"

///////////////////////////////////////////////////////////////////////////////
//init section structure
sigbin_section* section_init()
{
    sigbin_section *sb = NULL;
    
    sb = malloc( sizeof(sigbin_section) );
    if ( sb == NULL )
	{
		PRINT("Cannot allocate memory for section\n");
		return NULL;
	}
    memset( sb, 0x00, sizeof(sigbin_section) );
    
    return sb;
}

///////////////////////////////////////////////////////////////////////////////
//add hash value
int section_set_hash( sigbin_section *ss, const char *hash )
{
	switch ( ss->version )
	{
		case SIGBIN_V1:
			memcpy( ss->v1.sha_hash, hash, SIGBIN_SHA256_SIZE);
			return 0;
			break;
		/*
		case SIGBIN_V2:
			memcpy( ss->v2.sha_hash, hash, _HASH_SIZE );
			return 0;
			break;
		*/
		default:
			return 1;
			break;
	}
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//add aes key to section
int section_set_key( sigbin_section *ss, const char *key )
{
	if ( ss != NULL )
	{
		if ( key != NULL )
		{
			/*
			if ( ss->version == SIGBIN_V2 )
			{
				memcpy( ss->v2.aes_key, key, 128);
				return 1;
			}
			*/
		}
	}
	return 0;
}

///////////////////////////////////////////////////////////////////////////////
//set version
int section_set_ver( sigbin_section *ss, uint16_t ver)
{
    //ss->version = (short)SIGBIN_V0;
    if ( ss != NULL )
    {
		//if ((ver == SIGBIN_V1) || (ver == SIGBIN_V2) || (ver == SIGBIN_V3))
		if ( ver == SIGBIN_V1 )
		{
			ss->version = ver;
			return 0;
		}
	}
    return -1;
}

//if sigbin version is 3 then add rsa crypted signature
int section_set_rsa_signature( sigbin_section *ss, unsigned const char *signature)
{
	if ( ss != NULL )
	{
		if ( signature != NULL)
		{
			if ( ss->version == SIGBIN_V3 )
			{
				//memcpy( ss->v3.signature_buffer, signature, CERT_RSA_BLOCK_SIZE );
				return -1;
			}
		}
	}
	return -1;
}


///////////////////////////////////////////////////////////////////////////////
//set file size
uint32_t section_set_file_size( sigbin_section *ss, uint32_t file_size )
{
	if ( ss != NULL )
	{
		ss->file_size = file_size;
		return 0;
	}
	return -1;
}

///////////////////////////////////////////////////////////////////////////////
//encrypt section
char* section_encrypt( sigbin_section *ss )
{
//#ifdef HASH_KERNEL
	//PRINT("Function empty\n");
//#else
    //PRINT("Section encrypt\n");
    if (ss != NULL)
    {
		if ( ss->version == SIGBIN_V2 )
		{
			char *data = NULL;
			//PRINT("data 0x08%x\n", data);
			//data = crypt_rsa( (char *)ss, sizeof(sigbin_section), section_size(), "./cert/pub.key");
			#ifndef NO_HANDMADE_WARNINGS
				#warning "Not supported section encryption"
			#endif
			//data = crypt_rsa_plain( ss );
			//PRINT("data 0x%08x\n", data);
			return data;
		} else if ( ss->version == SIGBIN_V1 )
		{
			char *data = NULL;
			#ifndef NO_HANDMADE_WARNINGS
				#warning "Not supported section encryption"
			#endif
			//data = crypt_rsa_plain( ss );
			return data;
		}
		{
			PRINT("Section encryption\n");
		}
    }
//#endif
    return NULL;
}

///////////////////////////////////////////////////////////////////////////////
//destroy object
void section_destroy( sigbin_section *ss )
{
    if ( ss != NULL )
    {
        free( ss );
        ss = NULL;
    }
}

///////////////////////////////////////////////////////////////////////////////
//return size of section needed to reserve
size_t section_size( sigbin_section *s )
{

    div_t d;
	size_t result;
	
	switch ( s->version )
	{
		/*
		case SIGBIN_V1:
			d = div( sizeof(sigbin_section_v1), RSA_CHUNK_SIZE );
			break;
		case SIGBIN_V2:
			d = div( sizeof(sigbin_section_v2), RSA_CHUNK_SIZE );
			break;
		case SIGBIN_V3:
			d = div( sizeof(sigbin_section_v3), RSA_CHUNK_SIZE );
			break;
		*/
		case SIGBIN_V1:
		case SIGBIN_V2:
		case SIGBIN_V3:
			d = div(sizeof(sigbin_section), SIGBIN_RSA_KEY_SIZE );
			break;
		default:
		{
			PRINT("Uncorect section version (0x%08x)\n", s->version);
			abort();
		}
	}
    
	//PRINT("\n");
	if ( d.rem == 0 )
    {
        result =  (SIGBIN_RSA_KEY_SIZE*d.quot);
    } else
	{
		result = (SIGBIN_RSA_KEY_SIZE)*(d.quot+1);
	}

	//PRINT("QUOT: %d REM: %d SECSIZE:%d(0x%08x)\n", d.quot, d.rem, result, result);
    
	return result;
}

///////////////////////////////////////////////////////////////////////////////
void section_print( sigbin_section *ss )
{
	int i;
	int output_len=50;
	if ( ss != NULL )
	{
		PRINTF("Sigbin:\n");
		PRINTF("	Version: %04x\n", ss->version );
		PRINTF("	File size: %04x(%06d)\n", ss->file_size, ss->file_size );
		switch ( ss->version )
		{
			case SIGBIN_V1:
				{
					PRINTF("\tHASH: ");
					for (i=0; i < (SIGBIN_SHA256_SIZE%output_len); i++)
					{
						PRINTF("%02x",(unsigned char)ss->v1.sha_hash[i] );
					}
					PRINTF("\n");
				};
				break;
			/*
			case SIGBIN_V2:
				{
					PRINTF("\tHASH: ");
					for (i=0; i < (S_SHA256_SIZE%output_len); i++)
					{
						PRINTF("%02x",(unsigned char)ss->v2.sha_hash[i] );
					}
					PRINTF(" ... \n");
					PRINTF("\t KEY: ");
					for (i=0; i < (_AES_KEY_SIZE%output_len); i++)
					{
						PRINTF("%02x",(unsigned char) ss->v2.aes_key[i] );
					}
					PRINTF(" ... \n");
				};
				break;
			*/
			default:
				PRINTF(" Unknown section\n");
		}
	}
}

void section_print_test( sigbin_section *ss )
{
	uint32_t v1,v2,v3,v,total;
	PRINT("SIGBIN_SECTION: \n");
	if ( ss != NULL )
	{
	} else
	{
		PRINT("\n");
	}
	total = sizeof( sigbin_section );
	PRINT("Total sizes: \n");
	v1 = sizeof( sigbin_section_v1 );
	PRINT("\tV1: %d\n", v1);
	/*
	v2 = sizeof( sigbin_section_v2 );
	PRINT("\tV2: %d\n", v2);
	v3 = sizeof( sigbin_section_v3 );
	PRINT("\tV3: %d\n", v3);
	v = total-v1-v2-v3;
	*/
	v = total-v1;
	PRINT("\tTotal: %d V: %d \n", total, v );
}

