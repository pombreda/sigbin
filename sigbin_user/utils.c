#include "utils.h"

int copy_file( FILE *dest, FILE *src, uint32_t size)
{
	unsigned char *buf = NULL;
	if ( dest == NULL )
	{
		PRINT("Dest file is null\n");
		abort();
	}
	if ( src == NULL )
	{
		PRINT("SRC file is null\n");
		abort();
	}
	
	buf = malloc( size );
	if ( buf == NULL )
	{
		PRINT("Cannot allocate memory for file\n");
		abort();
	}

	fseek( src, 0, SEEK_SET );
	fread( buf, size, 1, src );

	fseek( dest, 0, SEEK_SET );
	fwrite( buf, size, 1, dest );
	
	free( buf );
	
	return 0;
}


int32_t get_file_size( FILE *f )
{
	int32_t itmp32=0;
	if ( f != NULL )
	{
		fseek( f, 0, SEEK_END );
		itmp32 = ftell( f );
		return itmp32;
	}
	return 0;
}


FILE* open_file_read( char *fname  )
{
	FILE *f;
	f = fopen( fname, "rw+" );
	if ( f == NULL  )
	{
		PRINT("Cannot open file %s\n", fname);
		abort();
	}
	return f;
}

FILE* open_file_write( char *fname )
{
	FILE *f;
	f = fopen( fname, "w+" );
	if ( f == NULL  )
	{
		PRINT("Cannot open file %s\n", fname);
		abort();
	}
	return f;

}

