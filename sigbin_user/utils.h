#ifndef __SIGBIN_UTILS_H
#define __SIGBIN_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>


#include "debug.h"


#define POLARSSL_ERROR(X) (~X+1)

int copy_file( FILE*, FILE*, uint32_t );
int32_t get_file_size( FILE * );
FILE *open_file_read( char* );
FILE *open_file_write( char* );


#endif
