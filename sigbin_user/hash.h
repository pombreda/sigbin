#ifndef __SIGBIN_HASH_H
#define __SIGBIN_HASH_H

#include <stdio.h>
#include <stdlib.h>

#include <polarssl/sha2.h>

#include "sigbin.h"
#include "debug.h"
#include "utils.h"

#define STATUS_NULL     0
#define STATUS_START    1
#define STATUS_FINISH   2

typedef struct hash_context
{
    int status;
    sha2_context *context;
    char hash[SIGBIN_SHA256_SIZE];
} hash_context;

hash_context* hash_start();
void hash_update( hash_context*, char*, size_t );
void hash_finish( hash_context* );
void hash_destroy( hash_context* );
void hash_print( hash_context* );

#endif
