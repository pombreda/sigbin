#ifndef __SIGBIN_SECTION_H
#define __SIGBIN_SECTION_H

#ifndef __SAFSIG_SECTION_H
#define __SAFSIG_SECTION_H

//#define HASH_KERNEL
#define NO_SUPPORT_V3

#ifdef HASH_KERNEL
	#include <linux/kernel.h>
	#include <linux/string.h>
#else
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>
	#include <stdint.h>	
#endif

#ifdef HASH_KERNEL
	#include "../debug.h"
	#include "sigbin.h"
#else
	#include "debug.h"
	#include "sigbin.h"
#endif


#ifdef HASH_KERNEL
	#define PRINTF printk
#else
	#define PRINTF printf
#endif

///////////////////////////////////////////////////////////////////////////////
//real size after encryption will be ([sizeof(sigbin_section)/117]+1)*128
//at date 21.01.2012 sizeof(2+128+16) = 256 bytes

typedef struct sigbin_section_v1
{
	char sha_hash[SIGBIN_SHA256_SIZE];
} sigbin_section_v1;

/*
typedef struct sigbin_section_v2
{
    char sha_hash[_HASH_SIZE];  //sha hash summ of all sections
	char aes_key[_AES_KEY_SIZE];  //aes key to encrypt data
} sigbin_section_v2;

#ifdef NO_SUPPORT_V3
typedef struct sigbin_section_v3
{
	unsigned char signature_buffer[_RSA_KEY_SIZE];//place where to hold rsa signature based on rsa_pkcs1_sign, this is rsa encrypted data
} sigbin_section_v3;
#endif
*/

typedef struct sigbin_section
{
	uint32_t version;
	uint32_t file_size;
	//uint8_t sha_hash[_HASH_SIZE];
	sigbin_section_v1 v1;
	//sigbin_section_v2 v2;
#ifdef NO_SUPPORT_V3
	//sigbin_section_v3 v3;
#endif
} sigbin_section;


#ifdef HASH_KERNEL
#else
	//init section structure
	sigbin_section* section_init();

	//add hash value
	int section_set_hash( sigbin_section *, const char* );

	//add aes key to section
	int section_set_key( sigbin_section*, const char* );

	//add format version
	int section_set_ver( sigbin_section*, uint16_t );

	//if sigbin version is 3 then add rsa crypted signature
	int section_set_rsa_signature( sigbin_section*, unsigned const char*);

	//set section size 
	uint32_t section_set_file_size( sigbin_section*, uint32_t );

	//get format version
	uint16_t section_get_ver( sigbin_section* );

	//section encrypt
	char* section_encrypt( sigbin_section* );

	//destroy object
	void section_destroy( sigbin_section* );

	//return size of section needed to reserve
	size_t section_size( sigbin_section* );

	void section_print( sigbin_section* );

	void section_print_test( sigbin_section* );

#endif

#endif


#endif
