#ifndef __SIGBIN_ELF_OP_H
#define __SIGBIN_ELF_OP_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <elf.h>

#include "sigbin.h"
#include "debug.h"
#include "section.h"
#include "elf_op.h"
#include "hash.h"

///////////////////////////////////////////////////////////////////////////////
//if all checks is passed
#define VALID_OK			0
//architectute of e_machine non arm
#define VALID_NONARM		(VALID_OK+1)
//non 32bit object EI_CLASS
#define VALID_NON32BIT		(VALID_NONARM+1)
//executable not ET_EXEC
#define VALID_NONEXE		(VALID_NON32BIT+1)
//if it is *.so shared object 
#define VALID_SO			(VALID_NONEXE+1)
//if magic number is not valid
#define VALID_NOMAGIC		(VALID_SO+1)
//section number not null it means it doesnt sstriped
#define VALID_NOTSSTRIPED	(VALID_NOMAGIC+1)


//default return value of function
#define VALID_NONE			(VALID_NOTSSTRIPED+1)

#define ELF_ENCRYPT_OK		(0)
#define ELF_ENCRYPT_ERR 	(-1)
#define ELF_ENCRYPT_SO		(-2)

Elf32_Shdr*		elf_find_section( FILE*, const char* );
Elf32_Addr 		elf_find_entry( FILE* );
Elf32_Phdr*		elf_find_program( FILE*, Elf32_Half, Elf32_Addr );
int32_t			elf_valid_header( FILE* );
unsigned char*	elf_hash( FILE*, int32_t );
int				elf_section_update( FILE*, unsigned char* );
int				elf_magic( FILE* );

#endif
