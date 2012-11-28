#include "elf_op.h"


///////////////////////////////////////////////////////////////////////////////
Elf32_Shdr *elf_find_section( FILE *f, const char *name )
{
	Elf32_Ehdr eh;
	Elf32_Shdr *esh=NULL,*str_sec=NULL;
	
	long int f_pos;
	char *read_buf=NULL;
	int ret;
	int i;
	
	if ( f != NULL )
	{
		if ( (name != NULL) && (strncmp(name,".text",5) == 0))
		{
			fseek( f, 0, SEEK_SET );
			ret = fread( &eh, sizeof(Elf32_Ehdr), 1, f );
			if ( ret != 1 ) return NULL;
			//support only for data section
			if ( eh.e_shnum == 0 )
			{
				return NULL;
			}
			//get strsection data
			f_pos = eh.e_shoff;
			//printf("%x %x\n", f_pos, eh.e_shstrndx);
			f_pos = f_pos + (sizeof(Elf32_Shdr)*(eh.e_shstrndx));
			//printf("%x\n", f_pos);
			str_sec = malloc( sizeof(Elf32_Shdr) );
			if ( str_sec == NULL )
			{
				return NULL;
			}
			memset( str_sec, 0, eh.e_shentsize );
			fseek( f, f_pos, SEEK_SET );
			fread( str_sec, sizeof(Elf32_Shdr), 1, f );
			//printf("Off %08x\n", str_sec->sh_offset);
			
			read_buf = malloc( str_sec->sh_size );
			fseek( f , str_sec->sh_offset, SEEK_SET );
			ret = fread( read_buf, str_sec->sh_size, 1, f );
			if ( ret != 1 )
			{
				PRINT("Cannot read string table\n");
				return NULL;
			}
			
			//find in sections needed section
			esh = malloc( sizeof(Elf32_Shdr) );
			for ( i=0; i<eh.e_shnum; i++ )
			{
				fseek( f , eh.e_shoff+(i*eh.e_shentsize), SEEK_SET );
				ret = fread( esh, sizeof(Elf32_Shdr), 1, f );
				if ( ret != 1 )
				{
					free( read_buf );
					free( str_sec );
					free( esh );
					return NULL;
				}
				//printf("name=%s\n",name);
				//printf("%s\n", read_buf+esh->sh_name);
				if ( strncmp( name, &read_buf[0]+esh->sh_name, strlen(name) ) == 0 )
				{
					free( read_buf );
					free( str_sec );
					return esh;
				}
			}
			
			free( read_buf );
			free( str_sec );
		} else
		{
			PRINT("Unsupported section name\n");
		}
	}
	return NULL;
}


///////////////////////////////////////////////////////////////////////////////
Elf32_Addr elf_find_entry( FILE *f )
{
	int ret;
	Elf32_Ehdr *eh;
	if ( f != NULL )
	{
		eh = malloc( sizeof(Elf32_Ehdr) );
		if ( eh == NULL )
		{
			PRINT("Cannot allocate memory\n");
			return 0;
		}
		fseek( f, 0, SEEK_SET );
		ret = fread( eh, sizeof(Elf32_Ehdr), 1, f );
		if (ret != 1)
		{
			PRINT("Cannot read elf header\n");
			free( eh );
			return 0;
		}
		if ( eh->e_ehsize != sizeof(Elf32_Ehdr) )
		{
			PRINT("Elf header size and sizeof elfheader not equile\n ");
			return 0;
		}
		ret = eh->e_entry;
		free( eh );
		return ret;
	}
	return 0;
}


///////////////////////////////////////////////////////////////////////////////
Elf32_Phdr *elf_find_program( FILE *f, Elf32_Half type, Elf32_Addr vaddr )
{
	Elf32_Ehdr *eh;
	Elf32_Phdr *ph;
	int i;
	
	if ( f != NULL )
	{
		eh = malloc( sizeof(Elf32_Ehdr) );
		if ( eh == NULL )
		{
			PRINT("Cannot allocate elf header memory\n");
			return 0;
		}
		fseek( f, 0, SEEK_SET );
		fread( eh, sizeof(Elf32_Ehdr), 1, f );
		ph = malloc( sizeof(Elf32_Phdr) );
		if (ph == NULL)
		{
			PRINT("Cannot allocate program header memory\n");
			return 0;
		}
		for (i=0; i<eh->e_phnum; i++)
		{
			fseek( f, eh->e_phoff+i*sizeof(Elf32_Phdr), SEEK_SET );
			fread( ph, sizeof(Elf32_Phdr), 1, f );
			if ( ph->p_type == PT_LOAD )
			{
				if ( (vaddr >= ph->p_vaddr) && (vaddr <= (ph->p_vaddr+ph->p_memsz)))
				{
					free( eh );
					return ph;
				}
			}
		}
		free( eh );
		free( ph );
	}
	return NULL;
}



///////////////////////////////////////////////////////////////////////////////
int32_t elf_valid_header( FILE *f )
{
	Elf32_Ehdr *eh;
	if ( f != NULL )
	{
		eh = malloc( sizeof( Elf32_Ehdr ) );
		fseek( f, 0, SEEK_SET );
		fread( eh, sizeof( Elf32_Ehdr ), 1, f );

		if ( eh != NULL )
		{
			//if ELF magic number is valid
			if ((eh->e_ident[EI_MAG0] != ELFMAG0) && 
				(eh->e_ident[EI_MAG1] != ELFMAG1) && 
				(eh->e_ident[EI_MAG2] != ELFMAG2) && 
				(eh->e_ident[EI_MAG3] != ELFMAG3))
			{
				PRINT("Invalid magick header\n");
				free( eh );
				return VALID_NOMAGIC;
			}

			//check if it is arm architecture
			//if ( eh->e_machine != EM_ARM )
			/*
			if ( (eh->e_machine != EM_ARN) || () )
			{


			//check if it is exe file
			/*
			if ( eh->e_type != ET_EXEC )
			{
				PRINT("e_type = %08x %08x\n", eh->e_type, ET_DYN);
				if ( eh->e_type == ET_DYN )
				{
					return VALID_SO;
				}
				return VALID_NONEXE;
			}
			*/

			//check if its 32bit class file
			if ( eh->e_ident[EI_CLASS] != ELFCLASS32  )
			{
				PRINT("Not 32bit ELF \n");
				free( eh );
				return VALID_NON32BIT;
			}

			//check how many section number there is
			if ( eh->e_shnum != 0 )
			{
				PRINT("Header not stripped\n");
				free( eh );
				return VALID_NOTSSTRIPED;
			}

			free( eh );
			return VALID_OK;
		}
		free( eh );
	}
	return VALID_NONE;
}


///////////////////////////////////////////////////////////////////////////////
//use if section number to elf header is added
unsigned char* elf_hash( FILE *f, int32_t file_old_len )
{
	int32_t file_size;
	unsigned char *buf=NULL;
	unsigned char *hash=NULL;
	hash_context *hash_ctx=NULL;

	if ( f != NULL )
	{
		
		file_size	= file_old_len;
		PRINT("File size = %x=>%d\n", file_size, file_size );
		buf 		= malloc( file_size );
		if ( buf == NULL )
		{
			PRINT("Cannot allocate memory for file mem buf\n");
			return NULL;
		}
		fseek( f, 0, SEEK_SET );
		if ( fread( buf, file_size, 1, f ) != 1 )
		{
			PRINT("Cannot read file for hash\n");
			return NULL;
		}
		
		{
			int i;
			char *p;
			unsigned char u8;
			PRINT("\n");	
			for (i=0; i < file_size;i++)
			{
				p = (char *)buf;
				u8 = p[i];
				printf("%02x ", (unsigned char)u8);
				if ((i % 16) == 15) printf("\n");
			}
			printf("\n");
		}
		
		hash = malloc( 32 );
		sha2( buf, file_size, hash, 0 );
		
		hash_ctx = hash_start();
		hash_update( hash_ctx, buf, file_size );
		hash_finish( hash_ctx );
		hash_print(  hash_ctx );
		hash_destroy( hash_ctx );
		
		free( buf );
		return hash;
	}
	return NULL;
}


///////////////////////////////////////////////////////////////////////////////
//adding zeroed section
//make hash after this function
/*
int elf_section_add( FILE *f, sigbin_section *ss )
{
	size_t file_size;
	Elf32_Ehdr *eh;
	Elf32_Shdr *sh;
	int i;
	unsigned char *enc_buf=NULL;
	unsigned char *empty_buf=NULL;

	if ( (f != NULL) && (ss != NULL) )
	{
		if ( elf_valid_header( f ) == VALID_OK )
		{
			file_size = get_file_size( f );

			eh = malloc( sizeof(Elf32_Ehdr) );
			sh = malloc( sizeof(Elf32_Shdr) );
			
			fseek( f, 0, SEEK_SET );
			fread( eh, sizeof(Elf32_Ehdr), 1, f );
			
			eh->e_shentsize = sizeof(Elf32_Shdr);
			eh->e_shnum = 1;
			eh->e_shoff = file_size;

			sh->sh_name 		= 0xb;
			sh->sh_type 		= SHT_SIGBIN;
			sh->sh_flags 		= 0x0;
			sh->sh_addr 		= 0x0;
			sh->sh_offset 		= file_size + sizeof(Elf32_Shdr);
			sh->sh_size 		= section_size( ss );
			sh->sh_link 		= SHN_UNDEF;
			sh->sh_info 		= 0x0;
			sh->sh_addralign 	= 0x1;
			sh->sh_entsize 		= 0x0;
		
			empty_buf = malloc( section_size( ss ) );
			memset( empty_buf, 0xab, section_size(ss) );

			fseek( f, 0, SEEK_SET );
			fwrite( eh, sizeof(Elf32_Ehdr), 1, f);

			fseek( f, eh->e_shoff, SEEK_SET );
			fwrite( sh, sizeof(Elf32_Shdr), 1, f);
			
			fseek( f, sh->sh_offset, SEEK_SET );
			fwrite( empty_buf, section_size( ss ), 1, f);
		
			
			free( empty_buf );
			free( eh );
			free( sh );
			return 0;
		}
		PRINT("Not valid ELF header\n");
	}
	PRINT("NULL param\n");
	return -1;
}
*/

//section should be added o ELF file before and
//now section should be encrypted sigbin now is brutaly crypted
int elf_section_update( FILE *f, unsigned char *sigbin )
{
	Elf32_Ehdr *eh=NULL;
	Elf32_Shdr *sh=NULL;
	if ( (f != NULL) && (sigbin != NULL) )
	{
		eh = malloc( sizeof(Elf32_Ehdr) );
		sh = malloc( sizeof(Elf32_Shdr) );

		fseek( f, 0, SEEK_SET );
		fread( eh, sizeof(Elf32_Ehdr), 1, f );

		//there should be one and only section
		fseek( f, eh->e_shoff, SEEK_SET );
		fread( sh, sizeof(Elf32_Shdr), 1, f );

		//go to section position
		fseek( f, sh->sh_offset	, SEEK_SET );
		fwrite( sigbin, sh->sh_size, 1, f );

		free( eh );
		free( sh );
		return 0;
	}
	PRINT("Cannot update SIGBIN section\n");
	return -1;
}


/*
//encrypt only code part
int	elf_encrypt_code( FILE *f, struct crypt_context *crypt )
{
	Elf32_Ehdr *eh=NULL;
	Elf32_Phdr *ph=NULL,*ph_code=NULL, *ph_data=NULL; //there should be two of them
	Elf32_Addr entry;
	char *encr_buf=NULL;
	int i;
	int tmp_len=0;

	
	if ( (f != NULL) && (crypt != NULL ))
	{
		PRINT("\n");
		eh = malloc( sizeof(Elf32_Ehdr) );
		PRINT("\n");
		ph_code = malloc( sizeof(Elf32_Phdr) );
		//ph_data = malloc( sizeof(Elf32_Phdr) );
		ph = malloc( sizeof(Elf32_Phdr) );
		
		PRINT("\n");
		fseek( f, 0, SEEK_SET );
		fread( eh, sizeof(Elf32_Ehdr), 1, f );
		
		//check if given file is SO if yes then dont encrypt it
		if ( eh->e_type == ET_DYN )
		{
			PRINT("This file is SO and nothing will encrypted\n");
			free( eh );
			free( ph );
			return ELF_ENCRYPT_SO;
		}

		/*
		//find 2 pt_load program headers
		for (i=0; i < eh->e_phnum; i++)
		{
			fseek( f, eh->e_phoff+i*sizeof(Elf32_Phdr), SEEK_SET );
			fread( ph, sizeof(Elf32_Phdr), 1, f );
			//PRINT("%d %x\n", i, ph->p_offset);
			if ( ph->p_type == PT_LOAD )
			{
				if ( ph_code == NULL )
				{
					ph_code = malloc( sizeof(Elf32_Phdr) );
					memcpy( ph_code, ph, sizeof(Elf32_Phdr) );
					PRINT("code segment = 0x%08x-0x%08x size=%x(%d)\n", ph->p_offset, ph_code->p_offset+ph_code->p_filesz, ph_code->p_offset+ph_code->p_filesz-ph->p_offset, ph_code->p_offset+ph_code->p_filesz-ph->p_offset );
					continue;
				} else if ( ph_data == NULL )
				{
					ph_data = malloc( sizeof(Elf32_Phdr) );
					memcpy( ph_data, ph, sizeof(Elf32_Phdr) );
					PRINT("data segment = 0x%08x-0x%08x size=%x(%d)\n", ph_data->p_offset, ph_data->p_offset+ph_data->p_filesz, ph_data->p_offset+ph_data->p_filesz-ph_data->p_offset, ph_data->p_offset+ph_data->p_filesz-ph_data->p_offset );
					continue;
				} else
				{
					PRINT("Too many PT_LOAD program headers\n");
					return ELF_ENCRYPT_ERR;
				}
			}
			
		}
		//load only first PT_LOAD header
		for ( i=0; i < eh->e_phnum; i++ )
		{
			fseek( f, eh->e_phoff+i*sizeof(Elf32_Phdr), SEEK_SET );
			fread( ph, sizeof(Elf32_Phdr), 1, f );
			if ( ph->p_type == PT_LOAD )
			{
				memcpy( ph_code, ph, sizeof(Elf32_Phdr) );
				break;
			}
		}
		
		
		PRINT("\n");

		//encrypt code sections
		//if ( (ph_code->p_filesz == ph_data->p_offset) )
		//{
			entry = elf_find_entry( f );
			PRINT("\n");
			//uint32_t tmp_len = ph_data->p_offset + ph_data->p_filesz -(entry-ph_code->p_vaddr);
			//PRINT("0x%x\n", ph_code->p_memsz);
			//PRINT("0x%x\n", entry-ph_code->p_vaddr);
			tmp_len = ph_code->p_memsz - (entry - ph_code->p_vaddr);
			PRINT("\n");
			//PRINT("entry=%x\n", entry);
			//PRINT("%08x\n", tmp_len);
			encr_buf = malloc( tmp_len );
			if ( encr_buf == NULL )
			{
				PRINT("\n");
			}
			//PRINT("\n");
			//calc offset file not mem addr
			PRINT("entry in file = %x\n", entry - ph_code->p_vaddr );
			PRINT("tmp_len = %x\n", tmp_len ); 
			fseek( f,  entry-ph_code->p_vaddr, SEEK_SET  );
			PRINT("encrypt start = %x(%d)\n", entry-ph_code->p_vaddr, entry-ph_code->p_vaddr);
			fread( encr_buf, tmp_len, 1, f );
			crypt_encrypt( crypt, encr_buf, tmp_len );
			PRINT("encrypted code_size = %x(%d)\n", tmp_len, tmp_len);
			
			//goto offset of entry point in file
			fseek( f, entry - ph_code->p_vaddr, SEEK_SET );
			fwrite( encr_buf, tmp_len, 1, f );
			
			free( encr_buf );
			free( ph_code );
			free( ph_data );
			free( eh );
			free( ph );
			return ELF_ENCRYPT_OK;
		/*
		} else
		{
			PRINT("Strange ELF header, code should go before data\n");
			return -1;
		}
		
	}
	
	return ELF_ENCRYPT_ERR;
}
*/


int elf_magic( FILE *f )
{
	Elf32_Ehdr *eh=NULL;
	char magic[]="ESAF";
	
	if ( f != NULL )
	{
		eh = malloc( sizeof(Elf32_Ehdr) );
		fseek( f, 0, SEEK_SET );
		fread( eh, sizeof(Elf32_Ehdr), 1, f );
		
		//add new header only for EXEC files not for SO libs
		if ( eh->e_type == ET_EXEC )
		{
			fseek( f, 0, SEEK_SET );
			fwrite( magic, 4, 1, f );
		}
		free( eh );
	}
	
	return 0;
}

