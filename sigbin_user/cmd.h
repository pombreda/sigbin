#ifndef __SIGBIN_CMD_H
#define __SIGBIN_CMD_H

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include "debug.h"

#define FALSE 0
#define TRUE 1

//daemon option structure
typedef struct cmd_arg_options
{
	char *in_file;
	char *out_file;
    char *akey_file;
    char *rkey_file;
	int rsa_key;
	int aes_key;
	int rsa_bits;
	int aes_bits;
	int help;
} cmd_arg_options;


static cmd_arg_options cmd_arg;


static const char *cmd_arg_short = "hi:o:l:b:";
static struct option cmd_arg_long[] = 
{
	{ "help",			no_argument,		0,	'h' },
	{ "input",			required_argument,	0,	'i' },
	{ "output",			required_argument,	0,	'o' },
	{ "rkey",			required_argument,  0,  'l' },
	{ "rsabits",		required_argument,  0,  'b' },
	{ 0, 0, 0, 0 }
};

//----------------------------------------------------------------------
//Interface
void	cmd_arg_init( int , char ** );
int		cmd_arg_help();
int		cmd_arg_rsa_key();
int		cmd_arg_rsa_bits();
void*	cmd_arg_input();
void*	cmd_arg_output();
void*	cmd_arg_rsa_key_file();
void	cmd_arg_destroy();
int		cmd_arg_file_sanity();


#endif
