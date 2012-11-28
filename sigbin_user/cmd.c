#include "cmd.h"

///////////////////////////////////////////////////////////////////////////////
void	cmd_arg_init( int argc, char **argv)
{
	int index,opt;
	
	//init structure as ALL FALSE
	cmd_arg.in_file = NULL;
	cmd_arg.out_file = NULL;
	cmd_arg.rkey_file = NULL;
	cmd_arg.rsa_key = FALSE;
	cmd_arg.rsa_bits = -1;
	cmd_arg.help = FALSE;

	//parse options
	while ((opt = getopt_long(argc, argv, cmd_arg_short, cmd_arg_long, &index)) != -1)
	//while ((opt = getopt(argc, argv, cmd_arg_short)) != -1)
	{
		if ( opt == -1 ) break;
		switch ( opt )
		{
			//case '?':
			case 'h':
				cmd_arg.help = TRUE;
				//exit(EXIT_SUCCESS);
				break;
			case 'i':
				cmd_arg.in_file = optarg;
				//printf("-I %s\n", cmd_arg.in_file);
				break;
			case 'o':
				cmd_arg.out_file = optarg;
				//printf("-O \n");
				break;
			case 'l':
				cmd_arg.rkey_file = optarg;
				break;
			case 'b':
				cmd_arg.rsa_bits = atoi( optarg );
				break;
			default:
				exit(EXIT_FAILURE);
		}
	}
}


///////////////////////////////////////////////////////////////////////////////
int cmd_arg_help()
{
	return cmd_arg.help;
}

///////////////////////////////////////////////////////////////////////////////
int cmd_arg_rsa_key()
{
	return cmd_arg.rsa_key;
}

///////////////////////////////////////////////////////////////////////////////
int cmd_arg_rsa_bits()
{
	return cmd_arg.rsa_bits;
}

//////////////////////////////////////////////////////////////////////////////
void*		cmd_arg_input()
{
	return cmd_arg.in_file;
}

///////////////////////////////////////////////////////////////////////////////
void*	cmd_arg_output()
{
	return cmd_arg.out_file;
}

void *cmd_arg_rsa_key_file()
{
	return cmd_arg.rkey_file;
}

///////////////////////////////////////////////////////////////////////////////
void	cmd_arg_destroy()
{
}

///////////////////////////////////////////////////////////////////////////////
int		cmd_arg_file_sanity()
{
	int ret = 0;

	if ( cmd_arg.in_file == NULL )
	{
		PRINT("No input filename\n");
		ret = -1;
	}

	if ( cmd_arg.out_file == NULL )
	{
		PRINT("No output filename\n");
		ret = -1;
	}


	//mark error if file name is the same
	if (ret == 0)
	{
		if ( strlen( cmd_arg.in_file ) == strlen( cmd_arg.out_file ) != 0)
		{
			if ( strncmp( cmd_arg.in_file, cmd_arg.out_file, strlen( cmd_arg.out_file )  ) == 0 )
			{
				PRINT("Input filename == Output filename \n");
				ret = -1;
			}
		}
	}

	if ( cmd_arg.rkey_file == NULL )
	{
		PRINT("No RSA key file\n");
		ret = -1;
	}

	if ( cmd_arg.rsa_bits <= 0)
	{
		PRINT("Set rsa bits\n");
		ret = -1;
	}

	//everything ok in default
	return ret;
}



