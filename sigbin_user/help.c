#include "help.h"


void help_print()
{
	printf("\
Usage: sigbin [options] \n\
Options: \n\
-i, --input \n\
    input file\n\
-o  --output \n\
    outout file\n\
-l  --rkey\n\
    rsa key file for encryption\n\
-b --rsabits\n\
    number of rsa bits\n\
-h --help\n\
    this MEGA man help\n\
");
}

