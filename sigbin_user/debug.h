#ifndef __SIGBIN_DEBUG_H
#define __SIGBIN_DEBUG_H

#define PRINT( format, args ...) printf( "DEBUG: %15s:%3d = " format, __FILE__,__LINE__, ##args)

#endif
