#ifndef __YMH_SCHANNEL_H__
#define __YMH_SCHANNEL_H__

#include "kern_unistd.h"

#define SCHANNEL_RETURN_OK		0x1357

#define SCHANNEL_CMD_SHIFT		12
#ifdef YMH_QEMU
#define SCHANNEL_CMD_BASE 		0x0e100
#else
// #define SCHANNEL_CMD_BASE 		0x3f000
#if defined(__ASSEMBLY__)
#define SCHANNEL_CMD_BASE 		0xF4000
#else
#define SCHANNEL_CMD_BASE 		0xF4000UL
#endif
#endif

// DO NOT CHANGE THE START (_ENTRY) AND END (_DEBUG_START)
#define SCHANNEL_CMD_ENTRY 				(SCHANNEL_CMD_BASE + 0)
#define SCHANNEL_CMD_EXIT 				(SCHANNEL_CMD_BASE + 1)
#define SCHANNEL_CMD_READ 				(SCHANNEL_CMD_BASE + 2)
#define SCHANNEL_CMD_SAVE 				(SCHANNEL_CMD_BASE + 3)
#define SCHANNEL_CMD_SAVE_CLEAN_V 		(SCHANNEL_CMD_BASE + 4)
#define SCHANNEL_CMD_READ_V 			(SCHANNEL_CMD_BASE + 5)
#define SCHANNEL_CMD_SAVE_M 			(SCHANNEL_CMD_BASE + 6)
#define SCHANNEL_CMD_READ_M 			(SCHANNEL_CMD_BASE + 7)
#define SCHANNEL_CMD_CFGCHECK 			(SCHANNEL_CMD_BASE + 8)	// deprecated
#define SCHANNEL_CMD_TELL				(SCHANNEL_CMD_BASE + 9)
#define SCHANNEL_CMD_DEBUG_START		(SCHANNEL_CMD_BASE + 10)

// don't use '+'
/*#define SCHANNEL_CMD_BASE_PADDR 		0x3F000000
#define SCHANNEL_CMD_ENTRY_PADDR 		0x3F000000
#define SCHANNEL_CMD_EXIT_PADDR 		0x3F000001*/

#endif