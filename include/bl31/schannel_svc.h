#ifndef __YMH_SCHANNEL_SVC_H__
#define __YMH_SCHANNEL_SVC_H__

#include "kern_unistd.h"
#include "schannel.h"

#define SCHANNEL_CMD_SVC_START 		(SCHANNEL_CMD_DEBUG_START + 1)
#define SCHANNEL_CMD_SVC_HONG		(SCHANNEL_CMD_SVC_START + __NR_hong)
#define SCHANNEL_CMD_SVC_GETPID		(SCHANNEL_CMD_SVC_START + __NR_getpid)
#define SCHANNEL_CMD_SVC_GETPPID	(SCHANNEL_CMD_SVC_START + __NR_getppid)
#define SCHANNEL_CMD_SVC_MMAP		(SCHANNEL_CMD_SVC_START + __NR_mmap)
//#define SCHANNEL_CMD_SVC_XXX		(SCHANNEL_CMD_SVC_START + __NR_XXX) // add more syscall routines
#define SCHANNEL_CMD_SVC_END		(SCHANNEL_CMD_SVC_START + __NR_syscalls - 1)
#endif