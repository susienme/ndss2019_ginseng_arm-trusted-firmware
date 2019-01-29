#ifndef __GINSENG_SCHANNEL_CMD_H
#define __GINSENG_SCHANNEL_CMD_H

// #define HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_ASYNCEXCEPTION	0xff03

// DON'T MODIFY THE TWO COMMENT LINES: 'MAGIC_START' AND 'MAGIC_END'
// DON'T USE SURFIX THAT RUST CANNOT UNDERSTAND SUCH AS 'UL'

// from HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SENTRY, those magics must be identical with schannel.h

// MAGIC_START
#define HANDLE_SCHANNEL_RETURN_NOT_MY_CONCERN				0xF4FFF
#define HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_EXCEPTION		0xF4FFE
#define HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_HCR				0xF4FFD
#define HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SENTRY			0xF4000
#define HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SEXIT			0xF4001

#define HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_READ			0xF4002
#define HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SS_DATA_START	HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_READ
#define HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SAVE			0xF4003
#define HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SAVE_CLEAN_V	0xF4004
#define HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_READ_V			0xF4005
#define HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SAVE_M			0xF4006
#define HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_READ_M			0xF4007
#define HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_TELL			0xF4009
#define HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SS_DATA_END		HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_TELL
// MAGIC_END
/* 'HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SS_DATA_END' must be same as the last CMD*/

// #define HANDLE_SCHANNEL_RETURN_HANDLED						0xff01
#endif