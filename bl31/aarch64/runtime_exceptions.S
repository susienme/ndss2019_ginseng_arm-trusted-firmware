/*
 * Copyright (c) 2013-2016, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <arch.h>
#include <asm_macros.S>
#include <context.h>
#include <cpu_data.h>
#include <interrupt_mgmt.h>
#include <platform_def.h>
#include <runtime_svc.h>
//////////////////////////// YMH_START
//
#include <schannel_svc.h>	// TODO: REMOVE this... BUT include schannel.h
#include <ginseng_schannel_cmd.h>	// HANDLE_SCHANNEL_RETURN_XXX
#include <ginseng_smc_cmd.h>		// 
#define HONG_SPSR_IRQ 	0x80000005
#define HONG_SPSR_SYNC 	0x3C5 //0x60000145

// #define YMH_DEBUG_MODE

.section .rodata.bl3_msgs, "aS"
str_unknown:
	.asciz " ASM: CMD_UNKNOWN\n"
//
//////////////////////////// YMH_END
	.globl	runtime_exceptions


	//////////////////////////// YMH_START
	//
	// clobber: x0
	.macro disalbeAFault
	mrs x0, sctlr_el3
	bic x0, x0, #2
	msr sctlr_el3, x0
	isb sy
	.endm
	
	// clobber: x0
	.macro enableAFault
	mrs x0, sctlr_el3
	orr x0, x0, #2
	msr sctlr_el3, x0
	.endm
	//
	//////////////////////////// YMH_END

	/* ---------------------------------------------------------------------
	 * This macro handles Synchronous exceptions.
	 * Only SMC exceptions are supported.
	 * ---------------------------------------------------------------------
	 */
	.macro	handle_sync_exception
	/* Enable the SError interrupt */
	msr	daifclr, #DAIF_ABT_BIT

	//////////////////////////// YMH_MODIFIED: store x29 & x30
	// str	x30, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_LR]
	stp	x29, x30, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X29]

#if ENABLE_RUNTIME_INSTRUMENTATION
	/*
	 * Read the timestamp value and store it in per-cpu data. The value
	 * will be extracted from per-cpu data by the C level SMC handler and
	 * saved to the PMF timestamp region.
	 */
	mrs	x30, cntpct_el0
	str	x29, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X29]
	mrs	x29, tpidr_el3
	str	x30, [x29, #CPU_DATA_PMF_TS0_OFFSET]
	ldr	x29, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X29]
#endif

	//////////////////////////// YMH_START
	//
	bl handleSChannel // this will do ERET when handled
	ldr x29, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X29]	// restore x29 before doing more work. x30 will be overwritten, thus don't care.
	//
	//////////////////////////// YMH_END

	mrs	x30, esr_el3
	ubfx	x30, x30, #ESR_EC_SHIFT, #ESR_EC_LENGTH

	/* Handle SMC exceptions separately from other synchronous exceptions */
	cmp	x30, #EC_AARCH32_SMC
	b.eq	smc_handler32

	cmp	x30, #EC_AARCH64_SMC
	b.eq	smc_handler64

	/* Other kinds of synchronous exceptions are not handled */
	ldr	x30, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_LR]
	b	report_unhandled_exception
	.endm


	/* ---------------------------------------------------------------------
	 * This macro handles FIQ or IRQ interrupts i.e. EL3, S-EL1 and NS
	 * interrupts.
	 * ---------------------------------------------------------------------
	 */
	.macro	handle_interrupt_exception label
	/* Enable the SError interrupt */
	msr	daifclr, #DAIF_ABT_BIT

	str	x30, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_LR]
	bl	save_gp_registers

	/* Save the EL3 system registers needed to return from this exception */
	mrs	x0, spsr_el3
	mrs	x1, elr_el3
	stp	x0, x1, [sp, #CTX_EL3STATE_OFFSET + CTX_SPSR_EL3]

	/* Switch to the runtime stack i.e. SP_EL0 */
	ldr	x2, [sp, #CTX_EL3STATE_OFFSET + CTX_RUNTIME_SP]
	mov	x20, sp
	msr	spsel, #0
	mov	sp, x2

	/*
	 * Find out whether this is a valid interrupt type.
	 * If the interrupt controller reports a spurious interrupt then return
	 * to where we came from.
	 */
	bl	plat_ic_get_pending_interrupt_type
	cmp	x0, #INTR_TYPE_INVAL
	b.eq	interrupt_exit_\label

	/*
	 * Get the registered handler for this interrupt type.
	 * A NULL return value could be 'cause of the following conditions:
	 *
	 * a. An interrupt of a type was routed correctly but a handler for its
	 *    type was not registered.
	 *
	 * b. An interrupt of a type was not routed correctly so a handler for
	 *    its type was not registered.
	 *
	 * c. An interrupt of a type was routed correctly to EL3, but was
	 *    deasserted before its pending state could be read. Another
	 *    interrupt of a different type pended at the same time and its
	 *    type was reported as pending instead. However, a handler for this
	 *    type was not registered.
	 *
	 * a. and b. can only happen due to a programming error. The
	 * occurrence of c. could be beyond the control of Trusted Firmware.
	 * It makes sense to return from this exception instead of reporting an
	 * error.
	 */
	bl	get_interrupt_type_handler
	cbz	x0, interrupt_exit_\label
	mov	x21, x0

	mov	x0, #INTR_ID_UNAVAILABLE

	/* Set the current security state in the 'flags' parameter */
	mrs	x2, scr_el3
	ubfx	x1, x2, #0, #1

	/* Restore the reference to the 'handle' i.e. SP_EL3 */
	mov	x2, x20

	/* x3 will point to a cookie (not used now) */
	mov	x3, xzr

	/* Call the interrupt type handler */
	blr	x21

interrupt_exit_\label:
	/* Return from exception, possibly in a different security state */
	b	el3_exit

	.endm


	.macro save_x18_to_x29_sp_el0
	stp	x18, x19, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X18]
	stp	x20, x21, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X20]
	stp	x22, x23, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X22]
	stp	x24, x25, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X24]
	stp	x26, x27, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X26]
	stp	x28, x29, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X28]
	mrs	x18, sp_el0
	str	x18, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_SP_EL0]
	.endm


vector_base runtime_exceptions

	/* ---------------------------------------------------------------------
	 * Current EL with SP_EL0 : 0x0 - 0x200
	 * ---------------------------------------------------------------------
	 */
vector_entry sync_exception_sp_el0
	/* We don't expect any synchronous exceptions from EL3 */
	b	report_unhandled_exception
	check_vector_size sync_exception_sp_el0

vector_entry irq_sp_el0
	/*
	 * EL3 code is non-reentrant. Any asynchronous exception is a serious
	 * error. Loop infinitely.
	 */
	b	report_unhandled_interrupt
	check_vector_size irq_sp_el0


vector_entry fiq_sp_el0
	b	report_unhandled_interrupt
	check_vector_size fiq_sp_el0


vector_entry serror_sp_el0
	b	report_unhandled_exception
	check_vector_size serror_sp_el0

	/* ---------------------------------------------------------------------
	 * Current EL with SP_ELx: 0x200 - 0x400
	 * ---------------------------------------------------------------------
	 */
vector_entry sync_exception_sp_elx
	/*
	 * This exception will trigger if anything went wrong during a previous
	 * exception entry or exit or while handling an earlier unexpected
	 * synchronous exception. There is a high probability that SP_EL3 is
	 * corrupted.
	 */
	b	report_unhandled_exception
	check_vector_size sync_exception_sp_elx

vector_entry irq_sp_elx
	b	report_unhandled_interrupt
	check_vector_size irq_sp_elx

vector_entry fiq_sp_elx
	b	report_unhandled_interrupt
	check_vector_size fiq_sp_elx

vector_entry serror_sp_elx
	b	report_unhandled_exception
	check_vector_size serror_sp_elx

	/* ---------------------------------------------------------------------
	 * Lower EL using AArch64 : 0x400 - 0x600
	 * ---------------------------------------------------------------------
	 */
vector_entry sync_exception_aarch64
	/*
	 * This exception vector will be the entry point for SMCs and traps
	 * that are unhandled at lower ELs most commonly. SP_EL3 should point
	 * to a valid cpu context where the general purpose and system register
	 * state can be saved.
	 */
	handle_sync_exception
	check_vector_size sync_exception_aarch64

vector_entry irq_aarch64
	handle_interrupt_exception irq_aarch64
	check_vector_size irq_aarch64

vector_entry fiq_aarch64
	handle_interrupt_exception fiq_aarch64
	check_vector_size fiq_aarch64

vector_entry serror_aarch64
	/*
	 * SError exceptions from lower ELs are not currently supported.
	 * Report their occurrence.
	 */
	b	report_unhandled_exception
	check_vector_size serror_aarch64

	/* ---------------------------------------------------------------------
	 * Lower EL using AArch32 : 0x600 - 0x800
	 * ---------------------------------------------------------------------
	 */
vector_entry sync_exception_aarch32
	/*
	 * This exception vector will be the entry point for SMCs and traps
	 * that are unhandled at lower ELs most commonly. SP_EL3 should point
	 * to a valid cpu context where the general purpose and system register
	 * state can be saved.
	 */
	handle_sync_exception
	check_vector_size sync_exception_aarch32

vector_entry irq_aarch32
	handle_interrupt_exception irq_aarch32
	check_vector_size irq_aarch32

vector_entry fiq_aarch32
	handle_interrupt_exception fiq_aarch32
	check_vector_size fiq_aarch32

vector_entry serror_aarch32
	/*
	 * SError exceptions from lower ELs are not currently supported.
	 * Report their occurrence.
	 */
	b	report_unhandled_exception
	check_vector_size serror_aarch32


	/* ---------------------------------------------------------------------
	 * The following code handles secure monitor calls.
	 * Depending upon the execution state from where the SMC has been
	 * invoked, it frees some general purpose registers to perform the
	 * remaining tasks. They involve finding the runtime service handler
	 * that is the target of the SMC & switching to runtime stacks (SP_EL0)
	 * before calling the handler.
	 *
	 * Note that x30 has been explicitly saved and can be used here
	 * ---------------------------------------------------------------------
	 */
func smc_handler
smc_handler32:
	/* Check whether aarch32 issued an SMC64 */
	tbnz	x0, #FUNCID_CC_SHIFT, smc_prohibited

	/*
	 * Since we're are coming from aarch32, x8-x18 need to be saved as per
	 * SMC32 calling convention. If a lower EL in aarch64 is making an
	 * SMC32 call then it must have saved x8-x17 already therein.
	 */
	stp	x8, x9, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X8]
	stp	x10, x11, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X10]
	stp	x12, x13, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X12]
	stp	x14, x15, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X14]
	stp	x16, x17, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X16]

	/* x4-x7, x18, sp_el0 are saved below */

smc_handler64:
	/*
	 * Populate the parameters for the SMC handler.
	 * We already have x0-x4 in place. x5 will point to a cookie (not used
	 * now). x6 will point to the context structure (SP_EL3) and x7 will
	 * contain flags we need to pass to the handler Hence save x5-x7.
	 *
	 * Note: x4 only needs to be preserved for AArch32 callers but we do it
	 *       for AArch64 callers as well for convenience
	 */
	//////////////////////////// YMH_START
	//
	stp	x0, x1, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X0]
	stp	x2, x3, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X2]
	//
	//////////////////////////// YMH_END
	stp	x4, x5, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X4]
	stp	x6, x7, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X6]

	/* Save rest of the gpregs and sp_el0*/
	save_x18_to_x29_sp_el0

	//////////////////////////// YMH_START
	//
	// x0-x5 contain params (6)
	// x6, x7 are temp
	mrs x7, esr_el3

	lsr	x6, x7, #25	// exception class (EC) | IL
	cmp x6, #0b0101111 // 0b010111 (SMC) | 0b1 (DA)
	b.ne 99f

	ubfx x6, x7, 0, #16 // #imm16


18:	cmp x6, #10  // all exceptions from EL1
	b.eq 70f

	cmp x6, #11  // TTBR trap
	b.eq 71f

	b 99f // not (10 | 11)


70:
	ldr x7, =HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_EXCEPTION
	b 72f

71:
	ldr x7, =HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_HCR

72:
	// Now, it's time to call Rust!
	ldp	x0, x1, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X0]
	ldp	x2, x3, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X2]
	ldp	x4, x5, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X4]
	ldr	x6, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X6]
	ldr	x18, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X18]
	ldr	x30, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_LR]


	b callRS_exception

2: 	// will be rached because callRS does ERET
	b 2b

99:
	cmp x6, #18
	b.le 99f	// OLD: Not my SMC -> jump to the normal SMC


// SMC for PTP change from the kernel
88:
	mov	x6, sp
	/* -----------------------------------------------------
	 * Restore the saved C runtime stack value which will
	 * become the new SP_EL0 i.e. EL3 runtime stack. It was
	 * saved in the 'cpu_context' structure prior to the last
	 * ERET from EL3.
	 * -----------------------------------------------------
	 */
	ldr	x12, [x6, #CTX_EL3STATE_OFFSET + CTX_RUNTIME_SP]


	/* Switch to SP_EL0 */
	msr	spsel, #0

	/* -----------------------------------------------------
	 * Save the SPSR_EL3, ELR_EL3, & SCR_EL3 in case there
	 * is a world switch during SMC handling.
	 * TODO: Revisit if all system registers can be saved
	 * later.
	 * -----------------------------------------------------
	 */
	mrs	x16, spsr_el3
	mrs	x17, elr_el3
	mrs	x18, scr_el3
	stp	x16, x17, [x6, #CTX_EL3STATE_OFFSET + CTX_SPSR_EL3]
	str	x18, [x6, #CTX_EL3STATE_OFFSET + CTX_SCR_EL3]

	mov	sp, x12

	disalbeAFault		// <-- clobber: X0
	ldr x0, [x6, #CTX_GPREGS_OFFSET + CTX_GPREG_X0]


	bl rsGinseng_smc	// <-- return void
	enableAFault		// <-- clobber: X0, but don't need to restore here because el3_exit will do
	b el3_exit

99:
	cmp x6, #7 // <-- exception redirection from EL2
	b.ne 99f

	mrs x4, hcr_el2
	bic x4, x4, #0x8000000
	msr hcr_el2, x4

	// prepare EL & SPSR (EL1 -> EL0)
	mrs x4, elr_el2
	// add x4, x4, #4		<-- don't advance ELR - IRQ must be handled...
	msr elr_el1, x4
	msr spsr_el1, xzr

	// prepare EL & SPSR (EL2 -> EL1)
	mrs x4, vbar_el1
	add x4, x4, #0x480 // IRQ handler in EL1
	msr elr_el2, x4
	ldr x4, =HONG_SPSR_IRQ
	msr spsr_el2, x4

	ldp	x0, x1, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X0]
	ldp	x2, x3, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X2]
	ldp	x4, x5, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X4]
	ldp	x6, x7, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X6]
	ldr	x18, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X18]
	ldr	x30, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_LR]

	isb sy
	eret // eret to EL2 (exception redirection)

99:
	cmp x6, #8 	// <-- sync from EL2
	b.ne 99f

	// prepare EL & SPSR (EL1 -> EL0)
	mrs x4, elr_el2
	// add x4, x4, #4		<-- don't advance ELR - IRQ must be handled...
	msr elr_el1, x4
	mrs x4, spsr_el2
	msr spsr_el1, xzr

	// prepare EL & SPSR (EL2 -> EL1)
	mrs x4, vbar_el1
	add x4, x4, #0x400 // SYNC handler in  EL1
	msr elr_el2, x4
	ldr x4, =HONG_SPSR_SYNC
	msr spsr_el2, x4

	b smc_return

99:
	//
	//////////////////////////// YMH_END

	mov	x5, xzr		// YMH: x5 points to a cookie
	mov	x6, sp 		// YMH: x6 points to SP_EL3

	/* Get the unique owning entity number */
	ubfx	x16, x0, #FUNCID_OEN_SHIFT, #FUNCID_OEN_WIDTH
	ubfx	x15, x0, #FUNCID_TYPE_SHIFT, #FUNCID_TYPE_WIDTH
	orr	x16, x16, x15, lsl #FUNCID_OEN_WIDTH 		//YMH: x6 is the index

	adr	x11, (__RT_SVC_DESCS_START__ + RT_SVC_DESC_HANDLE)

	/* Load descriptor index from array of indices */
	adr	x14, rt_svc_descs_indices
	ldrb	w15, [x14, x16]

	/*
	 * Restore the saved C runtime stack value which will become the new
	 * SP_EL0 i.e. EL3 runtime stack. It was saved in the 'cpu_context'
	 * structure prior to the last ERET from EL3.
	 */
	ldr	x12, [x6, #CTX_EL3STATE_OFFSET + CTX_RUNTIME_SP]

	/*
	 * Any index greater than 127 is invalid. Check bit 7 for
	 * a valid index
	 */
	tbnz	w15, 7, smc_unknown

	/* Switch to SP_EL0 */
	msr	spsel, #0

	/*
	 * Get the descriptor using the index
	 * x11 = (base + off), x15 = index
	 *
	 * handler = (base + off) + (index << log2(size))
	 */
	lsl	w10, w15, #RT_SVC_SIZE_LOG2
	ldr	x15, [x11, w10, uxtw]

	/*
	 * Save the SPSR_EL3, ELR_EL3, & SCR_EL3 in case there is a world
	 * switch during SMC handling.
	 * TODO: Revisit if all system registers can be saved later.
	 */
	mrs	x16, spsr_el3
	mrs	x17, elr_el3
	mrs	x18, scr_el3
	stp	x16, x17, [x6, #CTX_EL3STATE_OFFSET + CTX_SPSR_EL3]
	str	x18, [x6, #CTX_EL3STATE_OFFSET + CTX_SCR_EL3]

	/* Copy SCR_EL3.NS bit to the flag to indicate caller's security */
	bfi	x7, x18, #0, #1

	mov	sp, x12

	/*
	 * Call the Secure Monitor Call handler and then drop directly into
	 * el3_exit() which will program any remaining architectural state
	 * prior to issuing the ERET to the desired lower EL.
	 */
#if DEBUG
	cbz	x15, rt_svc_fw_critical_error
#endif
	blr	x15

	b	el3_exit

smc_unknown:
	/*
	 * Here we restore x4-x18 regardless of where we came from. AArch32
	 * callers will find the registers contents unchanged, but AArch64
	 * callers will find the registers modified (with stale earlier NS
	 * content). Either way, we aren't leaking any secure information
	 * through them.
	 */
	mov	w0, #SMC_UNK
	b	restore_gp_registers_callee_eret

smc_prohibited:
	ldr	x30, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_LR]
	mov	w0, #SMC_UNK
	eret

rt_svc_fw_critical_error:
	/* Switch to SP_ELx */
	msr	spsel, #1
	no_ret	report_unhandled_exception
endfunc smc_handler

//////////////////////////// YMH_START
//
// returns only when not handled (normal SMC call)
func handleSChannel
	stp x0, x1, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X0]
	stp x2, x3, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X2]
	stp x4, x5, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X4]
	stp x6, x7, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X6]
	str x8, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X8]
	// it is find because the above regs don't have secrets

	///////////////// CLOBBER
	// x0-x5, x30: used by asm_print_hex
	// x0: temp to compare CMD
	// x7: CODE (will be used the caller too)
	// x8: keeps LR
	// DON'T USE X8(HAS LR), X7(result)
	///////////////// NOT ANY MORE -- x9: temp to compare CMD
	///////////////// NOT ANY MORE -- x10: CODE

	mov x8, x30 // keep LR at x8 (<-- will not be used for print msgs) // DON'T TOUCH X8
	ldr x7, =HANDLE_SCHANNEL_RETURN_NOT_MY_CONCERN	// return value 0: not my concern, 1: S-Channel

	// if EA & from NS --> S-Channel
	// check EA
	mrs	x30, esr_el3
	lsr	x29, x30, #25	// exception class (EC) | IL
	cmp x29, #0b1001001 // 0b100100 (DA from a lower EL) | 0b1 (DA)
	b.ne CALL_GSERVICE

	ubfx x29, x30, 0, #25 // ISS
	cmp x29, #0b1000010000	// EA[9] | DFSC[5:0] = 010000 (sync EA, not on translation table walk)
	b.ne CALL_GSERVICE

	// TODO: check from NS

	// get CODE to x7
	mrs x0, far_el3 		// VA
	at s1e0r, x0 
	mrs x7, par_el1 		// PA
	ubfx x7, x7, #12, #36 // extrace PA

	ldr x0, =SCHANNEL_CMD_ENTRY
	cmp x7, x0
	b.lt 88f

	ldr x0, =SCHANNEL_CMD_DEBUG_START
	cmp x7, x0
	b.gt 88f

	b CALL_GSERVICE


// 2:	// if we have more...
88:	adr x4, str_unknown
	bl asm_print_str
	b 88b

CALL_GSERVICE:
	ldp x0, x1, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X0]
	ldp x2, x3, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X2]
	ldp x4, x5, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X4]
	mov x30, x8
	ldr x8, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X8]

	// check the result
	// if Ginseng-related -> handle and eret
	// if normal SMC -> ret
	ldr x29, =HANDLE_SCHANNEL_RETURN_NOT_MY_CONCERN
	cmp x7, x29
	b.eq 2f

1:	// check S-Entry
	ldr x29, =HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SENTRY
	cmp x7, x29
	b.ne 1f

	// call S-Entry and eret
	mov x1, 0x6789	// arg for sStoragePaddr; we don't implement but measure latency by changing code size

	b callRS // this will handle stack. so far, we saved x0-10, x29-30 in the stack
	// callRS will eret

1:	// check S-Exit
	ldr x29, =HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SEXIT
	cmp x7, x29
	b.ne 1f	

	// mov x1, 0x9876	// arg
	// call S-Exit and eret
	b callRS
	// callRS will eret

1:	// check other secure stack accesses
	ldr x29, =HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SS_DATA_START
	cmp x7, x29
	b.lt 1f	

	ldr x29, =HANDLE_SCHANNEL_RETURN_NEED_TO_CALL_SS_DATA_END
	cmp x7, x29
	b.gt 1f	

	mov x4, x3 	// arg - offset2blr
	mov x3, x2 	// arg - regNo
	mov x2, x1 	// arg - token bottom
	mov x1, x0 	// arg - token top
	// we're screwing up x1-x3, but is is fine because we don't need the info

	// call S-Exit and eret
	b callRS
	// callRS will eret

1:	// something is wrong
	adr x4, str_unknown
	bl asm_print_str
	b 1b

2:	// not my concern
	ldr x7, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X7]
	// ldr x9, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X9]
	ret
endfunc handleSChannel	

	// don't save any secret into memory
	.macro beforSSectionEntryExit
	mov v23.d[1], xzr
	mov v24.d[1], xzr
	mov v25.d[1], xzr
	mov v26.d[1], xzr
	mov v27.d[1], xzr
	mov v28.d[1], xzr
	mov v29.d[1], xzr
	mov v30.d[1], xzr

	mov v9.d[0], x9
	mov v10.d[0], x10
	mov v11.d[0], x11
	mov v12.d[0], x12
	mov v13.d[0], x13
	mov v14.d[0], x14
	mov v15.d[0], x15

	stp	x16, x17, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X16]
	stp	x18, x19, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X18]
	stp	x20, x21, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X20]
	stp	x22, x23, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X22]
	stp	x24, x25, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X24]
	stp	x26, x27, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X26]
	str	x28, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X28]
	mrs	x18, sp_el0
	str	x18, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_SP_EL0]
	// stack has [x8, x16-30, sp_ep0]
	mov	x6, sp
	ldr	x12, [x6, #CTX_EL3STATE_OFFSET + CTX_RUNTIME_SP]
	msr	spsel, #0

	mrs	x16, spsr_el3
	mrs	x17, elr_el3
	mrs	x18, scr_el3
	stp	x16, x17, [x6, #CTX_EL3STATE_OFFSET + CTX_SPSR_EL3]
	str	x18, [x6, #CTX_EL3STATE_OFFSET + CTX_SCR_EL3]

	mov	sp, x12
	disalbeAFault	// clobber: x0
	.endm

	.macro afterSSectionEntryExit, advanceELR
// copied and modified of el3_exit()
// different from el3_exit() in that it does not read elr from stack but use the current one set by the above code.
	enableAFault			// clobber: x0
	mov	x17, sp
	msr	spsel, #1
	str	x17, [sp, #CTX_EL3STATE_OFFSET + CTX_RUNTIME_SP]

	ldr	x18, [sp, #CTX_EL3STATE_OFFSET + CTX_SCR_EL3]
	ldp	x16, x17, [sp, #CTX_EL3STATE_OFFSET + CTX_SPSR_EL3]
	msr	scr_el3, x18
	msr	spsr_el3, x16
	.if \advanceELR == 1
	add x17, x17, #4
	.endif
	msr elr_el3, x17

	b _restore_gp_registers_eret
	.endm

	.macro __restore, vd xd
2: 	mov x18, v\vd\().d[1]
	cbz x18, 2f
	mov x\xd, v\vd\().d[0]
	mov v\vd\().d[1], xzr
	.endm

func _restore_gp_registers_eret
	ldp	x0, x1, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X0]
	ldp	x2, x3, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X2]
	ldp	x4, x5, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X4]
	ldp	x6, x7, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X6]

	ldr	x8, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X8]

	mov x9, v9.d[0]
	mov x10, v10.d[0]
	mov x11, v11.d[0]
	mov x12, v12.d[0]
	mov x13, v13.d[0]
	mov x14, v14.d[0]
	mov x15, v15.d[0]

	__restore 23 0
	__restore 24 1
	__restore 25 2
	__restore 26 3
	__restore 27 4
	__restore 28 5
	__restore 29 6
	__restore 30 7

2:	b restore_gp_registers_callee_eret_ginseng
endfunc _restore_gp_registers_eret

callRS:
	ldr x29, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X29]
	beforSSectionEntryExit	// x6 has sp with spsel-1
	mov x0, x7 	// CMD : SMC_CMD or SCHANNEL_CMD

	bl rsGinseng_smc
	mov x29, x0 			// x29 tells which register should not be restored: range(9-15)

	afterSSectionEntryExit 1	// clobber: x4 & restore regs from stack#1

callRS_exception:
	ldr x29, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X29]
	beforSSectionEntryExit	// x6 has sp with spsel-1

	mov x0, x7 	// CMD : SMC_CMD or SCHANNEL_CMD

	bl rsGinseng_smc
	mov x29, x0 			// x29 tells which register should not be restored: range(9-15)

	afterSSectionEntryExit 0	// clobber: x4 & restore regs from stack#1

smc_return:
	ldp	x0, x1, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X0]
	ldp	x2, x3, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X2]
	ldp	x4, x5, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X4]
	ldp	x6, x7, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X6]
	ldr	x18, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_X18]
	ldr	x30, [sp, #CTX_GPREGS_OFFSET + CTX_GPREG_LR]
	eret
//
//////////////////////////// YMH_END