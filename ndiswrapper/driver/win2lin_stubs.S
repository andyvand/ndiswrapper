/*
 *  Copyright (C) 2005 Karl Vogel, Giridhar Pemmasani
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 */

#include <linux/linkage.h>

#ifdef CONFIG_X86_64

/*
# Windows <---> Linux register usage conversion when calling functions
# V = Volatile
# NV = Non Volatile (needs to be saved)
#
#         Win                     Lin
# ---------------------------------------
# Rax    Return           V       Return          V
# Rbx                     NV                      NV
# Rcx     Arg1            V       Arg4            V
# Rdx     Arg2            V       Arg3            V
# Rsi                     NV      Arg2            V
# Rdi                     NV      Arg1            V
# Rsp                     NV                      NV
# Rbp                     NV                      NV
# R8      Arg3            V       Arg5            V
# R9      Arg4            V       Arg6            V
# R10                     V                       V
# R11                     V                       V
# R12                     NV                      NV
# R13                     NV                      NV
# R14                     NV                      NV
# R15                     NV                      NV
#
# In addition, Linux uses %rax to indicate number of SSE registers used
# when variadic functions are called. Since there is no way to obtain this
# from Windows, for now, we just assume this is 0 (hence %rax is cleared).
#
# Windows pushes arguments 5 and higher onto stack in case of integer
# variables and 4 and higher in case of floating point variables (passed
# in SSE registers).

In a windows function, the stackframe/registers look like this:

# 0x0048 ....
# 0x0040 arg8
# 0x0038 arg7
# 0x0030 arg6
# 0x0028 arg5
# 0x0020 shadow/spill space for arg4
# 0x0018 shadow/spill space for arg3
# 0x0010 shadow/spill space for arg2
# 0x0008 shadow/spill space for arg1
# 0x0000 ret

# register spill space is same irrespective of number of arguments - even
# if Windows function takes less than 4 arguments, 32 bytes above return
# address is reserved for the function

In Linux it should look like:

# 0x0018 ....
# 0x0010 arg8
# 0x0008 arg7
# 0x0000 ret

*/

	.text

/*
 * win2lin_win_arg(N, ARGTOTAL) gives the address of the Windows argument
 * N out of ARGTOTAL after the stack has been prepared for the Linux function
 * call.
 *
 * When calling the Linux function, two registers (%rdi and %rsi) are pushed
 * to the stack.  When passing more than 6 arguments, arguments starting with
 * argument 7 are pushed to the stack as well.
 *
 * When called from Windows, the Nth argument is at (N * 8)(%rsp).  We add two
 * 8-byte positions for the saved registers (%rdi and %rsi) and (ARGTOTAL - 6)
 * for the arguments to be passed on stack to the Linux function.
 *
 * If there are 6 and less arguments, ARGTOTAL must be 6.  N must be at least
 * 5, as arguments 1 to 4 are passed in registers.
 */
#define win2lin_win_arg(n, argtotal) ((n + 2 + (argtotal - 6)) * 8)(%rsp)

/*
 * win2lin_lin_arg(N) gives the address of the Nth linux argument of the extra
 * linux stack frame.  When more than 6 arguments are used, %rsp points to the
 * 7th argument.  The Nth argument is therefore at ((N - 7) * 8)(%rsp).
 */
#define win2lin_lin_arg(n) ((n - 7) * 8)(%rsp)

/* Declare function LONGNAME, call function SHORTNAME with ARGC arguments */
.macro win2linm longname, shortname, argc
	.type	\longname, @function
	ENTRY(\longname)

	/*
	 * Registers %rdi and %rsi are volatile on Linux, but not on Windows,
	 * so save them on the stack.
	 */
	push	%rsi
	push	%rdi

	/* Allocate extra stack space for arguments 7 and up */
	.if (\argc >= 7)
		sub $(\argc - 6) * 8, %rsp
	.endif

	/*
	 * Copy arguments 7 and up.  We do it early, before %rdi and %rsi
	 * are used for arguments 1 and 2, so we don't have to save them.
	 * We still need to save %rcx if using a string copy.
	 */
	.if (\argc <= 8)
		/* If 7 or 8 arguments, copy them individually through %r11 */
		.if (\argc >= 7)
			mov	win2lin_win_arg(7, \argc), %r11
			mov	%r11, win2lin_lin_arg(7)
		.endif
		.if (\argc >= 8)
			mov	win2lin_win_arg(8, \argc), %r11
			mov	%r11, win2lin_lin_arg(8)
		.endif
	.else
		/* If 9 and more arguments, copy them in a loop */
		mov	%rcx, %r11			/* save arg1 */
		lea	win2lin_win_arg(7, \argc), %rsi	/* source */
		lea	win2lin_lin_arg(7), %rdi	/* destination */
		mov	$(\argc - 6), %ecx		/* arguments to copy */
		rep	movsq
		mov	%r11, %rdi			/* restore arg1 */
	.endif

	/*
	 * Argument 1 - %rcx on Windows, %rdi on Linux
	 * Micro-optimization - if we used loop, arg1 is already in %rdi
	 */
	.if (\argc >= 1) && (\argc <= 8)
		mov %rcx, %rdi
	.endif

	/* Argument 2 - %rdx on Windows, %rsi on Linux */
	.if (\argc >= 2)
		mov %rdx, %rsi
	.endif

	/* Argument 3 - %r8 on Windows, %rdx on Linux */
	.if (\argc >= 3)
		mov %r8, %rdx
	.endif

	/* Argument 4 - %r9 on Windows, %rcx on Linux */
	.if (\argc >= 4)
		mov %r9, %rcx
	.endif

	/* Arguments 5 and 6 - on stack on Windows, %r8 and %r9 on Linux */
	.if (\argc >= 7)
		mov win2lin_win_arg(5, \argc), %r8
		mov win2lin_win_arg(6, \argc), %r9
	.else
		/*
		 * If no extra stack is needed, Windows arguments are located
		 * as if there are 6 arguments.
		 */
		.if (\argc >= 5)
			mov win2lin_win_arg(5, 6), %r8
		.endif
		.if (\argc >= 6)
			mov win2lin_win_arg(6, 6), %r9
		.endif
	.endif

	/* %rax on Linux is the number of arguments in SSE registers (zero) */
	xor	%rax, %rax

	/* Call the function */
	call	\shortname

	/* Free stack stack space for arguments 7 and up */
	.if (\argc >= 7)
		add $(\argc - 6) * 8, %rsp
	.endif

	/* Restore saved registers */
	pop	%rdi
	pop	%rsi

	/* Return to Windows code */
	ret
	.size	\longname, (. - \longname)
.endm

#define win2lin(name, argc) win2linm win2lin_ ## name ## _ ## argc, name, argc

#include "win2lin_stubs.h"

#endif	/* CONFIG_X86_64 */
