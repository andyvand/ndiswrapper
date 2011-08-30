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
 * Registers %rdi and %rsi must be preserved on Windows, but not on Linux.
 */

.macro win2lin_prolog
	push	%rsi
	push	%rdi
.endm

.macro win2lin_epilog
	pop	%rdi
	pop	%rsi
.endm

/*
 * Allocate stack frame for Linux arguments.
 *
 * First 6 arguments are passed through registers, so we need space for
 * argument 7 and above.  The arguments should be copied onto stack after
 * the space has been reserved.
 */

.macro reserve_stack argtotal
	sub $(\argtotal - 6) * 8, %rsp
	.endm

.macro free_stack argtotal
	add $(\argtotal - 6) * 8, %rsp
	.endm

/*
 * Call Linux function.  win2lin macro puts its address to %r10.
 */

.macro call_lin_func
	xor	%rax, %rax	/* number of arguments in SSE registers */
	call	*%r10
.endm

/*
 * win2lin_win_arg(N, ARGTOTAL) gives the address of the Windows argument
 * N out of ARGTOTAL after the stack has been prepared for the Linux function
 * call.
 *
 * When calling the Linux function, two registers (%rdi and %rsi) are pushed
 * to the stack in win2lin_prolog.  When passing more than 6 arguments,
 * arguments starting with argument 7 are pushed to the stack as well.
 *
 * When called from Windows, the Nth argument is at (N * 8)(%rsp).  We add two
 * 8-byte positions for the saved registers (%rdi and %rsi) and (ARGTOTAL - 6)
 * for the arguments to be passed on stack to the Linux function.
 *
 * If there are 6 and less arguments, ARGTOTAL must be 6.  N must be at least
 * 5, as arguments 1 to 4 are passed in registers.
 */
#define win2lin_win_arg(arg, argtotal) ((arg + 2 + (argtotal - 6)) * 8)(%rsp)

/*
 * win2lin_lin_arg(N) gives the address of the Nth linux argument of the extra
 * linux stack frame.  When more than 6 arguments are used, %rsp points to the
 * 7th argument.  The Nth argument is therefore at ((N - 7) * 8)(%rsp).
 */
#define win2lin_lin_arg(n) ((n - 7) * 8)(%rsp)

/* Copy arguments 1 - 4 */
#define win2lin_arg1 mov %rcx, %rdi
#define win2lin_arg2 mov %rdx, %rsi
#define win2lin_arg3 mov %r8, %rdx
#define win2lin_arg4 mov %r9, %rcx

/*
 * Copy arguments 5 - 6.
 *
 * Arguments 5 and 6 must be copied after arguments 3 and 4 to prevent
 * clobbering %r8 and %r9.  win2lin_arg5 and win2lin_arg6 must be used
 * only between win2lin_prolog and reserving the extra stack space for the
 * arguments.
 */
#define win2lin_arg5 mov win2lin_win_arg(5, 6), %r8
#define win2lin_arg6 mov win2lin_win_arg(6, 6), %r9

.macro win2lin0
	win2lin_prolog
	call_lin_func
	win2lin_epilog
	ret
.endm

.macro win2lin1
	win2lin_prolog
	win2lin_arg1
	call_lin_func
	win2lin_epilog
	ret
.endm

.macro win2lin2
	win2lin_prolog
	win2lin_arg1
	win2lin_arg2
	call_lin_func
	win2lin_epilog
	ret
.endm

.macro win2lin3
	win2lin_prolog
	win2lin_arg1
	win2lin_arg2
	win2lin_arg3
	call_lin_func
	win2lin_epilog
	ret
.endm

.macro win2lin4
	win2lin_prolog
	win2lin_arg1
	win2lin_arg2
	win2lin_arg3
	win2lin_arg4
	call_lin_func
	win2lin_epilog
	ret
.endm

.macro win2lin5
	win2lin_prolog
	win2lin_arg1
	win2lin_arg2
	win2lin_arg3
	win2lin_arg4
	win2lin_arg5
	call_lin_func
	win2lin_epilog
	ret
.endm

.macro win2lin6
	win2lin_prolog
	win2lin_arg1
	win2lin_arg2
	win2lin_arg3
	win2lin_arg4
	win2lin_arg5
	win2lin_arg6
	call_lin_func
	win2lin_epilog
	ret
.endm

.macro win2lin7
	win2lin_prolog

	win2lin_arg1
	win2lin_arg2
	win2lin_arg3
	win2lin_arg4
	win2lin_arg5
	win2lin_arg6

	reserve_stack(7)

	/* Copy Windows argument 7 onto stack for the Linux function */
	mov	win2lin_win_arg(7, 7), %r11
	mov	%r11, win2lin_lin_arg(7)

	call_lin_func

	free_stack(7)

	win2lin_epilog
	ret
.endm

.macro win2lin8
	win2lin_prolog

	win2lin_arg1
	win2lin_arg2
	win2lin_arg3
	win2lin_arg4
	win2lin_arg5
	win2lin_arg6

	reserve_stack(8)

	/* Copy Windows arguments 7 and 8 onto stack for the Linux function */
	mov	win2lin_win_arg(7,8), %r11
	mov	%r11, win2lin_lin_arg(7)
	mov	win2lin_win_arg(8,8), %r11
	mov	%r11, win2lin_lin_arg(8)

	call_lin_func

	free_stack(8)

	win2lin_epilog
	ret
.endm

/*
 * We assume here that we never need to handle more than 12 arguments.
 * Copy 12 arguments even if we need less.
 */
.macro win2lin12
	win2lin_prolog

	reserve_stack(12)

	/* Copy Windows arguments 7 through 12 onto stack */
	mov	%rcx, %r11			/* save %rcx */
	lea	win2lin_win_arg(7, 12), %rsi	/* source */
	lea	win2lin_lin_arg(7), %rdi	/* destination */
	mov	$6, %rcx			/* 6 arguments */
	rep
	movsq
	mov	%r11, %rcx			/* restore %rcx */

	/* Copy arguments 1 - 4 */
	win2lin_arg1
	win2lin_arg2
	win2lin_arg3
	win2lin_arg4

	/*
	 * Copy arguments 5 and 6. Cannot use win2lin_arg5 and win2lin_arg6
	 * after reserve_stack.
	 */
	mov win2lin_win_arg(5, 12), %r8
	mov win2lin_win_arg(6, 12), %r9

	call_lin_func

	free_stack(12)

	win2lin_epilog
	ret
.endm

.macro win2lin9
	win2lin12
.endm

.macro win2lin10
	win2lin12
.endm

.macro win2lin11
	win2lin12
.endm

#define win2lin(name, argc)					\
	.type	win2lin_ ## name ## _ ## argc, @function;	\
ENTRY(win2lin_ ## name ## _ ## argc)				\
	lea	name(%rip), %r10;				\
	win2lin ## argc;					\
	.size	win2lin_ ## name ## _ ## argc, .-win2lin_ ## name ## _ ## argc

#include "win2lin_stubs.h"

#endif	/* CONFIG_X86_64 */
