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
# R10                     NV                      V
# R11                     NV                      V
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
# variables and 4 and higher in case of floating point variabes (passed
# in SSE registers).

/*
In a windows function, the stackframe/registers look like this:

# 0x0048 ....
# 0x0040 arg8
# 0x0038 arg7
# 0x0030 arg6
# 0x0028 arg5
# 0x0020 register spill space
# 0x0018 register spill space
# 0x0010 register spill space
# 0x0008 register spill space
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

#
# setup for Windows to Linux function call
#

	.text

.macro win2lin_prolog
	push	%rsi
	push	%rdi
	push	%r10
	push	%r11
.endm

# when Windows function calls Linux function, the function address is in %rax

.macro call_lin_func
	mov	%rax, %r11	# function to call
	xor	%rax, %rax	# rax indicates number of SSE regs
	call	*%r11
.endm

.macro win2lin_epilog
	pop	%r11
	pop	%r10
	pop	%rdi
	pop	%rsi
.endm

# before prolog, 0(%rsp) is return address, 8(%rsp) would be arg1
# (but it is in register) and so on, so n'th arg would be at n*8(%rsp)
# for n > 4. But in prolog, we push 4 registers that are non-volaile in
# Windows, but volatile in Linux. So after prolog, args are at (n+4)*8(%rsp)

#define win2lin_win_arg(n) (n+4)*8(%rsp)

#define win2lin_arg1 mov %rcx, %rdi
#define win2lin_arg2 mov %rdx, %rsi
#define win2lin_arg3 mov %r8, %rdx
#define win2lin_arg4 mov %r9, %rcx
#define win2lin_arg5 mov win2lin_win_arg(5), %r8
#define win2lin_arg6 mov win2lin_win_arg(6), %r9

win2lin0:
	win2lin_prolog
	call_lin_func
	win2lin_epilog
	ret

win2lin1:
	win2lin_prolog
	win2lin_arg1
	call_lin_func
	win2lin_epilog
	ret

win2lin2:
	win2lin_prolog
	win2lin_arg1
	win2lin_arg2
	call_lin_func
	win2lin_epilog
	ret

win2lin3:
	win2lin_prolog
	win2lin_arg1
	win2lin_arg2
	win2lin_arg3
	call_lin_func
	win2lin_epilog
	ret

win2lin4:
	win2lin_prolog
	win2lin_arg1
	win2lin_arg2
	win2lin_arg3
	win2lin_arg4
	call_lin_func
	win2lin_epilog
	ret

win2lin5:
	win2lin_prolog
	win2lin_arg1
	win2lin_arg2
	win2lin_arg3
	win2lin_arg4
	win2lin_arg5
	call_lin_func
	win2lin_epilog
	ret

win2lin6:
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

# allocate stack frame for Linux arguments - first 6 args are passed
# through registers, so we need space for 7 to 12

#define win2lin_stack_frame(n) (n-6)*8

# m is index of Linux arg required, n is total number of args to function
# After stack frame is allocated, Linux arg 7 should be at 0(%rsp),
# arg 8 should be at 1*8(%rsp) and so on. So Linux arg m should be at (m-7)*8
# Stack frame starts at -(n-6)*8(%rsp), so before stack frame is allocated
# Linux arg m should be at (6-n+m-7)*8(%rsp)

#define win2lin_lin_arg(m,n) (m-1-n)*8(%rsp)

win2lin7:
	win2lin_prolog
	win2lin_arg1
	win2lin_arg2
	win2lin_arg3
	win2lin_arg4
	win2lin_arg5
	win2lin_arg6

	# copy windows argument 7 on the stack for the Linux function.

	mov	win2lin_win_arg(7), %r10
	mov	%r10, win2lin_lin_arg(7,7)
	sub	$win2lin_stack_frame(7), %rsp
	call_lin_func
	add	$win2lin_stack_frame(7), %rsp
	win2lin_epilog
	ret

win2lin8:
	win2lin_prolog
	win2lin_arg1
	win2lin_arg2
	win2lin_arg3
	win2lin_arg4
	win2lin_arg5
	win2lin_arg6

	# copy windows arguments 7 and 8
	# on the stack for the Linux function.

	mov	win2lin_win_arg(7), %r10
	mov	%r10, win2lin_lin_arg(7,8)
	mov	win2lin_win_arg(8), %r10
	mov	%r10, win2lin_lin_arg(8,8)
	sub	$win2lin_stack_frame(8), %rsp
	call_lin_func
	add	$win2lin_stack_frame(8), %rsp
	win2lin_epilog
	ret

win2lin9:
win2lin10:
win2lin11:
win2lin12:
	win2lin_prolog
	win2lin_arg1
	win2lin_arg2
	win2lin_arg3
	win2lin_arg4
	win2lin_arg5
	win2lin_arg6

	mov	%rcx, %r11		# save rcx
	# copy windows arguments 7 through 12
	# on the stack for the Linux function.
	lea	win2lin_win_arg(7), %rsi	# source (windows arg 7 and up)
	lea	win2lin_lin_arg(7,12), %rdi	# = destination
	mov	$6, %rcx			# 6 arguments
	rep
	movsq
	mov	%r11, %rcx		# restore rcx

	sub	$win2lin_stack_frame(12), %rsp
	call_lin_func
	add	$win2lin_stack_frame(12), %rsp
	win2lin_epilog
	ret

#define win2lin(name, argc)			\
ENTRY(x86_64_ ## name ##  _ ## argc)		\
	lea	name(%rip), %rax ; 		\
	jmp	win2lin ## argc

#include "x86_64_stubs.h"

#
# setup for Linux to Windows function call
#
	.text
	.globl lin2win0
	.globl lin2win1
	.globl lin2win2
	.globl lin2win3

# right above return address, there must be space for 4 registers,
# irrespective of number of arguments. After that, arguments 5 and above
# are stored

# reserve space for n arguments
.macro alloc_win_stack_frame n
	.ifgt \n-4
	sub	$\n*8, %rsp
	.else
	sub	$4*8, %rsp
	.endif
.endm

.macro free_win_stack_frame n
	.ifgt \n-4
	add	$\n*8, %rsp
	.else
	add	$4*8, %rsp
	.endif
.endm

# Linux to Windows functions are called with argument 1 being the
# Windows function to call, so Linux argument n should be moved to
# Windows argument (n-1). Linux arg 7 (function arg 6) and above
# are on stack; at 0(%rsp) is return address, so at 8(%rsp) is arg 7 etc

#define lin2win_lin_arg(n) (n-6)*8(%rsp)

# m is index of Windows arg required, n is total number of args to function
# Windows arg 1 should be at 0(%rsp), arg 2 at 8(%rsp) and so on, after stack
# frame is allocated, which starts at -n*8(%rsp) when stack frame is
# allocated. n should be >= 4

#define lin2win_win_arg(m,n) (m-1-n)*8(%rsp)

#define lin2win_arg5(n) \
	mov %r9, lin2win_win_arg(5,n)	# Linux arg6 to Windows arg5
#define lin2win_arg4 mov %r8, %r9	# Linux arg5 to Windows arg4
#define lin2win_arg3 mov %rcx, %r8	# Linux arg4 to Windows arg3
#define lin2win_arg2			# Linux arg3 is already in Windows arg2
#define lin2win_arg1 mov %rsi, %rcx	# Linux arg2 to Windows arg1

ENTRY(lin2win4)
	lin2win_arg4
lin2win3:
	lin2win_arg3
lin2win2:
	lin2win_arg2
lin2win1:
	lin2win_arg1
lin2win0:
	alloc_win_stack_frame 4
	call	*%rdi		# call Windows function
	free_win_stack_frame 4
	ret

ENTRY(lin2win5)
	# copy the arguments on stack where Windows function expects them
	# and then set up the stack frame
	lin2win_arg5(5)
	lin2win_arg4
	lin2win_arg3
	lin2win_arg2
	lin2win_arg1
	alloc_win_stack_frame 5
	call	*%rdi		# call Windows function
	free_win_stack_frame 5
	ret

ENTRY(lin2win6)
	# copy the arguments on stack where Windows function expects them
	# and then set up the stack frame
	mov	lin2win_lin_arg(7), %rax	# Linux arg7
	mov	%rax, lin2win_win_arg(6,6)	# to Windows arg6
	lin2win_arg5(6)
	lin2win_arg4
	lin2win_arg3
	lin2win_arg2
	lin2win_arg1
	alloc_win_stack_frame 6
	call	*%rdi		# call Windows function
	free_win_stack_frame 6
	ret
