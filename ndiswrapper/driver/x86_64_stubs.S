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
# 0x0020 arg4 %r9
# 0x0018 arg3 %r8
# 0x0010 arg2 %rdx
# 0x0008 arg1 %rcx
# 0x0000 ret

In Linux it should look like:

# 0x0018 ....
# 0x0010 arg8
# 0x0008 arg7
# 0x0000 ret

*/

#
# setup for Windows to Linux function call
#

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

win2lin0:
	win2lin_prolog
	call_lin_func
	win2lin_epilog
	ret

win2lin1:
	win2lin_prolog
	mov	%rcx, %rdi
	call_lin_func
	win2lin_epilog
	ret

win2lin2:
	win2lin_prolog
	mov	%rcx, %rdi
	mov	%rdx, %rsi
	call_lin_func
	win2lin_epilog
	ret

win2lin3:
	win2lin_prolog
	mov	%rcx, %rdi
	mov	%rdx, %rsi
	mov	%r8, %rdx
	call_lin_func
	win2lin_epilog
	ret

win2lin4:
	win2lin_prolog
	mov	%rcx, %rdi
	mov	%rdx, %rsi
	mov	%r8, %rdx
	mov	%r9, %rcx
	call_lin_func
	win2lin_epilog
	ret

# we have pushed 4 registers on stack, so args are at offset 4+

#define win2lin_arg(n) (n+4)*8(%rsp)

win2lin5:
	win2lin_prolog
	mov	%rcx, %rdi
	mov	%rdx, %rsi
	mov	%r8, %rdx
	mov	%r9, %rcx
	mov	win2lin_arg(5), %r8
	call_lin_func
	win2lin_epilog
	ret

win2lin6:
	win2lin_prolog
	mov	%rcx, %rdi
	mov	%rdx, %rsi
	mov	%r8, %rdx
	mov	%r9, %rcx
	mov	win2lin_arg(5), %r8
	mov	win2lin_arg(6), %r9
	call_lin_func
	win2lin_epilog
	ret

# reserve space for Linux arguments - first 6 args are passed through registers
# so we need space for 7 to 12

#define win2lin_stack_reserve 5*8

# 9 = 5 (stack reserved for Linux args) +
#     4 (registers pushed onto stack in prolog)

#define win2lin_arg_reserve(n) (n+9)*8(%rsp)

win2lin7:
	win2lin_prolog
	sub	$win2lin_stack_reserve, %rsp
	mov	%rcx, %rdi
	mov	%rdx, %rsi
	mov	%r8, %rdx
	mov	%r9, %rcx
	mov	win2lin_arg_reserve(5), %r8
	mov	win2lin_arg_reserve(6), %r9

	# copy windows argument 7 on the stack for the Linux function.

	mov	win2lin_arg_reserve(7), %r10
	mov	%r10, (%rsp)
	call_lin_func
	add	$win2lin_stack_reserve, %rsp
	win2lin_epilog
	ret

win2lin8:
	win2lin_prolog
	sub	$win2lin_stack_reserve, %rsp
	mov	%rcx, %rdi
	mov	%rdx, %rsi
	mov	%r8, %rdx
	mov	%r9, %rcx
	mov	win2lin_arg_reserve(5), %r8
	mov	win2lin_arg_reserve(6), %r9

	# copy windows arguments 7 and 8
	# on the stack for the Linux function.

	mov	win2lin_arg_reserve(7), %r10
	mov	%r10, (%rsp)
	mov	win2lin_arg_reserve(8), %r10
	mov	%r10, 8(%rsp)
	call_lin_func
	add	$win2lin_stack_reserve, %rsp
	win2lin_epilog
	ret

win2lin9:
win2lin10:
win2lin11:
win2lin12:
	win2lin_prolog
	sub	$win2lin_stack_reserve, %rsp
	mov	%rax, %r11	# function to call
	mov	%rcx, %rax

	# copy windows arguments 9 through 12
	# on the stack for the Linux function.

	lea	win2lin_arg_reserve(7), %rsi
				# source (windows arg 7 and up)
	mov	%rsp, %rdi	# = destination
	mov	$5, %rcx	# 5 arguments
	rep	movsq

	mov	%rax, %rdi
	mov	%rdx, %rsi
	mov	%r8, %rdx
	mov	%r9, %rcx
	mov	win2lin_arg_reserve(5), %r8
	mov	win2lin_arg_reserve(6), %r9
	xor	%rax, %rax
	call	*%r11

	add	$win2lin_stack_reserve, %rsp

	win2lin_epilog
	ret

#define stringify2(a, b) a ## b

#define win2lin(name, argc)				\
	.globl stringify2(x86_64_ ## name,  _ ##argc) ; \
stringify2(x86_64_ ## name, _ ## argc):	; 		\
	lea	name(%rip), %rax ; 			\
	jmp	*win2lin ## argc(%rip)

#include "x86_64_stubs.h"

#
# setup for Linux to Windows function call
#
	.text
	.globl lin2win1
	.globl lin2win2
	.globl lin2win3
	.globl lin2win4
	.globl lin2win5
	.globl lin2win6

# right above return address, there must be space for 4 registers,
# irrespective of number of arguments. After that, arguments 5 and above
# are stored

# n must be number of args more than 4 (e.g., for 5 args, n must be 1)

#define lin2win_args_on_stack(n) (n+4)*8

# n must be argument index, 1 through 6

#define lin2win_arg(n) (n-4)*8(%rsp)

# Linux to Windows functions are called with argument 1 being the
# Windows function to call.

lin2win4:
	mov	%r8, %r9	# Linux arg5 => Win arg4
lin2win3:
	mov	%rcx, %r8	# Linux arg4 => Win arg3
lin2win2:
				# Linux arg3 already in Win arg2 (%rdx)
lin2win1:
	mov	%rsi, %rcx	# Linux arg2 => Win arg1
	sub	lin2win_args_on_stack(0), %rsp
	call	*%rdi		# call Windows function
	add	lin2win_args_on_stack(0), %rsp
	ret

lin2win5:
	# setup a new stack frame for Windows function and put the arguments
	# where it expects them
	sub	lin2win_args_on_stack(1), %rsp	# reserve stack space
	mov	%r9, lin2win_arg(5)	# Linux arg6 => Win arg5
	mov	%r8, %r9	# Linux arg5 => Win arg4
	mov	%rcx, %r8	# Linux arg4 => Win arg3
				# Linux arg3 already in Win arg2 (%rdx)
	mov	%rsi, %rcx	# Linux arg2 => Win arg1
	call	*%rdi		# call Windows function
	add	lin2win_args_on_stack(1), %rsp
	ret

lin2win6:
	# setup a new stack frame for Windows function and put the arguments
	# where it expects them
	mov	8(%rsp), %rax	# get Linux arg7
	sub	lin2win_args_on_stack(2), %rsp	# reserve stack space
	mov	%rax, lin2win_arg(6)	# Linux arg7 => Win arg6
	mov	%r9, lin2win_arg(5) # Linux arg6 => Win arg5
	mov	%r8, %r9	# Linux arg5 => Win arg4
	mov	%rcx, %r8	# Linux arg4 => Win arg3
				# Linux arg3 already in Win arg2 (%rdx)
	mov	%rsi, %rcx	# Linux arg2 => Win arg1
	call	*%rdi		# call Windows function
	add	lin2win_args_on_stack(2), %rsp
	ret
