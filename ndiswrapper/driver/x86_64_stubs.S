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

	.text
	.globl lin_to_win1
	.globl lin_to_win2
	.globl lin_to_win3
	.globl lin_to_win4
	.globl lin_to_win5
	.globl lin_to_win6
	
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

# 0x0040 arg8
# 0x0038 arg7
# 0x0030 arg6
# 0x0028 arg5
# 0x0020 arg4 %r9
# 0x0018 arg3 %r8
# 0x0010 arg2 %rdx
# 0x0008 arg1 %rcx
# 0x0000 ret
*/

_win_to_lin:
	push	%rbx	# just save everything to be sure
	push	%rcx	# clean this up later when everything works.
	push	%rdx
	push	%rsi
	push	%rdi
	push	%rbp
	push	%r8
	push	%r9
	push	%r10
	push	%r11
	push	%r12
	push	%r13
	push	%r14
	push	%r15	# 14

	mov	%rax, %r11	# function to call
	mov	%rcx, %rax

	lea     (7+14)*8(%rsp), %rsi
	sub     $648, %rsp
	mov     %rsp, %rdi
	mov     $640/8-8, %rcx
	rep     movsq
	
	mov	%rax, %rdi	# arg1
	mov	%rdx, %rsi	# arg2
	mov	%r8, %rdx	# arg3
	mov	%r9, %rcx	# arg4
	mov	(5+14)*8+648(%rsp), %r8
				# arg5 is at 9th position (offset 72)
				# due to 4 more push'es
	mov	(6+14)*8+648(%rsp), %r9	# arg6
	xor	%eax, %eax	# number of SSE regs for variadic funcs
	call	*%r11

	add	$648, %rsp	

	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%r11
	pop	%r10
	pop	%r9
	pop	%r8
	pop	%rbp
	pop	%rdi
	pop	%rsi
	pop	%rdx
	pop	%rcx
	pop	%rbx
	ret


lin_to_win4:
	mov	%r8, %r9	# Lin-arg5 => Win-arg4
lin_to_win3:
	mov	%rcx, %r8	# Lin-arg4 => Win-arg3
lin_to_win2:
				#  Lin-arg3 already in Win-arg2 (%rdx)
lin_to_win1:
	mov	%rsi, %rcx	# Lin-arg2 => Win-arg1
	jmp	*%rdi		# call Lin-arg1

	# 0x28 / 0  - ret
	#
	# 0x20 - arg5   -0x8
	# 0x18 - arg4   -0x10
	# 0x10 - arg3   -0x18
	# 0x8  - arg2   -0x20
	# 0x0  - arg1   -0x28
lin_to_win5:
	# setup a new stack frame for Windows function and put the arguments
	# where it expects them
	sub	$0x28, %rsp
	mov	%r9, 0x20(%rsp)
	mov	%r8, %r9
	mov	%rcx, %r8
				#   arg2 is already in %rdx
	mov	%rsi, %rcx
	call	*%rdi
	add	$0x28, %rsp
	ret

	# 0x38 / 8  - lin-arg7
	# 0x30 / 0  - ret
	#
	# 0x28 - arg6   -0x8
	# 0x20 - arg5   -0x10
	# 0x18 - arg4   -0x18
	# 0x10 - arg3   -0x20
	# 0x8  - arg2   -0x28
	# 0x0  - arg1   -0x30
lin_to_win6:
	# setup a new stack frame for Windows function and put the arguments
	# where it expects them
	sub	$0x30, %rsp
	mov	0x38(%rsp), %rax
	mov	%rax, 0x28(%rsp)
	mov	%r9, 0x20(%rsp)
	mov	%r8, %r9
	mov	%rcx, %r8
				#   arg2 is already in %rdx
	mov	%rsi, %rcx
	call	*%rdi
	add	$0x30, %rsp
	ret


	.macro	win_to_lin_stub name
	.globl x86_64_\name
x86_64_\name:
	lea	\name(%rip),%rax
	jmp	*win_to_lin(%rip)
	.endm

#include "x86_64_stubs.h"

	.data
win_to_lin:
	.quad	_win_to_lin

