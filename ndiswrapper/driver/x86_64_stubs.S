
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

_win_to_lin:
	push	%r11
	push	%r10		# non volatile
	push	%rsi		# non volatile
	push	%rdi		# non volatile
	mov	%rcx, %rdi	# arg1
	mov	%rdx, %rsi	# arg2
	mov	%r8, %rdx	# arg3
	mov	%r9, %rcx	# arg4
	mov	0x48(%rsp), %r8	# arg5 is at 9th position (offset 0x48)
				# due to 4 more push'es %r11 to %rdi
	mov	0x50(%rsp), %r9	# arg6
	mov	%rax, %r11
	mov	0x58(%rsp), %rax
	push	%rax		# arg7
	xor	%al, %al	# number of SSE regs for variadic funcs
	call	*%r11
	pop	%r11
	pop	%rdi
	pop	%rsi
	pop	%r10
	pop	%r11
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

