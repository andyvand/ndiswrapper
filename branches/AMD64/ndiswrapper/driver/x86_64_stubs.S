
	.text
	.globl lin_to_win1
	.globl lin_to_win2
	.globl lin_to_win3
	.globl lin_to_win4
	.globl lin_to_win5
	.globl lin_to_win6
	
_win_to_lin:
	push	%r10		# non volatile
	push	%r11		# non volatile
	push	%rsi		# non volatile
	push	%rdi		# non volatile
	mov	%rcx, %rdi	# arg1
	mov	%rdx, %rsi	# arg2
	mov	%r8, %rdx	# arg3
	mov	%r9, %rcx	# arg4
	mov	72(%rsp), %r8	# arg5
	mov	80(%rsp), %r9	# arg6
	call	*%rax
	pop	%rdi
	pop	%rsi
	pop	%r11
	pop	%r10
	ret


lin_to_win4:
	mov %r8, %r9		# Lin-arg5 => Win-arg4
lin_to_win3:
	mov %rcx, %r8		# Lin-arg4 => Win-arg3
lin_to_win2:
				#  Lin-arg3 already in Win-arg2 (%rdx)
lin_to_win1:
	mov %rsi, %rcx		# Lin-arg2 => Win-arg1
	jmp *%rdi		# call Lin-arg1

	# 28 / 0  - ret
	#
	# 20 - arg5   - 8
	# 18 - arg4   -10
	# 10 - arg3   -18
	# 8  - arg2   -20
	# 0  - arg1   -28
lin_to_win5:
	sub 0x28, %rsp
	mov %r9, 0x20(%rsp)
	mov %r8, %r9
	mov %rcx, %r8
				#   arg2 is already in %rdx
	mov %rsi, %rcx
	call *%rdi
	add 0x28, %rsp
	ret

	# 38 / 8  - lin-arg7
	# 30 / 0  - ret
	#
	# 28 - arg6   - 8
	# 20 - arg5   -10
	# 18 - arg4   -18
	# 10 - arg3   -20
	# 8  - arg2   -28
	# 0  - arg1   -30
lin_to_win6:
	sub 0x30, %rsp
	mov 0x38(%rsp), %eax
	mov %eax, 0x28(%rsp)
	mov %r9, 0x20(%rsp)
	mov %r8, %r9
	mov %rcx, %r8
				#   arg2 is already in %rdx
	mov %rsi, %rcx
	call *%rdi
	add 0x30, %rsp
	ret


	.macro	win_to_lin_stub name
	.globl _\name
_\name:
	lea	\name(%rip),%rax
	jmp	*win_to_lin(%rip)
	.endm

#include "x86_64_stubs.h"

	.data
win_to_lin:
	.quad	_win_to_lin

