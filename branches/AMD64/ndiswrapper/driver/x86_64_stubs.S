
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

lin_to_win1:
	mov %rsi, %rcx
	jmp *%rdi

lin_to_win2:
	mov %rdi, %rax	# call
	mov %rsi, %rcx	# arg1
	#   arg2 is already in %rdx
	jmp *%rdi

lin_to_win3:
	mov %rcx, %r8	# arg3
	#   arg2 is already in %rdx
	mov %rsi, %rcx	# arg1
	jmp *%rdi

lin_to_win4:
	mov %r8, %r9	# arg4
	mov %rcx, %r8	# arg3
	#   arg2 is already in %rdx
	mov %rsi, %rcx	# arg1
	jmp *%rdi

lin_to_win5:
	mov %r9, 0x20(%rsp)	# arg5
	mov %r8, %r9	# arg4
	mov %rcx, %r8	# arg3
	#   arg2 is already in %rdx
	mov %rsi, %rcx	# arg1
	jmp *%rdi

lin_to_win6:
	mov (%rsp), %rax
	mov %rax, 0x28(%rsp) # arg6
	mov %r9, 0x20(%rsp)	# arg5
	mov %r8, %r9	# arg4
	mov %rcx, %r8	# arg3
	#   arg2 is already in %rdx
	mov %rsi, %rcx	# arg1
	jmp *%rdi

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

