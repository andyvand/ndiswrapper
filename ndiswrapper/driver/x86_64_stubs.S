
	.text

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

	.macro	x86_64_stub name
	.globl _\name
_\name:
	lea	\name(%rip),%rax
	jmp	*win_to_lin(%rip)
	.endm

#include "x86_64_stubs.h"

	.data
win_to_lin:
	.quad	_win_to_lin

