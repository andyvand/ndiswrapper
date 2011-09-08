/*
 *  Copyright (C) 2011 Pavel Roskin
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

	.text

#define WORD_BYTES 8

/*
 * lin2win(func, unused, winarg1, winarg2, ...)
 *
 * Call Windows function FUNC with arguments WINARG1, WINARG2 etc using
 * Windows calling convention.  The second argument is unused to preserve
 * 16-bit stack alignment.
 *
 * We use the fact that Linux passes more arguments in the registers than
 * Windows and that Windows preserves more registers across function calls.
 * This allows us to reuse the arguments allocated on the stack without
 * copying.
 */
.type	lin2win, @function
ENTRY(lin2win)
	/* Save our return address to %rsi, it's saved by Windows functions */
	mov (%rsp), %rsi

	/*
	 * Allocate spill space for Windows arguments 1 to 4.  We sacrifice
	 * our return address as well, so that's one position less.
	 */
	sub $(4 - 1) * WORD_BYTES, %rsp

	/*
	 * arg3(winarg1) is in %rdx, goes to %rcx
	 * arg4(winarg2) is in %rcx, goes to %rdx
	 * So we swap %rcx and %rdx.
	 * arg5 and winarg3 are in %r8 - nothing needed.
	 * arg6 and winarg4 are in %r9 - nothing needed.
	 */
	xchg %rcx, %rdx

	/* Call function (arg1) */
	call *%rdi

	/* Reclaim all spill space */
	add $4 * WORD_BYTES, %rsp

	/* Return to the address saved in %rsi */
	push %rsi
	ret
.size	lin2win, (. - lin2win)
