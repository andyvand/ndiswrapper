/*
 *  Copyright (C) 2006 Giridhar Pemmasani
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

#ifdef CONFIG_X86_64

/* Windows functions must have 32 bytes of reserved space above return
 * address, irrespective of number of args. So argc >= 4 */

#define alloc_win_stack_frame(argc)		\
	"subq $" #argc "*8, %%rsp\n\t"
#define free_win_stack_frame(argc)		\
	"addq $" #argc "*8, %%rsp\n\t"

/* m is index of Windows arg required, n is total number of args to
 * function Windows arg 1 should be at 0(%rsp), arg 2 at 8(%rsp) and
 * so on, after stack frame is allocated, which starts at -n*8(%rsp)
 * when stack frame is allocated. n should be > 4
*/

#define lin2win_win_arg(m,n) "(" #m "-1-" #n ")*8(%%rsp)"

/* volatile args for Windows function must be in clobber list */

#define LIN2WIN0(func)							\
({									\
	u64 ret, dummy;							\
	DBGTRACE6("calling %p", func);					\
	__asm__ __volatile__(						\
		alloc_win_stack_frame(4)				\
		"call *%3\n\t"						\
		free_win_stack_frame(4)					\
		: "=a" (ret), "=c" (dummy), "=d" (dummy)		\
		: "a" (func)						\
		: "r8", "r9", "r10", "r11");				\
	DBGTRACE6("%p done", func);					\
	ret;								\
})

#define LIN2WIN1(func, arg1)						\
({									\
	u64 ret, dummy;							\
	DBGTRACE6("calling %p", func);					\
	__asm__ __volatile__(						\
		alloc_win_stack_frame(4)				\
		"call *%4\n\t"						\
		free_win_stack_frame(4)					\
		: "=a" (ret), "=c" (dummy), "=d" (dummy)		\
		: "c" (arg1),						\
		  "a" (func)						\
		: "r8", "r9", "r10", "r11");				\
	DBGTRACE6("%p done", func);					\
	ret;								\
})

#define LIN2WIN2(func, arg1, arg2)					\
({									\
	u64 ret, dummy;							\
	DBGTRACE6("calling %p", func);					\
	__asm__ __volatile__(						\
		alloc_win_stack_frame(4)				\
		"call *%5\n\t"						\
		free_win_stack_frame(4)					\
		: "=a" (ret), "=c" (dummy), "=d" (dummy)		\
		: "c" (arg1), "d" (arg2),				\
		  "a" (func)						\
		: "r8", "r9", "r10", "r11");				\
	DBGTRACE6("%p done", func);					\
	ret;								\
})

#define LIN2WIN3(func, arg1, arg2, arg3)				\
({									\
	u64 ret, dummy;							\
	DBGTRACE6("calling %p", func);					\
	__asm__ __volatile__(						\
		"movq %5, %%r8\n\t"					\
		alloc_win_stack_frame(4)				\
		"call *%6\n\t"						\
		free_win_stack_frame(4)					\
		: "=a" (ret), "=c" (dummy), "=d" (dummy)		\
		: "c" (arg1), "d" (arg2), "g" ((u64)arg3),		\
		  "a" (func)						\
		: "r8", "r9", "r10", "r11");				\
	DBGTRACE6("%p done", func);					\
	ret;								\
})

#define LIN2WIN4(func, arg1, arg2, arg3, arg4)				\
({									\
	u64 ret, dummy;							\
	DBGTRACE6("calling %p", func);					\
	__asm__ __volatile__(						\
		"movq %5, %%r8\n\t"					\
		"movq %6, %%r9\n\t"					\
		alloc_win_stack_frame(4)				\
		"call *%7\n\t"						\
		free_win_stack_frame(4)					\
		: "=a" (ret), "=c" (dummy), "=d" (dummy)		\
		: "c" (arg1), "d" (arg2), "g" ((u64)arg3),		\
		  "g" ((u64)arg4),					\
		  "a" (func)						\
		: "r8", "r9", "r10", "r11");				\
	DBGTRACE6("%p done", func);					\
	ret;								\
})

#define LIN2WIN5(func, arg1, arg2, arg3, arg4, arg5)			\
({									\
	u64 ret, dummy;							\
	DBGTRACE6("calling %p", func);					\
	__asm__ __volatile__(						\
		"movq %5, %%r8\n\t"					\
		"movq %6, %%r9\n\t"					\
		"movq %7, " lin2win_win_arg(5,5) "\n\t"			\
		alloc_win_stack_frame(5)				\
		"call *%8\n\t"						\
		free_win_stack_frame(5)					\
		: "=a" (ret), "=c" (dummy), "=d" (dummy)		\
		: "c" (arg1), "d" (arg2), "g" ((u64)arg3),		\
		  "g" ((u64)arg4), "ri" ((u64)arg5),			\
		  "a" (func)						\
		: "r8", "r9", "r10", "r11");				\
	DBGTRACE6("%p done", func);					\
	ret;								\
})

#define LIN2WIN6(func, arg1, arg2, arg3, arg4, arg5, arg6)		\
({									\
	u64 ret, dummy;							\
	DBGTRACE6("calling %p", func);					\
	__asm__ __volatile__(						\
		"movq %5, %%r8\n\t"					\
		"movq %6, %%r9\n\t"					\
		"movq %7, %%r10\n\t"					\
		"movq %7, " lin2win_win_arg(5,6) "\n\t"			\
		"movq %8, " lin2win_win_arg(6,6) "\n\t"			\
		alloc_win_stack_frame(6)				\
		"call *%9\n\t"						\
		free_win_stack_frame(6)					\
		: "=a" (ret), "=c" (dummy), "=d" (dummy)		\
		: "c" (arg1), "d" (arg2), "g" ((u64)arg3),		\
		  "g" ((u64)arg4), "ri" ((u64)arg5), "ri" ((u64)arg6),	\
		  "a" (func)						\
		: "r8", "r9", "r10", "r11");				\
	DBGTRACE6("%p done", func);					\
	ret;								\
})

#else // CONFIG_X86_64

#define LIN2WIN1(func, arg1)						\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1);							\
})
#define LIN2WIN2(func, arg1, arg2)					\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1, arg2);						\
})
#define LIN2WIN3(func, arg1, arg2, arg3)				\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1, arg2, arg3);						\
})
#define LIN2WIN4(func, arg1, arg2, arg3, arg4)				\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1, arg2, arg3, arg4);					\
})
#define LIN2WIN5(func, arg1, arg2, arg3, arg4, arg5)			\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1, arg2, arg3, arg4, arg5);				\
})
#define LIN2WIN6(func, arg1, arg2, arg3, arg4, arg5, arg6)		\
({									\
	DBGTRACE6("calling %p", func);					\
	func(arg1, arg2, arg3, arg4, arg5, arg6);			\
})

#endif // CONFIG_X86_64
